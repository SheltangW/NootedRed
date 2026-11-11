"""把 fixtures/<system>-compat.json 重新绑定到本机 dyld 缓存。

背景：fixtures 里的 uuid/size/sha256 绑定的是作者生成数据时的 macOS 构建版本。
在不同构建上（例如 23G93），个别函数体不同，导致 --check 与运行时的字节核验失败。
本工具从本机缓存重新采集这些字段，仅更新可派生的数值，不改任何结构假设；
结构假设（引用偏移、gate 字节、立即数、上下文哈希）仍由 build_sequoia_surface.py
和 build_video_decode_patch.py 的硬校验把关，一旦不符会直接报错而不是产出可疑数据。
AppleGVA 静态函数若在构建间平移，会以原函数的序言、分支位置及至少 90% 的
逐字节一致性重新定位，避免仅凭固定地址套用其他构建的数据。
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

from audit_video_driver import symbols
from metal_cache import CacheReader

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True, help='dyld 共享缓存目录')
    parser.add_argument('--major', type=int, choices=(23, 24), default=23)
    parser.add_argument('--write', action='store_true', help='写回 fixture，否则只报告差异')
    args = parser.parse_args()

    system = 'sonoma' if args.major == 23 else 'sequoia'
    path = ROOT / f'tools/fixtures/{system}-compat.json'
    profile = json.loads(path.read_text())

    # 先用本机 uuid 打开；若 fixture 的 uuid 与磁盘不符，此处会直接报错，需人工确认系统版本。
    cache = CacheReader(args.cache, cache_uuid(args.cache))
    try:
        changed = []
        for name, meta in profile['metal'].items():
            address, code = cache.function(name)
            digest = hashlib.sha256(code).hexdigest()
            if (meta['address'], meta['size'], meta['sha256']) != (address, len(code), digest):
                changed.append((name, meta['size'], len(code)))
                meta.update(address=address, size=len(code), sha256=digest)
        print(f'缓存 uuid：{cache.uuid.hex()}（fixture 原值 {profile["uuid"]}）')
        for name, old, new in changed:
            print(f'  重新绑定显示函数 {name[:64]}  {old}B -> {new}B')
        if not changed:
            print('  六个显示目标函数均已与 fixture 一致')

        video_changed = rebind_video(cache, profile)
        for name, old, new in video_changed:
            print(f'  重新绑定视频函数 {name[:64]}  {old}B -> {new}B')
        if not video_changed:
            print('  十六个视频目标函数均已与 fixture 一致')

        gva_changed = rebind_gva(cache, profile)
        print('  AppleGVA 选择函数已一致' if not gva_changed else
              f'  重新绑定 AppleGVA 选择函数：地址 {gva_changed[0]:#x} -> {gva_changed[1]:#x}')
        profile['uuid'] = cache.uuid.hex()
        if args.write:
            path.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + '\n')
            print(f'已写回 {path.relative_to(ROOT)}')
        else:
            print('（未写回，加 --write 生效）')
    finally:
        cache.close()


def image_symbols(cache, image):
    lines = (cache.directory / 'dyld_shared_cache_x86_64h.map').read_text().splitlines()
    base = int(lines[lines.index(image) + 1].split()[1], 16)
    return symbols(cache.read, base)[0]


def rebind_video(cache, profile):
    """重新采集 AMDRadeonVADriver2 的函数边界、地址与哈希。"""
    names = image_symbols(
        cache, '/System/Library/Extensions/AMDRadeonVADriver2.bundle/Contents/MacOS/AMDRadeonVADriver2')
    changed = []
    for name, meta in profile.get('video', {}).items():
        address = names[name]
        end = min(a for a in names.values() if a > address)
        code = cache.read(address, end - address)
        digest = hashlib.sha256(code).hexdigest()
        if (meta['address'], meta['length'], meta['sha256']) != (address, len(code), digest):
            changed.append((name, meta['length'], len(code)))
            meta.update(address=address, length=len(code), sha256=digest)
    for name, context in profile.get('encodeContexts', {}).items():
        following, size, _ = context
        address = names[name]
        end = min(a for a in names.values() if a > address)
        if end != names[following] or min(a for a in names.values() if a > end) != address + size:
            raise ValueError(f'编码锚点边界改变，拒绝自动重绑定：{name}')
        context[2] = hashlib.sha256(cache.read(address, size)).hexdigest()
    return changed


def rebind_gva(cache, profile):
    """在旧地址附近定位同一 AppleGVA 静态函数，容忍构建间代码平移。

    以已生成数据中的完整参考函数为锚点，要求函数序言、分支位置和分支字节一致；
    rel32 引用可随布局变化，因此不能要求整个函数逐字节相同。
    """
    gva = profile.get('gva')
    if not gva:
        return None
    code = cache.read(gva['address'], gva['size'])
    digest = hashlib.sha256(code).hexdigest()
    if digest == gva['sha256']:
        return None

    header_path = ROOT / 'NootedRed/UserSonomaVideoData.hpp'
    header = header_path.read_text()
    match = re.search(r'ResolverOriginal0\[\] = \{(.*?)\};', header, re.S)
    if not match:
        raise ValueError('找不到 AppleGVA 参考函数，拒绝猜测地址')
    reference = bytes(int(x, 16) for x in re.findall(r'0x([0-9A-F]{2})', match.group(1)))
    if len(reference) != gva['size']:
        raise ValueError('AppleGVA 参考函数长度与 fixture 不符')
    prologue = reference[:26]
    branch = bytes.fromhex(gva['branch'])
    offset = gva['offset']
    window = 0x10000
    start = gva['address'] - window
    region = cache.read(start, window * 2 + gva['size'])
    candidates = []
    cursor = 0
    while (found := region.find(prologue, cursor)) >= 0:
        address = start + found
        candidate = region[found:found + len(reference)]
        if len(candidate) == len(reference) and candidate[offset:offset + len(branch)] == branch:
            equal = sum(a == b for a, b in zip(reference, candidate))
            candidates.append((equal, address, candidate))
        cursor = found + 1
    if not candidates:
        raise ValueError('附近找不到结构一致的 AppleGVA 选择函数')
    candidates.sort(reverse=True)
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        raise ValueError('AppleGVA 候选函数不唯一，拒绝猜测地址')
    equal, address, code = candidates[0]
    if equal < len(reference) * 0.9:
        raise ValueError(f'AppleGVA 最佳候选仅有 {equal}/{len(reference)} 字节一致')
    old = gva['address']
    gva.update(address=address, sha256=hashlib.sha256(code).hexdigest())
    return old, address


def cache_uuid(directory):
    """读取主缓存头里的 UUID，避免重绑定过程被旧 fixture 值挡住。"""
    path = Path(directory) / 'dyld_shared_cache_x86_64h'
    import struct
    with path.open('rb') as handle:
        header = handle.read(104)
    if not header.startswith(b'dyld_v1'):
        raise SystemExit(f'不是 dyld 共享缓存：{path}')
    return header[88:104].hex()


if __name__ == '__main__':
    main()
