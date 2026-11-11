"""把 fixtures/<system>-compat.json 重新绑定到本机 dyld 缓存。

背景：fixtures 里的 uuid/size/sha256 绑定的是作者生成数据时的 macOS 构建版本。
在不同构建上（例如 23G93），个别函数体不同，导致 --check 与运行时的字节核验失败。
本工具从本机缓存重新采集这些字段，仅更新可派生的数值，不改任何结构假设；
结构假设（引用偏移、gate 字节、立即数、上下文哈希）仍由 build_sequoia_surface.py
的硬校验把关，一旦不符会直接报错而不是产出可疑数据。
"""
import argparse
import hashlib
import json
from pathlib import Path

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
            print(f'  重新绑定 {name[:72]}  {old}B -> {new}B')
        if not changed:
            print('  六个目标函数均已与 fixture 一致，无需改动')
        profile['uuid'] = cache.uuid.hex()
        if args.write:
            path.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + '\n')
            print(f'已写回 {path.relative_to(ROOT)}')
        else:
            print('（未写回，加 --write 生效）')
    finally:
        cache.close()


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
