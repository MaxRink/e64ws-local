#!/usr/bin/env python3
"""Extract every Qt resource set (qInitResources_*) from libNgxUi.so.

Qt's rcc v3 layout, as used by Qt 5.15.x:
  tree node (22 bytes, big endian):
      u32 name_offset  | u16 flags | u32 data_offset_or_childcount
      u32 length       | u64 last_modified
  name blob entry:  u16 length(chars) | u32 hash | UTF-16BE chars
  data blob entry:  u32 stored_size | payload
      flags bit 0x01 -> zlib payload (qCompress, 4-byte BE size prefix)
      flags bit 0x02 -> directory node
"""
from __future__ import annotations

import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from elfview import Elf  # noqa: E402

NODE_SIZE = 22
SETS = {
    # (struct_va, struct_size, name_va, name_size, data_va, data_size)
    "Ui":          (0x004A81D0, 7348, 0x004A9E84, 16068, 0x004ADD48, 967081),
    "CloudCA":     (0x0059AA40, 110,  0x0059A9E8, 86,    0x00599EF4, 2804),
    "Sqlite":      (0x0059AF1C, 660,  0x0059AAB0, 1130,  0x0059B1B0, 19986),
    "ExtraFonts":  (0x005A009C, 176,  0x0059FFC4, 214,   0x005A014C, 254998),
    "Translation": (0x005DE62C, 110,  0x005DE564, 198,   0x005DE69C, 483536),
}


def be16(b, o):
    return struct.unpack_from(">H", b, o)[0]


def be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def classify(path: str, payload: bytes) -> str:
    if payload[:4] == b"qmlc":
        return "qmlc"
    if payload[:1] == b"{" or payload[:1] in b"<" or payload[:1] == b"/":
        return "text"
    if payload[:4] == b"\x89PNG":
        return "png"
    if payload[:6] in (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"):
        return "ico"
    if payload[:4] == b"\x00\x01\x00\x00":
        return "ttf"
    if payload[:4] == b"OTTO":
        return "otf"
    if payload[:4] == b"wOFF":
        return "woff"
    if payload[:4] in (b"\x1c\x00\x00\x00", b"\xab\x00\x00\x00", b"lmza"):
        return "qm"
    if payload[:15] == b"SQLite format 3":
        return "sqlite"
    if payload[:5] == b"-----":
        return "pem"
    return "binary"


def main() -> None:
    elf = Elf(sys.argv[1])
    outroot = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "/tmp/qml-recon/qrc")
    report = {}
    for set_name, (tva, tsize, nva, nsize, dva, dsize) in SETS.items():
        tree = elf.read_va(tva, tsize)
        names = elf.read_va(nva, nsize)
        data = elf.read_va(dva, dsize)
        count = tsize // NODE_SIZE
        entries = []

        def name_of(off: int) -> str:
            ln = be16(names, off)
            return names[off + 6:off + 6 + ln * 2].decode("utf-16-be")

        def node(i):
            o = i * NODE_SIZE
            return (be32(tree, o), be16(tree, o + 4),
                    be32(tree, o + 6), be32(tree, o + 10))

        def walk(i, prefix):
            name_off, flags, a, b = node(i)
            comp = name_of(name_off) if i else ""
            path = (prefix + "/" + comp) if comp else (prefix or "/")
            if i == 0 or flags & 0x2:
                # directories: word at +6 = child count, word at +10 = first child
                children, first = a, b
                for c in range(first, first + children):
                    walk(c, "" if i == 0 else path)
                return
            # Qt 5.15: for regular files the *second* word is the offset into the
            # data blob; the stored size is the big-endian word at that offset.
            stored_size = be32(data, b)
            stored = data[b + 4:b + 4 + stored_size]
            if flags & 0x01:
                import zlib
                payload = zlib.decompress(stored[4:])
            else:
                payload = stored
            dest = outroot / set_name / path.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(payload)
            entries.append(dict(path="/" + path.lstrip("/"), set=set_name,
                                flags=flags, stored=stored_size,
                                size=len(payload),
                                format=classify(path, payload)))

        walk(0, "")
        report[set_name] = dict(tree_va=hex(tva), nodes=count,
                                name_va=hex(nva), name_bytes=nsize,
                                data_va=hex(dva), data_bytes=dsize,
                                files=len(entries), entries=entries)
        print(f"== {set_name}: {count} nodes, {len(entries)} files, "
              f"{sum(e['size'] for e in entries)} bytes uncompressed")
        for e in sorted(entries, key=lambda x: x["path"]):
            print(f"   {e['flags']:#04x} {e['size']:>8} {e['format']:<8} {e['path']}")

    (pathlib.Path("/tmp/qml-recon/work") / "resources.json").write_text(
        json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
