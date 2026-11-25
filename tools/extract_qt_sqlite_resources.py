#!/usr/bin/env python3
"""Extract the Qt SQLite resource bundle from E64 WS firmware 1.16-24.

Read-only extractor for qInitResources_Sqlite in libNgxUi.so.  It parses the
Qt v3 resource tree and decompresses flagged qCompress payloads.
"""
from __future__ import annotations

import argparse
import pathlib
import struct
import zlib

TREE_VA = 0x0059AF1C
NAME_VA = 0x0059AAB0
DATA_VA = 0x0059B1B0
NODE_SIZE = 22


def be32(blob: bytes, offset: int) -> int:
    return struct.unpack_from(">I", blob, offset)[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    blob = args.elf.read_bytes()
    args.output.mkdir(parents=True, exist_ok=True)

    def node(index: int) -> tuple[int, int, int, int]:
        offset = TREE_VA + NODE_SIZE * index
        return (
            be32(blob, offset),
            struct.unpack_from(">H", blob, offset + 4)[0],
            be32(blob, offset + 6),
            be32(blob, offset + 10),
        )

    def resource_name(offset: int) -> str:
        length = struct.unpack_from(">H", blob, NAME_VA + offset)[0]
        start = NAME_VA + offset + 6  # length + Qt name hash
        return blob[start : start + length * 2].decode("utf-16-be")

    def walk(index: int, prefix: str = "") -> None:
        name_offset, flags, count, offset = node(index)
        component = resource_name(name_offset) if name_offset else ""
        resource_path = (prefix + "/" + component).replace("//", "/")
        if flags & 0x2:
            for child in range(offset, offset + count):
                walk(child, resource_path)
            return
        stored_size = be32(blob, DATA_VA + offset)
        stored = blob[DATA_VA + offset + 4 : DATA_VA + offset + 4 + stored_size]
        content = zlib.decompress(stored[4:]) if flags & 0x1 else stored
        if flags & 0x1 and len(content) != be32(blob, DATA_VA + offset + 4):
            raise ValueError(f"bad decompressed size for {resource_path}")
        destination = args.output / resource_path.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        print(f"{resource_path}\tflags=0x{flags:x}\tstored={stored_size}\textracted={len(content)}")

    walk(0)


if __name__ == "__main__":
    main()
