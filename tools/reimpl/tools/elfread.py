#!/usr/bin/env python3
"""Read strings/bytes from an ELF32 little-endian ARM shared object by vaddr.

Used only as analysis tooling for the clean-room reimplementation.  Ghidra
addresses in the decompiler dumps are ELF vaddrs + 0x10000 for this image
(image base 0x10000), so pass `--ghidra` to convert.
"""
from __future__ import annotations

import argparse
import struct
import sys

PATH = ("/Users/A92615428/git/GitHub/MaxRink/mahlkoenig-e64ws-local-research/"
        ".tools/firmware-1.16-24/app-tree/bin/libNgxUi.so")


class Elf:
    def __init__(self, path: str) -> None:
        self.data = open(path, "rb").read()
        assert self.data[:4] == b"\x7fELF"
        assert self.data[4] == 1, "ELF32 expected"
        assert self.data[5] == 1, "little-endian expected"
        e_phoff = struct.unpack_from("<I", self.data, 0x1C)[0]
        e_phentsize = struct.unpack_from("<H", self.data, 0x2A)[0]
        e_phnum = struct.unpack_from("<H", self.data, 0x2C)[0]
        self.segments = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from(
                "<IIIII", self.data, off)
            if p_type == 1:  # PT_LOAD
                self.segments.append((p_vaddr, p_offset, p_filesz))

    def read(self, vaddr: int, size: int) -> bytes:
        for p_vaddr, p_offset, p_filesz in self.segments:
            if p_vaddr <= vaddr < p_vaddr + p_filesz:
                delta = vaddr - p_vaddr
                return self.data[p_offset + delta:p_offset + delta + size]
        raise ValueError(f"vaddr 0x{vaddr:x} not mapped")

    def cstr(self, vaddr: int, maxlen: int = 400) -> str:
        raw = self.read(vaddr, maxlen)
        end = raw.find(b"\x00")
        if end >= 0:
            raw = raw[:end]
        return raw.decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("addr", nargs="+", help="address(es), hex or decimal")
    ap.add_argument("--ghidra", action="store_true",
                    help="addresses are Ghidra vaddrs (+0x10000)")
    ap.add_argument("--len", type=int, default=40)
    args = ap.parse_args()
    elf = Elf(PATH)
    for a in args.addr:
        v = int(a, 0)
        if args.ghidra:
            v -= 0x10000
        raw = elf.read(v, args.len)
        print(f"0x{v:08x} ghidra=0x{v + 0x10000:08x}  "
              f"str={elf.cstr(v, args.len)!r}  hex={raw.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
