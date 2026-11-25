#!/usr/bin/env python3
"""Minimal ELF32/64 reader (no external deps) for libNgxUi.so analysis."""
from __future__ import annotations

import struct
import sys


class Elf:
    def __init__(self, path: str):
        self.path = path
        self.blob = open(path, "rb").read()
        b = self.blob
        if b[:4] != b"\x7fELF":
            raise SystemExit("not an ELF")
        self.is64 = b[4] == 2
        self.end = "<" if b[5] == 1 else ">"
        if not self.is64:
            (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
             self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
                self.end + "HHIIIIIHHHHHH", b, 16)
        else:
            (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
             self.e_shoff) = struct.unpack_from(self.end + "HHIQQQ", b, 16)
            (self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
                self.end + "IHHHHHH", b, 48)
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if not self.is64:
                (name, typ, flags, addr, offset, size, link, info, align,
                 entsize) = struct.unpack_from(self.end + "IIIIIIIIII", b, off)
            else:
                (name, typ, flags, addr, offset, size, link, info, align,
                 entsize) = struct.unpack_from(self.end + "IIQQQQIIQQ", b, off)
            self.sections.append(dict(index=i, name_off=name, type=typ, flags=flags,
                                      addr=addr, offset=offset, size=size,
                                      link=link, info=info, align=align,
                                      entsize=entsize))
        shstr = self.sections[self.e_shstrndx]
        for s in self.sections:
            s["name"] = self.cstr(shstr["offset"] + s["name_off"])
        self.phdrs = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if not self.is64:
                (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags,
                 p_align) = struct.unpack_from(self.end + "IIIIIIII", b, off)
            else:
                (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
                 p_align) = struct.unpack_from(self.end + "IIQQQQQQ", b, off)
            self.phdrs.append(dict(type=p_type, offset=p_offset, vaddr=p_vaddr,
                                   filesz=p_filesz, memsz=p_memsz, flags=p_flags))
        self.symbols = self._read_syms()
        self._by_addr = None

    def cstr(self, offset: int) -> str:
        end = self.blob.index(b"\0", offset)
        return self.blob[offset:end].decode("utf-8", "replace")

    def section(self, name: str):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def _read_syms(self):
        sym = self.section(".symtab")
        if not sym:
            sym = self.section(".dynsym")
            strtab = self.sections[sym["link"]]
        else:
            strtab = self.section(".strtab")
        out = []
        entsize = sym["entsize"]
        for i in range(sym["size"] // entsize):
            off = sym["offset"] + i * entsize
            if not self.is64:
                name, value, size, info, other, shndx = struct.unpack_from(
                    self.end + "IIIBBH", self.blob, off)
            else:
                name, info, other, shndx, value, size = struct.unpack_from(
                    self.end + "IBBHQQ", self.blob, off)
            out.append(dict(index=i, name=self.cstr(strtab["offset"] + name),
                            value=value, size=size, info=info,
                            bind=info >> 4, type=info & 0xF, shndx=shndx))
        return out

    def va_to_off(self, va: int):
        for p in self.phdrs:
            if p["type"] == 1 and p["vaddr"] <= va < p["vaddr"] + p["filesz"]:
                return p["offset"] + (va - p["vaddr"])
        for s in self.sections:
            if s["type"] != 8 and s["addr"] and s["addr"] <= va < s["addr"] + s["size"]:
                return s["offset"] + (va - s["addr"])
        return None

    def read_va(self, va: int, size: int) -> bytes:
        off = self.va_to_off(va)
        if off is None:
            raise KeyError(hex(va))
        return self.blob[off:off + size]

    def sym_by_name(self, name: str):
        return [s for s in self.symbols if s["name"] == name]


if __name__ == "__main__":
    e = Elf(sys.argv[1])
    print(f"{'idx':>3} {'name':<20} {'addr':>10} {'off':>10} {'size':>10} type")
    for s in e.sections:
        print(f"{s['index']:>3} {s['name']:<20} {s['addr']:>#10x} {s['offset']:>#10x} "
              f"{s['size']:>#10x} {s['type']}")
    print("--- phdrs")
    for p in e.phdrs:
        print(f"type={p['type']} off={p['offset']:#x} vaddr={p['vaddr']:#x} "
              f"filesz={p['filesz']:#x} memsz={p['memsz']:#x}")
    print(f"--- symbols: {len(e.symbols)}")
