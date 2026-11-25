#!/usr/bin/env python3
"""Compare two ELF files: overall bytes and per-section sizes/hashes."""
import hashlib, struct, sys

def sections(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'\x7fELF' and d[4] == 1, 'ELF32 only'
    e_shoff = struct.unpack_from('<I', d, 32)[0]
    e_shentsize = struct.unpack_from('<H', d, 46)[0]
    e_shnum = struct.unpack_from('<H', d, 48)[0]
    e_shstrndx = struct.unpack_from('<H', d, 50)[0]
    def sh(i):
        o = e_shoff + i * e_shentsize
        return struct.unpack_from('<IIIIIIIIII', d, o)
    st = sh(e_shstrndx)
    strs = d[st[4]:st[4]+st[5]]
    def name(n):
        return strs[n:strs.find(b'\0', n)].decode()
    out = {}
    for i in range(e_shnum):
        nm, typ, flags, addr, off, size, link, info, align, ent = sh(i)
        out[name(nm)] = dict(addr=addr, off=off, size=size, data=d[off:off+size])
    return d, out

def main(a, b):
    da, sa = sections(a); db, sb = sections(b)
    print(f"A {a}: {len(da)} bytes  sha256={hashlib.sha256(da).hexdigest()}")
    print(f"B {b}: {len(db)} bytes  sha256={hashlib.sha256(db).hexdigest()}")
    print(f"{'section':20s} {'sizeA':>10s} {'sizeB':>10s}  {'hashA':12s} {'hashB':12s} same")
    for nm in sorted(set(sa) | set(sb)):
        x = sa.get(nm); y = sb.get(nm)
        if not x or not y:
            print(f"{nm:20s} {'MISSING' if not x else x['size']:>10} {'MISSING' if not y else y['size']:>10}")
            continue
        ha = hashlib.sha256(x['data']).hexdigest()[:12]
        hb = hashlib.sha256(y['data']).hexdigest()[:12]
        print(f"{nm:20s} {x['size']:10d} {y['size']:10d}  {ha} {hb} {'YES' if ha==hb else 'no'}")

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
