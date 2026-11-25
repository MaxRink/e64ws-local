#!/usr/bin/env python3
"""Coarse .text comparison: longest common prefix/suffix and unmatched 64-byte blocks."""
import struct, sys, hashlib

def section(path, want):
    d = open(path,'rb').read()
    shoff = struct.unpack_from('<I', d, 32)[0]
    ents = struct.unpack_from('<H', d, 46)[0]
    n = struct.unpack_from('<H', d, 48)[0]
    si = struct.unpack_from('<H', d, 50)[0]
    def sh(i):
        return struct.unpack_from('<IIIIIIIIII', d, shoff+i*ents)
    st = sh(si); strs = d[st[4]:st[4]+st[5]]
    for i in range(n):
        nm, typ, fl, addr, off, size, *_ = sh(i)
        name = strs[nm:strs.find(b'\0',nm)].decode()
        if name == want:
            return d[off:off+size]
    raise SystemExit(f"no {want}")

a = section(sys.argv[1], '.text')
b = section(sys.argv[2], '.text')
print(f"text sizes: A={len(a)} B={len(b)} delta={len(a)-len(b)}")
i = 0
while i < min(len(a),len(b)) and a[i] == b[i]:
    i += 1
print(f"common prefix: {i} bytes (0x{i:x})")
j = 0
while j < min(len(a),len(b))-i and a[-1-j] == b[-1-j]:
    j += 1
print(f"common suffix: {j} bytes")
# 64-byte block matching
bs = 64
bh = {}
for k in range(0, len(b)-bs+1, bs):
    bh.setdefault(hashlib.sha256(b[k:k+bs]).digest(), []).append(k)
unmatched = []
for k in range(0, len(a)-bs+1, bs):
    if hashlib.sha256(a[k:k+bs]).digest() not in bh:
        unmatched.append(k)
print(f"unmatched 64B blocks: {len(unmatched)} of {len(a)//bs} ({100*len(unmatched)*bs/len(a):.1f}% of A)")
# group contiguous unmatched blocks
groups=[]
for k in unmatched:
    if groups and k == groups[-1][1]:
        groups[-1][1] = k+bs
    else:
        groups.append([k,k+bs])
print("unmatched ranges (first 40):")
for s,e in groups[:40]:
    print(f"  A 0x{s:06x}-0x{e:06x} ({e-s} B)")
