#!/usr/bin/env python3
import re, sys, collections

def strings(path, minlen=4):
    d = open(path, 'rb').read()
    return [m.group().decode('latin1') for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, d)]

a = collections.Counter(strings(sys.argv[1]))
b = collections.Counter(strings(sys.argv[2]))
only_a = a - b
only_b = b - a
print(f"unique strings: A={len(a)} B={len(b)}")
print("--- only in A ---")
for s, n in sorted(only_a.items())[:80]:
    print(f"{n:3d} {s!r}")
print("--- only in B ---")
for s, n in sorted(only_b.items())[:80]:
    print(f"{n:3d} {s!r}")
