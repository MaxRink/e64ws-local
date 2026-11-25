#!/usr/bin/env python3
"""Match functions from an unstripped ELF against a stripped binary's .text."""
import struct, sys

def elf(path):
    d=open(path,'rb').read()
    shoff=struct.unpack_from('<I',d,32)[0]; ents=struct.unpack_from('<H',d,46)[0]
    n=struct.unpack_from('<H',d,48)[0]; si=struct.unpack_from('<H',d,50)[0]
    raw=[struct.unpack_from('<IIIIIIIIII',d,shoff+i*ents) for i in range(n)]
    st=raw[si]; strs=d[st[4]:st[4]+st[5]]
    seclist=[]; secs={}
    for i,(nm,typ,fl,addr,off,size,link,info,align,ent) in enumerate(raw):
        name=strs[nm:strs.find(b'\0',nm)].decode()
        rec=dict(name=name,addr=addr,off=off,size=size,link=link,ent=ent,data=d[off:off+size],idx=i)
        seclist.append(rec); secs[name]=rec
    return d,secs,seclist

def funcs(path):
    d,s,sl=elf(path)
    syms=s.get('.symtab')
    if not syms: raise SystemExit('no symtab')
    strtab=sl[syms['link']]['data']
    out=[]
    for o in range(0,syms['size'],syms['ent']):
        name,val,size,info,other,shndx=struct.unpack_from('<IIIBBH',syms['data'],o)
        if (info&0xf)==2 and size>0:
            nm=strtab[name:strtab.find(b'\0',name)].decode()
            out.append((nm,val,size))
    return d,s,sl,out

A=sys.argv[1]; B=sys.argv[2]
da,sa,sla,fs=funcs(A)
_,sb,slb=elf(B)
text=sb['.text']['data']; aaddr=sa['.text']['addr']; atext=sa['.text']['data']
matched=0; matched_bytes=0; unmatched=[]
total=0
for nm,val,size in fs:
    if not (aaddr <= val < aaddr+len(atext)): continue
    total+=size
    code=atext[val-aaddr:val-aaddr+size]
    if text.find(code)>=0:
        matched+=1; matched_bytes+=size
    else:
        unmatched.append((size,nm,val))
print(f"functions={len(fs)} text_bytes={total} matched_functions={matched} matched_bytes={matched_bytes} ({100*matched_bytes/total:.2f}%)")
print(f"unmatched functions={len(unmatched)} bytes={sum(x[0] for x in unmatched)}")
for size,nm,val in sorted(unmatched, reverse=True)[:40]:
    print(f"  {size:6d}  {nm}  @0x{val-aaddr:x}")
