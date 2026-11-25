#!/usr/bin/env python3
import struct,sys,hashlib,collections

def sec(path,name):
    d=open(path,'rb').read(); shoff=struct.unpack_from('<I',d,32)[0]
    ents=struct.unpack_from('<H',d,46)[0]; n=struct.unpack_from('<H',d,48)[0]; si=struct.unpack_from('<H',d,50)[0]
    raw=[struct.unpack_from('<IIIIIIIIII',d,shoff+i*ents) for i in range(n)]
    st=raw[si]; strs=d[st[4]:st[4]+st[5]]
    for nm,typ,fl,addr,off,size,link,info,align,ent in raw:
        if strs[nm:strs.find(b'\0',nm)].decode()==name:
            return d[off:off+size]
a=sec(sys.argv[1],'.text'); b=sec(sys.argv[2],'.text')
bs=32; win=3000
bm={}
for k in range(0,len(b)-bs+1,bs):
    bm.setdefault(hashlib.sha256(b[k:k+bs]).digest(),[]).append(k)
prof=[]
for k in range(0,len(a)-bs+1,bs):
    h=hashlib.sha256(a[k:k+bs]).digest()
    cands=bm.get(h)
    if not cands: 
        prof.append((k,None)); continue
    best=min(cands,key=lambda p:abs((p-k)-(-760)))
    prof.append((k,best-k))
hist=collections.Counter(s for _,s in prof if s is not None)
print('shift histogram (top 10):',hist.most_common(10))
print('unmatched blocks:',sum(1 for _,s in prof if s is None),'of',len(prof))
# print shift transitions
last=None
for k,s in prof:
    if s!=last:
        print(f'  at text+0x{k:05x} shift -> {s}')
        last=s
