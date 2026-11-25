#!/bin/bash
# Cross-build the armhf QML stub with Debian Qt 5.15.2 *headers* but link
# against the firmware's own Qt 5.15.8 + glibc 2.34 libraries, so the binary
# runs inside the vendor rootfs without shipping a parallel userland.
set -e
FW=/Users/A92615428/git/GitHub/MaxRink/mahlkoenig-e64ws-local-research/.tools/firmware-1.16-24
docker run --rm --platform linux/arm64 \
  -v /tmp/qml-recon:/w -v "$FW/rootfs-tree":/rootfs:ro -w /w/build ngxstub-build bash -c '
set -e
CXX=arm-linux-gnueabihf-g++
QTINC=/usr/include/arm-linux-gnueabihf/qt5
INC="-I$QTINC -I$QTINC/QtCore -I$QTINC/QtGui -I$QTINC/QtQml -I$QTINC/QtQuick -I$QTINC/QtNetwork"
LIBDIR="-L/rootfs/usr/lib -L/rootfs/lib"
MOC=/usr/lib/qt5/bin/moc
$MOC -I/usr/include/arm-linux-gnueabihf/qt5 stubs.h -o moc_stubs.cpp
$MOC -I/usr/include/arm-linux-gnueabihf/qt5 main.cpp -o moc_main.cpp
$CXX -O1 -fPIC -std=c++14 $INC -c moc_stubs.cpp -o moc_stubs.o
$CXX -O1 -fPIC -std=c++14 $INC -c main.cpp -o main.o
$CXX -O1 -fPIC -std=c++14 $INC -c moc_main.cpp -o moc_main.o 2>/dev/null || true
$CXX main.o moc_stubs.o moc_main.o -o ngxstub $LIBDIR \
  -Wl,-rpath-link,/rootfs/usr/lib -Wl,-rpath-link,/rootfs/lib \
  -Wl,--dynamic-linker=/lib/ld-linux-armhf.so.3 \
  -static-libstdc++ -static-libgcc \
  -lQt5Quick -lQt5Qml -lQt5Gui -lQt5Core -lQt5Network
arm-linux-gnueabihf-strip ngxstub
ls -la ngxstub
' 
python3 - <<'PY'
import sys; sys.path.insert(0,'/tmp/qml-recon/bin')
from elfview import Elf
import struct
e=Elf('/tmp/qml-recon/build/ngxstub')
ver=e.section('.gnu.version_r')
if ver:
    raw=e.blob[ver['offset']:ver['offset']+ver['size']]
    n=struct.unpack_from('<H',raw,2)[0]
    need=[]
    for i in range(n):
        off=struct.unpack_from('<I',raw,4+16*i)[0]
        s=e.blob.index(b'\0', e.sections[e.e_shstrndx]['offset']+ver['link'] and 0 or 0)
    # simple: list version strings in .dynstr
dyn=e.section('.dynstr'); s=e.blob[dyn['offset']:dyn['offset']+dyn['size']]
import re
print('GLIBC versions:', sorted(set(m.group(0).decode() for m in re.finditer(rb'GLIBC_2\.[0-9]+', s))))
print('GLIBCXX versions:', sorted(set(m.group(0).decode() for m in re.finditer(rb'GLIBCXX_3\.4(\.\d+)?', s))))
PY
