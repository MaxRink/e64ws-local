#!/bin/bash
set -euo pipefail
SRC=/work/zlib-1.2.12
BR=/work/buildroot-2022.02.3
TC=${TC:-/work/toolchain-out}
OUT=${OUT:-/work/out/zlib}
ARCHFLAGS=${ARCHFLAGS:--mcpu=cortex-a7 -mfpu=vfpv4-d16 -mfloat-abi=hard}
OPT=${OPT:--O3}
mkdir -p "$OUT"
rm -rf "$SRC"; mkdir -p "$SRC"
tar xzf /work/dl/zlib-1.2.12.tar.gz -C /work
cd "$SRC"
patch -p1 < "$BR/package/libzlib/0001-Fix-configure-issue-that-discarded-provided-CC-definition.patch" >/dev/null
export PATH="$TC/host/bin:$PATH"
CC=arm-buildroot-linux-gnueabihf-gcc
CFLAGS="-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $OPT -g0 -D_FORTIFY_SOURCE=2 $ARCHFLAGS -fPIC"
CFLAGS="$CFLAGS" CC="$CC" ./configure --shared --prefix=/usr >/dev/null
make -j"$(nproc)" CC="$CC" CFLAGS="$CFLAGS" >/dev/null
cp libz.so.1.2.12 "$OUT/libz.so.1.2.12.unstripped"
"${CC%gcc}strip" --strip-all --remove-section=.comment libz.so.1.2.12 -o "$OUT/libz.so.1.2.12"
sha256sum "$OUT/libz.so.1.2.12" "$OUT/libz.so.1.2.12.unstripped"
ls -l "$OUT/libz.so.1.2.12"
