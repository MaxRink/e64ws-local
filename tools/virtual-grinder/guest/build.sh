#!/bin/sh
# Build the guest-side binaries in arm32v7 containers.
#
#   vg-agent      static musl armhf  (runs in the VM)
#   libvgsim.so   glibc 2.31 armhf   (LD_PRELOAD into the vendor HMI)
#
# Outputs: guest/build/vg-agent, guest/build/libvgsim.so
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/build"
mkdir -p "$out"

echo "== building vg-agent (static, arm32v7/musl) =="
docker run --rm --platform linux/arm/v7 \
    -v "$here:/src" -w /src \
    alpine:3.20 sh -c '
        apk add --no-cache gcc musl-dev linux-headers >/dev/null
        gcc -static -O2 -Wall -Wextra -pthread -o /src/build/vg-agent /src/vg-agent.c
    '

echo "== building libvgsim.so (arm32v7/glibc, needs GLIBC_2.34) =="
docker run --rm --platform linux/arm/v7 \
    -v "$here:/src" -w /src \
    debian:12 sh -c '
        apt-get update -qq >/dev/null
        apt-get install -y -qq gcc libc6-dev >/dev/null
        gcc -shared -fPIC -O2 -Wall -Wextra -o /src/build/libvgsim.so /src/vg-sim.c -ldl -pthread
    '

ls -l "$out"
file "$out"/* 2>/dev/null || true
