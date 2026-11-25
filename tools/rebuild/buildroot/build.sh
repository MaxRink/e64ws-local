#!/bin/bash
# =============================================================================
# e64ws / MMI-SW.640 userland reproduction harness
#
# Reproduces the two packages that are feasible from public sources:
#   * BusyBox 1.35.0  (target: /bin/busybox)
#   * zlib 1.2.12     (target: /usr/lib/libz.so.1.2.12)
#
# The vendor toolchain is not public.  This harness builds the closest
# matching toolchain that can be inferred from the shipped binaries:
#   - Buildroot 2022.02.3, GCC 10.3.0, binutils 2.36.1, glibc 2.34, headers 5.10
#   - generic ARMv7-A defaults for the toolchain itself (--with-arch=armv7-a,
#     --with-fpu=vfpv3-d16, no --with-cpu)
#   - packages compiled with -march=armv7ve -mtune=cortex-a7 -mfpu=vfpv4-d16
#
# Usage:
#   ./build.sh                 # full run (toolchain ~20-30 min)
#   SKIP_TOOLCHAIN=1 ./build.sh   # reuse an existing toolchain in the volume
#   FW_ROOT=/path/to/rootfs-tree ./build.sh
#   RUN_MATRIX=1 ./build.sh    # also rebuild the flag-matrix variants
# =============================================================================
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
FW_ROOT=${FW_ROOT:-/Users/A92615428/git/GitHub/MaxRink/mahlkoenig-e64ws-local-research/.tools/firmware-1.16-24/rootfs-tree}
IMAGE=${IMAGE:-e64-repro-builder}
VOLUME=${VOLUME:-e64-repro-work}
BR_VERSION=2022.02.3
BB_VERSION=1.35.0
ZLIB_VERSION=1.2.12
if [ -z "${JOBS:-}" ]; then
    if command -v sysctl >/dev/null 2>&1 && sysctl -n hw.ncpu >/dev/null 2>&1; then
        JOBS=$(sysctl -n hw.ncpu)
    else
        JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
    fi
fi

BR_TARBALL=buildroot-${BR_VERSION}.tar.gz
BB_TARBALL=busybox-${BB_VERSION}.tar.bz2
ZLIB_TARBALL=zlib-${ZLIB_VERSION}.tar.gz
BR_SHA=1e87ef8ecbd24c26725295874a29b364538904caa241f9f72135c28a13a010ff
BB_SHA=faeeb244c35a348a334f4a59e44626ee870fb07b6884d68c10ae8bc19f83a694
ZLIB_SHA=91844808532e5ce316b3c010929493c0244f3d37593afd6de04f71821d5136d9

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is required"
mkdir -p "$ROOT/dl" "$ROOT/src" "$ROOT/results"

# ---------------------------------------------------------------------------
# 1. Container image
# ---------------------------------------------------------------------------
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "Building container image $IMAGE"
    docker build -t "$IMAGE" -f "$ROOT/docker/Dockerfile" "$ROOT/docker"
fi

# ---------------------------------------------------------------------------
# 2. Downloads
# ---------------------------------------------------------------------------
checksum() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

fetch() {
    url=$1; file=$2; sha=$3
    if [ -f "$ROOT/dl/$file" ] && [ "$(checksum "$ROOT/dl/$file")" = "$sha" ]; then
        log "Using cached $file"
        return
    fi
    log "Downloading $file"
    curl -fL --retry 3 -o "$ROOT/dl/$file.tmp" "$url"
    [ "$(checksum "$ROOT/dl/$file.tmp")" = "$sha" ] || die "checksum mismatch for $file"
    mv "$ROOT/dl/$file.tmp" "$ROOT/dl/$file"
}

fetch "https://buildroot.org/downloads/$BR_TARBALL" "$BR_TARBALL" "$BR_SHA"
fetch "https://busybox.net/downloads/$BB_TARBALL" "$BB_TARBALL" "$BB_SHA"
fetch "https://zlib.net/fossils/$ZLIB_TARBALL" "$ZLIB_TARBALL" "$ZLIB_SHA"

# ---------------------------------------------------------------------------
# 3. Extract and patch Buildroot / BusyBox on the host
# ---------------------------------------------------------------------------
if [ ! -d "$ROOT/src/buildroot-$BR_VERSION" ]; then
    log "Extracting Buildroot $BR_VERSION"
    tar xzf "$ROOT/dl/$BR_TARBALL" -C "$ROOT/src"
fi
if [ ! -d "$ROOT/src/busybox-$BB_VERSION" ]; then
    log "Extracting BusyBox $BB_VERSION"
    tar xjf "$ROOT/dl/$BB_TARBALL" -C "$ROOT/src"
fi

# The inferred vendor toolchain has generic ARMv7-A defaults (no --with-cpu)
# while packages are compiled with -mcpu/-march=cortex-a7.  Buildroot's
# cortex-A7 entry normally passes --with-cpu=cortex-a7, so suppress that.
ARM_CONFIG="$ROOT/src/buildroot-$BR_VERSION/arch/Config.in.arm"
if ! grep -q 'e64ws: generic ARMv7-A toolchain' "$ARM_CONFIG"; then
    log "Patching Buildroot: empty GCC target CPU for cortex-A7"
    python3 - "$ARM_CONFIG" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
needle = "config BR2_GCC_TARGET_CPU\n"
assert needle in s
s = s.replace(needle, needle + "\t# e64ws: generic ARMv7-A toolchain\n\tdefault \"\"\tif BR2_cortex_a7\n", 1)
open(p, "w").write(s)
PY
fi

cp "$ROOT/configs/e64_toolchain_generic_defconfig" \
   "$ROOT/src/buildroot-$BR_VERSION/configs/"
# Force --with-arch=armv7-a for the toolchain itself.  The shipped libc and
# libstdc++ were built for generic ARMv7-A (libstdc++ Tag_CPU_name "7-A"),
# while packages are compiled with -march=armv7ve/-mcpu=cortex-a7.
GCC_MK="$ROOT/src/buildroot-$BR_VERSION/package/gcc/gcc.mk"
if ! grep -q 'e64ws: force ARMv7-A arch' "$GCC_MK"; then
    log "Patching Buildroot: force --with-arch=armv7-a"
    python3 - "$GCC_MK" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
needle = 'ifneq ($(GCC_TARGET_ARCH),)\nHOST_GCC_COMMON_CONF_OPTS += --with-arch="$(GCC_TARGET_ARCH)"\nendif\n'
assert needle in s
add = 'ifeq ($(BR2_cortex_a7),y)\nHOST_GCC_COMMON_CONF_OPTS += --with-arch=armv7-a\nendif\n'
if 'e64ws: force ARMv7-A arch' not in s:
    s = s.replace(needle, needle + '# e64ws: force ARMv7-A arch\n' + add, 1)
    open(p, 'w').write(s)
PY
fi


# ---------------------------------------------------------------------------
# 4. Populate the Docker volume (native Linux filesystem: much faster than a
#    macOS bind mount, where kconfig can take minutes instead of <1 s)
# ---------------------------------------------------------------------------
log "Populating volume $VOLUME"
docker volume create "$VOLUME" >/dev/null
docker run --rm -v "$VOLUME":/work -v "$ROOT":/host "$IMAGE" bash -c '
    set -e
    rm -rf /work/buildroot-b
    cp -a /host/src/buildroot-'"$BR_VERSION"' /work/buildroot-b
    rm -rf /work/busybox-'"$BB_VERSION"'
    cp -a /host/src/busybox-'"$BB_VERSION"' /work/busybox-'"$BB_VERSION"'
    mkdir -p /work/dl /work/out /work/results /work/scripts
    cp -a /host/dl/. /work/dl/
    cp -a /host/scripts/. /work/scripts/
'

# ---------------------------------------------------------------------------
# 5. Toolchain (generic ARMv7-A, glibc 2.34, GCC 10.3.0, -Os, reproducible)
# ---------------------------------------------------------------------------
if [ "${SKIP_TOOLCHAIN:-0}" = "1" ]; then
    log "SKIP_TOOLCHAIN=1: reusing existing toolchain"
else
    log "Building toolchain (this takes 20-30 minutes)"
    docker run --rm -v "$VOLUME":/work -w /work/buildroot-b "$IMAGE" bash -c '
        set -e
        make O=/work/toolchain-c-out BR2_DL_DIR=/work/dl e64_toolchain_generic_defconfig
        make O=/work/toolchain-c-out BR2_DL_DIR=/work/dl -j'"$JOBS"' toolchain
    '
fi

# ---------------------------------------------------------------------------
# 6. Build BusyBox and zlib
# ---------------------------------------------------------------------------
log "Building BusyBox 1.35.0"
docker run --rm -v "$VOLUME":/work -e TC=/work/toolchain-c-out "$IMAGE" bash -c '
    set -e
    export TC=/work/toolchain-c-out
    export TARGET_CPU_FLAGS="-march=armv7ve -mtune=cortex-a7 -mfpu=vfpv4-d16 -mfloat-abi=hard"
    export BR=/work/buildroot-b
    export OUT=/work/out/busybox
    bash /work/scripts/build_busybox.sh
'

log "Building zlib 1.2.12"
docker run --rm -v "$VOLUME":/work "$IMAGE" bash -c '
    set -e
    export TC=/work/toolchain-c-out
    export ARCHFLAGS="-march=armv7ve -mtune=cortex-a7 -mfpu=vfpv4-d16 -mfloat-abi=hard"
    export BR=/work/buildroot-b
    export OUT=/work/out/zlib
    bash /work/scripts/build_zlib.sh
'

if [ "${RUN_MATRIX:-0}" = "1" ]; then
    log "Running BusyBox flag matrix"
    docker run --rm -v "$VOLUME":/work "$IMAGE" bash -c 'bash /work/scripts/run_busybox_variants.sh'
fi

# ---------------------------------------------------------------------------
# 7. Copy artifacts back and compare
# ---------------------------------------------------------------------------
log "Copying artifacts to $ROOT/results"
docker run --rm -v "$VOLUME":/work -v "$ROOT":/host "$IMAGE" bash -c '
    set -e
    mkdir -p /host/results/busybox /host/results/zlib /host/results/toolchain
    cp /work/out/busybox/busybox /host/results/busybox/
    cp /work/out/busybox/busybox.unstripped /host/results/busybox/
    cp /work/busybox-'"$BB_VERSION"'/.config /host/results/busybox/busybox.config
    cp /work/out/zlib/libz.so.1.2.12 /host/results/zlib/
    cp /work/out/zlib/libz.so.1.2.12.unstripped /host/results/zlib/
    cp /work/toolchain-c-out/.config /host/results/toolchain/toolchain-c.config
    [ -f /work/results/busybox_variants.csv ] && cp /work/results/busybox_variants.csv /host/results/ || true
'

log "Comparing with $FW_ROOT"
FW_ROOT="$FW_ROOT" python3 "$ROOT/scripts/make_results.py"

log "Done.  Results in $ROOT/results"
cat "$ROOT/results/diff_ranges.txt"
