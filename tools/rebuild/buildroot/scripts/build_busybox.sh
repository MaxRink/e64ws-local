#!/bin/bash
# Build BusyBox 1.35.0 the way the vendor's Buildroot build did, then strip like the vendor image.
set -euo pipefail
export KCONFIG_NOTIMESTAMP=1
SRC=${SRC:-/work/busybox-1.35.0}
BR=${BR:-/work/buildroot-2022.02.3}
TC=${TC:-/work/toolchain-out}
OUT=${OUT:-/work/out/busybox}
OPT=${OPT:--O3}
TARGET_CPU_FLAGS=${TARGET_CPU_FLAGS:--march=armv7-a -mfpu=vfpv4-d16 -mfloat-abi=hard}
EXTRA_CFLAGS=${EXTRA_CFLAGS:-}
mkdir -p "$OUT"
cd "$SRC"
make distclean >/dev/null 2>&1 || true
cp "$BR/package/busybox/busybox.config" .config
python3 /work/scripts/set_config.py .config '{"CONFIG_BLOCKDEV":"y","CONFIG_FTPGET":"y","CONFIG_FTPPUT":"y","CONFIG_IOSTAT":"y","CONFIG_RDEV":"y","CONFIG_FREE":"n","CONFIG_IFDOWN":"n","CONFIG_IFUP":"n","CONFIG_IP":"n","CONFIG_IPADDR":"n","CONFIG_IPLINK":"n","CONFIG_IPNEIGH":"n","CONFIG_IPROUTE":"n","CONFIG_IPRULE":"n","CONFIG_IPTUNNEL":"n","CONFIG_KILL":"n","CONFIG_KILLALL5":"n","CONFIG_PIDOF":"n","CONFIG_PS":"n","CONFIG_BB_SYSCTL":"n","CONFIG_TAR":"n","CONFIG_TOP":"n","CONFIG_UPTIME":"n","CONFIG_WATCH":"n","CONFIG_USE_BB_CRYPT_SHA":"y","CONFIG_FEATURE_DD_THIRD_STATUS_LINE":"y","CONFIG_FEATURE_DEFAULT_PASSWD_ALGO":"\"sha256\""}'
if [ -n "${EXTRA_CONFIG_JSON:-}" ]; then
  python3 /work/scripts/set_config.py .config "$EXTRA_CONFIG_JSON"
fi
make oldconfig </dev/null >/dev/null
export PATH="$TC/host/bin:$PATH"
CROSS=arm-buildroot-linux-gnueabihf-
CFLAGS="-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $OPT -g0 -D_FORTIFY_SOURCE=2 $TARGET_CPU_FLAGS $EXTRA_CFLAGS"
# Buildroot passes CFLAGS through the environment; BusyBox's Makefile then appends
# its own flags (-Os, -fno-builtin-printf, -ffunction-sections, ...).
CFLAGS="$CFLAGS" make -j"$(nproc)" ARCH=arm CROSS_COMPILE="$CROSS" \
  AR="${CROSS}ar" NM="${CROSS}nm" RANLIB="${CROSS}ranlib" CC="${CROSS}gcc" \
  EXTRA_LDFLAGS="${LDFLAGS_EXTRA:-}" SKIP_STRIP=y >/dev/null
cp busybox "$OUT/busybox.unstripped"
"${CROSS}strip" --strip-all --remove-section=.comment busybox -o "$OUT/busybox"
"${CROSS}strip" --strip-all --remove-section=.none busybox -o "$OUT/busybox.striponly" 2>/dev/null || true
sha256sum "$OUT/busybox.unstripped" "$OUT/busybox"
ls -l "$OUT/busybox.unstripped" "$OUT/busybox"
