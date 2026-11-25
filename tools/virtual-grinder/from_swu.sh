#!/bin/sh
# Build a virtual grinder from a vendor SWU, without reusing the repository's
# extracted firmware tree.
#
#   ./from_swu.sh [path/to/firmware.swu] [target-dir]
#
# Default target: /tmp/vg-swu. The script extracts the cpio members, unpacks the
# rootfs/app ext4 images, extracts their trees, then runs `vg build --force`.
# The DB image is still a fixture (the SWU carries no /db); it is seeded from
# the repository's QEMU fixture and documented as such.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SWU="${1:-/tmp/all-firmware/downloads/HEM-HSG-HMI-S01-V01.16-24.swu}"
OUT="${2:-/tmp/vg-swu}"
DEBUGFS="${DEBUGFS:-$(command -v debugfs || true)}"
for candidate in /opt/homebrew/opt/e2fsprogs/sbin/debugfs /opt/homebrew/sbin/debugfs; do
    [ -n "$DEBUGFS" ] && break
    [ -x "$candidate" ] && DEBUGFS="$candidate"
done
[ -n "$DEBUGFS" ] || { echo "from_swu: debugfs not found (install e2fsprogs)" >&2; exit 1; }
[ -f "$SWU" ] || { echo "from_swu: missing SWU $SWU" >&2; exit 1; }

echo "from_swu: $SWU"
rm -rf "$OUT"
mkdir -p "$OUT/raw" "$OUT/fw" "$OUT/vm"
bsdtar -xf "$SWU" -C "$OUT/raw"

gunzip -c "$OUT/raw/images.standard.rootfs.ext2.gz" > "$OUT/fw/rootfs.ext2"
gunzip -c "$OUT/raw/images.standard.app_image.ext4.gz" > "$OUT/fw/app_image.ext4"
mkdir -p "$OUT/fw/rootfs-tree" "$OUT/fw/app-tree"
"$DEBUGFS" -R "rdump / $OUT/fw/rootfs-tree" "$OUT/fw/rootfs.ext2" >/dev/null 2>&1
"$DEBUGFS" -R "rdump / $OUT/fw/app-tree" "$OUT/fw/app_image.ext4" >/dev/null 2>&1

# The guest binaries are built from tools/virtual-grinder/guest; the VM tree
# only needs them under $VG_ROOT/guest/build.
mkdir -p "$OUT/vm/guest"
ln -s "$HERE/guest/build" "$OUT/vm/guest/build"
ln -s "$HERE/vgrinder" "$OUT/vm/vgrinder"

echo "from_swu: building fresh VM under $OUT/vm"
VG_ROOT="$OUT/vm" \
VG_REPO="$REPO" \
E64_FW_DIR="$OUT/fw" \
E64_QEMU_DIR="$REPO/.tools/qemu" \
    "$REPO/tools/virtual-grinder/vg" build --force

echo "from_swu: build complete"
echo "  start:  VG_ROOT=$OUT/vm E64_FW_DIR=$OUT/fw $REPO/tools/virtual-grinder/vg up"
echo "  device: development-mode /etc/issue, seeded lockedDdStore, IIO fixtures"
