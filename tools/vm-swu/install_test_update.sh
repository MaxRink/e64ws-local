#!/bin/sh
# Generate, sign and install a tiny test SWU on the disposable VM.
#
#   tools/vm-swu/install_test_update.sh [out-dir]
#
# The VM's HSG anchor is replaced with the generated public key. This is a
# deliberate root-only trust change on a disposable image; it is not a vendor
# key and must never be used on hardware.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${1:-/tmp/vm-swu-test}"
VG_ROOT="${VG_ROOT:-/tmp/vg-swu/vm}"
E64_FW_DIR="${E64_FW_DIR:-/tmp/vg-swu/fw}"
export VG_ROOT E64_FW_DIR

python3 "$HERE/make_test_swu.py" --out "$OUT"

KEY=$(base64 -i "$OUT/test-signing.pub" | tr -d '\n')
SWU=$(base64 -i "$OUT/test-update.swu" | tr -d '\n')

"$REPO/tools/virtual-grinder/vg" shell "mount -o remount,rw / 2>/dev/null || true; [ -f /tmp/hem-hsg-orig.pub ] || cp /etc/keys/hem-hsg-swupdate-key.pub /tmp/hem-hsg-orig.pub; echo $KEY | base64 -d > /etc/keys/hem-hsg-swupdate-key.pub; echo $SWU | base64 -d > /tmp/test-update.swu; ls -l /tmp/test-update.swu"
"$REPO/tools/virtual-grinder/vg" shell "swupdate -c -v -i /tmp/test-update.swu -k /etc/keys/hem-hsg-swupdate-key.pub -H STM32MP15x:1.0 > /tmp/test-check.log 2>&1; echo check=\$?; grep -E 'Verified|compatible|ERROR' /tmp/test-check.log | tail -4"
"$REPO/tools/virtual-grinder/vg" shell "swupdate -i /tmp/test-update.swu -k /etc/keys/hem-hsg-swupdate-key.pub -H STM32MP15x:1.0 -m -M > /tmp/test-install.log 2>&1; echo install=\$?; tail -3 /tmp/test-install.log"

echo "test package: $OUT/test-update.swu"
echo "restore anchor: cp /tmp/hem-hsg-orig.pub /etc/keys/hem-hsg-swupdate-key.pub"
