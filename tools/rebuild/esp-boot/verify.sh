#!/usr/bin/env bash
# One-shot verification: rebuild the Ng2EspApp ESP32 bootloader from public
# sources and compare it byte-for-byte with the vendor image.
#
#   ./verify.sh            # rebuild + compare
#   ./verify.sh --quiet    # compare only, using out/console2/bootloader.bin
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$HERE/out/target-bootloader.bin"
EXPECT="7802748598c2c7f253d6cd905917ada84222489d0ca1994d924009a0bf737304"

# The vendor bootloader is not committed. Extract it from the firmware tree on
# first run if it is present; otherwise fail with the exact path to supply.
if [ ! -f "$TARGET" ]; then
  SRC="${VENDOR_TREE:-$HERE/../../../.tools/firmware-1.16-24}/app-tree/esp/bootloader.bin"
  if [ -f "$SRC" ]; then
    mkdir -p "$HERE/out"
    cp "$SRC" "$TARGET"
    echo "target: extracted $SRC"
  else
    echo "target missing: $TARGET" >&2
    echo "extract it with: cp <firmware>/app-tree/esp/bootloader.bin $TARGET" >&2
    exit 2
  fi
fi

if [ "${1:-}" != "--quiet" ]; then
  OUT="$HERE/out/console2" TAG=console2 CONSOLE=custom_num1 \
  EXTRA_SDKCONFIG='CONFIG_ESP_CONSOLE_UART_TX_GPIO=18
CONFIG_ESP_CONSOLE_UART_RX_GPIO=19' \
  "$HERE/build.sh"
fi

B="$HERE/out/console2/bootloader.bin"
echo
echo "target : $(shasum -a 256 "$TARGET" | cut -d' ' -f1)  $(stat -f%z "$TARGET" 2>/dev/null || stat -c%s "$TARGET") bytes"
echo "rebuild: $(shasum -a 256 "$B"      | cut -d' ' -f1)  $(stat -f%z "$B" 2>/dev/null || stat -c%s "$B") bytes"
echo "expected rebuild sha256: $EXPECT"
if cmp -s "$TARGET" "$B"; then
  echo "RESULT: 100.00% byte-identical ($(stat -f%z "$B" 2>/dev/null || stat -c%s "$B") / $(stat -f%z "$B" 2>/dev/null || stat -c%s "$B") bytes)"
else
  echo "RESULT: MISMATCH"; cmp -l "$TARGET" "$B" | head; exit 1
fi
