#!/usr/bin/env bash
# Repro-build harness for the Ng2EspApp (Project NG2) ESP32 2nd-stage bootloader.
#
# Variant knobs (all env-overridable):
#   IDF_IMAGE          docker image (default espressif/idf:v5.0  = ESP-IDF v5.0.0)
#   SDE                SOURCE_DATE_EPOCH (default 1780667868 = 2026-06-05 13:57:48 UTC)
#   CONSOLE            "default" | "custom_num1"   (sdkconfig console choice)
#   EXTRA_SDKCONFIG    newline-separated extra "CONFIG_X=y" lines
#   OUT                output dir for bootloader.bin + elf/map (default out)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ROOT:-$HERE}"
IDF_IMAGE="${IDF_IMAGE:-espressif/idf:v5.0}"
SDE="${SDE:-1780667868}"
CONSOLE="${CONSOLE:-default}"
OUT="${OUT:-$ROOT/out}"
TAG="${TAG:-$(basename "$OUT")}"
PROJ="$ROOT/work/proj-$TAG"

rm -rf "$PROJ"; mkdir -p "$PROJ/main" "$OUT"

cat > "$PROJ/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(ng2esp_bootloader)
EOF

cat > "$PROJ/main/CMakeLists.txt" <<'EOF'
idf_component_register(SRCS "main.c")
EOF

echo 'void app_main(void) {}' > "$PROJ/main/main.c"

cat > "$PROJ/partitions.csv" <<'EOF'
# Name,   Type, SubType, Offset,  Size, Flags
nvs,      data, nvs,     0x9000,  0x4000,
phy_init, data, phy,     0xf000,  0x1000,
factory,  app,  factory, 0x10000, 0x200000,
spiflash, data, fat,     0x210000,0x100000,
EOF

{
  echo 'CONFIG_IDF_TARGET="esp32"'
  echo 'CONFIG_ESPTOOLPY_FLASHMODE_DIO=y'
  echo 'CONFIG_ESPTOOLPY_FLASHFREQ_40M=y'
  echo 'CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y'
  echo 'CONFIG_PARTITION_TABLE_CUSTOM=y'
  echo 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"'
  case "$CONSOLE" in
    custom_num1)
      echo 'CONFIG_ESP_CONSOLE_UART_CUSTOM=y'
      echo 'CONFIG_ESP_CONSOLE_UART_CUSTOM_NUM_1=y'
      ;;
    default) : ;;
    *) echo "unknown CONSOLE=$CONSOLE" >&2; exit 2 ;;
  esac
  [ -n "${EXTRA_SDKCONFIG:-}" ] && printf '%s\n' "$EXTRA_SDKCONFIG"
} > "$PROJ/sdkconfig.defaults"

echo "== build tag=$TAG image=$IDF_IMAGE console=$CONSOLE sde=$SDE"
docker run --rm -v "$PROJ":/project -v "$ROOT/work":/w -w /project \
    -e SOURCE_DATE_EPOCH="$SDE" -e PRE_BUILD="${PRE_BUILD:-}" -e HOME=/tmp "$IDF_IMAGE" bash -c \
    'rm -rf /opt/esp/idf/.git; eval "$PRE_BUILD"; idf.py build' > "$ROOT/logs/build-$TAG.log" 2>&1 \
  || { echo "BUILD FAILED"; grep -E 'error:|FAILED|Error' "$ROOT/logs/build-$TAG.log" | head -20; exit 1; }

cp "$PROJ/build/bootloader/bootloader.bin"  "$OUT/bootloader.bin"
cp "$PROJ/build/bootloader/bootloader.elf"  "$OUT/bootloader.elf"
cp "$PROJ/build/bootloader/bootloader.map"  "$OUT/bootloader.map"
cp "$PROJ/build/bootloader/project_description.json" "$OUT/" 2>/dev/null || true
[ -f "$PROJ/sdkconfig" ] && cp "$PROJ/sdkconfig" "$OUT/sdkconfig"
sha256sum "$OUT/bootloader.bin" 2>/dev/null || shasum -a 256 "$OUT/bootloader.bin"
