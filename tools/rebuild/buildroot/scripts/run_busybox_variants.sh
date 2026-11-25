#!/bin/bash
# Build BusyBox variants and record size/hash/section sizes.
set -u
cd /work
OUTCSV=/work/results/busybox_variants.csv
echo "variant,bytes,sha256,text,rodata,needed,notes" > "$OUTCSV"
run() {
  name=$1; shift
  src=/work/bb-$name
  rm -rf "$src"; cp -a /work/busybox-1.35.0 "$src"
  env SRC="$src" OUT="/work/out/bb-$name" "$@" >/dev/null 2>&1 || { echo "$name,BUILD_FAILED" >> "$OUTCSV"; return; }
  bin=/work/out/bb-$name/busybox
  [ -f "$bin" ] || { echo "$name,NO_BINARY" >> "$OUTCSV"; return; }
  txt=$(readelf -SW "$bin" | awk '$2==".text"{print strtonum("0x"$6)}')
  rod=$(readelf -SW "$bin" | awk '$2==".rodata"{print strtonum("0x"$6)}')
  need=$(readelf -d "$bin" 2>/dev/null | grep -c NEEDED)
  printf "%s,%s,%s,%s,%s,%s,%s\n" "$name" "$(stat -c%s "$bin")" "$(sha256sum "$bin" | cut -d' ' -f1)" "$txt" "$rod" "$need" "$*" >> "$OUTCSV"
}
run base env TARGET_CPU_FLAGS="-march=armv7ve -mfpu=vfpv4-d16 -mfloat-abi=hard" bash /work/scripts/build_busybox.sh
# -O2 / -O3: patch BusyBox's own -Os default
for opt in O2 O3; do
  src=/work/bb-$opt; rm -rf "$src"; cp -a /work/busybox-1.35.0 "$src"
  sed -i "s/-Os,\$(call cc-option,-O2,)/-$opt,\$(call cc-option,-O2,)/" "$src/Makefile.flags"
  env SRC="$src" OUT="/work/out/bb-$opt" TARGET_CPU_FLAGS="-march=armv7ve -mfpu=vfpv4-d16 -mfloat-abi=hard" bash /work/scripts/build_busybox.sh >/dev/null 2>&1
  bin=/work/out/bb-$opt/busybox
  printf "%s,%s,%s,%s,%s,%s,%s\n" "-$opt" "$(stat -c%s $bin)" "$(sha256sum $bin|cut -d' ' -f1)" "$(readelf -SW $bin|awk '$2==".text"{print strtonum("0x"$6)}')" "$(readelf -SW $bin|awk '$2==".rodata"{print strtonum("0x"$6)}')" "$(readelf -d $bin|grep -c NEEDED)" "patched Makefile.flags" >> "$OUTCSV"
done
run lto env TARGET_CPU_FLAGS="-march=armv7ve -mfpu=vfpv4-d16 -mfloat-abi=hard" EXTRA_CFLAGS="-flto" LDFLAGS_EXTRA="-flto" bash /work/scripts/build_busybox.sh
run static env TARGET_CPU_FLAGS="-march=armv7ve -mfpu=vfpv4-d16 -mfloat-abi=hard" EXTRA_CONFIG_JSON='{"CONFIG_STATIC":"y"}' bash /work/scripts/build_busybox.sh
run thumb env TARGET_CPU_FLAGS="-march=armv7ve -mfpu=vfpv4-d16 -mfloat-abi=hard" EXTRA_CFLAGS="-mthumb" bash /work/scripts/build_busybox.sh
run nopie env TARGET_CPU_FLAGS="-march=armv7ve -mfpu=vfpv4-d16 -mfloat-abi=hard" EXTRA_CFLAGS="-fno-PIE" LDFLAGS_EXTRA="-no-pie" bash /work/scripts/build_busybox.sh
run relrofull env TARGET_CPU_FLAGS="-march=armv7ve -mfpu=vfpv4-d16 -mfloat-abi=hard" LDFLAGS_EXTRA="-Wl,-z,now" bash /work/scripts/build_busybox.sh
run ssp-regular env TARGET_CPU_FLAGS="-march=armv7ve -mfpu=vfpv4-d16 -mfloat-abi=hard" EXTRA_CFLAGS="-fstack-protector" bash /work/scripts/build_busybox.sh
run ssp-none env TARGET_CPU_FLAGS="-march=armv7ve -mfpu=vfpv4-d16 -mfloat-abi=hard" EXTRA_CFLAGS="-fno-stack-protector" bash /work/scripts/build_busybox.sh
cat "$OUTCSV"
