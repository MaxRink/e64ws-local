#!/bin/bash
# Boot the E64 WS rootfs in QEMU with the QML stub payload on /dev/vdd.
#
#   /tmp/qml-recon/bin/run_vm.sh <stub-dir> <out-dir> [extra args]
#
# <stub-dir> holds the payload (ngxstub + res/); it is packed into an ext2
# image that the guest mounts at /mnt/stub.  Screenshots and the log land in
# <out-dir> after the guest powers off.
set -euo pipefail
export PATH=/opt/homebrew/opt/e2fsprogs/sbin:$PATH

REPO=/Users/A92615428/git/GitHub/MaxRink/mahlkoenig-e64ws-local-research
QDIR=$REPO/.tools/qemu
WORK=/tmp/qml-recon/vm
PAYLOAD=${1:?payload dir}
OUT=${2:?out dir}
mkdir -p "$OUT" "$WORK"

STUB_IMG=$WORK/stub.ext2
[ -f "$WORK/db.ext4" ] || cp "$QDIR/db.ext4" "$WORK/db.ext4"   # guest writes here
rm -f "$STUB_IMG"
mkdir -p "$PAYLOAD/shots"
mke2fs -q -t ext2 -d "$PAYLOAD" -L stub "$STUB_IMG" 65536   # 64 MiB

LOG=$OUT/console.log
: > "$LOG"

timeout 240 qemu-system-arm \
  -M virt -cpu cortex-a7 -m 1024 \
  -kernel "$QDIR/kernel/vmlinuz" -initrd "$QDIR/kernel/initrd-img" \
  -append "console=ttyAMA0,115200 root=/dev/vda rw" \
  -drive id=root,file="$WORK/rootfs.ext2",format=raw,if=none \
  -device virtio-blk-device,drive=root \
  -drive id=app,file="$QDIR/app-virt-hsg.ext4",format=raw,if=none,readonly=on \
  -device virtio-blk-device,drive=app \
  -drive id=db,file="$WORK/db.ext4",format=raw,if=none \
  -device virtio-blk-device,drive=db \
  -drive id=stub,file="$STUB_IMG",format=raw,if=none \
  -device virtio-blk-device,drive=stub \
  -netdev "user,id=net0,hostfwd=tcp::15900-:5900,hostfwd=tcp::12222-:22" \
  -device virtio-net-device,netdev=net0 \
  -nographic -no-reboot >> "$LOG" 2>&1 || true

# pull artefacts back out of the ext2 payload image
for f in $(debugfs -R "ls -l /shots" "$STUB_IMG" 2>/dev/null | awk '{print $NF}' | grep -E '\.(png|log|txt)$'); do
  debugfs -R "dump /shots/$f $OUT/$f" "$STUB_IMG" 2>/dev/null || true
done
debugfs -R "cat /log.txt" "$STUB_IMG" 2>/dev/null > "$OUT/app.log" || true
echo "--- console tail"
tail -25 "$LOG"
echo "--- artefacts"
ls -la "$OUT"
