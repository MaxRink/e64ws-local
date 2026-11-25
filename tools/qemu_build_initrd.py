#!/usr/bin/env python3
"""Build a minimal initramfs that mounts the vendor rootfs and switches into it.

Used by tools/qemu_system_boot.sh. The Debian armmp kernel ships virtio-blk and
ext4 as modules, so the initramfs carries those .ko files and a small /init.

Usage: qemu_build_initrd.py KDEP_DIR OUTPUT
"""

from __future__ import annotations

import gzip
import io
import pathlib
import sys

KVER = "6.1.0-50-armmp"

MODULES = [
    ("kernel/drivers/virtio/virtio_mmio.ko", "virtio_mmio.ko"),
    ("kernel/drivers/virtio/virtio_pci_legacy_dev.ko", "virtio_pci_legacy_dev.ko"),
    ("kernel/drivers/virtio/virtio_pci_modern_dev.ko", "virtio_pci_modern_dev.ko"),
    ("kernel/drivers/virtio/virtio_pci.ko", "virtio_pci.ko"),
    ("kernel/drivers/block/virtio_blk.ko", "virtio_blk.ko"),
    ("kernel/net/core/failover.ko", "failover.ko"),
    ("kernel/drivers/net/net_failover.ko", "net_failover.ko"),
    ("kernel/drivers/net/virtio_net.ko", "virtio_net.ko"),
    ("kernel/lib/crc16.ko", "crc16.ko"),
    ("kernel/crypto/crc32c_generic.ko", "crc32c_generic.ko"),
    ("kernel/fs/jbd2/jbd2.ko", "jbd2.ko"),
    ("kernel/fs/mbcache.ko", "mbcache.ko"),
    ("kernel/fs/ext4/ext4.ko", "ext4.ko"),
]

INIT = b"""#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
[ -e /dev/urandom ] || mknod /dev/urandom c 1 9
[ -e /dev/random ] || mknod /dev/random c 1 8
[ -e /dev/ttyAMA0 ] || mknod /dev/ttyAMA0 c 204 64
for m in virtio virtio_mmio virtio_pci_legacy_dev virtio_pci_modern_dev virtio_pci virtio_blk failover net_failover virtio_net crc16 crc32c_generic jbd2 mbcache ext4; do
  [ -f /lib/modules/$m.ko ] || continue
  insmod /lib/modules/$m.ko
done
sleep 1
for dev in /dev/vda /dev/vdb /dev/vdc /dev/vdd; do
  [ -b "$dev" ] || continue
  mount -t ext4 -o rw "$dev" /newroot 2>/dev/null || continue
  if [ -x /newroot/sbin/init ] && [ -d /newroot/usr/local ]; then
    echo "initramfs: root filesystem is $dev"
    mount -t devtmpfs dev /newroot/dev 2>/dev/null || true
    mount -t tmpfs -o mode=1777 tmpfs /newroot/tmp 2>/dev/null || true
    mkdir -p /newroot/log && mount -t tmpfs -o mode=1777 tmpfs /newroot/log 2>/dev/null || true
    [ -e /newroot/dev/ttySTM5 ] || mknod /newroot/dev/ttySTM5 c 1 3
    chmod 666 /newroot/dev/ttySTM5
    [ -e /newroot/dev/urandom ] || mknod /newroot/dev/urandom c 1 9
    for extra in /dev/vda /dev/vdb /dev/vdc /dev/vdd; do
      [ -b "$extra" ] || continue
      [ "$extra" = "$dev" ] && continue
      if mount -t ext4 -o ro "$extra" /newroot/usr/local 2>/dev/null; then
        if [ -f /newroot/usr/local/www/login.php ]; then
          echo "initramfs: app image is $extra"
          continue
        fi
        umount /newroot/usr/local
      fi
      if mount -t ext4 -o rw "$extra" /newroot/db 2>/dev/null; then
        if [ -f /newroot/db/webui.crt ]; then
          echo "initramfs: db volume is $extra"
          continue
        fi
        umount /newroot/db
      fi
    done
    echo "initramfs: switching root"
    exec switch_root /newroot /sbin/init
  fi
  umount /newroot
done
echo "initramfs: no vendor root filesystem found; dropping to shell"
exec /bin/sh
"""


def build_cpio(entries: list[tuple[str, bytes, int]]) -> bytes:
    out = io.BytesIO()
    ino = 1

    def write(name: str, data: bytes, mode: int) -> None:
        nonlocal ino
        name_b = name.encode()
        header = b"070701" + b"".join(
            f"{value:08x}".encode()
            for value in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_b) + 1, 0)
        )
        out.write(header)
        out.write(name_b + b"\x00")
        out.write(b"\x00" * ((4 - out.tell() % 4) % 4))
        out.write(data)
        out.write(b"\x00" * ((4 - out.tell() % 4) % 4))
        ino += 1

    dirs: set[str] = set()
    for path, _, _ in entries:
        parts = path.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    for directory in sorted(dirs):
        write(directory, b"", 0o040755)
    for path, data, mode in entries:
        write(path, data, mode if mode & 0o170000 else mode | 0o100000)
    write("TRAILER!!!", b"", 0)
    return out.getvalue()


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    kdir = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    modroot = kdir / "kx" / "lib" / "modules" / KVER
    busybox = kdir / "busybox"

    if not busybox.is_file():
        print(f"missing busybox at {busybox}", file=sys.stderr)
        return 1

    entries: list[tuple[str, bytes, int]] = [
        (d, b"", 0o040755) for d in ("dev", "proc", "sys", "newroot", "tmp", "run")
    ]
    entries.append(("bin/busybox", busybox.read_bytes(), 0o755))
    for source, name in MODULES:
        module = modroot / source
        if module.is_file():
            entries.append((f"lib/modules/{name}", module.read_bytes(), 0o644))
        else:
            print(f"warning: missing module {source}", file=sys.stderr)
    entries.append(("init", INIT, 0o755))

    data = build_cpio(entries)
    output.write_bytes(gzip.compress(data, 6))
    print(f"initramfs: {output} ({len(data)} bytes, {output.stat().st_size} gzipped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
