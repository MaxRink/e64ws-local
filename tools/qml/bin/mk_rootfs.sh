#!/bin/bash
# Build a bootable, patched copy of the vendor rootfs for the QML stub run.
# The vendor image is ext4 with a live journal, so every debugfs write has to
# be followed by a journal replay (e2fsck), otherwise the mount undoes it.
set -euo pipefail
export PATH=/opt/homebrew/opt/e2fsprogs/sbin:$PATH

FW=/Users/A92615428/git/GitHub/MaxRink/mahlkoenig-e64ws-local-research/.tools/firmware-1.16-24
W=/tmp/qml-recon/vm
IMG=$W/rootfs.ext2
STUB=$W/bootstub.sh

cp "$FW/rootfs.ext2" "$IMG"
e2fsck -fy "$IMG" >/dev/null 2>&1 || true

debugfs -w -R "rm /etc/init.d/S90app" "$IMG" >/dev/null 2>&1 || true
debugfs -R "cat /etc/inittab" "$IMG" 2>/dev/null | sed 's|^::sysinit:/opt/bootstub.sh$||' > "$W/inittab.cur"
printf '::sysinit:/sbin/udhcpc -i eth0 -q -n -t 5 2>/dev/null || true\n' >> "$W/inittab.cur"
printf '::sysinit:/bin/sh /opt/bootstub.sh\n' >> "$W/inittab.cur"
printf 'ttyAMA0::respawn:/sbin/getty -L ttyAMA0 115200 vt100\n' >> "$W/inittab.cur"
chmod 644 "$W/inittab.cur"
debugfs -w -R "rm /etc/inittab" "$IMG" >/dev/null 2>&1 || true
debugfs -w -R "write $W/inittab.cur /etc/inittab" "$IMG" >/dev/null
debugfs -w -R "rm /opt/bootstub.sh" "$IMG" >/dev/null 2>&1 || true
debugfs -w -R "write $STUB /opt/bootstub.sh" "$IMG" >/dev/null
INODE=$(debugfs -R "stat /opt/bootstub.sh" "$IMG" 2>/dev/null | sed -n 's/^Inode: \([0-9]*\).*/\1/p')
debugfs -w -R "sif $INODE mode 0100755" "$IMG" >/dev/null 2>&1 || true
INODE2=$(debugfs -R "stat /etc/inittab" "$IMG" 2>/dev/null | sed -n 's/^Inode: \([0-9]*\).*/\1/p')
debugfs -w -R "sif $INODE2 mode 0100644" "$IMG" >/dev/null 2>&1 || true

e2fsck -fy "$IMG" >/dev/null 2>&1 || true
echo "rootfs patched:"
debugfs -R "stat /opt/bootstub.sh" "$IMG" 2>/dev/null | sed -n '1,3p'
debugfs -R "cat /etc/inittab" "$IMG" 2>/dev/null | tail -4
