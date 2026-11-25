#!/usr/bin/env bash
# Boot the extracted E64 WS rootfs as a virtual machine under qemu-system-arm.
#
# The vendor kernel is an STM32MP1 BSP image and does not run on QEMU's `virt`
# machine (no mach-virt support, no console). This script instead uses a
# Debian armhf `armmp` kernel with a small initramfs that loads virtio-blk and
# switches into the vendor rootfs.
#
# Virtual hardware:
#   vda  vendor rootfs copy (writable, virt-adapted)
#   vdb  vendor application image  -> /usr/local
#   vdc  fresh ext4 db volume      -> /db
#   net  user-mode networking, host TCP 18082 -> guest 80 (web UI)
#   Qt   the HMI's own VNC platform plugin is available for a virtual display
#
# Usage:
#   tools/qemu_system_boot.sh prepare   fetch kernel deps and build images
#   tools/qemu_system_boot.sh run       boot (serial console on stdio)
#   tools/qemu_system_boot.sh run --graphics   also attach a VNC display
#   tools/qemu_system_boot.sh clean
#
# Evidence and limits are documented in docs/QEMU_SYSTEM_BOOT.md.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fw="${E64_FW_DIR:-$root/.tools/firmware-1.16-24}"
work="${E64_QEMU_DIR:-$root/.tools/qemu}"
kdir="$work/kernel"
rootfs_src="$fw/rootfs-tree"
app_img="${E64_APP_IMAGE:-$fw/app_image.ext4}"
www="$fw/app-tree/www"
rootfs_img="$work/rootfs-virt.ext2"
db_img="$work/db.ext4"
initrd="$kdir/initrd-img"
kernel="$kdir/vmlinuz"

KVER=6.1.0-50-armmp
KDEB="linux-image-${KVER}_6.1.176-1_armhf.deb"
KURL="https://deb.debian.org/debian/pool/main/l/linux/${KDEB}"
BURL="https://deb.debian.org/debian/pool/main/b/busybox/busybox-static_1.35.0-4+deb12u1+b1_armhf.deb"

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || { [[ -x "/opt/homebrew/opt/e2fsprogs/sbin/$1" ]] && export PATH="/opt/homebrew/opt/e2fsprogs/sbin:$PATH" || die "missing $1"; }; }

prepare_kernel() {
    need curl; need ar; need tar; need python3
    mkdir -p "$kdir"
    if [[ ! -f "$kdir/busybox" ]]; then
        ( cd "$kdir" && curl -fsSLO "$BURL" && mkdir -p bb && cd bb && ar x "../$(basename "$BURL")" && tar -xf data.tar.* && cp bin/busybox ../busybox )
    fi
    if [[ ! -f "$kernel" ]]; then
        ( cd "$kdir" && curl -fsSLO "$KURL" && mkdir -p kx && cd kx && ar x "../$KDEB" && tar -xf data.tar.* && cp "boot/vmlinuz-$KVER" ../vmlinuz && cp "boot/config-$KVER" ../config )
    fi
    if [[ ! -f "$initrd" ]]; then
        mkdir -p "$kdir/kx"
        [[ -d "$kdir/kx/lib" ]] || ( cd "$kdir/kx" && ar x "../$KDEB" && tar -xf data.tar.* )
        python3 "$root/tools/qemu_build_initrd.py" "$kdir" "$initrd"
    fi
}

prepare_images() {
    [[ -d "$rootfs_src" ]] || die "extract the firmware first (docs/REPRODUCTION.md)"
    need debugfs; need mke2fs
    mkdir -p "$work"
    if [[ ! -f "$rootfs_img" ]]; then
        echo "building virt-adapted rootfs (byte copy + debugfs patch)"
        cp "$fw/rootfs.ext2" "$rootfs_img"
        python3 - "$rootfs_src/etc/inittab" "$work/inittab.new" <<'PYGEN'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_text().splitlines()
out = []
for line in src:
    if line.startswith("::sysinit:/etc/init.d/rcS"):
        out.append("::sysinit:/sbin/udhcpc -i eth0 -q -n -t 5 2>/dev/null || true")
    out.append(line)
out.append("ttyAMA0::respawn:/sbin/getty -L ttyAMA0 115200 vt100")
pathlib.Path(sys.argv[2]).write_text("\n".join(out) + "\n")
PYGEN
        chmod 644 "$work/inittab.new"
        debugfs -w -R "rm /etc/inittab" "$rootfs_img" >/dev/null 2>&1 || true
        debugfs -w -R "write $work/inittab.new /etc/inittab" "$rootfs_img" >/dev/null
    fi
    if [[ ! -f "$db_img" ]]; then
        rm -rf "$work/db-stage"; mkdir -p "$work/db-stage"
        cp "$www/cert/webui.crt" "$www/cert/webui.key" "$work/db-stage/" 2>/dev/null || true
        mke2fs -q -t ext4 -d "$work/db-stage" -L db "$db_img" 64M
    fi
}

run_qemu() {
    local graphics=0
    local port="${E64_QEMU_PORT:-18082}"
    local https_port="${E64_QEMU_HTTPS_PORT:-18443}"
    local vnc_port="${E64_QEMU_VNC_PORT:-15900}"
    local ssh_port="${E64_QEMU_SSH_PORT:-12222}"
    local mqtt_port="${E64_QEMU_MQTT_PORT:-11883}"
    [[ "${1:-}" == "--graphics" ]] && graphics=1
    local args=(
        -M virt -cpu cortex-a7 -m 1024
        -kernel "$kernel" -initrd "$initrd"
        -append "console=ttyAMA0,115200 root=/dev/vda rw"
        -drive id=root,file="$rootfs_img",format=raw,if=none
        -device virtio-blk-device,drive=root
        -drive id=app,file="$app_img",format=raw,if=none,readonly=on
        -device virtio-blk-device,drive=app
        -drive id=db,file="$db_img",format=raw,if=none
        -device virtio-blk-device,drive=db
        -netdev "user,id=net0,hostfwd=tcp::${port}-:80,hostfwd=tcp::${https_port}-:443,hostfwd=tcp::${vnc_port}-:5900,hostfwd=tcp::${ssh_port}-:22,hostfwd=tcp::${mqtt_port}-:1883"
        -device virtio-net-device,netdev=net0
        -nographic -no-reboot
    )
    [[ -n "${E64_DTB:-}" ]] && args+=(-dtb "$E64_DTB")
    if [[ $graphics -eq 1 ]]; then
        args+=(-device virtio-gpu-device -vnc 127.0.0.1:5)
        echo "VNC display on 127.0.0.1:5905 (Qt VNC plugin also listens on guest :5900)"
    fi
    echo "web UI: http://127.0.0.1:${port}/login.php (HTTPS ${https_port})"
    echo "HMI VNC: vnc://127.0.0.1:${vnc_port}"
    echo "SSH: ssh -p ${ssh_port} root@127.0.0.1"
    echo "MQTT: tcp://127.0.0.1:${mqtt_port}"
    exec qemu-system-arm "${args[@]}"
}

case "${1:-run}" in
    prepare) prepare_kernel; prepare_images; echo "prepared under $work" ;;
    run) prepare_kernel; prepare_images; shift || true; run_qemu "${1:-}" ;;
    clean) rm -rf "$work"; echo "removed $work" ;;
    *) die "usage: $0 [prepare|run [--graphics]|clean]" ;;
esac
