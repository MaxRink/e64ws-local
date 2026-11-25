"""Build the disposable VM images from the extracted vendor firmware.

Nothing in the research repository is written. Every artifact is copied into
VG_WORK first; the vendor rootfs/app/db images are then patched with debugfs
(no root, no loop mounts).
"""

from __future__ import annotations

import gzip
import io
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import paths

KVER = "6.1.0-50-armmp"

MODULES = [
    "virtio",
    "virtio_mmio",
    "virtio_pci_legacy_dev",
    "virtio_pci_modern_dev",
    "virtio_pci",
    "virtio_blk",
    "virtio_console",
    "failover",
    "net_failover",
    "virtio_net",
    "dummy",
    "evdev",
    "uinput",
    "crc16",
    "crc32c_generic",
    "jbd2",
    "mbcache",
    "ext4",
]

INIT = b"""#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
[ -e /dev/urandom ] || mknod /dev/urandom c 1 9
[ -e /dev/random ] || mknod /dev/random c 1 8
[ -e /dev/ttyAMA0 ] || mknod /dev/ttyAMA0 c 204 64
for m in MODULE_LIST; do
  [ -f /lib/modules/$m.ko ] || continue
  insmod /lib/modules/$m.ko 2>/dev/null
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
    chmod 666 /newroot/dev/ttySTM5 2>/dev/null || true
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


def die(message: str) -> None:
    raise SystemExit(f"vg build: {message}")


def find_tool(name: str) -> str:
    candidates = [
        shutil.which(name),
        f"/opt/homebrew/opt/e2fsprogs/sbin/{name}",
        f"/usr/local/opt/e2fsprogs/sbin/{name}",
        f"/opt/homebrew/sbin/{name}",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    die(f"missing {name} (install e2fsprogs / qemu / dtc)")


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, **kwargs)


# ------------------------------------------------------------------ initrd


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


def build_initrd(force: bool = False) -> Path:
    if paths.INITRD.exists() and not force:
        return paths.INITRD
    kernel = paths.KERNEL
    busybox = paths.KDIR / "busybox"
    if not kernel.is_file():
        src = paths.KDIR / "vmlinuz"
        if not src.is_file():
            die(f"missing kernel at {src}; run tools/qemu_system_boot.sh prepare in the repo first")
        shutil.copy2(src, kernel)
    if not busybox.is_file():
        die(f"missing busybox at {busybox}; run tools/qemu_system_boot.sh prepare first")

    modroot = paths.KDIR / "kx" / "lib" / "modules" / KVER
    entries: list[tuple[str, bytes, int]] = [
        (d, b"", 0o040755) for d in ("dev", "proc", "sys", "newroot", "tmp", "run", "lib/modules")
    ]
    entries.append(("bin/busybox", busybox.read_bytes(), 0o755))
    for module in MODULES:
        source = modroot / f"kernel/**/{module}.ko"
        matches = list(modroot.glob(f"**/{module}.ko"))
        if not matches:
            print(f"  warning: module {module}.ko not found", file=sys.stderr)
            continue
        entries.append((f"lib/modules/{module}.ko", matches[0].read_bytes(), 0o644))
    init = INIT.replace(b"MODULE_LIST", " ".join(MODULES).encode())
    entries.append(("init", init, 0o755))
    data = build_cpio(entries)
    paths.INITRD.parent.mkdir(parents=True, exist_ok=True)
    paths.INITRD.write_bytes(gzip.compress(data, 6))
    print(f"  initrd: {paths.INITRD} ({paths.INITRD.stat().st_size} bytes)")
    return paths.INITRD


# --------------------------------------------------------------------- dtb

HDE = """\n\thde {
\t\tbname = "HEM-HSG-HMI-P01";
\t\tbrev = "210";
\t\tsernr = "0123456789AB";
\t\tproddate = "2026-07-01";
\t\tedpk = [ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ];
\t};
"""


def build_dtb(force: bool = False) -> Path:
    if paths.DTB.exists() and not force:
        return paths.DTB
    qemu = shutil.which("qemu-system-arm")
    dtc = shutil.which("dtc")
    if not qemu or not dtc:
        die("qemu-system-arm and dtc are required")
    paths.DTB.parent.mkdir(parents=True, exist_ok=True)
    base = paths.IMAGES / "virt-base.dtb"
    run([qemu, "-M", "virt,dumpdtb=" + str(base), "-cpu", "cortex-a7", "-m", "1024", "-nographic"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dts = run([dtc, "-I", "dtb", "-O", "dts", "-o", "-", str(base)],
              capture_output=True).stdout
    if "/hde" not in dts:
        marker = dts.rstrip().rfind("\n};")
        if marker < 0:
            die("could not find the root node in the generated DTS")
        dts = dts[:marker] + HDE + dts[marker:]
    # Make sure the kernel gets a command line even if QEMU does not rewrite
    # /chosen for a user-supplied DTB. The dumped DTB already has a /chosen
    # node (stdout-path/rng-seed), so extend it rather than duplicating it.
    if "bootargs" not in dts:
        chosen = dts.find("chosen {")
        if chosen >= 0:
            insert = chosen + len("chosen {")
            dts = dts[:insert] + '\n\t\tbootargs = "console=ttyAMA0,115200 root=/dev/vda rw";' + dts[insert:]
        else:
            node = '\n\tchosen {\n\t\tbootargs = "console=ttyAMA0,115200 root=/dev/vda rw";\n\t};\n'
            marker = dts.rstrip().rfind("\n};")
            dts = dts[:marker] + node + dts[marker:]
    dts_path = paths.IMAGES / "virt-hsg.dts"
    dts_path.write_text(dts)
    run([dtc, "-I", "dts", "-O", "dtb", "-o", str(paths.DTB), str(dts_path)])
    print(f"  dtb:    {paths.DTB}")
    return paths.DTB


# ------------------------------------------------------------------ rootfs


def debugfs_script(image: Path, commands: str) -> None:
    debugfs = find_tool("debugfs")
    with tempfile.NamedTemporaryFile("w", suffix=".debugfs", delete=False) as handle:
        handle.write(commands)
        script = handle.name
    try:
        result = subprocess.run([debugfs, "-w", "-f", script, str(image)],
                                text=True, capture_output=True)
        if result.returncode != 0:
            # debugfs returns non-zero for a missing file in a `rm` line; the
            # caller verifies the critical outputs separately.
            tail = result.stderr.strip().splitlines()
            if tail:
                print(f"  debugfs: {tail[-1]}", file=sys.stderr)
    finally:
        os.unlink(script)


def debugfs_stat(image: Path, guest_path: str) -> str:
    debugfs = find_tool("debugfs")
    result = subprocess.run([debugfs, "-R", f"stat {guest_path}", str(image)],
                            text=True, capture_output=True)
    return result.stdout + result.stderr


def fsck(image: Path, fix: bool = True) -> None:
    """Replay/clear the journal and repair metadata after direct edits.

    debugfs writes do not update ext4 checksums or the journal. If the vendor
    image is copied while its journal is dirty, a later mount replays the old
    metadata and hides (or orphans) the patched files. Always check the copy
    before and after editing.
    """
    binary = find_tool("e2fsck")
    subprocess.run([binary, "-fy" if fix else "-fn", str(image)],
                   text=True, capture_output=True)


def verify_guest_file(image: Path, guest_path: str, min_size: int = 1) -> bool:
    debugfs = find_tool("debugfs")
    result = subprocess.run([debugfs, "-R", f"stat {guest_path}", str(image)],
                            text=True, capture_output=True)
    text = result.stdout + result.stderr
    if "Inode:" not in text:
        return False
    for line in text.splitlines():
        if "Size:" in line:
            tail = line.split("Size:", 1)[1].split()
            if tail:
                try:
                    return int(tail[0]) >= min_size
                except ValueError:
                    return False
    return False


def write_guest_file(image: Path, local: Path, guest_path: str, mode: int = 0o644) -> None:
    # Include S_IFREG in the mode; debugfs `sif mode` replaces the whole i_mode.
    file_mode = 0o100000 | (mode & 0o7777)
    debugfs_script(
        image,
        f"rm {guest_path}\nwrite {local} {guest_path}\nsif {guest_path} mode 0{file_mode:o}\n",
    )


def build_rootfs(force: bool = False) -> Path:
    if paths.ROOTFS_IMG.exists() and not force:
        return paths.ROOTFS_IMG
    if not paths.FW_ROOTFS.is_file():
        die(f"missing vendor rootfs {paths.FW_ROOTFS}")
    paths.ROOTFS_IMG.parent.mkdir(parents=True, exist_ok=True)
    print(f"  rootfs: copying {paths.FW_ROOTFS.name}")
    shutil.copy2(paths.FW_ROOTFS, paths.ROOTFS_IMG)
    fsck(paths.ROOTFS_IMG, fix=True)

    vendor_inittab = (paths.FW_ROOTFS_TREE / "etc/inittab").read_text()
    lines = []
    for line in vendor_inittab.splitlines():
        if line.startswith("::sysinit:/etc/init.d/rcS"):
            lines.append("::sysinit:/sbin/udhcpc -i eth0 -q -n -t 5 2>/dev/null || true")
        lines.append(line)
    if "ttyAMA0" not in vendor_inittab:
        lines.append("ttyAMA0::respawn:/sbin/getty -L ttyAMA0 115200 vt100")
    inittab = "\n".join(lines) + "\n"

    s90 = (paths.FW_ROOTFS_TREE / "etc/init.d/S90app").read_text()
    start_marker = "\tstart)"
    end_marker = "\t\t;;"
    start = s90.index(start_marker)
    end = s90.index(end_marker, start)
    new_start = """\tstart)
\t\t[ -f /db/vg.conf ] && . /db/vg.conf
\t\tif [ "${VG_SHIM:-1}" = "1" ] && [ -f /db/libvgsim.so ]; then
\t\t\texport LD_PRELOAD=/db/libvgsim.so
\t\tfi
\t\texport QT_QPA_PLATFORM="${VG_QT_PLATFORM:-vnc:size=320x480:port=5900}"
\t\techo "S90app: starting $APP_NAME with QT_QPA_PLATFORM=$QT_QPA_PLATFORM"
\t\t$PREPARE_BIN --create --update -S $SERIAL_NO
\t\t$UI_BIN $UI_DEBUG_LEVEL &> /dev/console &
"""
    s90_patched = s90[:start] + new_start + s90[end:]

    s50 = (paths.FW_ROOTFS_TREE / "etc/init.d/S50esp").read_text()
    s50_patched = (
        "#!/bin/sh\n"
        "# vg: the ESP32 is emulated on virtio-serial (host vg daemon).\n"
        "case \"$1\" in\n"
        "start)\n"
        "\tln -sf /dev/vport0p1 /dev/esps0\n"
        "\tchmod 666 /dev/esps0 2>/dev/null || true\n"
        "\t;;\n"
        "esac\n"
        "exit 0\n"
    )

    s00 = """#!/bin/sh
case "$1" in
start)
    mkdir -p /tmp/vg
    if [ -x /usr/sbin/vg-agent ]; then
        /usr/sbin/vg-agent >/dev/console 2>&1 &
    fi
    ;;
esac
exit 0
"""

    issue = (paths.FW_ROOTFS_TREE / "etc/issue").read_text().strip()
    issue_tokens = issue.split()
    if issue_tokens:
        issue_tokens[0] = "development"
    issue_patched = " ".join(issue_tokens) + "\n"

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "inittab").write_text(inittab)
        (tmpdir / "issue").write_text(issue_patched)
        (tmpdir / "S90app").write_text(s90_patched)
        (tmpdir / "S50esp").write_text(s50_patched)
        (tmpdir / "S00vgagent").write_text(s00)
        agent = paths.GUEST / "build/vg-agent"
        if not agent.is_file():
            die(f"missing {agent}; run guest/build.sh")
        commands = [
            f"rm /etc/inittab",
            f"write {tmpdir / 'inittab'} /etc/inittab",
            "sif /etc/inittab mode 0100644",
            f"rm /etc/issue",
            f"write {tmpdir / 'issue'} /etc/issue",
            "sif /etc/issue mode 0100644",
            f"rm /etc/init.d/S00vgagent",
            f"write {tmpdir / 'S00vgagent'} /etc/init.d/S00vgagent",
            "sif /etc/init.d/S00vgagent mode 0100755",
            f"rm /etc/init.d/S50esp",
            f"write {tmpdir / 'S50esp'} /etc/init.d/S50esp",
            "sif /etc/init.d/S50esp mode 0100755",
            f"rm /etc/init.d/S90app",
            f"write {tmpdir / 'S90app'} /etc/init.d/S90app",
            "sif /etc/init.d/S90app mode 0100755",
            f"rm /usr/sbin/vg-agent",
            f"write {agent} /usr/sbin/vg-agent",
            "sif /usr/sbin/vg-agent mode 0100755",
        ]
        debugfs_script(paths.ROOTFS_IMG, "\n".join(commands) + "\n")
    fsck(paths.ROOTFS_IMG, fix=True)
    for guest_path, minimum in (
        ("/usr/sbin/vg-agent", 1000),
        ("/etc/init.d/S00vgagent", 20),
        ("/etc/init.d/S90app", 100),
    ):
        if not verify_guest_file(paths.ROOTFS_IMG, guest_path, minimum):
            die(f"failed to install {guest_path} into the rootfs image")
    print(f"  rootfs: {paths.ROOTFS_IMG} (vendor + S00vgagent, S50esp, S90app)")
    return paths.ROOTFS_IMG


# --------------------------------------------------------------------- app


def patch_ngxui(image: Path) -> bool:
    """Make recoverEcPrivateKey() return NULL instead of dereferencing the
    decrypted EDPK buffer.

    The vendor EDPK is provisioned per machine and cannot be synthesized. With
    an empty EDPK the recovery routine does memcpy(dst, NULL, 68) and crashes.
    This patch is emulation-only and only ever applied to the disposable app
    image copy.
    """
    debugfs = find_tool("debugfs")
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "NgxUiApp"
        subprocess.run([debugfs, "-R", f"dump /bin/NgxUiApp {local}", str(image)],
                       text=True, capture_output=True)
        if not local.is_file():
            return False
        data = bytearray(local.read_bytes())
        offset = 0x1853C  # recoverEcPrivateKey, .text VMA == file offset
        original = bytes.fromhex("30402de9")
        if len(data) < offset + 12:
            return False
        if data[offset:offset + 4] == bytes.fromhex("0030a0e3003080e5"):
            return True  # already patched
        if data[offset:offset + 4] != original:
            print(f"  warning: unexpected NgxUiApp prologue at 0x{offset:x}", file=sys.stderr)
            return False
        # mov r3,#0 ; str r3,[r0] ; bx lr
        data[offset:offset + 12] = bytes.fromhex("0030a0e3003080e51eff2fe1")
        local.write_bytes(data)
        write_guest_file(image, local, "/bin/NgxUiApp", 0o755)
    return True


def patch_libngxui(image: Path) -> bool:
    """Skip EspUartDriver::processInitialCommunicationCheck().

    The check decides whether the ESP application firmware must be updated.
    A virtual grinder has no ESP flash to update, and the JSON-over-pty
    handshake is timing sensitive; skipping the check keeps the HMI on the
    normal UI instead of the update-abort screen. Emulation-only.
    """
    debugfs = find_tool("debugfs")
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "libNgxUi.so"
        subprocess.run([debugfs, "-R", f"dump /bin/libNgxUi.so {local}", str(image)],
                       text=True, capture_output=True)
        if not local.is_file():
            return False
        data = bytearray(local.read_bytes())
        offset = 0x1D8B80
        bx_lr = bytes.fromhex("1eff2fe1")
        if len(data) < offset + 4:
            return False
        if data[offset:offset + 4] == bx_lr:
            return True
        if data[offset:offset + 4] != bytes.fromhex("a4229fe5"):
            print(f"  warning: unexpected libNgxUi prologue at 0x{offset:x}", file=sys.stderr)
            return False
        data[offset:offset + 4] = bx_lr
        local.write_bytes(data)
        write_guest_file(image, local, "/bin/libNgxUi.so", 0o755)
    return True


def build_app(force: bool = False) -> Path:
    if paths.APP_IMG.exists() and not force:
        return paths.APP_IMG
    if not paths.FW_APP.is_file():
        die(f"missing vendor app image {paths.FW_APP}")
    print(f"  app:    copying {paths.FW_APP.name}")
    shutil.copy2(paths.FW_APP, paths.APP_IMG)
    fsck(paths.APP_IMG, fix=True)
    ngstart = """#!/bin/sh
[ -f /db/vg.conf ] && . /db/vg.conf
if [ "${VG_SHIM:-1}" = "1" ] && [ -f /db/libvgsim.so ]; then
    export LD_PRELOAD=/db/libvgsim.so
fi
export QT_QPA_PLATFORM="${VG_QT_PLATFORM:-vnc:size=320x480:port=5900}"
killall -9 -q NgxUiApp
NgxUiApp -D 2 -t $1 $2 $3 $4 $5 $6 $7 $8 $9
"""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ngstart"
        path.write_text(ngstart)
        write_guest_file(paths.APP_IMG, path, "/bin/ngstart", 0o755)
    fsck(paths.APP_IMG, fix=True)
    if not verify_guest_file(paths.APP_IMG, "/bin/ngstart", 100):
        die("failed to patch /bin/ngstart in the app image")
    if not patch_ngxui(paths.APP_IMG):
        die("failed to patch NgxUiApp's EDPK recovery path")
    if not patch_libngxui(paths.APP_IMG):
        die("failed to patch libNgxUi's ESP update check")
    fsck(paths.APP_IMG, fix=True)
    print(f"  app:    {paths.APP_IMG} (ngstart patched, EDPK recovery nulled, ESP update check skipped)")
    return paths.APP_IMG


# ---------------------------------------------------------------------- db


def _seed_db(stage: Path) -> None:
    seed = paths.REPO / ".tools/qemu/db.ext4"
    if not seed.is_file():
        return
    debugfs = find_tool("debugfs")
    for name in ("HsgSqlite.db", "HsgConfig.json"):
        out = stage / name
        subprocess.run([debugfs, "-R", f"dump /{name} {out}", str(seed)],
                       text=True, capture_output=True)
        if out.is_file() and out.stat().st_size > 0:
            print(f"  db:     seeded {name} ({out.stat().st_size} bytes)")
        elif out.exists():
            out.unlink()


def build_db(force: bool = False) -> Path:
    if paths.DB_IMG.exists() and not force:
        return paths.DB_IMG
    stage = paths.WORK / "db-stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    cert = paths.FW_APP_TREE / "www/cert"
    for name in ("webui.crt", "webui.key"):
        if (cert / name).is_file():
            shutil.copy2(cert / name, stage / name)
    _seed_db(stage)
    config = stage / "HsgConfig.json"
    if not config.exists():
        config.write_text('{"id": 0, "grinderType": 0, "grinderSubType": 0}\n')
    shim = paths.GUEST / "build/libvgsim.so"
    if not shim.is_file():
        die(f"missing {shim}; run guest/build.sh")
    shutil.copy2(shim, stage / "libvgsim.so")
    (stage / "vg.conf").write_text(
        "# virtual-grinder runtime configuration (disposable VM only)\n"
        "VG_SHIM=1\n"
        "VG_QT_PLATFORM=vnc:size=320x480:port=5900\n"
    )
    (stage / "lockedDdStore.json").write_text(
        '{"ddValue": 12000, "locked": true}\n'
    )
    (stage / "wifiConfig.json").write_text(
        '{\n'
        '  "apSsid": "E64-WS-VIRTUAL",\n'
        '  "apPassword": "virtual-grinder",\n'
        '  "apIp": "192.168.4.1",\n'
        '  "staSsid": "",\n'
        '  "staPassword": "",\n'
        '  "staDhcp": true,\n'
        '  "staStaticGateway": "",\n'
        '  "staStaticDns": "",\n'
        '  "staStaticIp": "",\n'
        '  "staStaticNetmask": ""\n'
        '}\n'
    )
    (stage / "resolv.conf").write_text("nameserver 10.0.2.3\n")
    mke2fs = find_tool("mke2fs")
    run([mke2fs, "-q", "-t", "ext4", "-d", str(stage), "-L", "db", str(paths.DB_IMG), "64M"],
        stdout=subprocess.DEVNULL)
    fsck(paths.DB_IMG, fix=True)
    if not verify_guest_file(paths.DB_IMG, "/libvgsim.so", 1000):
        die("db image is missing libvgsim.so")
    print(f"  db:     {paths.DB_IMG} (cert, config, shim)")
    return paths.DB_IMG


# --------------------------------------------------------------------- all


def build_all(force: bool = False) -> dict:
    paths.ensure_dirs()
    print("building virtual grinder images")
    build_initrd(force)
    build_dtb(force)
    build_rootfs(force)
    build_app(force)
    build_db(force)
    for path in (paths.KERNEL, paths.INITRD, paths.DTB, paths.ROOTFS_IMG, paths.APP_IMG, paths.DB_IMG):
        if not path.exists():
            die(f"missing artifact {path}")
    return {
        "kernel": str(paths.KERNEL),
        "initrd": str(paths.INITRD),
        "dtb": str(paths.DTB),
        "rootfs": str(paths.ROOTFS_IMG),
        "app": str(paths.APP_IMG),
        "db": str(paths.DB_IMG),
    }
