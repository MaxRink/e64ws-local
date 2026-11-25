"""Filesystem layout and defaults for the virtual grinder.

Everything generated lives under VG_ROOT (default /tmp/virtual-grinder) so the
research repository is never modified.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.environ.get("VG_ROOT", "/tmp/virtual-grinder")).resolve()
# Prebuilt guest binaries (vg-agent, libvgsim.so).  They are not generated, they
# are checked in next to this package, so resolve them from the tool tree rather
# than from VG_ROOT.  A tree staged under VG_ROOT keeps working: the package and
# the guest directory are siblings in that layout too.
TOOL_TREE = Path(__file__).resolve().parents[1]
GUEST = TOOL_TREE / "guest"
WORK = Path(os.environ.get("VG_WORK", ROOT / "work")).resolve()
RUN = Path(os.environ.get("VG_RUN", ROOT / "run")).resolve()

REPO = Path(
    os.environ.get(
        "VG_REPO",
        "/Users/A92615428/git/GitHub/MaxRink/mahlkoenig-e64ws-local-research",
    )
).resolve()

# Vendor firmware extracted by the repository's reproduction steps.
FW = Path(os.environ.get("E64_FW_DIR", REPO / ".tools/firmware-1.16-24")).resolve()
FW_ROOTFS = FW / "rootfs.ext2"
FW_APP = FW / "app_image.ext4"
FW_ROOTFS_TREE = FW / "rootfs-tree"
FW_APP_TREE = FW / "app-tree"

# Reusable kernel/busybox from the repository's QEMU preparation step.
KDIR = Path(os.environ.get("E64_QEMU_DIR", REPO / ".tools/qemu")) / "kernel"

# Generated images.
IMAGES = WORK / "images"
ROOTFS_IMG = IMAGES / "rootfs.ext2"
APP_IMG = IMAGES / "app.ext4"
DB_IMG = IMAGES / "db.ext4"
INITRD = IMAGES / "initrd.img"
DTB = IMAGES / "virt-hsg.dtb"
KERNEL = IMAGES / "vmlinuz"

SERIAL_LOG = WORK / "serial.log"
QEMU_LOG = WORK / "qemu.log"
STATE_FILE = RUN / "state.json"
DAEMON_SOCK = RUN / "vg.sock"
DAEMON_PID = RUN / "vg.pid"
QMP_SOCK = RUN / "qmp.sock"
SERIAL_SOCK = RUN / "serial.sock"
ESP_SOCK = RUN / "esp0.sock"
ESPJSON_SOCK = RUN / "espjson.sock"
AGENT_SOCK = RUN / "agent.sock"

SCREEN_DIR = WORK / "screens"

DEFAULTS = {
    "http_port": int(os.environ.get("VG_HTTP_PORT", "28082")),
    "https_port": int(os.environ.get("VG_HTTPS_PORT", "28443")),
    "wss_port": int(os.environ.get("VG_WSS_PORT", "29997")),
    "qt_vnc_port": int(os.environ.get("VG_QT_VNC_PORT", "25900")),
    "qemu_vnc_port": int(os.environ.get("VG_QEMU_VNC_PORT", "25905")),
    "ssh_port": int(os.environ.get("VG_SSH_PORT", "22222")),
    "control_port": int(os.environ.get("VG_CONTROL_PORT", "28765")),
    "scale_port": int(os.environ.get("VG_SCALE_PORT", "28090")),
}

# Guest-side paths referenced by the vendor binaries (evidence in
# docs/research/stm32-peripheral-dependencies.md and docs/ESP_ROOT_ACCESS.md).
GUEST_ESP_DEV = "/dev/esps0"
GUEST_ESP_UART = "/dev/ttySTM1"
GUEST_ESP_FLASH = "/dev/ttySTM5"
GUEST_AGENT = "/usr/sbin/vg-agent"
GUEST_DB = "/db"


def ensure_dirs() -> None:
    for directory in (WORK, RUN, IMAGES, SCREEN_DIR, ROOT / "guest" / "build"):
        directory.mkdir(parents=True, exist_ok=True)
