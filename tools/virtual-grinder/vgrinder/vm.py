"""QEMU lifecycle for the virtual grinder."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from . import paths
from .qmp import QMP, QMPError


class VMError(RuntimeError):
    pass


def qemu_binary() -> str:
    real = shutil.which("qemu-system-arm")
    if not real:
        raise VMError("qemu-system-arm not found (brew install qemu)")
    # Run through a differently named symlink. Concurrent tooling in this
    # workspace uses `pkill -f qemu-system-arm`, which would otherwise kill
    # this VM mid-run.
    alias = paths.WORK / "bin" / "vg-qemu"
    alias.parent.mkdir(parents=True, exist_ok=True)
    if not alias.exists() or alias.resolve() != Path(real).resolve():
        try:
            alias.unlink()
        except FileNotFoundError:
            pass
        alias.symlink_to(real)
    return str(alias)


class VM:
    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.qmp = QMP(paths.QMP_SOCK)
        self.started_at: float | None = None
        self.qt_size = os.environ.get("VG_QT_SIZE", "320x480")

    # ------------------------------------------------------------ command

    def command(self) -> list[str]:
        d = paths.DEFAULTS
        chardevs = [
            f"socket,id=serial0,path={paths.SERIAL_SOCK},server=on,wait=off,logfile={paths.SERIAL_LOG}",
            f"socket,id=esp0,path={paths.ESP_SOCK},server=on,wait=off",
            f"socket,id=espjson,path={paths.ESPJSON_SOCK},server=on,wait=off",
            f"socket,id=agent,path={paths.AGENT_SOCK},server=on,wait=off",
        ]
        args = [
            qemu_binary(),
            "-M", "virt",
            "-cpu", "cortex-a7",
            "-m", "1024",
            "-kernel", str(paths.KERNEL),
            "-initrd", str(paths.INITRD),
            "-dtb", str(paths.DTB),
            "-append", "console=ttyAMA0,115200 root=/dev/vda rw",
            "-drive", f"id=root,file={paths.ROOTFS_IMG},format=raw,if=none",
            "-device", "virtio-blk-device,drive=root",
            "-drive", f"id=app,file={paths.APP_IMG},format=raw,if=none,readonly=on",
            "-device", "virtio-blk-device,drive=app",
            "-drive", f"id=db,file={paths.DB_IMG},format=raw,if=none",
            "-device", "virtio-blk-device,drive=db",
            "-netdev", (
                f"user,id=net0,"
                f"hostfwd=tcp::{{http}}-:80,"
                f"hostfwd=tcp::{{https}}-:443,"
                f"hostfwd=tcp::{{wss}}-:9997,"
                f"hostfwd=tcp::{{vnc}}-:5900,"
                f"hostfwd=tcp::{{ssh}}-:22"
            ).format(http=d["http_port"], https=d["https_port"], wss=d["wss_port"],
                     vnc=d["qt_vnc_port"], ssh=d["ssh_port"]),
            "-device", "virtio-net-device,netdev=net0",
            "-device", "virtio-rng-device",
            "-monitor", "none",
            "-nographic",
        ]
        for chardev in chardevs:
            args += ["-chardev", chardev]
        args += ["-serial", "chardev:serial0"]
        args += ["-qmp", f"unix:{paths.QMP_SOCK},server=on,wait=off"]
        args += [
            "-device", "virtio-serial-device",
            "-device", "virtserialport,chardev=esp0,name=esp0",
            "-device", "virtserialport,chardev=espjson,name=espjson",
            "-device", "virtserialport,chardev=agent,name=vgagent",
        ]
        return args

    # ---------------------------------------------------------- lifecycle

    def start(self) -> None:
        if self.process and self.process.poll() is None:
            return
        for path in (paths.ROOTFS_IMG, paths.APP_IMG, paths.DB_IMG, paths.KERNEL,
                     paths.INITRD, paths.DTB):
            if not path.exists():
                raise VMError(f"missing image {path}; run `vg build` first")
        paths.ensure_dirs()
        for sock in (paths.QMP_SOCK, paths.ESP_SOCK, paths.ESPJSON_SOCK, paths.AGENT_SOCK,
                     paths.SERIAL_SOCK):
            try:
                sock.unlink()
            except FileNotFoundError:
                pass
        paths.SERIAL_LOG.write_text("")
        log = open(paths.QEMU_LOG, "wb")
        self.process = subprocess.Popen(
            self.command(), stdout=log, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )
        self.started_at = time.time()
        paths.DAEMON_PID.write_text(str(self.process.pid))

    def wait_for_qmp(self, timeout: float = 20.0) -> None:
        deadline = time.time() + timeout
        last: Exception | None = None
        while time.time() < deadline:
            if self.process and self.process.poll() is not None:
                raise VMError(f"QEMU exited early (see {paths.QEMU_LOG})")
            try:
                self.qmp.connect(retries=1, delay=0)
                return
            except QMPError as exc:
                last = exc
                time.sleep(0.4)
        raise VMError(f"QMP did not come up: {last}")

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def boot_marker(self) -> str | None:
        """Return the most advanced boot milestone seen in the serial log."""
        try:
            text = paths.SERIAL_LOG.read_text(errors="replace")
        except OSError:
            return None
        markers = [
            ("login:", "login"),
            ("S90app: starting", "hmi-start"),
            ("initramfs: switching root", "switch-root"),
            ("initramfs: root filesystem", "initramfs"),
            ("Kernel panic", "panic"),
        ]
        best = None
        best_pos = -1
        for marker, name in markers:
            pos = text.rfind(marker)
            if pos > best_pos:
                best_pos, best = pos, name
        return best

    def wait_boot(self, timeout: float = 120.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.running():
                return False
            marker = self.boot_marker()
            if marker in ("login", "hmi-start"):
                return True
            time.sleep(1.0)
        return False

    def status(self) -> dict:
        result = {
            "running": self.running(),
            "pid": self.process.pid if self.process else None,
            "uptime_s": round(time.time() - self.started_at, 1) if self.started_at else None,
            "boot": self.boot_marker(),
        }
        if self.running():
            result["qmp"] = self.qmp.status()
        else:
            result["qmp"] = {"ok": False, "error": "not running"}
        return result

    def stop(self, timeout: float = 10.0) -> None:
        if not self.process:
            return
        if self.process.poll() is None:
            try:
                self.qmp.connect(retries=1, delay=0)
                self.qmp.execute("quit")
            except (QMPError, OSError):
                pass
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
        self.process = None
        self.qmp.close()
        try:
            paths.DAEMON_PID.unlink()
        except FileNotFoundError:
            pass

    def reset(self) -> dict:
        if not self.running():
            raise VMError("VM is not running")
        self.qmp.execute("system_reset")
        return {"ok": True, "action": "reset"}

    def powerdown(self) -> dict:
        if not self.running():
            raise VMError("VM is not running")
        self.qmp.execute("system_powerdown")
        return {"ok": True, "action": "powerdown"}
