#!/usr/bin/env python3
"""chip2_stub.py - HMI "chip #2" (ESP32) UART stub.

WHAT "CHIP #2" IS
-----------------
"Chip #2" is the ESP32 WiFi co-processor, not the AGSA motor driver.  Evidence
is in README.md (section 1); the short version:

  * All four "Chip #2" strings live in the Qt translation tables of
    `EspUpdateScreen` (`libNgxUi.so`, file offsets 0x598148/0x5981ca/0x59823c).
  * The notification table at 0x6705a8-0x670660 pairs "Chip #2 failed" /
    "UART communication to chip #2 failed" with "WiFi module failed" /
    "SDIO status invalid".
  * The only UART drivers in the product are `EspDriver::EspUartDriver`
    (`/dev/ttySTM1`, JSON) and `EspDriver::EspFlashDriver` (`/dev/ttySTM5`,
    esp-serial-flasher).  No AGSA class touches a tty.

TRANSPORT
---------
`NgxUiApp` builds
    EspUartDriver::create("/dev/ttySTM1", 576000, "/usr/local/esp/Ng2EspAppVersion.json")
(`NgxUiApp` rodata 0x270f4 / 0x27104).  QSerialPort 8N1, no flow control.
The wire format is *one JSON object*, not line-delimited and not framed:
`EspUartDriver::processUartData()` does

    buf += port->readAll();
    doc  = QJsonDocument::fromJson(buf, &err);
    if (doc.object().isEmpty()) { restart_incomplete_timer(); return; }   // 0x1d1ffc
    buf.clear();                                                          // 0x1d2018
    if (obj.contains("pong")) { setAlive(true); ... }                     // 0x1d2040

so a response must be a single, complete JSON object.  Two objects written
back-to-back make `fromJson()` fail and the HMI waits for a timeout.

OBSERVED MESSAGE SET (strings at libNgxUi.so 0x463744-0x463958)
--------------------------------------------------------------
  HMI -> ESP   {"ping":true}                               (4-char key + bool)
  HMI -> ESP   {"type":"RequestVersion"}                   key "type", 17-char value
  HMI -> ESP   {"type":"RequestSdioStatus"}                key "type", 17-char value
  ESP -> HMI   {"pong":true}
  ESP -> HMI   {"versionNo":"...","versionDate":"..."}
  ESP -> HMI   {"sdioStatus":N,"sdioError":N,"fuseFailed":bool}
  ESP -> HMI   {"wifiRssi":N,"wifiApConnected":bool}       (unsolicited, optional)
  ESP -> HMI   {"requestConfig":true}                      (unsolicited, optional)

`DriverTypes::SdioState` enum order (libNgxUi.so 0x45ea88):
    Uninitialized=0, Init=1, Running=2, Failed=3, Restart=4

USAGE
-----
  # QEMU chardev socket (recommended; guest sees it as /dev/ttyAMA1)
  chip2_stub.py --socket /tmp/stubs/esp-json.sock

  # plain pty for local experiments; prints the slave path
  chip2_stub.py --pty --link /tmp/ttySTM1

  # capture only: answer nothing, hexdump everything (protocol discovery)
  chip2_stub.py --socket ... --capture --capture-file /tmp/stubs/esp-json.cap

  # self test (pty loopback, no hardware)
  chip2_stub.py --selftest
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import pty
import select
import socket
import sys
import time
import tty

# --- defaults taken from app-tree/esp/Ng2EspAppVersion.json ------------------

DEFAULT_VERSION_NO = "01.11"
DEFAULT_VERSION_DATE = "16.12.2025"
DEFAULT_SDIO_STATUS = 2          # DriverTypes::SdioState::Running
DEFAULT_SDIO_ERROR = 0
DEFAULT_FUSE_FAILED = False
DEFAULT_RSSI = -45
DEFAULT_AP_CONNECTED = False


def log(msg: str) -> None:
    print(f"chip2-stub: {msg}", flush=True)


def hexdump(data: bytes, prefix: str = "  ") -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{off:04x}  {hexpart:<47}  {text}")
    return "\n".join(lines)


# --- JSON framing ------------------------------------------------------------
#
# The HMI parses the *whole* buffer with QJsonDocument::fromJson().  We therefore
# have to answer with exactly one object per burst.  To find object boundaries
# without guessing we scan for a balanced top-level {...} while respecting
# strings and escapes, which also copes with Qt's indented `toJson()` output.

def extract_objects(buf: bytes) -> tuple[list[bytes], bytes]:
    objects: list[bytes] = []
    depth = 0
    in_string = False
    escaped = False
    start = -1
    i = 0
    while i < len(buf):
        ch = buf[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == 0x5C:          # backslash
                escaped = True
            elif ch == 0x22:          # quote
                in_string = False
        else:
            if ch == 0x22:
                in_string = True
            elif ch == 0x7B:          # {
                if depth == 0:
                    start = i
                depth += 1
            elif ch == 0x7D:          # }
                if depth:
                    depth -= 1
                    if depth == 0 and start >= 0:
                        objects.append(buf[start:i + 1])
                        start = -1
        i += 1
    rest = buf[start:] if (depth and start >= 0) else buf[len(buf):]
    if not depth:
        rest = b""
    return objects, rest


class Responder:
    def __init__(self, args: argparse.Namespace) -> None:
        self.version_no = args.version_no
        self.version_date = args.version_date
        self.sdio_status = args.sdio_status
        self.sdio_error = args.sdio_error
        self.fuse_failed = args.fuse_failed
        self.rssi = args.rssi
        self.ap_connected = args.ap_connected
        self.send_status_extra = args.send_status_extra
        self.capture = args.capture

    def reply_for(self, obj: dict) -> dict:
        """Return the merged reply object for one request object."""
        out: dict = {}

        if "ping" in obj:
            # `processUartData` checks contains("pong") first and returns.
            out["pong"] = True

        cmd = obj.get("type")
        if cmd is None:
            for key in ("RequestVersion", "RequestSdioStatus"):
                if key in obj:
                    cmd = key
                    break

        if cmd == "RequestVersion":
            out["versionNo"] = self.version_no
            out["versionDate"] = self.version_date
        elif cmd == "RequestSdioStatus":
            out["sdioStatus"] = self.sdio_status
            out["sdioError"] = self.sdio_error
            out["fuseFailed"] = self.fuse_failed
            if self.send_status_extra:
                out["wifiRssi"] = self.rssi
                out["wifiApConnected"] = self.ap_connected
        return out


def encode(obj: dict) -> bytes:
    # Compact form + newline.  QJsonDocument accepts trailing whitespace.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


# --- transports --------------------------------------------------------------

def open_pty(link: str | None) -> tuple[int, int]:
    master, slave = pty.openpty()
    tty.setraw(master)
    tty.setraw(slave)
    name = os.ttyname(slave)
    if link:
        try:
            os.unlink(link)
        except FileNotFoundError:
            pass
        os.symlink(name, link)
    log(f"pty slave {name}" + (f" (link {link})" if link else ""))
    return master, slave


def connect_socket(path: str, retry: bool = True) -> socket.socket:
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(path)
            log(f"connected to {path}")
            return sock
        except OSError as exc:
            sock.close()
            if not retry:
                raise
            if exc.errno not in (errno.ENOENT, errno.ECONNREFUSED):
                raise
            time.sleep(0.2)


def listen_socket(path: str) -> socket.socket:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    log(f"listening on {path}")
    return srv


def serve(args: argparse.Namespace) -> int:
    responder = Responder(args)
    capture_file = open(args.capture_file, "ab") if args.capture_file else None

    if args.mode == "pty":
        master, slave = open_pty(args.link)
        conn: socket.socket | None = None
        fd: int = master
    elif args.mode == "socket":
        conn = connect_socket(args.path)
        fd = conn.fileno()
    elif args.mode == "listen":
        srv = listen_socket(args.path)
        log("waiting for client")
        conn, _ = srv.accept()
        log("client connected")
        fd = conn.fileno()
    else:  # pragma: no cover - argparse enforces the choices
        raise SystemExit(f"unknown mode {args.mode}")

    buf = b""
    pending: dict = {}
    flush_at: float | None = None
    total_rx = total_tx = 0

    def send(obj: dict) -> None:
        nonlocal total_tx
        data = encode(obj)
        if args.delay_ms:
            time.sleep(args.delay_ms / 1000.0)
        if conn is not None:
            conn.sendall(data)
        else:
            os.write(master, data)
        total_tx += len(data)
        log(f"tx {data!r}")

    while True:
        timeout = 0.005 if pending else 0.5
        try:
            readable, _, _ = select.select([fd], [], [], timeout)
        except InterruptedError:
            continue
        except OSError:
            break

        if readable:
            try:
                if conn is not None:
                    chunk = conn.recv(65536)
                else:
                    chunk = os.read(master, 65536)
            except OSError as exc:
                if exc.errno in (errno.EIO, errno.EBADF):
                    if conn is not None:
                        log("peer closed; reconnecting")
                        conn.close()
                        conn = connect_socket(args.path)
                        fd = conn.fileno()
                        continue
                    break
                raise
            if not chunk:
                if conn is not None:
                    log("peer closed; reconnecting")
                    conn.close()
                    conn = connect_socket(args.path)
                    fd = conn.fileno()
                    continue
                break

            total_rx += len(chunk)
            buf += chunk
            if args.raw or args.capture:
                log(f"rx {len(chunk)} bytes\n{hexdump(chunk)}")
                if capture_file:
                    capture_file.write(f"# {time.time():.6f} rx {len(chunk)}\n".encode())
                    capture_file.write(hexdump(chunk, "").encode() + b"\n")
                    capture_file.flush()

            objects, buf = extract_objects(buf)
            for raw in objects:
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError as exc:
                    log(f"bad json {exc}: {raw!r}")
                    continue
                log(f"rx {json.dumps(obj, separators=(',', ':'))}")
                if args.capture:
                    continue
                reply = responder.reply_for(obj)
                if reply:
                    pending.update(reply)          # merge a burst into one object
                    flush_at = time.monotonic() + args.flush_ms / 1000.0

        if pending and flush_at is not None and time.monotonic() >= flush_at:
            send(pending)
            pending = {}
            flush_at = None

    log(f"session ended: rx={total_rx} tx={total_tx} bytes")
    return 0


# --- self test ---------------------------------------------------------------

def selftest() -> int:
    """Exercise framing + dispatch over a real pty, without the HMI."""
    master, slave = pty.openpty()
    tty.setraw(master)
    tty.setraw(slave)

    ns = argparse.Namespace(
        version_no=DEFAULT_VERSION_NO, version_date=DEFAULT_VERSION_DATE,
        sdio_status=2, sdio_error=0, fuse_failed=False,
        rssi=-45, ap_connected=False, send_status_extra=True, capture=False,
    )
    responder = Responder(ns)

    failures = 0

    def ask(payload: dict) -> dict | None:
        nonlocal failures
        # guest writes to the slave; the stub reads the master and answers on
        # the master; the guest then reads the reply from the slave.
        wire = json.dumps(payload, indent=4).encode() + b"\n"      # Qt-style
        os.write(slave, wire)
        time.sleep(0.02)
        rx = os.read(master, 4096)                                 # stub side
        objects, _ = extract_objects(rx)
        if len(objects) != 1:
            log(f"FAIL: {payload} -> {rx!r} (want exactly one request object)")
            failures += 1
            return None
        reply = responder.reply_for(json.loads(objects[0]))
        os.write(master, encode(reply))
        time.sleep(0.02)
        data = os.read(slave, 4096)                                # guest side
        got, _ = extract_objects(data)
        if len(got) != 1:
            log(f"FAIL: {payload} -> {data!r} (want exactly one reply object)")
            failures += 1
            return None
        reply = json.loads(got[0])
        log(f"{payload} -> {reply}")
        return reply

    r = ask({"ping": True})
    if not r or r.get("pong") is not True:
        failures += 1
    r = ask({"type": "RequestVersion"})
    if not r or r.get("versionNo") != DEFAULT_VERSION_NO:
        failures += 1
    r = ask({"type": "RequestSdioStatus"})
    if not r or r.get("sdioStatus") != 2 or r.get("fuseFailed") is not False:
        failures += 1

    # A ping + RequestVersion burst must still produce one object.
    os.write(slave, b'{"ping":true}\n{"type":"RequestVersion"}\n')
    time.sleep(0.02)
    rx = os.read(master, 4096)
    objects, _ = extract_objects(rx)
    merged: dict = {}
    for raw in objects:
        merged.update(responder.reply_for(json.loads(raw)))
    os.write(master, encode(merged))
    time.sleep(0.02)
    data = os.read(slave, 4096)
    got, _ = extract_objects(data)
    log(f"burst -> {[json.loads(o) for o in got]}")
    if len(got) != 1 or "pong" not in json.loads(got[0]):
        log("FAIL: burst was not merged into a single object")
        failures += 1

    log("selftest: " + ("OK" if failures == 0 else f"{failures} failure(s)"))
    return 0 if failures == 0 else 1


# --- cli ---------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pty", action="store_true", help="allocate a pty (default)")
    p.add_argument("--socket", nargs="?", const="/tmp/stubs/esp-json.sock",
                   metavar="PATH", help="connect to a QEMU unix chardev socket")
    p.add_argument("--listen", nargs="?", const="/tmp/stubs/esp-json.sock",
                   metavar="PATH", help="listen on a unix socket (QEMU client=on)")
    p.add_argument("--link", help="symlink this path to the pty slave")
    p.add_argument("--capture", action="store_true",
                   help="log and never answer (protocol discovery)")
    p.add_argument("--capture-file")
    p.add_argument("--raw", action="store_true", help="hexdump every read")
    p.add_argument("--delay-ms", type=int, default=0)
    p.add_argument("--flush-ms", type=float, default=15.0,
                   help="coalesce a burst of requests into one reply object")
    p.add_argument("--version-no", default=DEFAULT_VERSION_NO)
    p.add_argument("--version-date", default=DEFAULT_VERSION_DATE)
    p.add_argument("--sdio-status", type=int, default=DEFAULT_SDIO_STATUS)
    p.add_argument("--sdio-error", type=int, default=DEFAULT_SDIO_ERROR)
    p.add_argument("--fuse-failed", action="store_true", default=DEFAULT_FUSE_FAILED)
    p.add_argument("--rssi", type=int, default=DEFAULT_RSSI)
    p.add_argument("--ap-connected", action="store_true", default=DEFAULT_AP_CONNECTED)
    p.add_argument("--send-status-extra", action="store_true", default=True,
                   help="include wifiRssi/wifiApConnected in status replies")
    p.add_argument("--no-status-extra", dest="send_status_extra", action="store_false")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()
    if args.socket is not None:
        args.mode, args.path = "socket", args.socket
    elif args.listen is not None:
        args.mode, args.path = "listen", args.listen
    else:
        args.mode, args.path = "pty", "/tmp/stubs/esp-json.sock"

    if args.selftest:
        return selftest()
    try:
        return serve(args)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
