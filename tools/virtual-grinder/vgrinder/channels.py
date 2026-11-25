"""Byte/line channels to QEMU chardev sockets.

QEMU is started with `-chardev socket,...,server=on,wait=off`, so every channel
is a Unix socket that QEMU listens on and this process connects to. Connections
are retried because the guest may take a moment to create the virtio ports.
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import threading
import time
from pathlib import Path
from typing import Callable

LOG = logging.getLogger("vg")
LOG_LINES: list[str] = []


class ReconnectingChannel:
    def __init__(self, path: Path, name: str, on_bytes: Callable[[bytes], None] | None = None):
        self.path = Path(path)
        self.name = name
        self.on_bytes = on_bytes
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.connected = False
        self.bytes_rx = 0
        self.bytes_tx = 0
        self.last_error: str | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name=f"vg-{self.name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
        if self._thread:
            self._thread.join(timeout=2)

    def _connect(self) -> socket.socket | None:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect(str(self.path))
            sock.settimeout(None)
            self.connected = True
            self.last_error = None
            return sock
        except OSError as exc:
            self.last_error = str(exc)
            return None

    def _run(self) -> None:
        while not self._stop.is_set():
            sock = self._connect()
            if sock is None:
                time.sleep(0.4)
                continue
            with self._lock:
                self._sock = sock
            try:
                while not self._stop.is_set():
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    self.bytes_rx += len(chunk)
                    if self.on_bytes:
                        try:
                            self.on_bytes(chunk)
                        except Exception as exc:  # noqa: BLE001 - channel must survive
                            self.last_error = f"handler: {exc}"
            except OSError as exc:
                self.last_error = str(exc)
            finally:
                self.connected = False
                with self._lock:
                    self._sock = None
                try:
                    sock.close()
                except OSError:
                    pass
            time.sleep(0.4)

    def write(self, data: bytes) -> bool:
        with self._lock:
            sock = self._sock
        if not sock:
            return False
        try:
            sock.sendall(data)
            self.bytes_tx += len(data)
            return True
        except OSError as exc:
            self.last_error = str(exc)
            return False


class LineChannel(ReconnectingChannel):
    """Newline-delimited channel with a blocking request/response helper."""

    def __init__(self, path: Path, name: str, quiet: bool = False):
        super().__init__(path, name)
        self.on_bytes = self._feed
        self._buffer = bytearray()
        self._lines: queue.Queue[str] = queue.Queue()
        self._request_lock = threading.Lock()
        self._seq = 0
        self.quiet = quiet

    def _feed(self, chunk: bytes) -> None:
        self._buffer.extend(chunk)
        while b"\n" in self._buffer:
            raw, _, rest = self._buffer.partition(b"\n")
            self._buffer = bytearray(rest)
            line = raw.decode(errors="replace").strip()
            if line:
                self._lines.put(line)

    def send_line(self, line: str) -> bool:
        return self.write((line + "\n").encode())

    def request(self, line: str, timeout: float = 3.0) -> dict:
        """Send a command and return the first JSON reply line.

        Serialized: several daemon threads (state writer, CLI) share this
        channel, and replies carry no correlation id.
        """
        with self._request_lock:
            self._seq += 1
            seq = self._seq
            self.send_line(f"#{seq} {line}")
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    reply = self._lines.get(timeout=max(0.05, deadline - time.time()))
                except queue.Empty:
                    break
                if self.quiet:
                    continue
                try:
                    parsed = json.loads(reply)
                except json.JSONDecodeError:
                    continue
                if parsed.get("seq", seq) == seq:
                    return parsed
            return {"ok": False, "error": f"no reply from {self.name}"}

    def drain(self) -> list[str]:
        out = []
        while True:
            try:
                out.append(self._lines.get_nowait())
            except queue.Empty:
                return out
