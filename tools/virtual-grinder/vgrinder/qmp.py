"""Small QEMU Machine Protocol (QMP) client."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path


class QMPError(RuntimeError):
    pass


class QMP:
    def __init__(self, path: Path, timeout: float = 5.0):
        self.path = Path(path)
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self._buffer = b""
        self._lock = threading.Lock()

    def connect(self, retries: int = 40, delay: float = 0.25) -> dict:
        last: Exception | None = None
        for _ in range(retries):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect(str(self.path))
                self.sock = sock
                greeting = self._read_message()
                self.execute("qmp_capabilities")
                return greeting
            except (OSError, QMPError) as exc:
                last = exc
                self.close()
                time.sleep(delay)
        raise QMPError(f"cannot connect to QMP socket: {last}")

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _read_message(self) -> dict:
        if not self.sock:
            raise QMPError("not connected")
        while b"\n" not in self._buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise QMPError("QMP connection closed")
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return json.loads(line.decode())

    def execute(self, command: str, arguments: dict | None = None,
                timeout: float | None = None) -> dict:
        if not self.sock:
            raise QMPError("not connected")
        with self._lock:
            payload: dict = {"execute": command}
            if arguments:
                payload["arguments"] = arguments
            self.sock.sendall((json.dumps(payload) + "\n").encode())
            deadline = time.time() + (timeout if timeout is not None else self.timeout)
            while time.time() < deadline:
                message = self._read_message()
                if "return" in message:
                    return message["return"]
                if "error" in message:
                    raise QMPError(message["error"].get("desc", "QMP error"))
                # asynchronous event: keep reading
            raise QMPError(f"timeout waiting for {command}")

    def status(self) -> dict:
        try:
            return {"ok": True, "status": self.execute("query-status")}
        except (QMPError, OSError) as exc:
            return {"ok": False, "error": str(exc)}
