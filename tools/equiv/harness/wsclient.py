"""Minimal RFC 6455 client with observable close frames.

Deliberately dependency-free and independent of the vendor tooling so the
same client can drive the vendor HMI and a reconstruction. Every event the
client can observe is returned to the caller instead of being raised, because
a *silent connection close* is itself part of the contract under test.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@dataclass
class WSEvent:
    kind: str                      # open | text | binary | ping | pong | close | error
    data: object = None
    code: int | None = None
    reason: str = ""
    at_ms: int = 0
    meta: dict = field(default_factory=dict)


class WSClient:
    def __init__(self, url: str, timeout: float = 8.0):
        parts = urlsplit(url)
        if parts.scheme not in ("ws", "wss"):
            raise ValueError("url must be ws:// or wss://")
        self.url = url
        self.host = parts.hostname or "127.0.0.1"
        self.port = parts.port or (443 if parts.scheme == "wss" else 80)
        self.path = parts.path or "/"
        if parts.query:
            self.path += "?" + parts.query
        self.secure = parts.scheme == "wss"
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.t0 = time.monotonic()
        self.handshake: dict = {}

    # ------------------------------------------------------------- frames

    def _ms(self) -> int:
        return int((time.monotonic() - self.t0) * 1000)

    def connect(self) -> WSEvent:
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            sock.settimeout(self.timeout)
            if self.secure:
                ctx = ssl._create_unverified_context()
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            key = base64.b64encode(os.urandom(16)).decode()
            request = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}:{self.port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Origin: https://{self.host}\r\n"
                "\r\n"
            )
            sock.sendall(request.encode())
            status, headers, leftover = self._read_headers(sock)
            self.handshake = {
                "status": status,
                "subprotocol": headers.get("sec-websocket-protocol"),
                "server": headers.get("server"),
            }
            if status != 101:
                sock.close()
                return WSEvent("error", {"http_status": status, "handshake": self.handshake},
                               at_ms=self._ms())
            accept = base64.b64encode(
                hashlib.sha1((key + GUID).encode()).digest()).decode()
            if headers.get("sec-websocket-accept") != accept:
                sock.close()
                return WSEvent("error", {"error": "bad Sec-WebSocket-Accept"},
                               at_ms=self._ms())
            self.sock = sock
            self._buf = leftover
            return WSEvent("open", self.handshake, at_ms=self._ms())
        except OSError as exc:
            return WSEvent("error", {"error": f"{type(exc).__name__}: {exc}"}, at_ms=self._ms())

    def _read_headers(self, sock) -> tuple[int, dict[str, str], bytes]:
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed during handshake")
            buf.extend(chunk)
            if len(buf) > 65536:
                raise ConnectionError("handshake too large")
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        lines = head.decode(errors="replace").split("\r\n")
        status = int(lines[0].split()[1]) if len(lines[0].split()) > 1 else 0
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers, rest

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray(getattr(self, "_buf", b""))
        self._buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed")
            buf.extend(chunk)
        if len(buf) > n:
            self._buf = bytes(buf[n:])
            return bytes(buf[:n])
        return bytes(buf)

    def send_text(self, text: str) -> WSEvent:
        if not self.sock:
            return WSEvent("error", {"error": "not connected"})
        try:
            self.sock.sendall(self._frame(0x1, text.encode()))
            return WSEvent("sent", {"chars": len(text)}, at_ms=self._ms())
        except OSError as exc:
            return WSEvent("error", {"error": str(exc)}, at_ms=self._ms())

    def _frame(self, opcode: int, payload: bytes) -> bytes:
        header = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack(">H", n))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack(">Q", n))
        key = os.urandom(4)
        header.extend(key)
        return bytes(header) + bytes(b ^ key[i % 4] for i, b in enumerate(payload))

    def recv(self, timeout: float | None = None) -> WSEvent:
        """Read one event. Returns a 'closed' event on EOF, never raises."""
        if not self.sock:
            return WSEvent("error", {"error": "not connected"})
        old = self.sock.gettimeout()
        self.sock.settimeout(timeout if timeout is not None else self.timeout)
        try:
            while True:
                hdr = self._recv_exact(2)
                opcode = hdr[0] & 0x0F
                masked = hdr[1] & 0x80
                length = hdr[1] & 0x7F
                if length == 126:
                    length = struct.unpack(">H", self._recv_exact(2))[0]
                elif length == 127:
                    length = struct.unpack(">Q", self._recv_exact(8))[0]
                key = self._recv_exact(4) if masked else b""
                payload = self._recv_exact(length)
                if masked:
                    payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
                if opcode == 0x1:
                    return WSEvent("text", payload.decode(errors="replace"), at_ms=self._ms())
                if opcode == 0x2:
                    return WSEvent("binary", payload.hex(), at_ms=self._ms())
                if opcode == 0x9:
                    self.sock.sendall(self._frame(0xA, payload))
                    continue
                if opcode == 0xA:
                    continue
                if opcode == 0x8:
                    code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else None
                    reason = payload[2:].decode(errors="replace") if len(payload) > 2 else ""
                    return WSEvent("close", code=code, reason=reason, at_ms=self._ms())
                return WSEvent("error", {"error": f"unexpected opcode {opcode}"}, at_ms=self._ms())
        except (ConnectionError, OSError) as exc:
            # EOF without a close frame is observably different from a clean
            # close: record it as 'eof' rather than a close event.
            kind = "eof" if isinstance(exc, ConnectionError) else "error"
            return WSEvent(kind, {"error": str(exc)}, at_ms=self._ms())
        finally:
            if self.sock:
                try:
                    self.sock.settimeout(old)
                except OSError:
                    pass

    def close(self) -> None:
        if not self.sock:
            return
        try:
            self.sock.sendall(self._frame(0x8, struct.pack(">H", 1000)))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        self.sock = None


def exchange(url: str, message: str | dict, timeout: float = 8.0) -> dict:
    """Send one message, return the observable exchange.

    Result keys: open, reply (raw text or None), close (event dict or None).
    """
    client = WSClient(url, timeout=timeout)
    opened = client.connect()
    result = {"open": opened.__dict__, "reply": None, "close": None}
    if opened.kind != "open":
        return result
    text = message if isinstance(message, str) else json.dumps(message, separators=(",", ":"))
    client.send_text(text)
    try:
        event = client.recv(timeout=timeout)
    finally:
        if event.kind not in ("close", "eof", "error"):
            client.close()
        else:
            client.close()
    if event.kind == "text":
        result["reply"] = event.data
    else:
        result["close"] = {"kind": event.kind, "code": event.code,
                           "reason": event.reason, "data": event.data}
    return result
