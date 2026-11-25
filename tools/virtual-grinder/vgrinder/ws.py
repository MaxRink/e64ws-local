"""Minimal WebSocket client/server (RFC 6455) plus an OpenScale fixture.

The E64 WS runs its own TLS WebSocket server on :9997. `WSClient` is used to
observe it and to send the recovered JSON envelopes. `ScaleServer` is a
synthetic `ws://host/snapshot` source matching the documented upstream OpenScale
shape -- the E64 firmware has no local scale protocol, so this is explicitly a
development fixture, not a recovered E64 interface.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WSError(RuntimeError):
    pass


def _read_http_headers(sock: socket.socket) -> tuple[int, dict[str, str]]:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise WSError("connection closed during handshake")
        buf.extend(chunk)
        if len(buf) > 65536:
            raise WSError("handshake too large")
    head, _, _rest = bytes(buf).partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    status = int(lines[0].split()[1]) if len(lines[0].split()) > 1 else 0
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers


def _mask(payload: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def _frame(opcode: int, payload: bytes, mask: bool = True) -> bytes:
    header = bytearray([0x80 | opcode])
    length = len(payload)
    mask_bit = 0x80 if mask else 0
    if length < 126:
        header.append(mask_bit | length)
    elif length < 65536:
        header.append(mask_bit | 126)
        header.extend(struct.pack(">H", length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack(">Q", length))
    if mask:
        key = os.urandom(4)
        header.extend(key)
        return bytes(header) + _mask(payload, key)
    return bytes(header) + payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise WSError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


class WSClient:
    def __init__(self, url: str, timeout: float = 10.0):
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
        self._buffer = b""

    def connect(self) -> None:
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
            "Origin: https://%s\r\n"
            "\r\n" % self.host
        )
        sock.sendall(request.encode())
        status, headers = _read_http_headers(sock)
        if status != 101:
            raise WSError(f"handshake failed: HTTP {status}")
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        if headers.get("sec-websocket-accept") != accept:
            raise WSError("bad Sec-WebSocket-Accept")
        self.sock = sock

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.sendall(_frame(0x8, b""))
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_text(self, text: str) -> None:
        if not self.sock:
            raise WSError("not connected")
        self.sock.sendall(_frame(0x1, text.encode()))

    def send_json(self, obj: Any) -> None:
        self.send_text(json.dumps(obj, separators=(",", ":")))

    def _read_frame(self) -> tuple[int, bytes]:
        if not self.sock:
            raise WSError("not connected")
        header = _recv_exact(self.sock, 2)
        fin = header[0] & 0x80
        opcode = header[0] & 0x0F
        masked = header[1] & 0x80
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", _recv_exact(self.sock, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", _recv_exact(self.sock, 8))[0]
        key = _recv_exact(self.sock, 4) if masked else b""
        payload = _recv_exact(self.sock, length)
        if masked:
            payload = _mask(payload, key)
        return opcode, payload

    def recv_json(self, timeout: float | None = None) -> Any:
        if not self.sock:
            raise WSError("not connected")
        old = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            while True:
                opcode, payload = self._read_frame()
                if opcode == 0x1:
                    return json.loads(payload.decode(errors="replace"))
                if opcode == 0x8:
                    raise WSError("server closed the connection")
                if opcode == 0x9:  # ping
                    self.sock.sendall(_frame(0xA, payload))
        finally:
            self.sock.settimeout(old)


def query(url: str, message: Any, timeout: float = 8.0) -> dict:
    client = WSClient(url, timeout=timeout)
    try:
        client.connect()
        client.send_json(message)
        return client.recv_json(timeout=timeout)
    finally:
        client.close()


# ------------------------------------------------------------ scale fixture


class ScaleServer:
    """Synthetic OpenScale `ws://<host>/snapshot` source.

    Emits `{"grams": <float>, "ms": <int>}` snapshots at the requested rate and
    accepts the documented text commands `rate`, `status`, `tare`.
    """

    def __init__(self, weight_g: float = 0.0, rate_hz: float = 2.0):
        self.weight_g = weight_g
        self.rate_hz = rate_hz
        self.tare_g = 0.0
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._server: socket.socket | None = None
        self._clients: list[socket.socket] = []
        self._thread: threading.Thread | None = None
        self._ticker: threading.Thread | None = None
        self.port = 0

    def start(self, host: str = "127.0.0.1", port: int = 18090) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(4)
        srv.settimeout(0.5)
        self._server = srv
        self.port = srv.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, name="vg-scale", daemon=True)
        self._thread.start()
        self._ticker = threading.Thread(target=self._tick_loop, name="vg-scale-tick", daemon=True)
        self._ticker.start()

    def stop(self) -> None:
        self._stop.set()
        for client in list(self._clients):
            try:
                client.close()
            except OSError:
                pass
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass

    def set_weight(self, grams: float) -> None:
        with self.lock:
            self.weight_g = grams

    def _accept_loop(self) -> None:
        assert self._server
        while not self._stop.is_set():
            try:
                client, _addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._client_loop, args=(client,), daemon=True).start()

    def _handshake(self, client: socket.socket) -> bool:
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = client.recv(4096)
            if not chunk:
                return False
            buf.extend(chunk)
            if len(buf) > 65536:
                return False
        head = bytes(buf).split(b"\r\n\r\n")[0].decode(errors="replace")
        lines = head.split("\r\n")
        path = lines[0].split()[1] if len(lines[0].split()) > 1 else "/"
        if not path.startswith("/snapshot"):
            client.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            return False
        key = ""
        for line in lines[1:]:
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        if not key:
            return False
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        client.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )
        return True

    def _client_loop(self, client: socket.socket) -> None:
        try:
            if not self._handshake(client):
                client.close()
                return
            self._clients.append(client)
            client.settimeout(0.5)
            buf = b""
            while not self._stop.is_set():
                try:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while len(buf) >= 2:
                        opcode = buf[0] & 0x0F
                        masked = buf[1] & 0x80
                        length = buf[1] & 0x7F
                        off = 2
                        if length == 126:
                            if len(buf) < 4:
                                break
                            length = struct.unpack(">H", buf[2:4])[0]
                            off = 4
                        key = b""
                        if masked:
                            if len(buf) < off + 4:
                                break
                            key = buf[off:off + 4]
                            off += 4
                        if len(buf) < off + length:
                            break
                        payload = buf[off:off + length]
                        buf = buf[off + length:]
                        if masked:
                            payload = _mask(payload, key)
                        if opcode == 0x1:
                            self._command(payload.decode(errors="replace").strip())
                        elif opcode == 0x8:
                            return
                        elif opcode == 0x9:
                            client.sendall(_frame(0xA, payload))
                except socket.timeout:
                    continue
        except OSError:
            pass
        finally:
            if client in self._clients:
                self._clients.remove(client)
            try:
                client.close()
            except OSError:
                pass

    def _command(self, text: str) -> None:
        if text.startswith("rate"):
            parts = text.split()
            if len(parts) > 1:
                value = parts[1].lower().rstrip("k")
                try:
                    self.rate_hz = max(0.5, min(50.0, float(value)))
                except ValueError:
                    pass
        elif text == "tare":
            with self.lock:
                self.tare_g = self.weight_g

    def _tick_loop(self) -> None:
        while not self._stop.wait(1.0 / max(0.5, self.rate_hz)):
            with self.lock:
                grams = round(self.weight_g - self.tare_g, 2)
            payload = json.dumps({"grams": grams, "ms": int(time.time() * 1000)},
                                 separators=(",", ":")).encode()
            frame = _frame(0x1, payload, mask=False)
            for client in list(self._clients):
                try:
                    client.sendall(frame)
                except OSError:
                    if client in self._clients:
                        self._clients.remove(client)

    def summary(self) -> dict:
        with self.lock:
            return {
                "port": self.port,
                "weight_g": round(self.weight_g - self.tare_g, 2),
                "rate_hz": self.rate_hz,
                "clients": len(self._clients),
            }
