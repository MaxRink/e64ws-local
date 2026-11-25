"""Minimal WebSocket client used by the tests and the scenario recorder."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
from typing import Any, Optional

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WsClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 9997,
                 token: Optional[str] = None, tls: bool = False) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.tls = tls
        self.sock: Optional[socket.socket] = None
        self.closed = False

    def connect(self, timeout: float = 3.0) -> "WsClient":
        raw = socket.create_connection((self.host, self.port), timeout)
        if self.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw = context.wrap_socket(raw)
        key = base64.b64encode(os.urandom(16)).decode()
        path = "/" + (f"?token={self.token}" if self.token else "")
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        raw.sendall(request.encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = raw.recv(4096)
            if not chunk:
                raise ConnectionError("handshake failed")
            response += chunk
        if b"101" not in response.split(b"\r\n")[0]:
            raise ConnectionError(response.decode(errors="replace"))
        self.sock = raw
        return self

    def send(self, message: dict[str, Any]) -> None:
        payload = json.dumps(message, separators=(",", ":")).encode()
        header = bytearray([0x81])
        if len(payload) < 126:
            header.append(0x80 | len(payload))
        elif len(payload) < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", len(payload))
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", len(payload))
        mask = os.urandom(4)
        header += mask
        header += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        assert self.sock is not None
        self.sock.sendall(bytes(header))

    def recv(self, timeout: float = 2.0) -> Optional[bytes]:
        assert self.sock is not None
        self.sock.settimeout(timeout)
        try:
            header = self._recv_exact(2)
        except (socket.timeout, ConnectionError):
            return None
        if not header:
            self.closed = True
            return None
        opcode = header[0] & 0x0F
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_exact(8))[0]
        payload = self._recv_exact(length) if length else b""
        if opcode == 0x8:
            self.closed = True
            return None
        return payload

    def _recv_exact(self, count: int) -> bytes:
        assert self.sock is not None
        buf = b""
        while len(buf) < count:
            chunk = self.sock.recv(count - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def request(self, message: dict[str, Any], timeout: float = 2.0) -> Optional[dict]:
        self.send(message)
        payload = self.recv(timeout)
        if payload is None:
            return None
        return json.loads(payload.decode())

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.sendall(bytes([0x88, 0x80]) + os.urandom(4))
            except OSError:
                pass
            self.sock.close()
            self.sock = None
