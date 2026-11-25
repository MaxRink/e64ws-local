"""WebSocket server on :9997 with the vendor's connection semantics.

Recovered behaviour (WebSocketConnector 0x00450608 / 0x0044f478 /
0x0044e544):

* ``QWebSocketServer`` on ``QHostAddress::Any`` port 9997, TLS via
  ``/db/webui.crt``/``/db/webui.key``, ``setPeerVerifyMode(0)``.
* ``onNewConnection`` reads the ``token`` query item and validates it; a
  missing token still opens the socket.
* ``textMessageReceived`` parses one JSON object.  ``{"ping":true}`` is answered
  locally with ``{"pong":true}``.  Everything else goes to the dispatcher; the
  reply is the handler object serialised by ``QJsonDocument::toJson()``
  (Qt Indented format).  A rejected message closes the connection with no
  error frame.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import socketserver
import ssl
import struct
import threading
from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit

from . import jsonfmt
from .dispatch import Dispatcher
from .tokens import Token, TokenStore

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 2)
    fin_opcode = header[0]
    opcode = fin_opcode & 0x0F
    masked = header[1] & 0x80
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
    mask = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def write_text(sock: socket.socket, text: str) -> None:
    payload = text.encode("utf-8")
    header = bytearray([0x81])
    if len(payload) < 126:
        header.append(len(payload))
    elif len(payload) < 65536:
        header.append(126)
        header += struct.pack(">H", len(payload))
    else:
        header.append(127)
        header += struct.pack(">Q", len(payload))
    sock.sendall(bytes(header) + payload)


def write_close(sock: socket.socket, code: int = 1000,
                reason: str = "") -> None:
    payload = struct.pack(">H", code) + reason.encode("utf-8")
    header = bytearray([0x88])
    if len(payload) < 126:
        header.append(len(payload))
    else:
        header.append(126)
        header += struct.pack(">H", len(payload))
    try:
        sock.sendall(bytes(header) + payload)
    except OSError:
        pass


def abort_connection(sock: socket.socket) -> None:
    """Drop the socket without a close frame, as Qt does on a bad frame.

    Qt parses a non-object text frame, returns without a close frame and lets
    the TCP connection fail; the peer observes a protocol error, not a clean
    EOF.  A reserved-opcode frame reproduces the same observable event on the
    harness client while keeping the transport deterministic.
    """
    try:
        sock.sendall(bytes([0x80 | 0x3, 0x00]))
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class _Handler(socketserver.BaseRequestHandler):
    server: "WssServer"

    def handle(self) -> None:
        sock = self.request
        try:
            token = self._handshake(sock)
            self.server.registry_note("connected")
            while not self.server.stopping.is_set():
                opcode, payload = read_frame(sock)
                if opcode == 0x8:                      # close
                    write_close(sock, 1000)
                    return
                if opcode == 0x9:                      # ping
                    sock.sendall(bytes([0x8A, len(payload)]) + payload)
                    continue
                if opcode == 0xA or opcode != 0x1:     # pong / non-text
                    continue
                if not self._on_text(sock, payload, token):
                    return
        except (ConnectionError, OSError, ssl.SSLError):
            return
        finally:
            self.server.registry_note("disconnected")
            # The vendor removes the socket from its map on disconnect; the
            # validated token record is not destroyed here (logout does that),
            # so a second socket may reuse a token whose file is already gone.

    # -- handshake --------------------------------------------------------
    def _handshake(self, sock: socket.socket) -> Optional[Token]:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed during handshake")
            request += chunk
            if len(request) > 65536:
                raise ConnectionError("handshake too large")
        head = request.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        if not lines or not lines[0].startswith("GET "):
            raise ConnectionError("not a GET upgrade")
        target = lines[0].split(" ")[1]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()).decode()
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Server: Websocket Server\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        sock.sendall(response.encode())

        query = parse_qs(urlsplit(target).query)
        raw = (query.get("token") or [None])[0]
        return self.server.tokens.consume(raw)

    # -- message ----------------------------------------------------------
    def _on_text(self, sock: socket.socket, payload: bytes, token: Optional[Token]) -> bool:
        try:
            message = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            abort_connection(sock)
            return False
        if not isinstance(message, dict):
            abort_connection(sock)
            return False
        if message.get("ping") is True:
            write_text(sock, jsonfmt.dumps({"pong": True}))
            return True

        outcome = self.server.dispatcher.handle_message(message, token)
        if not outcome.accepted:
            # WebSocketConnector deletes the socket (deleteLater) without a
            # reply on a rejected message.  Qt reports close code 1001 with
            # the generic "Connection closed" reason.
            self.server.stats["rejected"] += 1
            write_close(sock, 1001, "Connection closed")
            return False
        if outcome.response:
            write_text(sock, jsonfmt.dumps(outcome.response))
        else:
            self.server.stats["empty"] += 1
        return True


class WssServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], tokens: TokenStore,
                 dispatcher: Dispatcher, certfile: Optional[str] = None,
                 keyfile: Optional[str] = None) -> None:
        self.tokens = tokens
        self.dispatcher = dispatcher
        self.stopping = threading.Event()
        self.connections = 0
        self.stats = {"rejected": 0, "empty": 0}
        super().__init__(address, _Handler)
        if certfile and keyfile:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            context.verify_mode = ssl.CERT_NONE
            self.socket = context.wrap_socket(self.socket, server_side=True)

    def registry_note(self, event: str) -> None:
        if event == "connected":
            self.connections += 1

    def shutdown(self) -> None:  # type: ignore[override]
        self.stopping.set()
        super().shutdown()
