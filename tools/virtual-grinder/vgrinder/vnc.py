"""Minimal RFB (VNC) client and PNG writer.

No third-party dependencies. Used for `vg screen`, which captures the Qt VNC
platform plugin (guest :5900, host 15900) and, when present, QEMU's own VNC.

Only the Raw encoding is requested, so any conforming server works. Qt's VNC
plugin negotiates RFB 3.3/3.8 and offers the None security type.
"""

from __future__ import annotations

import socket
import struct
import time
import zlib
from pathlib import Path


class VncError(RuntimeError):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise VncError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def capture(host: str = "127.0.0.1", port: int = 15900, timeout: float = 20.0) -> dict:
    """Connect, request one full framebuffer update, return RGB pixels."""
    deadline = time.time() + timeout
    sock = socket.create_connection((host, port), timeout=min(5.0, timeout))
    sock.settimeout(5.0)
    try:
        version = _recv_exact(sock, 12)
        if not version.startswith(b"RFB "):
            raise VncError(f"not an RFB server: {version!r}")
        major, minor = int(version[4:7]), int(version[8:11])
        if (major, minor) >= (3, 8):
            sock.sendall(b"RFB 003.008\n")
        elif (major, minor) == (3, 7):
            sock.sendall(b"RFB 003.007\n")
        else:
            sock.sendall(b"RFB 003.003\n")

        if (major, minor) >= (3, 7):
            count = _recv_exact(sock, 1)[0]
            types = list(_recv_exact(sock, count))
            if 1 not in types:
                raise VncError(f"no None security type; server offers {types}")
            sock.sendall(bytes([1]))
        else:
            sec = struct.unpack(">I", _recv_exact(sock, 4))[0]
            if sec != 1:
                raise VncError(f"unsupported RFB 3.3 security {sec}")

        if (major, minor) >= (3, 8):
            result = struct.unpack(">I", _recv_exact(sock, 4))[0]
            if result != 0:
                raise VncError(f"security handshake failed ({result})")

        sock.sendall(b"\x01")  # ClientInit, shared

        width, height = struct.unpack(">HH", _recv_exact(sock, 4))
        pf = _recv_exact(sock, 16)
        name_len = struct.unpack(">I", _recv_exact(sock, 4))[0]
        name = _recv_exact(sock, name_len).decode(errors="replace")
        if width == 0 or height == 0:
            raise VncError("server reported a zero-sized framebuffer")
        if width * height > 4096 * 4096:
            raise VncError(f"implausible framebuffer {width}x{height}")
        _ = pf

        # Ask for 32-bit true colour with RGB shifts 16/8/0.
        pixel_format = struct.pack(
            ">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0,
        )
        sock.sendall(b"\x00\x00\x00\x00" + pixel_format)
        sock.sendall(struct.pack(">BxH", 2, 1) + struct.pack(">i", 0))  # Raw only
        sock.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height))

        pixels = bytearray(width * height * 3)
        got_any = False
        while time.time() < deadline:
            msg_type = _recv_exact(sock, 1)[0]
            if msg_type == 0:
                _pad, count = struct.unpack(">BH", _recv_exact(sock, 3))
                for _ in range(count):
                    x, y, w, h, enc = struct.unpack(">HHHHi", _recv_exact(sock, 12))
                    if enc == 0:
                        data = _recv_exact(sock, w * h * 4)
                        for row in range(h):
                            src = row * w * 4
                            dst = ((y + row) * width + x) * 3
                            # BGRX -> RGB
                            for col in range(w):
                                b, g, r = data[src + col * 4], data[src + col * 4 + 1], data[src + col * 4 + 2]
                                pixels[dst + col * 3] = r
                                pixels[dst + col * 3 + 1] = g
                                pixels[dst + col * 3 + 2] = b
                        got_any = True
                    elif enc == 1:  # CopyRect
                        _recv_exact(sock, 4)
                    elif enc == -223:  # DesktopSize pseudo-encoding
                        width, height = w, h
                        pixels = bytearray(width * height * 3)
                    else:
                        raise VncError(f"unexpected encoding {enc}")
                if got_any:
                    return {"width": width, "height": height, "rgb": bytes(pixels), "name": name}
            elif msg_type == 1:  # SetColourMapEntries
                _pad, count = struct.unpack(">BH", _recv_exact(sock, 3))
                _recv_exact(sock, count * 6)
            elif msg_type == 2:  # Bell
                pass
            elif msg_type == 3:  # ServerCutText
                _recv_exact(sock, 3)
                length = struct.unpack(">I", _recv_exact(sock, 4))[0]
                _recv_exact(sock, length)
            else:
                raise VncError(f"unknown server message {msg_type}")
        raise VncError("timed out waiting for a framebuffer update")
    finally:
        sock.close()


def send_input(port: int, events: list[tuple], host: str = "127.0.0.1",
               timeout: float = 10.0) -> dict:
    """Send RFB pointer/key events (emulation-only input path).

    events: ("pointer", x, y[, button]) or ("key", keysym[, down])
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        version = _recv_exact(sock, 12)
        major, minor = int(version[4:7]), int(version[8:11])
        if (major, minor) >= (3, 8):
            sock.sendall(b"RFB 003.008\n")
            count = _recv_exact(sock, 1)[0]
            types = list(_recv_exact(sock, count))
            if 1 not in types:
                raise VncError(f"no None security type; server offers {types}")
            sock.sendall(bytes([1]))
            result = struct.unpack(">I", _recv_exact(sock, 4))[0]
            if result != 0:
                raise VncError(f"security handshake failed ({result})")
        else:
            sock.sendall(b"RFB 003.003\n")
            sec = struct.unpack(">I", _recv_exact(sock, 4))[0]
            if sec != 1:
                raise VncError(f"unsupported security {sec}")
        sock.sendall(b"\x01")  # shared
        _recv_exact(sock, 4)   # width, height
        _recv_exact(sock, 16)  # pixel format
        name_len = struct.unpack(">I", _recv_exact(sock, 4))[0]
        _recv_exact(sock, name_len)
        sent = 0
        for event in events:
            if event[0] == "pointer":
                x, y = int(event[1]), int(event[2])
                button = int(event[3]) if len(event) > 3 else 1
                sock.sendall(struct.pack(">BBHH", 5, button, x, y))
                sock.sendall(struct.pack(">BBHH", 5, 0, x, y))
            elif event[0] == "key":
                keysym = int(event[1])
                sock.sendall(struct.pack(">BBHI", 4, 1, 0, keysym))
                sock.sendall(struct.pack(">BBHI", 4, 0, 0, keysym))
            else:
                raise ValueError(f"unknown VNC event {event!r}")
            sent += 1
            time.sleep(0.08)
        return {"ok": True, "events": sent}
    finally:
        sock.close()


def _chunk(tag: bytes, data: bytes) -> bytes:    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def write_png(path: Path, width: int, height: int, rgb: bytes) -> None:
    if len(rgb) != width * height * 3:
        raise ValueError("pixel buffer size mismatch")
    raw = bytearray()
    stride = width * 3
    for row in range(height):
        raw.append(0)  # filter: None
        raw.extend(rgb[row * stride:(row + 1) * stride])
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + _chunk(b"IEND", b"")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)


def capture_to_file(path: Path, host: str = "127.0.0.1", port: int = 15900,
                    timeout: float = 20.0) -> dict:
    frame = capture(host, port, timeout)
    write_png(path, frame["width"], frame["height"], frame["rgb"])
    return {
        "path": str(path),
        "width": frame["width"],
        "height": frame["height"],
        "bytes": path.stat().st_size,
        "name": frame["name"],
    }
