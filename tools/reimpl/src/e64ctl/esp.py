"""ESP control plane: 14-byte TLV framing + protobuf-C ``CtrlMsg``.

Schema source: docs/ESP_PROTOBUF_SCHEMA.md, decoded from the protobuf-C
descriptors in ``EspWifiConfig``.  Framing helpers mirror tools/esp_stub.py,
which is the repository's validated reference implementation (byte-exact
against the two published vectors); this module re-implements them with the
full message table instead of the stub's four-response subset.

Two roles are provided:

* :class:`EspClient`  - the HMI side (what NgxUiApp does): open the device,
  send requests, read responses/events.
* :class:`EspSimulator` - the ESP32 side, for host tests and for running the
  service without hardware.
"""
from __future__ import annotations

import os
import select
import socket
import threading
import time
import tty
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

ENDPOINT_RESP = b"ctrlResp"
ENDPOINT_EVENT = b"ctrlEvnt"
MAX_FRAME = 4096  # kernel TX cap on /dev/esps0

MSG_TYPE_INVALID, MSG_TYPE_REQ, MSG_TYPE_RESP, MSG_TYPE_EVENT = 0, 1, 2, 3

# ---------------------------------------------------------------------------
# protobuf-C wire helpers
# ---------------------------------------------------------------------------


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def write_varint(value: int) -> bytes:
    value &= 0xFFFFFFFFFFFFFFFF if value < 0 else value
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field_varint(number: int, value: int) -> bytes:
    return write_varint(number << 3) + write_varint(int(value))


def field_bytes(number: int, payload: bytes) -> bytes:
    return write_varint((number << 3) | 2) + write_varint(len(payload)) + payload


# type tags: "u32"/"i32"/"bool"/"enum" -> varint, "string"/"bytes"/"msg" -> len
Field = tuple[str, str, int]  # (name, kind, number)

#: Request payloads (ids 101..121).  ``None`` = empty message.
REQ_FIELDS: dict[int, Optional[list[Field]]] = {
    101: [("mode", "u32", 1)],
    102: [("mac", "bytes", 1), ("mode", "u32", 2)],
    103: None,
    104: [("mode", "u32", 1)],
    105: None,
    106: None,
    107: [("ssid", "string", 1), ("pwd", "string", 2), ("bssid", "string", 3),
          ("is_wpa3_supported", "bool", 4), ("listen_interval", "i32", 5)],
    108: None,
    109: None,
    110: [("enable", "bool", 1), ("type", "enum", 2), ("idx", "enum", 3),
          ("vendor_ie_data", "VendorIEData", 4)],
    111: [("ssid", "string", 1), ("pwd", "string", 2), ("chnl", "i32", 3),
          ("sec_prot", "enum", 4), ("max_conn", "i32", 5),
          ("ssid_hidden", "bool", 6), ("bw", "i32", 7)],
    112: None,
    113: None,
    114: [("mode", "u32", 1)],
    115: None,
    116: None,
    117: [("ota_data", "bytes", 1)],
    118: None,
    119: [("wifi_max_tx_power", "i32", 1)],
    120: None,
    121: [("enable", "bool", 1), ("duration", "i32", 2)],
}

#: Response payloads (ids 201..221).
RESP_FIELDS: dict[int, Optional[list[Field]]] = {
    201: [("mac", "bytes", 1), ("resp", "i32", 2)],
    202: [("resp", "i32", 1)],
    203: [("mode", "i32", 1), ("resp", "i32", 2)],
    204: [("resp", "i32", 1)],
    205: [("count", "u32", 1), ("entries", "repeated ScanResult", 2),
          ("resp", "i32", 3)],
    206: [("ssid", "bytes", 1), ("bssid", "bytes", 2), ("rssi", "i32", 3),
          ("chnl", "i32", 4), ("sec_prot", "enum", 5), ("resp", "i32", 6)],
    207: [("resp", "i32", 1), ("mac", "bytes", 2)],
    208: [("resp", "i32", 1)],
    209: [("ssid", "bytes", 1), ("pwd", "bytes", 2), ("chnl", "i32", 3),
          ("sec_prot", "enum", 4), ("max_conn", "i32", 5),
          ("ssid_hidden", "bool", 6), ("bw", "i32", 7), ("resp", "i32", 8)],
    210: [("resp", "i32", 1)],
    211: [("resp", "i32", 1), ("mac", "bytes", 2)],
    212: [("num", "u32", 1), ("stations", "repeated ConnectedSTAList", 2),
          ("resp", "i32", 3)],
    213: [("resp", "i32", 1)],
    214: [("resp", "i32", 1)],
    215: [("mode", "i32", 1), ("resp", "i32", 2)],
    216: [("resp", "i32", 1)],
    217: [("resp", "i32", 1)],
    218: [("resp", "i32", 1)],
    219: [("resp", "i32", 1)],
    220: [("wifi_curr_tx_power", "i32", 1), ("resp", "i32", 2)],
    221: [("resp", "i32", 1)],
}

#: Asynchronous event payloads (ids 301..304).
EVENT_FIELDS: dict[int, Optional[list[Field]]] = {
    301: [("init_data", "bytes", 1)],
    302: [("hb_num", "i32", 1)],
    303: [("resp", "i32", 1)],
    304: [("resp", "i32", 1), ("mac", "bytes", 2)],
}

NESTED: dict[str, list[Field]] = {
    "ScanResult": [("ssid", "bytes", 1), ("chnl", "u32", 2), ("rssi", "i32", 3),
                   ("bssid", "bytes", 4), ("sec_prot", "enum", 5)],
    "ConnectedSTAList": [("mac", "bytes", 1), ("rssi", "i32", 2)],
    "VendorIEData": [("element_id", "i32", 1), ("length", "i32", 2),
                     ("vendor_oui", "bytes", 3), ("vendor_oui_type", "i32", 4),
                     ("payload", "bytes", 5)],
}


def _encode_kind(kind: str, value: Any) -> bytes:
    if kind in NESTED:
        return encode_message(NESTED[kind], value or {})
    if kind in ("bytes", "string"):
        if isinstance(value, str):
            return value.encode("utf-8")
        return value or b""
    if kind == "bool":
        return b"\x01" if value else b""
    return write_varint(int(value))


def encode_message(spec: Optional[list[Field]], values: dict[str, Any]) -> bytes:
    if not spec:
        return b""
    out = bytearray()
    for name, kind, number in spec:
        if name not in values or values[name] is None:
            continue
        value = values[name]
        if kind.startswith("repeated "):
            inner = NESTED[kind.split(" ", 1)[1]]
            for item in value:
                out += field_bytes(number, encode_message(inner, item))
            continue
        # protobuf-C (proto3 semantics) omits default values on the wire; the
        # published Resp_SetWifiMode{resp=0} vector is ``e2 0c 00`` (empty
        # payload), which is what this reproduces.
        if _is_default(kind, value):
            continue
        encoded = _encode_kind(kind, value)
        if kind in NESTED:
            out += field_bytes(number, encoded)
        elif kind in ("bytes", "string"):
            out += field_bytes(number, encoded)
        else:
            out += write_varint(number << 3) + encoded
    return bytes(out)


def _is_default(kind: str, value: Any) -> bool:
    if kind == "bool":
        return value is False
    if kind in ("u32", "i32", "enum"):
        return int(value) == 0
    if kind in ("bytes", "string"):
        return len(value or b"") == 0
    if kind in NESTED:
        return not value
    return False


def _signed32(value: int) -> int:
    """protobuf int32: negative values arrive as 10-byte two's-complement."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def decode_message(spec: Optional[list[Field]], data: bytes) -> dict[str, Any]:
    values: dict[str, Any] = {}
    if not spec:
        return values
    # proto3 accessors return 0/false/"" for unset scalars; mirror that so
    # callers read ``resp == 0`` instead of KeyError.
    for name, kind, _number in spec:
        if kind == "bool":
            values[name] = False
        elif kind in ("u32", "i32", "enum"):
            values[name] = 0
        elif kind == "string":
            values[name] = ""
        elif kind == "bytes":
            values[name] = b""
        elif kind.startswith("repeated "):
            values[name] = []
    by_number = {number: (name, kind) for name, kind, number in spec}
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            raw, pos = read_varint(data, pos)
        elif wire == 2:
            length, pos = read_varint(data, pos)
            raw = data[pos:pos + length]
            pos += length
        else:
            raise ValueError(f"unsupported wire type {wire}")
        entry = by_number.get(number)
        if entry is None:
            continue
        name, kind = entry
        if kind.startswith("repeated "):
            inner = NESTED[kind.split(" ", 1)[1]]
            values.setdefault(name, []).append(decode_message(inner, raw))
        elif kind in NESTED:
            values[name] = decode_message(NESTED[kind], raw)
        elif kind == "string":
            values[name] = raw.decode("utf-8", "replace")
        elif kind == "bytes":
            values[name] = raw
        elif kind == "bool":
            values[name] = bool(raw)
        elif kind == "i32":
            values[name] = _signed32(raw)
        else:
            values[name] = raw
    return values


# ---------------------------------------------------------------------------
# CtrlMsg + TLV framing
# ---------------------------------------------------------------------------


@dataclass
class CtrlMsg:
    msg_type: int
    msg_id: int
    payload: dict[str, Any] = field(default_factory=dict)

    def encode(self) -> bytes:
        body = field_varint(1, self.msg_type) + field_varint(2, self.msg_id)
        spec = (REQ_FIELDS.get(self.msg_id) if self.msg_type == MSG_TYPE_REQ
                else RESP_FIELDS.get(self.msg_id) if self.msg_type == MSG_TYPE_RESP
                else EVENT_FIELDS.get(self.msg_id))
        # protobuf-C always writes the oneof member tag, even when the
        # payload message has no set fields (published vector ``e2 0c 00``).
        payload = encode_message(spec, self.payload)
        body += field_bytes(self.msg_id, payload)
        return body

    @classmethod
    def decode(cls, body: bytes) -> "CtrlMsg":
        msg_type = 0
        msg_id = 0
        chunks: dict[int, bytes] = {}
        pos = 0
        while pos < len(body):
            key, pos = read_varint(body, pos)
            number, wire = key >> 3, key & 7
            if wire == 0:
                value, pos = read_varint(body, pos)
                if number == 1:
                    msg_type = value
                elif number == 2:
                    msg_id = value
            elif wire == 2:
                length, pos = read_varint(body, pos)
                chunks[number] = body[pos:pos + length]
                pos += length
            else:
                raise ValueError(f"unsupported wire type {wire}")
        if not msg_id:
            payload_fields = [n for n in chunks if n >= 100]
            if payload_fields:
                msg_id = payload_fields[0]
        raw_payload = chunks.get(msg_id, b"")
        spec = (REQ_FIELDS.get(msg_id) if msg_type == MSG_TYPE_REQ
                else RESP_FIELDS.get(msg_id) if msg_type == MSG_TYPE_RESP
                else EVENT_FIELDS.get(msg_id))
        return cls(msg_type, msg_id, decode_message(spec, raw_payload))


def encode_frame(msg: CtrlMsg, endpoint: bytes = ENDPOINT_RESP) -> bytes:
    payload = msg.encode()
    return (b"\x01" + len(endpoint).to_bytes(2, "little") + endpoint
            + b"\x02" + len(payload).to_bytes(2, "little") + payload)


def frame_length(buffer: bytes) -> Optional[int]:
    if len(buffer) < 3:
        return None
    endpoint_len = int.from_bytes(buffer[1:3], "little")
    header = 3 + endpoint_len + 3
    if len(buffer) < header:
        return None
    if buffer[0] != 0x01:
        raise ValueError(f"bad data type 0x{buffer[0]:02x}")
    if endpoint_len != 8:
        raise ValueError(f"bad endpoint length {endpoint_len}")
    if buffer[3 + endpoint_len] != 0x02:
        raise ValueError("bad message-type tag")
    payload_len = int.from_bytes(buffer[3 + endpoint_len + 1:
                                       3 + endpoint_len + 3], "little")
    return header + payload_len


def decode_frame(frame: bytes) -> tuple[bytes, CtrlMsg]:
    endpoint_len = int.from_bytes(frame[1:3], "little")
    endpoint = frame[3:3 + endpoint_len]
    offset = 3 + endpoint_len + 1
    payload_len = int.from_bytes(frame[offset:offset + 2], "little")
    body = frame[offset + 2:offset + 2 + payload_len]
    return endpoint, CtrlMsg.decode(body)


# ---------------------------------------------------------------------------
# HMI-side client
# ---------------------------------------------------------------------------


class EspTransport:
    """Byte-stream transport: character device, pty or unix socket."""

    def __init__(self, target: Optional[str] = None) -> None:
        self.target = target
        self.fd: Optional[int] = None
        self.sock: Optional[socket.socket] = None

    def open(self, timeout: float = 2.0) -> None:
        if not self.target:
            return
        deadline = time.time() + timeout
        while True:
            try:
                if self.target.startswith("unix:"):
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect(self.target[5:])
                    self.sock = sock
                else:
                    self.fd = os.open(self.target, os.O_RDWR | os.O_NOCTTY)
                return
            except OSError:
                if time.time() >= deadline:
                    raise
                time.sleep(0.05)

    def write(self, data: bytes) -> None:
        if self.sock is not None:
            self.sock.sendall(data)
        elif self.fd is not None:
            os.write(self.fd, data)

    def read(self, timeout: float) -> bytes:
        if self.sock is not None:
            self.sock.settimeout(timeout)
            try:
                return self.sock.recv(MAX_FRAME)
            except socket.timeout:
                return b""
        if self.fd is None:
            time.sleep(timeout)
            return b""
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return b""
        return os.read(self.fd, MAX_FRAME)

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class EspClient:
    """Sends ``Req_*`` and correlates ``Resp_*`` (id = request + 100)."""

    def __init__(self, transport: EspTransport,
                 on_event: Optional[Callable[[CtrlMsg], None]] = None) -> None:
        self.transport = transport
        self.on_event = on_event
        self._pending: dict[int, tuple[threading.Event, list[CtrlMsg]]] = {}
        self._lock = threading.Lock()
        self._buffer = b""
        self._reader: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        self.transport.open()
        self._reader = threading.Thread(target=self._read_loop, daemon=True,
                                        name="esp-reader")
        self._reader.start()

    def stop(self) -> None:
        self._stop.set()
        self.transport.close()

    # -- API --------------------------------------------------------------
    def request(self, msg_id: int, payload: Optional[dict[str, Any]] = None,
                timeout: float = 2.0) -> Optional[CtrlMsg]:
        msg = CtrlMsg(MSG_TYPE_REQ, msg_id, payload or {})
        event = threading.Event()
        box: list[CtrlMsg] = []
        with self._lock:
            self._pending[msg_id + 100] = (event, box)
        try:
            self.transport.write(encode_frame(msg))
        except OSError:
            pass
        event.wait(timeout)
        with self._lock:
            self._pending.pop(msg_id + 100, None)
        return box[0] if box else None

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            try:
                chunk = self.transport.read(0.2)
            except OSError:
                time.sleep(0.1)
                continue
            if not chunk:
                continue
            self._buffer += chunk
            while True:
                try:
                    length = frame_length(self._buffer)
                except ValueError:
                    self._buffer = b""
                    break
                if length is None or len(self._buffer) < length:
                    break
                frame, self._buffer = self._buffer[:length], self._buffer[length:]
                try:
                    _, msg = decode_frame(frame)
                except Exception:  # noqa: BLE001 - keep the link alive
                    continue
                if msg.msg_type == MSG_TYPE_EVENT:
                    if self.on_event:
                        self.on_event(msg)
                    continue
                with self._lock:
                    pending = self._pending.get(msg.msg_id)
                if pending:
                    pending[1].append(msg)
                    pending[0].set()


# ---------------------------------------------------------------------------
# ESP32-side simulator
# ---------------------------------------------------------------------------


@dataclass
class SimEspState:
    mode: int = 0                       # Ctrl_WifiMode
    mac: bytes = b"\x02\x00\x00\x00\x00\x01"
    sta_ssid: bytes = b""
    sta_pwd: bytes = b""
    sta_connected: bool = False
    softap_running: bool = False
    softap_ssid: bytes = b"E64-WS-VIRTUAL"
    softap_pwd: bytes = b""
    channel: int = 6
    security: int = 0
    max_conn: int = 4
    hidden: bool = False
    bandwidth: int = 1
    power_save: int = 1
    tx_power: int = 20
    heartbeat_enabled: bool = False
    heartbeat_period: float = 1.0
    ota_active: bool = False
    ota_bytes: int = 0
    #: Shared ESP32 fixture (same three APs the virtual grinder reports).
    scan_results: list[dict[str, Any]] = field(default_factory=lambda: [
        {"ssid": b"vg-lab", "chnl": 6, "rssi": -42,
         "bssid": b"\x02\x00\x00\x00\x00\x01", "sec_prot": 3},
        {"ssid": b"Mahlkoenig-Dev", "chnl": 11, "rssi": -58,
         "bssid": b"\x02\x00\x00\x00\x00\x02", "sec_prot": 3},
        {"ssid": b"Guest", "chnl": 1, "rssi": -71,
         "bssid": b"\x02\x00\x00\x00\x00\x03", "sec_prot": 0},
    ])


class EspSimulator:
    """Behavioural ESP32: answers 101..121 on a pty or unix socket."""

    def __init__(self, target: str, state: Optional[SimEspState] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.target = target
        self.state = state or SimEspState()
        self.clock = clock
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._master: Optional[int] = None
        self._listener: Optional[socket.socket] = None

    # -- transport ---------------------------------------------------------
    def start(self) -> None:
        if self.target.startswith("unix:"):
            path = self.target[5:]
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)
            self._listener = listener
        else:
            master, slave = os.openpty()
            tty.setraw(master)
            tty.setraw(slave)
            name = os.ttyname(slave)
            try:
                os.unlink(self.target)
            except FileNotFoundError:
                pass
            os.symlink(name, self.target)
            self._master = master
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="esp-sim")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._master is not None:
            os.close(self._master)
        if self._listener is not None:
            self._listener.close()

    def _serve(self) -> None:
        if self._master is not None:
            self._serve_fd(self._master)
            return
        assert self._listener is not None
        while not self._stop.is_set():
            conn, _ = self._listener.accept()
            with conn:
                self._serve_fd(conn.fileno(), conn)

    def _serve_fd(self, fd: int, sock: Optional[socket.socket] = None) -> None:
        buffer = b""
        next_heartbeat = self.clock() + self.state.heartbeat_period
        while not self._stop.is_set():
            try:
                if sock is not None:
                    sock.settimeout(0.2)
                    try:
                        chunk = sock.recv(MAX_FRAME)
                    except socket.timeout:
                        chunk = b""
                else:
                    ready, _, _ = select.select([fd], [], [], 0.2)
                    chunk = os.read(fd, MAX_FRAME) if ready else b""
            except OSError:
                return
            if not chunk:
                if (self.state.heartbeat_enabled
                        and self.clock() >= next_heartbeat):
                    beat = encode_frame(self.event(302, hb_num=1),
                                        endpoint=ENDPOINT_EVENT)
                    try:
                        if sock is not None:
                            sock.sendall(beat)
                        else:
                            os.write(fd, beat)
                    except OSError:
                        return
                    next_heartbeat = self.clock() + self.state.heartbeat_period
                continue
            buffer += chunk
            while True:
                try:
                    length = frame_length(buffer)
                except ValueError:
                    buffer = b""
                    break
                if length is None or len(buffer) < length:
                    break
                frame, buffer = buffer[:length], buffer[length:]
                try:
                    _, msg = decode_frame(frame)
                except Exception:  # noqa: BLE001
                    continue
                if msg.msg_type != MSG_TYPE_REQ:
                    continue
                reply = self.handle(msg)
                if reply is not None:
                    data = encode_frame(reply)
                    try:
                        if sock is not None:
                            sock.sendall(data)
                        else:
                            os.write(fd, data)
                    except OSError:
                        return

    # -- protocol ---------------------------------------------------------
    def handle(self, msg: CtrlMsg) -> Optional[CtrlMsg]:
        handler = getattr(self, f"_req_{msg.msg_id}", None)
        if handler is None:
            return None
        return handler(msg.payload)

    def _resp(self, msg_id: int, **fields: Any) -> CtrlMsg:
        return CtrlMsg(MSG_TYPE_RESP, msg_id, fields)

    def _req_101(self, p: dict) -> CtrlMsg:          # GetMACAddress
        return self._resp(201, mac=self.state.mac, resp=0)

    def _req_102(self, p: dict) -> CtrlMsg:          # SetMacAddress
        mac = p.get("mac") or b""
        if len(mac) != 6:
            return self._resp(202, resp=4)
        self.state.mac = mac
        return self._resp(202, resp=0)

    def _req_103(self, p: dict) -> CtrlMsg:          # GetWifiMode
        return self._resp(203, mode=self.state.mode, resp=0)

    def _req_104(self, p: dict) -> CtrlMsg:          # SetWifiMode
        mode = int(p.get("mode", 0))
        if mode > 3:
            return self._resp(204, resp=5)
        self.state.mode = mode
        return self._resp(204, resp=0)

    def _req_105(self, p: dict) -> CtrlMsg:          # GetAPScanList
        entries = self.state.scan_results
        return self._resp(205, count=len(entries), entries=entries, resp=0)

    def _req_106(self, p: dict) -> CtrlMsg:          # GetAPConfig
        if not self.state.sta_connected:
            return self._resp(206, resp=1)
        return self._resp(206, ssid=self.state.sta_ssid,
                          bssid=self.state.mac, rssi=-45, chnl=6,
                          sec_prot=3, resp=0)

    def _req_107(self, p: dict) -> CtrlMsg:          # ConnectAP
        ssid = p.get("ssid") or b""
        pwd = p.get("pwd") or b""
        if len(ssid) > 32:
            return self._resp(207, resp=4)
        if len(pwd) > 64:
            return self._resp(207, resp=4)
        bssid = p.get("bssid") or b""
        if len(bssid) > 18:
            return self._resp(207, resp=4)
        wanted = ssid if isinstance(ssid, bytes) else str(ssid).encode()
        known = [entry.get("ssid") for entry in self.state.scan_results]
        if wanted not in known:
            # No_AP_Found: the fixture only knows the APs in its scan list.
            self.state.sta_connected = False
            return self._resp(207, resp=2)
        self.state.sta_ssid = wanted
        self.state.sta_pwd = pwd if isinstance(pwd, bytes) else str(pwd).encode()
        self.state.sta_connected = True
        return self._resp(207, resp=0, mac=self.state.mac)

    def _req_108(self, p: dict) -> CtrlMsg:          # DisconnectAP
        self.state.sta_connected = False
        return self._resp(208, resp=0)

    def _req_109(self, p: dict) -> CtrlMsg:          # GetSoftAPConfig
        return self._resp(209, ssid=self.state.softap_ssid,
                          pwd=self.state.softap_pwd, chnl=self.state.channel,
                          sec_prot=self.state.security,
                          max_conn=self.state.max_conn,
                          ssid_hidden=self.state.hidden, bw=self.state.bandwidth,
                          resp=0)

    def _req_110(self, p: dict) -> CtrlMsg:          # SetSoftAPVendorSpecificIE
        return self._resp(210, resp=0)

    def _req_111(self, p: dict) -> CtrlMsg:          # StartSoftAP
        ssid = p.get("ssid") or b""
        if len(ssid) > 32 or len(p.get("pwd") or b"") > 64:
            return self._resp(211, resp=4)
        self.state.softap_ssid = ssid
        self.state.softap_pwd = p.get("pwd") or b""
        self.state.channel = int(p.get("chnl", 6))
        self.state.max_conn = int(p.get("max_conn", 4))
        self.state.softap_running = True
        return self._resp(211, resp=0, mac=self.state.mac)

    def _req_112(self, p: dict) -> CtrlMsg:          # GetSoftAPConnectedSTAList
        stations = [{"mac": self.state.mac, "rssi": -45}] \
            if self.state.softap_running else []
        return self._resp(212, num=len(stations), stations=stations, resp=0)

    def _req_113(self, p: dict) -> CtrlMsg:          # StopSoftAP
        self.state.softap_running = False
        return self._resp(213, resp=0)

    def _req_114(self, p: dict) -> CtrlMsg:          # SetPowerSaveMode
        mode = int(p.get("mode", 0))
        if mode not in (1, 2):
            return self._resp(214, resp=5)
        self.state.power_save = mode
        return self._resp(214, resp=0)

    def _req_115(self, p: dict) -> CtrlMsg:          # GetPowerSaveMode
        return self._resp(215, mode=self.state.power_save, resp=0)

    def _req_116(self, p: dict) -> CtrlMsg:          # OTABegin
        self.state.ota_active = True
        self.state.ota_bytes = 0
        return self._resp(216, resp=0)

    def _req_117(self, p: dict) -> CtrlMsg:          # OTAWrite
        data = p.get("ota_data") or b""
        if not data:
            return self._resp(217, resp=4)           # null write rejected
        if not self.state.ota_active:
            return self._resp(217, resp=3)
        self.state.ota_bytes += len(data)
        return self._resp(217, resp=0)

    def _req_118(self, p: dict) -> CtrlMsg:          # OTAEnd
        if not self.state.ota_active:
            return self._resp(218, resp=3)
        self.state.ota_active = False
        return self._resp(218, resp=0)

    def _req_119(self, p: dict) -> CtrlMsg:          # SetWifiMaxTxPower
        self.state.tx_power = int(p.get("wifi_max_tx_power", 20))
        return self._resp(219, resp=0)

    def _req_120(self, p: dict) -> CtrlMsg:          # GetWifiCurrTxPower
        return self._resp(220, wifi_curr_tx_power=self.state.tx_power, resp=0)

    def _req_121(self, p: dict) -> CtrlMsg:          # ConfigHeartbeat
        self.state.heartbeat_enabled = bool(p.get("enable"))
        if p.get("duration"):
            self.state.heartbeat_period = float(p["duration"]) / 1000.0
        return self._resp(221, resp=0)

    # -- events -----------------------------------------------------------
    def event(self, msg_id: int, **fields: Any) -> CtrlMsg:
        return CtrlMsg(MSG_TYPE_EVENT, msg_id, fields)
