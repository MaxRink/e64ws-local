"""ESP control protocol: 14-byte TLV envelope + protobuf-C CtrlMsg.

Wire layout (observed in app-tree/bin/EspWifiConfig, see
docs/research/esp32-emulation-evidence.md):

    0x00  1  0x01
    0x01  2  LE16 endpoint length (8)
    0x03  8  "ctrlResp" (the host always sends on this endpoint)
    0x0B  1  0x02
    0x0C  2  LE16 payload length
    0x0E  N  protobuf CtrlMsg

CtrlMsg: field 1 msg_type, field 2 msg_id, and a oneof whose field number is
the msg_id. There is no checksum, sequence number or correlation id; responses
are matched by order and must arrive within 30 s.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ENDPOINT = b"ctrlResp"
ENDPOINT_EVENT = b"ctrlEvnt"
HEADER = b"\x01" + len(ENDPOINT).to_bytes(2, "little") + ENDPOINT + b"\x02"

MSG_REQ = 1
MSG_RESP = 2
MSG_EVENT = 3


# --------------------------------------------------------------- varints


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def write_varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1
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
    return write_varint(number << 3) + write_varint(value)


def field_bytes(number: int, payload: bytes) -> bytes:
    return write_varint((number << 3) | 2) + write_varint(len(payload)) + payload


def field_string(number: int, value: str) -> bytes:
    return field_bytes(number, value.encode())


# --------------------------------------------------------------- framing


def encode_frame(payload: bytes) -> bytes:
    return HEADER + len(payload).to_bytes(2, "little") + payload


def encode_event_frame(payload: bytes) -> bytes:
    """Events are accepted on either endpoint by parse_tlv; use ctrlEvnt."""
    header = b"\x01" + len(ENDPOINT_EVENT).to_bytes(2, "little") + ENDPOINT_EVENT + b"\x02"
    return header + len(payload).to_bytes(2, "little") + payload


def frame_length(buffer: bytes) -> int | None:
    if len(buffer) < 3:
        return None
    endpoint_len = int.from_bytes(buffer[1:3], "little")
    if endpoint_len > 64:
        raise ValueError(f"implausible endpoint length {endpoint_len}")
    header_end = 3 + endpoint_len + 1 + 2
    if len(buffer) < header_end:
        return None
    offset = 3 + endpoint_len
    if buffer[offset] != 0x02:
        raise ValueError(f"unexpected tag 0x{buffer[offset]:02x} at {offset}")
    payload_len = int.from_bytes(buffer[offset + 1:offset + 3], "little")
    return header_end + payload_len


def decode_frame(frame: bytes) -> tuple[bytes, bytes]:
    endpoint_len = int.from_bytes(frame[1:3], "little")
    endpoint = frame[3:3 + endpoint_len]
    offset = 3 + endpoint_len + 1
    payload_len = int.from_bytes(frame[offset:offset + 2], "little")
    return endpoint, frame[offset + 2:offset + 2 + payload_len]


# --------------------------------------------------------------- messages


def parse_message(msg: bytes) -> dict[int, list[int | bytes]]:
    fields: dict[int, list[int | bytes]] = {}
    pos = 0
    while pos < len(msg):
        key, pos = read_varint(msg, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = read_varint(msg, pos)
        elif wire == 2:
            length, pos = read_varint(msg, pos)
            value = msg[pos:pos + length]
            pos += length
        elif wire == 5:
            value = msg[pos:pos + 4]
            pos += 4
        elif wire == 1:
            value = msg[pos:pos + 8]
            pos += 8
        else:
            raise ValueError(f"unsupported wire type {wire}")
        fields.setdefault(number, []).append(value)
    return fields


def first(fields: dict[int, list[int | bytes]], number: int, default=None):
    values = fields.get(number)
    return values[0] if values else default


def as_int(value) -> int:
    if isinstance(value, bytes):
        return int.from_bytes(value, "little", signed=False)
    return int(value)


def as_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


@dataclass
class CtrlMsg:
    msg_type: int
    msg_id: int
    body: bytes = b""

    def encode(self) -> bytes:
        out = field_varint(1, self.msg_type) + field_varint(2, self.msg_id)
        if self.msg_id:
            out += field_bytes(self.msg_id, self.body)
        return out

    @classmethod
    def decode(cls, payload: bytes) -> "CtrlMsg":
        fields = parse_message(payload)
        msg_type = as_int(first(fields, 1, 0))
        msg_id = as_int(first(fields, 2, 0))
        body = first(fields, msg_id, b"") if msg_id else b""
        if not isinstance(body, bytes):
            body = b""
        return cls(msg_type, msg_id, body)


def parse_scan_result(data: bytes) -> dict:
    fields = parse_message(data)
    return {
        "ssid": as_text(first(fields, 1, b"")),
        "channel": as_int(first(fields, 2, 0)),
        "rssi": int.from_bytes(first(fields, 3, b"\x00\x00\x00\x00"), "little", signed=True)
        if isinstance(first(fields, 3), bytes) else as_int(first(fields, 3, 0)),
        "bssid": first(fields, 4, b"").hex(":") if isinstance(first(fields, 4), bytes) else "",
        "security": as_int(first(fields, 5, 0)),
    }


def scan_result(ssid: str, channel: int, rssi: int, bssid: bytes, security: int = 3) -> bytes:
    return (
        field_bytes(1, ssid.encode())
        + field_varint(2, channel)
        + field_varint(3, rssi)
        + field_bytes(4, bssid)
        + field_varint(5, security)
    )


# ------------------------------------------------------------- responses


def resp(msg_id: int, body: bytes = b"") -> bytes:
    """Encode a response CtrlMsg (msg_type=2) with the payload field."""
    return CtrlMsg(MSG_RESP, msg_id, body).encode()


def event(event_id: int, body: bytes = b"") -> bytes:
    return CtrlMsg(MSG_EVENT, event_id, body).encode()


def r_mac(mac: bytes) -> bytes:
    return resp(201, field_bytes(1, mac) + field_varint(2, 0))


def r_set_mac(status: int = 0) -> bytes:
    return resp(202, field_varint(1, status))


def r_get_mode(mode: int, status: int = 0) -> bytes:
    return resp(203, field_varint(1, mode) + field_varint(2, status))


def r_set_mode(status: int = 0) -> bytes:
    # protobuf-C omits the default value: Resp_SetWifiMode{resp=0} is an
    # empty message, encoded as field 204 with length 0.
    return resp(204, b"" if status == 0 else field_varint(1, status))


def r_scan(entries: list[bytes], status: int = 0) -> bytes:
    body = field_varint(1, len(entries))
    for entry in entries:
        body += field_bytes(2, entry)
    body += field_varint(3, status)
    return resp(205, body)


def r_ap_config(ssid: str, bssid: bytes, rssi: int, channel: int, sec: int, status: int = 0) -> bytes:
    body = (
        field_bytes(1, ssid.encode())
        + field_bytes(2, bssid)
        + field_varint(3, rssi & ((1 << 64) - 1))
        + field_varint(4, channel)
        + field_varint(5, sec)
        + field_varint(6, status)
    )
    return resp(206, body)


def r_connect(status: int = 0, mac: bytes = b"") -> bytes:
    body = field_varint(1, status)
    if mac:
        body += field_bytes(2, mac)
    return resp(207, body)


def r_simple(msg_id: int, status: int = 0) -> bytes:
    return resp(msg_id, b"" if status == 0 else field_varint(1, status))


def r_softap(ssid: str, pwd: str, channel: int, sec: int, max_conn: int,
            hidden: bool, bw: int, status: int = 0) -> bytes:
    body = (
        field_bytes(1, ssid.encode())
        + field_bytes(2, pwd.encode())
        + field_varint(3, channel)
        + field_varint(4, sec)
        + field_varint(5, max_conn)
        + field_varint(6, 1 if hidden else 0)
        + field_varint(7, bw)
        + field_varint(8, status)
    )
    return resp(209, body)


def r_sta_list(stations: list[tuple[bytes, int]], status: int = 0) -> bytes:
    body = field_varint(1, len(stations))
    for mac, rssi in stations:
        body += field_bytes(2, field_bytes(1, mac) + field_varint(2, rssi))
    body += field_varint(3, status)
    return resp(212, body)


def r_get_ps(mode: int, status: int = 0) -> bytes:
    return resp(215, field_varint(1, mode) + field_varint(2, status))


def r_get_tx_power(power: int, status: int = 0) -> bytes:
    return resp(220, field_varint(1, power) + field_varint(2, status))


def ev_init(data: bytes = b"\x01") -> bytes:
    return event(301, field_bytes(1, data))


def ev_heartbeat(number: int) -> bytes:
    return event(302, field_varint(1, number))


def ev_sta_disconnect(status: int = 1) -> bytes:
    return event(303, field_varint(1, status))


def ev_softap_disconnect(status: int = 1, mac: bytes = b"") -> bytes:
    body = field_varint(1, status)
    if mac:
        body += field_bytes(2, mac)
    return event(304, body)


# --------------------------------------------------------------- test data

# Byte-exact vector from docs/research/esp32-emulation-evidence.md.
VECTOR_REQ_SET_MODE = bytes.fromhex(
    "01 08 00 63 74 72 6c 52 65 73 70 02 09 00 08 01 10 68 c2 06 02 08 01"
)
VECTOR_RESP_SET_MODE = bytes.fromhex(
    "01 08 00 63 74 72 6c 52 65 73 70 02 08 00 08 02 10 cc 01 e2 0c 00"
)


def selftest() -> list[str]:
    problems: list[str] = []
    if frame_length(VECTOR_REQ_SET_MODE) != len(VECTOR_REQ_SET_MODE):
        problems.append("request framing length")
    endpoint, payload = decode_frame(VECTOR_REQ_SET_MODE)
    if endpoint != ENDPOINT:
        problems.append(f"endpoint {endpoint!r}")
    msg = CtrlMsg.decode(payload)
    if (msg.msg_type, msg.msg_id) != (MSG_REQ, 104):
        problems.append(f"CtrlMsg {msg.msg_type}/{msg.msg_id}")
    reply = encode_frame(r_set_mode(0))
    if reply != VECTOR_RESP_SET_MODE:
        problems.append(f"reply bytes {reply.hex()} != {VECTOR_RESP_SET_MODE.hex()}")
    if encode_frame(r_set_mode(0)) != VECTOR_RESP_SET_MODE:
        problems.append("resp() helper mismatch")
    return problems
