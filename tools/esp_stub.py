#!/usr/bin/env python3
"""ESP32 co-processor stub for the E64 WS HMI.

The HMI talks to the ESP over /dev/esps0 (SDIO char device) using a 14-byte TLV
envelope followed by a protobuf-C CtrlMsg. This stub presents a pty at that
path, answers the control messages the HMI needs for WiFi, and logs every frame.

Framing (verified against EspWifiConfig, see docs/research/esp32-emulation-evidence.md):

    0x00  1  0x01
    0x01  2  LE16 endpoint length (8)
    0x03  8  endpoint string, "ctrlResp"
    0x0B  1  0x02
    0x0C  2  LE16 payload length
    0x0E  N  protobuf CtrlMsg

CtrlMsg: field 1 = msg_type (varint), field 2 = msg_id (varint), and a oneof
field whose number equals msg_id carrying the concrete message.

Usage:
    esp_stub.py --selftest            decode/encode the two published vectors
    esp_stub.py --serve [--device P]  run the pty stub (default /dev/esps0)
    esp_stub.py --inject HEX          write a frame to a pty and print the reply
"""

from __future__ import annotations

import argparse
import os
import select
import sys
import time
import tty

ENDPOINT = b"ctrlResp"
HEADER = b"\x01" + len(ENDPOINT).to_bytes(2, "little") + ENDPOINT + b"\x02"


# --- protobuf helpers -------------------------------------------------------

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


def parse_ctrl(msg: bytes) -> dict:
    fields: dict[int, object] = {}
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
        else:
            raise ValueError(f"unsupported wire type {wire}")
        fields[number] = value
    return fields


# --- framing ----------------------------------------------------------------

def encode_frame(msg: bytes) -> bytes:
    return HEADER + len(msg).to_bytes(2, "little") + msg


def frame_length(buffer: bytes) -> int | None:
    """Return the full frame length if a complete frame is buffered."""
    if len(buffer) < 3:
        return None
    endpoint_len = int.from_bytes(buffer[1:3], "little")
    if len(buffer) < 3 + endpoint_len + 1 + 2:
        return None
    offset = 3 + endpoint_len
    if buffer[offset] != 0x02:
        raise ValueError(f"unexpected tag 0x{buffer[offset]:02x} at {offset}")
    payload_len = int.from_bytes(buffer[offset + 1:offset + 3], "little")
    return offset + 3 + payload_len


def decode_frame(frame: bytes) -> tuple[bytes, bytes]:
    endpoint_len = int.from_bytes(frame[1:3], "little")
    endpoint = frame[3:3 + endpoint_len]
    offset = 3 + endpoint_len + 1
    payload_len = int.from_bytes(frame[offset:offset + 2], "little")
    return endpoint, frame[offset + 2:offset + 2 + payload_len]


# --- responses --------------------------------------------------------------

MSG_TYPE_REQ_RESP = {}


def response_for(fields: dict) -> bytes | None:
    """Build a CtrlMsg response for a recognised request id."""
    msg_id = fields.get(2)
    if msg_id is None:
        return None
    # Resp_* ids are Req_* + 100 in the recovered schema.
    resp_id = int(msg_id) + 100
    body = b""
    if msg_id == 104:          # Req_SetWifiMode -> Resp_SetWifiMode{resp=0}
        body = field_bytes(resp_id, b"")
    elif msg_id in (101, 102, 103, 106, 107, 108, 109, 110, 111):
        body = field_bytes(resp_id, b"")
    msg = field_varint(1, 2) + field_varint(2, resp_id) + body
    return msg


# --- transport --------------------------------------------------------------

def serve(device: str) -> int:
    master, slave = os.openpty()
    tty.setraw(master)
    slave_name = os.ttyname(slave)
    try:
        os.unlink(device)
    except FileNotFoundError:
        pass
    os.symlink(slave_name, device)
    print(f"esp-stub: {device} -> {slave_name}, endpoint={ENDPOINT.decode()}", flush=True)

    buffer = b""
    while True:
        readable, _, _ = select.select([master], [], [], 1.0)
        if not readable:
            continue
        chunk = os.read(master, 4096)
        if not chunk:
            continue
        buffer += chunk
        while True:
            try:
                length = frame_length(buffer)
            except ValueError as exc:
                print(f"esp-stub: framing error: {exc}", flush=True)
                buffer = b""
                break
            if length is None or len(buffer) < length:
                break
            frame, buffer = buffer[:length], buffer[length:]
            endpoint, payload = decode_frame(frame)
            try:
                fields = parse_ctrl(payload)
            except Exception as exc:  # noqa: BLE001 - log and continue
                print(f"esp-stub: bad CtrlMsg: {exc}", flush=True)
                continue
            print(f"esp-stub: rx endpoint={endpoint.decode(errors='replace')} "
                  f"msg_type={fields.get(1)} msg_id={fields.get(2)} "
                  f"frame={frame.hex()}", flush=True)
            reply = response_for(fields)
            if reply is not None:
                out = encode_frame(reply)
                os.write(master, out)
                print(f"esp-stub: tx msg_id={fields.get(2, 0) + 100} frame={out.hex()}",
                      flush=True)


def inject(hex_frame: str, timeout: float = 3.0) -> int:
    master, slave = os.openpty()
    tty.setraw(master)
    tty.setraw(slave)
    request = bytes.fromhex(hex_frame.replace(" ", ""))
    os.write(slave, request)
    deadline = time.time() + timeout
    buffer = b""
    while time.time() < deadline:
        readable, _, _ = select.select([master], [], [], 0.2)
        if not readable:
            continue
        buffer += os.read(master, 4096)
        length = frame_length(buffer)
        if length is None or len(buffer) < length:
            continue
        endpoint, payload = decode_frame(buffer[:length])
        fields = parse_ctrl(payload)
        reply = encode_frame(response_for(fields))
        os.write(master, reply)
        print(f"request : {request.hex()}")
        print(f"endpoint: {endpoint.decode()}")
        print(f"msg_id  : {fields.get(2)} -> reply msg_id {fields.get(2, 0) + 100}")
        print(f"reply   : {reply.hex()}")
        # Read the reply back on the host side of the pty.
        got = b""
        read_deadline = time.time() + 1.0
        while time.time() < read_deadline and len(got) < len(reply):
            r, _, _ = select.select([slave], [], [], 0.2)
            if r:
                got += os.read(slave, 4096)
        print(f"pty     : {'reply delivered' if got == reply else 'no reply delivered'}")
        return 0
    print("no reply", file=sys.stderr)
    return 1


def selftest() -> int:
    request = bytes.fromhex(
        "01 08 00 63 74 72 6c 52 65 73 70 02 09 00 08 01 10 68 c2 06 02 08 01"
    )
    expected_reply = bytes.fromhex(
        "01 08 00 63 74 72 6c 52 65 73 70 02 08 00 08 02 10 cc 01 e2 0c 00"
    )
    assert frame_length(request) == len(request), "request framing"
    endpoint, payload = decode_frame(request)
    assert endpoint == ENDPOINT, endpoint
    fields = parse_ctrl(payload)
    assert fields[1] == 1 and fields[2] == 104, fields
    assert fields[104] == b"\x08\x01", fields
    reply = encode_frame(response_for(fields))
    print(f"request  : {request.hex()}")
    print(f"reply    : {reply.hex()}")
    print(f"expected : {expected_reply.hex()}")
    if reply != expected_reply:
        print("MISMATCH", file=sys.stderr)
        return 1
    print("selftest: OK (framing, varint, msg_id mapping, byte-exact reply)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--device", default="/dev/esps0")
    parser.add_argument("--inject")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.inject:
        return inject(args.inject)
    if args.serve:
        return serve(args.device)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
