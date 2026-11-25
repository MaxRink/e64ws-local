#!/usr/bin/env python3
"""Offline checks for the virtual grinder protocol and image tooling.

Run: python3 tests/test_proto.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vgrinder import proto  # noqa: E402


def test_vectors() -> None:
    problems = proto.selftest()
    assert not problems, problems


def test_frame_roundtrip() -> None:
    msg = proto.CtrlMsg(proto.MSG_REQ, 104, proto.field_varint(1, 1)).encode()
    frame = proto.encode_frame(msg)
    assert proto.frame_length(frame) == len(frame)
    endpoint, payload = proto.decode_frame(frame)
    assert endpoint == proto.ENDPOINT
    decoded = proto.CtrlMsg.decode(payload)
    assert (decoded.msg_type, decoded.msg_id) == (proto.MSG_REQ, 104)


def test_scan_encoding() -> None:
    entry = proto.scan_result("vg-lab", 6, -42, bytes.fromhex("020000000001"), 3)
    body = proto.r_scan([entry])
    fields = proto.parse_message(proto.CtrlMsg.decode(body).body)
    assert proto.as_int(proto.first(fields, 1)) == 1
    nested = proto.first(fields, 2)
    assert isinstance(nested, bytes)
    parsed = proto.parse_scan_result(nested)
    assert parsed["ssid"] == "vg-lab"
    assert parsed["channel"] == 6


def test_token_file_shape() -> None:
    # The WSS server reads this JSON shape from /tmp/tok_<token>.
    token = "a" * 64
    payload = json.dumps(
        {"sessionId": "vg-test", "token": token, "role": "Owner", "expires": 1},
        separators=(",", ":"),
    )
    assert json.loads(payload)["token"] == token


if __name__ == "__main__":
    test_vectors()
    test_frame_roundtrip()
    test_scan_encoding()
    test_token_file_shape()
    print("tests: OK")
