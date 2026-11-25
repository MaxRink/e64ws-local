"""Virtual ESP32 co-processor for the E64 WS HMI.

Serves the 14-byte TLV + protobuf-C protocol the vendor `EspWifiConfig` binary
speaks on /dev/esps0. One response per request, in order, with no correlation
id -- the host pops responses from a FIFO and times out after 30 s.

State is synthetic. This is a development fixture, not a model of ESP RF
behaviour; see docs/ESP_PROTOBUF_SCHEMA.md for the recovered field numbers.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from . import proto
from .channels import ReconnectingChannel

DEFAULT_SCAN = [
    ("vg-lab", 6, -42, bytes.fromhex("020000000001"), 3),
    ("Mahlkoenig-Dev", 11, -58, bytes.fromhex("020000000002"), 3),
    ("Guest", 1, -71, bytes.fromhex("020000000003"), 0),
]


class EspServer:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.state: dict[str, Any] = {
            "mode": 0,               # 0 none, 1 STA, 2 AP, 3 APSTA
            "mac": "02:00:00:00:00:01",
            "sta_mac": "02:00:00:00:00:02",
            "connected": False,
            "ssid": "",
            "bssid": "",
            "rssi": 0,
            "channel": 0,
            "security": 0,
            "scan": [
                {"ssid": s, "channel": c, "rssi": r, "bssid": b.hex(":"), "security": sec}
                for s, c, r, b, sec in DEFAULT_SCAN
            ],
            "softap": {
                "ssid": "E64-WS-VIRTUAL",
                "pwd": "virtual-grinder",
                "channel": 6,
                "security": 3,
                "max_conn": 4,
                "hidden": False,
                "bw": 1,
                "running": False,
            },
            "power_save": 0,
            "tx_power": 20,
            "heartbeat": {"enabled": False, "duration": 0, "counter": 0},
            "frames_rx": 0,
            "frames_tx": 0,
            "requests": [],
            "events_tx": [],
            "last_error": None,
        }
        self._buffer = bytearray()
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self.channel = ReconnectingChannel(self.path, "esp0", self._on_bytes)

    # ---------------------------------------------------------- lifecycle

    def start(self) -> None:
        self.channel.start()

    def stop(self) -> None:
        self._heartbeat_stop.set()
        self.channel.stop()

    # ------------------------------------------------------------ framing

    def _on_bytes(self, chunk: bytes) -> None:
        self._buffer.extend(chunk)
        while True:
            try:
                length = proto.frame_length(self._buffer)
            except ValueError as exc:
                self.state["last_error"] = f"framing: {exc}"
                self._buffer.clear()
                return
            if length is None or len(self._buffer) < length:
                return
            frame, self._buffer = bytes(self._buffer[:length]), bytearray(self._buffer[length:])
            self._handle_frame(frame)

    def _handle_frame(self, frame: bytes) -> None:
        try:
            endpoint, payload = proto.decode_frame(frame)
            msg = proto.CtrlMsg.decode(payload)
        except Exception as exc:  # noqa: BLE001
            self.state["last_error"] = f"decode: {exc}"
            return
        with self.lock:
            self.state["frames_rx"] += 1
            self.state["requests"].append({
                "t": round(time.time(), 3),
                "endpoint": endpoint.decode(errors="replace"),
                "type": msg.msg_type,
                "id": msg.msg_id,
            })
            self.state["requests"] = self.state["requests"][-50:]

        if msg.msg_type != proto.MSG_REQ:
            return
        reply = self._respond(msg)
        if reply is not None:
            out = proto.encode_frame(reply)
            if self.channel.write(out):
                with self.lock:
                    self.state["frames_tx"] += 1

    def send_event(self, event_id: int, body: bytes = b"") -> bool:
        payload = proto.CtrlMsg(proto.MSG_EVENT, event_id, body).encode()
        ok = self.channel.write(proto.encode_event_frame(payload))
        if ok:
            with self.lock:
                self.state["frames_tx"] += 1
                self.state["events_tx"].append({"t": round(time.time(), 3), "id": event_id})
                self.state["events_tx"] = self.state["events_tx"][-50:]
        return ok

    # ----------------------------------------------------------- handlers

    def _respond(self, msg: proto.CtrlMsg) -> bytes | None:
        mid, body = msg.msg_id, msg.body
        fields = proto.parse_message(body) if body else {}
        try:
            handler = getattr(self, f"_req_{mid}", None)
            if handler is None:
                # Unknown request in the 101..121 range: answer with the
                # matching response id and resp=Invalid_Argument so a caller
                # blocked in the synchronous path is released.
                if 101 <= mid <= 121:
                    return proto.r_simple(mid + 100, 4)
                return None
            return handler(fields)
        except Exception as exc:  # noqa: BLE001 - never kill the channel
            with self.lock:
                self.state["last_error"] = f"handler {mid}: {exc}"
            if 101 <= mid <= 121:
                return proto.r_simple(mid + 100, 4)
            return None

    def _req_101(self, fields) -> bytes:  # GetMacAddress
        return proto.r_mac(bytes.fromhex(self.state["mac"].replace(":", "")))

    def _req_102(self, fields) -> bytes:  # SetMacAddress
        mac = fields.get(1, [b""])[0]
        if isinstance(mac, bytes) and len(mac) == 6:
            self.state["mac"] = mac.hex(":")
        return proto.r_set_mac(0)

    def _req_103(self, fields) -> bytes:  # GetWifiMode
        return proto.r_get_mode(self.state["mode"])

    def _req_104(self, fields) -> bytes:  # SetWifiMode
        mode = proto.as_int(proto.first(fields, 1, 0))
        if mode not in (0, 1, 2, 3):
            return proto.r_set_mode(4)
        with self.lock:
            self.state["mode"] = mode
        return proto.r_set_mode(0)

    def _req_105(self, fields) -> bytes:  # Scan
        with self.lock:
            entries = [
                proto.scan_result(
                    ap["ssid"], ap["channel"], ap["rssi"],
                    bytes.fromhex(ap["bssid"].replace(":", "")), ap["security"],
                )
                for ap in self.state["scan"]
            ]
        return proto.r_scan(entries)

    def _req_106(self, fields) -> bytes:  # GetAPConfig
        with self.lock:
            if not self.state["connected"]:
                return proto.r_ap_config("", b"", 0, 0, 0, 1)
            return proto.r_ap_config(
                self.state["ssid"],
                bytes.fromhex(self.state["bssid"].replace(":", "")),
                self.state["rssi"], self.state["channel"], self.state["security"], 0,
            )

    def _req_107(self, fields) -> bytes:  # ConnectAP
        ssid = proto.as_text(proto.first(fields, 1, b""))
        pwd = proto.as_text(proto.first(fields, 2, b""))
        bssid = proto.first(fields, 3, b"")
        mac = bytes.fromhex(self.state["sta_mac"].replace(":", ""))
        if ssid.upper().startswith("FAIL"):
            return proto.r_connect(3, mac)
        if not ssid:
            return proto.r_connect(4, mac)
        with self.lock:
            self.state.update({
                "connected": True, "ssid": ssid, "channel": 6, "rssi": -45,
                "security": 3, "mode": max(self.state["mode"], 1),
                "bssid": bssid.hex(":") if isinstance(bssid, bytes) and len(bssid) == 6
                else "02:00:00:00:00:09",
            })
            self.state["last_password_len"] = len(pwd)
        return proto.r_connect(0, mac)

    def _req_108(self, fields) -> bytes:  # DisconnectAP
        with self.lock:
            self.state.update({"connected": False, "ssid": "", "bssid": ""})
        return proto.r_simple(208, 0)

    def _req_109(self, fields) -> bytes:  # GetSoftAPConfig
        ap = self.state["softap"]
        return proto.r_softap(ap["ssid"], ap["pwd"], ap["channel"], ap["security"],
                              ap["max_conn"], ap["hidden"], ap["bw"], 0)

    def _req_110(self, fields) -> bytes:
        return proto.r_simple(210, 0)

    def _req_111(self, fields) -> bytes:  # StartSoftAP
        ap = self.state["softap"]
        ssid = proto.as_text(proto.first(fields, 1, b"")).strip("\x00")
        if ssid:
            ap["ssid"] = ssid
        ap["pwd"] = proto.as_text(proto.first(fields, 2, b"")).strip("\x00")
        ap["channel"] = proto.as_int(proto.first(fields, 3, ap["channel"]))
        ap["security"] = proto.as_int(proto.first(fields, 4, ap["security"]))
        ap["max_conn"] = proto.as_int(proto.first(fields, 5, ap["max_conn"]))
        ap["hidden"] = bool(proto.as_int(proto.first(fields, 6, 0)))
        ap["bw"] = proto.as_int(proto.first(fields, 7, ap["bw"]))
        ap["running"] = True
        self.state["mode"] = 2
        mac = bytes.fromhex(self.state["mac"].replace(":", ""))
        return proto.resp(211, proto.field_varint(1, 0) + proto.field_bytes(2, mac))

    def _req_112(self, fields) -> bytes:  # Connected STAs
        stations = []
        if self.state["softap"]["running"]:
            stations.append((bytes.fromhex("0200000000aa"), -40))
        return proto.r_sta_list(stations)

    def _req_113(self, fields) -> bytes:
        self.state["softap"]["running"] = False
        return proto.r_simple(213, 0)

    def _req_114(self, fields) -> bytes:
        self.state["power_save"] = proto.as_int(proto.first(fields, 1, 0))
        return proto.r_simple(214, 0)

    def _req_115(self, fields) -> bytes:
        return proto.r_get_ps(self.state["power_save"])

    def _req_116(self, fields) -> bytes:
        return proto.r_simple(216, 0)

    def _req_117(self, fields) -> bytes:
        return proto.r_simple(217, 0)

    def _req_118(self, fields) -> bytes:
        return proto.r_simple(218, 0)

    def _req_119(self, fields) -> bytes:
        self.state["tx_power"] = proto.as_int(proto.first(fields, 1, self.state["tx_power"]))
        return proto.r_simple(219, 0)

    def _req_120(self, fields) -> bytes:
        return proto.r_get_tx_power(self.state["tx_power"])

    def _req_121(self, fields) -> bytes:  # ConfigHeartbeat
        enabled = bool(proto.as_int(proto.first(fields, 1, 0)))
        duration = proto.as_int(proto.first(fields, 2, 0))
        with self.lock:
            self.state["heartbeat"].update({"enabled": enabled, "duration": duration})
        self._restart_heartbeat()
        return proto.r_simple(221, 0)

    # ---------------------------------------------------------- heartbeat

    def _restart_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=1)
        self._heartbeat_stop = threading.Event()
        hb = self.state["heartbeat"]
        if not hb["enabled"]:
            return
        period = max(1, hb["duration"] or 5)

        def run() -> None:
            while not self._heartbeat_stop.wait(period):
                hb["counter"] += 1
                self.send_event(302, proto.field_varint(1, hb["counter"]))

        self._heartbeat_thread = threading.Thread(target=run, name="vg-esp-hb", daemon=True)
        self._heartbeat_thread.start()

    # -------------------------------------------------------------- state

    def summary(self) -> dict:
        with self.lock:
            return json.loads(json.dumps(self.state))

    def set_scan(self, entries: list[dict]) -> None:
        with self.lock:
            self.state["scan"] = entries

    def connect(self, ssid: str, password: str = "") -> bool:
        body = proto.field_string(1, ssid) + proto.field_string(2, password)
        fields = proto.parse_message(body)
        self._req_107(fields)
        return not ssid.upper().startswith("FAIL")

    def disconnect(self) -> None:
        self._req_108({})
