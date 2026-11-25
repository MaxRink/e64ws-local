"""The /dev/ttySTM1 JSON channel between the HMI and the ESP32.

Evidence: EspUartDriver opens /dev/ttySTM1 at 576000 8N1 with QSerialPort and
exchanges newline-delimited JSON. The recovered keys are ping, pong, version,
sdioStatus, requestConfig, alive, EspState. The exact value schema was not
recovered, so replies here are explicitly inferred.

The HMI sends {"ping":true}; the documented browser-side heartbeat expects
{"pong":true}. Everything else is answered conservatively and logged.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from .channels import LineChannel


class EspJsonServer:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._last_send = 0.0
        self.state: dict[str, Any] = {
            "frames_rx": 0,
            "frames_tx": 0,
            "last": [],
            "version": "vg-esp-1.0.0",
            "sdio_status": 2,
            "sdio_error": 0,
            "fuse_failed": False,
            "wifi_rssi": -45,
            "wifi_ap_connected": True,
            "alive": True,
        }
        self.channel = LineChannel(self.path, "espjson")
        self.channel.on_bytes = self._feed
        self._buffer = bytearray()
        self._pending_text = ""

    def start(self) -> None:
        self.channel.start()

    def _proactive(self) -> None:
        # Retained for compatibility; the HMI requests the version itself and
        # unsolicited frames can coalesce with a pong in one read().
        return

    def stop(self) -> None:
        self.channel.stop()

    def _feed(self, chunk: bytes) -> None:
        self._buffer.extend(chunk)
        text = bytes(self._buffer).decode(errors="replace")
        self._buffer = bytearray()
        self._pending = getattr(self, "_pending_text", "") + text
        while True:
            start = self._pending.find("{")
            if start < 0:
                self._pending = ""
                break
            depth = 0
            in_string = False
            escape = False
            end = None
            for index in range(start, len(self._pending)):
                char = self._pending[index]
                if in_string:
                    if escape:
                        escape = False
                    elif char == "\\":
                        escape = True
                    elif char == '"':
                        in_string = False
                elif char == '"':
                    in_string = True
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        end = index + 1
                        break
            if end is None:
                self._pending = self._pending[start:]
                break
            obj = self._pending[start:end]
            self._pending = self._pending[end:]
            self._handle(obj)
        self._pending_text = self._pending

    def _send(self, obj: dict) -> None:
        # The HMI accumulates bytes and parses one QJsonDocument per read();
        # two objects in one read are rejected as trailing garbage. Pace every
        # reply so a pong and a version response cannot coalesce.
        payload = json.dumps(obj, separators=(",", ":")).encode() + b"\n"
        with self._send_lock:
            gap = 0.05 - (time.time() - self._last_send)
            if gap > 0:
                time.sleep(gap)
            if self.channel.write(payload):
                with self.lock:
                    self.state["frames_tx"] += 1
            self._last_send = time.time()

    def _handle(self, line: str) -> None:
        with self.lock:
            self.state["frames_rx"] += 1
            self.state["last"].append({"t": round(time.time(), 3), "line": line[:500]})
            self.state["last"] = self.state["last"][-30:]
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(msg, dict):
            return
        if msg.get("ping"):
            self._send({"pong": True})
            return
        if "requestConfig" in msg or msg.get("type") == "RequestConfig":
            self._send({"type": "RequestConfig",
                        "sdioStatus": self.state["sdio_status"],
                        "sdioError": self.state["sdio_error"],
                        "fuseFailed": self.state["fuse_failed"],
                        "wifiRssi": self.state["wifi_rssi"],
                        "wifiApConnected": self.state["wifi_ap_connected"],
                        "alive": True})
            return
        if msg.get("type") == "RequestSdioStatus" or "sdioStatus" in msg:
            self._send({"type": "RequestSdioStatus",
                        "sdioStatus": self.state["sdio_status"],
                        "sdioError": self.state["sdio_error"],
                        "fuseFailed": self.state["fuse_failed"],
                        "wifiRssi": self.state["wifi_rssi"],
                        "wifiApConnected": self.state["wifi_ap_connected"],
                        "versionNo": "01.11", "versionDate": "16.12.2025"})
            return
        if "version" in msg or msg.get("type") == "RequestVersion":
            # Exact key recovered from EspUartDriver::processUartData():
            # "versionNo" (0x4880dc) and "versionDate" (0x4880e8).
            self._send({"versionNo": "01.11", "versionDate": "16.12.2025"})
            return
        if "sdioStatus" in msg:
            self._send({"sdioStatus": self.state["sdio_status"]})
            return
        # Unknown key: answer with a generic alive frame rather than silence,
        # so an HMI waiting on a timer is released.
        self._send({"alive": True})

    def summary(self) -> dict:
        with self.lock:
            return json.loads(json.dumps(self.state))
