"""High-level ESP bridge used by the command handlers and REST routes.

Plays the HMI side of both channels:

* ``/dev/esps0``  - 14-byte TLV + protobuf (see :mod:`e64ctl.esp`)
* ``/dev/ttySTM1`` - one JSON object per burst (``ping``/``pong``,
  ``RequestVersion``, ``RequestSdioStatus``, ``StartFunction``)

By default an in-process :class:`~e64ctl.esp.EspSimulator` provides the ESP32
side on a pty, so the service runs standalone.  Pass a real device path to talk
to hardware or to the repository's ``tools/esp_stub.py``.
"""
from __future__ import annotations

import json
import os
import select
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .esp import CtrlMsg, EspClient, EspSimulator, EspTransport, SimEspState

NOZZLE_FUNCTION_COLORS = {
    "Off": 0,
    "Standby": 1,
    "Grinding": 2,
}


@dataclass
class JsonUartState:
    version_no: str = "01.11"
    version_date: str = "16.12.2025"
    sdio_status: int = 1
    sdio_error: int = 0
    fuse_failed: bool = False
    last_function: Optional[dict[str, Any]] = None


class JsonUartSimulator:
    """ESP app-UART side (``/dev/ttySTM1``): answers one JSON object per burst."""

    def __init__(self, target: str, state: JsonUartState) -> None:
        self.target = target
        self.state = state
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._master: Optional[int] = None
        self.received: list[dict[str, Any]] = []

    def start(self) -> None:
        import pty
        import tty

        master, slave = pty.openpty()
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
                                        name="esp-json-sim")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._master is not None:
            os.close(self._master)

    def _serve(self) -> None:
        buffer = b""
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([self._master], [], [], 0.2)
                if not ready:
                    continue
                chunk = os.read(self._master, 4096)
            except (OSError, ValueError, TypeError):
                return
            buffer += chunk
            while b"}" in buffer:
                end = buffer.index(b"}") + 1
                raw, buffer = buffer[:end], buffer[end:]
                try:
                    obj = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    continue
                self.received.append(obj)
                reply = self.reply(obj)
                if reply is not None:
                    os.write(self._master, json.dumps(reply).encode())

    def reply(self, obj: dict[str, Any]) -> Optional[dict[str, Any]]:
        if obj.get("ping") is True:
            return {"pong": True}
        kind = obj.get("type")
        if kind == "RequestVersion":
            return {"versionNo": self.state.version_no,
                    "versionDate": self.state.version_date}
        if kind == "RequestSdioStatus":
            return {"sdioStatus": self.state.sdio_status,
                    "sdioError": self.state.sdio_error,
                    "fuseFailed": self.state.fuse_failed}
        if kind == "StartFunction":
            self.state.last_function = obj
            return None
        return None


class EspBridge:
    """Facade over the protobuf channel and the JSON UART channel."""

    def __init__(self, device: Optional[str] = None,
                 json_device: Optional[str] = None,
                 simulate: bool = True,
                 state: Any = None) -> None:
        self.state = state
        self.device = device
        self.json_device = json_device
        self.simulate = simulate
        self.sim_state = SimEspState()
        self.json_state = JsonUartState()
        self.simulator: Optional[EspSimulator] = None
        self.json_simulator: Optional[JsonUartSimulator] = None
        self.client: Optional[EspClient] = None
        self.json_fd: Optional[int] = None
        self.json_buffer = b""
        self.last_json: Optional[dict[str, Any]] = None
        self.json_frames_rx = 0
        self.json_frames_tx = 0
        self.json_last: list[dict[str, Any]] = []
        self._json_lock = threading.Lock()
        self._tmpdir: Optional[str] = None

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self.simulate:
            self._tmpdir = tempfile.mkdtemp(prefix="e64esp-")
            self.device = self.device or os.path.join(self._tmpdir, "esps0")
            self.json_device = self.json_device or os.path.join(
                self._tmpdir, "ttySTM1")
            self.simulator = EspSimulator(self.device, self.sim_state)
            self.simulator.start()
            self.json_simulator = JsonUartSimulator(self.json_device,
                                                    self.json_state)
            self.json_simulator.start()
        if self.device:
            self.client = EspClient(EspTransport(self.device),
                                    on_event=self._on_event)
            try:
                self.client.start()
            except OSError:
                self.client = None
        if self.client is not None:
            # S50esp/EspDriver configures the ESP heartbeat at start-up; the
            # HMI treats three missed cycles as a dead link.
            self.client.request(121, {"enable": True, "duration": 1000}, 0.5)
        if self.json_device:
            deadline = time.time() + 1.0
            while time.time() < deadline and not os.path.exists(self.json_device):
                time.sleep(0.02)
            try:
                self.json_fd = os.open(self.json_device, os.O_RDWR | os.O_NOCTTY)
            except OSError:
                self.json_fd = None

    def stop(self) -> None:
        if self.client is not None:
            self.client.stop()
        if self.simulator is not None:
            self.simulator.stop()
        if self.json_simulator is not None:
            self.json_simulator.stop()
        if self.json_fd is not None:
            os.close(self.json_fd)

    # -- protobuf channel -------------------------------------------------
    def _on_event(self, msg: CtrlMsg) -> None:
        if self.state is None:
            return
        if msg.msg_id == 302:                    # Event_Heartbeat
            self.state.esp_heartbeat(msg.payload.get("hb_num", 0))
        elif msg.msg_id == 301:                  # Event_ESPInit
            self.state.esp.sdio_status = 2
            self.state.esp.alive = True
        elif msg.msg_id == 303:                  # StationDisconnectFromAP
            self.state.esp.ap_connected = False
            self.state.emit("espStationDisconnected", msg.payload)
        elif msg.msg_id == 304:                  # StationDisconnectFromESPSoftAP
            self.state.emit("espStaDisconnectedFromSoftAp", msg.payload)

    def _request(self, msg_id: int, payload: Optional[dict[str, Any]] = None,
                 timeout: float = 1.0) -> Optional[CtrlMsg]:
        if self.client is None:
            return None
        return self.client.request(msg_id, payload, timeout)

    def _sync_esp_state(self) -> None:
        if self.state is None:
            return
        # sdioStatus is owned by the JSON UART poll, not the WiFi mode.
        self.state.esp.mode = self.sim_state.mode
        self.state.esp.ap_connected = self.sim_state.sta_connected

    def apply_station_config(self, sta: Any) -> None:
        # SetWifiMode(STA) then ConnectAP with the browser-supplied credentials.
        self._request(104, {"mode": 1})
        reply = self._request(107, {
            "ssid": sta.ssid,
            "pwd": sta.password,
            "bssid": "",
            "is_wpa3_supported": False,
            "listen_interval": 3,
        })
        connected = bool(reply and reply.payload.get("resp") == 0)
        self.sim_state.mode = 1 if connected else 0
        self.sim_state.sta_ssid = sta.ssid.encode() if connected else b""
        self.sim_state.sta_connected = connected
        self._sync_esp_state()

    def start_softap(self, ssid: str, password: str = "", channel: int = 6) -> None:
        self._request(104, {"mode": 3})
        self._request(111, {"ssid": ssid, "pwd": password, "chnl": channel,
                            "sec_prot": 3, "max_conn": 4,
                            "ssid_hidden": False, "bw": 1})
        self.sim_state.mode = 3
        self.sim_state.softap_running = True
        self._sync_esp_state()

    def scan(self) -> list[dict[str, Any]]:
        reply = self._request(105)
        if reply is None:
            entries = self.sim_state.scan_results
        else:
            entries = reply.payload.get("entries") or []
        results = []
        for entry in entries:
            results.append({
                "ssid": _text(entry.get("ssid")),
                "bssid": _mac(entry.get("bssid")),
                "rssi": entry.get("rssi", 0),
                "channel": entry.get("chnl", 0),
                "encryptionMode": entry.get("sec_prot", 0),
            })
        return results

    def reset(self) -> None:
        if self.state is not None:
            self.state.esp.sdio_status = 1
        if self.simulator is not None:
            self.sim_state.sta_connected = False
            self.sim_state.mode = 0

    # -- JSON UART channel ------------------------------------------------
    def _json_send(self, payload: dict[str, Any], timeout: float = 0.5) -> Optional[dict]:
        if self.json_fd is None:
            return None
        line = json.dumps(payload)
        with self._json_lock:
            try:
                os.write(self.json_fd, line.encode())
            except OSError:
                return None
            self.json_frames_tx += 1
            self.json_last.append({"t": time.time(), "line": line})
            self.json_last = self.json_last[-64:]
            deadline = time.time() + timeout
            while time.time() < deadline:
                ready, _, _ = select.select([self.json_fd], [], [], 0.05)
                if not ready:
                    continue
                try:
                    chunk = os.read(self.json_fd, 4096)
                except OSError:
                    return None
                self.json_buffer += chunk
                if b"}" not in self.json_buffer:
                    continue
                end = self.json_buffer.index(b"}") + 1
                raw, self.json_buffer = self.json_buffer[:end], self.json_buffer[end:]
                try:
                    reply = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    continue
                self.json_frames_rx += 1
                self.last_json = reply
                return reply
        return None

    def ping(self) -> bool:
        reply = self._json_send({"ping": True})
        return bool(reply and reply.get("pong") is True)

    def request_version(self) -> Optional[dict[str, Any]]:
        reply = self._json_send({"type": "RequestVersion"})
        if reply and "versionNo" in reply and self.state is not None:
            self.state.esp.version_no = str(reply["versionNo"])
        return reply

    def request_sdio_status(self) -> Optional[dict[str, Any]]:
        reply = self._json_send({"type": "RequestSdioStatus"})
        if reply and self.state is not None:
            self.state.esp.sdio_status = int(reply.get("sdioStatus", 0))
            self.state.esp.sdio_error = int(reply.get("sdioError", 0))
            self.state.esp.fuse_failed = bool(reply.get("fuseFailed", False))
        return reply

    def start_function(self, function: str, color: int = 0,
                       brightness_phase: int = 0, min_brightness: int = 0,
                       max_brightness: int = 255,
                       brightness_increment: int = 1) -> Optional[dict]:
        return self._json_send({
            "type": "StartFunction",
            "function": function,
            "color": color,
            "brightnessPhase": brightness_phase,
            "minBrightness": min_brightness,
            "maxBrightness": max_brightness,
            "brightnessIncrement": brightness_increment,
        })


def _mac(value: Any) -> str:
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join(f"{byte:02x}" for byte in value)
    return _text(value)


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return "" if value is None else str(value)
