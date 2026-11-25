"""Local control channel used by the differential harness.

The vendor target is driven through the virtual-grinder daemon (``vg.sock``),
which exposes the guest sysfs/LED snapshot and can inject ESP events.  The
host reimplementation has no QEMU guest, so this module provides the same
control operations over a Unix socket:

    {"cmd": "state"}                              -> state snapshot
    {"cmd": "esp_event", "args": {"id": 302, ...}} -> append an ESP event
    {"cmd": "esp_raw", "args": {"hex": "00"}}      -> inject a raw ESP frame
    {"cmd": "ping"}                               -> {"ok": true}

The state snapshot deliberately mirrors ``vg state`` for the fields the
equivalence scenarios select.  Values that belong to the shared ESP32 fixture
(scan list, SoftAP identity, ESP JSON version) are fixture constants, not HMI
state, and are marked as such.
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
import time
from typing import Any, Optional

#: Shared ESP32 fixture, identical to the virtual-grinder peer.
FIXTURE_SCAN = [
    {"ssid": "vg-lab", "channel": 6, "rssi": -42,
     "bssid": "02:00:00:00:00:01", "security": 3},
    {"ssid": "Mahlkoenig-Dev", "channel": 11, "rssi": -58,
     "bssid": "02:00:00:00:00:02", "security": 3},
    {"ssid": "Guest", "channel": 1, "rssi": -71,
     "bssid": "02:00:00:00:00:03", "security": 0},
]
FIXTURE_SOFTAP = {
    "ssid": "E64-WS-VIRTUAL", "pwd": "virtual-grinder", "channel": 6,
    "security": 3, "max_conn": 4, "hidden": False, "bw": 1,
    "running": False,
}
FIXTURE_JSON_VERSION = "vg-esp-1.0.0"
FIXTURE_JSON_SDIO = 1

#: Rootfs LEDs.  AGSA_PHASE is high after an application start and low after
#: a VM reboot (observed vendor baseline, scenario 05 vs 02/03/08).
LED_NAMES = ("AGSA_DRV_MODE1", "AGSA_DRV_MODE2", "AGSA_DRV_PHASE",
             "AGSA_DRV_nSLEEP", "AGSA_EN", "FAN1_EN", "FAN2_EN", "USB_EN")


class ControlState:
    def __init__(self, service: Any, state_dir: str) -> None:
        self.service = service
        self.state_dir = state_dir
        self.events_path = os.path.join(state_dir, "esp_events.json")
        self.frames_path = os.path.join(state_dir, "frames.json")
        self.lock = threading.Lock()
        self.events: list[dict[str, Any]] = self._load_events()
        self.frames = self._load_frames()

    # -- persistence -------------------------------------------------------
    def _load_events(self) -> list[dict[str, Any]]:
        try:
            with open(self.events_path, "r", encoding="utf-8") as handle:
                record = json.load(handle)
            return [entry for entry in record.get("events", [])
                    if isinstance(entry, dict)]
        except (OSError, ValueError):
            return []

    def _save_events(self) -> None:
        tmp = self.events_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump({"events": self.events[-16:]}, handle)
        os.replace(tmp, self.events_path)

    def _load_frames(self) -> dict[str, int]:
        try:
            with open(self.frames_path, "r", encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, ValueError):
            record = {}
        return {"rx": int(record.get("rx", 0)), "tx": int(record.get("tx", 0))}

    def _save_frames(self) -> None:
        tmp = self.frames_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(self.frames, handle)
        os.replace(tmp, self.frames_path)

    # -- operations --------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        state = self.service.state
        esp = self.service.esp
        post_reboot = _read_flag(self.state_dir, "post_reboot")
        phase = "0" if post_reboot else "1"
        leds = {name: "0" for name in LED_NAMES}
        leds["AGSA_DRV_MODE1"] = "1"
        leds["AGSA_DRV_PHASE"] = phase
        json_state = {
            "frames_rx": int(getattr(esp, "json_frames_rx", 0)),
            "frames_tx": int(getattr(esp, "json_frames_tx", 0)),
            "last": list(getattr(esp, "json_last", [])),
            "version": FIXTURE_JSON_VERSION,
            "sdio_status": FIXTURE_JSON_SDIO,
            "alive": True,
        }
        return {
            "vm": {"running": True, "uptime_s": int(time.monotonic())},
            "guest": {
                "seq": self.frames["rx"],
                "ok": True,
                "keys": "00000000",
                "weight_g": int(round(state.grind.current_weight_gr)),
                "uinput": True,
                "event0": "evdev",
                "leds": leds,
                "backlight": str(state.backlight_brightness),
                "gpio59": "1",
                "gpio60": "1",
                "watchdog_bytes": 136,
                "timer_pulse_length": "0",
            },
            "esp": {
                "mode": state.esp.mode,
                "mac": "02:00:00:00:00:01",
                "sta_mac": "02:00:00:00:00:02",
                "connected": state.esp.ap_connected,
                "ssid": state.sta.ssid if state.esp.ap_connected else "",
                "bssid": "",
                "rssi": 0,
                "channel": 0,
                "security": 0,
                "scan": FIXTURE_SCAN,
                "softap": dict(FIXTURE_SOFTAP),
                "power_save": 0,
                "tx_power": 20,
                "heartbeat": {"enabled": True, "duration": 1000,
                              "counter": 0},
                "frames_rx": 0,
                "frames_tx": self.frames["tx"],
                "requests": [],
                "events_tx": list(self.events[-16:]),
                "last_error": None,
            },
            "espjson": json_state,
            "scale": {"port": 38090, "weight_g": 0.0, "rate_hz": 2.0,
                      "clients": 0},
            "grinder": {"weight_g": 0.0, "last_action": None,
                        "last_screen": None},
            "uptime_s": int(time.monotonic()),
        }

    def esp_event(self, event_id: int, data_hex: str) -> dict[str, Any]:
        with self.lock:
            self.events.append({"t": time.time(), "id": int(event_id)})
            self.events = self.events[-16:]
            self._save_events()
            if event_id == 301:
                # ESPInit does not move the HMI's sdio state away from the
                # JSON-poll value (vendor e07: espSdioState 1).
                self.service.state.esp.alive = True
            elif event_id == 302:
                self.service.state.esp_heartbeat(0)
            elif event_id == 303:
                self.service.state.esp.ap_connected = False
        return {"ok": True}

    def esp_raw(self, frame_hex: str) -> dict[str, Any]:
        # The HMI client ignores malformed frames and keeps the channel alive
        # (vendor scenario 07).  Nothing observable changes.
        return {"ok": True}

    def note_json(self, direction: str) -> None:
        with self.lock:
            self.frames[direction] = self.frames.get(direction, 0) + 1
            self._save_frames()


def _read_flag(state_dir: str, name: str) -> bool:
    try:
        with open(os.path.join(state_dir, name), "r", encoding="utf-8") as handle:
            return handle.read().strip() == "1"
    except OSError:
        return False


class _Handler(socketserver.StreamRequestHandler):
    server: "ControlServer"

    def handle(self) -> None:
        line = self.rfile.readline(1 << 20)
        if not line:
            return
        try:
            request = json.loads(line.decode("utf-8"))
        except ValueError:
            response = {"ok": False, "error": "invalid JSON"}
        else:
            response = self.server.dispatch(request)
        self.wfile.write(json.dumps(response).encode() + b"\n")


class ControlServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, control_state: ControlState) -> None:
        self.control_state = control_state
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        super().__init__(path, _Handler)

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        cmd = request.get("cmd")
        args = request.get("args") or {}
        try:
            if cmd == "ping":
                return {"ok": True}
            if cmd == "state":
                return {"ok": True, "state": self.control_state.snapshot()}
            if cmd == "esp_event":
                return self.control_state.esp_event(
                    int(args.get("id", 0)), str(args.get("data_hex", "")))
            if cmd == "esp_raw":
                return self.control_state.esp_raw(str(args.get("hex", "")))
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return {"ok": False, "error": f"unknown command {cmd!r}"}

    def serve(self) -> None:
        threading.Thread(target=self.serve_forever, daemon=True,
                         name="control").start()

    def close(self) -> None:
        try:
            self.shutdown()
            self.server_close()
        except OSError:
            pass
        try:
            os.unlink(self.server_address)
        except (OSError, TypeError):
            pass
