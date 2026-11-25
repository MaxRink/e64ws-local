"""Virtual grinder control daemon.

Owns the QEMU process, the virtual ESP32 (SDIO + UART channels), the guest
agent channel, the synthetic scale, and the developer control surface:

  - Unix socket  run/vg.sock    (newline-delimited JSON, used by `vg`)
  - HTTP         127.0.0.1:8765 (dashboard + JSON API)
  - state file   run/state.json (rewritten every second)
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import secrets
import signal
import socketserver
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import http_probe, paths, proto, vnc, ws
from .channels import LineChannel
from .hardware import HardwareModel
from .esp import EspServer
from .espjson import EspJsonServer
from .vm import VM, VMError

LOG = logging.getLogger("vg")

KEY_NAMES = {
    "top": 0,
    "button1": 0,
    "bottom": 1,
    "button2": 1,
    "rotary": 2,
    "ddd": 3,
    "hopper": 4,
    "agsa": 5,
}

ACTIONS = {
    "manual": "StartGrindManual",
    "gbw": "StartGrindGbw",
    "gbt": "StartGrindGbt",
}


def ntc_millivolts(celsius: float) -> int:
    """HSG NTC divider: 3.3 V, 22k series, 10k/3984 K at 25 C.

    Matches NtcDriver::ntcMillivoltToTemperatureDegC() (CircuitType 0):
    R = (Vcc - V) / V * 22k, 1/T = 1/T0 + ln(R/R0)/B.
    """
    r = 10000.0 * math.exp(3984.0 * (1.0 / (celsius + 273.15) - 1.0 / 298.15))
    mv = 3300.0 * r / (r + 22000.0)
    return max(0, min(3300, int(round(mv))))


def _json_default(value: Any):
    if isinstance(value, Path):
        return str(value)
    return str(value)


class Daemon:
    def __init__(self, control_port: int | None = None, scale: bool = True):
        self.vm = VM()
        self.esp = EspServer(paths.ESP_SOCK)
        self.espjson = EspJsonServer(paths.ESPJSON_SOCK)
        self.agent = LineChannel(paths.AGENT_SOCK, "agent")
        self.scale: ws.ScaleServer | None = ws.ScaleServer() if scale else None
        self.control_port = control_port or paths.DEFAULTS["control_port"]
        self.weight_g = 0.0
        self.base_weight_g = 0.0
        self.weight_rate_g_per_s = 0.0
        self.grinding = False
        self._weight_lock = threading.Lock()
        self.hardware = HardwareModel()
        self.last_screen: dict | None = None
        self.last_action: dict | None = None
        self.started_at = time.time()
        self._stop = threading.Event()
        self._http: ThreadingHTTPServer | None = None
        self._unix: socketserver.UnixStreamServer | None = None
        self._writer: threading.Thread | None = None
        self._msg_id = 1

    # ---------------------------------------------------------- lifecycle

    def start(self, wait: bool = True) -> None:
        paths.ensure_dirs()
        LOG.info("starting VM")
        self.vm.start()
        self.vm.wait_for_qmp()
        self.esp.start()
        self.espjson.start()
        self.agent.start()
        if self.scale:
            self.scale.start(port=paths.DEFAULTS["scale_port"])
        self._start_control()
        self._writer = threading.Thread(target=self._state_loop, name="vg-state", daemon=True)
        self._writer.start()
        threading.Thread(target=self._weight_loop, name="vg-weight", daemon=True).start()
        if wait:
            booted = self.vm.wait_boot(timeout=float(os.environ.get("VG_BOOT_TIMEOUT", "150")))
            LOG.info("boot wait finished: %s", booted)
        LOG.info("daemon ready")

    def stop(self) -> None:
        LOG.info("stopping")
        self._stop.set()
        if self._http:
            self._http.shutdown()
            self._http.server_close()
        if self._unix:
            self._unix.shutdown()
            self._unix.server_close()
        self.agent.stop()
        self.esp.stop()
        self.espjson.stop()
        if self.scale:
            self.scale.stop()
        self.vm.stop()
        try:
            paths.DAEMON_SOCK.unlink()
        except FileNotFoundError:
            pass

    # ------------------------------------------------------------ control

    def _start_control(self) -> None:
        daemon = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # noqa: D401 - quiet
                LOG.debug("http: " + fmt, *args)

            def _send(self, status: int, body: bytes, ctype: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                url = urlsplit(self.path)
                if url.path in ("/", "/index.html"):
                    self._send(200, daemon.dashboard_html().encode(), "text/html; charset=utf-8")
                elif url.path == "/api/state":
                    self._send(200, json.dumps(daemon.state(), default=_json_default).encode(),
                               "application/json")
                elif url.path == "/api/logs":
                    count = int(parse_qs(url.query).get("n", ["200"])[0])
                    self._send(200, json.dumps(daemon.logs(count)).encode(), "application/json")
                elif url.path == "/healthz":
                    self._send(200, b"ok", "text/plain")
                else:
                    self._send(404, b"not found", "text/plain")

            def do_POST(self):  # noqa: N802
                url = urlsplit(self.path)
                if url.path != "/api/cmd":
                    self._send(404, b"not found", "text/plain")
                    return
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    request = json.loads(self.rfile.read(length) or b"{}")
                    result = daemon.dispatch(request.get("cmd", ""), request.get("args", {}))
                    self._send(200, json.dumps(result, default=_json_default).encode(),
                               "application/json")
                except Exception as exc:  # noqa: BLE001
                    self._send(500, json.dumps({"ok": False, "error": str(exc)}).encode(),
                               "application/json")

        self._http = ThreadingHTTPServer(("127.0.0.1", self.control_port), Handler)
        threading.Thread(target=self._http.serve_forever, name="vg-http", daemon=True).start()

        daemon = self

        class UnixHandler(socketserver.StreamRequestHandler):
            def handle(self):
                for raw in self.rfile:
                    try:
                        request = json.loads(raw or b"{}")
                        result = daemon.dispatch(request.get("cmd", ""), request.get("args", {}))
                    except Exception as exc:  # noqa: BLE001
                        result = {"ok": False, "error": str(exc),
                                  "trace": traceback.format_exc(limit=2)}
                    self.wfile.write((json.dumps(result, default=_json_default) + "\n").encode())
                    self.wfile.flush()

        try:
            paths.DAEMON_SOCK.unlink()
        except FileNotFoundError:
            pass
        self._unix = socketserver.ThreadingUnixStreamServer(str(paths.DAEMON_SOCK), UnixHandler)
        threading.Thread(target=self._unix.serve_forever, name="vg-unix", daemon=True).start()
        LOG.info("control: http://127.0.0.1:%d/  unix:%s", self.control_port, paths.DAEMON_SOCK)

    # ----------------------------------------------------------- dispatch

    def dispatch(self, cmd: str, args: dict | None = None) -> dict:
        args = args or {}
        handler = getattr(self, f"cmd_{cmd.replace('.', '_')}", None)
        if handler is None:
            return {"ok": False, "error": f"unknown command {cmd!r}"}
        try:
            return handler(**args)
        except TypeError as exc:
            return {"ok": False, "error": f"bad arguments for {cmd}: {exc}"}
        except Exception as exc:  # noqa: BLE001
            LOG.warning("command %s failed: %s", cmd, exc)
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------ commands

    def cmd_status(self) -> dict:
        vm = self.vm.status()
        guest = self._guest_state()
        return {
            "ok": True,
            "vm": vm,
            "boot": vm.get("boot"),
            "services": self._probe_services(),
            "guest": guest,
            "esp": self.esp.summary(),
            "espjson": self.espjson.summary(),
            "scale": self.scale.summary() if self.scale else None,
            "hardware": self.hardware.snapshot(),
            "grinder": {"weight_g": round(self.weight_g, 2),
                         "base_weight_g": self.base_weight_g,
                         "weight_rate_g_per_s": self.weight_rate_g_per_s,
                         "grinding": self.grinding,
                         "last_action": self.last_action},
            "control": {"http": self.control_port, "unix": str(paths.DAEMON_SOCK)},
            "uptime_s": round(time.time() - self.started_at, 1),
        }

    def cmd_state(self) -> dict:
        return {"ok": True, **self.state()}

    def cmd_issue(self, mode: str = "development") -> dict:
        if mode not in ("development", "custom"):
            return {"ok": False, "error": "mode must be development|custom"}
        result = self.agent.request(
            "exec mount -o remount,rw / 2>/dev/null; "
            f"sed -i '1s/^[^ ]*/{mode}/' /etc/issue; "
            "killall NgxUiApp 2>/dev/null; sleep 2; /etc/init.d/S90app start",
            timeout=30,
        )
        issue = self.agent.request("exec head -1 /etc/issue", timeout=4)
        return {"ok": result.get("ok", False), "mode": mode,
                "issue": issue.get("stdout", "").strip(), "restart": result}

    def cmd_hardware(self, **updates) -> dict:
        for key, value in updates.items():
            if hasattr(self.hardware, key):
                setattr(self.hardware, key, value)
        # Push the values the vendor actually polls into the guest fixture.
        args: list[str] = []
        if "agsa_current_ma" in updates:
            args += ["agsa_ma", str(int(updates["agsa_current_ma"]))]
        if "ntc1_c" in updates:
            args += ["ntc1_mv", str(ntc_millivolts(float(updates["ntc1_c"])))]
        if "ntc2_c" in updates:
            args += ["ntc2_mv", str(ntc_millivolts(float(updates["ntc2_c"])))]
        if "fan1_rpm" in updates:
            args += ["fan_rpm", str(int(updates["fan1_rpm"]))]
        guest = None
        if args:
            self.hardware.set_weight(self.weight_g)
            guest = self.agent.request("hw " + " ".join(args), timeout=4)
        return {"ok": True, "hardware": self.hardware.snapshot(), "guest": guest}

    def cmd_logs(self, n: int = 200) -> dict:
        return {"ok": True, "lines": self.logs(int(n))}

    def cmd_probe(self) -> dict:
        return {"ok": True, "services": self._probe_services(), "guest": self._guest_state()}

    def cmd_key(self, name: str | None = None, index: int | None = None,
                hold_ms: int = 150, value: int | None = None) -> dict:
        idx = index if index is not None else KEY_NAMES.get((name or "").lower())
        if idx is None:
            return {"ok": False, "error": f"unknown key {name!r}; use {sorted(KEY_NAMES)} or index"}
        if value is not None:
            return self.agent.request(f"key {idx} {1 if value else 0}", timeout=4)
        return self.agent.request(f"press {idx} {int(hold_ms)}", timeout=max(4, hold_ms / 1000 + 3))

    def cmd_key_down(self, name: str | None = None, index: int | None = None) -> dict:
        return self.cmd_key(name=name, index=index, value=1)

    def cmd_key_up(self, name: str | None = None, index: int | None = None) -> dict:
        return self.cmd_key(name=name, index=index, value=0)

    def cmd_rotate(self, clicks: int = 1) -> dict:
        if clicks == 0:
            return {"ok": False, "error": "clicks must be non-zero"}
        return self.agent.request(f"rotate {int(clicks)}", timeout=4)

    def cmd_weight(self, grams: float = 0.0) -> dict:
        with self._weight_lock:
            self.weight_g = float(grams)
            self.hardware.set_weight(self.weight_g)
        if self.scale:
            self.scale.set_weight(self.weight_g)
        result = self.agent.request(f"weight {int(grams)}", timeout=4)
        result["weight_g"] = self.weight_g
        return result

    def cmd_weight_base(self, grams: float = 0.0) -> dict:
        # Empty-basket tare; while idle this also sets the live weight.
        with self._weight_lock:
            self.base_weight_g = float(grams)
            if not self.grinding:
                self.weight_g = float(grams)
                self.hardware.set_weight(self.weight_g)
                target = self.weight_g
            else:
                target = None
        if target is not None:
            self.agent.request(f"weight {int(target)}", timeout=4)
            if self.scale:
                self.scale.set_weight(target)
        return {"ok": True, "base_weight_g": self.base_weight_g,
                "weight_g": self.weight_g, "grinding": self.grinding}

    def cmd_weight_rate(self, grams_per_s: float = 0.0) -> dict:
        self.weight_rate_g_per_s = max(0.0, float(grams_per_s))
        return {"ok": True, "weight_rate_g_per_s": self.weight_rate_g_per_s}

    def cmd_weight_start(self) -> dict:
        with self._weight_lock:
            self.weight_g = self.base_weight_g
            self.grinding = True
            self.hardware.set_weight(self.weight_g)
        self.agent.request(f"weight {int(self.weight_g)}", timeout=4)
        return {"ok": True, "weight_g": self.weight_g, "grinding": True}

    def cmd_weight_stop(self) -> dict:
        with self._weight_lock:
            self.grinding = False
        return {"ok": True, "weight_g": self.weight_g, "grinding": False}

    def cmd_wifi_status(self) -> dict:
        return {"ok": True, "esp": self.esp.summary()}

    def cmd_wifi_scan(self, add: list[dict] | None = None) -> dict:
        if add:
            current = self.esp.state["scan"]
            current.extend(add)
            self.esp.set_scan(current)
        return {"ok": True, "scan": self.esp.summary()["scan"]}

    def cmd_wifi_join(self, ssid: str = "", password: str = "") -> dict:
        if not ssid:
            return {"ok": False, "error": "ssid is required"}
        result = self.esp.connect(ssid, password)
        return {"ok": result, "esp": self.esp.summary()}

    def cmd_wifi_off(self) -> dict:
        self.esp.disconnect()
        return {"ok": True, "esp": self.esp.summary()}

    def cmd_esp_event(self, id: int = 302, data_hex: str = "") -> dict:
        body = bytes.fromhex(data_hex.replace(" ", "")) if data_hex else b""
        ok = self.esp.send_event(int(id), body)
        return {"ok": ok, "event": int(id)}

    def cmd_esp_raw(self, hex: str = "") -> dict:
        frame = bytes.fromhex(hex.replace(" ", ""))
        ok = self.esp.channel.write(frame)
        return {"ok": ok, "bytes": len(frame)}

    def cmd_shell(self, cmd: str = "") -> dict:
        if not cmd:
            return {"ok": False, "error": "cmd is required"}
        return self.agent.request("exec " + cmd, timeout=20)

    def cmd_grind(self, action: str = "start", mode: str = "manual",
                  target_g: float | None = None) -> dict:
        if action == "stop":
            return self._send_action("Stop")
        action_type = ACTIONS.get(mode.lower())
        if action_type is None:
            return {"ok": False, "error": f"unknown mode {mode!r}; use {sorted(ACTIONS)}"}
        if target_g is not None:
            self.cmd_weight(target_g)
        return self._send_action(action_type)

    def cmd_grind_start(self, mode: str = "manual", target_g: float | None = None) -> dict:
        if target_g is None:
            self.cmd_weight_start()
        return self.cmd_grind("start", mode, target_g)

    def cmd_grind_stop(self) -> dict:
        self.cmd_weight_stop()
        return self.cmd_grind("stop")

    def cmd_wss(self, message: dict | None = None, token: str | None = None,
                mint: bool = True, timeout: float = 8.0) -> dict:
        if not message:
            return {"ok": False, "error": "message is required"}
        token = token or (self._mint_token() if mint else None)
        url = f"wss://127.0.0.1:{paths.DEFAULTS['wss_port']}/"
        if token:
            url += f"?token={token}"
        try:
            reply = ws.query(url, message, timeout=timeout)
            safe_url = url.rsplit("token=", 1)[0] + "token=<token>" if token else url
            return {"ok": True, "reply": reply, "url": safe_url}
        except Exception as exc:  # noqa: BLE001
            safe_url = url.rsplit("token=", 1)[0] + "token=<token>" if token else url
            return {"ok": False, "error": str(exc), "url": safe_url}

    def cmd_web_get(self, path: str = "/login.php", https: bool = True) -> dict:
        port = paths.DEFAULTS["https_port"] if https else paths.DEFAULTS["http_port"]
        result = http_probe.probe_http(port, path, https=https)
        return {"ok": bool(result.get("ok")), **result}

    def cmd_screen(self, display: str = "qt", path: str | None = None,
                   timeout: float = 20.0) -> dict:
        port = paths.DEFAULTS["qt_vnc_port"] if display == "qt" else paths.DEFAULTS["qemu_vnc_port"]
        target = Path(path) if path else paths.SCREEN_DIR / f"{display}-{int(time.time())}.png"
        try:
            info = vnc.capture_to_file(target, "127.0.0.1", port, timeout=timeout)
            self.last_screen = info
            return {"ok": True, **info}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc), "display": display, "port": port}

    def cmd_vnc(self, action: str = "click", x: int = 0, y: int = 0,
                keysym: int = 0) -> dict:
        """Send a pointer or key event to the Qt VNC server (no touchscreen is
        present in the vendor userland; this is an emulation-only input path)."""
        try:
            if action == "click":
                return vnc.send_input(paths.DEFAULTS["qt_vnc_port"], [("pointer", x, y)])
            if action == "key":
                return vnc.send_input(paths.DEFAULTS["qt_vnc_port"], [("key", keysym)])
            return {"ok": False, "error": "action must be click|key"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def cmd_power(self, action: str = "reset") -> dict:
        if action == "reset":
            return self.vm.reset()
        if action == "off":
            return self.vm.powerdown()
        if action == "reboot":
            return self.agent.request("reboot", timeout=4)
        if action == "shutdown":
            return self.agent.request("poweroff", timeout=4)
        return {"ok": False, "error": "action must be reset|off|reboot|shutdown"}

    def cmd_shutdown(self) -> dict:
        threading.Thread(target=self.stop, name="vg-shutdown", daemon=True).start()
        return {"ok": True, "action": "shutdown"}

    def cmd_ping(self) -> dict:
        return {"ok": True, "pong": True, "uptime_s": round(time.time() - self.started_at, 1)}

    # ------------------------------------------------------------- helpers

    def _send_action(self, action_type: str) -> dict:
        self._msg_id += 1
        message = {
            "type": "GrinderAction",
            "msgId": self._msg_id,
            "data": {"actionType": action_type},
        }
        result = self.cmd_wss(message=message)
        self.last_action = {
            "t": round(time.time(), 3),
            "actionType": action_type,
            "ok": result.get("ok"),
            "reply": result.get("reply"),
            "error": result.get("error"),
        }
        return result

    def _mint_token(self, role: str = "Owner") -> str:
        token = secrets.token_hex(32)
        expires = int(time.time()) + 300
        payload = json.dumps(
            {"sessionId": "vg-" + token[:8], "token": token, "role": role, "expires": expires},
            separators=(",", ":"),
        )
        cmd = f"mkdir -p /tmp; printf '%s' '{payload}' > /tmp/tok_{token}; echo minted"
        reply = self.agent.request("exec " + cmd, timeout=6)
        if not reply.get("ok"):
            raise RuntimeError(f"could not mint a WSS token in the guest: {reply.get('error')}")
        return token

    def _guest_state(self) -> dict:
        if not self.agent.connected:
            return {"ok": False, "error": "guest agent not connected"}
        return self.agent.request("state", timeout=3)

    def _probe_services(self) -> dict:
        d = paths.DEFAULTS
        http = http_probe.probe_http(d["http_port"], "/", https=False)
        https = http_probe.probe_http(d["https_port"], "/login.php", https=True)
        wss_probe = {"ok": False}
        try:
            token = self._mint_token()
            reply = ws.query(
                f"wss://127.0.0.1:{d['wss_port']}/?token={token}",
                {"type": "RequestDriverState", "msgId": 1, "data": {}},
                timeout=4.0,
            )
            wss_probe = {"ok": True, "reply_type": reply.get("type"),
                         "refId": reply.get("refId")}
        except Exception as exc:  # noqa: BLE001
            wss_probe = {"ok": False, "error": str(exc)}
        vnc_probe = {"ok": False}
        try:
            import socket
            with socket.create_connection(("127.0.0.1", d["qt_vnc_port"]), timeout=2) as sock:
                banner = sock.recv(12)
                vnc_probe = {"ok": banner.startswith(b"RFB "), "banner": banner.decode(errors="replace")}
        except OSError as exc:
            vnc_probe = {"ok": False, "error": str(exc)}
        return {
            "http": {"ok": http.get("ok") and http.get("status") in (200, 301, 302),
                     "status": http.get("status"), "title": http.get("title"),
                     "error": http.get("error")},
            "https": {"ok": https.get("ok") and https.get("status") == 200,
                      "status": https.get("status"), "title": https.get("title"),
                      "error": https.get("error")},
            "wss": wss_probe,
            "qt_vnc": vnc_probe,
            "agent": {"ok": self.agent.connected},
            "esp_channel": {"ok": self.esp.channel.connected},
        }

    def state(self) -> dict:
        return {
            "vm": self.vm.status(),
            "guest": self._guest_state(),
            "esp": self.esp.summary(),
            "espjson": self.espjson.summary(),
            "scale": self.scale.summary() if self.scale else None,
            "hardware": self.hardware.snapshot(),
            "grinder": {"weight_g": round(self.weight_g, 2),
                         "base_weight_g": self.base_weight_g,
                         "weight_rate_g_per_s": self.weight_rate_g_per_s,
                         "grinding": self.grinding,
                         "last_action": self.last_action,
                         "last_screen": self.last_screen},
            "control": {"http": self.control_port, "unix": str(paths.DAEMON_SOCK)},
            "uptime_s": round(time.time() - self.started_at, 1),
        }

    def logs(self, n: int = 200) -> list[str]:
        try:
            lines = paths.SERIAL_LOG.read_text(errors="replace").splitlines()
        except OSError:
            return []
        return lines[-max(1, n):]

    def _weight_loop(self) -> None:
        # Simulate a load cell: base weight plus a rate while grinding. Only
        # send an agent update when the integer gram value changes, otherwise
        # the vendor serial log is flooded with weight commands.
        last = time.time()
        last_sent = None
        while not self._stop.is_set():
            time.sleep(0.1)
            now = time.time()
            dt = max(0.0, min(1.0, now - last))
            last = now
            with self._weight_lock:
                if not self.grinding:
                    continue
                grams = self.weight_g + self.weight_rate_g_per_s * dt
                self.weight_g = round(grams, 2)
                grams_int = int(self.weight_g)
                self.hardware.set_weight(self.weight_g)
            if grams_int != last_sent:
                last_sent = grams_int
                try:
                    self.agent.request(f"weight {grams_int}", timeout=0.4)
                except Exception:
                    pass
            if self.scale:
                self.scale.set_weight(self.weight_g)

    def _state_loop(self) -> None:
        while not self._stop.wait(1.0):
            try:
                paths.STATE_FILE.write_text(
                    json.dumps(self.state(), default=_json_default, indent=1)
                )
            except Exception:  # noqa: BLE001 - never kill the writer
                pass

    def dashboard_html(self) -> str:
        return DASHBOARD.replace("__CONTROL__", str(self.control_port))


DASHBOARD = """<!doctype html>
<html><head><meta charset="utf-8"><title>Virtual grinder</title>
<style>
body{font:14px ui-monospace,Menlo,monospace;background:#14161a;color:#d7dae0;margin:24px}
h1{font-size:18px;margin:0 0 12px}
section{border:1px solid #2c313a;border-radius:8px;padding:12px;margin:12px 0}
button{background:#2a6df4;color:#fff;border:0;border-radius:5px;padding:6px 10px;margin:2px;cursor:pointer}
button.alt{background:#3a404b}
pre{white-space:pre-wrap;word-break:break-word;background:#0b0d10;padding:10px;border-radius:6px;max-height:420px;overflow:auto}
</style></head><body>
<h1>Virtual grinder — E64 WS</h1>
<section>
<button onclick="cmd('key',{name:'top'})">press top</button>
<button onclick="cmd('key',{name:'bottom'})">press bottom</button>
<button onclick="cmd('rotate',{clicks:1})">rotate +1</button>
<button onclick="cmd('rotate',{clicks:-1})">rotate -1</button>
<button onclick="cmd('grind_start',{mode:'manual'})">grind manual</button>
<button onclick="cmd('grind_stop',{})">stop</button>
<button class="alt" onclick="cmd('screen',{})">screenshot</button>
<button class="alt" onclick="cmd('probe',{})">probe</button>
</section>
<section><pre id="state">loading…</pre></section>
<script>
async function cmd(c,a){await fetch('/api/cmd',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({cmd:c,args:a})});refresh();}
async function refresh(){try{const r=await fetch('/api/state');document.getElementById('state').textContent=JSON.stringify(await r.json(),null,1);}catch(e){document.getElementById('state').textContent=String(e);}}
refresh();setInterval(refresh,2000);
</script></body></html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="virtual grinder control daemon")
    parser.add_argument("--control-port", type=int, default=paths.DEFAULTS["control_port"])
    parser.add_argument("--no-scale", action="store_true")
    parser.add_argument("--no-wait", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(paths.WORK / "daemon.log"),
            logging.StreamHandler(sys.stderr),
        ],
    )
    daemon = Daemon(control_port=args.control_port, scale=not args.no_scale)
    stopping = threading.Event()

    def handle_signal(signum, _frame):
        LOG.info("signal %s", signum)
        stopping.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        daemon.start(wait=not args.no_wait)
    except VMError as exc:
        LOG.error("startup failed: %s", exc)
        return 1
    except Exception:
        LOG.exception("startup failed")
        daemon.stop()
        return 1

    while not stopping.wait(1.0):
        if not daemon.vm.running():
            # The exit status is the only direct evidence that QEMU ended
            # cleanly rather than crashing; `vg status` cannot report it.
            LOG.warning("QEMU exited with status %s",
                        daemon.vm.process.returncode
                        if daemon.vm.process else "unknown")
            break
    daemon.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
