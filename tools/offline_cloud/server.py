#!/usr/bin/env python3
"""Local replacement for the Mahlkönig device-service cloud (mTLS).

Serves the subset of `https://ngx-secured.sync.mahlkoenig.com/api/device-service/`
that drives grind-by-sync, so the grinder can run without the vendor cloud:

  GET  /api/device-service/system/time
  GET  /api/device-service/firmware/checkUpdate
  POST /api/device-service/brew-event/find        <- the grinder polls this
  GET  /api/device-service/brewer-binding/find
  POST /api/device-service/device-event/fire      <- grinder -> cloud events
  GET  /api/device-service/system/device-cert-download

A small control API on :8081 queues brew events (fed by a scale bridge):

  POST /event  {"mass": 18.2, "duration": 25.0, "doseType": "doubleShot"}

TLS: presents a server certificate; client certificates are accepted and
recorded. `--require-client-cert` enforces mTLS once the grinder's certificate
provisioning is understood.

Usage:
  ./gen_certs.sh /tmp/e64certs
  ./server.py --certs /tmp/e64certs --port 8443 --control-port 8081
"""

from __future__ import annotations

import argparse
import json
import ssl
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATE = {"events": [], "device_events": [], "bindings": []}
LOCK = threading.Lock()

DEFAULT_GRINDER = "HEM-HSG-HMI-S01"


def now_ms() -> int:
    return int(time.time() * 1000)


def device_service(handler, body: bytes) -> tuple[int, dict]:
    path = handler.path.split("?")[0]
    if path.endswith("/system/time"):
        return 200, {"timestamp": now_ms(), "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if path.endswith("/firmware/checkUpdate"):
        return 200, {"versionText": "", "downloadUrl": "", "notes": "", "updateAvailable": False}
    if path.endswith("/brew-event/find"):
        try:
            request = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return 400, {"error": "bad json"}
        grinder = (
            request.get("payload", {}).get("grinderId")
            or request.get("grinderId")
            or DEFAULT_GRINDER
        )
        with LOCK:
            events = [e for e in STATE["events"] if e.get("deviceId") == grinder]
            STATE["events"] = [e for e in STATE["events"] if e.get("deviceId") != grinder]
        return 200, {"brewEvents": events, "count": len(events)}
    if path.endswith("/brewer-binding/find"):
        return 200, {"bindings": STATE["bindings"]}
    if path.endswith("/device-event/fire"):
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return 400, {"error": "bad json"}
        with LOCK:
            STATE["device_events"].append({"received": now_ms(), **payload})
        return 200, {"status": "ok"}
    if path.endswith("/device-cert-download"):
        cert = Path(handler.server.cert_dir) / "client.crt"
        return 200, {"certificate": cert.read_text() if cert.exists() else ""}
    return 404, {"error": "unknown device-service route", "path": path}


class Service(BaseHTTPRequestHandler):
    server_version = "e64-local-cloud/0.1"

    def log_message(self, fmt: str, *args) -> None:  # quiet
        pass

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/api/device-service/"):
            status, payload = device_service(self, b"")
            self._send(status, payload)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.startswith("/api/device-service/"):
            status, payload = device_service(self, self._body())
            self._send(status, payload)
            return
        self._send(404, {"error": "not found"})


class Control(BaseHTTPRequestHandler):
    server_version = "e64-local-cloud-control/0.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"control: {fmt % args}", flush=True)

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b"{}"
        if self.path.rstrip("/") == "/event":
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._send(400, {"error": "bad json"})
                return
            mass_g = float(data.get("mass", 0))
            duration_s = float(data.get("duration", 0))
            valid = 15 < duration_s <= float(data.get("target", duration_s)) + 15
            event = {
                "eventUuid": str(uuid.uuid4()),
                "deviceId": data.get("grinderId", DEFAULT_GRINDER),
                "brewer": {"scale": {"id": data.get("scaleId", "local-scale")}},
                "groupNumber": "0",
                "doseIndex": data.get("doseIndex", "doubleShot"),
                "doseType": data.get("doseType", "doubleShot"),
                "validity": valid,
                "duration": int(duration_s * 1000),
                "mass": int(round(mass_g * 1000)),
                "grindEventUuid": data.get("grindEventUuid", str(uuid.uuid4())),
                "stopTarget": float(data.get("stopTarget", 0)),
                "cloudDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            with LOCK:
                STATE["events"].append(event)
            self._send(200, {"queued": event, "pending": len(STATE["events"])})
            return
        if self.path.rstrip("/") == "/bindings":
            with LOCK:
                STATE["bindings"].append(json.loads(body))
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not found"})

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/state":
            with LOCK:
                self._send(200, STATE)
            return
        self._send(404, {"error": "not found"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certs", required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--control-port", type=int, default=8081)
    parser.add_argument("--require-client-cert", action="store_true")
    args = parser.parse_args()

    certs = Path(args.certs)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certs / "server.crt", certs / "server.key")
    context.load_verify_locations(cafile=str(certs / "ca.crt"))
    context.verify_mode = ssl.CERT_REQUIRED if args.require_client_cert else ssl.CERT_NONE

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Service)
    server.cert_dir = str(certs)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    control = ThreadingHTTPServer(("127.0.0.1", args.control_port), Control)

    print(f"device-service: https://0.0.0.0:{args.port}/api/device-service/", flush=True)
    print(f"control:        http://127.0.0.1:{args.control_port}/event", flush=True)
    print(f"client certs:   {'required' if args.require_client_cert else 'accepted if offered'}", flush=True)

    threading.Thread(target=control.serve_forever, daemon=True).start()
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
