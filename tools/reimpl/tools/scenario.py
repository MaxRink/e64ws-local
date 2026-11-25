#!/usr/bin/env python3
"""Scenario runner compatible with the /tmp/equiv record model.

Runs the same scenario JSON files the equivalence harness uses (ops: wss,
wss.raw, http, assert, capture, mark, sleep, db, shell, esp.event, esp.raw,
espjson.watch, state) against this reimplementation and writes a JSONL
transcript:

    {"seq": 1, "step": "h01", "op": "http", "kind": "http.rx",
     "t_rel_ms": 12, "payload": {...}, "meta": {...}}

The transcript can be compared with a vendor run by `tools/compare_runs.py`
(or dropped into the /tmp/equiv runs directory once a 'direct' target spec is
installed, see integration/reimpl_target.json).

Usage:
    python3 tools/scenario.py --scenario /tmp/equiv/scenarios/02_readonly.json \\
        --out runs/reimpl/02_readonly.jsonl
    python3 tools/scenario.py --scenario ... --url ws://127.0.0.1:9997 \\
        --http http://127.0.0.1:8080 --token-file /tmp/e64ctl/tmp/tok_x
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE.parent / "tests"))

from wsclient import WsClient  # noqa: E402


class Recorder:
    def __init__(self, path: Path, target: str, scenario: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = path.open("w")
        self.seq = 0
        self.t0 = time.monotonic()
        self.target = target
        self.scenario = scenario
        self._write({"record": "run", "target": target, "scenario": scenario,
                     "started_epoch": int(time.time())})

    def _write(self, obj: dict[str, Any]) -> None:
        self.handle.write(json.dumps(obj, sort_keys=True) + "\n")
        self.handle.flush()

    def event(self, step: str, op: str, kind: str, payload: Any,
              meta: Optional[dict[str, Any]] = None) -> None:
        self.seq += 1
        self._write({
            "seq": self.seq, "step": step, "op": op, "kind": kind,
            "t_rel_ms": int((time.monotonic() - self.t0) * 1000),
            "payload": payload, "meta": meta or {},
        })

    def close(self) -> None:
        self.handle.close()


class Runner:
    def __init__(self, recorder: Recorder, wss_url: str, http_url: str,
                 token: Optional[str], state_dir: Optional[str],
                 verbose: bool = False) -> None:
        self.rec = recorder
        self.wss_url = wss_url
        self.http_url = http_url.rstrip("/")
        self.token = token
        self.state_dir = state_dir
        self.verbose = verbose
        self.cookie: Optional[str] = None
        self.last_reply: Any = None
        self.last_http: Any = None
        self.refs: dict[str, Any] = {}
        self.ws: Optional[WsClient] = None
        self.ws_notoken: Optional[WsClient] = None

    # -- transport --------------------------------------------------------
    def _connect(self, token: Optional[str] = None) -> WsClient:
        if token is None and self.ws is not None:
            return self.ws
        parsed = urllib.parse.urlsplit(self.wss_url)
        tls = parsed.scheme == "wss"
        client = WsClient(parsed.hostname or "127.0.0.1",
                          parsed.port or (443 if tls else 80),
                          token=token, tls=tls)
        client.connect()
        return client

    def mint(self) -> str:
        status, body, headers = self.http(
            "POST", "/rest_api/login",
            {"userRole": "Owner", "password": "e64-equivalence"})
        if status != 200:
            raise RuntimeError(f"login failed: {status} {body!r}")
        for key, value in headers.items():
            if key.lower() == "authorization":
                return value.split(" ", 1)[-1]
        raise RuntimeError("login did not return an Authorization header")

    def http(self, method: str, path: str, body: Optional[dict] = None,
             timeout: float = 20.0) -> tuple[int, bytes, dict[str, str]]:
        url = self.http_url + path
        data = None
        if body is not None:
            data = json.dumps(body).encode()
        request = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.cookie:
            request.add_header("Cookie", self.cookie)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                headers = dict(response.headers)
                self._store_cookie(headers)
                return response.status, response.read(), headers
        except urllib.error.HTTPError as error:
            headers = dict(error.headers)
            self._store_cookie(headers)
            return error.code, error.read(), headers

    def _http_raw(self, method: str, path: str, data: bytes | None,
                  headers: Optional[dict[str, str]], timeout: float):
        url = self.http_url + path
        request = urllib.request.Request(url, data=data, method=method)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        if self.cookie:
            request.add_header("Cookie", self.cookie)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response_headers = dict(response.headers)
                self._store_cookie(response_headers)
                return response.status, response.read(), response_headers
        except urllib.error.HTTPError as error:
            response_headers = dict(error.headers)
            self._store_cookie(response_headers)
            return error.code, error.read(), response_headers

    def _store_cookie(self, headers: dict[str, str]) -> None:
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                self.cookie = value.split(";")[0]

    # -- steps ------------------------------------------------------------
    def run(self, scenario: dict[str, Any]) -> None:
        for step in scenario.get("steps", []):
            step_id = step.get("id", "?")
            op = step.get("op")
            try:
                getattr(self, f"step_{op.replace('.', '_')}")(step, step_id)
            except AttributeError:
                self.rec.event(step_id, op, "unsupported", None,
                               {"reason": f"op {op!r} not implemented"})
            except Exception as exc:  # noqa: BLE001
                self.rec.event(step_id, op, "error", str(exc))

    def step_mark(self, step, step_id) -> None:
        self.rec.event(step_id, "mark", "mark", step.get("label", ""))

    def step_sleep(self, step, step_id) -> None:
        seconds = float(step.get("seconds", step.get("ms", 0) / 1000.0))
        time.sleep(seconds)
        self.rec.event(step_id, "sleep", "sleep", seconds)

    def step_wss(self, step, step_id) -> None:
        message: dict[str, Any] = {"msgId": step.get("msg_id", 0)}
        if "type" in step:
            message["type"] = step["type"]
        elif "action" in step:
            message["type"] = "GrinderAction"
            data = dict(step.get("data") or {})
            data["actionType"] = step["action"]
            message["data"] = data
        if "data" in step and "data" not in message:
            message["data"] = step["data"]
        use_token = step.get("token", True)
        if use_token:
            if self.ws is None:
                if not self.token:
                    self.token = self.mint()
                self.ws = self._connect(self.token)
            client = self.ws
        else:
            if self.ws_notoken is None:
                self.ws_notoken = self._connect(None)
            client = self.ws_notoken
        self.rec.event(step_id, "wss", "wss.tx", message)
        client.send(message)
        payload = client.recv(float(step.get("timeout", 3.0)))
        if payload is None:
            self.last_reply = None
            self.rec.event(step_id, "wss", "wss.close", None,
                           {"closed": True})
            if use_token:
                self.ws = None
            else:
                self.ws_notoken = None
        else:
            decoded = json.loads(payload.decode())
            self.last_reply = decoded
            self.rec.event(step_id, "wss", "wss.rx", decoded)

    def step_wss_raw(self, step, step_id) -> None:
        client = self._connect()
        raw = step.get("text")
        if raw is None:
            raw = step.get("json")
        if isinstance(raw, str):
            payload = raw.encode()
        else:
            payload = json.dumps(raw).encode()
        self.rec.event(step_id, "wss.raw", "wss.tx.raw", payload.decode("utf-8", "replace"))
        # send the raw bytes as a text frame through the client helper
        header = bytearray([0x81])
        if len(payload) < 126:
            header.append(0x80 | len(payload))
        else:
            header.append(0x80 | 126)
            header += struct.pack(">H", len(payload))
        mask = os.urandom(4)
        header += mask
        header += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        client.sock.sendall(bytes(header))
        reply = client.recv(float(step.get("timeout", 2.0)))
        if reply is None:
            self.rec.event(step_id, "wss.raw", "wss.close", None,
                           {"closed": True})
            self.ws = None
        else:
            text = reply.decode("utf-8", "replace")
            try:
                self.last_reply = json.loads(text)
            except ValueError:
                self.last_reply = text
            self.rec.event(step_id, "wss.raw", "wss.rx.raw", text)

    def step_http(self, step, step_id) -> None:
        body_value = step.get("json")
        raw_body = step.get("body")
        if raw_body is not None:
            body_bytes = raw_body.encode() if isinstance(raw_body, str) else raw_body
            status, body, headers = self._http_raw(
                step.get("method", "GET"), step["path"], body_bytes,
                step.get("headers"), float(step.get("timeout", 20.0)))
        else:
            status, body, headers = self.http(
                step.get("method", "GET"), step["path"], body_value,
                float(step.get("timeout", 20.0)))
        mode = step.get("binary_mode")
        if mode == "len":
            payload = {"length": len(body)}
        elif mode == "sha256":
            import hashlib
            payload = {"length": len(body),
                       "sha256": hashlib.sha256(body).hexdigest()}
        else:
            text = body.decode("utf-8", "replace")
            try:
                payload = json.loads(text)
            except ValueError:
                payload = text
        self.last_http = {"status": status, "body": payload,
                          "headers": {k: v for k, v in headers.items()
                                      if k.lower() not in ("date", "server")}}
        self.rec.event(step_id, "http", "http.rx", self.last_http,
                       {"status": status,
                        "request": {"method": step.get("method", "GET"),
                                    "path": step["path"]}})

    def step_db(self, step, step_id) -> None:
        from guest_shim import run_command

        output = run_command(
            f'sqlite3 /db/HsgSqlite.db "{step["sql"]}"', self.state_dir)
        self.rec.event(step_id, "db", "db.rx", output, {"sql": step["sql"]})

    def step_shell(self, step, step_id) -> None:
        from guest_shim import run_command

        output = run_command(step["cmd"], self.state_dir)
        self.rec.event(step_id, "shell", "shell.rx", output,
                       {"cmd": step["cmd"]})

    def step_state(self, step, step_id) -> None:
        self.rec.event(step_id, "state", "state.rx", self._state_snapshot(),
                       {"keep": step.get("keep")})

    def step_esp_event(self, step, step_id) -> None:
        self.rec.event(step_id, "esp.event", "unsupported", None,
                       {"reason": "drive the ESP simulator directly"})

    def step_esp_raw(self, step, step_id) -> None:
        self.rec.event(step_id, "esp.raw", "unsupported", None,
                       {"reason": "drive the ESP simulator directly"})

    def step_espjson_watch(self, step, step_id) -> None:
        self.rec.event(step_id, "espjson.watch", "unsupported", None,
                       {"reason": "no ESP32 JSON traffic is recorded"})

    def step_capture(self, step, step_id) -> None:
        value = self._lookup(step.get("from", "last_reply"), step.get("path"))
        self.refs[step["as"]] = value
        self.rec.event(step_id, "capture", "capture", {"as": step["as"],
                                                       "value": value})

    def step_assert(self, step, step_id) -> None:
        source = step.get("source", "last_reply")
        if source == "last_reply":
            base = self.last_reply
        elif source == "last_http":
            base = self.last_http
        elif source == "state":
            base = self._state_snapshot()
        else:
            base = None
        value = self._lookup(source, step.get("path"))
        ok = True
        reason = ""
        if step.get("absent"):
            ok = value is None
            reason = "expected absent"
        elif "equals" in step:
            ok = value == step["equals"]
            reason = f"expected {step['equals']!r}"
        elif "equals_ref" in step:
            ok = value == self.refs.get(step["equals_ref"])
            reason = f"expected ref {step['equals_ref']!r}"
        self.rec.event(step_id, "assert", "assert", {"ok": ok,
                                                     "value": value},
                       {"expected": step.get("equals", step.get("equals_ref")),
                        "path": step.get("path"), "reason": reason})

    def step_wait(self, step, step_id) -> None:
        deadline = time.time() + float(step.get("timeout_s", 5))
        interval = float(step.get("interval_s", 0.2))
        wanted = step.get("equals")
        path = step.get("path", "")
        last = None
        while time.time() < deadline:
            client = self.ws
            if client is None:
                if not self.token:
                    self.token = self.mint()
                self.ws = self._connect(self.token)
                client = self.ws
            client.send({"type": step.get("type", "RequestDriverState"),
                         "msgId": 9000})
            payload = client.recv(2.0)
            if payload is None:
                self.ws = None
                continue
            last = json.loads(payload.decode())
            value = self._lookup("last_reply", path) if False else None
            current = last
            for part in path.split("."):
                current = current.get(part) if isinstance(current, dict) else None
            value = current
            if value == wanted:
                self.rec.event(step_id, "wait", "wait.ok",
                               {"value": value, "replies": 1})
                return
            time.sleep(interval)
        self.rec.event(step_id, "wait", "wait.timeout",
                       {"last": last, "want": wanted})

    def step_reboot(self, step, step_id) -> None:
        status, body, _ = self.http("POST", "/rest_api/reboot")
        self.rec.event(step_id, "reboot", "reboot.rx",
                       {"status": status, "body": body.decode("utf-8", "replace")})

    # -- helpers ----------------------------------------------------------
    def _lookup(self, source: str, path: Optional[str]) -> Any:
        if source == "last_http":
            base = self.last_http
        elif source == "state":
            base = self._state_snapshot()
        else:
            base = self.last_reply
        if not path:
            return base
        current = base
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit():
                index = int(part)
                current = current[index] if index < len(current) else None
            else:
                return None
        return current

    def _state_snapshot(self) -> dict[str, Any]:
        from guest_shim import _virtual_files

        root = self.state_dir or "/tmp/e64ctl"
        result: dict[str, Any] = {"files": {}}
        for name in ("db", "tmp"):
            base = os.path.join(root, name)
            if os.path.isdir(base):
                result["files"][name] = sorted(os.listdir(base))
        files = _virtual_files(self.state_dir)
        result["guest"] = {
            "gpio59": files["/sys/class/gpio/gpio59/value"],
            "gpio60": files["/sys/class/gpio/gpio60/value"],
            "gpio61": files["/sys/class/gpio/gpio61/value"],
            "backlight": files["/sys/class/backlight/backlight/brightness"],
            "leds": {name: files[f"/sys/class/leds/{name}/brightness"]
                     for name in ("led1", "led2", "led3", "led4")},
        }
        return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--wss", default="ws://127.0.0.1:9997")
    parser.add_argument("--http", default="http://127.0.0.1:8080")
    parser.add_argument("--token")
    parser.add_argument("--token-file")
    parser.add_argument("--state-dir", default="/tmp/e64ctl")
    parser.add_argument("--target", default="reimpl")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    token = args.token
    if args.token_file and not token:
        token = open(args.token_file).read().strip()
    scenario = json.loads(Path(args.scenario).read_text())
    recorder = Recorder(Path(args.out), args.target, scenario.get("id", "?"))
    runner = Runner(recorder, args.wss, args.http, token, args.state_dir,
                    args.verbose)
    try:
        runner.run(scenario)
    finally:
        recorder.close()
        for client in (runner.ws, runner.ws_notoken):
            if client is not None:
                client.close()
    print(f"wrote {args.out} ({recorder.seq} records)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
