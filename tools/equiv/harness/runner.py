"""Scenario runner: drives one scripted scenario against one target.

Record model (JSONL, one object per line):

    {"seq": 12, "step": "s7", "op": "wss", "kind": "wss.rx",
     "t_rel_ms": 43, "payload": {...}, "meta": {...}}

`seq` is assigned by the runner, so two runs of the same scenario align by
`seq` even when a step produced a different number of records (in which case
the comparison reports a structural difference -- which is the point).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import ssl
import time
import urllib.parse
from pathlib import Path
from typing import Any

from . import wsclient
from .target import Target

MAX_TEXT = 20000
SENSITIVE_HEADERS = ("authorization", "set-cookie", "cookie")


class Recorder:
    def __init__(self, path: Path, target: str, scenario: str, run_index: int):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("w")
        self.seq = 0
        self.t0 = time.monotonic()
        self.target = target
        self.scenario = scenario
        self.run_index = run_index
        self.header = {
            "record": "run",
            "target": target,
            "scenario": scenario,
            "run": run_index,
            "started_epoch": int(time.time()),
        }
        self._write(self.header)

    def _write(self, obj: dict) -> None:
        self.handle.write(json.dumps(obj, sort_keys=True) + "\n")
        self.handle.flush()

    def event(self, step: str, op: str, kind: str, payload: Any,
              meta: dict | None = None, t_rel_ms: int | None = None) -> None:
        self.seq += 1
        self._write({
            "seq": self.seq,
            "step": step,
            "op": op,
            "kind": kind,
            "t_rel_ms": t_rel_ms if t_rel_ms is not None else int(
                (time.monotonic() - self.t0) * 1000),
            "payload": payload,
            "meta": meta or {},
        })

    def close(self) -> None:
        self.handle.close()


def normalise_line(line: str) -> str:
    """Strip terminal control sequences and volatile numbers from a log line."""
    line = re.sub(r"\x1b\[[0-9;]*m", "", line)
    line = re.sub(r"\b\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}\b", "<DATETIME>", line)
    line = re.sub(r"\bpid[=: ]+\d+\b", "pid=<PID>", line)
    return line[:200]


def rate_bucket(frames: int, window_ms: int) -> str:
    """Coarse message-rate class; exact counts are timing noise."""
    if frames <= 0 or window_ms <= 0:
        return "none"
    hz = frames * 1000.0 / window_ms
    for limit, label in ((1, "<1Hz"), (5, "1-5Hz"), (20, "5-20Hz")):
        if hz < limit:
            return label
    return ">20Hz"


def _truncate(text: str, limit: int = MAX_TEXT) -> dict:
    if len(text) <= limit:
        return {"text": text}
    return {"text": text[:limit], "truncated": True, "full_len": len(text),
            "sha256": hashlib.sha256(text.encode()).hexdigest()}


def _jsonpath(obj: Any, path: str, default=None):
    cur = obj
    for part in path.split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            if part not in cur:
                return default
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return default
        else:
            return default
    return cur


class Runner:
    def __init__(self, target: Target, recorder: Recorder, scenario: dict,
                 verbose: bool = False):
        self.target = target
        self.rec = recorder
        self.scenario = scenario
        self.verbose = verbose
        self.cookies: dict[str, str] = {}
        self.bearer: str | None = None
        self.last_reply: Any = None
        self.last_reply_step: str | None = None
        self.last_http: dict | None = None
        self.msg_id = int(scenario.get("msg_id_start", 100))
        self.captures: dict[str, Any] = {}

    # ------------------------------------------------------------- helpers

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"    {message}")

    def _digest_path(self, obj: Any, path: str) -> None:
        """Replace a runtime-dependent array with its structural digest.

        Used for ring buffers such as RequestLogMessages: the *content* is a
        history of ambient events, not a function of the scripted inputs, but
        the level/category distribution is still a behavioural property.
        """
        parts = path.split(".")
        cur = obj
        for part in parts[:-1]:
            cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None:
                return
        key = parts[-1]
        if not isinstance(cur, dict) or not isinstance(cur.get(key), list):
            return
        lines = [x for x in cur[key] if isinstance(x, str)]
        levels = sorted({m.group(1) for line in lines
                         if (m := re.match(r"\(([A-Z])\)", line))})
        categories = sorted({m.group(0) for line in lines
                             if (m := re.search(r"\)\s*([A-Za-z_][A-Za-z0-9_]*)::", line))})
        cur[key] = {"levels": levels, "categories": categories}

    def _http(self, method: str, path: str, body: bytes | None,
              headers: dict[str, str], secure: bool, timeout: float) -> dict:
        base = self.target.https if secure else self.target.http
        parts = urllib.parse.urlsplit(base)
        host, port = parts.hostname, parts.port or (443 if secure else 80)
        context = None
        if secure:
            context = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            data = response.read()
            return {"status": response.status, "reason": response.reason,
                    "headers": {k.lower(): v for k, v in response.getheaders()},
                    "body": data}
        except OSError as exc:
            return {"status": 0, "reason": f"{type(exc).__name__}: {exc}",
                    "headers": {}, "body": b""}
        finally:
            conn.close()

    def _body_payload(self, data: bytes, content_type: str, binary_mode: str = "hash") -> dict:
        ctype = (content_type or "").lower()
        if binary_mode == "len":
            return {"binary_len": len(data)}
        if any(t in ctype for t in ("json", "text", "xml", "javascript", "html")):
            text = data.decode(errors="replace")
            try:
                return {"json": json.loads(text)}
            except json.JSONDecodeError:
                return _truncate(text)
        return {"binary_len": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}

    def _headers_payload(self, headers: dict[str, str]) -> dict:
        out = {}
        for key, value in headers.items():
            if key in SENSITIVE_HEADERS:
                out[key] = "<present>" if value else "<empty>"
            elif key in ("content-type", "location", "content-length", "server",
                         "cache-control", "www-authenticate", "connection"):
                out[key] = value
        return out

    def _shell(self, cmd: str, timeout: float = 20.0) -> dict:
        result = self.target.shell(cmd, timeout=timeout)
        if not result.get("ok"):
            return {"ok": False, "error": result.get("error", "shell failed")[:600]}
        return {"ok": True, "stdout": result.get("stdout", "")}

    def _boot_id(self) -> str:
        result = self._shell("cat /proc/sys/kernel/random/boot_id")
        if result.get("ok"):
            return result["stdout"].strip()
        return "unknown"

    # ---------------------------------------------------------------- steps

    def step_wss(self, step: dict, record_id: str) -> None:
        msg_type = step.get("type")
        action = step.get("action")
        message: dict[str, Any] = {"type": "GrinderAction" if action else msg_type,
                                   "msgId": step.get("msg_id", self.msg_id)}
        data = step.get("data")
        if action:
            message["data"] = dict(data or {}, actionType=action)
        elif data is not None:
            message["data"] = data
        self.msg_id = max(self.msg_id, int(message["msgId"])) + 1
        token = None
        if step.get("token", True):
            try:
                token = self.target.mint_token()
            except Exception as exc:  # noqa: BLE001 - recorded, not raised
                self.rec.event(record_id, "wss", "wss.token_error",
                               {"error": str(exc)}, {"type": message["type"]})
                return
        self.rec.event(record_id, "wss", "wss.tx", message,
                       {"token": "present" if token else "absent",
                        "action": action})
        url = self.target.wss_url(token)
        timeout = float(step.get("timeout", 10))
        exchange = wsclient.exchange(url, message, timeout=timeout)
        opened = exchange["open"]
        if opened.get("kind") != "open":
            self.rec.event(record_id, "wss", "wss.open_failed",
                           {"error": opened.get("data")},
                           {"http_status": (opened.get("data") or {}).get("http_status")})
            return
        self.rec.event(record_id, "wss", "wss.open",
                       {"handshake": opened.get("data")})
        reply = exchange["reply"]
        if reply is not None:
            try:
                parsed = json.loads(reply)
                for path in step.get("digest", []):
                    self._digest_path(parsed, path)
                payload = {"json": parsed}
                self.last_reply = parsed
            except json.JSONDecodeError:
                payload = {"text": reply}
                self.last_reply = None
            self.last_reply_step = record_id
            self.rec.event(record_id, "wss", "wss.rx", payload,
                           {"bytes": len(reply)})
        if exchange["close"]:
            close = exchange["close"]
            self.rec.event(record_id, "wss", "wss.closed",
                           {"code": close.get("code"), "reason": close.get("reason"),
                            "observed": close.get("kind")},
                           {"after_reply": reply is not None})
        else:
            self.rec.event(record_id, "wss", "wss.closed",
                           {"code": 1000, "reason": "", "observed": "client_close"},
                           {"after_reply": True})

    def step_wss_raw(self, step: dict, record_id: str) -> None:
        text = step["text"]
        token = None
        if step.get("token", True):
            token = self.target.mint_token()
        self.rec.event(record_id, "wss", "wss.tx", {"raw": text},
                       {"token": "present" if token else "absent"})
        exchange = wsclient.exchange(self.target.wss_url(token), text,
                                     timeout=float(step.get("timeout", 8)))
        if exchange["open"].get("kind") != "open":
            self.rec.event(record_id, "wss", "wss.open_failed",
                           {"error": exchange["open"].get("data")})
            return
        if exchange["reply"] is not None:
            try:
                self.rec.event(record_id, "wss", "wss.rx",
                               {"json": json.loads(exchange["reply"])})
                self.last_reply = json.loads(exchange["reply"])
            except json.JSONDecodeError:
                self.rec.event(record_id, "wss", "wss.rx", {"text": exchange["reply"]})
        if exchange["close"]:
            self.rec.event(record_id, "wss", "wss.closed",
                           {"code": exchange["close"].get("code"),
                            "reason": exchange["close"].get("reason"),
                            "observed": exchange["close"].get("kind")})

    def step_http(self, step: dict, record_id: str) -> None:
        method = step.get("method", "POST").upper()
        path = step["path"]
        headers = {"Accept": "*/*"}
        headers.update(step.get("headers", {}))
        body: bytes | None = None
        if "json" in step:
            body = json.dumps(step["json"], separators=(",", ":")).encode()
            headers.setdefault("Content-Type", "application/json")
        elif "form" in step:
            body = urllib.parse.urlencode(step["form"]).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif "body" in step:
            body = step["body"].encode()
        if step.get("session") and self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if step.get("auth") and self.bearer:
            headers["Authorization"] = f"Bearer {self.bearer}"
        secure = step.get("secure", True)
        req_meta = {"method": method, "secure": secure,
                    "session": bool(step.get("session") and self.cookies),
                    "auth": bool(step.get("auth") and self.bearer)}
        self.rec.event(record_id, "http", "http.req",
                       {"method": method, "path": path,
                        "body": (body.decode(errors="replace") if body else "")},
                       req_meta)
        started = time.monotonic()
        response = self._http(method, path, body, headers, secure,
                              float(step.get("timeout", 20)))
        elapsed = int((time.monotonic() - started) * 1000)
        content_type = response["headers"].get("content-type", "")
        # Persist the session credential the same way a browser would.
        set_cookie = response["headers"].get("set-cookie")
        if set_cookie:
            pair = set_cookie.split(";", 1)[0]
            if "=" in pair:
                name, value = pair.split("=", 1)
                self.cookies[name.strip()] = value.strip()
        auth = response["headers"].get("authorization", "")
        if auth.lower().startswith("bearer "):
            self.bearer = auth.split(" ", 1)[1].strip()
        payload = {"status": response["status"], "reason": response["reason"],
                   "headers": self._headers_payload(response["headers"]),
                   "body": self._body_payload(response["body"], content_type,
                                              step.get("binary_mode", "hash"))}
        self.last_http = {"status": payload["status"], "body": payload["body"],
                          "headers": payload["headers"]}
        self.rec.event(record_id, "http", "http.resp", payload,
                       {"elapsed_ms": elapsed})

    def step_shell(self, step: dict, record_id: str) -> None:
        result = self._shell(step["cmd"], timeout=float(step.get("timeout", 20)))
        if result.get("ok"):
            self.rec.event(record_id, "shell", "shell.out",
                           _truncate(result["stdout"]), {"cmd": step["cmd"]})
        else:
            self.rec.event(record_id, "shell", "shell.error", result,
                           {"cmd": step["cmd"]})

    def step_db(self, step: dict, record_id: str) -> None:
        sql = step["sql"]
        db = step.get("db", "/db/HsgSqlite.db")
        escaped = sql.replace("'", "'\"'\"'")
        cmd = f"sqlite3 -json {db} '{escaped}'"
        result = self._shell(cmd, timeout=30)
        payload: dict[str, Any] = {"sql": sql}
        if not result.get("ok"):
            payload["error"] = result.get("error")
        else:
            text = result["stdout"].strip()
            try:
                payload["rows"] = json.loads(text) if text else []
            except json.JSONDecodeError:
                payload["raw"] = text[:2000]
        self.rec.event(record_id, "db", "db.rows", payload)

    def step_state(self, step: dict, record_id: str) -> None:
        state = self.target.state()
        keep = step.get("keep")
        if keep:
            state = {k: _jsonpath(state, k) for k in keep}
        self.rec.event(record_id, "state", "target.state", state)

    def step_esp_event(self, step: dict, record_id: str) -> None:
        event_id = int(step["id"])
        data_hex = step.get("data", "")
        before = self.target.espjson_state()
        result = self.target.esp_event(event_id, data_hex)
        self.rec.event(record_id, "esp.event", "esp.tx",
                       {"id": event_id, "data_hex": data_hex}, result)
        time.sleep(float(step.get("settle_ms", 300)) / 1000)
        self._record_esp_state(record_id, before)

    def step_esp_raw(self, step: dict, record_id: str) -> None:
        before = self.target.espjson_state()
        result = self.target.esp_raw(step["frame_hex"])
        self.rec.event(record_id, "esp.raw", "esp.tx",
                       {"frame_hex": step["frame_hex"]}, result)
        time.sleep(float(step.get("settle_ms", 300)) / 1000)
        self._record_esp_state(record_id, before)

    def _record_esp_state(self, record_id: str, before: dict) -> None:
        state = self.target.state().get("esp", {})
        requests = state.get("requests", [])
        events = state.get("events_tx", [])
        # Cumulative frame counters are daemon-lifetime totals, not a function
        # of the scenario. The event/request tails carry the same evidence.
        payload = {
            "requests": requests[-int(self.scenario.get("esp_request_tail", 6)):],
            "events_tx": events[-4:],
            "last_error": state.get("last_error"),
        }
        self.rec.event(record_id, "esp", "esp.state", payload)

    def step_espjson_watch(self, step: dict, record_id: str) -> None:
        window_ms = int(step.get("ms", 1500))
        before = self.target.espjson_state()
        before_rx = int(before.get("frames_rx") or 0)
        time.sleep(window_ms / 1000)
        after = self.target.espjson_state()
        after_rx = int(after.get("frames_rx") or 0)
        lines = [entry.get("line", "") for entry in after.get("last", [])]
        parsed = []
        pings = 0
        for line in lines:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parsed.append({"malformed": line[:200]})
                continue
            if isinstance(obj, dict) and set(obj.keys()) == {"ping"}:
                pings += 1
                continue
            parsed.append(obj)
        # Only the tail of the window is observable through the daemon. The
        # compared payload keeps the deterministic property (heartbeat present,
        # order-of-magnitude rate); the raw sample stays in `meta`, which the
        # comparison never reads, so UI-driven animation frames cannot make a
        # correct implementation look different.
        distinct = []
        for item in parsed:
            if item not in distinct:
                distinct.append(item)
        period_ms = (window_ms / after_rx_delta) if (after_rx_delta := (after_rx - before_rx)) else None
        self.rec.event(record_id, "esp.json", "esp.json.window", {
            "window_ms": window_ms,
            "heartbeat_seen": pings > 0,
            "heartbeat_rate": rate_bucket(after_rx_delta, window_ms),
        }, {"non_ping_frames": distinct, "frames_delta": after_rx_delta,
            "period_ms": round(period_ms, 1) if period_ms else None})

    def step_wait(self, step: dict, record_id: str) -> None:
        path = step["path"]
        expected = step.get("equals", "__absent__")
        timeout = float(step.get("timeout_s", 30))
        interval = float(step.get("interval_s", 0.5))
        started = time.monotonic()
        polls = 0
        last = None
        ok = False
        while time.monotonic() - started < timeout:
            polls += 1
            token = self.target.mint_token()
            exchange = wsclient.exchange(self.target.wss_url(token),
                                         {"type": step.get("type", "RequestDriverState"),
                                          "msgId": 900 + polls}, timeout=8)
            last = exchange.get("reply")
            if last:
                try:
                    value = _jsonpath(json.loads(last), path)
                except json.JSONDecodeError:
                    value = None
                if expected == "__absent__":
                    ok = value is not None
                else:
                    ok = value == expected
                if ok:
                    break
            time.sleep(interval)
        elapsed = int((time.monotonic() - started) * 1000)
        last_value = None
        if last:
            try:
                last_value = _jsonpath(json.loads(last), path)
            except json.JSONDecodeError:
                last_value = None
        self.rec.event(record_id, "wait", "wait.result", {
            "path": path,
            "expected": expected,
            "ok": ok,
            "last_value": last_value,
        }, {"elapsed_ms": elapsed})

    def step_reboot(self, step: dict, record_id: str) -> None:
        before = self._boot_id()
        self.rec.event(record_id, "reboot", "reboot.request",
                       {"action": step.get("action", "reboot")}, {})
        started = time.monotonic()
        result = self.target.power(step.get("action", "reboot"))
        self.rec.event(record_id, "reboot", "reboot.ack",
                       {"ok": result.get("ok"), "error": result.get("error")},
                       {"ack": result})
        ready = self.target.wait_ready(float(step.get("timeout_s", 180)))
        elapsed = int((time.monotonic() - started) * 1000)
        after = self._boot_id() if ready else "not-ready"
        self.rec.event(record_id, "reboot", "reboot.ready", {
            "ready": ready,
            "boot_id_changed": bool(before and after and before != after),
        }, {"elapsed_ms": elapsed})

    def step_mark(self, step: dict, record_id: str) -> None:
        self.rec.event(record_id, "mark", "mark", {"label": step.get("label", "")})

    def step_sleep(self, step: dict, record_id: str) -> None:
        time.sleep(float(step.get("ms", 500)) / 1000)
        self.rec.event(record_id, "sleep", "sleep", {"ms": int(step.get("ms", 500))})

    def step_logs(self, step: dict, record_id: str) -> None:
        result = self.target.logs(int(step.get("n", 200))) if hasattr(self.target, "logs") else {"ok": False}
        if not result.get("ok"):
            self.rec.event(record_id, "logs", "logs.error",
                           {"error": result.get("error", "no log adapter")})
            return
        noise = ("vg-agent:", "tok_", "/dev/ttySTM0", "random: crng")
        lines = [line for line in result.get("lines", [])
                 if line.strip() and not any(marker in line for marker in noise)]
        hmi = [line for line in lines if re.search(r"\((C|W|E)\)", line)]
        levels = sorted({m.group(1) for line in hmi if (m := re.search(r"\(([CWE])\)", line))})
        categories = sorted({m.group(1) for line in hmi
                             if (m := re.search(r"\)\s*([A-Za-z_][A-Za-z0-9_]*)::", line))})
        self.rec.event(record_id, "logs", "logs.digest", {
            "total_lines": len(lines),
            "hmi_log_lines": len(hmi),
            "levels": levels,
            "categories": categories,
        }, {"tail": [normalise_line(x) for x in lines[-8:]]})

    def step_capture(self, step: dict, record_id: str) -> None:
        source = step.get("from", "last_reply")
        if source == "last_reply":
            value = self.last_reply
        elif source == "last_http":
            value = self.last_http
        elif source == "state":
            value = self.target.state()
        else:
            value = None
        actual = _jsonpath(value, step["path"]) if step.get("path") else value
        name = step["as"]
        self.captures[name] = actual
        self.rec.event(record_id, "capture", "capture",
                       {"name": name, "path": step.get("path")})

    def step_assert(self, step: dict, record_id: str) -> None:
        """Scenario-local invariant over the previous WSS reply or shell output."""
        source = step.get("source", "last_reply")
        value = None
        actual = None
        if source == "last_reply":
            value = self.last_reply
            actual = _jsonpath(value, step["path"]) if step.get("path") else value
        elif source == "last_http":
            value = self.last_http
            actual = _jsonpath(value, step["path"])
        elif source == "state":
            value = self.target.state()
            actual = _jsonpath(value, step["path"])
        ok = True
        detail = {"path": step.get("path"), "expected": step.get("equals"),
                  "actual": actual}
        if "equals" in step:
            ok = actual == step["equals"]
        if "equals_ref" in step:
            ok = ok and actual == self.captures.get(step["equals_ref"])
            detail["expected_ref"] = step["equals_ref"]
            detail["ref_value"] = self.captures.get(step["equals_ref"])
        if "exists" in step:
            ok = ok and (actual is not None) == bool(step["exists"])
        if "absent" in step:
            ok = ok and (actual is None) == bool(step["absent"])
        if "type" in step:
            type_map = {"string": str, "number": (int, float), "bool": bool,
                        "object": dict, "array": list}
            ok = ok and isinstance(actual, type_map[step["type"]])
        detail["ok"] = ok
        self.rec.event(record_id, "assert", "invariant", detail, {"source": source})

    # ------------------------------------------------------------- dispatch

    OPS = {
        "wss": "step_wss",
        "wss.raw": "step_wss_raw",
        "http": "step_http",
        "shell": "step_shell",
        "db": "step_db",
        "state": "step_state",
        "esp.event": "step_esp_event",
        "esp.raw": "step_esp_raw",
        "espjson.watch": "step_espjson_watch",
        "wait": "step_wait",
        "reboot": "step_reboot",
        "mark": "step_mark",
        "sleep": "step_sleep",
        "logs": "step_logs",
        "capture": "step_capture",
        "assert": "step_assert",
    }

    def run(self) -> dict:
        self.rec.event("scenario", "meta", "scenario.start", {
            "id": self.scenario["id"],
            "title": self.scenario.get("title", ""),
            "profile": self.scenario.get("profile", "shipped"),
            "reset": self.scenario.get("reset", "none"),
            "steps": len(self.scenario["steps"]),
        })
        started = time.monotonic()
        for index, step in enumerate(self.scenario["steps"], start=1):
            record_id = step.get("id") or f"s{index:02d}"
            op = step["op"]
            handler = self.OPS.get(op)
            if handler is None:
                self.rec.event(record_id, op, "error",
                               {"error": f"unknown op {op!r}"})
                continue
            step_started = time.monotonic()
            self.log(f"{record_id}: {op}")
            try:
                getattr(self, handler)(step, record_id)
            except Exception as exc:  # noqa: BLE001 - a failed step is data
                self.rec.event(record_id, op, "step.error",
                               {"error": f"{type(exc).__name__}: {exc}"},
                               {"elapsed_ms": int((time.monotonic() - step_started) * 1000)})
        elapsed = int((time.monotonic() - started) * 1000)
        self.rec.event("scenario", "meta", "scenario.end", {}, {"elapsed_ms": elapsed})
        return {"scenario": self.scenario["id"], "elapsed_ms": elapsed,
                "records": self.rec.seq}


def run_scenario(target: Target, scenario: dict, out_dir: Path,
                 run_index: int = 1, verbose: bool = False) -> dict:
    rec_path = out_dir / f"run-{run_index}.raw.jsonl"
    recorder = Recorder(rec_path, target.name, scenario["id"], run_index)
    runner = Runner(target, recorder, scenario, verbose=verbose)
    try:
        summary = runner.run()
    finally:
        recorder.close()
    summary.update({"raw": str(rec_path)})
    return summary
