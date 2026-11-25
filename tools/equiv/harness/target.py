"""Target adapters: the only target-specific code in the harness.

A *target* is one running instance of the HMI stack (vendor or reconstruction)
plus the environment around it. The harness never assumes vendor tooling: it
talks to a small JSON control socket (kind=vg), or directly to the network and
an optional shell/argv adapter (kind=direct).

Target spec (JSON) fields
-------------------------
name            label used in run directories
kind            "vg" | "direct"
http, https     base URLs (https may be empty)
wss             WebSocket base URL (token is appended as ?token=)
shell           {"argv": ["ssh","-p","33222","root@127.0.0.1"]}  (direct only)
                   receives the command on stdin, must print stdout and exit 0
reset           {"argv": [...]} -> restore pristine state (optional)
wait_ready      {"argv": [...]} -> exit 0 when WSS answers (optional)
mint_token      {"argv": [...]} -> prints a token on stdout (direct only)
tls_verify      bool (default false; the device certificate is self-signed)
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any


class TargetError(RuntimeError):
    pass


class Target:
    name = "target"

    # ------------------------------------------------------------ network
    def http_request(self, method: str, path: str, body: bytes | None,
                     headers: dict[str, str], secure: bool, timeout: float) -> dict:
        raise NotImplementedError

    def wss_url(self, token: str | None) -> str:
        raise NotImplementedError

    # ------------------------------------------------------------- control
    def shell(self, cmd: str, timeout: float = 20.0) -> dict:
        raise NotImplementedError

    def mint_token(self) -> str:
        raise NotImplementedError

    def state(self) -> dict:
        return {}

    def esp_event(self, event_id: int, data_hex: str) -> dict:
        return {"ok": False, "error": "esp events not supported by this target"}

    def esp_raw(self, frame_hex: str) -> dict:
        return {"ok": False, "error": "esp raw not supported by this target"}

    def espjson_state(self) -> dict:
        return {}

    def power(self, action: str) -> dict:
        return {"ok": False, "error": "power actions not supported by this target"}

    def reset(self) -> dict:
        return {"ok": False, "error": "no reset hook"}

    def wait_ready(self, timeout: float = 120.0) -> bool:
        raise NotImplementedError

    def close(self) -> None:
        pass


# --------------------------------------------------------------------- vg


class VgTarget(Target):
    """Vendor stack driven through the virtual-grinder control daemon."""

    kind = "vg"

    def __init__(self, spec: dict):
        self.spec = spec
        self.name = spec.get("name", "vendor")
        self.sock_path = Path(spec["daemon_sock"])
        self.http = spec["http"].rstrip("/")
        self.https = (spec.get("https") or "").rstrip("/")
        self.wss = spec["wss"].rstrip("/") + "/"
        self.timeout = float(spec.get("timeout", 30))

    def _send(self, cmd: str, args: dict | None = None, timeout: float | None = None) -> dict:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout or self.timeout)
        try:
            sock.connect(str(self.sock_path))
            sock.sendall((json.dumps({"cmd": cmd, "args": args or {}}) + "\n").encode())
            buf = bytearray()
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
            if not buf:
                return {"ok": False, "error": "empty reply from daemon"}
            return json.loads(bytes(buf).split(b"\n", 1)[0])
        except (OSError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "daemon_down": True}
        finally:
            sock.close()

    # ------------------------------------------------------------ network
    def http_request(self, method, path, body, headers, secure, timeout):
        # http.client lives in runner.py; VgTarget only supplies base URLs.
        raise NotImplementedError

    def wss_url(self, token: str | None) -> str:
        return self.wss + (f"?token={token}" if token else "")

    # ------------------------------------------------------------- control
    def shell(self, cmd: str, timeout: float = 20.0) -> dict:
        result = self._send("shell", {"cmd": cmd}, timeout=timeout + 10)
        if not result.get("ok"):
            return {"ok": False, "error": result.get("error", "shell failed")}
        return {"ok": True, "stdout": result.get("stdout", ""), "stderr": result.get("stderr", "")}

    def mint_token(self) -> str:
        """Write a valid /tmp/tok_<token> in the guest, as the PHP login does.

        The daemon masks the token in its JSON replies, so the harness mints
        its own token through the guest shell (same file format the vendor
        WebSocketConnector validates).
        """
        import secrets
        token = secrets.token_hex(32)
        expires = int(time.time()) + 300
        payload = json.dumps({"sessionId": "vg-" + token[:8], "token": token,
                              "role": "Owner", "expires": expires},
                             separators=(",", ":"))
        cmd = (f"mkdir -p /tmp; printf '%s' '{payload}' > /tmp/tok_{token}; "
               "echo minted")
        result = self.shell(cmd, timeout=8)
        if not result.get("ok"):
            raise TargetError(f"could not mint token: {result}")
        return token

    def state(self) -> dict:
        return self._send("state")

    def esp_event(self, event_id: int, data_hex: str) -> dict:
        return self._send("esp_event", {"id": event_id, "data_hex": data_hex})

    def esp_raw(self, frame_hex: str) -> dict:
        return self._send("esp_raw", {"hex": frame_hex})

    def espjson_state(self) -> dict:
        return self._send("state").get("espjson", {})

    def logs(self, n: int = 200) -> dict:
        return self._send("logs", {"n": n})

    def power(self, action: str) -> dict:
        return self._send("power", {"action": action})

    def reset(self) -> dict:
        return self._send("shell", {"cmd": self.spec.get("reset_cmd", "true")}, timeout=120)

    def wait_ready(self, timeout: float = 120.0) -> bool:
        """Require three consecutive successful WSS round-trips.

        A single successful probe is not enough: the vendor HMI accepts TLS
        connections while its driver initialisation is still running, then the
        event loop blocks for a few seconds. Treating that window as "ready"
        produces spurious open_failed records in the first steps of a scenario.
        """
        deadline = time.time() + timeout
        streak = 0
        while time.time() < deadline:
            result = self._send("probe", timeout=25)
            if result.get("services", {}).get("wss", {}).get("ok"):
                streak += 1
                if streak >= 3:
                    return True
            else:
                streak = 0
            time.sleep(1.5)
        return False


# ----------------------------------------------------------------- direct


class DirectTarget(Target):
    """A reconstruction (or any HMI instance) reached over the network.

    Shell access is optional. If the reconstruction runs in a container or VM,
    point `shell` at `docker exec -i ...` or `ssh ...`; the command is written
    to stdin so no quoting is required.
    """

    kind = "direct"

    def __init__(self, spec: dict):
        self.spec = spec
        self.name = spec.get("name", "recon")
        self.http = spec["http"].rstrip("/")
        self.https = (spec.get("https") or "").rstrip("/")
        self.wss = spec["wss"].rstrip("/") + "/"
        self.timeout = float(spec.get("timeout", 30))

    def wss_url(self, token: str | None) -> str:
        return self.wss + (f"?token={token}" if token else "")

    def _argv(self, key: str, cmd: str | None = None, timeout: float = 30.0) -> dict:
        spec = self.spec.get(key)
        if not spec:
            return {"ok": False, "error": f"target has no '{key}' adapter"}
        argv = list(spec["argv"])
        try:
            proc = subprocess.run(argv, input=(cmd or "").encode(),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": str(exc)}
        if proc.returncode != 0:
            return {"ok": False, "error": proc.stderr.decode(errors="replace")[-800:],
                    "stdout": proc.stdout.decode(errors="replace")}
        return {"ok": True, "stdout": proc.stdout.decode(errors="replace"), "stderr": ""}

    def shell(self, cmd: str, timeout: float = 20.0) -> dict:
        return self._argv("shell", cmd, timeout)

    def mint_token(self) -> str:
        result = self._argv("mint_token", "", 15)
        token = (result.get("stdout") or "").strip().splitlines()
        if not result.get("ok") or not token:
            raise TargetError(f"mint_token failed: {result}")
        return token[-1].strip()

    def state(self) -> dict:
        result = self._argv("state", "", 15)
        if not result.get("ok"):
            return {"ok": False, "error": result.get("error")}
        try:
            return json.loads(result["stdout"])
        except json.JSONDecodeError:
            return {"ok": False, "error": "state adapter did not return JSON"}

    def esp_event(self, event_id: int, data_hex: str) -> dict:
        return self._argv("esp_event", json.dumps({"id": event_id, "data": data_hex}))

    def esp_raw(self, frame_hex: str) -> dict:
        return self._argv("esp_raw", frame_hex)

    def espjson_state(self) -> dict:
        return self.state().get("espjson", {})

    def power(self, action: str) -> dict:
        return self._argv("power", action, 120)

    def reset(self) -> dict:
        return self._argv("reset", "", 180)

    def wait_ready(self, timeout: float = 120.0) -> bool:
        deadline = time.time() + timeout
        url = self.wss_url(None)
        from .wsclient import WSClient
        while time.time() < deadline:
            client = WSClient(url, timeout=5)
            event = client.connect()
            client.close()
            if event.kind == "open":
                return True
            time.sleep(2)
        return False


def load(spec_path: str | Path) -> Target:
    spec = json.loads(Path(spec_path).read_text())
    kind = spec.get("kind", "direct")
    if kind == "vg":
        return VgTarget(spec)
    if kind == "direct":
        return DirectTarget(spec)
    raise TargetError(f"unknown target kind {kind!r} in {spec_path}")
