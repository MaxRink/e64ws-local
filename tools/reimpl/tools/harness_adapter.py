#!/usr/bin/env python3
"""argv adapter for the /tmp/equiv ``direct`` target (``targets/reimpl.json``).

The harness writes the operation input to stdin and reads stdout.  This
adapter owns the service lifecycle so a run always starts from a fresh state
directory:

    shell        guest-shell shim, plus ``profile <shipped|dev>``
    mint_token   POST /rest_api/login as the fixture Owner over HTTPS
    state        vg-shaped JSON snapshot from the control socket
    reset        stop, wipe /db + /tmp, provision the fixture owner, restart
    wait_ready   exit 0 when the control socket and WSS answer
    esp_event    inject an asynchronous ESP control event
    esp_raw      inject a raw ESP frame (malformed frames are ignored)
    power        stop/restart the service (reboot) and rotate the boot id

Environment (all optional):
    E64CTL_STATE_DIR   default /tmp/e64ctl-equiv
    E64CTL_HTTP_PORT   default 48080 (plain, redirects)
    E64CTL_HTTPS_PORT  default 48443 (REST)
    E64CTL_WSS_PORT    default 48997 (WSS)
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "src"))

from e64ctl.rest import pwhash  # noqa: E402
from guest_shim import run_command  # noqa: E402

STATE_DIR = os.environ.get("E64CTL_STATE_DIR", "/tmp/e64ctl-equiv")
HTTP_PORT = int(os.environ.get("E64CTL_HTTP_PORT", "48080"))
HTTPS_PORT = int(os.environ.get("E64CTL_HTTPS_PORT", "48443"))
WSS_PORT = int(os.environ.get("E64CTL_WSS_PORT", "48997"))
CONTROL = os.path.join(STATE_DIR, "control.sock")
PID_FILE = os.path.join(STATE_DIR, "service.pid")
PROFILE_FILE = os.path.join(STATE_DIR, "profile")
LOG_FILE = os.path.join(STATE_DIR, "service.log")

FIXTURE_PASSWORD = "e64-equivalence"
FIXTURE_SALT = "testsalt"
FIXTURE_ROUNDS = 5000


# ---------------------------------------------------------------------------
# process lifecycle
# ---------------------------------------------------------------------------


def _profile() -> str:
    try:
        with open(PROFILE_FILE, "r", encoding="utf-8") as handle:
            value = handle.read().strip()
        if value in ("shipped", "dev"):
            return value
    except OSError:
        pass
    return "shipped"


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _pid() -> int | None:
    try:
        with open(PID_FILE, "r", encoding="utf-8") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


def _alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _control(cmd: str, args: dict | None = None, timeout: float = 10.0) -> dict:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(CONTROL)
        sock.sendall(json.dumps({"cmd": cmd, "args": args or {}}).encode()
                     + b"\n")
        buf = bytearray()
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf.extend(chunk)
        return json.loads(bytes(buf).split(b"\n", 1)[0])
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        sock.close()


def _wait_control(timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _control("ping", timeout=1.0).get("ok"):
            return True
        time.sleep(0.1)
    return False


def start_service() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    pid = _pid()
    if _alive(pid) and _control("ping", timeout=1.0).get("ok"):
        return
    if _alive(pid):
        stop_service()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    argv = [
        sys.executable, "-m", "e64ctl",
        "--state-dir", STATE_DIR,
        "--wss-port", str(WSS_PORT),
        "--http-port", str(HTTP_PORT),
        "--https-port", str(HTTPS_PORT),
        "--tls",
        "--control-socket", CONTROL,
        "--no-motion-sim",
        "--serial", "0123456789AB",
        "--grinder-type", "5",
    ]
    argv.append("--dev-mode" if _profile() == "dev" else "--no-dev-mode")
    log = open(LOG_FILE, "ab", buffering=0)
    proc = subprocess.Popen(argv, cwd=str(ROOT), env=env,
                            stdout=log, stderr=log, start_new_session=True)
    _write(PID_FILE, str(proc.pid))
    if not _wait_control(30.0):
        raise SystemExit(f"e64ctl did not start; see {LOG_FILE}")


def stop_service() -> None:
    pid = _pid()
    if _alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        deadline = time.time() + 10
        while time.time() < deadline and _alive(pid):
            time.sleep(0.1)
        if _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    try:
        os.unlink(PID_FILE)
    except OSError:
        pass


def _rotate_boot(post_reboot: bool) -> None:
    _write(os.path.join(STATE_DIR, "boot_id"),
           str(uuid.uuid4()))
    _write(os.path.join(STATE_DIR, "post_reboot"),
           "1" if post_reboot else "0")


def restart_service(post_reboot: bool = False) -> None:
    stop_service()
    _rotate_boot(post_reboot)
    start_service()


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def provision_owner() -> None:
    db_dir = os.path.join(STATE_DIR, "db")
    os.makedirs(db_dir, exist_ok=True)
    connection = sqlite3.connect(os.path.join(db_dir, "HsgSqlite.db"))
    connection.execute(
        'CREATE TABLE IF NOT EXISTS "settings" ("key" TEXT NOT NULL PRIMARY'
        ' KEY, "value" TEXT)')
    encoded = (f"1${FIXTURE_ROUNDS}${FIXTURE_SALT}$"
               f"{pwhash(FIXTURE_PASSWORD, FIXTURE_SALT, FIXTURE_ROUNDS)}")
    connection.execute(
        "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
        ("Role.Owner.LoginData", encoded))
    connection.commit()
    connection.close()


def reset_state() -> None:
    stop_service()
    for name in ("db", "tmp"):
        shutil.rmtree(os.path.join(STATE_DIR, name), ignore_errors=True)
    for name in ("state.json", "control.sock", "esp.zip",
                 "FirmwareUpdateState.json"):
        try:
            os.unlink(os.path.join(STATE_DIR, name))
        except OSError:
            pass
    _rotate_boot(False)
    # Create the schema/default rows before the service loads ConfigManager,
    # then inject the fixture owner hash, then start.
    from e64ctl.persistence import Persistence

    bootstrap = Persistence(STATE_DIR)
    bootstrap.close()
    provision_owner()
    start_service()


# ---------------------------------------------------------------------------
# operations
# ---------------------------------------------------------------------------


def op_shell() -> int:
    command = sys.stdin.read()
    if command.startswith("profile "):
        wanted = command.split(None, 1)[1].strip()
        if wanted not in ("shipped", "dev"):
            print(f"unknown profile {wanted!r}", file=sys.stderr)
            return 2
        _write(PROFILE_FILE, wanted)
        restart_service(False)
        print(f"profile-{wanted}")
        return 0
    start_service()
    sys.stdout.write(run_command(command, STATE_DIR))
    return 0


def op_mint_token() -> int:
    start_service()
    body = json.dumps({"userRole": "Owner",
                       "password": FIXTURE_PASSWORD}).encode()
    context = ssl._create_unverified_context()
    request = urllib.request.Request(
        f"https://127.0.0.1:{HTTPS_PORT}/rest_api/login", data=body,
        method="POST")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10,
                                    context=context) as response:
            token = response.headers.get("Authorization", "")
    except urllib.error.HTTPError as error:
        print(f"login failed: {error.code}", file=sys.stderr)
        return 1
    print(token.split(" ", 1)[-1])
    return 0


def op_state() -> int:
    start_service()
    result = _control("state")
    if not result.get("ok"):
        print(json.dumps(result))
        return 0
    print(json.dumps(result["state"], separators=(",", ":")))
    return 0


def op_reset() -> int:
    reset_state()
    print("reset-ok")
    return 0


def op_wait_ready() -> int:
    start_service()
    return 0 if _control("ping").get("ok") else 1


def op_esp_event() -> int:
    start_service()
    raw = sys.stdin.read()
    try:
        event = json.loads(raw or "{}")
    except ValueError:
        event = {}
    result = _control("esp_event", {"id": event.get("id", 0),
                                    "data_hex": event.get("data", "")})
    print(json.dumps(result))
    return 0 if result.get("ok") else 1


def op_esp_raw() -> int:
    start_service()
    result = _control("esp_raw", {"hex": sys.stdin.read().strip()})
    print(json.dumps(result))
    return 0 if result.get("ok") else 1


def op_power() -> int:
    sys.stdin.read()
    restart_service(post_reboot=True)
    print("ok")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    operation = sys.argv[1]
    handlers = {
        "shell": op_shell,
        "mint_token": op_mint_token,
        "state": op_state,
        "reset": op_reset,
        "wait_ready": op_wait_ready,
        "esp_event": op_esp_event,
        "esp_raw": op_esp_raw,
        "power": op_power,
    }
    handler = handlers.get(operation)
    if handler is None:
        print(f"unknown operation {operation!r}", file=sys.stderr)
        return 2
    return handler()


if __name__ == "__main__":
    sys.exit(main())
