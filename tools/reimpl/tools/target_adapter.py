#!/usr/bin/env python3
"""argv adapter used by the /tmp/equiv 'direct' target for the reimplementation.

The harness calls the adapter with the operation name and writes any input on
stdin (see /tmp/equiv/harness/target.py).  Supported operations:

    shell        guest-shell shim (sysfs, /db files, sqlite3, EspWifiConfig)
    mint_token   POST /rest_api/login as the fixture Owner, print the bearer
    state        JSON snapshot (guest.* and files.*)
    reset        clear grind/brew/event rows, re-provision the owner password
    wait_ready   exit 0 when the HTTP surface answers
    esp_event    not available cross-process (the ESP link is in-process)
    esp_raw      not available cross-process

Environment:
    E64CTL_STATE_DIR  state directory of the running service (default /tmp/e64ctl)
    E64CTL_HTTP       base URL (default http://127.0.0.1:8080)
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

from e64ctl.rest import pwhash  # noqa: E402
from guest_shim import _virtual_files, run_command  # noqa: E402

STATE_DIR = os.environ.get("E64CTL_STATE_DIR", "/tmp/e64ctl")
HTTP = os.environ.get("E64CTL_HTTP", "http://127.0.0.1:8080").rstrip("/")


def _db_path() -> str:
    return os.path.join(STATE_DIR, "db", "HsgSqlite.db")


def op_shell() -> int:
    command = sys.stdin.read()
    print(run_command(command, STATE_DIR))
    return 0


def op_mint_token() -> int:
    body = json.dumps({"userRole": "Owner",
                       "password": "e64-equivalence"}).encode()
    request = urllib.request.Request(HTTP + "/rest_api/login", data=body,
                                     method="POST")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            token = response.headers.get("Authorization", "")
    except urllib.error.HTTPError as error:
        print(f"login failed: {error.code}", file=sys.stderr)
        return 1
    print(token.split(" ", 1)[-1])
    return 0


def op_state() -> int:
    files = _virtual_files(STATE_DIR)
    snapshot = {
        "guest": {
            "gpio59": files["/sys/class/gpio/gpio59/value"],
            "gpio60": files["/sys/class/gpio/gpio60/value"],
            "gpio61": files["/sys/class/gpio/gpio61/value"],
            "backlight": files["/sys/class/backlight/backlight/brightness"],
            "leds": {name: files[f"/sys/class/leds/{name}/brightness"]
                     for name in ("led1", "led2", "led3", "led4")},
        },
        "files": {},
    }
    for name in ("db", "tmp"):
        base = os.path.join(STATE_DIR, name)
        if os.path.isdir(base):
            snapshot["files"][name] = sorted(os.listdir(base))
    print(json.dumps(snapshot))
    return 0


def op_reset() -> int:
    path = _db_path()
    if os.path.exists(path):
        connection = sqlite3.connect(path)
        for table in ("grind_log", "brew_events", "event_log", "alert_log"):
            try:
                connection.execute(f"DELETE FROM {table}")
            except sqlite3.Error:
                pass
        connection.commit()
        connection.close()
    tmp = os.path.join(STATE_DIR, "tmp")
    if os.path.isdir(tmp):
        for name in os.listdir(tmp):
            if name.startswith("tok_") or name in (
                    "onboardingRequest.json", "wifiStaConfig.json",
                    "FirmwareUpdateState.json"):
                os.unlink(os.path.join(tmp, name))
    _provision_owner()
    print("reset-ok")
    return 0


def _provision_owner() -> None:
    path = _db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        'CREATE TABLE IF NOT EXISTS "settings" ("key" TEXT NOT NULL PRIMARY KEY,'
        ' "value" TEXT)')
    encoded = "1$5000$e64fixture$" + pwhash("e64-equivalence", "e64fixture", 5000)
    connection.execute(
        "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
        ("Role.Owner.LoginData", encoded))
    connection.commit()
    connection.close()


def op_wait_ready() -> int:
    try:
        with urllib.request.urlopen(HTTP + "/rest_api/ping", timeout=5):
            return 0
    except (urllib.error.URLError, socket.timeout, ConnectionError):
        return 1


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    operation = sys.argv[1]
    if operation == "shell":
        return op_shell()
    if operation == "mint_token":
        return op_mint_token()
    if operation == "state":
        return op_state()
    if operation == "reset":
        return op_reset()
    if operation == "wait_ready":
        return op_wait_ready()
    if operation in ("esp_event", "esp_raw"):
        print(json.dumps({"ok": False,
                          "error": "ESP link is in-process; use tests/test_esp.py"}))
        return 0
    print(f"unknown operation {operation!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
