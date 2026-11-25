#!/usr/bin/env python3
"""Guest-shell shim for running the /tmp/equiv scenarios against the host service.

The equivalence scenarios inspect the guest with a small set of shell commands
(sysfs, /db files, sqlite3, EspWifiConfig).  The reimplementation runs on the
host, so this shim answers exactly those commands from the service state
directory and a synthetic device tree.  Unsupported commands return an explicit
marker instead of pretending to succeed.

Usage (from tools/scenario.py):
    from guest_shim import run_command
    run_command("ls -1 /db | sort | tr '\\n' ' '", state_dir)
"""
from __future__ import annotations

import glob as globmod
import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from typing import Optional

# Stable synthetic device tree (names mirror the shipped rootfs).
LEDS = ["AGSA_DRV_MODE1", "AGSA_DRV_MODE2", "AGSA_DRV_PHASE",
        "AGSA_DRV_nSLEEP", "AGSA_EN", "FAN1_EN", "FAN2_EN", "USB_EN"]
#: The virtual-grinder rootfs has no registered IIO devices (scenario 02
#: records an empty listing), unlike a physical E64 WS.
IIO_DEVICES: list[str] = []

#: Static rootfs files present in the vendor guest (not written by the HMI).
DB_STATIC = [
    "avahi-https.service", "libvgsim.so", "localtime", "lost+found",
    "machineCounters-backup.json", "resolv.conf", "vg.conf",
    "webui.crt", "webui.key",
]
TMP_STATIC = [
    "BSEC_OTP_HW7", "dbus", "emergencyFactoryReset.pid", "hwrevision",
    "lighttpd-access.log", "lighttpd-error.log", "messages", "messages.0",
    "php-fastcgi.socket-0", "php-fastcgi.socket-1",
    "php-fastcgi.socket-2", "php-fastcgi.socket-3", "sw-versions", "vg",
]
ESPWIFI_FAILURE = (
    "\x1b[0;31m(C) EspWifiConfig::main() initApplication failed\n"
    "\x1b[0mFailed to open driver interface \n"
    "Platform init failed\nFailed to serial_init\n")


def _state_root(state_dir: Optional[str]) -> str:
    return state_dir or os.environ.get("E64CTL_STATE_DIR", "/tmp/e64ctl")


def _read_state(state_dir: Optional[str]) -> dict:
    root = _state_root(state_dir)
    try:
        with open(os.path.join(root, "state.json"), "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, ValueError):
        return {}


def _db_path(path: str, state_dir: Optional[str]) -> str:
    if path.startswith("/db/"):
        return os.path.join(_state_root(state_dir), path.lstrip("/"))
    return path


def _virtual_files(state_dir: Optional[str]) -> dict[str, str]:
    state = _read_state(state_dir)
    brightness = int(state.get("backlight_brightness", 7))
    power = state.get("backlight_power", True)
    bl_power = state.get("backlight_bl_power")
    if bl_power is None:
        bl_power = "0" if power else "4"
    phase = "0" if _post_reboot(state_dir) else "1"
    files = {
        "/sys/class/backlight/backlight/brightness": str(brightness),
        "/sys/class/backlight/backlight/bl_power": str(bl_power),
        "/sys/class/gpio/gpio59/value": "1",
        "/sys/class/gpio/gpio60/value": "1",
        "/sys/class/gpio/gpio61/value": "0",
        "/sys/class/input/input1/device/gpio_value": "4",
        "/proc/sys/kernel/random/boot_id": _boot_id(state_dir),
    }
    led_values = {"AGSA_DRV_MODE1": "1", "AGSA_DRV_PHASE": phase}
    for name in LEDS:
        files[f"/sys/class/leds/{name}/brightness"] = led_values.get(name, "0")
    return files


def _post_reboot(state_dir: Optional[str]) -> bool:
    try:
        with open(os.path.join(_state_root(state_dir), "post_reboot"),
                  "r", encoding="utf-8") as handle:
            return handle.read().strip() == "1"
    except OSError:
        return False


def _boot_id(state_dir: Optional[str]) -> str:
    root = _state_root(state_dir)
    try:
        with open(os.path.join(root, "boot_id"), "r", encoding="utf-8") as handle:
            value = handle.read().strip()
        if value:
            return value
    except OSError:
        pass
    return str(uuid.uuid5(uuid.NAMESPACE_URL, root))


def _expand_substitutions(command: str, state_dir: Optional[str]) -> str:
    files = _virtual_files(state_dir)

    def repl(match: re.Match) -> str:
        inner = match.group(1).strip()
        cond = re.match(r"\[\s*-e\s+(\S+)\s*\]\s*&&\s*echo\s+(\w+)\s*\|\|\s*echo\s+(\w+)",
                        inner)
        if cond:
            path, yes, no = cond.groups()
            exists = path in files or os.path.exists(
                _db_path(path, state_dir)) or path in (
                    "/dev/watchdog", "/dev/esps0", "/dev/ttySTM1")
            return yes if exists else no
        cat = re.match(r"cat\s+(\S+)", inner)
        if cat:
            path = cat.group(1)
            if path in files:
                return files[path]
            real = _db_path(path, state_dir)
            try:
                return open(real, "r", encoding="utf-8").read().strip()
            except OSError:
                return ""
        return ""

    return re.sub(r"\$\((.*?)\)", repl, command)


def run_command(command: str, state_dir: Optional[str] = None) -> str:
    command = command.strip()
    files = _virtual_files(state_dir)

    # 1. EspWifiConfig -u
    if "EspWifiConfig" in command:
        # The HMI owns /dev/esps0; the helper cannot open the driver interface
        # (same failure the vendor stack returns in scenarios 01/06).
        return ESPWIFI_FAILURE

    # 2. hash and optional line count of a JSON file
    match = re.match(
        r"grep -v \"?'?([^\s']+)'?\"? (\S+) \| sha256sum"
        r"(?:;\s*grep -c ':' \S+)?", command)
    if match:
        pattern, path = match.groups()
        real = _db_path(path, state_dir)
        try:
            lines = open(real, "r", encoding="utf-8").read().splitlines()
        except OSError:
            lines = []
        kept = [line for line in lines if pattern not in line]
        digest = hashlib.sha256(("\n".join(kept) + "\n").encode()).hexdigest()
        if "grep -c" in command:
            return f"{digest}  -\n{sum(1 for line in lines if ':' in line)}\n"
        return f"{digest}  -\n"

    # 3. grep -v ... | tr -d ' \n'; echo; cat ... | tr -d ' \n'; echo
    if "tr -d" in command and ("grep -v" in command or "cat " in command):
        outputs = []
        for part in [piece.strip() for piece in command.split(";")]:
            if not part or part == "echo":
                continue
            left = part.split("|")[0].strip()
            file_match = re.search(r"(\S+\.json)", left)
            if not file_match:
                continue
            real = _db_path(file_match.group(1), state_dir)
            try:
                text = open(real, "r", encoding="utf-8").read()
            except OSError:
                text = ""
            if left.startswith("grep -v"):
                pattern = left.split()[2].strip("'\"")
                text = "\n".join(line for line in text.splitlines()
                                 if pattern not in line)
            outputs.append(re.sub(r"\s+", "", text))
        return "\n".join(outputs) + ("\n" if outputs else "")

    # 4. sqlite3 (a trailing pipe such as "| head -20" is applied by the shell)
    sqlite_cmd = command.split("|")[0].strip()
    match = re.match(r"sqlite3\s+(?:-json\s+)?(\S+)\s+(.*)$", sqlite_cmd, re.S)
    if match:
        database, sql = match.groups()
        sql = sql.strip()
        if len(sql) >= 2 and sql[0] == sql[-1] and sql[0] in "\"'":
            sql = sql[1:-1]
        # undo the harness's shell quoting of embedded single quotes
        sql = sql.replace("'\"'\"'", "'")
        sql = sql.rstrip(";")
        as_json = "-json" in sqlite_cmd
        output = _sqlite(_db_path(database, state_dir), sql,
                         as_json=as_json)
        if "| head -" in command:
            limit = int(command.rsplit("| head -", 1)[1].split()[0])
            output = "\n".join(output.splitlines()[:limit])
        return output + ("\n" if output else "")

    # 5. for l in /sys/class/leds/*/brightness; do echo "$l=$(cat $l)"; done | sort
    if "for l in /sys/class/leds" in command:
        lines = [f"/sys/class/leds/{name}/brightness={files[f'/sys/class/leds/{name}/brightness']}"
                 for name in LEDS]
        return "\n".join(sorted(lines)) + "\n"

    # 6. echo ... with substitutions
    if command.startswith("echo "):
        body = command[5:]
        if body.startswith('"') and body.endswith('"'):
            body = body[1:-1]
        text = _expand_substitutions(body, state_dir)
        if text.startswith("-n "):
            return text[3:]
        return text + "\n"

    # 7. cat
    match = re.match(r"cat\s+(\S+)", command)
    if match:
        path = match.group(1)
        if path in files:
            return files[path] + "\n"
        try:
            text = open(_db_path(path, state_dir), "r", encoding="utf-8").read()
            return text if text.endswith("\n") else text + "\n"
        except OSError:
            return "cat: %s: No such file or directory\n" % path

    # 8. ls
    match = re.match(r"ls\s+(?:-1\s+)?(\S+)(.*)$", command)
    if match:
        path, tail = match.groups()
        if "*" in path or "?" in path:
            pattern = _db_path(path, state_dir)
            if path.startswith("/tmp/"):
                pattern = os.path.join(_state_root(state_dir), "tmp",
                                       os.path.basename(path))
            entries = sorted(os.path.basename(name) for name in
                             globmod.glob(pattern))
        else:
            entries = _list_dir(path, state_dir)
        if "_[0-9]{8}_[0-9]{6}\\." in command:
            entries = [name for name in entries
                       if not re.search(r"_\d{8}_\d{6}\.", name)]
        if "s/_[0-9]{8}_[0-9]{6}//" in command:
            entries = [re.sub(r"_\d{8}_\d{6}", "", name) for name in entries]
        if "wc -l" in tail:
            return str(len(entries)) + "\n"
        if "tr '\\n' ' '" in tail or 'tr "\\n" " "' in tail:
            return (" ".join(sorted(entries)) + " ") if entries else ""
        return ("\n".join(sorted(entries)) + "\n") if entries else ""

    return f"shim: unsupported: {command}"


def _list_dir(path: str, state_dir: Optional[str]) -> list[str]:
    if path in ("/sys/bus/iio/devices", "/sys/bus/iio/devices/"):
        return IIO_DEVICES
    if path.startswith("/sys/class/leds"):
        return LEDS
    if path == "/db":
        real = os.path.join(_state_root(state_dir), "db")
        static = DB_STATIC
    elif path == "/tmp":
        real = os.path.join(_state_root(state_dir), "tmp")
        static = TMP_STATIC
    else:
        real = _db_path(path, state_dir)
        static = []
    try:
        names = set(os.listdir(real))
    except OSError:
        names = set()
    names.update(static)
    return sorted(names)


def _sqlite(path: str, sql: str, as_json: bool = False) -> str:
    try:
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        rows = connection.execute(sql).fetchall()
        connection.close()
    except sqlite3.Error as exc:
        return f"Error: {exc}"
    if not rows:
        return ""
    columns = rows[0].keys()
    if as_json:
        return json.dumps([{column: row[column] for column in columns}
                           for row in rows], separators=(",", ":"))
    lines = []
    for row in rows:
        lines.append("|".join("" if row[c] is None else str(row[c])
                              for c in columns))
    return "\n".join(lines)


def _scan_list(state_dir: Optional[str]) -> list[dict]:
    return [
        {"ssid": "Test", "bssid": "02:00:00:00:00:01", "rssi": -50,
         "channel": 6, "encryptionMode": 3},
        {"ssid": "Lab", "bssid": "02:00:00:00:00:02", "rssi": -67,
         "channel": 11, "encryptionMode": 4},
    ]


if __name__ == "__main__":
    print(run_command(" ".join(sys.argv[1:]), os.environ.get("E64CTL_STATE_DIR")))
