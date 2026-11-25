#!/usr/bin/env python3
"""Drive the official Sync login screen with synthetic data only.

This is a deliberately narrow companion to ``run_official_app_sim_test.py``.
It exercises Flutter text fields, keyboard dismissal, accessibility focus, and
the Login control.  It never accepts caller-supplied credentials.  Use
``--offline`` for a reversible Android airplane-mode boundary; the local proxy
still rejects CONNECT/TLS and the simulator remains host-loopback only.

The probe is not an account-free client and does not prove that the official
APK can talk to the recovered E64 protocol.  Its useful negative result is
that the stock app remains at the account gate without a local request.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from run_official_app_sim_test import (
    PACKAGE,
    ContainedProxy,
    Transcript,
    activity_is_foreground,
    adb,
    add_reverse,
    choose_device,
    redact,
    restore_reverse,
    reverse_mappings,
    simulator_interpreter,
    simulator_probe,
)


SYNTHETIC_EMAIL = "test@example.invalid"
SYNTHETIC_PASSWORD = "notarealpassword"
BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def bounds(node: ET.Element) -> tuple[int, int, int, int] | None:
    match = BOUNDS_RE.fullmatch(node.attrib.get("bounds", ""))
    if not match:
        return None
    return tuple(int(value) for value in match.groups())  # type: ignore[return-value]


def center(node: ET.Element) -> tuple[int, int]:
    value = bounds(node)
    if value is None:
        raise RuntimeError("accessibility node has no usable bounds")
    left, top, right, bottom = value
    return ((left + right) // 2, (top + bottom) // 2)


def ui_dump(serial: str, remote_path: str = "/sdcard/codex-official-ui.xml") -> ET.Element:
    dumped = adb(serial, "shell", "uiautomator", "dump", remote_path, check=False)
    xml = adb(serial, "shell", "cat", remote_path, check=False).stdout
    if dumped.returncode != 0 or not xml.lstrip().startswith("<?xml"):
        raise RuntimeError("uiautomator dump unavailable")
    return ET.fromstring(xml)


def nodes(root: ET.Element) -> list[ET.Element]:
    return list(root.iter("node"))


def edit_fields(root: ET.Element) -> list[ET.Element]:
    return [
        node
        for node in nodes(root)
        if node.attrib.get("class") == "android.widget.EditText"
        and node.attrib.get("enabled") == "true"
    ]


def login_node(root: ET.Element) -> ET.Element | None:
    for node in nodes(root):
        if (
            node.attrib.get("content-desc") == "Login"
            and node.attrib.get("enabled") == "true"
        ):
            return node
    return None


def focused_login(root: ET.Element) -> bool:
    node = login_node(root)
    return node is not None and node.attrib.get("focused") == "true"


def keyboard_visible(root: ET.Element) -> bool:
    """Infer the soft keyboard from Flutter's resized ScrollView bounds."""
    for node in nodes(root):
        if node.attrib.get("class") != "android.widget.ScrollView":
            continue
        value = bounds(node)
        if value is not None and value[3] < 2000:
            return True
    return False


def tap(serial: str, node: ET.Element) -> None:
    x, y = center(node)
    adb(serial, "shell", "input", "touchscreen", "tap", str(x), str(y))


def key(serial: str, code: str) -> None:
    adb(serial, "shell", "input", "keyevent", code)


def input_text(serial: str, value: str) -> None:
    adb(serial, "shell", "input", "text", value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="ADB serial; otherwise require one device")
    parser.add_argument("--package", default=PACKAGE)
    parser.add_argument("--sim-port", type=int, default=8787)
    parser.add_argument("--sim-ws-port", type=int, default=9997)
    parser.add_argument("--scale-port", type=int, default=8765)
    parser.add_argument("--proxy-port", type=int, default=0)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--offline", action="store_true", help="enable reversible airplane mode")
    parser.add_argument("--clear-data", action="store_true")
    parser.add_argument("--no-start-simulator", action="store_true")
    args = parser.parse_args()

    if args.package != PACKAGE:
        raise SystemExit("this probe only permits the owner-authorized official package")
    output_dir = args.output_dir or Path("/private/tmp/mahlkoenig-official-touch")
    output_dir.mkdir(parents=True, exist_ok=True)
    transcript = Transcript()
    proxy: ContainedProxy | None = None
    serial: str | None = None
    simulator_process: Any = None
    added_reverse: list[int] = []
    original_proxy: str | None = None
    proxy_changed = False
    original_airplane = "0"
    airplane_changed = False
    report: dict[str, Any] = {
        "policy": {
            "synthetic_credentials_only": True,
            "real_credentials": False,
            "cloud_connect": False,
            "offline_requested": bool(args.offline),
        },
        "output_dir": str(output_dir),
    }
    try:
        import subprocess

        if not args.no_start_simulator:
            simulator_process = subprocess.Popen(
                [
                    simulator_interpreter(),
                    str(Path(__file__).with_name("e64ws_simulator.py")),
                    "--host", "127.0.0.1",
                    "--port", str(args.sim_ws_port),
                    "--scale-port", str(args.scale_port),
                    "--http-port", str(args.sim_port),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                text=True,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status, _ = simulator_probe(args.sim_port)
                if status == "PASS":
                    break
                time.sleep(0.1)
        status, state = simulator_probe(args.sim_port)
        report["simulator"] = {"status": status, "evidence": state}
        if status != "PASS":
            raise RuntimeError("local simulator did not pass its state probe")

        proxy = ContainedProxy(("127.0.0.1", args.proxy_port), transcript)
        proxy_port = proxy.server_address[1]
        import threading

        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        serial = choose_device(args.serial)
        existing_reverse = reverse_mappings(serial)
        for port in (args.sim_port, args.sim_ws_port, proxy_port):
            if add_reverse(serial, port, existing_reverse):
                added_reverse.append(port)

        original_proxy = adb(
            serial, "shell", "settings", "get", "global", "http_proxy"
        ).stdout.strip()
        if original_proxy in {"", "null", "None"}:
            original_proxy = None
        original_airplane = adb(
            serial, "shell", "settings", "get", "global", "airplane_mode_on"
        ).stdout.strip() or "0"
        if args.offline and original_airplane != "1":
            adb(serial, "shell", "cmd", "connectivity", "airplane-mode", "enable")
            airplane_changed = True
        adb(
            serial, "shell", "settings", "put", "global", "http_proxy",
            f"127.0.0.1:{proxy_port}",
        )
        proxy_changed = True
        if args.clear_data:
            adb(serial, "shell", "pm", "clear", args.package)
        launch = adb(
            serial,
            "shell",
            "am",
            "start",
            "-W",
            "-n",
            f"{args.package}/de.yukawa.hemro.ngx.MainActivity",
            check=False,
        )
        report["app_launch"] = {
            "status": "PASS" if activity_is_foreground(serial, args.package) else "FAIL",
            "returncode": launch.returncode,
        }
        if report["app_launch"]["status"] != "PASS":
            raise RuntimeError("official app did not reach its foreground activity")

        root = ui_dump(serial)
        fields = edit_fields(root)
        if len(fields) < 2:
            raise RuntimeError("official login screen did not expose two edit fields")
        tap(serial, fields[0])
        input_text(serial, SYNTHETIC_EMAIL)
        time.sleep(0.25)
        root = ui_dump(serial)
        if keyboard_visible(root):
            key(serial, "4")
            time.sleep(0.25)
            root = ui_dump(serial)
        fields = edit_fields(root)
        tap(serial, fields[1])
        input_text(serial, SYNTHETIC_PASSWORD)
        time.sleep(0.25)
        root = ui_dump(serial)
        if keyboard_visible(root):
            key(serial, "4")
            time.sleep(0.25)
            root = ui_dump(serial)
        button = login_node(root)
        report["touch_input"] = {
            "email_field": True,
            "password_field": True,
            "login_enabled": button is not None,
            "raw_values_recorded": False,
        }
        if button is None:
            raise RuntimeError("synthetic values did not enable Login")

        # First attempt a measured touchscreen tap.  Some headless Flutter AVDs
        # expose semantics bounds but do not deliver this button tap reliably.
        tap(serial, button)
        time.sleep(0.5)
        root = ui_dump(serial)
        direct_tap_changed = login_node(root) is None

        # Fallback uses focus navigation, still without invoking any app-private
        # API.  Starting from the password field makes the sequence deterministic:
        # eye icon -> Login.  DPAD_CENTER is the Android focused-button action.
        if not direct_tap_changed:
            fields = edit_fields(root)
            tap(serial, fields[1])
            root = ui_dump(serial)
            if keyboard_visible(root):
                key(serial, "4")
                time.sleep(0.25)
            key(serial, "61")
            key(serial, "61")
            root = ui_dump(serial)
        keyboard_activation = focused_login(root)
        if keyboard_activation:
            key(serial, "23")
        report["touch_input"].update(
            {
                "measured_tap_changed_screen": direct_tap_changed,
                "login_focus_reached": keyboard_activation,
                "activation_sent": keyboard_activation,
            }
        )
        time.sleep(2)
        final_root = ui_dump(serial)
        foreground = activity_is_foreground(serial, args.package)
        report["post_action"] = {
            "app_foreground": foreground,
            "login_screen_still_present": foreground and login_node(final_root) is not None,
            "local_proxy_requests": len(
                [event for event in transcript.snapshot() if event.get("kind") == "local_request"]
            ),
        }
    except Exception as exc:  # contained probe reports failures for review
        report.setdefault("harness", {})["error"] = redact(
            f"{type(exc).__name__}: {exc}"
        )
    finally:
        if proxy is not None:
            proxy.shutdown()
            proxy.server_close()
        if serial:
            if proxy_changed:
                if original_proxy is None:
                    adb(serial, "shell", "settings", "delete", "global", "http_proxy", check=False)
                else:
                    adb(serial, "shell", "settings", "put", "global", "http_proxy", original_proxy, check=False)
            if airplane_changed:
                adb(serial, "shell", "cmd", "connectivity", "airplane-mode", "disable", check=False)
            restore_reverse(serial, added_reverse)
        if simulator_process is not None:
            simulator_process.terminate()
            try:
                simulator_process.wait(timeout=3)
            except Exception:
                simulator_process.kill()
        report["transcript"] = transcript.snapshot()
        (output_dir / "network.redacted.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("app_launch", {}).get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
