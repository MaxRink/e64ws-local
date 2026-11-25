#!/usr/bin/env python3
"""Exercise the stock Sync APK against the owner-local synthetic cloud fixture.

This is a narrow, account-free UI harness.  It only enters the disposable
fixture credentials defined in ``official_app_cloud_fixture.py``; it never
accepts caller-supplied credentials and never contacts a Mahlkönig service.
The emulator must already have the exact local AP, cloud, and DNS bridges
installed as described by ``docs/ANDROID_LOCAL_APP_SETUP.md``.
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Any

from official_app_touch_probe import (
    PACKAGE,
    adb,
    activity_is_foreground,
    choose_device,
    edit_fields,
    focused_login,
    keyboard_visible,
    key,
    login_node,
    tap,
    ui_dump,
)


FIXTURE_EMAIL = "fixture@example.invalid"
FIXTURE_PASSWORD = "fixture-only-password"


def input_text(serial: str, value: str) -> None:
    adb(serial, "shell", "input", "text", value)


def wait_for_fields(serial: str, timeout: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            root = ui_dump(serial)
            if len(edit_fields(root)) >= 2:
                return root
        except Exception as exc:  # transient Flutter startup state
            last_error = exc
        time.sleep(0.25)
    if last_error is not None:
        raise RuntimeError(f"official login fields did not appear: {last_error}")
    raise RuntimeError("official login fields did not appear")


def dismiss_keyboard(serial: str, root: Any) -> Any:
    if keyboard_visible(root):
        key(serial, "4")
        time.sleep(0.3)
        return ui_dump(serial)
    return root


def report_result(serial: str, *, activated: bool, activation_method: str) -> dict[str, Any]:
    time.sleep(5.0)
    root = ui_dump(serial)
    foreground = activity_is_foreground(serial, PACKAGE)
    login_present = foreground and login_node(root) is not None
    return {
        "schema": "official-app-cloud-ui-test-v1",
        "policy": {
            "synthetic_credentials_only": True,
            "real_credentials": False,
            "vendor_cloud_allowed": False,
            "raw_field_values_recorded": False,
        },
        "app_foreground": foreground,
        "login_activation_sent": activated,
        "activation_method": activation_method,
        "login_screen_still_present": login_present,
        "post_login_surface": (
            "login" if login_present else "non_login_or_loading_surface"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="ADB serial; otherwise require one device")
    args = parser.parse_args(argv)

    report: dict[str, Any] = {
        "schema": "official-app-cloud-ui-test-v1",
        "policy": {
            "synthetic_credentials_only": True,
            "real_credentials": False,
            "vendor_cloud_allowed": False,
            "raw_field_values_recorded": False,
        },
    }
    serial: str | None = None
    try:
        serial = choose_device(args.serial)
        adb(serial, "shell", "am", "force-stop", PACKAGE)
        adb(serial, "shell", "pm", "clear", PACKAGE)
        adb(
            serial,
            "shell",
            "am",
            "start",
            "-W",
            "-n",
            f"{PACKAGE}/de.yukawa.hemro.ngx.MainActivity",
        )
        root = wait_for_fields(serial)
        fields = edit_fields(root)
        tap(serial, fields[0])
        input_text(serial, FIXTURE_EMAIL)
        root = dismiss_keyboard(serial, ui_dump(serial))
        fields = edit_fields(root)
        tap(serial, fields[1])
        input_text(serial, FIXTURE_PASSWORD)
        root = dismiss_keyboard(serial, ui_dump(serial))
        button = login_node(root)
        if button is None:
            raise RuntimeError("fixture values did not enable Login")

        tap(serial, button)
        time.sleep(0.75)
        root = ui_dump(serial)
        if login_node(root) is None:
            report.update(report_result(serial, activated=True, activation_method="measured_tap"))
        else:
            fields = edit_fields(root)
            if len(fields) < 2:
                raise RuntimeError("login form disappeared before focus fallback")
            tap(serial, fields[1])
            root = dismiss_keyboard(serial, ui_dump(serial))
            key(serial, "61")
            key(serial, "61")
            root = ui_dump(serial)
            if not focused_login(root):
                raise RuntimeError("Login focus fallback did not reach the control")
            key(serial, "23")
            report.update(
                report_result(serial, activated=True, activation_method="accessibility_focus")
            )
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        return_code = 1
    else:
        return_code = 0
    print(json.dumps(report, indent=2, sort_keys=True))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
