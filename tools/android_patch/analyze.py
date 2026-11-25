#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import (
    AUTH_LITERALS,
    ARM64_SPLIT,
    BLOCKED_HOST,
    CLOUD_HOST,
    LIBAPP_SHA256,
    LOCAL_LITERALS,
    PatchError,
    offsets,
    read_libapp,
    verify_inputs,
)


def strings_line_map(strings_path: Path) -> dict[str, list[int]]:
    wanted = {
        "/rest_api/login",
        "/rest_api/request_onboarding",
        "/rest_api/scan_wifi",
        "/api/v2/network",
        "/api/v2/network/list",
        "/api/v2/network/connect",
        "/api/v2/network/forcescan",
        "http://172.16.0.1/",
        "http://192.168.4.1/",
        "https://192.168.4.1/",
        "RequestOnboardingData(token: ",
        "ScannedWifiResponse(data: ",
        "ScannedWifi(bssid: ",
        "WifiConfig(ssid: ",
        "XeniaWifiConnectionRequest(ssid: ",
        "XeniaWifiSsidResponse(networks: ",
        "XeniaNetworkResponse(accessPointIP: ",
        "_$RequestOnboardingDataToJson@1172456414",
        "_$ScannedWifiResponseFromJson@1174159360",
        "_$ScannedWifiResponseToJson@1174159360",
        "_$ScannedWifiFromJson@1173242322",
        "_$ScannedWifiToJson@1173242322",
        "_$WifiConfigToJson@1175145900",
        "_$XeniaWifiConnectionRequestToJson@881176348",
        "_$XeniaWifiSsidResponseFromJson@882388341",
        "_$XeniaWifiSsidResponseToJson@882388341",
        "_$XeniaNetworkResponseFromJson@880410736",
        "_$XeniaNetworkResponseToJson@880410736",
        "AuthState.notLoggedIn(refreshToken: ",
        "AuthState.loggedIn(accessToken: ",
        ", ssid: ",
        ", channel: ",
        ", rssi: ",
        ", password: ",
        ", connectedSSID: ",
        "userRole",
        "password",
        "networks",
    }
    result = {value: [] for value in wanted}
    with strings_path.open("r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            value = line.rstrip("\r\n")
            if value in result:
                result[value].append(number)
    return {key: value for key, value in sorted(result.items()) if value}


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze the pinned owner-supplied APK locally")
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--strings", type=Path)
    args = parser.parse_args()
    strings_path = args.strings or args.input_dir / "libapp.strings"
    try:
        split_hashes = verify_inputs(args.input_dir)
        libapp = read_libapp(args.input_dir / ARM64_SPLIT)
        report = {
            "artifact": {
                "libapp_sha256": LIBAPP_SHA256,
                "split_sha256": split_hashes,
            },
            "cloud_host": {
                "source": CLOUD_HOST.decode(),
                "replacement": BLOCKED_HOST.decode(),
                "offsets": [hex(value) for value in offsets(libapp, CLOUD_HOST)],
                "length_preserving": len(CLOUD_HOST) == len(BLOCKED_HOST),
            },
            "local_literals": {
                value.decode(): [hex(item) for item in offsets(libapp, value)]
                for value in LOCAL_LITERALS
            },
            "auth_literals": {
                value.decode(): [hex(item) for item in offsets(libapp, value)]
                for value in AUTH_LITERALS
            },
            "strings_lines": strings_line_map(strings_path),
            "account_gate_patch": {
                "status": "blocked",
                "reason": (
                    "No Dart-AOT-aware control-flow export or high-confidence, "
                    "hash-pinned account-gate instruction patch is available."
                ),
            },
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except PatchError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
