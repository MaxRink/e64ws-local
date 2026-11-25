"""Contract coverage: which contract rows are actually exercised by a suite.

Coverage is deliberately conservative: a row counts as covered only if some
scenario contains a step that targets it. Rows that cannot be exercised safely
are listed with the reason recorded in the contract (`coverage_note`).
"""

from __future__ import annotations

import json
from pathlib import Path

REST_PATHS = {
    "ping": "/rest_api/ping",
    "login": "/rest_api/login",
    "logout": "/rest_api/logout",
    "check_session": "/rest_api/check_session",
    "update_session": "/rest_api/update_session",
    "get_machine_info": "/rest_api/get_machine_info",
    "get_wifi_info": "/rest_api/get_wifi_info",
    "scan_wifi": "/rest_api/scan_wifi",
    "request_onboarding": "/rest_api/request_onboarding",
    "reboot": "/rest_api/reboot",
    "get_fw_update_state": "/rest_api/get_fw_update_state",
    "download_database": "/rest_api/download_database",
    "download_machine_logs": "/rest_api/download_machine_logs",
    "upload_swu": "/upload_swu.php",
    "upload_esp": "/upload_esp.php",
    "upload_splash": "/upload_splash_screen.php",
    "wifi_save": "/wifi.php",
}


def _matches(entry: dict, step: dict) -> bool:
    surface = entry["surface"]
    if surface == "wss":
        if entry.get("action"):
            return step.get("op") == "wss" and step.get("action") == entry["action"]
        return step.get("op") == "wss" and step.get("type") == entry["name"]
    if surface == "rest":
        path = REST_PATHS.get(entry["name"])
        return step.get("op") == "http" and path and step.get("path", "").startswith(path)
    if surface == "esp.ctrl":
        if entry["direction"] == "X->D":
            return step.get("op") == "esp.event" and step.get("id") == int(entry["id"].split("-")[1])
        return step.get("op") == "shell" and "EspWifiConfig" in step.get("cmd", "")
    if surface == "esp.json":
        return step.get("op") == "espjson.watch"
    if surface in ("sysfs",):
        return step.get("op") == "shell"
    if surface == "files":
        return step.get("op") in ("shell", "db")
    if surface == "power":
        return step.get("op") == "reboot"
    return False


def coverage(contract: dict, scenarios: list[dict]) -> dict:
    steps = [(scenario["id"], step) for scenario in scenarios for step in scenario["steps"]]
    rows = []
    for entry in contract["entries"]:
        hits = [sid for sid, step in steps if _matches(entry, step)]
        rows.append({
            "id": entry["id"],
            "surface": entry["surface"],
            "name": (entry.get("action") or entry["name"]),
            "covered": bool(hits),
            "scenarios": sorted(set(hits)),
            "reason": entry.get("coverage_note", ""),
        })
    by_surface: dict[str, dict[str, int]] = {}
    for row in rows:
        surface = by_surface.setdefault(row["surface"], {"covered": 0, "total": 0})
        surface["total"] += 1
        surface["covered"] += 1 if row["covered"] else 0
    return {"rows": rows, "by_surface": by_surface,
            "covered": sum(1 for r in rows if r["covered"]), "total": len(rows)}


def render(result: dict) -> str:
    lines = ["| Surface | Covered | Total |", "|---|---:|---:|"]
    for surface, counts in sorted(result["by_surface"].items()):
        lines.append(f"| {surface} | {counts['covered']} | {counts['total']} |")
    lines.append(f"| **total** | **{result['covered']}** | **{result['total']}** |")
    missing = [r for r in result["rows"] if not r["covered"]]
    if missing:
        lines.append("")
        lines.append("Not covered (documented):")
        for row in missing:
            lines.append(f"- `{row['id']}` {row['name']}: {row['reason'] or 'no scenario step'}")
    return "\n".join(lines)


def load_scenarios(directory: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(directory.glob("*.json"))]
