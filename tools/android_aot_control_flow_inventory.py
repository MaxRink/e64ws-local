#!/usr/bin/env python3
"""Build a reproducible, compact control-flow ledger from unflutter AOT output.

This is a static review aid, not a source recovery tool.  It classifies every
function using retained names/literal references, then follows the named
``bl`` edges from the pairing/onboarding roots.  The full unflutter directory
is intentionally kept outside Git; only CSV/JSON/Mermaid reductions are
checked in.

The script never reads or emits cookies, passwords, account data, or raw
assembly.  A route literal is reported as evidence of presence only.  A call
edge is reported as direct/annotated graph evidence; it is not proof that the
edge is reached for every runtime state.

Example::

    python tools/android_aot_control_flow_inventory.py \
      --input /private/tmp/mahlkoenig-unflutter-app \
      --output docs/generated/android-aot
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any, Iterable


ROUTE_RE = re.compile(
    r"^/(?:api/v\d+/|rest_api/|security-service/|mobile-service/|"
    r"dashboard-service/|stats/|push-token/|chain/)"
)

# These are intentionally method-level roots.  A suffix containing a snapshot
# hash/address changes between builds, while method_name is normally retained.
ROOT_METHODS = {
    "_requestGrinderOnboarding",
    "_initializePolling",
    "_handleDeviceStatusPollingResult",
    "_stopPolling",
    "requestOnboarding",
    "_connectToWifiBySsid",
    "_onConnected",
    "_continueLoggedIn",
    "_loginGrinder",
    "_getPasswordPart",
    "_getSsidFromDeviceId",
    "onQrCodeScanned",
    "login",
    "scanWifis",
    "connect",
    "wificred",
    "toJson",
    "simplified",
}

FOCUS_OWNERS = {
    "DevicePairingCubit",
    "DeviceConnectionRepository",
    "DeviceConnectionInterface",
    "IOTWiFiService",
    "ScaleConnectionInterface",
    "WifiConfig",
    "_WifiConfig",
    "_RequestOnboardingData",
    "RequestOnboardingData",
    "TokenProviderService",
    "AuthStorage",
    "GrinderApiClient",
    "FlavorConfig",
}

FIELD_LAYOUTS: dict[str, dict[int, tuple[str, str, str]]] = {
    "_RequestOnboardingData@1172456414": {
        4: ("token", "wire-field-0", "high: retained toString/serializer evidence"),
        8: ("restUrl", "wire-field-1", "high: retained toString/serializer evidence"),
        12: ("status", "wire-field-2", "high: retained toString/serializer evidence"),
        16: ("subType", "wire-field-3", "medium: retained name and serializer order"),
        20: ("socketUrl", "wire-field-4", "high: retained toString/serializer evidence"),
        24: ("unknown_wire_field", "wire-field-5", "low: serializer writes a sixth slot; key/value unresolved"),
        28: ("unresolved_storage_slot", "not-proven-wire", "low: class layout has a seventh slot; serializer access not established"),
    },
    "_WifiConfig@1175145900": {
        4: ("ssid", "wire-field-0", "high: retained toString/serializer evidence"),
        8: ("password_or_validity", "wire-field-1", "medium: toString retains isNewPasswordValid; request-body meaning unresolved"),
        12: ("dhcp", "wire-field-2", "high: retained toString/serializer evidence"),
    },
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"invalid JSON in {path}:{line_number}: {exc}") from exc
            if isinstance(value, dict):
                rows.append(value)
    return rows


def pc_key(row: dict[str, Any]) -> int:
    value = row.get("pc", row.get("addr", "0"))
    try:
        return int(str(value), 16)
    except ValueError:
        return 0


def method_name(row: dict[str, Any]) -> str:
    return str(row.get("method_name", ""))


def owner_name(row: dict[str, Any]) -> str:
    return str(row.get("owner", row.get("class_name", "")))


def route_refs_by_func(string_refs: Iterable[dict[str, Any]]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for ref in string_refs:
        value = ref.get("value")
        if isinstance(value, str) and ROUTE_RE.match(value):
            result[str(ref.get("func", ""))].add(value)
    return result


def classify_function(row: dict[str, Any], route_refs: set[str]) -> tuple[str, str, str]:
    """Return domain, confidence, and reason without pretending unknown names are semantic."""

    text = " ".join(
        str(row.get(key, ""))
        for key in ("name", "owner", "class_name", "method_name")
    )
    lower = text.lower()
    if route_refs:
        if any(route.startswith("/rest_api/") for route in route_refs):
            return "local-route", "high", "retained function has E64-overlap REST literal"
        if any(route.startswith("/api/v2/network") for route in route_refs):
            return "xenia-provisioning", "high", "retained function has Xenia route literal"
        return "cloud-route", "high", "retained function has service route literal"
    if any(token in lower for token in ("requestonboarding", "pairing", "qrscan", "connecttowifi", "getpasswordpart", "getssidfromdeviceid")):
        return "pairing-onboarding", "high" if not lower.startswith(("sub_", "f_0x")) else "low", "retained pairing/onboarding name"
    if any(token in lower for token in ("deviceconnection", "iotwifi", "wificonfig", "wifi_config", "wificred")):
        return "local-transport", "high" if not lower.startswith(("sub_", "f_0x")) else "low", "retained local transport/model name"
    if any(token in lower for token in ("scaleconnection", "scalelivedata", "scalebinding", "scale")):
        return "scale", "high" if not lower.startswith(("sub_", "f_0x")) else "low", "retained scale name"
    if any(token in lower for token in ("authstorage", "tokenprovider", "authrepository", "refreshaccesstoken", "login")):
        return "cloud-auth", "high" if not lower.startswith(("sub_", "f_0x")) else "low", "retained authentication name"
    if any(token in lower for token in ("serializer", "tojson", "fromjson", "copywith", "requestdata", "response")):
        return "model-serializer", "high" if not lower.startswith(("sub_", "f_0x")) else "low", "retained model/serializer name"
    if any(token in lower for token in ("security", "certificate", "tls", "socket", "dio", "http", "network")):
        return "network-security", "medium", "retained network/security term"
    if any(token in lower for token in ("cubit", "state", "widget", "screen", "route", "step")):
        return "ui-state", "medium", "retained UI/state term"
    if lower.startswith(("sub_", "f_0x", "unknown", "undefined")):
        return "unknown-generated", "low", "synthetic/generated name without semantic anchor"
    return "utility-or-unclassified", "low", "no retained domain anchor"


def is_root(row: dict[str, Any]) -> bool:
    owner = owner_name(row)
    method = method_name(row)
    if method in ROOT_METHODS and (owner in FOCUS_OWNERS or owner == ""):
        return True
    name = str(row.get("name", ""))
    return any(
        marker in name
        for marker in (
            "_requestGrinderOnboarding",
            "_initializePolling",
            "_handleDeviceStatusPollingResult",
            "_stopPolling",
        )
    )


def write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_mermaid(root_rows: list[dict[str, Any]], edge_rows: list[dict[str, Any]]) -> str:
    labels = {
        "_requestGrinderOnboarding": "requestGrinderOnboarding",
        "_initializePolling": "initializePolling",
        "_handleDeviceStatusPollingResult": "handleDeviceStatusPollingResult",
        "_stopPolling": "stopPolling",
        "_connectToWifiBySsid": "connectToWifiBySsid",
        "_onConnected": "onConnected",
        "_loginGrinder": "loginGrinder",
        "requestOnboarding": "requestOnboarding",
        "login": "localLogin",
        "connect": "wifiConnect",
    }

    def node_id(row: dict[str, Any]) -> str:
        return "n" + re.sub(r"[^A-Za-z0-9_]", "_", str(row.get("pc", "unknown")))

    lines = [
        "flowchart TD",
        "    QR[onQrCodeScanned] --> WIFI[connectToWifiBySsid]",
        "    WIFI --> CONNECTED[onConnected]",
        "    CONNECTED --> LOGIN[DeviceConnectionRepository.login]",
        "    LOGIN --> REQUEST[requestGrinderOnboarding]",
        "    REQUEST --> SERIALIZE[RequestOnboardingData.toJson]",
        "    REQUEST --> POLL[initializePolling]",
        "    POLL --> GUARD{attempts <= 30}",
        "    GUARD -->|yes| QUERY[mobile-service/device/query]",
        "    GUARD -->|no| STOP[stopPolling / timeout]",
        "    QUERY --> ACCEPT{items non-empty?}",
        "    ACCEPT -->|yes| DONE[paired/bound path]",
        "    ACCEPT -->|no| GUARD",
        "    classDef evidence fill:#e8f4ff,stroke:#246;",
        "    class REQUEST,SERIALIZE,POLL,GUARD,QUERY evidence;",
        "",
        "    %% The nodes above are intentionally normalized labels. The CSV contains exact PCs/names.",
    ]
    # Add a small exact-PC appendix only for roots, keeping the diagram legible.
    for row in sorted(root_rows, key=pc_key):
        node = node_id(row)
        method = method_name(row) or str(row.get("name", ""))
        lines.append(f'    {node}["{method}\\n{row.get("pc", "")}"]')
    lines.append("    %% Direct-edge count in the generated ledger: " + str(len(edge_rows)))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="unflutter output directory")
    parser.add_argument("--output", type=Path, required=True, help="checked-in report directory")
    parser.add_argument("--depth", type=int, default=2, help="named BL edge depth from roots (default: 2)")
    args = parser.parse_args()
    if args.depth < 0 or args.depth > 8:
        raise SystemExit("--depth must be between 0 and 8")

    input_dir = args.input.resolve()
    output_dir = args.output
    functions = read_jsonl(input_dir / "functions.jsonl")
    classes = read_jsonl(input_dir / "classes.jsonl")
    string_refs = read_jsonl(input_dir / "string_refs.jsonl")
    call_edges = read_jsonl(input_dir / "call_edges.jsonl")

    routes_by_func = route_refs_by_func(string_refs)
    function_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in functions:
        function_by_name[str(row.get("name", ""))].append(row)

    all_rows: list[dict[str, Any]] = []
    domain_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    for row in sorted(functions, key=pc_key):
        name = str(row.get("name", ""))
        domain, confidence, reason = classify_function(row, routes_by_func.get(name, set()))
        domain_counts[domain] += 1
        confidence_counts[confidence] += 1
        all_rows.append(
            {
                "pc": row.get("pc", row.get("addr", "")),
                "size": row.get("size", ""),
                "name": name,
                "owner": row.get("owner", ""),
                "class_name": row.get("class_name", ""),
                "method_name": row.get("method_name", ""),
                "symbol_source": row.get("symbol_source", ""),
                "domain": domain,
                "confidence": confidence,
                "evidence": reason,
                "route_refs": ";".join(sorted(routes_by_func.get(name, set()))),
            }
        )
    write_csv(
        output_dir / "android_aot_all_functions.csv",
        ["pc", "size", "name", "owner", "class_name", "method_name", "symbol_source", "domain", "confidence", "evidence", "route_refs"],
        all_rows,
    )

    root_rows = [row for row in functions if is_root(row)]
    root_names = {str(row.get("name", "")) for row in root_rows}
    edges_by_from: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in call_edges:
        if edge.get("kind") == "bl":
            edges_by_from[str(edge.get("from_func", ""))].append(edge)

    discovered: dict[str, int] = {name: 0 for name in root_names}
    queue: deque[tuple[str, int]] = deque((name, 0) for name in sorted(root_names))
    while queue:
        current, depth = queue.popleft()
        if depth >= args.depth:
            continue
        for edge in edges_by_from.get(current, ()):
            target = str(edge.get("target", ""))
            if target not in discovered:
                discovered[target] = depth + 1
                queue.append((target, depth + 1))

    focus_names = set(discovered)
    focus_rows: list[dict[str, Any]] = []
    for row in sorted(functions, key=pc_key):
        name = str(row.get("name", ""))
        if name not in focus_names:
            continue
        domain, confidence, reason = classify_function(row, routes_by_func.get(name, set()))
        focus_rows.append(
            {
                "pc": row.get("pc", row.get("addr", "")),
                "size": row.get("size", ""),
                "name": name,
                "owner": row.get("owner", ""),
                "method_name": row.get("method_name", ""),
                "depth_from_root": discovered[name],
                "domain": domain,
                "confidence": confidence,
                "evidence": reason,
            }
        )
    write_csv(
        output_dir / "android_aot_focus_functions.csv",
        ["pc", "size", "name", "owner", "method_name", "depth_from_root", "domain", "confidence", "evidence"],
        focus_rows,
    )

    focus_edges: list[dict[str, Any]] = []
    for edge in call_edges:
        if edge.get("kind") != "bl":
            continue
        source = str(edge.get("from_func", ""))
        target = str(edge.get("target", ""))
        if source not in focus_names or target not in focus_names:
            continue
        target_rows = function_by_name.get(target, [])
        focus_edges.append(
            {
                "from": source,
                "from_pc": edge.get("from_pc", ""),
                "kind": edge.get("kind", ""),
                "target": target,
                "target_known": bool(target_rows),
                "target_pcs": ";".join(sorted(str(item.get("pc", "")) for item in target_rows)),
                "source_depth": discovered.get(source, ""),
                "target_depth": discovered.get(target, ""),
                "evidence": "unflutter call_edges.jsonl direct/annotated BL record",
            }
        )
    focus_edges.sort(key=lambda row: (str(row["from"]), str(row["from_pc"]), str(row["target"])))
    write_csv(
        output_dir / "android_aot_focus_edges.csv",
        ["from", "from_pc", "kind", "target", "target_known", "target_pcs", "source_depth", "target_depth", "evidence"],
        focus_edges,
    )

    field_rows: list[dict[str, Any]] = []
    selected_class_names = set(FIELD_LAYOUTS)
    for row in classes:
        class_name = str(row.get("class_name", ""))
        if class_name not in selected_class_names:
            continue
        for field in row.get("fields") or []:
            if not isinstance(field, dict):
                continue
            offset = int(field.get("byte_offset", 0))
            label, wire_role, evidence = FIELD_LAYOUTS[class_name].get(
                offset,
                ("unresolved_field", "not-proven-wire", "low: no retained semantic label"),
            )
            field_rows.append(
                {
                    "class_name": class_name,
                    "class_id": row.get("class_id", ""),
                    "instance_size": row.get("instance_size", ""),
                    "byte_offset": offset,
                    "serialized_slot": (offset - 4) // 4,
                    "aot_field_name": field.get("name", ""),
                    "recovered_label": label,
                    "wire_role": wire_role,
                    "confidence_evidence": evidence,
                }
            )
    field_rows.sort(key=lambda row: (str(row["class_name"]), int(row["byte_offset"])))
    write_csv(
        output_dir / "android_aot_field_ledger.csv",
        ["class_name", "class_id", "instance_size", "byte_offset", "serialized_slot", "aot_field_name", "recovered_label", "wire_role", "confidence_evidence"],
        field_rows,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    mermaid = build_mermaid(root_rows, focus_edges)
    (output_dir / "android_aot_control_flow.mmd").write_text(mermaid, encoding="utf-8")

    input_names = ("functions.jsonl", "classes.jsonl", "string_refs.jsonl", "call_edges.jsonl")
    summary = {
        "input_dir": str(input_dir),
        "input_files": {name: hashlib.sha256((input_dir / name).read_bytes()).hexdigest() for name in input_names},
        "functions": len(functions),
        "classes": len(classes),
        "string_refs": len(string_refs),
        "call_edges": len(call_edges),
        "direct_bl_edges": sum(1 for edge in call_edges if edge.get("kind") == "bl"),
        "classified_function_count": len(all_rows),
        "domain_counts": dict(sorted(domain_counts.items())),
        "confidence_counts": dict(sorted(confidence_counts.items())),
        "focus_root_count": len(root_rows),
        "focus_root_names": sorted(root_names),
        "focus_function_count": len(focus_rows),
        "focus_edge_count": len(focus_edges),
        "focus_depth": args.depth,
        "field_ledger_rows": len(field_rows),
        "concrete_findings": [
            "The current AOT build retains a named DevicePairingCubit -> local WiFi -> local login -> onboarding/polling method family.",
            "The current pairing model has six serializer-accessed RequestOnboardingData slots plus a seventh class-layout slot whose wire meaning is unresolved.",
            "RequestOnboardingData has five retained field labels (token, restUrl, status, subType, socketUrl); one serialized slot remains unresolved.",
            "WifiConfig has three serializer-accessed slots; ssid and dhcp are retained, while the middle slot is only safely labeled password_or_validity.",
            "The polling implementation contains a 30-attempt guard in the analyzed current-build control flow; its exact timer interval and cloud response schema remain runtime-untested.",
        ],
        "limitations": [
            "This is a name/call-edge reduction, not a decompilation into buildable Dart source.",
            "Indirect dispatch, closures, and generated runtime helpers can make the graph incomplete or over-inclusive.",
            "The field ledger records exact class byte offsets but does not infer a missing JSON key or password algorithm.",
            "A route literal proves presence only; it does not prove HTTP verb, body, headers, response schema, or runtime reachability.",
            "The checked-in reports contain no raw assembly, tokens, cookies, passwords, or account data.",
        ],
    }
    (output_dir / "android_aot_control_flow_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
