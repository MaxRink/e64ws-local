#!/usr/bin/env python3
"""Reduce an unflutter Flutter-AOT run to reviewable, non-secret inventories.

The full unflutter output is intentionally kept outside Git because it contains
large assembly/CFG artifacts.  This script extracts the parts useful for the
repository's API and architecture ledgers: literal route references, retained
Dart component names, class layouts, and a compact run summary.

Example:

    python tools/android_aot_inventory.py \
      --input /private/tmp/mahlkoenig-unflutter-app \
      --output docs/generated/android-aot

All values are derived from the input JSONL and no credentials, cookies, or
tokens are read or emitted.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


API_ROUTE_RE = re.compile(
    r"^/(?:api/v\d+/|rest_api/|security-service/|mobile-service/|"
    r"dashboard-service/|stats/|push-token/|chain/)"
)
COMPONENT_RE = re.compile(
    r"(?i)(auth|grinder|scale|device|pair|wifi|recipe|shot|brew|token|"
    r"firmware|health|binding|cloud|analytics|event|coffee|xenia|hemro)"
)


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


def family_for_route(route: str) -> tuple[str, str]:
    if route.startswith("/rest_api/"):
        return "local-grinder-onboarding-candidate", "literal-overlap-with-E64-firmware"
    if route.startswith("/api/v2/network"):
        return "xenia-local-provisioning-candidate", "literal-and-Xenia-names"
    if route.startswith("/security-service/"):
        return "cloud-auth", "cloud-service-route-literal"
    if route.startswith("/mobile-service/"):
        return "cloud-mobile-service", "cloud-service-route-literal"
    if route.startswith("/dashboard-service/"):
        return "cloud-dashboard-service", "cloud-service-route-literal"
    if route.startswith("/stats/"):
        return "cloud-stats", "cloud-service-route-literal"
    if route.startswith("/push-token/"):
        return "cloud-push", "cloud-service-route-literal"
    if route.startswith("/chain/"):
        return "cloud-account-chain", "cloud-service-route-literal"
    return "route-unknown", "route-literal"


def shorten(values: Iterable[str], limit: int = 48) -> tuple[str, int]:
    unique = sorted(set(values))
    if len(unique) <= limit:
        return ";".join(unique), 0
    return ";".join(unique[:limit]), len(unique) - limit


def write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="unflutter output directory")
    parser.add_argument("--output", type=Path, required=True, help="checked-in report directory")
    args = parser.parse_args()

    input_dir = args.input.resolve()
    output_dir = args.output
    functions = read_jsonl(input_dir / "functions.jsonl")
    classes = read_jsonl(input_dir / "classes.jsonl")
    string_refs = read_jsonl(input_dir / "string_refs.jsonl")

    route_refs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ref in string_refs:
        value = ref.get("value")
        if isinstance(value, str) and API_ROUTE_RE.match(value):
            route_refs[value].append(ref)

    selected_functions = [
        row for row in functions if COMPONENT_RE.search(str(row.get("name", "")))
    ]

    route_rows: list[dict[str, Any]] = []
    for route in sorted(route_refs):
        refs = route_refs[route]
        names, omitted = shorten(str(ref.get("func", "")) for ref in refs)
        pcs = sorted({str(ref.get("pc", "")) for ref in refs})
        family, evidence = family_for_route(route)
        route_rows.append(
            {
                "route": route,
                "family": family,
                "literal_ref_count": len(refs),
                "distinct_functions": len({str(ref.get("func", "")) for ref in refs}),
                "functions": names,
                "omitted_functions": omitted,
                "literal_pcs": ";".join(pcs[:24]),
                "evidence": evidence,
            }
        )

    component_rows: list[dict[str, Any]] = []
    named_component_count = 0
    named_field_count = 0
    for row in classes:
        class_name = str(row.get("class_name", ""))
        if not COMPONENT_RE.search(class_name):
            continue
        fields = row.get("fields") or []
        named_fields = [
            str(field.get("name"))
            for field in fields
            if isinstance(field, dict)
            and field.get("name")
            and not str(field["name"]).startswith("f_0x")
        ]
        if named_fields:
            named_component_count += 1
            named_field_count += len(named_fields)
        field_names, omitted = shorten(named_fields, limit=64)
        component_rows.append(
            {
                "class_id": row.get("class_id", ""),
                "class_name": class_name,
                "instance_size": row.get("instance_size", ""),
                "field_count": len(fields),
                "named_field_count": len(named_fields),
                "named_fields": field_names,
                "omitted_named_fields": omitted,
                "field_offsets": ";".join(
                    f"{field.get('name')}@{field.get('byte_offset')}"
                    for field in fields
                    if isinstance(field, dict)
                    and field.get("name") in named_fields
                ),
            }
        )

    function_rows: list[dict[str, Any]] = []
    route_by_function: dict[str, set[str]] = defaultdict(set)
    for route, refs in route_refs.items():
        for ref in refs:
            route_by_function[str(ref.get("func", ""))].add(route)
    for row in sorted(selected_functions, key=lambda value: int(str(value.get("pc", "0x0")), 16)):
        name = str(row.get("name", ""))
        routes, omitted = shorten(route_by_function.get(name, ()), limit=16)
        function_rows.append(
            {
                "pc": row.get("pc", row.get("addr", "")),
                "size": row.get("size", ""),
                "name": name,
                "owner": row.get("owner", ""),
                "class_name": row.get("class_name", ""),
                "method_name": row.get("method_name", ""),
                "symbol_source": row.get("symbol_source", ""),
                "route_refs": routes,
                "omitted_route_refs": omitted,
            }
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(
        output_dir / "android_aot_api_routes.csv",
        [
            "route",
            "family",
            "literal_ref_count",
            "distinct_functions",
            "functions",
            "omitted_functions",
            "literal_pcs",
            "evidence",
        ],
        route_rows,
    )
    write_csv(
        output_dir / "android_aot_components.csv",
        [
            "class_id",
            "class_name",
            "instance_size",
            "field_count",
            "named_field_count",
            "named_fields",
            "omitted_named_fields",
            "field_offsets",
        ],
        component_rows,
    )
    write_csv(
        output_dir / "android_aot_functions.csv",
        [
            "pc",
            "size",
            "name",
            "owner",
            "class_name",
            "method_name",
            "symbol_source",
            "route_refs",
            "omitted_route_refs",
        ],
        function_rows,
    )

    summary = {
        "input_dir": str(input_dir),
        "input_files": {
            name: hashlib.sha256((input_dir / name).read_bytes()).hexdigest()
            for name in ("functions.jsonl", "classes.jsonl", "string_refs.jsonl")
        },
        "functions": len(functions),
        "classes": len(classes),
        "string_refs": len(string_refs),
        "api_route_count": len(route_rows),
        "api_route_literal_refs": sum(len(refs) for refs in route_refs.values()),
        "selected_component_function_count": len(function_rows),
        "selected_component_class_count": len(component_rows),
        "selected_classes_with_named_fields": named_component_count,
        "selected_named_field_count": named_field_count,
        "route_families": {
            family: sum(1 for row in route_rows if row["family"] == family)
            for family in sorted({str(row["family"]) for row in route_rows})
        },
        "limitations": [
            "A route literal proves presence, not HTTP verb, request body, response schema, or runtime reachability.",
            "Fields named f_0x... are synthetic offsets; only other retained field names are counted as named.",
            "The selected component regex is a review index, not a complete semantic classification.",
            "Generated reports contain no raw assembly, tokens, cookies, passwords, or account data.",
        ],
    }
    (output_dir / "android_aot_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
