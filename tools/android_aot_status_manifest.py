#!/usr/bin/env python3
"""Create a complete, stable naming/status manifest for a Flutter AOT dump.

The unflutter output contains one row for every recovered function and class
field, but many release-build names are synthetic (``sub_*`` or ``f_0x*``).
This tool gives every row a deterministic review identifier while preserving
the original name and an explicit semantic-status value.  A generated name
is an index, not a claim that the original Dart identifier or behavior was
recovered.

Only compact CSV/JSON reports are written to the repository.  The input AOT
directory remains outside Git and may contain assembly, CFGs, or strings.

Example::

    python tools/android_aot_status_manifest.py \
      --input /private/tmp/mahlkoenig-unflutter-app \
      --output docs/generated/android-aot
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from android_aot_control_flow_inventory import (
    FIELD_LAYOUTS,
    classify_function,
    pc_key,
    read_jsonl,
    route_refs_by_func,
)


GENERIC_FUNCTION_RE = re.compile(r"^(?:sub_|f_0x|unknown|undefined)")
GENERIC_FIELD_RE = re.compile(r"^(?:f_0x|unknown|undefined)")


def is_generic_function_name(value: str) -> bool:
    return not value or bool(GENERIC_FUNCTION_RE.match(value))


def is_generic_field_name(value: str) -> bool:
    return not value or bool(GENERIC_FIELD_RE.match(value))


def safe_token(value: Any, fallback: str) -> str:
    token = re.sub(r"[^A-Za-z0-9]+", "_", str(value)).strip("_")
    return token or fallback


def function_review_name(row: dict[str, Any]) -> tuple[str, str, str]:
    """Return stable review name, naming status, and naming evidence."""

    name = str(row.get("name", ""))
    method = str(row.get("method_name", ""))
    owner = str(row.get("owner", row.get("class_name", "")))
    pc = safe_token(row.get("pc", "0"), "unknown_pc")

    if not is_generic_function_name(name):
        return name, "retained-name", "AOT row retains a non-generated function name"

    if method and not is_generic_function_name(method):
        owner_token = safe_token(owner, "global")
        method_token = safe_token(method, "method")
        return (
            f"aot_{pc}_{owner_token}_{method_token}",
            "method-retained-name",
            "function address is generated, but method_name is retained",
        )

    owner_token = safe_token(owner, "global")
    return (
        f"aot_{pc}_{owner_token}",
        "generated-unresolved",
        "stable address/owner index; original function meaning is unresolved",
    )


def field_review_name(
    class_row: dict[str, Any], field: dict[str, Any]
) -> tuple[str, str, str, str]:
    """Return review name, status, evidence, and optional recovered label."""

    class_name = str(class_row.get("class_name", ""))
    class_id = safe_token(class_row.get("class_id", "unknown_class"), "unknown_class")
    offset = int(field.get("byte_offset", 0))
    original = str(field.get("name", ""))
    known = FIELD_LAYOUTS.get(class_name, {}).get(offset)
    recovered_label = known[0] if known else ""

    if known:
        label, _wire_role, evidence = known
        return label, "recovered-layout-label", evidence, label

    if original and not is_generic_field_name(original):
        return original, "retained-field-name", "AOT class layout retains a non-generated field name", ""

    return (
        f"aot_field_{class_id}_{offset:#x}",
        "generated-offset-index",
        "stable class-id/byte-offset index; field meaning is unresolved",
        "",
    )


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
    routes_by_func = route_refs_by_func(string_refs)

    function_rows: list[dict[str, Any]] = []
    function_statuses: Counter[str] = Counter()
    function_domains: Counter[str] = Counter()
    function_confidence: Counter[str] = Counter()
    for row in sorted(functions, key=pc_key):
        original_name = str(row.get("name", ""))
        review_name, name_status, name_evidence = function_review_name(row)
        domain, confidence, classification_evidence = classify_function(
            row, routes_by_func.get(original_name, set())
        )
        function_statuses[name_status] += 1
        function_domains[domain] += 1
        function_confidence[confidence] += 1
        function_rows.append(
            {
                "pc": row.get("pc", row.get("addr", "")),
                "size": row.get("size", ""),
                "review_name": review_name,
                "original_name": original_name,
                "owner": row.get("owner", ""),
                "class_name": row.get("class_name", ""),
                "method_name": row.get("method_name", ""),
                "symbol_source": row.get("symbol_source", ""),
                "name_status": name_status,
                "domain": domain,
                "confidence": confidence,
                "name_evidence": name_evidence,
                "classification_evidence": classification_evidence,
                "route_refs": ";".join(sorted(routes_by_func.get(original_name, set()))),
            }
        )

    field_rows: list[dict[str, Any]] = []
    field_statuses: Counter[str] = Counter()
    for class_row in classes:
        fields = class_row.get("fields") or []
        if not isinstance(fields, list):
            continue
        for field_index, field in enumerate(fields):
            if not isinstance(field, dict):
                continue
            offset = int(field.get("byte_offset", 0))
            review_name, status, evidence, recovered_label = field_review_name(class_row, field)
            field_statuses[status] += 1
            field_rows.append(
                {
                    "class_id": class_row.get("class_id", ""),
                    "class_name": class_row.get("class_name", ""),
                    "instance_size": class_row.get("instance_size", ""),
                    "field_index": field_index,
                    "byte_offset": offset,
                    "review_name": review_name,
                    "original_name": field.get("name", ""),
                    "name_status": status,
                    "recovered_label": recovered_label,
                    "evidence": evidence,
                }
            )
    field_rows.sort(
        key=lambda row: (
            str(row["class_name"]),
            int(row["byte_offset"]),
            int(row["field_index"]),
        )
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(
        output_dir / "android_aot_function_status.csv",
        [
            "pc",
            "size",
            "review_name",
            "original_name",
            "owner",
            "class_name",
            "method_name",
            "symbol_source",
            "name_status",
            "domain",
            "confidence",
            "name_evidence",
            "classification_evidence",
            "route_refs",
        ],
        function_rows,
    )
    write_csv(
        output_dir / "android_aot_field_status.csv",
        [
            "class_id",
            "class_name",
            "instance_size",
            "field_index",
            "byte_offset",
            "review_name",
            "original_name",
            "name_status",
            "recovered_label",
            "evidence",
        ],
        field_rows,
    )

    input_names = ("functions.jsonl", "classes.jsonl", "string_refs.jsonl")
    summary = {
        "input_dir": str(input_dir),
        "input_files": {
            name: hashlib.sha256((input_dir / name).read_bytes()).hexdigest()
            for name in input_names
        },
        "function_count": len(function_rows),
        "function_name_status_counts": dict(sorted(function_statuses.items())),
        "function_domain_counts": dict(sorted(function_domains.items())),
        "function_confidence_counts": dict(sorted(function_confidence.items())),
        "field_count": len(field_rows),
        "field_name_status_counts": dict(sorted(field_statuses.items())),
        "all_rows_have_review_name": all(bool(row["review_name"]) for row in function_rows + field_rows),
        "limitations": [
            "Generated review names are stable indexes, not recovered source identifiers.",
            "AOT output does not expose the original Dart local-variable table; locals are not represented by this manifest.",
            "A field offset is not a type or semantic proof unless retained names or a separately documented layout fact supports it.",
            "Domain and confidence values are static evidence classifications, not runtime reachability claims.",
            "This report contains no raw assembly, cookies, passwords, access tokens, or account data.",
        ],
    }
    (output_dir / "android_aot_status_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
