#!/usr/bin/env python3
"""Create a redacted D/S/M/R/U status manifest for all retained ELF rows.

The exhaustive Ghidra export proves that a body was discovered and, usually,
decompiled. It does not prove that the body is semantically understood or
runtime-validated. This manifest makes that distinction machine-readable for
every exported row:

* ``D`` — explicitly annotated/reviewed at a recovered address;
* ``M`` — a vendor subsystem is statically classified, but only a model or
  hotspot-level conclusion is justified;
* ``R`` — a custom runtime/I/O boundary is statically present but needs a live
  or hardware experiment for behavior;
* ``S`` — symbol/ABI/library-level evidence (including thunks/externals);
* ``U`` — failed decompilation or missing artifact.

These are review statuses, not a claim that every ``D`` function is fully
recovered source. The input CSVs and C artifacts stay outside Git.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


ANNOTATION_RE = re.compile(r"f\(\s*0x([0-9A-Fa-f]+)L\s*,")
RUNTIME_CATEGORIES = {
    "auth-session",
    "esp-transport",
    "grinder-runtime",
    "protocol-network",
    "sqlite-storage",
    "update-boot",
}
MODEL_NAME_RE = re.compile(
    r"(?i)(?:^|[^a-z])(gbs|agsa|grind|machineconfig|jsonconnector|command|rest|cloud|"
    r"driver|espdriver|wificonfig|swupdate|rollback)(?:[^a-z]|$)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exports-root", type=Path, default=Path("/private/tmp/mahlkoenig-e64-full-decomp"))
    parser.add_argument("--annotation-script", type=Path, default=Path("tools/ghidra/ApplyE64RecoveredAnnotations.java"))
    parser.add_argument("--elf-offset", type=lambda value: int(value, 0), default=0x10000)
    parser.add_argument("--output", type=Path, default=Path("docs/generated/ghidra_function_status.csv"))
    parser.add_argument("--summary", type=Path, default=Path("docs/generated/ghidra_function_status_summary.json"))
    return parser.parse_args()


def bool_value(value: str) -> bool:
    return value.strip().lower() == "true"


def annotation_addresses(path: Path, elf_offset: int) -> set[int]:
    addresses: set[int] = set()
    for match in ANNOTATION_RE.finditer(path.read_text(encoding="utf-8")):
        addresses.add(int(match.group(1), 16) + elf_offset)
    return addresses


def artifact_exists(row: dict[str, str], exports_root: Path) -> bool:
    raw = row.get("decomp_file", "")
    if not raw:
        return False
    path = Path(raw)
    if path.is_file():
        return True
    # Permit a relocated export root without emitting or depending on the
    # original temporary absolute path.
    program = row.get("program", "")
    return (exports_root / program / path.name).is_file()


def review_status(row: dict[str, str], annotated: bool, artifact: bool) -> tuple[str, str]:
    if row.get("decomp_status") != "ok" or not artifact:
        return "U", "decompilation failed or C artifact is unavailable"
    if annotated:
        return "D", "address has an explicit recovered annotation"
    if bool_value(row.get("external", "false")) or bool_value(row.get("thunk", "false")):
        return "S", "external/ABI thunk evidence; vendor semantics not asserted"
    category = row.get("category", "")
    name = row.get("name", "")
    if category in RUNTIME_CATEGORIES:
        if MODEL_NAME_RE.search(name):
            return "M", "vendor subsystem model/hotspot classification without full runtime proof"
        return "R", "custom runtime/I/O boundary requires live or hardware validation"
    if MODEL_NAME_RE.search(name):
        return "M", "retained vendor name supports subsystem model, not source equivalence"
    return "S", "symbol/category evidence only; no semantic annotation"


def main() -> int:
    args = parse_args()
    exports_root = args.exports_root.resolve()
    if not exports_root.is_dir():
        raise SystemExit(f"export root not found: {exports_root}")
    if not args.annotation_script.is_file():
        raise SystemExit(f"annotation script not found: {args.annotation_script}")
    annotated_addresses = annotation_addresses(args.annotation_script, args.elf_offset)
    rows: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    program_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    annotated_count = 0
    artifact_missing = 0
    for csv_path in sorted(exports_root.glob("*.csv"), key=lambda path: path.name.lower()):
        with csv_path.open(encoding="utf-8", newline="") as stream:
            for raw in csv.DictReader(stream):
                if raw is None:
                    continue
                try:
                    address = int(raw.get("address", "0"), 16)
                except ValueError:
                    address = 0
                annotated = address in annotated_addresses
                artifact = artifact_exists(raw, exports_root)
                status, reason = review_status(raw, annotated, artifact)
                if annotated:
                    annotated_count += 1
                if not artifact:
                    artifact_missing += 1
                status_counts[status] += 1
                program_counts[raw.get("program", "")] += 1
                category_counts[raw.get("category", "")] += 1
                rows.append(
                    {
                        "program": raw.get("program", ""),
                        "index": raw.get("index", ""),
                        "address": raw.get("address", ""),
                        "name": raw.get("name", ""),
                        "category": raw.get("category", ""),
                        "thunk": raw.get("thunk", ""),
                        "external": raw.get("external", ""),
                        "body_bytes": raw.get("body_bytes", ""),
                        "parameters": raw.get("parameters", ""),
                        "locals": raw.get("locals", ""),
                        "decomp_status": raw.get("decomp_status", ""),
                        "artifact_present": str(artifact).lower(),
                        "explicit_annotation": str(annotated).lower(),
                        "review_status": status,
                        "status_reason": reason,
                    }
                )
    rows.sort(key=lambda row: (str(row["program"]).lower(), int(str(row["address"]), 16) if row["address"] else 0, str(row["index"])))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    input_hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(exports_root.glob("*.csv"), key=lambda item: item.name)
    }
    summary = {
        "exports_root": str(exports_root),
        "input_hashes": input_hashes,
        "function_count": len(rows),
        "program_counts": dict(sorted(program_counts.items())),
        "review_status_counts": dict(sorted(status_counts.items())),
        "category_counts": dict(sorted(category_counts.items())),
        "explicit_annotation_count": annotated_count,
        "artifact_missing_count": artifact_missing,
        "elf_offset": args.elf_offset,
        "status_definitions": {
            "D": "explicitly annotated/reviewed address; not source-equivalent",
            "M": "static vendor subsystem model/hotspot; runtime or full-path gaps remain",
            "R": "runtime/I/O boundary requiring live or hardware validation",
            "S": "symbol/ABI/library evidence only",
            "U": "failed decompilation or missing artifact",
        },
        "limitations": [
            "The manifest reads CSV metadata and annotation addresses, never decompiler C bodies.",
            "Status is a review classification, not a proof of complete semantics.",
            "A function can be statically decompiled and still be runtime-only for protocol, hardware, or safety behavior.",
            "The ESP raw Xtensa images are not included because no retained ESP CSV was supplied to this manifest.",
        ],
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
