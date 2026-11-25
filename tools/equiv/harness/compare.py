"""Transcript comparison and difference classification.

Comparison is strict by default: every difference is a MISMATCH unless a rule
in diffs/classification.json declares it an EXPECTED emulation artefact with a
written reason. That asymmetry is deliberate -- silently ignoring noise is how
a behavioural regression gets shipped.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any


def load_jsonl(path: str | Path) -> list[dict]:
    records = []
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("record") == "run":
            continue  # file header, not an observation
        records.append(record)
    return records


def _flatten(value: Any, prefix: str, out: list[tuple[str, Any]]) -> None:
    if isinstance(value, dict):
        if not value:
            out.append((prefix, {}))
            return
        for key, item in value.items():
            _flatten(item, f"{prefix}.{key}" if prefix else key, out)
        return
    if isinstance(value, list):
        if not value:
            out.append((prefix, []))
            return
        for index, item in enumerate(value):
            _flatten(item, f"{prefix}[]", out)
        return
    out.append((prefix, value))


def _add_shape(value: Any, prefix: str, out: dict[str, str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _add_shape(item, f"{prefix}.{key}" if prefix else key, out)
    elif isinstance(value, list):
        for item in value:
            _add_shape(item, f"{prefix}[]", out)
    else:
        if isinstance(value, bool):
            out[prefix] = "bool"
        elif isinstance(value, (int, float)):
            out[prefix] = "number"
        elif isinstance(value, str):
            out[prefix] = "string"
        elif value is None:
            out[prefix] = "null"
        else:
            out[prefix] = type(value).__name__


def _match_rule(rule: dict, scenario: str, record: dict, path: str) -> bool:
    if rule.get("scenario") and not fnmatch.fnmatch(scenario, rule["scenario"]):
        return False
    if rule.get("kind") and not fnmatch.fnmatch(record.get("kind", ""), rule["kind"]):
        return False
    if rule.get("step") and not fnmatch.fnmatch(record.get("step", ""), rule["step"]):
        return False
    pattern = rule.get("path")
    if pattern and not fnmatch.fnmatch(path, pattern):
        return False
    return True


def _classify(rules: list[dict], scenario: str, record: dict, path: str) -> dict:
    for rule in rules:
        if _match_rule(rule, scenario, record, path):
            return {"class": rule.get("class", "mismatch"),
                    "reason": rule.get("reason", ""),
                    "rule": rule.get("id", "")}
    return {"class": "mismatch", "reason": "", "rule": ""}


def _cut_after(records: list[dict], step: str) -> tuple[list[dict], int]:
    """Truncate after the last record of ``step`` (inclusive).

    Used for scenarios whose oracle dies part-way through: the steps before the
    crash are compared, the crash and everything after it are kept in the raw
    transcript as evidence but are not part of the comparison window.
    """
    last = None
    for index, record in enumerate(records):
        if record.get("step") == step:
            last = index
    if last is None:
        return records, 0
    return records[:last + 1], len(records) - last - 1


def compare(a_path: str | Path, b_path: str | Path, scenario: str,
            rules: list[dict] | None = None,
            until_step: str | None = None) -> dict:
    rules = rules or []
    a = load_jsonl(a_path)
    b = load_jsonl(b_path)
    dropped_a = dropped_b = 0
    if until_step:
        a, dropped_a = _cut_after(a, until_step)
        b, dropped_b = _cut_after(b, until_step)
    diffs: list[dict] = []

    # Compare record-by-record in sequence. Both runs must produce the same
    # sequence of records; a missing record is a structural difference.
    limit = max(len(a), len(b))
    for index in range(limit):
        ra = a[index] if index < len(a) else None
        rb = b[index] if index < len(b) else None
        if ra is None or rb is None:
            present = ra or rb
            diffs.append({
                "seq": present.get("seq"),
                "step": present.get("step"),
                "kind": present.get("kind"),
                "path": "record",
                "a": "present" if ra else "missing",
                "b": "present" if rb else "missing",
                **(_classify(rules, scenario, present, "record")),
            })
            continue
        if ra.get("kind") != rb.get("kind") or ra.get("step") != rb.get("step"):
            diffs.append({
                "seq": ra.get("seq"), "step": ra.get("step"),
                "kind": ra.get("kind"), "path": "record.identity",
                "a": {"step": ra.get("step"), "kind": ra.get("kind")},
                "b": {"step": rb.get("step"), "kind": rb.get("kind")},
                **(_classify(rules, scenario, ra, "record.identity")),
            })
            continue
        shape_a: dict[str, str] = {}
        shape_b: dict[str, str] = {}
        _add_shape(ra.get("payload"), "payload", shape_a)
        _add_shape(rb.get("payload"), "payload", shape_b)
        for path in sorted(set(shape_a) | set(shape_b)):
            ta, tb = shape_a.get(path), shape_b.get(path)
            if ta != tb:
                diffs.append({
                    "seq": ra.get("seq"), "step": ra.get("step"),
                    "kind": ra.get("kind"), "path": path,
                    "a": ta or "absent", "b": tb or "absent",
                    "class": "mismatch",
                    "reason": "JSON shape/type difference",
                    "rule": "shape",
                })
        flat_a: list[tuple[str, Any]] = []
        flat_b: list[tuple[str, Any]] = []
        _flatten(ra.get("payload"), "payload", flat_a)
        _flatten(rb.get("payload"), "payload", flat_b)
        map_a = dict(flat_a)
        map_b = dict(flat_b)
        for path in sorted(set(map_a) | set(map_b)):
            va = map_a.get(path, "__absent__")
            vb = map_b.get(path, "__absent__")
            if va == vb:
                continue
            if shape_a.get(path) != shape_b.get(path) and path in shape_a and path in shape_b:
                continue  # already reported as a shape difference
            diffs.append({
                "seq": ra.get("seq"), "step": ra.get("step"),
                "kind": ra.get("kind"), "path": path,
                "a": va, "b": vb,
                **(_classify(rules, scenario, ra, path)),
            })

    mismatch = [d for d in diffs if d["class"] != "expected"]
    expected = [d for d in diffs if d["class"] == "expected"]
    return {
        "scenario": scenario,
        "a": str(a_path),
        "b": str(b_path),
        "records_a": len(a),
        "records_b": len(b),
        "records_dropped_a": dropped_a,
        "records_dropped_b": dropped_b,
        "compared_until": until_step,
        "identical": not diffs,
        "behaviourally_identical": not mismatch,
        "mismatches": len(mismatch),
        "expected": len(expected),
        "diffs": diffs,
    }


def summarise(result: dict) -> str:
    lines = []
    status = "IDENTICAL" if result["identical"] else (
        "EQUIVALENT (expected diffs only)" if result["behaviourally_identical"]
        else "MISMATCH")
    lines.append(f"{result['scenario']}: {status} "
                 f"({result['records_a']} vs {result['records_b']} records, "
                 f"{result['mismatches']} mismatch, {result['expected']} expected)")
    if result.get("compared_until"):
        lines.append(f"  comparison window ends after {result['compared_until']!r}; "
                     f"not compared: {result.get('records_dropped_a', 0)} vendor / "
                     f"{result.get('records_dropped_b', 0)} candidate record(s)")
    for diff in result["diffs"][:40]:
        marker = "ok  " if diff["class"] == "expected" else "DIFF"
        lines.append(f"  {marker} seq={diff['seq']} {diff['step']} {diff['kind']} "
                     f"{diff['path']}: {json.dumps(diff['a'])} != {json.dumps(diff['b'])}"
                     + (f"  [{diff.get('rule')}] {diff.get('reason')}" if diff.get("rule") else ""))
    if len(result["diffs"]) > 40:
        lines.append(f"  ... {len(result['diffs']) - 40} more")
    return "\n".join(lines)
