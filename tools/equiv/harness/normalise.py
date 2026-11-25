"""Normalisation of known-irrelevant differences.

Two rules govern everything here:

1. A field is normalised only if its value is *provably* environment-dependent
   and carries no behavioural information (time, random token, PID, socket
   address). Anything else -- field presence, JSON types, enum strings, numbers
   that come from the grinder model -- is preserved, because a reconstruction
   must reproduce it.
2. Every normalisation is recorded (rule id + JSON path), so a reviewer can
   audit what the diff was allowed to ignore. `--no-normalise` produces the raw
   transcript for exactly that purpose.

Rules are declared in normalisers/rules.json so the accepted-noise budget is a
reviewable artefact rather than code.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Field names whose *values* are known-volatile. Matched at any depth.
VOLATILE_KEYS = {
    "hmiTime": "N-TIME",             # wall clock rendered by the HMI
    "sessionId": "N-UUID",           # per-database session identity
    "uptime_s": "N-DURATION",        # harness/target uptime
    "t": "N-TIME",                   # emulator frame timestamps
    "t_rel_ms": "N-DURATION",        # transcript-relative timing
    "lastUpdate": "N-TIME",
    "timestamp": "N-TIME",
    "expires": "N-EPOCH",
    "configId": "N-COUNTER",         # append-only config row id: +1 per app start
    "powerOnCycles": "N-COUNTER",    # append-only boot counter in /db/machineCounters.json
}

# Exact JSON paths (dotted) with special handling.
ARRAY_SORT_PATHS = {
    "data.logMessages": "N-ORDER",   # ring buffer drained concurrently
}

REGEX_RULES: list[tuple[str, re.Pattern, str]] = [
    ("N-TOKEN", re.compile(r"\b[0-9a-f]{64}\b"), "<TOKEN>"),
    ("N-UUID", re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
     "<UUID>"),
    ("N-DATETIME", re.compile(r"\b\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}\b"), "<DATETIME>"),
    ("N-DATETIME", re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"),
     "<DATETIME>"),
    ("N-MAC", re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b"), "<MAC>"),
    ("N-ADDR", re.compile(r"\b(?:wss?|https?)://(?:127\.0\.0\.1|localhost)(?::\d+)?"),
     "<URL>"),
    ("N-IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    ("N-PID", re.compile(r"\bpid[=: ]+\d+\b", re.IGNORECASE), "pid=<PID>"),
    ("N-PATH", re.compile(r"/tmp/tok_[0-9a-f]{64}"), "/tmp/tok_<TOKEN>"),
    ("N-LOGTS", re.compile(r"^\[\d+\.\d+\]"), "[<T>]"),
    ("N-EPOCH", re.compile(r"\b17\d{8}(?:\d{3})?\b"), "<EPOCH>"),
]


@dataclass
class Result:
    value: Any
    fired: list[str] = field(default_factory=list)


def _walk(value: Any, path: str, fired: list[str], sort_arrays: bool) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            child = f"{path}.{key}" if path else key
            if key in VOLATILE_KEYS:
                out[key] = VOLATILE_KEYS[key]
                fired.append(f"{VOLATILE_KEYS[key]}@{child}")
            else:
                out[key] = _walk(item, child, fired, sort_arrays)
        return out
    if isinstance(value, list):
        items = [_walk(item, f"{path}[]", fired, sort_arrays) for item in value]
        if sort_arrays and path in ARRAY_SORT_PATHS:
            items = sorted(items, key=lambda x: json.dumps(x, sort_keys=True))
            fired.append(f"{ARRAY_SORT_PATHS[path]}@{path}")
        return items
    if isinstance(value, str):
        return normalise_text(value, path, fired)
    return value


def normalise_text(text: str, path: str, fired: list[str]) -> str:
    out = text
    for rule, pattern, replacement in REGEX_RULES:
        if pattern.search(out):
            new = pattern.sub(replacement, out)
            if new != out:
                fired.append(f"{rule}@{path or '$'}")
                out = new
    return out


def normalise_record(record: dict, rule_set: dict | None = None) -> Result:
    fired: list[str] = []
    payload = _walk(record.get("payload"), "payload", fired, True)
    meta = _walk(record.get("meta"), "meta", fired, True)
    out = {
        "seq": record.get("seq"),
        "step": record.get("step"),
        "op": record.get("op"),
        "kind": record.get("kind"),
        "payload": payload,
        "meta": meta,
    }
    # Timing is observed separately as buckets; exact milliseconds are noise.
    timing = record.get("t_rel_ms")
    if isinstance(timing, (int, float)):
        out["t_bucket"] = bucket(timing)
        fired.append("N-DURATION@t_rel_ms")
    elif timing is not None:
        out["t_bucket"] = timing
    return Result(out, fired)


def bucket(ms: float) -> str:
    """Coarse latency bucket. Order-of-magnitude is behaviour; jitter is not."""
    for limit, label in ((50, "<50ms"), (100, "<100ms"), (250, "<250ms"),
                         (500, "<500ms"), (1000, "<1s"), (2000, "<2s"),
                         (5000, "<5s"), (15000, "<15s")):
        if ms < limit:
            return label
    return ">=15s"


def shape(value: Any) -> Any:
    """Structure-only projection: types instead of scalar values."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [shape(v) for v in value]
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if value is None:
        return "null"
    return type(value).__name__


def load_rules(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def write_normalised(raw_path: Path, out_path: Path, rules: dict | None = None) -> dict:
    """Normalise a JSONL transcript. Returns per-rule fire counts."""
    counts: dict[str, int] = {}
    lines = []
    for line in raw_path.read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("record") == "run":
            continue  # transcript header, not an observation
        result = normalise_record(record, rules)
        for item in result.fired:
            rule = item.split("@", 1)[0]
            counts[rule] = counts.get(rule, 0) + 1
        lines.append(json.dumps(result.value, sort_keys=True))
    out_path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return counts
