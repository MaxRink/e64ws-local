#!/usr/bin/env python3
"""Comparator self-test.

A differential harness that cannot detect a difference is worthless. This
copies the vendor baseline, changes exactly one scalar in one transcript, and
asserts that `compare` reports it as a mismatch at the expected path.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harness import compare  # noqa: E402


def main() -> int:
    source = ROOT / "runs" / "vendor" / "02_readonly"
    mutant_root = ROOT / "runs" / "selftest-mutant" / "02_readonly"
    if not (source / "run-1.norm.jsonl").exists():
        print("no vendor baseline to mutate; run ./run.sh baseline first")
        return 2
    mutant_root.mkdir(parents=True, exist_ok=True)
    records = [json.loads(line) for line in
               (source / "run-1.norm.jsonl").read_text().splitlines() if line.strip()]
    target = None
    for record in records:
        if record.get("kind") == "wss.rx" and record.get("step") == "r07b":
            target = record
            break
    if target is None:
        # Fall back to the first driver-state reply.
        target = next(r for r in records
                      if r.get("kind") == "wss.rx" and "json" in r.get("payload", {}))
    before = target["payload"]["json"]["data"]["grindState"]
    target["payload"]["json"]["data"]["grindState"] = "Grinding" if before != "Grinding" else "Idle"
    (mutant_root / "run-1.norm.jsonl").write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")

    result = compare.compare(source / "run-1.norm.jsonl",
                             mutant_root / "run-1.norm.jsonl",
                             "02_readonly", [])
    print(compare.summarise(result))
    detected = (not result["behaviourally_identical"]
                and any(d["path"] == "payload.json.data.grindState" for d in result["diffs"]))
    print("\nself-test:", "PASS (one-value change detected)" if detected else "FAIL")
    shutil.rmtree(ROOT / "runs" / "selftest-mutant", ignore_errors=True)
    return 0 if detected else 1


if __name__ == "__main__":
    raise SystemExit(main())
