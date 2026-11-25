#!/usr/bin/env python3
"""Print a summary of a grind_capture JSONL trace."""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from e64ctl.weight_trace import load_capture_trace, trace_summary  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: capture_trace.py CAPTURE.jsonl")
    trace = load_capture_trace(sys.argv[1])
    json.dump(trace_summary(trace), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
