#!/usr/bin/env python3
"""Check that the security summary indexes every detailed finding exactly once."""

from __future__ import annotations

import re
from pathlib import Path


SUMMARY_ID = re.compile(r"^\|\s*SEC-(\d+)\s*\|")
DETAIL_IDS = re.compile(r"^###\s+(.+)$")
SEC_ID = re.compile(r"SEC-(\d+)")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    document = root / "docs" / "SECURITY.md"
    lines = document.read_text(encoding="utf-8").splitlines()
    summary = [int(match.group(1)) for line in lines if (match := SUMMARY_ID.match(line))]
    details = [
        int(match.group(1))
        for line in lines
        if (heading := DETAIL_IDS.match(line))
        for match in SEC_ID.finditer(heading.group(1))
    ]

    errors: list[str] = []
    if len(summary) != len(set(summary)):
        errors.append("summary contains duplicate SEC IDs")
    if len(details) != len(set(details)):
        errors.append("detail headings contain duplicate SEC IDs")
    if set(summary) != set(details):
        errors.append(
            "summary/detail mismatch: "
            f"summary-only={sorted(set(summary) - set(details))}, "
            f"detail-only={sorted(set(details) - set(summary))}"
        )
    if not summary:
        errors.append("no summary entries found")

    if errors:
        print("Security index: FAIL")
        print("\n".join(f"- {error}" for error in errors))
        return 1

    ordered = sorted(set(summary))
    print(f"Security index: PASS ({len(ordered)} findings, SEC-{ordered[0]:02d}..SEC-{ordered[-1]:02d})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
