#!/usr/bin/env python3
"""Run the repository's offline suites, security index, GBS parity and evidence checks."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


GBS_PLUGIN = Path(
    "decaid/test/fixtures/gbs/mahlkoenig-e64ws.reaplugin/plugin.js"
)


def run(label: str, command: list[str], root: Path) -> int:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True)
    output = (result.stdout or "") + (result.stderr or "")
    print(f"\n== {label} ==")
    print(output, end="")
    return result.returncode


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failures: list[str] = []
    skipped: list[str] = []

    if run("offline test suites", [sys.executable, "tools/run_tests.py"], root):
        failures.append("offline test suites failed")

    if run(
        "security index",
        [sys.executable, "tools/check_security_index.py"],
        root,
    ):
        failures.append("security index check failed")

    plugin = root / GBS_PLUGIN
    node = shutil.which("node")
    if not plugin.is_file():
        skipped.append(
            f"GBS parity: SKIP (missing {GBS_PLUGIN}; the decaid/ checkout is gitignored)"
        )
    elif not node:
        skipped.append("GBS parity: SKIP (node not found)")
    elif run(
        "GBS Python/Node parity",
        [sys.executable, "tools/test_gbs_parity.py"],
        root,
    ):
        failures.append("GBS Python/Node parity check failed")

    # The verifier's own unit tests run in the "tools" suite via run_tests.py.
    if run(
        "evidence manifests",
        [sys.executable, "tools/verify_evidence.py", "--quiet"],
        root,
    ):
        failures.append("evidence manifest verification failed")

    for item in skipped:
        print(item)
    if failures:
        print("\nHost checks: FAIL")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print("\nHost checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
