#!/usr/bin/env python3
"""Render REPORT.md markers from the contract and the recorded runs."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harness.contract import contract_table, load_contract  # noqa: E402
from harness.coverage import coverage as coverage_mod, load_scenarios, render as render_coverage  # noqa: E402


def baseline_results() -> str:
    root = ROOT / "runs" / "vendor"
    aggregate = {}
    agg_path = root / "determinism.json"
    if agg_path.exists():
        for detail in json.loads(agg_path.read_text()).get("details", []):
            aggregate[detail["scenario"]] = detail
    rows = []
    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        det = directory / "determinism.json"
        meta = directory / "run-1.meta.json"
        if not meta.exists():
            continue
        info = json.loads(meta.read_text())
        scenario = json.loads((ROOT / "scenarios" / f"{directory.name}.json").read_text())
        if det.exists():
            result = aggregate.get(directory.name) or json.loads(det.read_text())
            status = "**PASS**" if result["identical"] else "**FAIL**"
            records = (result.get("comparisons") or [{}])[0].get("records_a", info["records"])
            detail = f"{records} records"
        elif scenario.get("deterministic", True) is False:
            status = "excluded"
            detail = f"{info['records']} records (declared non-deterministic)"
        else:
            status = "not run"
            detail = "-"
        rows.append((directory.name, scenario.get("profile", "shipped"),
                     status, detail, info["elapsed_ms"]))
    lines = ["| Scenario | Profile | Two identical runs | Records | Run time |",
             "|---|---|---|---:|---:|"]
    for name, profile, status, detail, ms in rows:
        lines.append(f"| `{name}` | {profile} | {status} | {detail} | {ms/1000:.1f}s |")
    return "\n".join(lines)


def final_result() -> str:
    root = ROOT / "runs" / "vendor"
    total = passed = 0
    failures = []
    for det in sorted(root.glob("*/determinism.json")):
        total += 1
        if json.loads(det.read_text())["identical"]:
            passed += 1
        else:
            failures.append(det.parent.name)
    status = "PASS" if passed == total else "FAIL"
    lines = [
        f"**Baseline determinism: {status} — {passed}/{total} deterministic scenarios "
        f"produced identical normalised transcripts on two consecutive runs.**",
        "",
    ]
    if failures:
        lines.append("Failing scenarios: " + ", ".join(f"`{f}`" for f in failures))
    else:
        lines.append("No scenario produced a difference between run 1 and run 2 after "
                     "normalisation. Scenario 08 (`08_hw_paths`) is excluded by design.")
    return "\n".join(lines)


def main() -> None:
    template = ROOT / "REPORT.template.md"
    report = (template if template.exists() else ROOT / "REPORT.md").read_text()
    contract = load_contract(ROOT / "contract" / "hmi_contract.json")
    table = contract_table(contract)
    report = report.replace("<!-- CONTRACT TABLE -->", table)
    cov = coverage_mod(contract, load_scenarios(ROOT / "scenarios"))
    report = report.replace("<!-- COVERAGE -->", render_coverage(cov))
    (ROOT / "coverage.json").write_text(json.dumps(cov, indent=2))
    report = report.replace("<!-- BASELINE RESULTS -->", baseline_results())
    report = report.replace("<!-- FINAL RESULT -->", final_result())
    (ROOT / "REPORT.md").write_text(report)
    print("rendered REPORT.md")


if __name__ == "__main__":
    main()
