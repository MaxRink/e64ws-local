#!/usr/bin/env python3
"""Render the generated sections of ``docs/FINDINGS_REPRODUCTION.md``.

The findings document mixes analysis (sections 1, 3, 4, 6 and 7) with data
(section 2's counts and the 63-row matrix in section 5).  Only the data is
generated: it is derived from ``results-fresh-swu.json`` and from the status
table in ``run.py``, so the document cannot drift away from the run it cites.

Sections are delimited by HTML comments::

    <!-- generated:summary:start -->
    ...
    <!-- generated:summary:end -->

``--check`` exits non-zero when the committed document differs from the
rendered output, which is what the offline test suite asserts.

Usage:
    python3 tools/verify_findings/render_doc.py --check
    python3 tools/verify_findings/render_doc.py --write
    python3 tools/verify_findings/render_doc.py --stdout
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNNER_PATH = HERE / "run.py"
DEFAULT_JSON = HERE / "results-fresh-swu.json"
DEFAULT_DOC = ROOT / "docs" / "FINDINGS_REPRODUCTION.md"

SUMMARY_START = "<!-- generated:summary:start -->"
SUMMARY_END = "<!-- generated:summary:end -->"
MATRIX_START = "<!-- generated:matrix:start -->"
MATRIX_END = "<!-- generated:matrix:end -->"

STATUS_ORDER = ("reproduced", "partly", "static-only", "not reproduced", "latent", "superseded")


def validate(document: dict) -> dict[str, int]:
    """Check the result file's internal consistency before rendering it.

    The renderer used to transcribe ``counts`` and trust it, so a file whose
    counts contradicted its own checks rendered a lie and passed ``--check``.
    Now the counts are recomputed and a disagreement raises.
    """
    checks = document.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError("result file has no checks")
    recomputed = {"pass": 0, "fail": 0, "skip": 0}
    seen: set[str] = set()
    for check in checks:
        identifier = check.get("id")
        if not identifier or identifier in seen:
            raise ValueError(f"duplicate or missing check id: {identifier!r}")
        seen.add(identifier)
        status = check.get("status")
        if status not in recomputed:
            raise ValueError(f"{identifier}: unknown status {status!r}")
        if not check.get("surface"):
            raise ValueError(f"{identifier}: missing surface")
        recomputed[status] += 1
    declared = document.get("counts")
    if declared != recomputed:
        raise ValueError(f"declared counts {declared} disagree with the checks {recomputed}")
    return recomputed


def load_runner():
    """Import ``run.py`` without depending on the package layout."""
    spec = importlib.util.spec_from_file_location("verify_findings_run", RUNNER_PATH)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _cell(value: object) -> str:
    """Make a value safe for a markdown table cell."""
    return " ".join(str(value).split()).replace("|", "\\|")


def matrix_counts(runner) -> tuple[int, dict[str, int]]:
    """Return the advisory row count and the MATRIX status distribution."""
    rows = runner.parse_findings()
    counts = {status: 0 for status in STATUS_ORDER}
    counts["unclassified"] = 0
    for row in rows:
        status, _ = runner.MATRIX.get(row["id"], ("unclassified", ""))
        counts[status] = counts.get(status, 0) + 1
    return len(rows), counts


def render_summary(document: dict, runner) -> str:
    checks = document["checks"]
    counts = {"pass": 0, "fail": 0, "skip": 0}
    for check in checks:
        counts[check["status"]] += 1
    total = len(checks)
    advisory_total, advisory = matrix_counts(runner)

    lines = [
        "| Measure | Count |",
        "|---|---:|",
        f"| Checks run | **{total}** |",
        f"| Pass | **{counts['pass']}** |",
        f"| Fail | **{counts['fail']}** |",
        f"| Skip | **{counts['skip']}** |",
        f"| Advisory findings in matrix | **{advisory_total}** |",
    ]
    for status in STATUS_ORDER:
        label = status.capitalize()
        lines.append(f"| {label} | **{advisory.get(status, 0)}** |")

    surfaces: dict[str, dict[str, int]] = {}
    for check in checks:
        bucket = surfaces.setdefault(check["surface"], {"total": 0, "pass": 0, "fail": 0, "skip": 0})
        bucket["total"] += 1
        bucket[check["status"]] += 1

    lines += [
        "",
        "### Checks by surface",
        "",
        "| Surface | Checks | Pass | Fail | Skip |",
        "|---|---:|---:|---:|---:|",
    ]
    for surface in sorted(surfaces, key=lambda name: (-surfaces[name]["total"], name)):
        bucket = surfaces[surface]
        lines.append(
            f"| `{surface}` | {bucket['total']} | {bucket['pass']} | "
            f"{bucket['fail']} | {bucket['skip']} |"
        )

    failed = [check for check in checks if check["status"] == "fail"]
    lines += ["", "### Failed checks", ""]
    if failed:
        lines += ["| Check | Observed |", "|---|---|"]
        for check in failed:
            lines.append(f"| `{check['id']}` | {_cell(check['evidence'])} |")
    else:
        lines.append("None. Every probe in the committed pass either confirmed its claim or was skipped for a stated reason.")

    skipped = [check for check in checks if check["status"] == "skip"]
    lines += ["", "### Skipped checks", ""]
    if skipped:
        lines += ["| Check | Reason |", "|---|---|"]
        for check in skipped:
            lines.append(f"| `{check['id']}` | {_cell(check['evidence'])} |")
    else:
        lines.append("None.")

    provenance = document.get("provenance")
    defects = document.get("known_defects") or []
    if defects:
        lines += [
            "",
            "### Known defects in this result file",
            "",
            "These strings were written by the pre-2026-11-25 harness. Each row names the "
            "check, what is wrong with the recorded string, and what the probe observed.",
            "",
            "| Check | Issue | Authoritative |",
            "|---|---|---|",
        ]
        for defect in defects:
            lines.append(
                f"| `{_cell(defect.get('check'))}` | {_cell(defect.get('issue'))} | "
                f"{_cell(defect.get('authoritative'))} |"
            )
    lines += ["", "### Run provenance", ""]
    if provenance and provenance.get("recorded"):
        git = provenance.get("git", {})
        ports = provenance.get("ports", {})
        fixture = provenance.get("fixture", {})
        port_text = ", ".join(f"{name} {value}" for name, value in ports.items())
        lines += [
            "| Item | Value |",
            "|---|---|",
            f"| Mode | `{provenance.get('mode', 'unknown')}` |",
            f"| Commit | `{git.get('commit') or 'unknown'}` on `{git.get('branch') or 'unknown'}` |",
            f"| Working tree dirty | {'yes' if git.get('dirty') else 'no'} |",
            f"| Ports | {port_text or 'none recorded'} |",
            f"| Fixture prepared by the harness | {'yes' if fixture.get('prepared') else 'no'} |",
            f"| Recorded fixture mutations | {len(fixture.get('mutations') or [])} |",
            f"| Generated at | {provenance.get('generated_at', 'unknown')} |",
        ]
        mutations = fixture.get("mutations") or []
        if mutations:
            lines += [
                "",
                "| Fixture step | Target | Before | After |",
                "|---|---|---|---|",
            ]
            for entry in mutations:
                lines.append(
                    f"| `{_cell(entry.get('command'))}` | `{_cell(entry.get('target'))}` | "
                    f"`{_cell(entry.get('before') or 'unreadable')}` | "
                    f"`{_cell(entry.get('after') or 'unreadable')}` |"
                )
    else:
        note = (provenance or {}).get("note", "this result file pre-dates the provenance block")
        lines.append(f"Not recorded: {note}.")

    return "\n".join(lines)


def render_matrix(runner) -> str:
    return runner.matrix_markdown()


def splice(text: str, start: str, end: str, body: str, label: str) -> str:
    starts, ends = text.count(start), text.count(end)
    if starts != 1 or ends != 1:
        raise ValueError(
            f"{label}: expected exactly one {start!r} and one {end!r}, "
            f"found {starts} and {ends}"
        )
    start_at = text.index(start)
    end_at = text.index(end)
    if end_at < start_at:
        raise ValueError(f"{label}: {end!r} appears before {start!r}")
    return text[:start_at] + start + "\n" + body + "\n" + end + text[end_at + len(end):]


def render(document: dict, doc_text: str, runner) -> str:
    validate(document)
    text = splice(doc_text, SUMMARY_START, SUMMARY_END, render_summary(document, runner), "summary")
    return splice(text, MATRIX_START, MATRIX_END, render_matrix(runner), "matrix")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--check", action="store_true", help="fail when the document is out of date")
    parser.add_argument("--write", action="store_true", help="rewrite the generated sections in place")
    parser.add_argument("--stdout", action="store_true", help="print the rendered sections only")
    args = parser.parse_args(argv)

    document = json.loads(args.json.read_text(encoding="utf-8"))
    runner = load_runner()
    current = args.doc.read_text(encoding="utf-8")
    rendered = render(document, current, runner)

    if args.stdout:
        print(render_summary(document, runner))
        return 0
    if args.check:
        if rendered != current:
            print(f"out of date: {args.doc}", file=sys.stderr)
            return 1
        print(f"up to date: {args.doc}")
        return 0
    if args.write:
        if rendered != current:
            args.doc.write_text(rendered, encoding="utf-8")
            print(f"updated: {args.doc}")
        else:
            print(f"unchanged: {args.doc}")
        return 0
    parser.error("choose --check, --write or --stdout")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
