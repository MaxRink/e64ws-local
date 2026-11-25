#!/usr/bin/env python3
"""Check, and keep the counts current in, the tracked backlog.

``todo.md`` is a claims file: every item must carry exactly one tag, a blocked
item must name what blocks it, anything claimed done or partly done must cite a
path that exists, and the count line must be the only one.  This tool enforces
those rules rather than describing them.

A rule that is advertised here but not implemented is a bug: the adversarial
review of 2026-11-25 found several, which is why the checks below are strict
about markers, fences, duplicate tags and paths outside the repository.

Usage:
    python3 tools/todo_status.py --check
    python3 tools/todo_status.py --write
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TODO = ROOT / "todo.md"
ARCHIVE = ROOT / "docs" / "archive" / "todo-2026-10-31.md"

TAGS = ("STOCK", "DEV", "HW", "CLOUD", "VENDOR", "VM", "UI", "CI", "INTEGRITY")
STATES = {" ": "open", "x": "done", "~": "vm-only", "!": "blocked"}
STATES_NEEDING_PATH = {"x", "~"}
ITEM = re.compile(r"^(\s*)[-*+] \[([ x~!])\] (.*)$")
TAG = re.compile(r"\[([A-Z]+)\]")
BLOCKED = re.compile(r"BLOCKED-(HW|CLOUD|VENDOR|ACCOUNT)")
COUNTS = re.compile(r"^<!-- counts: open=\d+ vm-only=\d+ blocked=\d+ done=\d+ -->$")
COUNTS_ANY = re.compile(r"<!-- counts:")
PATH = re.compile(r"`([^`\s]+)`")


def load(path: Path = TODO) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _fenced(lines: list[str]) -> list[bool]:
    """Mark lines that sit inside a ``` fence (they are not checklist items)."""
    inside = []
    fence = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            inside.append(True)
            fence = not fence
            continue
        inside.append(fence)
    return inside


def items(lines: list[str]) -> list[tuple[int, str, str, str]]:
    """Return ``(line number, state, tag, block)`` for every tracked item."""
    fenced = _fenced(lines)
    found: list[tuple[int, str, str, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = ITEM.match(line) if not fenced[index] else None
        if match is None:
            index += 1
            continue
        indent, state, first = match.groups()
        block = [first]
        cursor = index + 1
        while cursor < len(lines):
            following = lines[cursor]
            if not following.strip():
                break
            if ITEM.match(following) and not fenced[cursor]:
                break
            if following.startswith(" " * (len(indent) + 2)) or following.startswith("\t"):
                block.append(following.strip())
                cursor += 1
                continue
            break
        found.append((index + 1, state, first, "\n".join(block)))
        index = cursor
    return found


def counts(lines: list[str]) -> dict[str, int]:
    tally = {name: 0 for name in STATES.values()}
    for _, state, _, _ in items(lines):
        if state in STATES:
            tally[STATES[state]] += 1
    return tally


def item_tag(text: str) -> str:
    """The single tag of an item block, or an empty string when the count is wrong.

    Only names from the taxonomy count: an item is allowed to write ``[NOTE]``
    or ``[HW]`` in its prose without that being read as a second tag.  The
    whole block is scanned, so a real second tag on a continuation line is
    still caught.
    """
    tags = [name for name in TAG.findall(text) if name in TAGS]
    return tags[0] if len(tags) == 1 else ""


def cited_paths(text: str) -> list[str]:
    """Repository paths in backticks; endpoint routes and home paths are not evidence."""
    return [
        token
        for token in PATH.findall(text)
        if "/" in token and not token.startswith(("/", "~"))
    ]


def path_problem(token: str) -> str | None:
    if ".." in Path(token).parts:
        return f"cites a path outside the repository: {token}"
    if not (ROOT / token).exists():
        return f"cites a path that does not exist: {token}"
    return None


def delivery_rows(lines: list[str]) -> list[tuple[int, str]]:
    """Return every body row of section 1, which records delivered work."""
    rows = []
    started = False
    for number, line in enumerate(lines, 1):
        if line.startswith("## 1."):
            started = True
            continue
        if started and line.startswith("## "):
            break
        if not started or not line.startswith("| "):
            continue
        if line.startswith("| Delivered") or set(line.strip()) <= set("|-: "):
            continue
        rows.append((number, line))
    return rows


def problems(lines: list[str]) -> list[str]:
    out: list[str] = []
    for number, state, first, block in items(lines):
        tag = item_tag(block)
        if not tag:
            found = TAG.findall(block)
            out.append(
                f"{number}: expected exactly one tag from {TAGS}, found {found or 'none'}"
            )
            continue
        if tag not in TAGS:
            out.append(f"{number}: unknown tag [{tag}]")
        if state == "!" and not BLOCKED.search(block):
            out.append(f"{number}: blocked item without a BLOCKED- reason")
        if state in STATES_NEEDING_PATH and not cited_paths(block):
            out.append(f"{number}: {STATES[state]} item without an evidence path")
        for token in cited_paths(block):
            problem = path_problem(token)
            if problem:
                out.append(f"{number}: {problem}")

    for number, row in delivery_rows(lines):
        tokens = cited_paths(row)
        if not tokens:
            out.append(f"{number}: delivery row without an evidence path")
        for token in tokens:
            problem = path_problem(token)
            if problem:
                out.append(f"{number}: {problem}")

    markers = [number for number, line in enumerate(lines, 1) if COUNTS_ANY.search(line)]
    if len(markers) != 1:
        out.append(f"expected exactly one counts line, found {len(markers)}")
    elif not COUNTS.match(lines[markers[0] - 1]):
        out.append(f"{markers[0]}: counts line is malformed")
    return out


def marker(tally: dict[str, int]) -> str:
    return (
        f"<!-- counts: open={tally['open']} vm-only={tally['vm-only']} "
        f"blocked={tally['blocked']} done={tally['done']} -->"
    )


def rendered(lines: list[str]) -> list[str]:
    current = marker(counts(lines))
    markers = [number for number, line in enumerate(lines, 1) if COUNTS_ANY.search(line)]
    if len(markers) != 1:
        raise SystemExit(f"expected exactly one counts line, found {len(markers)}")
    lines = list(lines)
    lines[markers[0] - 1] = current
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the tracked backlog.")
    parser.add_argument("--check", action="store_true", help="report problems (default)")
    parser.add_argument("--write", action="store_true", help="update the count line")
    parser.add_argument("--path", type=Path, default=TODO)
    args = parser.parse_args(argv)

    lines = load(args.path)
    if args.write:
        found = problems(lines)
        if found:
            for problem in found:
                print(problem)
            print("refusing to write: fix the problems above")
            return 1
        args.path.write_text("\n".join(rendered(lines)) + "\n", encoding="utf-8")
        print(f"updated: {args.path}")
        return 0

    found = problems(lines)
    markers = [number for number, line in enumerate(lines, 1) if COUNTS_ANY.search(line)]
    if len(markers) == 1:
        expected = marker(counts(lines))
        if lines[markers[0] - 1] != expected:
            found.append(f"{markers[0]}: count line is stale; expected {expected}")
    if ARCHIVE.is_file():
        archived = sum(1 for line in load(ARCHIVE) if re.match(r"^\s*[-*+] \[[ x~!]\]", line))
        if archived == 0:
            found.append("the archived checklist is empty")
    else:
        found.append(f"missing archive: {ARCHIVE}")
    for problem in found:
        print(problem)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
