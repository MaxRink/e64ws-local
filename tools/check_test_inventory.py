#!/usr/bin/env python3
"""Prove the test inventory in ``docs/TEST_INVENTORY.md`` instead of asserting it.

What this tool does
-------------------
``docs/TEST_INVENTORY.md`` records, per suite, the number of tests a runner
actually reported.  This tool re-runs the cheap suites, parses each runner's own
summary line, and compares **every suite count against the number recorded in
that document**.  No count is a constant in this file: the counts come from the
runners and the expectations come from the document, so the only way to change
the gate is to regenerate the document (``--write``) and show that diff.

Gated suites -- every one must run, and none may report fewer tests than recorded:

  main-runner          ``sh tools/run_tests.sh``            this checkout
  bridge-unittest      ``python3 -m unittest discover -s tests``
  plugin-npm-test      ``npm test``                         (needs node_modules)
  dialin-npm-test      ``npm test``                         (needs node_modules)

A missing checkout or a missing ``node_modules`` is **UNPROVEN** (exit 2), never
a quiet skip: a clean clone that never ran ``npm ci`` has not shown anything.

Relationship to ``tools/run_tests.py``
-------------------------------------
``tools/run_tests.py`` is authoritative for this repository and this tool does
not compete with it:

  * its ``SUITES`` tuple carries a per-suite ``minimum`` and fails when a suite
    collects zero tests, fewer than its minimum, or errors;
  * its implicit floor for this repository is the sum of those minimums, which
    this tool reads out of the module itself (``--offline`` prints it) instead
    of repeating a number that drifts;
  * if ``run_tests.py`` fails, this tool cannot pass: a non-zero exit from a
    suite is reported as UNPROVEN (exit 2), whatever the counts look like.

What this tool adds that ``run_tests.py`` does not do:

  * the three sibling checkouts (scale bridge, both plugins), which no gate in
    this repository covers at all;
  * measured counts recorded per suite and per runner sub-suite, so deleting
    tests that stays above a ``minimum`` is still a failure;
  * the runner's own per-suite rows cross-checked against the document *and*
    against ``run_tests.py``'s ``SUITES`` names, in both directions, so a new or
    renamed sub-suite cannot be absorbed silently into the ``main-runner`` total;
  * a check that the document's arithmetic agrees with itself;
  * a check that no gated number is repeated in the document's prose: the block
    is the only place a recorded count may appear, because a second copy is a
    copy that drifts.  Every aggregate is watched, and so is every per-suite
    count or minimum written with two digits or more; a one-digit per-suite
    count is left to review, because ``3`` and ``5`` are ordinary words in prose;
  * ``--self-test``: fixture tests for the three output parsers and for the
    document guards.  ``tools/run_tests.py``'s coverage manifest refuses to
    start when it meets a ``tools/test_*.py`` it does not know, so this file is
    deliberately *not* named ``test_*.py`` and the runner can never exercise it.
    The self-test and the CI step are therefore mandatory, not optional: without
    them nothing would notice if this file stopped working.

Where the two gates disagree, ``run_tests.py`` wins for this repository.  The
counts recorded in the document may never be lower than its minimums --
``--offline`` enforces that inequality without running anything.

Modes
-----
  (default)        run every gated suite, compare with the document, print the
                   table.  Missing checkouts are UNPROVEN, not skipped.
  --local          run only the suites that live in this checkout (``main-runner``).
                   This is the mode CI uses: the sibling checkouts are absent there.
  --offline        run nothing.  Read the counts back out of the document and
                   prove it is internally consistent: the same keys as ``SUITES``,
                   the same sub-suites as ``tools/run_tests.py``, the totals equal
                   the sums of their rows, and no recorded count below a
                   ``run_tests.py`` minimum.  It cannot prove the numbers are
                   still true (that needs a run); it does prove that no gated row
                   can be edited on its own.
  --self-test      exercise the parsers and the document guards on fixtures.
  --strict-rise    also fail when a suite reports MORE tests than the document
                   records.  Without it a rise is only a ``note:``, and a stale
                   baseline can mask a later deletion inside the same suite: five
                   recorded, six ran with one of them deleted, still PASSes.  CI
                   runs this mode, so the recorded counts must be exact rather
                   than a floor.
  --write          regenerate the generated block of ``docs/TEST_INVENTORY.md``
                   from a live run.  Refuses to write a partial measurement, and
                   validates the document it is about to write instead of
                   refusing to repair one that is already stale.
  --json PATH      also write the full result as JSON to PATH.

Exit status
-----------
  0  every selected suite ran, nothing dropped, every cross-check passed
  1  a suite ran but reported fewer tests than the document records, or more
     than it records under ``--strict-rise``
  2  unproven: a checkout or ``node_modules`` is missing, a command exited
     non-zero, an output could not be parsed, or the document does not agree
     with the code (keys, sub-suites, arithmetic)

Standard library only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIBLINGS = ROOT.parent
INVENTORY = ROOT / "docs" / "TEST_INVENTORY.md"
RUNNER = ROOT / "tools" / "run_tests.py"

GENERATED_BEGIN = (
    "<!-- BEGIN GENERATED: tools/check_test_inventory.py --write owns this block -->"
)
GENERATED_END = "<!-- END GENERATED -->"

DEFAULT_TIMEOUT = 1800
TAIL_LINES = 20

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


@dataclass(frozen=True)
class Suite:
    """One suite this tool knows how to run and parse."""

    key: str                 # id used in docs/TEST_INVENTORY.md
    repo: str                # directory name of the checkout, for siblings
    name: str
    command: tuple[str, ...]
    parser: str              # "run_tests_sh" | "unittest" | "node_test"
    needs_node_modules: bool = False
    timeout: int = DEFAULT_TIMEOUT
    # The checkout this file lives in is located by its own path, never by a
    # directory name: a clone of this repository may be called anything.
    is_self: bool = False

    @property
    def cwd(self) -> Path:
        return ROOT if self.is_self else SIBLINGS / self.repo

    @property
    def repo_name(self) -> str:
        """The directory name actually in use, measured rather than assumed."""
        return ROOT.name if self.is_self else self.repo

    def display_command(self) -> str:
        # The interpreter's absolute path is a property of the host, not of the
        # suite; the document records the command a reader can type.
        return " ".join(
            "python3" if part == sys.executable else part for part in self.command
        )


SUITES: tuple[Suite, ...] = (
    Suite(
        key="main-runner",
        repo="mahlkoenig-e64ws-local-research",
        name="offline Python suites (tools/run_tests.sh)",
        command=("sh", "tools/run_tests.sh"),
        parser="run_tests_sh",
        is_self=True,
    ),
    Suite(
        key="bridge-unittest",
        repo="e64ws-scale-bridge",
        name="unittest discover -s tests",
        command=(sys.executable, "-m", "unittest", "discover", "-s", "tests"),
        parser="unittest",
    ),
    Suite(
        key="plugin-npm-test",
        repo="decaid-e64ws-plugin",
        name="npm test",
        command=("npm", "test"),
        parser="node_test",
        needs_node_modules=True,
    ),
    Suite(
        key="dialin-npm-test",
        repo="decaid-assisted-dialin-plugin",
        name="npm test",
        command=("npm", "test"),
        parser="node_test",
        needs_node_modules=True,
    ),
)


# --- parsers ---------------------------------------------------------------
# Each returns what the runner itself printed, or raises ValueError with the
# reason.  None of them may fall back to a constant, and none may report a count
# it did not read.


@dataclass(frozen=True)
class Parsed:
    """What a runner's output said: a total, and any per-suite rows."""

    total: int
    suites: dict[str, int] = field(default_factory=dict)
    not_pass: tuple[str, ...] = ()


def _clean(text: str) -> str:
    return ANSI_RE.sub("", text)


RUNNER_SUITE_RE = re.compile(
    r"^== (?P<name>.+?) ==[ \t]*\n"
    r"[ \t]+(?P<status>PASS|FAIL|ERROR|EMPTY): ran (?P<ran>\d+),",
    re.MULTILINE,
)
RUNNER_TOTAL_RE = re.compile(r"^total[ \t]+(?P<ran>\d+)[ \t]", re.MULTILINE)


def parse_run_tests_sh(output: str) -> Parsed:
    """Parse the summary printed by ``tools/run_tests.py``.

    Per-suite rows come from the ``== suite ==`` / ``PASS: ran N, ...`` pairs.
    The ``total`` row is parsed separately and must agree with the sum of the
    per-suite rows: a truncated or rewritten table cannot pass silently, and a
    suite that reports anything other than PASS is surfaced through
    ``not_pass`` so a red run is never counted as green.
    """
    text = _clean(output)

    suites: dict[str, int] = {}
    not_pass: list[str] = []
    for match in RUNNER_SUITE_RE.finditer(text):
        name = match.group("name").strip()
        if name in suites:
            raise ValueError(f"runner printed suite {name!r} twice")
        suites[name] = int(match.group("ran"))
        if match.group("status") != "PASS":
            not_pass.append(name)

    total_match = None
    for total_match in RUNNER_TOTAL_RE.finditer(text):
        pass
    total = int(total_match.group("ran")) if total_match else None

    if total is None and not suites:
        raise ValueError(
            "no 'total' row and no per-suite '== suite ==' / 'PASS: ran N' pair "
            "in the runner output"
        )
    if total is None:
        return Parsed(total=sum(suites.values()), suites=suites,
                      not_pass=tuple(not_pass))
    if suites and sum(suites.values()) != total:
        raise ValueError(
            f"runner total {total} disagrees with the per-suite sum "
            f"{sum(suites.values())}"
        )
    return Parsed(total=total, suites=suites, not_pass=tuple(not_pass))


UNITTEST_RE = re.compile(r"^Ran (?P<ran>\d+) tests? in ", re.MULTILINE)


def parse_unittest(output: str) -> Parsed:
    text = _clean(output)
    matches = list(UNITTEST_RE.finditer(text))
    if not matches:
        raise ValueError("no 'Ran N tests' summary line in the unittest output")
    return Parsed(total=int(matches[-1].group("ran")))


NODE_TEST_RE = re.compile(r"^[ \t]*(?:ℹ|#)[ \t]*tests[ \t]+(?P<ran>\d+)[ \t]*$", re.MULTILINE)


def parse_node_test(output: str) -> Parsed:
    """Parse ``node --test``'s summary (``ℹ tests 78``, older: ``# tests 62``)."""
    text = _clean(output)
    matches = list(NODE_TEST_RE.finditer(text))
    if not matches:
        raise ValueError("no node test-runner summary ('tests N') in the output")
    return Parsed(total=int(matches[-1].group("ran")))


PARSERS = {
    "run_tests_sh": parse_run_tests_sh,
    "unittest": parse_unittest,
    "node_test": parse_node_test,
}


# --- running ---------------------------------------------------------------


@dataclass
class Outcome:
    suite: Suite
    status: str = "ERROR"     # RAN | ERROR | MISSING | NOT-SELECTED
    count: int | None = None
    detail: str = ""
    returncode: int | None = None
    parsed: Parsed | None = None
    recorded: int | None = None
    output: str = field(default="", repr=False)

    @property
    def counted(self) -> bool:
        return self.status == "RAN" and self.count is not None

    @property
    def verdict(self) -> str:
        if self.status == "MISSING":
            return "UNPROVEN"
        if self.status == "ERROR":
            return "UNPROVEN"
        if self.status == "NOT-SELECTED":
            return "not selected"
        if self.recorded is None:
            return "no recorded count"
        if self.count is None:
            return "UNPROVEN"
        if self.count < self.recorded:
            return f"DROP -{self.recorded - self.count}"
        if self.count > self.recorded:
            return f"rise +{self.count - self.recorded}"
        return "ok"


def _blocked_reason(suite: Suite) -> str | None:
    if not suite.cwd.is_dir():
        return f"missing checkout {suite.cwd}"
    if suite.needs_node_modules and not (suite.cwd / "node_modules").is_dir():
        return "node_modules absent; run npm ci first"
    return None


def run_suite(suite: Suite) -> Outcome:
    """Run one suite.  Never reports RAN unless the command succeeded."""
    outcome = Outcome(suite=suite)

    blocked = _blocked_reason(suite)
    if blocked is not None:
        outcome.status = "MISSING"
        outcome.detail = blocked
        return outcome

    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            list(suite.command),
            cwd=suite.cwd,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=suite.timeout,
            check=False,
        )
    except FileNotFoundError as error:
        outcome.status = "ERROR"
        outcome.detail = f"could not start {suite.command[0]}: {error.strerror}"
        return outcome
    except subprocess.TimeoutExpired:
        outcome.status = "ERROR"
        outcome.detail = f"timed out after {suite.timeout}s"
        return outcome

    outcome.output = completed.stdout or ""
    outcome.returncode = completed.returncode

    try:
        parsed = PARSERS[suite.parser](outcome.output)
    except ValueError as error:
        outcome.status = "ERROR"
        outcome.detail = f"{error} (command exited {completed.returncode})"
        return outcome

    if completed.returncode != 0:
        # A failing run is not a measurement of passing tests.  Say so instead
        # of counting its numbers: 783 tests where 460 of them failed is not
        # "783 tests".
        outcome.status = "ERROR"
        outcome.count = parsed.total
        outcome.parsed = parsed
        outcome.detail = (
            f"command exited {completed.returncode}; counts are not evidence"
        )
        return outcome

    if parsed.not_pass:
        outcome.status = "ERROR"
        outcome.count = parsed.total
        outcome.parsed = parsed
        outcome.detail = "runner reported non-PASS suites: " + ", ".join(parsed.not_pass)
        return outcome

    outcome.parsed = parsed
    outcome.count = parsed.total
    outcome.status = "RAN"
    outcome.detail = "ok"
    return outcome


# --- the runner's own configuration ----------------------------------------


@dataclass(frozen=True)
class RunnerSuite:
    """One entry of ``tools/run_tests.py``'s ``SUITES`` tuple."""

    name: str
    kind: str                 # "unittest" | "function" | "command"
    minimum: int | None       # command suites carry no minimum


@dataclass(frozen=True)
class RunnerConfig:
    suites: tuple[RunnerSuite, ...]

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(suite.name for suite in self.suites)

    @property
    def minimum_total(self) -> int:
        """``run_tests.py``'s implicit floor for this repository."""
        return sum(suite.minimum or 0 for suite in self.suites)


def load_runner(path: Path = RUNNER) -> RunnerConfig:
    """Read ``tools/run_tests.py``'s suite table instead of copying it.

    A renamed or added suite in the runner changes what the document has to
    record, so the document is cross-checked against this every run.
    """
    if not path.is_file():
        raise FileNotFoundError(f"{path} does not exist; cannot cross-check the document")
    spec = importlib.util.spec_from_file_location("_inventory_run_tests", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:  # noqa: BLE001 - surfaced, never swallowed
        raise ValueError(f"cannot import {path}: {error}") from error

    entries = getattr(module, "SUITES", None)
    if not entries:
        raise ValueError(f"{path} defines no SUITES tuple")

    suites: list[RunnerSuite] = []
    for entry in entries:
        kind = type(entry).__name__.replace("Suite", "").lower()
        suites.append(
            RunnerSuite(
                name=str(entry.name),
                kind=kind,
                minimum=getattr(entry, "minimum", None),
            )
        )
    if not suites:
        raise ValueError(f"{path} defines an empty SUITES tuple")
    return RunnerConfig(suites=tuple(suites))


# --- the recorded document -------------------------------------------------

GATED_HEADER = ("key", "repo", "command", "tests")
RUNNER_HEADER = ("suite", "kind", "ran", "minimum")
TOTAL_KEY = "total"


@dataclass(frozen=True)
class Document:
    gated: dict[str, int]                 # suite key -> recorded tests
    gated_total: int | None               # the generated "total" row
    runner: dict[str, int]                # run_tests.py suite name -> recorded ran
    runner_minimums: dict[str, int | None]  # suite name -> recorded minimum
    runner_total: int | None
    runner_minimum_total: int | None


def _markdown_tables(text: str) -> list[tuple[tuple[str, ...], list[tuple[str, ...]]]]:
    """Every markdown table in ``text`` as ``(header, rows)`` of raw cells."""
    tables: list[tuple[tuple[str, ...], list[tuple[str, ...]]]] = []
    header: tuple[str, ...] | None = None
    rows: list[tuple[str, ...]] = []

    def flush() -> None:
        nonlocal header, rows
        if header is not None:
            tables.append((header, rows))
        header, rows = None, []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            flush()
            continue
        cells = tuple(cell.strip().strip("`").strip() for cell in stripped.strip("|").split("|"))
        if all(set(cell) <= set("-: ") for cell in cells if cell):
            continue  # the |---|---| separator
        if header is None:
            header = cells
            rows = []
            continue
        rows.append(cells)
    flush()
    return tables


def _digits(cell: str) -> int | None:
    return int(cell) if re.fullmatch(r"\d+", cell) else None


def read_document(path: Path = INVENTORY) -> Document:
    """Read the generated block.  Raises ValueError when it is not usable."""
    if not path.is_file():
        raise ValueError(f"{path} does not exist; run --write to generate it")
    text = path.read_text(encoding="utf-8")
    if GENERATED_BEGIN not in text or GENERATED_END not in text:
        raise ValueError(f"{path} has no generated block; run --write to generate it")
    inner = text.split(GENERATED_BEGIN, 1)[1].split(GENERATED_END, 1)[0]

    gated: dict[str, int] = {}
    gated_total: int | None = None
    runner: dict[str, int] = {}
    runner_minimums: dict[str, int] = {}
    runner_total: int | None = None
    runner_minimum_total: int | None = None

    seen_gated = seen_runner = False
    for header, rows in _markdown_tables(inner):
        if header == GATED_HEADER:
            seen_gated = True
            for cells in rows:
                key = cells[0]
                count = _digits(cells[3])
                if not key or count is None:
                    raise ValueError(f"unusable row in the gated table: {' | '.join(cells)}")
                if key == TOTAL_KEY:
                    gated_total = count
                elif key in gated:
                    raise ValueError(f"suite {key!r} recorded twice in the gated table")
                else:
                    gated[key] = count
        elif header == RUNNER_HEADER:
            seen_runner = True
            for cells in rows:
                name = cells[0]
                kind = cells[1]
                ran = _digits(cells[2])
                minimum_cell = cells[3]
                minimum = _digits(minimum_cell)
                if not name or ran is None:
                    raise ValueError(f"unusable row in the runner table: {' | '.join(cells)}")
                if name == TOTAL_KEY:
                    runner_total = ran
                    runner_minimum_total = minimum
                    continue
                if name in runner:
                    raise ValueError(f"runner suite {name!r} recorded twice")
                # Command suites carry no minimum in run_tests.py: they fail on a
                # non-zero exit instead.  Anything else must record a number.
                if minimum is None and kind != "command":
                    raise ValueError(
                        f"runner suite {name!r} ({kind}) has no numeric minimum"
                    )
                runner[name] = ran
                runner_minimums[name] = minimum

    if not seen_gated:
        raise ValueError(f"{path}: no table with the header {' | '.join(GATED_HEADER)}")
    if not seen_runner:
        raise ValueError(f"{path}: no table with the header {' | '.join(RUNNER_HEADER)}")
    return Document(
        gated=gated,
        gated_total=gated_total,
        runner=runner,
        runner_minimums=runner_minimums,
        runner_total=runner_total,
        runner_minimum_total=runner_minimum_total,
    )


def check_gated_keys(document: Document, suites: tuple[Suite, ...]) -> list[str]:
    """The document and ``SUITES`` must name exactly the same suites."""
    problems: list[str] = []
    documented = set(document.gated)
    iterated = {suite.key for suite in suites}
    for key in sorted(iterated - documented):
        problems.append(
            f"{key}: SUITES runs it but docs/TEST_INVENTORY.md records no count for it"
        )
    for key in sorted(documented - iterated):
        problems.append(
            f"{key}: docs/TEST_INVENTORY.md marks it as gated but SUITES does not run it"
        )
    return problems


def check_runner_rows(document: Document, config: RunnerConfig) -> list[str]:
    """The document's runner sub-table must match ``run_tests.py``'s SUITES."""
    problems: list[str] = []
    documented = set(document.runner)
    declared = set(config.names)
    for name in sorted(declared - documented):
        problems.append(
            f"{name}: declared in tools/run_tests.py SUITES but not recorded as a "
            "row in docs/TEST_INVENTORY.md (it would be absorbed into main-runner)"
        )
    for name in sorted(documented - declared):
        problems.append(
            f"{name}: recorded in docs/TEST_INVENTORY.md but tools/run_tests.py has "
            "no such suite"
        )
    for suite in config.suites:
        if suite.name in document.runner_minimums:
            recorded_minimum = document.runner_minimums[suite.name]
            if recorded_minimum != suite.minimum:
                problems.append(
                    f"{suite.name}: the document records minimum "
                    f"{recorded_minimum if recorded_minimum is not None else 'none'}, "
                    f"tools/run_tests.py says "
                    f"{suite.minimum if suite.minimum is not None else 'none'}; "
                    "regenerate with --write"
                )
    measured_minimum_total = config.minimum_total
    if document.runner_minimum_total is not None and document.runner_minimum_total != measured_minimum_total:
        problems.append(
            f"the recorded minimum total {document.runner_minimum_total} does not equal "
            f"the sum of tools/run_tests.py's minimums {measured_minimum_total}"
        )
    return problems


def compare_runner_rows(
    document: Document, parsed: Parsed
) -> tuple[list[str], list[str]]:
    """Compare the runner's measured sub-suites with the recorded ones.

    Returns ``(drops, problems)``.  A row that moved down is a drop even when the
    total did not move (one suite gaining what another lost is still a deletion);
    a row the document does not know about, or a recorded row the runner did not
    report, means the two disagree about what the runner is.
    """
    drops: list[str] = []
    problems: list[str] = []
    for name, measured in parsed.suites.items():
        recorded = document.runner.get(name)
        if recorded is None:
            problems.append(
                f"{name}: the runner reported a suite the document does not record"
            )
        elif measured < recorded:
            drops.append(
                f"{name}: {measured} tests, {recorded} recorded "
                f"(-{recorded - measured})"
            )
    for name in document.runner:
        if name not in parsed.suites:
            problems.append(
                f"{name}: recorded in the document but missing from the runner's output"
            )
    return drops, problems


def check_document_arithmetic(document: Document) -> list[str]:
    """Every total in the document must equal the rows it summarises."""
    problems: list[str] = []

    recorded_sum = sum(document.gated.values())
    if document.gated_total is None:
        problems.append("the gated table has no 'total' row")
    elif document.gated_total != recorded_sum:
        problems.append(
            f"the gated 'total' row says {document.gated_total} but its rows sum to "
            f"{recorded_sum}"
        )

    runner_sum = sum(document.runner.values())
    if document.runner_total is None:
        problems.append("the runner table has no 'total' row")
    elif document.runner_total != runner_sum:
        problems.append(
            f"the runner 'total' row says {document.runner_total} but its rows sum "
            f"to {runner_sum}"
        )

    main_runner = document.gated.get("main-runner")
    if main_runner is not None and document.runner_total is not None:
        if main_runner != document.runner_total:
            problems.append(
                f"the main-runner row says {main_runner} but the runner sub-suite "
                f"rows sum to {document.runner_total}: one of them is stale"
            )

    for name, ran in document.runner.items():
        minimum = document.runner_minimums.get(name)
        if minimum is not None and ran < minimum:
            problems.append(
                f"{name}: recorded {ran} tests, below tools/run_tests.py's minimum "
                f"{minimum}; the document cannot promise less than the runner does"
            )
    return problems


# A per-suite count written with fewer digits than this is not scanned for: a
# bare ``3`` or ``5`` is a word as much as a number, and section 6's ungated
# tables use single digits legitimately, so scanning those would make the check
# noise.  The aggregates are watched at any width.
PROSE_MIN_DIGITS = 2

# ``docs/OBJECTIVE_STATUS.md:25`` is a citation, not a count: this document quotes
# figures and cites a file and line for each, so a line number has to be scrubbed
# before the scan or a citation whose line happens to equal a gated count
# (``apps/ios/README.md:339`` against a ``tools`` row of 339) reads as a copy of
# one and blocks ``--write`` for no reason.
CITATION_RE = re.compile(r"[\w./~-]+\.(?:md|py|yml|yaml|json|sh|toml|cfg|txt):\d+")


def _watched_numbers(document: Document) -> dict[int, list[str]]:
    """Every recorded number that prose must not repeat, and what it belongs to."""
    watched: dict[int, list[str]] = {}

    def add(value: int | None, label: str, *, any_width: bool) -> None:
        if value is None:
            return
        if not any_width and len(str(abs(value))) < PROSE_MIN_DIGITS:
            return
        labels = watched.setdefault(value, [])
        if label not in labels:
            labels.append(label)

    for key, value in document.gated.items():
        add(value, f"the {key} count", any_width=True)
    add(document.gated_total, "the gated total", any_width=True)
    add(document.runner_total, "the runner total", any_width=True)
    add(document.runner_minimum_total, "the runner floor", any_width=True)
    for name, value in document.runner.items():
        add(value, f"the {name} count", any_width=False)
    for name, value in document.runner_minimums.items():
        if document.runner.get(name) != value:
            add(value, f"the {name} minimum", any_width=False)
    return watched


def check_no_gated_numbers_in_prose(text: str, document: Document) -> list[str]:
    """No gated number may be repeated outside the generated block.

    The block is the only place a recorded count is allowed to appear: a second
    copy in prose is a copy that drifts, and this file's predecessor drifted
    exactly that way -- one total headlined in three sections, a floor repeated
    in a fourth, disagreeing with each other and with the runner.

    What is watched is every aggregate -- each gated suite's count, the gated
    total, the runner total and the runner minimum total (the floor) -- plus the
    runner's own table, where every per-suite count and minimum written with
    ``PROSE_MIN_DIGITS`` digits or more is watched.  A one-digit per-suite count
    is not, and that is the one case this scan leaves to review: the prose needs
    ``3`` and ``5`` as ordinary numbers, and a check that cries wolf every time
    is a check that gets deleted.  An ISO date or timestamp and a ``file:line``
    citation are scrubbed before the scan, so neither ``2026-11-25`` nor
    ``README.md:339`` can be mistaken for a count.
    """
    watched = _watched_numbers(document)
    if not watched:
        return []

    problems: list[str] = []
    inside = False
    for number, line in enumerate(text.splitlines(), start=1):
        if GENERATED_BEGIN in line:
            inside = True
            continue
        if GENERATED_END in line:
            inside = False
            continue
        if inside:
            continue
        scrubbed = re.sub(r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z?)?", " ", line)
        scrubbed = CITATION_RE.sub(" ", scrubbed)
        for token in re.findall(r"\b\d+\b", scrubbed):
            value = int(token)
            if value in watched:
                problems.append(
                    f"line {number}: {value} repeats {', '.join(watched[value])} "
                    "outside the generated block; point at section 1 instead of "
                    "copying the number"
                )
    return problems


def all_problems(
    document: Document,
    suites: tuple[Suite, ...],
    config: RunnerConfig,
    text: str | None = None,
) -> list[str]:
    """Every structural problem: the document against the code, and its prose."""
    if text is None:
        try:
            text = INVENTORY.read_text(encoding="utf-8")
        except OSError:
            text = ""
    problems = structural_problems(document, suites, config)
    problems.extend(check_no_gated_numbers_in_prose(text, document))
    return problems


def structural_problems(
    document: Document, suites: tuple[Suite, ...], config: RunnerConfig
) -> list[str]:
    problems: list[str] = []
    problems.extend(check_gated_keys(document, suites))
    problems.extend(check_runner_rows(document, config))
    problems.extend(check_document_arithmetic(document))
    return problems


# --- writing the document --------------------------------------------------


def render_block(
    document: Document,
    measured: dict[str, int],
    when: datetime,
    config: RunnerConfig,
) -> str:
    """Render the generated block from a completed measurement."""
    lines: list[str] = [GENERATED_BEGIN, ""]
    lines.append(provenance_stamp(when, _git_head(), _git_dirty()))
    lines.append("")
    lines.append(
        "These recorded counts are the gate's baseline: the next run fails when any "
        "suite reports fewer tests than recorded here, or cannot run at all."
    )
    lines.append("")
    total = sum(measured.values())
    lines.append("| key | repo | command | tests |")
    lines.append("| --- | --- | --- | --- |")
    for suite in SUITES:
        if suite.key not in measured:
            continue
        # The checkout's directory name is whatever the clone is called; the
        # document names the repository, not the local path.
        repo_cell = "this checkout" if suite.is_self else suite.repo_name
        lines.append(
            f"| {suite.key} | {repo_cell} | `{suite.display_command()}` | "
            f"{measured[suite.key]} |"
        )
    lines.append(f"| total |  |  | {total} |")
    lines.append("")
    lines.append(
        "`tools/run_tests.py`'s own suites, which make up the `main-runner` row above. "
        "Its per-suite minimums sum to "
        f"{config.minimum_total}; its own totals include the command suites, which "
        "have no minimum because they fail on a non-zero exit instead:"
    )
    lines.append("")
    lines.append("| suite | kind | ran | minimum |")
    lines.append("| --- | --- | --- | --- |")
    for suite in config.suites:
        if suite.name not in document.runner:
            continue
        minimum = "-" if suite.minimum is None else str(suite.minimum)
        lines.append(
            f"| {suite.name} | {suite.kind} | {document.runner[suite.name]} | {minimum} |"
        )
    lines.append(
        f"| total |  | {sum(document.runner.values())} | {config.minimum_total} |"
    )
    lines.append("")
    command_runs = sum(
        document.runner.get(suite.name, 0) for suite in config.suites if suite.kind == "command"
    )
    lines.append(
        f"Command invocations inside the `main-runner` row: {command_runs} of "
        f"{sum(document.runner.values())}. They are counted (and gated) like every "
        "other row -- see §3 -- so a lost command suite cannot hide."
    )
    lines.append("")
    lines.append(GENERATED_END)
    return "\n".join(lines)


def _git(*args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    return (completed.stdout or "").strip()


def _git_head() -> str:
    return _git("rev-parse", "--short", "HEAD") or "unknown"


def _git_dirty() -> bool:
    """Whether the working tree carries changes ``--write`` would be measuring."""
    return bool(_git("status", "--porcelain", "--untracked-files=no"))


def provenance_stamp(when: datetime, head: str, dirty: bool) -> str:
    """One sentence naming the tree the counts were measured on.

    ``--write`` measures a working tree *before* the commit that carries the
    block exists, so a bare ``git rev-parse HEAD`` names the parent of that
    commit.  Printed unqualified it reads as "these counts describe ``2383374``"
    when the block actually landed in its child -- which is the defect this
    function exists to remove.  A dirty tree is therefore reported as that commit
    *plus the uncommitted changes*; only a clean tree is reported as the commit
    itself, because only then is the commit the tree that was measured.
    """
    stamp = (
        "Measured by `python3 tools/check_test_inventory.py --write` on "
        f"{when.strftime('%Y-%m-%dT%H:%M:%SZ')} (UTC), from this checkout at "
        f"`git rev-parse --short HEAD` = `{head}`"
    )
    if dirty:
        return stamp + (
            ", together with the uncommitted changes in the working tree. That "
            "commit is the **parent** of the commit that carries this block: "
            "`--write` runs before that commit exists, so the name above is the "
            "base the measurement started from, not the commit that records it."
        )
    return stamp + (
        " with a clean working tree, so the counts below describe exactly that "
        "commit's tree."
    )


def write_document(path: Path, block: str) -> None:
    text = path.read_text(encoding="utf-8")
    if GENERATED_BEGIN not in text or GENERATED_END not in text:
        raise ValueError(f"{path} has no generated block; add the markers first")
    head = text.split(GENERATED_BEGIN, 1)[0]
    tail = text.split(GENERATED_END, 1)[1]
    path.write_text(head + block + tail, encoding="utf-8")


# --- reporting -------------------------------------------------------------


def _print_table(outcomes: list[Outcome]) -> None:
    print()
    width = max(len(o.suite.repo_name) for o in outcomes)
    name_width = max(len(o.suite.name) for o in outcomes)
    print(
        f"{'repo':<{width}}  {'suite':<{name_width}}  {'status':<12} "
        f"{'tests':>6} {'recorded':>8}  verdict"
    )
    print("-" * (width + name_width + 44))
    for outcome in outcomes:
        count = "" if outcome.count is None else str(outcome.count)
        recorded = "" if outcome.recorded is None else str(outcome.recorded)
        print(
            f"{outcome.suite.repo_name:<{width}}  {outcome.suite.name:<{name_width}}  "
            f"{outcome.status:<12} {count:>6} {recorded:>8}  {outcome.verdict}"
            + (f"  ({outcome.detail})" if outcome.detail and outcome.status != "RAN" else "")
        )
    print("-" * (width + name_width + 44))


def _write_json(
    path: Path,
    outcomes: list[Outcome],
    document: Document | None,
    problems: list[str],
    mode: str,
) -> None:
    measured_total = sum(o.count for o in outcomes if o.counted)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": mode,
        "source": "docs/TEST_INVENTORY.md (recorded)" if mode == "offline"
        else "parsed runner output (measured)",
        "document": None if document is None else {
            "gated": document.gated,
            "gated_total": document.gated_total,
            "runner": document.runner,
            "runner_minimums": document.runner_minimums,
            "runner_total": document.runner_total,
            "runner_minimum_total": document.runner_minimum_total,
        },
        "measured_total": measured_total,
        "problems": problems,
        "suites": [
            {
                "key": outcome.suite.key,
                "repo": outcome.suite.repo_name,
                "suite": outcome.suite.name,
                "command": outcome.suite.display_command(),
                "status": outcome.status,
                "count": outcome.count,
                "recorded": outcome.recorded,
                "verdict": outcome.verdict,
                "returncode": outcome.returncode,
                "detail": outcome.detail,
            }
            for outcome in outcomes
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")


# --- self-test -------------------------------------------------------------
# The three parsers and the document guards are the only clever parts of this
# file, and tools/run_tests.py's manifest cannot reach this file, so their
# fixtures live here and are run from CI.

RUNNER_FIXTURE = """\
Python 3.13.0 at /usr/bin/python3
Repository root: /tmp/checkout

== tests ==
  PASS: ran 63, passed 63, failed 0, errors 0, skipped 0

== tools ==
  PASS: ran 270, passed 270, failed 0, errors 0, skipped 0

== boot-script ==
  PASS: ran 2, passed 2, failed 0, errors 0, skipped 0

suite              status    ran  pass  fail error  skip
--------------------------------------------------------------
tests              PASS        63    63     0     0     0
tools              PASS       270   270     0     0     0
boot-script        PASS         2     2     0     0     0
--------------------------------------------------------------
total                          335   335     0     0     0

Result: PASS
"""

GATED_FIXTURE = """\
| key | repo | command | tests |
| --- | --- | --- | --- |
| main-runner | checkout | `sh tools/run_tests.sh` | 335 |
| bridge-unittest | bridge | `python3 -m unittest discover -s tests` | 90 |
| total |  |  | 425 |
"""

RUNNER_TABLE_FIXTURE = """\
| suite | kind | ran | minimum |
| --- | --- | --- | --- |
| tests | unittest | 63 | 63 |
| tools | unittest | 270 | 270 |
| boot-script | command | 2 | - |
| total |  | 335 | 333 |
"""


def _fixture_document(gated: str = GATED_FIXTURE, runner: str = RUNNER_TABLE_FIXTURE) -> Document:
    tables = _markdown_tables(gated + "\n" + runner)

    def pick(header: tuple[str, ...]) -> list[tuple[str, ...]]:
        for candidate, rows in tables:
            if candidate == header:
                return rows
        raise AssertionError(f"missing table {header}")

    gated_rows = pick(GATED_HEADER)
    runner_rows = pick(RUNNER_HEADER)
    gated_map: dict[str, int] = {}
    gated_total = None
    for cells in gated_rows:
        if cells[0] == TOTAL_KEY:
            gated_total = int(cells[3])
        else:
            gated_map[cells[0]] = int(cells[3])
    runner_map: dict[str, int] = {}
    minimums: dict[str, int | None] = {}
    runner_total = None
    minimum_total = None
    for cells in runner_rows:
        if cells[0] == TOTAL_KEY:
            runner_total = int(cells[2])
            minimum_total = int(cells[3])
        else:
            runner_map[cells[0]] = int(cells[2])
            minimums[cells[0]] = _digits(cells[3])
    return Document(
        gated=gated_map,
        gated_total=gated_total,
        runner=runner_map,
        runner_minimums=minimums,
        runner_total=runner_total,
        runner_minimum_total=minimum_total,
    )


def self_test() -> int:
    """Exercise the parsers and the guards.  Returns a process exit status."""
    failures: list[str] = []
    checks = 0

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(f"{name}{': ' + detail if detail else ''}")

    def parses(name: str, function, text: str, expected: int) -> None:
        """A parser must return this count; a crash is a failed check, not a traceback."""
        nonlocal checks
        checks += 1
        try:
            got = function(text).total
        except Exception as error:  # noqa: BLE001 - a crash is a self-test failure
            failures.append(f"{name}: raised {error}")
            return
        if got != expected:
            failures.append(f"{name}: parsed {got}, expected {expected}")

    def raises(name: str, function, *args) -> None:
        nonlocal checks
        checks += 1
        try:
            function(*args)
        except ValueError:
            return
        failures.append(f"{name}: expected ValueError, got none")

    # parse_run_tests_sh
    parsed = parse_run_tests_sh(RUNNER_FIXTURE)
    check("run_tests_sh total", parsed.total == 335, str(parsed.total))
    check("run_tests_sh suites", parsed.suites.get("tools") == 270, str(parsed.suites))
    check("run_tests_sh not_pass", parsed.not_pass == (), str(parsed.not_pass))
    check(
        "run_tests_sh per-suite sum",
        sum(parsed.suites.values()) == parsed.total,
        f"{sum(parsed.suites.values())} != {parsed.total}",
    )
    truncated = RUNNER_FIXTURE.split("suite              status")[0]
    check("run_tests_sh truncated table", parse_run_tests_sh(truncated).total == 335)
    raises(
        "run_tests_sh total disagrees",
        parse_run_tests_sh,
        RUNNER_FIXTURE.replace("total                          335", "total                          340"),
    )
    raises(
        "run_tests_sh no numbers",
        parse_run_tests_sh,
        "Coverage manifest problems:\n  - tools/test_x.py: not covered by a suite\n",
    )
    red = RUNNER_FIXTURE.replace("== tools ==\n  PASS:", "== tools ==\n  FAIL:")
    check("run_tests_sh red suite recorded", parse_run_tests_sh(red).not_pass == ("tools",))

    # parse_unittest
    parses("unittest", parse_unittest,
           "\n----\nRan 90 tests in 19.098s\n\nOK (skipped=1)\n", 90)
    parses("unittest ansi", parse_unittest, "\x1b[32mRan 78 tests in 1.2s\x1b[0m", 78)
    parses("unittest singular", parse_unittest, "Ran 1 test in 0.001s", 1)
    raises("unittest no summary", parse_unittest, "no summary here\n")

    # parse_node_test
    parses("node flat", parse_node_test, "ℹ tests 78\nℹ pass 78\nℹ fail 0\n", 78)
    parses("node hash", parse_node_test, "# tests 62\n# pass 62\n", 62)
    parses("node last summary wins", parse_node_test, "# tests 10\nℹ tests 12\n", 12)
    # The leading [ \t]* in NODE_TEST_RE is load-bearing, not cosmetic: node
    # indents the summary line of a nested suite, and this parser takes the LAST
    # match, so an indented subtest summary is a real candidate for the total.
    # These three fixtures are the ones that fail when the token is dropped -- an
    # unindented fixture named "indented" is how the token went unmeasured.
    parses("node indented summary", parse_node_test,
           "▶ outer\n  ℹ tests 78\n  ℹ pass 78\n", 78)
    parses("node tab-indented summary", parse_node_test, "\tℹ tests 5\n", 5)
    parses("node indented last summary wins", parse_node_test,
           "ℹ tests 40\n    ℹ tests 12\n", 12)
    raises("node no summary", parse_node_test, "✔ something (1ms)\n")
    raises("node wrong word", parse_node_test, "ℹ suites 78\n")

    # the document guards
    document = _fixture_document()
    check("document gated", document.gated.get("main-runner") == 335, str(document.gated))
    check("document total", document.gated_total == 425, str(document.gated_total))
    check("document runner", document.runner.get("tools") == 270, str(document.runner))
    check("document problems", check_document_arithmetic(document) == [],
          str(check_document_arithmetic(document)))
    check(
        "document ignores a gated row it cannot run",
        check_gated_keys(document, (SUITES[0],)) != [],
    )
    check(
        "document records a suite SUITES does not run",
        any("bridge-unittest" in p for p in check_gated_keys(document, (SUITES[0],))),
    )
    tampered = _fixture_document(
        gated=GATED_FIXTURE.replace("| 335 |", "| 325 |").replace("| 425 |", "| 415 |")
    )
    check(
        "document catches a gated row edited on its own",
        check_document_arithmetic(tampered) != [],
        str(check_document_arithmetic(tampered)),
    )
    lower = Document(
        gated=dict(document.gated),
        gated_total=document.gated_total,
        runner=dict(document.runner, tools=10),
        runner_minimums=dict(document.runner_minimums),
        runner_total=document.runner_total,
        runner_minimum_total=document.runner_minimum_total,
    )
    check(
        "document catches a runner row below the runner minimum",
        any("below" in problem for problem in check_document_arithmetic(lower)),
        str(check_document_arithmetic(lower)),
    )
    config = RunnerConfig(
        suites=(
            RunnerSuite("tests", "unittest", 63),
            RunnerSuite("tools", "unittest", 270),
            RunnerSuite("boot-script", "command", None),
        )
    )
    check("runner rows agree", check_runner_rows(document, config) == [],
          str(check_runner_rows(document, config)))
    missing_row = RunnerConfig(
        suites=config.suites + (RunnerSuite("new-suite", "unittest", 1),)
    )
    check(
        "a new runner suite cannot be absorbed silently",
        any("new-suite" in problem for problem in check_runner_rows(document, missing_row)),
        str(check_runner_rows(document, missing_row)),
    )
    parsed = Parsed(
        total=335,
        suites={"tests": 64, "tools": 269, "boot-script": 2},
    )
    row_drops, row_problems = compare_runner_rows(document, parsed)
    check(
        "a net-zero movement is still a drop",
        len(row_drops) == 1 and row_problems == [],
        f"{row_drops} {row_problems}",
    )
    absent_row = Parsed(total=333, suites={"tests": 63, "tools": 270})
    row_drops, row_problems = compare_runner_rows(document, absent_row)
    check(
        "a runner row missing from the output is a problem",
        any("boot-script" in problem for problem in row_problems),
        str(row_problems),
    )
    renamed = RunnerConfig(suites=(RunnerSuite("tests", "unittest", 63),))
    check(
        "a renamed runner suite is reported in both directions",
        len(check_runner_rows(document, renamed)) >= 2,
        str(check_runner_rows(document, renamed)),
    )

    # the prose guard: a gated number outside the block is a copy that drifts
    def prose(extra: str) -> str:
        return (
            f"{GENERATED_BEGIN}\n"
            "| key | repo | command | tests |\n"
            "| --- | --- | --- | --- |\n"
            "| main-runner | checkout | `sh tools/run_tests.sh` | 335 |\n"
            f"{GENERATED_END}\n" + extra
        )

    def prose_problems(extra: str) -> list[str]:
        return check_no_gated_numbers_in_prose(prose(extra), document)

    check("prose guard allows the block itself", prose_problems("plain prose\n") == [],
          str(prose_problems("plain prose\n")))
    check("prose guard catches the runner floor",
          any("runner floor" in p for p in prose_problems("that sum is 333\n")),
          str(prose_problems("that sum is 333\n")))
    check("prose guard catches a suite count",
          any("bridge-unittest" in p for p in prose_problems("it reported 90\n")),
          str(prose_problems("it reported 90\n")))
    check("prose guard catches the gated total",
          any("gated total" in p for p in prose_problems("a total of 425\n")),
          str(prose_problems("a total of 425\n")))
    # A per-suite row is a gated number too: planting one in prose is the copy
    # this check exists to stop, and only watching aggregates left it open.
    check("prose guard catches a per-suite count",
          any("the tools count" in p for p in prose_problems("the row said 270\n")),
          str(prose_problems("the row said 270\n")))
    check("prose guard ignores a file:line citation",
          prose_problems("see `apps/ios/README.md:270`\n") == [],
          str(prose_problems("see `apps/ios/README.md:270`\n")))
    check("prose guard leaves a one-digit per-suite count alone",
          prose_problems("there are 2 of them\n") == [],
          str(prose_problems("there are 2 of them\n")))
    check("prose guard ignores a number it does not gate",
          prose_problems("the old headline was 827\n") == [],
          str(prose_problems("the old headline was 827\n")))
    check("prose guard ignores an ISO timestamp",
          prose_problems("measured 2026-11-25T22:43:57Z\n") == [],
          str(prose_problems("measured 2026-11-25T22:43:57Z\n")))

    # the provenance stamp: name the tree measured, not the commit it lands in
    when = datetime(2026, 11, 25, 22, 43, 57, tzinfo=timezone.utc)
    dirty_stamp = provenance_stamp(when, "2383374", dirty=True)
    check("stamp names the base commit", "`2383374`" in dirty_stamp, dirty_stamp)
    check("stamp says parent when the tree is dirty",
          "parent" in dirty_stamp, dirty_stamp)
    check("stamp does not claim a clean tree when dirty",
          "clean working tree" not in dirty_stamp, dirty_stamp)
    check("stamp carries a UTC timestamp",
          "2026-11-25T22:43:57Z" in dirty_stamp, dirty_stamp)
    clean_stamp = provenance_stamp(when, "7400893", dirty=False)
    check("stamp says clean when the tree is clean",
          "clean working tree" in clean_stamp, clean_stamp)
    check("stamp does not say parent when clean",
          "parent" not in clean_stamp, clean_stamp)

    # run_suite: the exit-status rule and the missing-checkout rule
    ok_suite = Suite(
        key="self-test-ok",
        repo="unused",
        name="synthetic passing suite",
        command=(sys.executable, "-c",
                 "print('Ran 5 tests in 0.1s'); print('OK')"),
        parser="unittest",
        is_self=True,
    )
    outcome = run_suite(ok_suite)
    check("run_suite counts a green run", outcome.status == "RAN" and outcome.count == 5,
          f"{outcome.status} {outcome.count}")
    failing = Suite(
        key="self-test-red",
        repo="unused",
        name="synthetic failing suite",
        command=(sys.executable, "-c",
                 "print('Ran 5 tests in 0.1s'); print('FAILED (failures=1)'); raise SystemExit(1)"),
        parser="unittest",
        is_self=True,
    )
    outcome = run_suite(failing)
    check(
        "run_suite refuses to count a non-zero exit",
        outcome.status == "ERROR" and not outcome.counted,
        f"{outcome.status} {outcome.counted} {outcome.detail}",
    )
    absent = Suite(
        key="self-test-absent",
        repo="no-such-checkout-anywhere",
        name="synthetic absent suite",
        command=(sys.executable, "-c", "print('never')"),
        parser="unittest",
    )
    outcome = run_suite(absent)
    check("run_suite reports a missing checkout as unproven",
          outcome.status == "MISSING" and not outcome.counted,
          f"{outcome.status} {outcome.detail}")
    no_modules = Suite(
        key="self-test-npm",
        repo=".",
        name="synthetic suite without node_modules",
        command=(sys.executable, "-c", "print('never')"),
        parser="node_test",
        needs_node_modules=True,
    )
    outcome = run_suite(no_modules)
    check("run_suite reports absent node_modules as unproven",
          outcome.status == "MISSING" and not outcome.counted,
          f"{outcome.status} {outcome.detail}")

    for failure in failures:
        print(f"self-test FAIL: {failure}", file=sys.stderr)
    print(f"self-test: {checks} checks, {len(failures)} failed")
    return 0 if not failures else 1


# --- main ------------------------------------------------------------------


def _select(suites: tuple[Suite, ...], local_only: bool) -> tuple[Suite, ...]:
    return tuple(suite for suite in suites if suite.is_self) if local_only else suites


def _run_outcomes(suites: tuple[Suite, ...], document: Document) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for suite in suites:
        print(f"$ (cd {suite.cwd} && {suite.display_command()})", flush=True)
        outcome = run_suite(suite)
        outcome.recorded = document.gated.get(suite.key)
        print(
            f"  -> {outcome.status} "
            f"{outcome.count if outcome.count is not None else ''}"
            f"{(' (' + outcome.detail + ')') if outcome.detail else ''}",
            flush=True,
        )
        # A failure the tool cannot explain is a failure nobody debugs: show the
        # end of the runner's own output for anything that was not counted.
        if outcome.status != "RAN" and outcome.output:
            for line in outcome.output.rstrip().splitlines()[-TAIL_LINES:]:
                print(f"  | {line}", flush=True)
        outcomes.append(outcome)
    return outcomes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Re-run the gated test suites and compare them with "
                    "docs/TEST_INVENTORY.md.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--json", metavar="PATH", type=Path,
                        help="also write the full result as JSON to PATH")
    parser.add_argument("--offline", action="store_true",
                        help="run nothing; check the document against itself and "
                             "against tools/run_tests.py")
    parser.add_argument("--local", action="store_true",
                        help="run only the suites in this checkout (CI mode)")
    parser.add_argument("--write", action="store_true",
                        help="regenerate the generated block of "
                             "docs/TEST_INVENTORY.md from this run")
    parser.add_argument("--self-test", action="store_true",
                        help="test the parsers and the document guards on fixtures")
    parser.add_argument("--strict-rise", action="store_true",
                        help="also fail when a suite reports MORE tests than "
                             "recorded, so a stale baseline cannot mask a later "
                             "deletion inside the same suite (CI runs this)")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.write and (args.offline or args.local):
        print("--write needs a full run: it refuses to record a partial measurement",
              file=sys.stderr)
        return 2
    if args.write and args.strict_rise:
        print("--write and --strict-rise contradict each other: --write records a "
              "rise, --strict-rise fails on one", file=sys.stderr)
        return 2
    if args.offline and args.strict_rise:
        print("--strict-rise needs a run: --offline measures nothing, so nothing "
              "can rise", file=sys.stderr)
        return 2

    print(f"repository: {ROOT}")
    try:
        config = load_runner()
    except (OSError, ValueError) as error:
        print(f"cannot read tools/run_tests.py: {error}", file=sys.stderr)
        return 2

    try:
        document = read_document()
    except ValueError as error:
        if not args.write:
            print(f"cannot read docs/TEST_INVENTORY.md: {error}", file=sys.stderr)
            return 2
        # Bootstrap: --write is how the generated block comes into existence.
        print(f"note: {error}; --write will create the generated block",
              file=sys.stderr)
        document = Document(
            gated={},
            gated_total=None,
            runner={},
            runner_minimums={},
            runner_total=None,
            runner_minimum_total=None,
        )

    suites = _select(SUITES, args.local)
    # --write replaces section 1, so a section 1 that disagrees with the code is
    # exactly what it is for: it must not refuse to repair the state it exists to
    # repair.  (The previous revision evaluated this before the run, so on a
    # freshly merged tree --write exited 2 telling the reader to run --write.)
    # The document it is about to write is validated after the measurement
    # instead, so a genuine inconsistency still fails -- on the new document
    # rather than on the stale one.  Every other mode compares against section 1
    # and needs it to agree before it runs anything.
    problems: list[str] = []
    if not args.write:
        problems = all_problems(document, SUITES, config)
    print(f"gated suites: {len(suites)} ({'local' if args.local else 'all'})")
    print(f"tools/run_tests.py floor for this repository: {config.minimum_total} "
          f"(sum of its per-suite minimums)")
    print()

    if args.offline:
        print("source: docs/TEST_INVENTORY.md (offline, no commands run)")
        outcomes = []
        for suite in suites:
            outcome = Outcome(suite=suite, status="RECORDED")
            outcome.count = document.gated.get(suite.key)
            outcome.recorded = outcome.count
            outcome.detail = "recorded"
            outcomes.append(outcome)
        _print_table(outcomes)
        measured_total = sum(o.count for o in outcomes if o.count is not None)
        print()
        print(f"recorded total: {measured_total}")
        if problems:
            for problem in problems:
                print(f"problem: {problem}", file=sys.stderr)
            print("Result: UNPROVEN (the document does not agree with the code)",
                  file=sys.stderr)
            if args.json is not None:
                _write_json(args.json, outcomes, document, problems, "offline")
            return 2
        print(
            "offline: the document is internally consistent and agrees with "
            "tools/run_tests.py; it is not a measurement of the suites."
        )
        if args.json is not None:
            _write_json(args.json, outcomes, document, problems, "offline")
        return 0

    for problem in problems:
        print(f"problem: {problem}", file=sys.stderr)
    if problems:
        print()
        print("Result: UNPROVEN (fix the document or the code first; "
              "the gate cannot compare against a baseline that disagrees with itself)",
              file=sys.stderr)
        if args.json is not None:
            _write_json(args.json, [], document, problems,
                        "local" if args.local else "run")
        return 2

    outcomes = _run_outcomes(suites, document)
    _print_table(outcomes)

    dropped = [o for o in outcomes if o.counted and o.recorded is not None
               and o.count < o.recorded]
    runner_drops: list[str] = []
    for outcome in outcomes:
        if outcome.parsed is not None and outcome.parsed.suites:
            row_drops, row_problems = compare_runner_rows(document, outcome.parsed)
            runner_drops.extend(row_drops)
            problems.extend(row_problems)
    unproven = [o for o in outcomes if o.status in {"ERROR", "MISSING"}]
    rose = [o for o in outcomes if o.counted and o.recorded is not None
            and o.count > o.recorded]
    measured_total = sum(o.count for o in outcomes if o.counted)
    recorded_total = sum(o.recorded or 0 for o in outcomes)

    print()
    for outcome in unproven:
        print(f"unproven: {outcome.suite.repo_name} {outcome.suite.name} - {outcome.detail}",
              file=sys.stderr)
    for outcome in dropped:
        print(
            f"dropped:  {outcome.suite.repo_name} {outcome.suite.name} - "
            f"{outcome.count} tests, {outcome.recorded} recorded "
            f"(-{outcome.recorded - outcome.count})",
            file=sys.stderr,
        )
    for outcome in rose:
        print(
            f"note:     {outcome.suite.repo_name} {outcome.suite.name} - "
            f"{outcome.count} tests, {outcome.recorded} recorded; the document "
            "under-reports: run --write to record the new counts",
            file=sys.stderr,
        )
    for drop in runner_drops:
        print(f"dropped:  {drop} (tools/run_tests.py sub-suite)", file=sys.stderr)
    for problem in problems:
        print(f"problem:  {problem}", file=sys.stderr)
    print(f"measured total: {measured_total}   recorded total: {recorded_total}")

    exit_code = 0
    if unproven or problems:
        print("Result: UNPROVEN (a suite could not run, failed, or could not be parsed, "
              "or the document and the runner disagree about what the runner is)",
              file=sys.stderr)
        exit_code = 2
    elif dropped or runner_drops:
        print("Result: FAIL (a suite reports fewer tests than the document records)",
              file=sys.stderr)
        exit_code = 1
    elif args.strict_rise and rose:
        print("Result: FAIL (a suite reports more tests than the document records, "
              "and --strict-rise makes a stale baseline a failure instead of a "
              "note: run --write to record the new counts)", file=sys.stderr)
        exit_code = 1
    elif any(o.recorded is None for o in outcomes if o.status == "RAN") and not args.write:
        print("Result: UNPROVEN (a suite has no recorded count to compare against)",
              file=sys.stderr)
        exit_code = 2
    else:
        print(f"Result: PASS ({measured_total} tests across {len(outcomes)} suites, "
              "none below its recorded count)")

    if args.json is not None:
        _write_json(args.json, outcomes, document, problems,
                    "local" if args.local else "run")

    if args.write:
        # --write is how the baseline moves, so a drop does not fail it: the
        # measured numbers are about to replace the recorded ones and the diff
        # is what review sees.  An incomplete measurement is still refused.
        if not all(o.counted for o in outcomes):
            print("refusing to write: this run is not a complete measurement",
                  file=sys.stderr)
            return 2
        for outcome in dropped:
            print(
                f"recording a drop: {outcome.suite.repo_name} "
                f"{outcome.suite.name} {outcome.recorded} -> {outcome.count}",
                file=sys.stderr,
            )
        measured = {o.suite.key: int(o.count) for o in outcomes if o.count is not None}
        document = _document_from_run(document, outcomes, config)
        # The state section 1 is *in* is not a reason to refuse -- that is the
        # deadlock this branch fixes.  The state it is about to be written *into*
        # is: everything --offline would check on the new document is checked
        # here, before anything touches the disk.  --write edits only the block,
        # never the prose, so the prose it validates is the prose that stays.
        new_problems = all_problems(document, SUITES, config)
        if new_problems:
            for problem in new_problems:
                print(f"problem: {problem}", file=sys.stderr)
            print("refusing to write: this measurement does not describe a "
                  "document this tool would accept", file=sys.stderr)
            return 2
        block = render_block(document, measured, datetime.now(timezone.utc), config)
        write_document(INVENTORY, block)
        print(f"wrote {INVENTORY}")
        return 0
    return exit_code


def _document_from_run(
    document: Document, outcomes: list[Outcome], config: RunnerConfig
) -> Document:
    """The document as it should read after this run."""
    gated = dict(document.gated)
    for outcome in outcomes:
        if outcome.count is not None:
            gated[outcome.suite.key] = outcome.count
    runner = dict(document.runner)
    for outcome in outcomes:
        if outcome.parsed is not None and outcome.parsed.suites:
            runner = dict(outcome.parsed.suites)
    return Document(
        gated=gated,
        gated_total=sum(gated.values()),
        runner=runner,
        runner_minimums={suite.name: suite.minimum for suite in config.suites},
        runner_total=sum(runner.values()),
        runner_minimum_total=config.minimum_total,
    )


if __name__ == "__main__":
    sys.exit(main())
