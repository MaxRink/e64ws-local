#!/usr/bin/env python3
"""Keep ``docs/HACKS.md`` honest: parse it, then check it against the code.

The document is prose, but the parts that can rot are mechanical: the route
names, the numeric bounds and the evidence labels.  This module parses those
out of the markdown and compares them with the authoritative tables in
``tools/e64local_actions.py``.  It is a document check, not a device tool: it
opens no socket, writes no file and cannot actuate anything.

Contract, as documented in ``docs/HACKS.md`` §1.3 and §4.2.

A **hack section** is a level-2 heading shaped ``## H<n> · <title>``.  Each one
must carry these machine-parsed field bullets::

    - **Verdict:** <text starting with one of VERDICT_CLASSES>
    - **Route:** `action_...`, ... | none
    - **Command:** <prose>
    - **Bounds:** none | `name`=min..max[; ...]
    - **Observable effect:** <prose>
    - **Reversibility:** <prose>
    - **Risk:** **<bold text>**

plus exactly one claims table whose last column header is ``Label``.  A claim
row's label cell starts with exactly one of ``documented``, ``inferred`` or
``needs hardware`` and then carries at least one ``path:line`` evidence
reference.

Checks:

(a) routes — every ``action_*`` token in the whole document must be in
    ``ACTION_CATALOG`` or ``ACTION_META_ROUTES`` (wildcard forms such as
    ``action_esp_*`` are skipped, because they name an absent namespace rather
    than a route).  A ``Route`` field must decompose into ``none`` or known
    routes.  If every route a section names is catalogued ``unavailable``, the
    verdict may not claim the hack is reachable.
(b) bounds — every ``name=min..max`` in a ``Bounds`` field must exist in
    ``ABSOLUTE_BOUNDS`` and match it *exactly*.  A wider bound fails; a narrower
    one fails too, because a document that quietly tightens a bound is claiming
    a limit the code does not enforce.
(c) labels — a section without a claims table fails; a claim with zero or two
    labels fails; a claim without an evidence reference fails; and a section
    must use all three labels, so no hack rests on one kind of evidence.
(d) evidence — every ``path:line`` / ``path:line-line`` must resolve inside this
    repository and stay within the file's line count.
(e) safety — the document must still say ``owner authorization``,
    ``recovery path``, ``bench run`` and ``jammed burr at speed``.
(f) shape — every field above must be present exactly once, the risk line must
    be bold, and the number of hack sections may not fall below
    ``SECTION_FLOOR``.

``ABSOLUTE_BOUNDS`` is imported and read only.  Nothing here may widen a bound,
and a change to this file that relaxes a check is a change to the contract, not
a test fix.

Usage::

    python3 tools/test_hacks_doc.py          # lint; prints problems, exit 1 on failure
    python3 -m unittest tools.test_hacks_doc # the same checks as a suite
"""

from __future__ import annotations

import re
import sys
import unittest
from decimal import Decimal, InvalidOperation
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "HACKS.md"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.e64local_actions import (  # noqa: E402  (path set above)
    ABSOLUTE_BOUNDS,
    ACTION_CATALOG,
    ACTION_META_ROUTES,
)

#: The three evidence labels, in the order the document introduces them.
LABELS: tuple[str, ...] = ("documented", "inferred", "needs hardware")

#: Allowed verdict classes.  A verdict must *start* with one of them.
VERDICT_CLASSES: tuple[str, ...] = (
    "not possible",
    "possible on stock firmware",
    "only with dev mode",
    "only with root",
)

#: Required machine-parsed field bullets, in the order they normally appear.
REQUIRED_FIELDS: tuple[str, ...] = (
    "Verdict",
    "Route",
    "Command",
    "Bounds",
    "Observable effect",
    "Reversibility",
    "Risk",
)

#: The safety banner keywords.  Losing one of these is a regression.
SAFETY_KEYWORDS: tuple[str, ...] = (
    "owner authorization",
    "recovery path",
    "bench run",
    "jammed burr at speed",
)

#: A floor, so deleting a hack section cannot look like a passing run.
SECTION_FLOOR = 7

SECTION_RE = re.compile(r"^##\s+(?P<name>H\d+)\s*·\s*(?P<title>.+?)\s*$", re.MULTILINE)
FIELD_RE = re.compile(r"^-\s+\*\*(?P<name>[^*]+?)\*\*\s*:?\s*(?P<value>.*)$", re.MULTILINE)
ROUTE_TOKEN_RE = re.compile(r"(?<![\w-])action_[a-z0-9_]+")
BOUND_RE = re.compile(
    r"`(?P<name>[A-Za-z][A-Za-z0-9]*)`\s*=\s*(?P<min>-?\d+(?:\.\d+)?)\s*\.\.\s*(?P<max>-?\d+(?:\.\d+)?)"
)
EVIDENCE_RE = re.compile(
    r"(?P<path>[A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:md|py|php)):(?P<start>\d+)(?:-(?P<end>\d+))?"
)
#: A line reference with no path in front of it, e.g. ", `:918-936`".  Every
#: reference must carry its path, otherwise it escapes check (d) entirely.
BARE_REF_RE = re.compile(r"(?<![A-Za-z0-9_.\-/]):\d+(?:-\d+)?")
LABEL_PREFIX_RE = re.compile(
    r"^(?P<label>needs hardware|documented|inferred)\b(?P<rest>.*)$", re.IGNORECASE | re.DOTALL
)


class Section:
    """One ``## H<n> · <title>`` block of the document."""

    def __init__(self, name: str, title: str, body: str) -> None:
        self.name = name
        self.title = title
        self.body = body

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Section {self.name} {self.title!r}>"


def sections(text: str) -> list[Section]:
    """Split the document into hack sections, in order.

    A section ends at the next level-2 heading of *any* shape, not just the next
    hack heading, so the prose after the last hack cannot leak into it.
    """
    heading_starts = [match.start() for match in re.finditer(r"^## ", text, re.MULTILINE)]
    result: list[Section] = []
    for match in SECTION_RE.finditer(text):
        end = next((start for start in heading_starts if start > match.start()), len(text))
        result.append(Section(match.group("name"), match.group("title"), text[match.end():end]))
    return result


def fields(body: str) -> tuple[dict[str, str], list[str]]:
    """Extract the field bullets, joining their wrapped continuation lines.

    A field's value may wrap over several indented lines, which is normal
    markdown for a list item.  A blank line, a new bullet, a table row or a
    heading ends the value.
    """
    values: dict[str, str] = {}
    problems: list[str] = []
    current: str | None = None
    parts: list[str] = []

    def flush() -> None:
        nonlocal current, parts
        if current is None:
            return
        values[current] = " ".join(parts).strip()
        current, parts = None, []

    for line in body.splitlines():
        match = FIELD_RE.match(line)
        if match is not None:
            flush()
            name = match.group("name").strip().rstrip(":").strip()
            if name not in REQUIRED_FIELDS:
                continue
            if name in values:
                problems.append(f"field {name!r} appears more than once")
                continue
            current = name
            parts = [match.group("value").strip()]
            continue
        if current is None:
            continue
        if not line.strip() or line[:1] in ("-", "|", "#"):
            flush()
            continue
        parts.append(line.strip())
    flush()
    return values, problems


def claims(body: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Return ``(id, claim, label_cell)`` rows of the single claims table.

    A table is identified by its header's last cell being ``Label``.  A second
    such table in one section is an error, because the reader cannot tell which
    one is authoritative.
    """
    rows: list[tuple[str, str, str]] = []
    problems: list[str] = []
    tables = 0
    lines = body.splitlines()
    index = 0
    while index < len(lines):
        if not lines[index].lstrip().startswith("|"):
            index += 1
            continue
        block: list[str] = []
        while index < len(lines) and lines[index].lstrip().startswith("|"):
            block.append(lines[index])
            index += 1
        header = _cells(block[0])
        if not header or header[-1].lower() != "label":
            continue
        tables += 1
        if len(block) < 2:
            problems.append("claims table has a header but no separator/rows")
            continue
        for raw in block[2:]:
            cells = _cells(raw)
            if len(cells) != 3:
                problems.append(f"claims row has {len(cells)} cells, expected 3: {raw.strip()[:60]}")
                continue
            rows.append((cells[0], cells[1], cells[2]))
    if tables == 0:
        problems.append("no claims table (a table whose last column header is 'Label')")
    elif tables > 1:
        problems.append(f"{tables} claims tables; exactly one is allowed")
    return rows, problems


def _cells(row: str) -> list[str]:
    stripped = row.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [cell.strip() for cell in stripped.split("|")]


def label_of(cell: str) -> tuple[str | None, str, str | None]:
    """Split a label cell into ``(label, remainder, problem)``."""
    match = LABEL_PREFIX_RE.match(cell.strip())
    if match is None:
        found = [label for label in LABELS if label in cell.lower()]
        if len(found) > 1:
            return None, cell, f"claim carries more than one label ({', '.join(found)})"
        if found:
            # A label that does not start the cell is still ambiguous.
            return None, cell, f"label {found[0]!r} must start the label cell"
        return None, cell, "claim carries no evidence label"
    label = match.group("label").lower()
    rest = match.group("rest").strip()
    if any(other != label and other in rest.lower() for other in LABELS):
        return None, rest, f"claim carries more than one label ({label} and another)"
    return label, rest, None


def evidence_refs(text: str) -> list[tuple[str, int, int]]:
    """Every ``path:line`` or ``path:line-line`` reference in the document."""
    refs: list[tuple[str, int, int]] = []
    for match in EVIDENCE_RE.finditer(text):
        start = int(match.group("start"))
        end = int(match.group("end")) if match.group("end") else start
        refs.append((match.group("path"), start, end))
    return refs


def route_tokens(text: str) -> list[str]:
    """Every ``action_*`` token, skipping wildcard namespace forms."""
    tokens: list[str] = []
    for match in ROUTE_TOKEN_RE.finditer(text):
        if text[match.end():match.end() + 1] == "*":
            continue  # e.g. action_esp_* names an absent namespace, not a route
        tokens.append(match.group(0))
    return tokens


def _decimal(value: str) -> Decimal | None:
    try:
        return Decimal(value)
    except InvalidOperation:  # pragma: no cover - regex already constrains this
        return None


def validate(
    text: str,
    *,
    catalog: dict[str, dict] = ACTION_CATALOG,
    bounds: dict[str, dict] = ABSOLUTE_BOUNDS,
    meta_routes: tuple[str, ...] = ACTION_META_ROUTES,
    root: Path | None = ROOT,
) -> list[str]:
    """Return every problem with ``text``.  An empty list means it is honest.

    ``root`` is the directory evidence paths are resolved against; pass ``None``
    to skip check (d) when validating a synthetic document.
    """
    problems: list[str] = []
    known = set(catalog) | set(meta_routes)

    # -- (a) every action token, anywhere, must exist -------------------------
    for token in route_tokens(text):
        if token not in known:
            problems.append(f"(a) route {token!r} is not in ACTION_CATALOG or ACTION_META_ROUTES")

    # -- (e) the safety banner ------------------------------------------------
    lowered = text.lower()
    for keyword in SAFETY_KEYWORDS:
        if keyword not in lowered:
            problems.append(f"(e) the safety banner lost the phrase {keyword!r}")

    # -- (f) section floor ----------------------------------------------------
    blocks = sections(text)
    if len(blocks) < SECTION_FLOOR:
        problems.append(
            f"(f) found {len(blocks)} hack section(s), floor is {SECTION_FLOOR}"
        )

    for section in blocks:
        where = section.name
        values, field_problems = fields(section.body)
        for problem in field_problems:
            problems.append(f"(f) {where}: {problem}")

        for name in REQUIRED_FIELDS:
            if name not in values:
                problems.append(f"(f) {where}: missing the {name!r} field")
        for name, value in values.items():
            if not value:
                problems.append(f"(f) {where}: the {name!r} field is empty")

        # (f) verdict class
        verdict = values.get("Verdict", "")
        normalised = verdict.lstrip("`* ").rstrip("`* ").lower()
        if verdict and not normalised.startswith(VERDICT_CLASSES):
            problems.append(
                f"(f) {where}: verdict {verdict[:40]!r} does not start with one of {VERDICT_CLASSES}"
            )

        # (a) route field
        route_value = values.get("Route", "")
        section_routes: list[str] = []
        if route_value:
            section_routes = [
                token
                for match in re.finditer(r"`(action_[a-z0-9_]+)`", route_value)
                for token in [match.group(1)]
            ]
            if not section_routes and not route_value.lstrip("` ").lower().startswith("none"):
                problems.append(
                    f"(a) {where}: Route is neither 'none' nor a backticked action_* route "
                    f"({route_value[:40]!r})"
                )

        # (a) an all-unavailable route set cannot be a reachable hack
        if section_routes:
            unavailable = [
                route
                for route in section_routes
                if catalog.get(route, {}).get("status") == "unavailable"
            ]
            if len(unavailable) == len(section_routes) and normalised.startswith(
                ("possible on stock firmware", "only with dev mode", "only with root")
            ):
                problems.append(
                    f"(a) {where}: every named route is catalogued unavailable, "
                    f"but the verdict claims it is reachable"
                )

        # (b) bounds
        bounds_value = values.get("Bounds", "")
        if bounds_value:
            matches = list(BOUND_RE.finditer(bounds_value))
            if bounds_value.lstrip("` ").lower().startswith("none"):
                if matches:
                    problems.append(
                        f"(b) {where}: Bounds says 'none' but also lists {len(matches)} bound(s)"
                    )
            elif not matches:
                problems.append(
                    f"(b) {where}: Bounds is neither 'none' nor a list of `name`=min..max"
                )
            for match in matches:
                name = match.group("name")
                if name not in bounds:
                    problems.append(f"(b) {where}: {name!r} is not an ABSOLUTE_BOUNDS entry")
                    continue
                absolute_min = _decimal(str(bounds[name]["min"]))
                absolute_max = _decimal(str(bounds[name]["max"]))
                stated_min = _decimal(match.group("min"))
                stated_max = _decimal(match.group("max"))
                if stated_min != absolute_min or stated_max != absolute_max:
                    problems.append(
                        f"(b) {where}: {name} stated as {match.group('min')}..{match.group('max')}, "
                        f"ABSOLUTE_BOUNDS is {bounds[name]['min']}..{bounds[name]['max']}"
                    )

        # (f) bold risk line
        risk = values.get("Risk", "")
        if risk and not (risk.startswith("**") and risk.rstrip().endswith("**") and len(risk) > 8):
            problems.append(f"(f) {where}: the Risk value is not one bold sentence")

        # (c) claims and labels
        rows, claim_problems = claims(section.body)
        for problem in claim_problems:
            problems.append(f"(c) {where}: {problem}")
        used: set[str] = set()
        for claim_id, claim_text, label_cell in rows:
            label, remainder, label_problem = label_of(label_cell)
            if label_problem is not None:
                problems.append(f"(c) {where}: {claim_id}: {label_problem}")
                continue
            assert label is not None
            used.add(label)
            if not claim_text.strip():
                problems.append(f"(c) {where}: {claim_id}: the claim text is empty")
            refs = evidence_refs(remainder)
            if not refs:
                problems.append(f"(c) {where}: {claim_id}: no `path:line` evidence reference")
        if rows and used != set(LABELS):
            missing = sorted(set(LABELS) - used)
            problems.append(
                f"(c) {where}: the section never uses the label(s) {', '.join(missing)}"
            )

    # -- (d) evidence paths and line ranges ----------------------------------
    for match in BARE_REF_RE.finditer(text):
        problems.append(
            f"(d) line reference {match.group(0)!r} has no path in front of it; "
            "write the full path"
        )
    if root is not None:
        cache: dict[str, list[str] | None] = {}
        for path, start, end in evidence_refs(text):
            if path not in cache:
                candidate = root / path
                try:
                    cache[path] = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    cache[path] = None
            lines = cache[path]
            if lines is None:
                problems.append(f"(d) evidence path {path!r} is not in this repository")
                continue
            total = len(lines)
            if start < 1 or end < start or end > total:
                problems.append(
                    f"(d) {path}:{start}-{end} is outside the file (1..{total})"
                )

    return problems


def main() -> int:
    if not DOC.is_file():
        print(f"missing document: {DOC.relative_to(ROOT)}", file=sys.stderr)
        return 2
    text = DOC.read_text(encoding="utf-8")
    problems = validate(text)
    blocks = sections(text)
    claim_count = sum(len(claims(section.body)[0]) for section in blocks)
    if problems:
        for problem in problems:
            print(problem)
        print(f"\nFAIL: {len(problems)} problem(s) in {DOC.relative_to(ROOT)}")
        return 1
    print(
        f"OK: {DOC.relative_to(ROOT)} — {len(blocks)} hack sections, "
        f"{claim_count} labelled claims, {len(route_tokens(text))} route mentions, "
        f"{len(evidence_refs(text))} evidence references all resolve"
    )
    return 0


# --------------------------------------------------------------------------
# The suite.  Each test proves a gate fires; a check that cannot fail is not a
# check.  Tests that mutate the real document prove the gate is wired to the
# file, not to a copy of it.
# --------------------------------------------------------------------------


def _document() -> str:
    return DOC.read_text(encoding="utf-8")


def _mutated(old: str, new: str) -> str:
    text = _document()
    if old not in text:
        raise AssertionError(f"fixture text not found in {DOC.name}: {old[:60]!r}")
    return text.replace(old, new, 1)


class DocumentIsClean(unittest.TestCase):
    def test_the_document_passes(self) -> None:
        problems = validate(_document())
        self.assertEqual([], problems, "\n".join(problems))

    def test_the_safety_banner_is_present(self) -> None:
        text = _document()
        for keyword in SAFETY_KEYWORDS:
            self.assertIn(keyword, text.lower())

    def test_every_catalog_route_named_is_real(self) -> None:
        known = set(ACTION_CATALOG) | set(ACTION_META_ROUTES)
        for token in route_tokens(_document()):
            self.assertIn(token, known)


class RoutesMustExist(unittest.TestCase):
    def test_unknown_route_in_a_route_field_fails(self) -> None:
        problems = validate(_mutated("`action_agsa_stop`, `action_recipe_update`",
                                     "`action_agsa_stop`, `action_agsa_speed`"))
        self.assertTrue(any("(a)" in p and "action_agsa_speed" in p for p in problems), problems)

    def test_unknown_route_in_prose_fails(self) -> None:
        problems = validate(_mutated("The root-owned runner independently bounds",
                                     "The `action_motor_speed` route bounds"))
        self.assertTrue(any("(a)" in p and "action_motor_speed" in p for p in problems), problems)

    def test_wildcard_namespace_is_not_a_route(self) -> None:
        # "action_esp_*" names an absent namespace, not a route, so it is skipped;
        # the same name without the wildcard is a route claim and must fail.
        allowed = validate("## H1 · x\n\n  anything `action_esp_*` is absent\n", root=None)
        self.assertFalse(any("action_esp" in p for p in allowed), allowed)
        refused = validate("## H1 · x\n\n  `action_esp_reset` is absent\n", root=None)
        self.assertTrue(any("action_esp_reset" in p for p in refused), refused)

    def test_meta_route_is_allowed(self) -> None:
        Problems = validate(_mutated("The root-owned runner independently bounds",
                                    "`action_prepare` is required, and the runner bounds"))
        self.assertFalse(any("action_prepare" in p for p in Problems), Problems)


class BoundsMustMatch(unittest.TestCase):
    def test_widened_bound_fails(self) -> None:
        problems = validate(_mutated("`purgeMs`=100..10000", "`purgeMs`=100..60000"))
        self.assertTrue(any("(b)" in p and "purgeMs" in p for p in problems), problems)

    def test_narrowed_bound_fails(self) -> None:
        problems = validate(_mutated("`manualGrindMs`=100..5000", "`manualGrindMs`=100..2000"))
        self.assertTrue(any("(b)" in p and "manualGrindMs" in p for p in problems), problems)

    def test_unknown_bound_name_fails(self) -> None:
        problems = validate(_mutated("`agsaStepDd`=1..300", "`agsaStepDeg`=1..300"))
        self.assertTrue(any("(b)" in p and "agsaStepDeg" in p for p in problems), problems)

    def test_junk_bounds_field_fails(self) -> None:
        problems = validate(
            _mutated(
                "- **Bounds:** `manualGrindMs`=100..5000; `grindTimeSec`=0.5..60",
                "- **Bounds:** 100 ms up to five seconds",
            )
        )
        self.assertTrue(any("(b)" in p and "Bounds is neither" in p for p in problems), problems)

    def test_none_bounds_with_numbers_fails(self) -> None:
        problems = validate(_mutated("- **Bounds:** `none`\n- **Observable effect:** none.",
                                     "- **Bounds:** none, but `fanDuty`=0..100\n"
                                     "- **Observable effect:** none."))
        self.assertTrue(any("(b)" in p and "also lists" in p for p in problems), problems)


class LabelsAreMandatory(unittest.TestCase):
    def test_missing_label_fails(self) -> None:
        problems = validate(
            _mutated("| documented `docs/bible/protocols.md:1075-1080` |", "| see above |")
        )
        self.assertTrue(any("(c)" in p and "no evidence label" in p for p in problems), problems)

    def test_two_labels_fail(self) -> None:
        problems = validate(
            _mutated("| documented `docs/bible/protocols.md:1075-1080` |",
                     "| documented, inferred `docs/bible/protocols.md:1075-1080` |")
        )
        self.assertTrue(any("(c)" in p and "more than one label" in p for p in problems), problems)

    def test_a_section_must_use_all_three_labels(self) -> None:
        text = _document()
        start = text.index("## H2 · Variable RPM during a grind")
        end = text.index("## H3 ·")
        section = text[start:end]
        if section.count("needs hardware") != 1:
            self.skipTest("H2 has more than one 'needs hardware' claim; pick another fixture")
        altered = section.replace("needs hardware", "inferred")
        problems = validate(text[:start] + altered + text[end:])
        self.assertTrue(
            any("(c) H2" in p and "never uses the label" in p for p in problems), problems
        )

    def test_missing_claims_table_fails(self) -> None:
        text = _document()
        start = text.index("## H4 · Purge duration")
        end = text.index("## H5 ·")
        section = text[start:end]
        head, _, _ = section.partition("| # | Claim | Label |")
        problems = validate(text[:start] + head + text[end:])
        self.assertTrue(
            any("(c) H4" in p and "no claims table" in p for p in problems), problems
        )

    def test_claim_without_evidence_fails(self) -> None:
        problems = validate(
            _mutated("| needs hardware `docs/DRIVER_LIMITS.md:183-191` |", "| needs hardware |")
        )
        self.assertTrue(
            any("(c)" in p and "no `path:line` evidence" in p for p in problems), problems
        )


class EvidenceMustResolve(unittest.TestCase):
    def test_missing_evidence_file_fails(self) -> None:
        problems = validate(_mutated("`docs/API_REFERENCE.md:2033`", "`docs/NOPE.md:2033`"))
        self.assertTrue(
            any("(d)" in p and "not in this repository" in p for p in problems), problems
        )

    def test_line_beyond_end_of_file_fails(self) -> None:
        problems = validate(
            _mutated("`docs/API_REFERENCE.md:2033`", "`docs/API_REFERENCE.md:99999`")
        )
        self.assertTrue(any("(d)" in p and "outside the file" in p for p in problems), problems)

    def test_bare_line_reference_fails(self) -> None:
        problems = validate(
            _mutated(
                "`docs/SQLITE_CLOSURE.md:115`, `tools/e64local_actions.py:86`",
                "`docs/SQLITE_CLOSURE.md:115`, `:86`",
            )
        )
        self.assertTrue(any("(d)" in p and "has no path" in p for p in problems), problems)

    def test_evidence_check_can_be_skipped_for_synthetic_documents(self) -> None:
        problems = validate("## H1 · x\n\n- **Route:** `action_not_real`\n", root=None)
        self.assertTrue(any("(a)" in p for p in problems), problems)
        self.assertFalse(any("(d)" in p for p in problems), problems)


class ShapeIsEnforced(unittest.TestCase):
    def test_missing_verdict_class_fails(self) -> None:
        problems = validate(_mutated("- **Verdict:** `not possible` —",
                                     "- **Verdict:** probably not —"))
        self.assertTrue(any("(f)" in p and "verdict" in p for p in problems), problems)

    def test_missing_field_fails(self) -> None:
        problems = validate(_mutated("- **Reversibility:** n/a.", ""))
        self.assertTrue(
            any("(f)" in p and "Reversibility" in p for p in problems), problems
        )

    def test_unbold_risk_fails(self) -> None:
        text = _document()
        marker = "- **Risk:** **The risk is the obvious next step"
        self.assertIn(marker, text)
        problems = validate(text.replace(marker, "- **Risk:** The risk is the obvious next step", 1)
                            .replace("command with no stop.**", "command with no stop.", 1))
        self.assertTrue(any("(f)" in p and "bold sentence" in p for p in problems), problems)

    def test_section_floor_fails_when_a_section_is_deleted(self) -> None:
        text = _document()
        start = text.index("## H7 · GBS bypass")
        end = text.index("Three hacks this document refuses")
        problems = validate(text[:start] + text[end:])
        self.assertTrue(any("(f)" in p and "floor is" in p for p in problems), problems)

    def test_a_later_section_cannot_leak_into_the_last_hack(self) -> None:
        # A second "Label" table outside any hack section must not be counted as
        # a claims table of the hack section before it.
        problems = validate(
            _mutated(
                "## 5. Related documents",
                "## 5. Related documents\n\n| a | Claim | Label |\n|---|---|---|\n| x | y | z |",
            )
        )
        self.assertFalse(any("2 claims tables" in p for p in problems), problems)

    def test_missing_safety_phrase_fails(self) -> None:
        problems = validate(_document().replace("jammed burr at speed", "jammed burr"))
        self.assertTrue(
            any("(e)" in p and "jammed burr at speed" in p for p in problems), problems
        )


class BoundsAreReadOnly(unittest.TestCase):
    def test_the_module_never_mutates_the_catalog(self) -> None:
        snapshot = {name: dict(value) for name, value in ABSOLUTE_BOUNDS.items()}
        validate(_document())
        self.assertEqual(snapshot, ABSOLUTE_BOUNDS)

    def test_no_bound_is_widened_by_this_document(self) -> None:
        text = _document()
        for match in BOUND_RE.finditer(text):
            name = match.group("name")
            self.assertIn(name, ABSOLUTE_BOUNDS)
            self.assertEqual(Decimal(match.group("min")), Decimal(str(ABSOLUTE_BOUNDS[name]["min"])))
            self.assertEqual(Decimal(match.group("max")), Decimal(str(ABSOLUTE_BOUNDS[name]["max"])))


if __name__ == "__main__":
    raise SystemExit(main())
