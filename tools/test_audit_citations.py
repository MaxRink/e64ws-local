#!/usr/bin/env python3
"""Keep the citation table in ``docs/DEPENDENCY_AUDIT.md`` resolvable.

The table under "Prose that still quoted the old build" records, for each stale
line, where it was (``File:line``), what it said, and what it says now.

Its ``File:line`` column is a *historical* anchor, not a pointer into today's
tree: the sentence above the table says the rows "were located on `2416666`",
the commit where the stale text was still in place.  A HEAD-relative number
cannot carry that meaning -- at HEAD the quoted text is gone, and every later
edit that adds a line moves the target.  Mixing the two conventions is what let
one row cite ``Dockerfile:20`` for a version that sits on line 21 of the file it
names: a claim about a document rather than about an artefact, which no build can
catch and no green local run would notice.

So the anchor, the rows and the widest span a row may cite are pinned in this
module, and the document has to agree with them:

(a) anchor  -- :data:`ANCHOR_COMMIT` is the commit, as a constant here.  The
               prose's own claim is *checked against* that constant
               (:func:`prose_anchor`) instead of being trusted as the source, so
               re-pointing the sentence above the table is not a way to make a
               bad row pass: the anchor cannot move without editing this file,
               which review sees.  The pinned commit has to exist and be an
               ancestor of HEAD, or a history rewrite silently orphans the table;
(b) rows    -- :data:`ROWS` is the exact set of citations.  A floor is a count,
               so deleting a row and pasting a duplicate of another keeps the
               count and passes; a set does not;
(c) span    -- a row cites at most :data:`MAX_SPAN` lines, so widening ``:16`` to
               ``:1-71`` cannot make an unfindable quote resolve;
(d) resolve -- every row's ``path:line[-line]`` exists at the pinned anchor and
               stays inside that file's line count there;
(e) quoted  -- the version numbers in the row's ``Said`` cell appear on those
               very lines at the anchor: the citation must point at the text it
               quotes.  This is the check ``Dockerfile:20`` fails;
(f) carried -- the version numbers in ``Now says`` appear in the region the cited
               lines became, following the anchor-to-working-tree diff, and not on
               the cited lines at the anchor.  Searching the whole file instead
               would let a row claim a correction the file carries anywhere at
               all -- a Python version in §3 standing in for a Gradle version in
               §1.

What (f) does *not* bound, stated plainly because a docstring that claims more
than the code is the defect this module exists to prevent.  :data:`EDIT_HORIZON`
bounds where a hunk **starts** relative to the citation, not how large the block
it replaced was: when the diff replaces a paragraph, the region is the whole
replacement block, so the region can be tens of lines wide and reach past the
point the cited line itself landed on.  Measured on the table below, the widest
region is :data:`WIDEST_REGION` lines and no line in one sits further than
:data:`FURTHEST_OFFSET` from where its own citation landed --
``test_the_successor_region_stays_within_the_documented_bound`` fails if those
two numbers move, so this paragraph cannot drift away from the code again.

Two consequences worth being explicit about, because both are covered by the
bound rather than by the check: a row can claim a version that is inside the
replacement block but on a line other than the one it is about, and two rows
whose citations land within the same block can exchange versions.  Clamping the
region to the citation's landed position plus-or-minus :data:`EDIT_HORIZON` was
the alternative; it rejects ``docs/REPRODUCIBLE_BUILDS.md:456``, whose corrected
sentence moved into the block next to the one that replaced the cited lines, and
a clamp that rejects a true row is worse than a bound that is written down.

Three checkout states, three reports
------------------------------------
:func:`unresolvable` asks ``git rev-parse --is-shallow-repository`` **first**,
then whether the anchor object is there at all, and says one of:

* **shallow** -- a depth-1 clone (the ``actions/checkout`` default, and the
  reason ``.github/workflows/tests.yml`` asks for ``fetch-depth: 0``): the guard
  cannot answer, so every test skips and the message asks for full history.
  ``test_every_checkout_in_ci_fetches_full_history`` asserts the workflow asks
  for it, so this state is for a clone made by hand, not for CI;
* **not shallow, anchor missing** -- the pinned commit is gone from this
  repository: a rewrite, a squash-merge that dropped it, or a clone of a
  repository where it never existed.  A skip, because the guard cannot answer,
  but the message says the *pin* is the thing to repair and points at the
  procedure below.  A fresh clone of a rewritten history is therefore green with
  the guard skipped, and its message names the pin rather than the fetch depth;
* **present, not an ancestor of HEAD** -- a failure, not a skip: the object is
  here and the history leading to it is not, which is exactly the rewrite this
  guard exists to notice.

Repairing the anchor
--------------------
The table is a record of a past audit, so its anchor is a fact about the
repository, not a preference.  When the history that carried those lines is
gone, the repair is one commit that changes three things together, because any
two of them without the third leave the table unresolvable:

1. ``ANCHOR_COMMIT`` -- the commit the stale lines were located on, full sha;
2. the sentence above the table (``all were located on `<short sha>`'``) -- it
   must name the same commit, and ``test_the_prose_names_the_pinned_anchor``
   fails until it does;
3. every ``File:line`` cell in ``docs/DEPENDENCY_AUDIT.md`` **and** :data:`ROWS`
   -- re-aimed at that commit's line numbers.

Then run ``python3 -m unittest tools.test_audit_citations``: it names the first
row whose ``Said`` text is not on its cited lines.  Re-picking the anchor is
deliberately a code change rather than a prose edit -- that is the whole point
of step 1 -- so it appears in review next to the table it re-aims.

Usage::

    python3 tools/test_audit_citations.py          # lint; exit 1 on failure
    python3 -m unittest tools.test_audit_citations # the same checks as a suite
"""

from __future__ import annotations

import re
import subprocess
import unittest
from dataclasses import dataclass
from pathlib import Path

try:  # imported as ``tools.test_audit_citations``
    from .required_inputs import skip_without
except ImportError:  # imported from inside ``tools/``
    from required_inputs import skip_without  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "DEPENDENCY_AUDIT.md"

#: The commit every row of the table is anchored to.  A constant, not a value
#: read out of the prose: the prose is the thing under test, so deriving the
#: anchor from it would let a row be made to pass by re-pointing the sentence
#: above the table -- an unguarded way to make a bad row resolve.  Moving the
#: anchor means editing this line, which is a change to the guard itself.
ANCHOR_COMMIT = "24166666a38fa5c7e10cdc992890b5c5878495c7"

#: The sentence that declares the anchor commit for every row in the table.  Its
#: claim is compared with :data:`ANCHOR_COMMIT`; it is not the source of truth.
ANCHOR = re.compile(r"all were located on\s*`(?P<commit>[0-9a-f]{7,40})`")

#: A version number.  Version drift is what this table records, so a version
#: number is also what a citation has to hit to be worth anything.
VERSION = re.compile(r"\b\d+\.\d+(?:\.\d+)*\b")

#: A hunk header from ``git diff --unified=0``: the old range and the new one.
HUNK = re.compile(r"^@@ -(?P<old_first>\d+)(?:,(?P<old_count>\d+))? "
                  r"\+(?P<new_first>\d+)(?:,(?P<new_count>\d+))? @@", re.MULTILINE)

#: The exact citations the table carries.  A set, not a floor: a citation may be
#: corrected, but adding or removing one is a change to this set in the same
#: commit, which is a change review sees.
ROWS = frozenset({
    "docker/README.md:16",
    "docker/android/Dockerfile:5",
    "docker/android/Dockerfile:8",
    "docker/android/Dockerfile:9",
    "docker/android/Dockerfile:16",
    "docs/DECAID_DEPENDENCIES.md:41",
    "docs/REPRODUCIBLE_BUILDS.md:36",
    "docs/REPRODUCIBLE_BUILDS.md:456",
    "docs/REPRODUCIBLE_BUILDS.md:463",
    "docs/REPRODUCIBLE_BUILDS.md:466",
})

#: The widest span a single row may cite.  Every row here cites one line; the
#: bound exists so a citation cannot be widened over the whole file until the
#: quote it claims to contain happens to fall inside it.
MAX_SPAN = 3

#: How far from a citation a hunk may *start* and still be read for it.  Rewriting
#: a paragraph reflows the sentence a row points at into the hunks beside it, so
#: the check reads the diff around the citation rather than the whole file.  This
#: bounds the hunk's start and not its size: the region a row is allowed is the
#: replacement block of every hunk that starts within this many lines, which on
#: this table is up to :data:`WIDEST_REGION` lines long.  The docstring's
#: "what (f) does not bound" paragraph is the honest statement of that.
EDIT_HORIZON = 8

#: The widest successor region the table's ten rows produce today, in lines --
#: ``docs/REPRODUCIBLE_BUILDS.md:456``, whose cited paragraph was replaced by a
#: 36-line block.
WIDEST_REGION = 36

#: The furthest any line in a successor region sits from where its own citation
#: landed, in lines -- ``docs/REPRODUCIBLE_BUILDS.md:463``, whose region starts 32
#: lines above the row's own position.
FURTHEST_OFFSET = 32


def git(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run one git command against this checkout, never raising on status."""
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def split_row(line: str) -> list[str]:
    """Split a markdown table row, honouring the ``\\|`` escape inside a cell."""
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", line)]


@dataclass(frozen=True)
class Citation:
    """One row: where the stale line was, what it said, what it says now."""

    path: str
    first: int
    last: int
    said: str
    now: str

    def label(self) -> str:
        span = f"{self.first}" if self.first == self.last else f"{self.first}-{self.last}"
        return f"{self.path}:{span}"


WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
CHECKOUT = "uses: actions/checkout"


def document() -> str:
    return DOC.read_text(encoding="utf-8")


def checkout_steps(workflow: str) -> list[tuple[int, str]]:
    """Each ``actions/checkout`` step in a workflow: its line number and its block.

    Read as text rather than through a parser because this repository's suites use
    the standard library only.  The block is every line indented deeper than the
    step itself, which is exactly what ``with:`` and its keys are.
    """
    lines = workflow.splitlines()
    steps: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if CHECKOUT not in line:
            continue
        indent = len(line) - len(line.lstrip())
        block: list[str] = []
        for following in lines[index + 1:]:
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            block.append(following)
        steps.append((index + 1, "\n".join(block)))
    return steps


def prose_anchor(text: str) -> str:
    """The one commit the table's prose claims, or a failure naming the prose."""
    found = ANCHOR.findall(text)
    if len(found) != 1:
        raise AssertionError(
            "docs/DEPENDENCY_AUDIT.md must declare exactly one anchor commit in "
            f"the form 'all were located on `<commit>`'; found {found!r}"
        )
    return found[0]


def citations(text: str) -> list[Citation]:
    """Every ``path:line[-line]`` row of the three-column citation table."""
    rows: list[Citation] = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = split_row(line)
        # A row is |, cell, cell, cell, | -- five pieces after the split.
        if len(cells) != 5:
            continue
        span = re.fullmatch(r"`([^`]+):(\d+)(?:-(\d+))?`", cells[1])
        if span is None:
            continue
        first = int(span.group(2))
        rows.append(
            Citation(
                path=span.group(1),
                first=first,
                last=int(span.group(3) or first),
                said=cells[2],
                now=cells[3],
            )
        )
    return rows


def lines_at(commit: str, path: str) -> list[str]:
    """The file at ``path`` as it stood at ``commit``; empty when absent."""
    shown = git("show", f"{commit}:{path}")
    if shown.returncode != 0:
        return []
    return shown.stdout.splitlines()


def hunks_between(commit: str, path: str) -> list[tuple[int, int, int, int]]:
    """``(old_first, old_count, new_first, new_count)`` for each change to path.

    From ``commit`` to the *working tree*, not to ``HEAD``: the same test reads
    the row's ``Now says`` text out of the working tree, so both sides of the
    comparison have to describe the file the reader has.  Diffing against
    ``HEAD`` while reading the working tree would map an uncommitted edit's lines
    onto the previous commit's numbering, which is an off-by-a-refactor.

    ``--unified=0`` so a hunk is exactly the lines that changed, never a context
    window that would quietly widen the region a row is allowed to cite.
    """
    diff = git("diff", "--unified=0", "--no-color", "--no-ext-diff",
               commit, "--", path)
    if diff.returncode != 0:
        return []
    return [
        (int(match.group("old_first")), int(match.group("old_count") or 1),
         int(match.group("new_first")), int(match.group("new_count") or 1))
        for match in HUNK.finditer(diff.stdout)
    ]


def landed_line(hunks: list[tuple[int, int, int, int]], number: int) -> int | None:
    """Where line ``number`` of the anchor file sits in today's file, if anywhere.

    A line no hunk touches survives at its own number, shifted by the net change
    of the hunks above it.  A line inside a hunk lands inside that hunk's
    replacement block, keeping its offset where the block is long enough and
    clamping to the block where it is not.  A line the diff deleted lands nowhere.
    """
    for old_first, old_count, new_first, new_count in hunks:
        if old_first <= number <= old_first + max(old_count, 1) - 1:
            if new_count == 0:
                return None
            return new_first + min(number - old_first, new_count - 1)
    shift = sum(
        new_count - old_count
        for old_first, old_count, _new_first, new_count in hunks
        if old_first + max(old_count, 1) - 1 < number
    )
    return number + shift


def correction_lines(commit: str, path: str, first: int, last: int) -> list[int]:
    """Today's ``path`` lines a correction of the ``first``-``last`` citation may sit on.

    The lines the diff added within :data:`EDIT_HORIZON` of the citation, plus
    the cited lines themselves where the diff left them alone and shifted them
    down the file.  A line inside a hunk became that hunk's replacement range --
    what "the file now says" means for a citation whose text was rewritten rather
    than edited -- and a neighbour inside the horizon is where a reflowed
    paragraph puts the replacement sentence.  Everything else in the file is out
    of scope for the row, which is the point.
    """
    hunks = hunks_between(commit, path)
    today: set[int] = set()
    for old_first, old_count, new_first, new_count in hunks:
        # For an insertion git reports the line it follows (`-a,0`), so the last
        # line a hunk covers is `a` when nothing was removed.  The horizon is
        # checked against that start: the block that follows is taken whole,
        # however long it is -- :data:`WIDEST_REGION` is the measured width.
        old_last = old_first + max(old_count, 1) - 1
        if old_last < first - EDIT_HORIZON or old_first > last + EDIT_HORIZON:
            continue
        today.update(range(new_first, new_first + new_count))
    for number in range(first, last + 1):
        landed = landed_line(hunks, number)
        if landed is not None:
            today.add(landed)
    return sorted(number for number in today if number >= 1)


def anchor_missing(shallow: bool) -> str:
    """Why the pinned anchor is not in this object store, for the skip message.

    ``shallow`` is read *first*, because the two ways the object can be absent
    ask for different repairs and only one of them is about the fetch depth.  A
    message that led with "this is what a shallow clone looks like" while printing
    ``is-shallow-repository`` ``false`` sent the reader after the wrong thing.
    """
    if shallow:
        return (
            f"the pinned anchor commit {ANCHOR_COMMIT[:7]} is not in this checkout "
            "and it is a shallow clone (`git rev-parse --is-shallow-repository` "
            "says 'true'), so the citation table's historical line numbers cannot "
            "be resolved here.  `actions/checkout` fetches one commit unless "
            "`fetch-depth: 0` is set; clone again with full history, or fetch the "
            "anchor's commit depth.  Nothing is wrong with the table."
        )
    return (
        f"the pinned anchor commit {ANCHOR_COMMIT[:7]} is not in this repository "
        "and this is NOT a shallow clone (`git rev-parse --is-shallow-repository` "
        "says 'false'), so the commit the citation table is anchored to is gone: a "
        "rewrite, a squash-merge that dropped it, or a clone of a repository that "
        "never had it.  Fetching deeper will not find it.  The repair is the "
        "procedure in this module's docstring, 'Repairing the anchor': pin the "
        "replacement commit in ANCHOR_COMMIT, name the same commit in the prose, "
        "and re-aim the table's `File:line` cells and ROWS at it, in one commit."
    )


def unresolvable() -> str | None:
    """Why the anchor cannot be resolved in this checkout, or ``None`` when it can.

    Three states, three reports, in this order:

    * no ``.git`` at all -- the export gate's git-archive mount;
    * no anchor object, and the clone *is* shallow -- a depth-1 checkout, which
      is what :func:`anchor_missing` asks for full history about;
    * no anchor object, and the clone is *not* shallow -- the pin itself is gone,
      which :func:`anchor_missing` names as a repair rather than a fetch depth.

    The anchor existing but not leading to HEAD is a fourth thing and not handled
    here: :class:`AnchorTests` fails on it, because an object that is present with
    its history cut away is exactly the rewrite this guard exists to notice.
    """
    if not (ROOT / ".git").exists():
        return (
            "this checkout carries no .git, so the historical anchor the "
            "citation table declares cannot be resolved; the table is checked "
            "in a clone"
        )
    if git("cat-file", "-e", f"{ANCHOR_COMMIT}^{{commit}}").returncode != 0:
        shallow = git("rev-parse", "--is-shallow-repository").stdout.strip() == "true"
        return anchor_missing(shallow)
    return None


def setUpModule() -> None:
    skip_without(["docs/DEPENDENCY_AUDIT.md"])


def require_anchor() -> None:
    """Skip this test, naming the reason, when the anchor cannot be resolved."""
    reason = unresolvable()
    if reason is not None:
        raise unittest.SkipTest(reason)


class AnchorGuard(unittest.TestCase):
    """Skip each test, with its reason, when this checkout cannot carry the anchor.

    Per test rather than per module or per class, because ``unittest`` reports a
    skip raised in ``setUpModule`` or ``setUpClass`` as ``Ran 0 tests``: the
    module would drop out of ``tools/run_tests.py``'s suite count and put the
    tools suite below its floor, so a shallow clone would fail for the wrong
    reason instead of reporting the named skip.
    """

    def setUp(self) -> None:
        require_anchor()


class AnchorTests(AnchorGuard):
    """The anchor is pinned here, the prose agrees, and the commit is in this history."""

    def test_the_prose_names_the_pinned_anchor(self) -> None:
        claimed = prose_anchor(document())
        self.assertTrue(
            ANCHOR_COMMIT.startswith(claimed),
            f"docs/DEPENDENCY_AUDIT.md says the rows 'were located on "
            f"`{claimed}`', but this guard pins {ANCHOR_COMMIT[:7]} "
            f"({ANCHOR_COMMIT}).  The pin is the anchor: move it here, in a "
            "commit that says why, rather than re-pointing the sentence -- a "
            "re-anchored table resolves whatever the new commit happens to say.",
        )

    def test_the_pinned_anchor_is_a_commit_in_this_history(self) -> None:
        kind = git("cat-file", "-t", ANCHOR_COMMIT)
        self.assertEqual(
            kind.stdout.strip(),
            "commit",
            f"{ANCHOR_COMMIT[:7]} is not a commit in this checkout: {kind.stderr.strip()}",
        )
        # `merge-base --is-ancestor` exits 0 only when the anchor is reachable
        # from HEAD.  A history rewrite that drops it turns the whole table into
        # unverifiable prose, which is a failure, not a stale comment.
        reachable = git("merge-base", "--is-ancestor", ANCHOR_COMMIT, "HEAD")
        self.assertEqual(
            reachable.returncode,
            0,
            f"{ANCHOR_COMMIT[:7]} is present but is not an ancestor of HEAD, so "
            "no row of the citation table can be resolved: the history that "
            f"carried those lines is gone. {reachable.stderr.strip()}",
        )


class TableTests(AnchorGuard):
    """Every row points at the text it quotes, at the commit it declares."""

    def setUp(self) -> None:
        super().setUp()
        self.rows = citations(document())

    def test_the_table_carries_exactly_the_pinned_rows(self) -> None:
        labels = [row.label() for row in self.rows]
        duplicates = sorted({label for label in labels if labels.count(label) > 1})
        self.assertFalse(
            duplicates,
            f"the citation table cites {', '.join(duplicates)} more than once; a "
            "duplicate row buys nothing and hides a deletion",
        )
        missing = sorted(ROWS - set(labels))
        extra = sorted(set(labels) - ROWS)
        self.assertFalse(
            missing or extra,
            "the citation table is not the pinned set of rows: "
            f"missing {missing or 'none'}, unexpected {extra or 'none'}.  A "
            "citation may be corrected; adding or removing one is a change to "
            "ROWS in this module, in the same commit, with the reason written "
            "down.",
        )

    def test_every_row_cites_a_bounded_span(self) -> None:
        for row in self.rows:
            with self.subTest(row=row.label()):
                self.assertGreaterEqual(row.first, 1, f"{row.label()}: line 0")
                self.assertLessEqual(
                    row.first,
                    row.last,
                    f"{row.label()}: the range runs backwards",
                )
                self.assertLessEqual(
                    row.last - row.first + 1,
                    MAX_SPAN,
                    f"{row.label()} cites {row.last - row.first + 1} lines, and a "
                    f"citation may span at most {MAX_SPAN}.  A row widened over "
                    "the whole file resolves whatever it is pointed at, so it "
                    "proves nothing about the line it claims to be about",
                )

    def test_every_row_carries_a_version_in_both_columns(self) -> None:
        for row in self.rows:
            with self.subTest(row=row.label()):
                self.assertTrue(
                    VERSION.findall(row.said),
                    f"{row.label()}: the 'Said' cell names no version, so this "
                    "row is not about the drift this table records",
                )
                self.assertTrue(
                    VERSION.findall(row.now),
                    f"{row.label()}: the 'Now says' cell names no version",
                )

    def test_every_row_resolves_at_the_anchor(self) -> None:
        for row in self.rows:
            with self.subTest(row=row.label()):
                lines = lines_at(ANCHOR_COMMIT, row.path)
                self.assertTrue(
                    lines,
                    f"{row.label()}: {row.path} does not exist at the anchor "
                    f"{ANCHOR_COMMIT[:7]}",
                )
                self.assertLessEqual(
                    row.last,
                    len(lines),
                    f"{row.label()}: the anchor commit's {row.path} has only "
                    f"{len(lines)} lines",
                )

    def test_every_row_quotes_text_present_on_the_cited_lines(self) -> None:
        """The check a HEAD-relative habit breaks: line 20 is not line 21."""
        for row in self.rows:
            with self.subTest(row=row.label()):
                lines = lines_at(ANCHOR_COMMIT, row.path)
                if not lines:
                    self.fail(f"{row.label()}: nothing to quote at {ANCHOR_COMMIT[:7]}")
                segment = "\n".join(lines[row.first - 1 : row.last])
                missing = sorted(set(VERSION.findall(row.said)) - set(VERSION.findall(segment)))
                self.assertFalse(
                    missing,
                    f"{row.label()} quotes {', '.join(missing)} as the text it "
                    f"replaced, but {ANCHOR_COMMIT[:7]}:{row.path} lines "
                    f"{row.first}-{row.last} do not contain it:\n    {segment}",
                )

    def test_every_row_states_a_correction_the_cited_lines_carry(self) -> None:
        """``Now says`` is about these lines, not about the file in general."""
        for row in self.rows:
            with self.subTest(row=row.label()):
                current = ROOT / row.path
                self.assertTrue(
                    current.is_file(),
                    f"{row.label()}: {row.path} is gone from this branch, so the "
                    "correction the row records is nowhere",
                )
                yesterday = "\n".join(
                    lines_at(ANCHOR_COMMIT, row.path)[row.first - 1 : row.last]
                )
                already = sorted(
                    set(VERSION.findall(row.now)) & set(VERSION.findall(yesterday))
                )
                self.assertFalse(
                    already,
                    f"{row.label()} claims {row.path} now says {', '.join(already)}, "
                    f"but it said so on the cited lines at {ANCHOR_COMMIT[:7]} "
                    "already: the row records no correction there",
                )
                lines = current.read_text(encoding="utf-8").splitlines()
                cited = correction_lines(ANCHOR_COMMIT, row.path, row.first, row.last)
                self.assertTrue(
                    cited,
                    f"{row.label()}: the cited lines were deleted between "
                    f"{ANCHOR_COMMIT[:7]} and HEAD with nothing added within "
                    f"{EDIT_HORIZON} lines, so the correction this row records "
                    "has no line to sit on",
                )
                region = "\n".join(
                    lines[number - 1] for number in cited if number <= len(lines)
                )
                elsewhere = sorted(
                    set(VERSION.findall(row.now)) - set(VERSION.findall(region))
                )
                self.assertFalse(
                    elsewhere,
                    f"{row.label()} claims the cited lines now say "
                    f"{', '.join(elsewhere)}, but the lines they became -- "
                    f"{', '.join(str(number) for number in cited[:12])}"
                    f"{', …' if len(cited) > 12 else ''} at HEAD -- do not "
                    "contain it.  A version that appears elsewhere in the file "
                    f"is not a correction of this citation:\n    {region[:600]}",
                )

    def test_the_successor_region_stays_within_the_documented_bound(self) -> None:
        """Assert the numbers the docstring quotes about what (f) does not bound.

        ``Now says`` is checked against the block the diff *replaced*, not against
        the citation's own line: the region is as wide as that block, and it can
        sit either side of where the cited line landed.  Those two measurements
        are constants in this module and repeated in the docstring; if a change to
        the table or to the files moves them, this test fails and the docstring has
        to move with them.
        """
        widest = 0
        furthest = 0
        for row in self.rows:
            with self.subTest(row=row.label()):
                hunks = hunks_between(ANCHOR_COMMIT, row.path)
                anchor = landed_line(hunks, row.first)
                self.assertIsNotNone(
                    anchor,
                    f"{row.label()}: the diff deleted the cited line, so there is "
                    "no position to measure the region against",
                )
                region = correction_lines(ANCHOR_COMMIT, row.path, row.first, row.last)
                widest = max(widest, len(region))
                furthest = max(furthest, *(abs(number - anchor) for number in region))
        self.assertEqual(
            widest,
            WIDEST_REGION,
            f"the widest successor region is now {widest} lines, not the "
            f"{WIDEST_REGION} the docstring quotes; re-measure and update both",
        )
        self.assertEqual(
            furthest,
            FURTHEST_OFFSET,
            f"a successor region now reaches {furthest} lines from its citation, "
            f"not the {FURTHEST_OFFSET} the docstring quotes; re-measure and "
            "update both",
        )


class WorkflowTests(unittest.TestCase):
    """The guard's own input is history, and CI is the only place that guarantees it.

    Nothing else in the suite reads ``tests.yml``, so deleting ``fetch-depth: 0``
    from it left every job green while the guard skipped in silence -- a guard
    that always skips is a guard that never runs.  This test is deliberately not
    an :class:`AnchorGuard`: it has to run in the checkout that has no anchor,
    which is the one where the answer matters.
    """

    def setUp(self) -> None:
        skip_without([".github/workflows/tests.yml"])

    def test_every_checkout_in_ci_fetches_full_history(self) -> None:
        steps = checkout_steps(WORKFLOW.read_text(encoding="utf-8"))
        self.assertTrue(
            steps,
            f"{WORKFLOW.relative_to(ROOT)} has no {CHECKOUT} step any more; this "
            "test guards the guard's input and cannot do that without one",
        )
        for number, block in steps:
            with self.subTest(line=number):
                self.assertIn(
                    "fetch-depth: 0",
                    block,
                    f"{WORKFLOW.relative_to(ROOT)}:{number} checks out without "
                    "`fetch-depth: 0`, so tools/test_audit_citations.py cannot "
                    "resolve its anchor there and skips instead of checking the "
                    "table.  Add `with:` and `fetch-depth: 0` to that step.  "
                    f"Step:\n{block}",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
