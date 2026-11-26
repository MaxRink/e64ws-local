"""Which inputs a suite needs, and how their absence is reported.

This repository is the source of a published subset: ``tools/public_export.py``
copies the paths whose class verdict is ``publish`` and withholds everything
else.  A test that reads a withheld path therefore has two lives -- it has its
input here, and it has none in the subset.  The honest report in the subset is a
documented skip that names the path: a failure would read as a regression that
nobody introduced, and silence would read as a green run.

The module makes that decision once, for both callers:

* ``tools/run_tests.py`` asks :func:`missing` before it starts a suite, so a
  suite whose input is absent is reported as ``SKIP`` rather than ``ERROR``.
* A test module asks :func:`skip_without` from ``setUpModule`` or
  ``setUpClass``, so only the tests that actually read the withheld path skip.

The guard that stops this from hiding real rot is that a skip is only reachable
by *declaring* the input and finding it *absent*.  Nothing here catches an
exception: a module whose input is present runs its assertions unchanged, and a
test that errors while its input is present still fails.  ``Skips`` is
deliberately a narrow, declarative type for the same reason -- there is no
``skip on error`` path to reach for.

The invariant is that this file can only ever *excuse an absence*.  It has no
way to turn a failure into a skip: callers ask it a question about a path and
act on the answer before running anything.
"""

from __future__ import annotations

import unittest
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Why a declared input can be absent from a published subset.  Keyed by path
# prefix and written once, so every skip says the same thing about the same
# area.  A path that matches nothing still skips; it just does not get to claim
# a reason it cannot support.
AREA_REASONS: tuple[tuple[str, str], ...] = (
    ("docs/", "the export gate withholds docs/ as research prose"),
    ("firmware/", "the export gate withholds firmware/ as vendor material"),
    ("captures/", "the export gate withholds captures/ as recorded evidence"),
    ("decaid/", "the decaid plugin is a separate, unvendored checkout"),
    (".tools/", "the export gate withholds .tools/ as machine-local tooling"),
)

DEFAULT_REASON = "it is withheld from the published subset"


def area_reason(path: str) -> str:
    """The one sentence explaining why ``path`` can be absent."""
    for prefix, reason in AREA_REASONS:
        if path.startswith(prefix):
            return reason
    return DEFAULT_REASON


@dataclass(frozen=True)
class Requirement:
    """A path a caller declares it needs, and whether this checkout carries it."""

    path: str
    reason: str
    present: bool

    def as_reason(self) -> str:
        return f"{self.path} is not carried by this checkout: {self.reason}"


def inspect(path: str, *, root: Path = ROOT) -> Requirement:
    """Resolve one declared path against this checkout."""
    return Requirement(path, area_reason(path), (Path(root) / path).exists())


def missing(paths: Iterable[str], *, root: Path = ROOT) -> Requirement | None:
    """The first declared input this checkout does not carry, or ``None``."""
    for path in paths:
        requirement = inspect(path, root=root)
        if not requirement.present:
            return requirement
    return None


def skip_without(paths: Iterable[str], *, root: Path = ROOT) -> None:
    """Skip the calling test, class or module if a declared input is absent.

    Call it from ``setUpModule`` to skip a whole module, or from ``setUpClass``
    to skip one class.  It runs every declared path, so the message names the
    first one that is missing and says nothing about the rest.
    """
    requirement = missing(paths, root=root)
    if requirement is not None:
        raise unittest.SkipTest(requirement.as_reason())
