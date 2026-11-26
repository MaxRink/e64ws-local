#!/usr/bin/env python3
"""The unlock-tier contract, tested as a contract.

``tools/unlock_tiers.py`` claims four tiers, three adjacent boundaries and two
properties.  This suite is the proof, one test per claim:

* **one test per tier** — ``stock``, ``dev``, ``root`` and ``root-custom-api``
  each get a fact set that only they can produce;
* **one boundary test per adjacent pair** — ``stock|dev`` (the 14-token
  ``/etc/issue`` profile, and the module answering at all), ``dev|root`` (the
  owner channel) and ``root|root+custom-api`` (the runner's sudoers rule, or an
  ``action_*`` answer).  Each boundary test flips exactly one fact;
* **the unknown case** — no tier supported, and the genuinely ambiguous
  observation (HTTP 500 on the read routes, which a stock image without the
  module and a development image without the module answer identically);
* **the unreviewed responder** — a document that is not the reviewed module,
  carrying every marker it could carry, must stay ``unknown``: nothing may raise
  the tier without the reviewed schema (``UnreviewedResponderTests``);
* **two properties** — a device reporting dev is never classified stock, and a
  device answering ``action_*`` through the reviewed module for the owner token
  is never classified below ``root-custom-api``;
* **the mutation proof** — every one of those tests is re-run against an
  inverted rule and must fail there;
* **the consumer** — ``E64DecaidAdapter.unlock_tier()`` is the first caller of
  ``detect()`` that is not a fixture.  Five classes pin that it *calls* the
  detector rather than re-deriving a tier, that each of the five outcomes
  arrives through it, that an unreachable or unreviewed responder stays
  ``unknown``, and that a fact the adapter cannot justify is passed absent
  (``AdapterWiringTests``, ``AdapterOutcomeTests``, ``AdapterUnknownTests``,
  ``AdapterFactHonestyTests``, ``ProbeTransportTests``).

What the inversions catch, and what they do not: the ``_decide`` substitutions
are *double* inversions, because the mock keeps the original function and calls
it with the arguments exchanged.  A real reordering inside ``_decide`` therefore
cancels out and these proofs cannot see it — the property tests can, and do
(``docs/UNLOCK_TIERS.md`` §8).  What these proofs catch is a signal that is
ignored, mis-supplied or numbered wrong, and a test that stops noticing that
stops passing this file.

89 tests. Nothing here touches a device, a socket or a file outside this
repository.
"""

from __future__ import annotations

import ast
import io
import json
import unittest
import urllib.error
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "UNLOCK_TIERS.md"
MODULE = ROOT / "tools" / "unlock_tiers.py"
PHP_MODULE = ROOT / "ondevice" / "rest_api_dev.php"
OPENAPI = ROOT / "docs" / "openapi" / "local-api.yaml"

from tools.required_inputs import skip_without  # noqa: E402  (ROOT is on sys.path)

from integrations.decaid.e64ws_adapter import (  # noqa: E402  (one consumer surface)
    ActionProbe,
    DecaidCapabilityPolicy,
    E64DecaidAdapter,
    LocalObservations,
    UnlockTierReport,
)
from tools import unlock_tiers  # noqa: E402  (path is set by the suite runner)
from tools.e64ws_api import E64LocalAPI, E64WSAPIError  # noqa: E402
from tools.unlock_tiers import (  # noqa: E402
    ACTION_META_ROUTES,
    DEV_TOKEN,
    DEV_TOKEN_COUNT,
    READ_ROUTES,
    TIER_DEV,
    TIER_ROOT,
    TIER_ROOT_CUSTOM_API,
    TIER_STOCK,
    TIER_UNKNOWN,
    TIERS,
    at_least,
    detect,
    facts_from_capabilities,
    issue_is_development,
    issue_tokens,
    rank,
)

# --- Fixtures --------------------------------------------------------------------

#: The image this repository analyses ships with ``custom`` in token 0 and 14
#: tokens on the line, so the count alone does not unlock anything.
SHIPPED_ISSUE = (
    "custom image, VERSION: HEM-HSG.140-git-g273ab65 "
    "(built through jenkins@36a955b69793 on Tue, 23 Jun 2026 11:02:11 +0000)"
)
#: The same line with token 0 replaced: the documented unlock recipe.
DEVELOPMENT_ISSUE = SHIPPED_ISSUE.replace("custom image", "development image", 1)
#: One word only.  The important negative control: substring matching is not
#: enough, the parser demands exactly 14 tokens.
ONE_WORD_ISSUE = "development"
#: ``develop`` is not ``development``.
DEVELOP_ISSUE = SHIPPED_ISSUE.replace("custom image", "develop image", 1)
#: ``development`` present but not in token 0, and 14 tokens.
MISPLACED_ISSUE = (
    "custom development image, VERSION: HEM-HSG.140-git-g273ab65 "
    "(built through jenkins@36a955b69793 Tue, 23 Jun 2026 11:02:11 +0000)"
)

#: The reviewed ``capabilities`` document, reduced to the facts that matter.
DEV_SCHEMA = {
    "schema": "e64local-api-v1",
    "apiVersion": "1",
    "routes": [
        "alert_log",
        "capabilities",
        "config",
        "file",
        "grind_log",
        "machine",
        "portafilters",
        "recipes",
        "service_log",
        "settings",
        "ws_token",
    ],
}


def thirteen(issue: str) -> str:
    """The same line with one token fewer, keeping token 0."""
    return " ".join(issue.split()[: DEV_TOKEN_COUNT - 1])


def fifteen(issue: str) -> str:
    """The same line with one token more, keeping token 0."""
    return issue + " extra"


def dev_api(**overrides: Any) -> dict[str, Any]:
    """The facts of a dev image whose module answered."""
    api: dict[str, Any] = {"reached": True, "status": 200, **DEV_SCHEMA}
    api.update(overrides)
    return api


def facts(
    *,
    issue: str | None = None,
    channel: bool | None = None,
    api: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """A fact set with only the observations the caller names."""
    built: dict[str, Any] = {}
    if api is not None:
        built["api"] = dict(api)
    if issue is not None or channel is not None:
        built["root"] = {"issue": issue, "channel": channel}
    return built


def tier(fact_set: Mapping[str, Any] | None = None) -> str:
    """The tier, asserting the document shape on the way through."""
    verdict = detect(fact_set)
    assert set(verdict) == {"tier", "evidence", "reasons"}, verdict
    return str(verdict["tier"])


#: The module's own decision point, captured before any test patches it.
ORIGINAL_DECIDE = unlock_tiers._decide


def swapped_decide(dev: bool, stock: bool, root: bool, custom_api: bool) -> str:
    """The rule with the dev and stock signals exchanged."""
    return ORIGINAL_DECIDE(stock, dev, root, custom_api)


def ignored_custom_decide(dev: bool, stock: bool, root: bool, custom_api: bool) -> str:
    """The rule with the top tier switched off."""
    return ORIGINAL_DECIDE(dev, stock, root, False)


def ignored_root_decide(dev: bool, stock: bool, root: bool, custom_api: bool) -> str:
    """The rule with the root signal switched off."""
    return ORIGINAL_DECIDE(dev, stock, False, custom_api)


def root_outranks_custom_decide(dev: bool, stock: bool, root: bool, custom_api: bool) -> str:
    """The rule with root outranking the top tier."""
    return TIER_ROOT if root else ORIGINAL_DECIDE(dev, stock, root, custom_api)


def stock_outranks_dev_decide(dev: bool, stock: bool, root: bool, custom_api: bool) -> str:
    """The rule with a stock signal beating a dev signal."""
    return ORIGINAL_DECIDE(dev and not stock, stock, root, custom_api)


class Inverted(unittest.TestCase):
    """Base class: run a rule under an inversion, restoring it afterwards."""

    def decide_under(self, inversion: Any) -> Any:
        return mock.patch.object(unlock_tiers, "_decide", inversion)

    def tier_under(self, inversion: Any, fact_set: Mapping[str, Any] | None = None) -> str:
        with self.decide_under(inversion):
            return tier(fact_set)


# --- The /etc/issue predicate ----------------------------------------------------


class IssueGateTests(unittest.TestCase):
    """The 14-token rule on its own, before any tier is involved."""

    def test_the_fixtures_are_the_documented_shapes(self) -> None:
        # Guards the fixtures themselves: a typo here would silently turn a
        # boundary test into a test of nothing.
        self.assertEqual(len(issue_tokens(DEVELOPMENT_ISSUE)), DEV_TOKEN_COUNT)
        self.assertEqual(len(issue_tokens(SHIPPED_ISSUE)), DEV_TOKEN_COUNT)
        self.assertEqual(len(issue_tokens(MISPLACED_ISSUE)), DEV_TOKEN_COUNT)
        self.assertEqual(len(issue_tokens(thirteen(DEVELOPMENT_ISSUE))), DEV_TOKEN_COUNT - 1)
        self.assertEqual(len(issue_tokens(fifteen(DEVELOPMENT_ISSUE))), DEV_TOKEN_COUNT + 1)

    def test_only_the_first_line_counts(self) -> None:
        self.assertTrue(issue_is_development(DEVELOPMENT_ISSUE))
        # A dev word on a later line is not token 0 of the line the device reads.
        self.assertFalse(issue_is_development(SHIPPED_ISSUE + "\n" + DEVELOPMENT_ISSUE))
        # ... and the first line may end in CRLF, as a copy from a Unix file can.
        self.assertTrue(issue_is_development(DEVELOPMENT_ISSUE + "\r\nsecond line"))

    def test_token_zero_is_compared_case_insensitively(self) -> None:
        upper = DEVELOPMENT_ISSUE.replace("development image", "DEVELOPMENT image", 1)
        mixed = DEVELOPMENT_ISSUE.replace("development image", "DeVeLoPmEnT image", 1)
        self.assertTrue(issue_is_development(upper))
        self.assertTrue(issue_is_development(mixed))
        # Inversion: the token is compared as written, so the vendor's
        # Qt::CaseInsensitive comparison is no longer modelled and the
        # upper-case line stops unlocking.
        with mock.patch.object(unlock_tiers, "token_is_development", lambda token: token == DEV_TOKEN):
            self.assertTrue(issue_is_development(DEVELOPMENT_ISSUE))
            self.assertFalse(issue_is_development(upper))

    def test_an_absent_or_wrong_typed_line_is_not_a_dev_line(self) -> None:
        for value in (None, "", "   ", 14, ["development"], {"issue": "development"}):
            with self.subTest(value=value):
                self.assertFalse(issue_is_development(value))


# --- One test per tier -----------------------------------------------------------


class TierTests(unittest.TestCase):
    def test_stock_from_the_shipped_issue_line(self) -> None:
        self.assertEqual(tier(facts(issue=SHIPPED_ISSUE)), TIER_STOCK)

    def test_stock_from_the_dev_gate_refusing(self) -> None:
        blocked = facts(api={"reached": True, "status": 403, "error_code": 403})
        self.assertEqual(tier(blocked), TIER_STOCK)
        verdict = detect(blocked)
        self.assertTrue(verdict["evidence"]["devGateRefused"])
        self.assertFalse(verdict["evidence"]["modulePresent"])
        self.assertIn("dev gate", " ".join(verdict["reasons"]))

    def test_dev_from_the_issue_line(self) -> None:
        self.assertEqual(tier(facts(issue=DEVELOPMENT_ISSUE)), TIER_DEV)

    def test_dev_from_the_module_answering(self) -> None:
        self.assertEqual(tier(facts(api=dev_api())), TIER_DEV)
        # A 401 on its own is not this tier: see UnreviewedResponderTests.
        unauthorized = facts(api={"reached": True, "status": 401, "error_code": 401})
        self.assertEqual(tier(unauthorized), TIER_UNKNOWN)

    def test_root_from_the_channel_alone(self) -> None:
        rooted = facts(channel=True, issue=SHIPPED_ISSUE)
        self.assertEqual(tier(rooted), TIER_ROOT)
        verdict = detect(rooted)
        self.assertEqual(verdict["evidence"]["unseparated"], [TIER_ROOT_CUSTOM_API])

    def test_root_custom_api_from_the_whole_deployment(self) -> None:
        deployed = facts(channel=True, issue=DEVELOPMENT_ISSUE, api=dev_api(sudoers=True))
        self.assertEqual(tier(deployed), TIER_ROOT_CUSTOM_API)
        verdict = detect(deployed)
        self.assertEqual(verdict["evidence"]["unseparated"], [])
        self.assertEqual(verdict["evidence"]["moduleMarkers"][0], "schema")

    def test_root_custom_api_from_an_action_answering(self) -> None:
        # The owner's property, as a positive case: one action_* answer with the
        # owner token is enough, and no root channel has to be observed.
        answered = facts(api=dev_api(action_answered=True))
        self.assertEqual(tier(answered), TIER_ROOT_CUSTOM_API)
        self.assertIn("action_*", " ".join(detect(answered)["reasons"]))


# --- Boundary tests, one per adjacent pair ---------------------------------------

class StockToDevBoundaryTests(Inverted):
    """``stock|dev`` — the 14-token profile, and the module answering at all."""

    def test_the_issue_line_flips_the_boundary(self) -> None:
        self.assertEqual(tier(facts(issue=SHIPPED_ISSUE)), TIER_STOCK)
        self.assertEqual(tier(facts(issue=DEVELOPMENT_ISSUE)), TIER_DEV)

        # Inversion: token 0 is compared against ``custom``, which swaps the two.
        with mock.patch.object(unlock_tiers, "DEV_TOKEN", "custom"):
            self.assertNotEqual(tier(facts(issue=SHIPPED_ISSUE)), TIER_STOCK)
            self.assertNotEqual(tier(facts(issue=DEVELOPMENT_ISSUE)), TIER_DEV)

    def test_the_token_count_flips_the_boundary(self) -> None:
        self.assertEqual(tier(facts(issue=DEVELOPMENT_ISSUE)), TIER_DEV)
        self.assertEqual(tier(facts(issue=thirteen(DEVELOPMENT_ISSUE))), TIER_STOCK)
        self.assertEqual(tier(facts(issue=fifteen(DEVELOPMENT_ISSUE))), TIER_STOCK)

        # Inversion: the parser demands 13 tokens.  Both directions must break.
        with mock.patch.object(unlock_tiers, "DEV_TOKEN_COUNT", DEV_TOKEN_COUNT - 1):
            self.assertNotEqual(tier(facts(issue=DEVELOPMENT_ISSUE)), TIER_DEV)
            self.assertNotEqual(tier(facts(issue=thirteen(DEVELOPMENT_ISSUE))), TIER_STOCK)

    def test_the_first_token_flips_the_boundary(self) -> None:
        self.assertEqual(tier(facts(issue=DEVELOPMENT_ISSUE)), TIER_DEV)
        self.assertEqual(tier(facts(issue=DEVELOP_ISSUE)), TIER_STOCK)
        self.assertEqual(tier(facts(issue=ONE_WORD_ISSUE)), TIER_STOCK)
        self.assertEqual(tier(facts(issue=MISPLACED_ISSUE)), TIER_STOCK)

        # Inversion: a prefix match instead of an exact one, so ``develop``
        # would unlock and the boundary would move.
        with mock.patch.object(unlock_tiers, "DEV_TOKEN", "develop"):
            self.assertNotEqual(tier(facts(issue=DEVELOP_ISSUE)), TIER_STOCK)

    def test_the_module_answering_flips_the_boundary(self) -> None:
        refused = facts(api={"reached": True, "status": 403, "error_code": 403})
        answered = facts(api=dev_api())
        absent = facts(api={"reached": True, "status": 404})
        self.assertEqual(tier(refused), TIER_STOCK)
        self.assertEqual(tier(answered), TIER_DEV)
        # A route the vendor dispatcher does not know is the module being
        # absent, which is stock once the image is known not to be dev.
        self.assertEqual(tier({**absent, "root": {"issue": SHIPPED_ISSUE}}), TIER_STOCK)

        # Inversion: dev and stock exchanged, so a 403 would read as dev.
        self.assertNotEqual(self.tier_under(swapped_decide, refused), TIER_STOCK)
        self.assertNotEqual(self.tier_under(swapped_decide, answered), TIER_DEV)


class DevToRootBoundaryTests(Inverted):
    """``dev|root`` — the owner channel, and nothing on the REST/WSS surface."""

    def test_the_root_channel_flips_the_boundary(self) -> None:
        base = dict(issue=DEVELOPMENT_ISSUE, api=dev_api())
        self.assertEqual(tier(facts(channel=False, **base)), TIER_DEV)
        self.assertEqual(tier(facts(channel=None, **base)), TIER_DEV)
        self.assertEqual(tier(facts(channel=True, **base)), TIER_ROOT)

        # Inversion: the root signal is switched off, so the channel stops
        # separating the pair and dev would be reported with root present.
        self.assertNotEqual(self.tier_under(ignored_root_decide, facts(channel=True, **base)), TIER_ROOT)

    def test_a_channel_that_refused_does_not_promote_the_device(self) -> None:
        refused = facts(channel=False, issue=DEVELOPMENT_ISSUE)
        verdict = detect(refused)
        self.assertEqual(verdict["tier"], TIER_DEV)
        # ``False`` is an observation: it rules the root tier out.
        self.assertNotIn(TIER_ROOT, verdict["evidence"]["unseparated"])

    def test_an_unobserved_channel_is_not_a_refused_one(self) -> None:
        # The three-state rule: ``None`` must never collapse into ``False``.
        unobserved = detect(facts(issue=DEVELOPMENT_ISSUE))
        self.assertEqual(unobserved["tier"], TIER_DEV)
        self.assertIn(TIER_ROOT, unobserved["evidence"]["unseparated"])
        self.assertIsNone(unobserved["evidence"]["rootChannel"])


class RootToCustomApiBoundaryTests(Inverted):
    """``root|root+custom-api`` — the runner rule, or an action answering."""

    def rooted(self, **api: Any) -> dict[str, Any]:
        return facts(channel=True, issue=DEVELOPMENT_ISSUE, api=dev_api(**api))

    def test_the_runner_rule_flips_the_boundary(self) -> None:
        self.assertEqual(tier(self.rooted(sudoers=False)), TIER_ROOT)
        self.assertEqual(tier(self.rooted(sudoers=None)), TIER_ROOT)
        self.assertEqual(tier(self.rooted(sudoers=True)), TIER_ROOT_CUSTOM_API)

        # Inversion: the top tier is switched off, so the sudoers rule would
        # stop being the thing that separates root from root-custom-api.
        self.assertNotEqual(
            self.tier_under(ignored_custom_decide, self.rooted(sudoers=True)),
            TIER_ROOT_CUSTOM_API,
        )

    def test_an_action_answering_flips_the_boundary(self) -> None:
        self.assertEqual(tier(facts(api=dev_api(action_answered=False))), TIER_DEV)
        self.assertEqual(tier(facts(api=dev_api(action_answered=True))), TIER_ROOT_CUSTOM_API)

        self.assertNotEqual(
            self.tier_under(ignored_custom_decide, facts(api=dev_api(action_answered=True))),
            TIER_ROOT_CUSTOM_API,
        )

    def test_root_does_not_outrank_the_top_tier(self) -> None:
        deployed = self.rooted(sudoers=True)
        self.assertEqual(tier(deployed), TIER_ROOT_CUSTOM_API)
        # Inversion: root wins, so the top tier becomes unreachable from a
        # rooted device — which is the state this repository builds.
        self.assertNotEqual(
            self.tier_under(root_outranks_custom_decide, deployed), TIER_ROOT_CUSTOM_API
        )

    def test_the_top_tier_flags_the_sudoers_contradiction(self) -> None:
        # An action_* answer without a 503 is what the runner rule makes
        # possible, so a report that also says the rule is absent is
        # contradictory.  The tier must not drop — the answer wins — but the
        # reason must say so instead of claiming the rule ran.
        contradictory = facts(api=dev_api(action_answered=True, sudoers=False))
        verdict = detect(contradictory)
        self.assertEqual(verdict["tier"], TIER_ROOT_CUSTOM_API)
        joined = " ".join(verdict["reasons"])
        self.assertIn("disagree", joined)
        self.assertIn("sudoers", joined)

    def test_the_top_tier_states_what_it_still_does_not_grant(self) -> None:
        verdict = detect(self.rooted(sudoers=True, actions_enabled=False))
        self.assertEqual(verdict["tier"], TIER_ROOT_CUSTOM_API)
        joined = " ".join(verdict["reasons"])
        self.assertIn("action gate is closed", joined)
        self.assertIn("destructive", joined)


# --- The unknown case ------------------------------------------------------------

class UnknownTests(unittest.TestCase):
    def test_no_facts_at_all(self) -> None:
        verdict = detect()
        self.assertEqual(verdict["tier"], TIER_UNKNOWN)
        self.assertTrue(verdict["reasons"])
        self.assertEqual(verdict["evidence"]["unseparated"], list(TIERS))

    def test_the_ambiguous_500_on_the_read_routes(self) -> None:
        # A stock image without the module and a development image without the
        # module answer identically.  Guessing here would be the bug.
        ambiguous = facts(api={"reached": True, "status": 500, "read_routes_ok": False})
        verdict = detect(ambiguous)
        self.assertEqual(verdict["tier"], TIER_UNKNOWN)
        joined = " ".join(verdict["reasons"])
        self.assertIn("does not settle which image", joined)
        self.assertIn("read routes", joined)
        self.assertFalse(verdict["evidence"]["modulePresent"])
        self.assertFalse(verdict["evidence"]["moduleAbsent"])

    def test_a_500_becomes_decidable_with_one_more_observation(self) -> None:
        base = {"reached": True, "status": 500, "read_routes_ok": False}
        self.assertEqual(tier(facts(api=base, issue=DEVELOPMENT_ISSUE)), TIER_DEV)
        self.assertEqual(tier(facts(api=base, issue=SHIPPED_ISSUE)), TIER_STOCK)
        self.assertEqual(tier(facts(api=base, channel=True, issue=DEVELOPMENT_ISSUE)), TIER_ROOT)

    def test_an_unreviewed_responder_proves_nothing(self) -> None:
        vendor = facts(api={"reached": True, "status": 200, "schema": "vendor-api-v9"})
        verdict = detect(vendor)
        self.assertEqual(verdict["tier"], TIER_UNKNOWN)
        self.assertIn("not a reviewed module schema", " ".join(verdict["reasons"]))

    def test_a_silent_device_is_unknown_not_stock(self) -> None:
        silent = facts(api={"reached": False})
        self.assertEqual(tier(silent), TIER_UNKNOWN)
        self.assertTrue(detect(silent)["evidence"]["moduleAbsent"])
        # Even a definitive "no module" needs the image fact to name a tier.
        self.assertEqual(tier(facts(api={"reached": False}, issue=SHIPPED_ISSUE)), TIER_STOCK)


# --- An unreviewed responder proves nothing --------------------------------------

#: A schema that is not the reviewed module.  Everything else in these documents
#: is exactly what the reviewed module would say, which is the point: any local
#: PHP page can say it.
UNREVIEWED_SCHEMA = "vendor-api-v9"


def unreviewed(**api: Any) -> dict[str, Any]:
    """A fact set whose only responder identifies itself as something else."""
    base: dict[str, Any] = {"reached": True, "status": 200, "schema": UNREVIEWED_SCHEMA}
    base.update(api)
    return facts(api=base)


class UnreviewedResponderTests(unittest.TestCase):
    """Only the reviewed schema may raise the tier.

    Every marker the detector can use — routes, ``apiVersion``, the action
    gates, an ``action_*`` answer — is trivially reproducible by anything that
    can answer HTTP on the device.  Accepting one from an unidentified responder
    would let a stranger's 200 raise the tier, which is the opposite of what
    this module is for.  The gate is therefore on the schema, once, and these
    are its regression tests.
    """

    def test_the_reviewers_document_is_unknown(self) -> None:
        document = {
            "success": True,
            "data": {
                "schema": UNREVIEWED_SCHEMA,
                "apiVersion": "1",
                "routes": ["capabilities", "action_prepare"],
                "features": {"actions": True},
            },
        }
        verdict = detect(facts_from_capabilities(document, status=200))
        self.assertEqual(verdict["tier"], TIER_UNKNOWN)
        self.assertEqual(verdict["evidence"]["moduleMarkers"], [])
        self.assertFalse(verdict["evidence"]["modulePresent"])
        self.assertIn("not a reviewed module schema", " ".join(verdict["reasons"]))

    def test_each_marker_alone_is_unknown(self) -> None:
        cases: dict[str, dict[str, Any]] = {
            "routes only": unreviewed(routes=["capabilities", "action_prepare"]),
            "apiVersion only": unreviewed(api_version="1"),
            "actions_enabled only": unreviewed(actions_enabled=True),
            "destructive only": unreviewed(actions_enabled=True, destructive_actions=True),
            "action_answered only": unreviewed(action_answered=True),
            "sudoers only": unreviewed(sudoers=True),
        }
        for name, fact_set in cases.items():
            with self.subTest(marker=name):
                verdict = detect(fact_set)
                self.assertEqual(verdict["tier"], TIER_UNKNOWN, name)
                self.assertEqual(verdict["evidence"]["moduleMarkers"], [], name)

    def test_no_marker_can_reach_the_top_tier_unreviewed(self) -> None:
        # The strongest possible claim from a stranger: everything at once, plus
        # a root channel and a runner rule.
        stranger = unreviewed(
            api_version="1",
            routes=["capabilities", "action_prepare"],
            actions_enabled=True,
            destructive_actions=True,
            action_answered=True,
            sudoers=True,
        )
        stranger["root"] = {"issue": DEVELOPMENT_ISSUE, "channel": True}
        verdict = detect(stranger)
        self.assertNotEqual(verdict["tier"], TIER_ROOT_CUSTOM_API)
        self.assertNotEqual(verdict["tier"], TIER_DEV)
        # The issue line and the channel are the caller's own observations, so
        # the tier is the strongest thing *they* saw: root.
        self.assertEqual(verdict["tier"], TIER_ROOT)

    def test_a_reviewed_schema_still_raises_the_tier(self) -> None:
        # The positive control: the gate must not be so tight that the legitimate
        # path stops working.  Same facts, reviewed schema.
        reviewed = dev_api(actions_enabled=True)
        self.assertEqual(tier(facts(api=reviewed)), TIER_DEV)
        self.assertEqual(
            tier(facts(api=dev_api(action_answered=True))), TIER_ROOT_CUSTOM_API
        )
        self.assertEqual(
            tier(facts(channel=True, api=dev_api(sudoers=True))), TIER_ROOT_CUSTOM_API
        )

    def test_a_bare_401_does_not_raise_the_tier(self) -> None:
        # 401 is the module's owner-token check, which only runs after the dev
        # gate — but an unidentified responder can say 401 too, and without the
        # reviewed schema the answer cannot be attributed.  The reason must say
        # what to do instead.
        verdict = detect(facts(api={"reached": True, "status": 401, "error_code": 401}))
        self.assertEqual(verdict["tier"], TIER_UNKNOWN)
        joined = " ".join(verdict["reasons"])
        self.assertIn("401", joined)
        self.assertIn("/etc/issue", joined)


# --- The two properties ----------------------------------------------------------

ISSUES: tuple[str | None, ...] = (
    None,
    SHIPPED_ISSUE,
    DEVELOPMENT_ISSUE,
    thirteen(DEVELOPMENT_ISSUE),
    ONE_WORD_ISSUE,
    DEVELOP_ISSUE,
    MISPLACED_ISSUE,
)

APIS: tuple[dict[str, Any] | None, ...] = (
    None,
    {"reached": True, "status": 403, "error_code": 403},
    {"reached": True, "status": 404},
    {"reached": True, "status": 500, "read_routes_ok": False},
    {"reached": True, "status": 401, "error_code": 401},
    dev_api(),
    dev_api(actions_enabled=True),
    dev_api(actions_enabled=True, destructive_actions=True),
    dev_api(action_answered=True),
    dev_api(action_answered=False),
    {"reached": True, "status": 200, "schema": "vendor-api-v9"},
)

CHANNELS: tuple[bool | None, ...] = (None, False, True)
SUDOERS: tuple[bool | None, ...] = (None, False, True)


def every_fact_set() -> list[dict[str, Any]]:
    """The cross product of every observation a caller can make."""
    built: list[dict[str, Any]] = []
    for issue in ISSUES:
        for api in APIS:
            for channel in CHANNELS:
                for sudoers in SUDOERS:
                    api_facts = dict(api) if api is not None else None
                    if api_facts is not None and sudoers is not None:
                        api_facts["sudoers"] = sudoers
                    built.append(
                        {
                            "api": api_facts or {},
                            "root": {"issue": issue, "channel": channel},
                        }
                    )
    return built


def has_dev_signal(fact_set: Mapping[str, Any]) -> bool:
    """True when the facts contain a signal only a dev image can produce."""
    api = fact_set.get("api") or {}
    root = fact_set.get("root") or {}
    return unlock_tiers.issue_is_development(root.get("issue")) or bool(
        unlock_tiers._module_markers(api)
    )


class PropertyTests(Inverted):
    """The two properties the tier order exists to guarantee."""

    def test_property_dev_is_never_stock(self) -> None:
        checked = 0
        for fact_set in every_fact_set():
            if not has_dev_signal(fact_set):
                continue
            checked += 1
            with self.subTest(facts=json.dumps(fact_set, sort_keys=True)):
                verdict = detect(fact_set)
                self.assertNotEqual(verdict["tier"], TIER_STOCK)
                self.assertTrue(at_least(verdict["tier"], TIER_DEV) or verdict["tier"] == TIER_UNKNOWN)
        self.assertGreater(checked, 0, "the property was never exercised")

    def test_property_dev_is_never_stock_survives_a_contradiction(self) -> None:
        # A dev `/etc/issue` and a 403 cannot both be current, and the tie goes
        # upwards: a device that reported dev must not be reported as stock.
        contradiction = facts(
            issue=DEVELOPMENT_ISSUE, api={"reached": True, "status": 403, "error_code": 403}
        )
        self.assertEqual(tier(contradiction), TIER_DEV)
        # Inversion: the stock signal is allowed to win, and the property breaks.
        self.assertEqual(
            self.tier_under(stock_outranks_dev_decide, contradiction), TIER_STOCK
        )

    def test_property_action_answered_is_never_below_top(self) -> None:
        checked = 0
        for fact_set in every_fact_set():
            api = fact_set.get("api") or {}
            if api.get("action_answered") is not True:
                continue
            checked += 1
            with self.subTest(facts=json.dumps(fact_set, sort_keys=True)):
                verdict = detect(fact_set)
                self.assertEqual(verdict["tier"], TIER_ROOT_CUSTOM_API)
                self.assertTrue(at_least(verdict["tier"], TIER_ROOT_CUSTOM_API))
        self.assertGreater(checked, 0, "the property was never exercised")

    def test_property_adding_a_signal_never_lowers_the_tier(self) -> None:
        # Each upgrade *adds* one positive observation.  None of them may remove
        # one, or this would be testing a downgrade and prove nothing.
        def add_root_channel(fact_set: dict[str, Any]) -> None:
            fact_set.setdefault("root", {})["channel"] = True

        def add_sudoers(fact_set: dict[str, Any]) -> None:
            fact_set.setdefault("api", {})["sudoers"] = True

        def add_module(fact_set: dict[str, Any]) -> None:
            api = fact_set.setdefault("api", {})
            api.setdefault("reached", True)
            api.setdefault("status", 200)
            api.setdefault("schema", "e64local-api-v1")
            api.setdefault("apiVersion", "1")
            api.setdefault("routes", list(READ_ROUTES))

        def add_action_answer(fact_set: dict[str, Any]) -> None:
            fact_set.setdefault("api", {})["action_answered"] = True

        upgrades = (
            ("root channel", add_root_channel),
            ("sudoers rule", add_sudoers),
            ("module answering", add_module),
            ("action answering", add_action_answer),
        )
        for fact_set in every_fact_set():
            base = tier(fact_set)
            base_rank = rank(base)
            for name, upgrade in upgrades:
                stronger = json.loads(json.dumps(fact_set))
                upgrade(stronger)
                new_rank = rank(tier(stronger))
                with self.subTest(facts=base, upgrade=name):
                    if base_rank is None or new_rank is None:
                        continue  # unknown is not a rank, and never a regression
                    self.assertGreaterEqual(new_rank, base_rank)


# --- The inversion proofs, one per rule ------------------------------------------

class MutationTests(Inverted):
    """Every rule in the module is load-bearing, and here is the proof.

    Each test names the rule, asserts the correct answer, then asserts that the
    same assertion *fails* under the matching inversion.  A test that survived
    its inversion would be measuring nothing.
    """

    def test_the_swap_proof_covers_every_boundary_case(self) -> None:
        cases = (
            (facts(issue=SHIPPED_ISSUE), TIER_STOCK),
            (facts(issue=DEVELOPMENT_ISSUE), TIER_DEV),
            (facts(api={"reached": True, "status": 403}), TIER_STOCK),
            (facts(api=dev_api()), TIER_DEV),
        )
        for fact_set, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(tier(fact_set), expected)
                self.assertNotEqual(self.tier_under(swapped_decide, fact_set), expected)

    def test_the_token_count_proof(self) -> None:
        boundary = DEV_TOKEN_COUNT
        self.assertEqual(len(issue_tokens(DEVELOPMENT_ISSUE)), boundary)
        with mock.patch.object(unlock_tiers, "DEV_TOKEN_COUNT", boundary - 1):
            self.assertFalse(issue_is_development(DEVELOPMENT_ISSUE))
            self.assertTrue(issue_is_development(thirteen(DEVELOPMENT_ISSUE)))

    def test_the_first_token_proof(self) -> None:
        self.assertTrue(issue_is_development(DEVELOPMENT_ISSUE))
        self.assertFalse(issue_is_development(MISPLACED_ISSUE))
        with mock.patch.object(unlock_tiers, "DEV_TOKEN", "custom"):
            self.assertTrue(issue_is_development(SHIPPED_ISSUE))

    def test_the_root_signal_proof(self) -> None:
        rooted = facts(channel=True, issue=SHIPPED_ISSUE)
        self.assertEqual(tier(rooted), TIER_ROOT)
        self.assertNotEqual(self.tier_under(ignored_root_decide, rooted), TIER_ROOT)

    def test_the_custom_api_signal_proof(self) -> None:
        deployed = facts(channel=True, issue=DEVELOPMENT_ISSUE, api=dev_api(sudoers=True))
        self.assertEqual(tier(deployed), TIER_ROOT_CUSTOM_API)
        self.assertNotEqual(
            self.tier_under(ignored_custom_decide, deployed), TIER_ROOT_CUSTOM_API
        )

    def test_the_precedence_proof(self) -> None:
        # Each tier must beat every tier below it, or the order means nothing.
        # The inversion is chosen per case, because each tier has exactly one
        # signal that can displace it.
        precedence = (
            (facts(api=dev_api(action_answered=True)), TIER_ROOT_CUSTOM_API, ignored_custom_decide),
            (facts(channel=True, issue=DEVELOPMENT_ISSUE, api=dev_api(sudoers=True)),
             TIER_ROOT_CUSTOM_API, root_outranks_custom_decide),
            (facts(issue=DEVELOPMENT_ISSUE, api=dev_api()), TIER_DEV, swapped_decide),
            (facts(issue=DEVELOPMENT_ISSUE, channel=True), TIER_ROOT, ignored_root_decide),
            (facts(api={"reached": True, "status": 403}), TIER_STOCK, swapped_decide),
        )
        for fact_set, expected, inversion in precedence:
            with self.subTest(expected=expected):
                self.assertEqual(tier(fact_set), expected)
                self.assertNotEqual(self.tier_under(inversion, fact_set), expected)


# --- The document shape the callers depend on ------------------------------------

class DocumentShapeTests(unittest.TestCase):
    def test_the_document_is_serialisable_and_stable(self) -> None:
        base = {"reached": True, "status": 500, "read_routes_ok": False}
        first = detect(facts(issue=DEVELOPMENT_ISSUE, api=base))
        second = detect(facts(issue=DEVELOPMENT_ISSUE, api=base))
        self.assertEqual(first, second)
        self.assertEqual(json.loads(json.dumps(first)), first)
        self.assertEqual(set(first), {"tier", "evidence", "reasons"})
        self.assertIsInstance(first["evidence"]["unseparated"], list)
        self.assertTrue(all(isinstance(reason, str) for reason in first["reasons"]))

    def test_every_returned_tier_is_a_known_name(self) -> None:
        for fact_set in every_fact_set():
            verdict = detect(fact_set)
            self.assertIn(verdict["tier"], TIERS + (TIER_UNKNOWN,))
            for name in verdict["evidence"]["unseparated"]:
                self.assertIn(name, TIERS)

    def test_a_fact_is_never_coerced_from_a_string(self) -> None:
        # "false" is not an observation.  Reading it as one would let a sloppy
        # caller turn "nobody asked" into "the device said no".
        sloppy = facts(api={"reached": True, "status": "403", "actions_enabled": "false"})
        verdict = detect(sloppy)
        self.assertIsNone(verdict["evidence"]["apiStatus"])
        self.assertIsNone(verdict["evidence"]["actionsEnabled"])
        self.assertEqual(verdict["tier"], TIER_UNKNOWN)

    def test_no_credential_or_address_can_appear_in_the_document(self) -> None:
        encoded = json.dumps(detect(facts(issue=DEVELOPMENT_ISSUE, api=dev_api(sudoers=True))))
        for needle in ("secret", "password", "192.168", "PHPSESSID", "grinderSn", "authorization"):
            self.assertNotIn(needle.lower(), encoded.lower())


class PurityTests(unittest.TestCase):
    """The module must stay pure: facts in, verdict out, nothing touched."""

    def test_the_module_imports_nothing_but_typing(self) -> None:
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported, {"__future__", "typing"})

    def test_the_module_calls_no_process_file_or_socket_helper(self) -> None:
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        banned = {
            "open",
            "exec",
            "eval",
            "compile",
            "__import__",
            "system",
            "popen",
            "run",
            "socket",
            "connect",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, banned)
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, banned)


class FactsFromCapabilitiesTests(unittest.TestCase):
    def test_the_envelope_and_the_data_object_agree(self) -> None:
        data = {"schema": "e64local-api-v1", "apiVersion": "1", "features": {"actions": True}}
        envelope = {"success": True, "data": data}
        self.assertEqual(
            facts_from_capabilities(envelope)["api"],
            facts_from_capabilities(data)["api"],
        )

    def test_a_missing_key_stays_missing(self) -> None:
        # A firmware without the action layer must not look like a closed gate.
        api = facts_from_capabilities({"schema": "e64local-api-v1"})["api"]
        self.assertNotIn("actions_enabled", api)
        self.assertNotIn("destructive_actions", api)
        # ... and the absent fact must not become stock.
        self.assertEqual(tier({"api": api}), TIER_DEV)

    def test_the_action_catalog_wins_over_features(self) -> None:
        document = {
            "schema": "e64local-api-v1",
            "features": {"actions": False, "destructiveActions": False},
            "actions": {"enabled": True, "destructiveEnabled": True},
        }
        api = facts_from_capabilities(document)["api"]
        self.assertTrue(api["actions_enabled"])
        self.assertTrue(api["destructive_actions"])

    def test_an_error_envelope_carries_its_code(self) -> None:
        api = facts_from_capabilities(
            {"success": False, "errorCode": 403, "error": "dev mode required"}, status=403
        )["api"]
        self.assertEqual(api["status"], 403)
        self.assertEqual(api["error_code"], 403)
        self.assertEqual(tier({"api": api}), TIER_STOCK)


class SimulatorWiringTests(unittest.TestCase):
    """The wiring is additive, and the real module never grows the key."""

    def setUp(self) -> None:
        from tools.e64ws_simulator import SimulatedLocalApi

        self.api_class = SimulatedLocalApi

    def test_the_key_is_present_and_the_rest_of_the_document_is_untouched(self) -> None:
        document = self.api_class().capabilities()
        self.assertIn("syntheticUnlockTier", document)
        before = self.api_class()._capabilities_document()
        for key, value in before.items():
            self.assertEqual(document[key], value, key)
        self.assertEqual(set(document), set(before) | {"syntheticUnlockTier"})

    def test_the_synthetic_key_carries_the_whole_verdict(self) -> None:
        verdict = self.api_class().capabilities()["syntheticUnlockTier"]
        self.assertEqual(set(verdict), {"tier", "evidence", "reasons"})
        self.assertIn(verdict["tier"], TIERS + (TIER_UNKNOWN,))
        self.assertEqual(verdict["tier"], TIER_DEV)

    def test_the_fixture_switches_move_the_tier(self) -> None:
        stock = self.api_class(dev_gate_open=False).capabilities()
        self.assertEqual(stock["syntheticUnlockTier"]["tier"], TIER_STOCK)

        rooted = self.api_class(actions_enabled=True, synthetic_root_channel=True)
        self.assertEqual(rooted.capabilities()["syntheticUnlockTier"]["tier"], TIER_ROOT_CUSTOM_API)

        dev_with_gate = self.api_class(actions_enabled=True).capabilities()
        self.assertEqual(dev_with_gate["syntheticUnlockTier"]["tier"], TIER_DEV)

    def test_the_fixtures_issue_line_matches_its_tier(self) -> None:
        dev_api_fixture = self.api_class()
        self.assertEqual(len(issue_tokens(dev_api_fixture.read_file("/etc/issue")[1])), DEV_TOKEN_COUNT)
        self.assertTrue(issue_is_development(dev_api_fixture.read_file("/etc/issue")[1]))

        stock_api_fixture = self.api_class(dev_gate_open=False)
        self.assertFalse(issue_is_development(stock_api_fixture.read_file("/etc/issue")[1]))

    def test_the_key_never_reaches_the_real_module_or_its_contract(self) -> None:
        # The contract half of this test reads the published schema, which the
        # gate withholds as research prose.  The module half still runs wherever
        # the module is carried; both run here.
        skip_without(["docs/openapi/local-api.yaml"])
        self.assertNotIn("syntheticUnlockTier", PHP_MODULE.read_text(encoding="utf-8"))
        self.assertNotIn("unlock_tier", PHP_MODULE.read_text(encoding="utf-8"))
        # The published schema declares additionalProperties: false for the real
        # capabilities data, so the synthetic key must not appear there either.
        self.assertNotIn("syntheticUnlockTier", OPENAPI.read_text(encoding="utf-8"))


class VocabularyTests(unittest.TestCase):
    """The detector's vocabulary and the fixture's must not drift apart."""

    def test_the_route_sets_match_the_fixture(self) -> None:
        from tools.e64ws_simulator import ACTION_META_ROUTES as SIM_ACTION_ROUTES
        from tools.e64ws_simulator import SimulatedLocalApi

        self.assertEqual(READ_ROUTES, set(SimulatedLocalApi.ROUTES))
        self.assertEqual(ACTION_META_ROUTES, set(SIM_ACTION_ROUTES))
        self.assertEqual(action_meta_routes_in(PHP_MODULE), ACTION_META_ROUTES)

    def test_the_document_names_every_tier(self) -> None:
        # docs/UNLOCK_TIERS.md is withheld from the published subset.
        skip_without(["docs/UNLOCK_TIERS.md"])
        text = DOC.read_text(encoding="utf-8")
        for name in TIERS:
            self.assertIn(name, text)
        self.assertIn("unknown", text)


def action_meta_routes_in(path: Path) -> set[str]:
    """Read ``$E64LOCAL_ACTION_META_ROUTES`` out of the PHP module."""
    source = path.read_text(encoding="utf-8")
    marker = "$E64LOCAL_ACTION_META_ROUTES = array("
    start = source.index(marker)
    end = source.index(");", start)
    body = source[start:end]
    return {
        token.strip().strip('",')
        for token in body.splitlines()[1:]
        if token.strip().startswith('"')
    }


# --- The consumer: the adapter, on a connection it does not get to fake ------------
#
# ``integrations/decaid/e64ws_adapter.py`` is the first caller of ``detect()``
# that is not a fixture.  These tests pin three different claims, and they are
# deliberately separate:
#
# * that the adapter *calls* the detector (``AdapterWiringTests``) — a second
#   implementation of the rule would pass every outcome test below while
#   failing these;
# * that each of the five outcomes arrives through the adapter from facts it
#   could actually have observed (``AdapterOutcomeTests``);
# * that a fact the adapter cannot justify is passed absent rather than guessed
#   (``AdapterFactHonestyTests``), which is what makes ``unknown`` reachable.

OWNER_TOKEN = "test-owner-token-not-a-real-secret"

#: The reviewed module's document, with the action gate closed: what a
#: development image with the module installed answers.
REVIEWED_CAPABILITIES: dict[str, Any] = {
    "success": True,
    "data": {
        "schema": "e64local-api-v1",
        "route": "capabilities",
        "apiVersion": "1",
        "routes": sorted(READ_ROUTES),
        "actions": {
            "schema": "e64local-api-v1",
            "enabled": False,
            "destructiveEnabled": False,
            "catalog": [],
        },
        "features": {"actions": False, "destructiveActions": False, "wssToken": True},
        "devMode": True,
    },
}


class FakeResponse:
    """One probe answer: an HTTP status and, usually, a JSON body."""

    def __init__(self, status: int, document: Any = None, *, decodable: bool = True) -> None:
        self.status = status
        self._document = document
        self._decodable = decodable

    def json(self) -> Any:
        if not self._decodable or self._document is None:
            raise ValueError("this answer carries no JSON document")
        return self._document


class FakeTransport:
    """The adapter's API client: records every probe, answers from a table.

    ``rest_probe`` has the shape ``E64LocalAPI.rest_probe`` has — any HTTP
    status is a response, and ``None`` means no response came back at all — so
    these tests cannot accidentally assume a status they did not supply.
    """

    def __init__(self, answers: Mapping[str, Any] | None = None) -> None:
        self.answers = dict(answers or {})
        self.calls: list[dict[str, Any]] = []

    def rest_probe(
        self,
        route: str,
        body: Any = None,
        *,
        method: str = "POST",
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> Any:
        self.calls.append({"route": route, "body": body, "headers": dict(headers or {})})
        return self.answers.get(route)

    def routes(self) -> list[str]:
        return [str(call["route"]) for call in self.calls]

    def call(self, route: str) -> dict[str, Any]:
        for call in self.calls:
            if call["route"] == route:
                return call
        raise AssertionError(f"no {route} request was made: {self.routes()}")


def reviewed_capabilities(**overrides: Any) -> FakeResponse:
    """A 200 carrying the reviewed document, with individual keys replaced."""
    document = json.loads(json.dumps(REVIEWED_CAPABILITIES))
    document["data"].update(overrides)
    return FakeResponse(200, document)


def adapter_for(transport: Any, **kwargs: Any) -> E64DecaidAdapter:
    kwargs.setdefault("owner_token", OWNER_TOKEN)
    return E64DecaidAdapter(transport, **kwargs)


class AdapterWiringTests(unittest.TestCase):
    """The adapter must call ``detect()``; a copy of the rule must fail here."""

    def test_the_adapter_calls_the_detector_rather_than_re_deriving_the_tier(self) -> None:
        # The detector is replaced by a spy whose tier is not a tier name, so
        # only a real call can produce it.  A consumer that re-implemented the
        # precedence would answer one of the five known names instead.
        seen: dict[str, Any] = {}

        def spy(fact_set: Mapping[str, Any]) -> dict[str, Any]:
            seen["facts"] = fact_set
            return {
                "tier": "answered-by-the-detector",
                "evidence": {"unseparated": [TIER_ROOT]},
                "reasons": ["the detector said so"],
            }

        transport = FakeTransport({"capabilities": reviewed_capabilities()})
        with mock.patch.object(unlock_tiers, "detect", spy):
            report = adapter_for(transport).unlock_tier()

        self.assertIsInstance(report, UnlockTierReport)
        self.assertEqual(report.tier, "answered-by-the-detector")
        self.assertEqual(report.reasons, ("the detector said so",))
        self.assertEqual(report.unseparated, (TIER_ROOT,))
        # ... and it decided from the facts the adapter gathered, not from a
        # fact set the adapter made up on the way past.
        self.assertEqual(seen["facts"]["api"]["schema"], "e64local-api-v1")
        self.assertEqual(seen["facts"]["api"]["status"], 200)
        self.assertIsNone(seen["facts"]["root"]["channel"])
        self.assertIsNone(seen["facts"]["root"]["issue"])

    def test_the_report_is_the_detectors_own_document(self) -> None:
        # No mock: the adapter's output is compared with a direct detect() call
        # on the adapter's own facts.  A second implementation would have to
        # reproduce these sentences byte for byte, which is why there is not
        # one — the sentences are the detector's work, not the adapter's.
        report = adapter_for(FakeTransport({"capabilities": reviewed_capabilities()})).unlock_tier()
        direct = unlock_tiers.detect(report.facts)

        self.assertEqual(report.tier, direct["tier"])
        self.assertEqual(dict(report.evidence), direct["evidence"])
        self.assertEqual(list(report.reasons), direct["reasons"])
        self.assertIn("the reviewed module answered past its dev gate", " ".join(report.reasons))

    def test_the_detector_and_the_adapter_cannot_disagree_about_unknown(self) -> None:
        # The one outcome a consumer is most tempted to paper over.
        report = adapter_for(FakeTransport({"capabilities": None})).unlock_tier()
        self.assertEqual(report.tier, unlock_tiers.detect(report.facts)["tier"])
        self.assertTrue(report.is_unknown)


class AdapterOutcomeTests(unittest.TestCase):
    """One test per outcome, each through the adapter and nothing else."""

    def test_stock_from_the_dev_gate_refusing(self) -> None:
        transport = FakeTransport(
            {"capabilities": FakeResponse(403, {"success": False, "errorCode": 403})}
        )
        report = adapter_for(transport).unlock_tier()

        self.assertEqual(report.tier, TIER_STOCK)
        self.assertFalse(report.is_unknown)
        self.assertTrue(report.evidence["devGateRefused"])
        self.assertFalse(report.evidence["modulePresent"])
        # A 403 says nothing about a root channel, so the neighbour is named.
        self.assertEqual(report.unseparated, (TIER_ROOT, TIER_ROOT_CUSTOM_API))
        self.assertEqual(transport.routes(), ["capabilities"])

    def test_dev_from_the_reviewed_document(self) -> None:
        report = adapter_for(FakeTransport({"capabilities": reviewed_capabilities()})).unlock_tier()

        self.assertEqual(report.tier, TIER_DEV)
        self.assertEqual(report.evidence["moduleMarkers"][0], "schema")
        self.assertEqual(report.unseparated, (TIER_ROOT, TIER_ROOT_CUSTOM_API))
        self.assertTrue(report.at_least(TIER_DEV))
        self.assertFalse(report.at_least(TIER_ROOT))

    def test_root_from_the_owner_channel_the_caller_holds(self) -> None:
        report = adapter_for(FakeTransport({"capabilities": reviewed_capabilities()})).unlock_tier(
            local=LocalObservations(channel=True, issue=DEVELOPMENT_ISSUE)
        )

        self.assertEqual(report.tier, TIER_ROOT)
        self.assertTrue(report.evidence["rootChannel"])
        self.assertTrue(report.evidence["devGateOpen"])
        # Only the runner's rule is left to observe: the top tier, not root.
        self.assertEqual(report.unseparated, (TIER_ROOT_CUSTOM_API,))

    def test_root_custom_api_from_one_action_prepare(self) -> None:
        transport = FakeTransport(
            {
                # A device whose gate is open: it is the gate that lets a
                # prepare reach the runner in the first place.
                "capabilities": reviewed_capabilities(
                    routes=sorted(READ_ROUTES | ACTION_META_ROUTES),
                    features={"actions": True, "destructiveActions": False},
                ),
                "action_prepare": FakeResponse(200, {"success": True, "data": {"confirmToken": "x"}}),
            }
        )
        report = adapter_for(transport).unlock_tier(
            action_probe=ActionProbe("action_grind_start_gbw", {"targetWeightGr": 18})
        )

        self.assertEqual(report.tier, TIER_ROOT_CUSTOM_API)
        self.assertEqual(report.unseparated, ())
        self.assertTrue(report.at_least(TIER_ROOT_CUSTOM_API))
        self.assertIn("actionAnswered", report.evidence["moduleMarkers"])
        # A prepare, never an execute: the returned token is discarded.
        self.assertEqual(transport.routes(), ["capabilities", "action_prepare"])

    def test_root_custom_api_from_the_local_observations(self) -> None:
        report = adapter_for(FakeTransport({"capabilities": reviewed_capabilities()})).unlock_tier(
            local=LocalObservations(channel=True, issue=DEVELOPMENT_ISSUE, sudoers=True)
        )

        self.assertEqual(report.tier, TIER_ROOT_CUSTOM_API)
        self.assertEqual(report.unseparated, ())
        self.assertTrue(report.evidence["sudoers"])

    def test_unknown_from_an_unreachable_device(self) -> None:
        report = adapter_for(FakeTransport({"capabilities": None})).unlock_tier()

        self.assertEqual(report.tier, TIER_UNKNOWN)
        self.assertTrue(report.is_unknown)
        self.assertFalse(report.at_least(TIER_STOCK))
        self.assertIs(report.evidence["apiReached"], False)
        self.assertIn("no HTTP response", " ".join(report.notes))
        self.assertIn("no dev, stock or root signal was observed", " ".join(report.reasons))


class AdapterUnknownTests(unittest.TestCase):
    """An unreachable or unreviewed responder is ``unknown``, never a tier."""

    def test_an_unreviewed_responder_that_says_everything_is_unknown(self) -> None:
        # Every marker the detector can use, from a schema it does not review:
        # routes, an API version, an open action gate, a 200 and `devMode`.
        document = {
            "success": True,
            "data": {
                "schema": "vendor-api-v9",
                "apiVersion": "1",
                "routes": sorted(READ_ROUTES | ACTION_META_ROUTES),
                "features": {"actions": True, "destructiveActions": True},
                "devMode": True,
            },
        }
        report = adapter_for(FakeTransport({"capabilities": FakeResponse(200, document)})).unlock_tier()

        self.assertEqual(report.tier, TIER_UNKNOWN)
        self.assertEqual(report.evidence["moduleMarkers"], [])
        self.assertFalse(report.evidence["modulePresent"])
        self.assertIn("not a reviewed module schema", " ".join(report.reasons))

    def test_a_500_on_the_read_routes_is_unknown(self) -> None:
        transport = FakeTransport({"capabilities": FakeResponse(500, None, decodable=False)})
        report = adapter_for(transport).unlock_tier()

        self.assertEqual(report.tier, TIER_UNKNOWN)
        self.assertIn("does not settle which image", " ".join(report.reasons))
        self.assertFalse(report.evidence["modulePresent"])
        self.assertFalse(report.evidence["moduleAbsent"])

    def test_no_owner_token_is_unknown_and_says_what_would_settle_it(self) -> None:
        transport = FakeTransport({"capabilities": FakeResponse(401, {"success": False, "errorCode": 401})})
        report = E64DecaidAdapter(transport).unlock_tier()

        self.assertEqual(report.tier, TIER_UNKNOWN)
        self.assertIn("401", " ".join(report.reasons))
        self.assertIn(unlock_tiers.OWNER_TOKEN_HEADER, " ".join(report.reasons))
        # The probe went out without a token, and no token appeared anywhere.
        self.assertEqual(transport.call("capabilities")["headers"], {})

    def test_a_document_without_the_reviewed_schema_is_unknown(self) -> None:
        report = adapter_for(
            FakeTransport({"capabilities": FakeResponse(200, {"success": True, "data": {"schema": "other"}})})
        ).unlock_tier()

        self.assertEqual(report.tier, TIER_UNKNOWN)
        self.assertIn("not a reviewed module schema", " ".join(report.reasons))


class AdapterFactHonestyTests(unittest.TestCase):
    """Facts the adapter cannot justify are passed absent, not guessed."""

    def test_an_unobserved_local_fact_stays_absent(self) -> None:
        report = adapter_for(FakeTransport({"capabilities": reviewed_capabilities()})).unlock_tier()

        self.assertEqual(report.facts["root"], {"channel": None, "issue": None})
        self.assertIsNone(report.evidence["rootChannel"])
        self.assertIsNone(report.evidence["issue"])
        # "not probed" is not "not there": the tier says so itself.
        self.assertIn(TIER_ROOT, report.unseparated)

    def test_the_issue_line_is_never_taken_from_an_api_answer(self) -> None:
        # ``detect()`` takes ``root.issue`` at face value with no schema gate,
        # so the one route that could read /etc/issue over HTTP must not be the
        # thing that fills it: any responder can serve a development line.
        transport = FakeTransport(
            {
                "capabilities": reviewed_capabilities(),
                "file": FakeResponse(
                    200, {"success": True, "data": {"path": "/etc/issue", "text": DEVELOPMENT_ISSUE}}
                ),
            }
        )
        report = adapter_for(transport).unlock_tier()

        self.assertNotIn("file", transport.routes())
        self.assertIsNone(report.facts["root"]["issue"])
        self.assertIsNone(report.evidence["issue"])
        self.assertEqual(report.tier, TIER_DEV)

    def test_a_root_read_of_the_rule_does_not_erase_a_503(self) -> None:
        # The caller saw /etc/sudoers.d/e64local and the probe saw the runner
        # refuse.  Both are observations, and the one that says "this did not
        # answer" is the one a tier claim must not erase: a present rule with a
        # runner that refuses is ``root``, not the top tier
        # (docs/UNLOCK_TIERS.md §2.4, "Runner binary removed").
        transport = FakeTransport(
            {
                "capabilities": reviewed_capabilities(),
                "action_prepare": FakeResponse(503, {"success": False, "errorCode": 503}),
            }
        )
        report = adapter_for(transport).unlock_tier(
            local=LocalObservations(channel=True, sudoers=True),
            action_probe=ActionProbe("action_grind_start_gbw", {"targetWeightGr": 18}),
        )

        self.assertEqual(report.tier, TIER_ROOT)
        self.assertIs(report.facts["api"]["sudoers"], False)
        self.assertIs(report.evidence["sudoers"], False)
        # Root, and ruled out of the top tier: nothing is left unseparated.
        self.assertEqual(report.unseparated, ())

    def test_a_root_read_of_the_rule_reaches_the_top_tier_without_a_probe(self) -> None:
        report = adapter_for(FakeTransport({"capabilities": reviewed_capabilities()})).unlock_tier(
            local=LocalObservations(channel=True, sudoers=True)
        )

        self.assertEqual(report.tier, TIER_ROOT_CUSTOM_API)
        self.assertIs(report.facts["api"]["sudoers"], True)

    def test_the_capabilities_document_alone_never_claims_the_top_tier(self) -> None:
        # An open action gate and the five meta routes in the handshake are
        # still not an action answering: the tier stops at dev and names the
        # two observations that would move it.
        open_gate = reviewed_capabilities(
            routes=sorted(READ_ROUTES | ACTION_META_ROUTES),
            features={"actions": True, "destructiveActions": True},
        )
        report = adapter_for(FakeTransport({"capabilities": open_gate})).unlock_tier()

        self.assertEqual(report.tier, TIER_DEV)
        self.assertNotIn("action_answered", report.facts["api"])
        self.assertNotIn("sudoers", report.facts["api"])
        self.assertEqual(report.unseparated, (TIER_ROOT, TIER_ROOT_CUSTOM_API))

    def test_a_503_probe_rules_the_runner_rule_out(self) -> None:
        transport = FakeTransport(
            {
                "capabilities": reviewed_capabilities(),
                "action_prepare": FakeResponse(503, {"success": False, "errorCode": 503}),
            }
        )
        report = adapter_for(transport).unlock_tier(
            action_probe=ActionProbe("action_grind_start_gbw", {"targetWeightGr": 18})
        )

        self.assertEqual(report.tier, TIER_DEV)
        self.assertIs(report.facts["api"]["action_answered"], False)
        self.assertIs(report.facts["api"]["sudoers"], False)
        self.assertFalse(report.evidence["sudoers"])
        # The runner's rule is now excluded, so the only neighbour left is root.
        self.assertEqual(report.unseparated, (TIER_ROOT,))
        self.assertIn("503", " ".join(report.notes))

    def test_a_403_probe_does_not_claim_the_runner_ran(self) -> None:
        # 403 is the closed policy gate, which answers before the runner is
        # consulted.  It is not evidence for the sudoers rule, so it supplies
        # no fact; the detector's own reason for that fact stays true.
        transport = FakeTransport(
            {
                "capabilities": reviewed_capabilities(),
                "action_prepare": FakeResponse(403, {"success": False, "errorCode": 403}),
            }
        )
        report = adapter_for(transport).unlock_tier(
            action_probe=ActionProbe("action_grind_start_gbw", {"targetWeightGr": 18})
        )

        self.assertEqual(report.tier, TIER_DEV)
        self.assertNotIn("action_answered", report.facts["api"])
        self.assertEqual(report.unseparated, (TIER_ROOT, TIER_ROOT_CUSTOM_API))
        self.assertIn("403", " ".join(report.notes))

    def test_an_action_probe_without_the_owner_token_is_not_sent(self) -> None:
        transport = FakeTransport({"capabilities": reviewed_capabilities()})
        report = E64DecaidAdapter(transport).unlock_tier(
            action_probe=ActionProbe("action_grind_start_gbw", {"targetWeightGr": 18})
        )

        self.assertEqual(report.tier, TIER_DEV)
        self.assertEqual(transport.routes(), ["capabilities"])
        self.assertIn("owner token", " ".join(report.notes))

    def test_the_probe_body_is_a_prepare_with_a_fresh_request_id(self) -> None:
        transport = FakeTransport(
            {
                "capabilities": reviewed_capabilities(),
                "action_prepare": FakeResponse(200, {"success": True}),
            }
        )
        adapter_for(transport).unlock_tier(
            action_probe=ActionProbe("action_grind_start_gbw", {"targetWeightGr": 18})
        )
        body = transport.call("action_prepare")["body"]

        self.assertEqual(set(body), {"route", "params", "requestId"})
        self.assertEqual(body["route"], "action_grind_start_gbw")
        self.assertEqual(body["params"], {"targetWeightGr": 18})
        # The module's idempotency key: 8..64 of A-Z a-z 0-9 . _ -
        self.assertRegex(body["requestId"], r"^[A-Za-z0-9._-]{8,64}$")

    def test_the_report_and_its_facts_carry_no_credential(self) -> None:
        report = adapter_for(FakeTransport({"capabilities": reviewed_capabilities()})).unlock_tier(
            local=LocalObservations(channel=True, sudoers=True)
        )
        encoded = json.dumps(report.as_document()) + json.dumps(report.facts)

        self.assertNotIn(OWNER_TOKEN, encoded)
        for needle in ("secret", "password", "192.168", "PHPSESSID", "authorization"):
            self.assertNotIn(needle.lower(), encoded.lower())

    def test_the_local_observations_reject_a_fourth_state(self) -> None:
        for value in ("false", 0, "no"):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    LocalObservations(channel=value)  # type: ignore[arg-type]

    def test_the_tier_probe_is_gated_by_the_read_permission(self) -> None:
        transport = FakeTransport({"capabilities": reviewed_capabilities()})
        adapter = adapter_for(transport, policy=DecaidCapabilityPolicy(allow_read=False))

        with self.assertRaises(E64WSAPIError):
            adapter.unlock_tier()
        self.assertEqual(transport.routes(), [])
        self.assertEqual(adapter.audit_log()[-1].operation, "grinder.tier")
        self.assertFalse(adapter.audit_log()[-1].allowed)


class CannedResponse:
    """The shape ``urllib`` hands back to ``E64LocalAPI``."""

    def __init__(self, status: int, body: bytes, headers: Mapping[str, str] | None = None) -> None:
        self.status = status
        self.body = body
        self.headers = dict(headers or {})

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> "CannedResponse":
        return self

    def __exit__(self, *_exc: Any) -> bool:
        return False


class RecordedOpen:
    """Stands in for ``OpenerDirector.open``, keeping each request."""

    def __init__(self, status: int, body: bytes, headers: Mapping[str, str] | None = None) -> None:
        self.status = status
        self.body = body
        self.headers = dict(headers or {})
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: float | None = None) -> CannedResponse:
        self.requests.append(request)
        return CannedResponse(self.status, self.body, self.headers)


class ProbeTransportTests(unittest.TestCase):
    """``E64LocalAPI.rest_probe`` is what makes an error status an observation."""

    def test_an_error_status_is_a_response_not_an_exception(self) -> None:
        api = E64LocalAPI("127.0.0.1", token="wss-token")
        error = urllib.error.HTTPError(
            f"{api.base_url}/rest_api/capabilities",
            403,
            "Forbidden",
            {"Content-Type": "application/json"},
            io.BytesIO(b'{"success":false,"errorCode":403}'),
        )
        self.addCleanup(error.close)
        with mock.patch.object(api._opener, "open", side_effect=error):
            response = api.rest_probe("capabilities", {})

        assert response is not None
        self.assertEqual(response.status, 403)
        self.assertEqual(response.json()["errorCode"], 403)
        api.close()

    def test_a_transport_failure_is_no_response(self) -> None:
        api = E64LocalAPI("127.0.0.1", token="wss-token")
        with mock.patch.object(
            api._opener, "open", side_effect=urllib.error.URLError("connection refused")
        ):
            self.assertIsNone(api.rest_probe("capabilities", {}))
        api.close()

    def test_rest_raw_still_raises_on_an_error_status(self) -> None:
        # The probe is additive: a failed call is still a failed call.
        api = E64LocalAPI("127.0.0.1", token="wss-token")
        error = urllib.error.HTTPError(
            f"{api.base_url}/rest_api/grind_log",
            403,
            "Forbidden",
            {},
            io.BytesIO(b'{"errorCode":403}'),
        )
        self.addCleanup(error.close)
        with mock.patch.object(api._opener, "open", side_effect=error):
            with self.assertRaises(E64WSAPIError):
                api.rest_raw("grind_log", {})
        api.close()

    def test_the_owner_token_reaches_the_wire_and_not_the_url(self) -> None:
        # The whole chain, with no socket: adapter -> consumer -> client ->
        # request.  The token is a header, never a query parameter.
        api = E64LocalAPI("127.0.0.1", token="wss-token")
        opener = RecordedOpen(200, json.dumps(REVIEWED_CAPABILITIES).encode())
        with mock.patch.object(api._opener, "open", opener):
            report = E64DecaidAdapter(api, owner_token=OWNER_TOKEN).unlock_tier()

        self.assertEqual(report.tier, TIER_DEV)
        self.assertEqual(len(opener.requests), 1)
        request = opener.requests[0]
        self.assertTrue(request.full_url.endswith("/rest_api/capabilities"))
        headers = {key.lower(): value for key, value in request.headers.items()}
        self.assertEqual(headers.get(unlock_tiers.OWNER_TOKEN_HEADER.lower()), OWNER_TOKEN)
        self.assertNotIn(OWNER_TOKEN, request.full_url)
        api.close()


if __name__ == "__main__":
    unittest.main()
