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
  inverted rule and must fail there.

What the inversions catch, and what they do not: the ``_decide`` substitutions
are *double* inversions, because the mock keeps the original function and calls
it with the arguments exchanged.  A real reordering inside ``_decide`` therefore
cancels out and these proofs cannot see it — the property tests can, and do
(``docs/UNLOCK_TIERS.md`` §8).  What these proofs catch is a signal that is
ignored, mis-supplied or numbered wrong, and a test that stops noticing that
stops passing this file.

60 tests. Nothing here touches a device, a socket or a file outside this
repository.
"""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "UNLOCK_TIERS.md"
MODULE = ROOT / "tools" / "unlock_tiers.py"
PHP_MODULE = ROOT / "ondevice" / "rest_api_dev.php"
OPENAPI = ROOT / "docs" / "openapi" / "local-api.yaml"

from tools import unlock_tiers  # noqa: E402  (path is set by the suite runner)
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


if __name__ == "__main__":
    unittest.main()
