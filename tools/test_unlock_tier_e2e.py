"""Unlock-tier discovery, end to end, against the simulator.

``tools/test_unlock_tiers.py`` proves the rule and the adapter's wiring against
a transport stub.  This file proves the thing a plugin actually does: open a
socket to a device, ask ``E64DecaidAdapter.unlock_tier()``, and get the tier the
contract promises — for each of the five outcomes, from a simulator state that
should produce exactly that one.

Nothing here calls ``detect()``.  The assertions are on the ``UnlockTierReport``
the plugin gets back, produced by ``tools/e2e/unlock_tier_e2e.py``'s case table
over a real loopback connection to ``tools/e64ws_simulator.py``.  A fixture that
stops producing its outcome fails here even when ``detect()`` is untouched, and
a ``detect()`` that stops being consulted fails the mutation proofs below.

The five outcomes, and the fixture each one needs:

===========================  ==========================================  ===================
case                         device state                                tier
===========================  ==========================================  ===================
dev gate refusing            ``dev=0``, HTTP 403 at the module's gate    ``stock``
reviewed capabilities        development image, action gate shut        ``dev``
owner channel                the same, plus an owner shell as uid 0      ``root``
one action prepare           + ``action_prepare`` answering HTTP 200     ``root-custom-api``
runner rule read             + ``/etc/sudoers.d/e64local`` present       ``root-custom-api``
nothing listening            no responder on the port                    ``unknown``
bare 401                     wrong owner token, no reviewed document     ``unknown``
destructive prepare          + ``--enable-destructive-actions``          ``root-custom-api``
prepare refused              open gate, destructive flag shut, 403       ``dev``
===========================  ==========================================  ===================

Two further classes assert what a plugin would otherwise have to take on
trust: that a reading spends no action budget unless the caller authorises a
probe (``TheProbeIsOptInTests``, measured in the fixture's action engine), and
that the verdict is the plugin's observation rather than the fixture's own
``syntheticUnlockTier`` key (``TheVerdictIsObservedTests``).

What the simulator cannot represent, and what is therefore unproven here:

1. **An owner SSH or dropbear channel.**  The fixture owns no shell, so
   ``root.channel`` arrives as a :class:`LocalObservations` value — the
   caller's own observation, which is exactly what the adapter's contract asks
   for.  ``root`` is proven *given* a channel, not that a fixture can produce
   one; a real login is covered by ``tools/e64root`` against a container, not
   by this file.
2. **``/etc/sudoers.d/e64local`` as a file.**  The ``root-custom-api`` case that
   reads it supplies ``sudoers=True`` the same way.  The *other* road to the top
   tier — one ``action_prepare`` answering 200 — is fully on the wire, so the
   top tier itself is proven end to end.
3. **A separate runner process.**  The fixture's action engine runs in the same
   process, so an HTTP 200 proves the module *answered* an action and not that
   ``www-data`` started a root runner through a rule.  The 503 that
   ``integrations/decaid/unlock_tier.py`` reads as "the rule is absent"
   (``LOCAL_API.md`` §12.2) cannot be produced at all: there is no runner to
   fail to start.  The closest state the fixture has is a prepare refused
   *before* the runner (a 403), which this file asserts must exclude nothing.
4. **A 404 from a vendor dispatcher that does not know the route**, and a 500
   from it.  ``--dev-gate locked`` answers 403 before the route is looked up, so
   the "module absent" branch is exercised only through ``reached: False``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import unittest
from dataclasses import dataclass
from typing import Any, Callable, ContextManager
from unittest import mock

from integrations.decaid.e64ws_adapter import UnlockTierReport
from integrations.decaid.unlock_tier import ActionProbe, LocalObservations
from tools import unlock_tiers
from tools.e2e.unlock_tier_e2e import (
    CASES,
    ISSUE_LINE,
    SESSION_PASSWORD,
    Case,
    CaseResult,
    Device,
    Fixture,
    assert_case,
    case,
    observe,
    start,
)
from tools.e64ws_api import E64LocalAPI
from tools.e64ws_simulator import SimulatedLocalApi
from tools.unlock_tiers import (
    TIER_DEV,
    TIER_ROOT,
    TIER_ROOT_CUSTOM_API,
    TIER_STOCK,
    TIER_UNKNOWN,
    TIERS,
    at_least,
)

#: The module's own decision point, captured before any test patches it.
ORIGINAL_DECIDE = unlock_tiers._decide


# --- The mutations -----------------------------------------------------------
#
# Each one breaks the single condition its case turns on, and does it the way a
# real device or a real edit would: a status code, a response body, an absent
# observation, a different action, or the rule itself.  None of them touches the
# assertion, so a proof that passes is a proof that the *case* noticed.


def ignored_custom_decide(dev: bool, stock: bool, root: bool, custom_api: bool) -> str:
    """``_decide`` with the top-tier signal switched off."""
    return ORIGINAL_DECIDE(dev, stock, root, False)


def open_the_dev_gate(device: Device) -> None:
    """A shipped image stops refusing at its gate: 403 becomes 200."""
    device.grinder.dev_mode = True
    device.local_api.dev_gate_open = True


def let_the_device_answer(device: Device) -> None:
    """Nothing was listening; now something is."""
    device.listen()


@dataclass(frozen=True)
class Mutation:
    """One load-bearing condition, broken on purpose."""

    description: str
    #: Replace the case's observations (a fact that was never observed, or a
    #: different action authorised).
    case: Callable[[Case], Case] = lambda entry: entry
    #: Change the device before the plugin connects to it.
    before: Callable[[Device], None] = lambda device: None
    #: Patch the code under test for the duration of the run.
    patch: Callable[[], ContextManager[Any]] = contextlib.nullcontext


MUTATIONS: dict[str, tuple[Mutation, ...]] = {
    TIER_STOCK: (
        Mutation(
            "the gate answers 200 instead of 403",
            before=open_the_dev_gate,
        ),
    ),
    TIER_DEV: (
        Mutation(
            "the document carries the vendor schema instead of the reviewed one",
            patch=lambda: mock.patch.object(SimulatedLocalApi, "SCHEMA", "vendor-api-v9"),
        ),
    ),
    TIER_ROOT: (
        Mutation(
            "the owner channel was not observed after all",
            case=lambda entry: dataclasses.replace(
                entry, local=LocalObservations(channel=None, issue=ISSUE_LINE)
            ),
        ),
    ),
    TIER_ROOT_CUSTOM_API: (
        Mutation(
            "detect() stops honouring the top-tier signal",
            patch=lambda: mock.patch.object(unlock_tiers, "_decide", ignored_custom_decide),
        ),
        Mutation(
            "the destructive flag is shut, so the prepare is refused with 403 "
            "before the runner is consulted",
            case=lambda entry: dataclasses.replace(
                entry,
                fixture=dataclasses.replace(entry.fixture, destructive_enabled=False),
            ),
        ),
        Mutation(
            "the caller authorised no probe",
            case=lambda entry: dataclasses.replace(entry, probe=None),
        ),
    ),
    TIER_UNKNOWN: (
        Mutation(
            "the device answers after all",
            before=let_the_device_answer,
        ),
    ),
}


def run_mutation(mutation: Mutation, entry: Case) -> CaseResult:
    """Run ``entry`` against a device whose one load-bearing condition is broken."""
    mutated = mutation.case(entry)
    with mutation.patch():
        device = start(mutated.fixture)
        try:
            mutation.before(device)
            return observe(mutated, device)
        finally:
            device.stop()


# --- The harness itself ------------------------------------------------------


class HarnessTests(unittest.TestCase):
    """Guards on the fixture table, so a broken fixture cannot pass quietly."""

    def test_every_outcome_has_at_least_one_fixture(self) -> None:
        for tier in TIERS + (TIER_UNKNOWN,):
            with self.subTest(tier=tier):
                self.assertTrue(
                    [entry for entry in CASES if entry.expected == tier],
                    f"no fixture asserts the {tier!r} tier",
                )

    def test_the_cases_have_distinct_names(self) -> None:
        names = [entry.name for entry in CASES]
        self.assertEqual(len(names), len(set(names)), names)

    def test_a_fixture_is_found_by_name_and_by_prefix(self) -> None:
        self.assertEqual(case("root-from-the-owner-channel").expected, TIER_ROOT)
        self.assertEqual(case("root-from").expected, TIER_ROOT)
        with self.assertRaises(KeyError):
            case("no-such-fixture")

    def test_the_silent_fixture_really_refuses_a_connection(self) -> None:
        # The 'unknown' case must be unknown because nothing answered, not
        # because a stub returned None on its behalf.
        device = start(Fixture(listening=False))
        try:
            api = E64LocalAPI("127.0.0.1", scheme="ws", rest_port=device.port, timeout=2.0)
            self.addCleanup(api.close)
            self.assertIsNone(api.rest_probe("capabilities", {}))
        finally:
            device.stop()

    def test_a_silent_fixture_can_be_made_to_answer(self) -> None:
        # The mutation that breaks the 'unknown' case depends on exactly this:
        # the same device object, silent at first and then answering on a port
        # of its own.  If it could not be made to answer, that proof would be
        # unable to break anything.
        device = start(Fixture(listening=False))
        try:
            self.assertFalse(device.listening)
            device.listen()
            self.assertTrue(device.listening)
            api = E64LocalAPI(
                "127.0.0.1", scheme="ws", rest_port=device.port, timeout=2.0
            )
            self.addCleanup(api.close)
            api.login("Owner", SESSION_PASSWORD)
            response = api.rest_probe(
                "capabilities",
                {},
                headers={unlock_tiers.OWNER_TOKEN_HEADER: device.fixture.api_token},
            )
            self.assertIsNotNone(response)
            self.assertEqual(response.status, 200)
        finally:
            device.stop()


# --- One test per outcome ----------------------------------------------------


class OutcomeTests(unittest.TestCase):
    """Each of the five outcomes, through the plugin's own call, over a socket."""

    #: Every fixture in ``CASES`` is asserted by a test in this class, and
    #: ``test_every_fixture_is_asserted_here`` keeps that true.  Without it a new
    #: fixture would be run by the mutation proofs only, which exercise it under
    #: a broken condition and never in the state it claims to be.
    COVERED = (
        "stock-from-the-dev-gate-refusing",
        "dev-from-the-reviewed-capabilities",
        "root-from-the-owner-channel",
        "root-custom-api-from-one-action-prepare",
        "root-custom-api-from-the-sudoers-observation",
        "root-custom-api-from-a-destructive-prepare",
        "unknown-from-an-unreachable-device",
        "unknown-from-a-bare-401",
        "dev-when-the-prepare-is-refused-before-the-runner",
    )

    def run_case(self, name: str) -> CaseResult:
        entry = case(name)
        result = observe(entry)
        assert_case(entry, result)
        return result

    def test_stock_from_the_dev_gate_refusing(self) -> None:
        result = self.run_case("stock-from-the-dev-gate-refusing")

        self.assertEqual(result.tier, TIER_STOCK)
        self.assertIsInstance(result.report, UnlockTierReport)
        # The status *is* the observation: 403 at the gate, not a 404 and not
        # silence.
        self.assertEqual(result.report.evidence["apiStatus"], 403)
        self.assertTrue(result.report.evidence["devGateRefused"])
        self.assertFalse(result.report.evidence["modulePresent"])
        # A shipped image's module never reaches the action layer.
        self.assertEqual(result.audit, ())

    def test_dev_from_the_reviewed_capabilities(self) -> None:
        result = self.run_case("dev-from-the-reviewed-capabilities")

        self.assertEqual(result.tier, TIER_DEV)
        self.assertIn("schema", result.report.evidence["moduleMarkers"])
        # The device answered, and the tier still stops at dev: an open action
        # gate is not an action answer, and /etc/issue was never read.
        self.assertIsNone(result.report.facts["root"]["issue"])
        self.assertIsNone(result.report.facts["root"]["channel"])

    def test_root_from_the_owner_channel(self) -> None:
        result = self.run_case("root-from-the-owner-channel")

        self.assertEqual(result.tier, TIER_ROOT)
        self.assertTrue(result.report.evidence["rootChannel"])
        self.assertTrue(result.report.evidence["devGateOpen"])
        # Root is not the top tier: the runner's rule is what is left.
        self.assertIn(TIER_ROOT_CUSTOM_API, result.report.unseparated)

    def test_root_custom_api_from_one_action_prepare(self) -> None:
        result = self.run_case("root-custom-api-from-one-action-prepare")

        self.assertEqual(result.tier, TIER_ROOT_CUSTOM_API)
        self.assertIn("actionAnswered", result.report.evidence["moduleMarkers"])
        # Observed on the device, not claimed by the client: one prepare, and
        # no execute.  The probe costs one rate-limit slot and one prepared
        # record, which is why it is opt-in.
        phases = [entry["phase"] for entry in result.audit]
        self.assertEqual(phases, ["prepare"], phases)
        self.assertEqual(result.audit[0]["route"], "action_grind_start_gbw")
        self.assertEqual(result.audit[0]["result"], "prepared")

    def test_root_custom_api_from_the_sudoers_observation(self) -> None:
        result = self.run_case("root-custom-api-from-the-sudoers-observation")

        self.assertEqual(result.tier, TIER_ROOT_CUSTOM_API)
        self.assertTrue(result.report.evidence["sudoers"])
        self.assertEqual(result.report.unseparated, ())
        # No probe was authorised, so the fixture was never asked to prepare.
        self.assertEqual(result.audit, ())

    def test_root_custom_api_from_a_destructive_prepare(self) -> None:
        result = self.run_case("root-custom-api-from-a-destructive-prepare")

        self.assertEqual(result.tier, TIER_ROOT_CUSTOM_API)
        self.assertTrue(result.report.evidence["destructiveActions"])
        # The second flag has to be open for the runner to be consulted at all,
        # and the prepare is still a prepare: one record, no execution.
        self.assertEqual([entry["phase"] for entry in result.audit], ["prepare"])
        self.assertEqual(result.audit[0]["route"], "action_logs_clear")
        self.assertEqual(result.report.unseparated, ())

    def test_unknown_from_an_unreachable_device(self) -> None:
        result = self.run_case("unknown-from-an-unreachable-device")

        self.assertEqual(result.tier, TIER_UNKNOWN)
        self.assertTrue(result.report.is_unknown)
        self.assertIs(result.report.evidence["apiReached"], False)
        self.assertIn("no HTTP response", " ".join(result.report.notes))
        self.assertIn("not decidable", " ".join(result.report.reasons))

    def test_unknown_from_a_bare_401(self) -> None:
        result = self.run_case("unknown-from-a-bare-401")

        self.assertEqual(result.tier, TIER_UNKNOWN)
        self.assertEqual(result.report.evidence["apiStatus"], 401)
        self.assertFalse(result.report.evidence["modulePresent"])
        self.assertIn("unidentified responder can say 401", " ".join(result.report.reasons))

    def test_dev_when_the_prepare_is_refused_before_the_runner(self) -> None:
        result = self.run_case("dev-when-the-prepare-is-refused-before-the-runner")

        self.assertEqual(result.tier, TIER_DEV)
        # The device refused it: observed on the device, not inferred.
        self.assertEqual([entry["phase"] for entry in result.audit], ["refuse"])
        self.assertEqual(result.audit[0]["errorCode"], 403)
        # A status emitted before the runner was consulted excludes nothing.
        self.assertNotIn("action_answered", result.report.facts["api"])
        self.assertNotIn("sudoers", result.report.facts["api"])
        self.assertIn(TIER_ROOT_CUSTOM_API, result.report.unseparated)

    def test_every_fixture_is_asserted_here(self) -> None:
        self.assertEqual(
            sorted(self.COVERED),
            sorted(entry.name for entry in CASES),
            "a fixture in CASES has no outcome test, or COVERED names one that "
            "no longer exists",
        )


# --- The tests can fail ------------------------------------------------------


class MutationProofTests(unittest.TestCase):
    """Each outcome's fixture, with its one condition broken, must fail loudly.

    A green test is only coverage of something if the thing it claims to
    observe can move it to red.  Every proof here runs the *same* assertion
    function the passing test uses (``assert_case``), so a proof cannot pass by
    checking something the suite does not check.
    """

    def assert_mutation_is_caught(self, mutation: Mutation, entry: Case) -> CaseResult:
        result = run_mutation(mutation, entry)
        self.assertNotEqual(
            result.tier,
            entry.expected,
            f"the mutation was a no-op, so it proves nothing: {mutation.description}",
        )
        with self.assertRaises(AssertionError) as caught:
            assert_case(entry, result)
        message = str(caught.exception)
        self.assertIn(
            f"the {entry.expected!r} tier",
            message,
            f"the failure does not name the tier it broke: {message}",
        )
        return result

    def test_every_tier_has_a_mutation(self) -> None:
        for tier in TIERS + (TIER_UNKNOWN,):
            with self.subTest(tier=tier):
                self.assertTrue(MUTATIONS.get(tier), f"no mutation for the {tier!r} tier")

    def test_the_stock_fixture_fails_when_the_gate_opens(self) -> None:
        entry = case("stock-from-the-dev-gate-refusing")
        result = self.assert_mutation_is_caught(MUTATIONS[TIER_STOCK][0], entry)
        self.assertEqual(result.tier, TIER_DEV, "an open gate leaves a development image")

    def test_the_dev_fixture_fails_when_the_schema_is_not_the_reviewed_one(self) -> None:
        entry = case("dev-from-the-reviewed-capabilities")
        result = self.assert_mutation_is_caught(MUTATIONS[TIER_DEV][0], entry)
        self.assertEqual(result.tier, TIER_UNKNOWN)
        self.assertEqual(result.report.evidence["apiSchema"], "vendor-api-v9")

    def test_the_root_fixture_fails_when_the_channel_was_not_observed(self) -> None:
        entry = case("root-from-the-owner-channel")
        result = self.assert_mutation_is_caught(MUTATIONS[TIER_ROOT][0], entry)
        self.assertEqual(result.tier, TIER_DEV)

    def test_the_top_fixture_fails_when_detect_stops_honouring_the_signal(self) -> None:
        entry = case("root-custom-api-from-one-action-prepare")
        result = self.assert_mutation_is_caught(
            MUTATIONS[TIER_ROOT_CUSTOM_API][0], entry
        )
        # Proof that the tier came from the rule and not from the fixture: the
        # device answered exactly as before — one action, still prepared — and
        # only _decide changed.  With the top-tier signal ignored this device
        # has no other support, so it falls to dev; the case that also holds a
        # root channel is the one that would fall to root.
        self.assertEqual(result.report.evidence["moduleMarkers"].count("actionAnswered"), 1)
        self.assertEqual(result.tier, TIER_DEV)

    def test_the_top_fixture_fails_when_the_destructive_flag_is_shut(self) -> None:
        # The same case as 'dev-when-the-prepare-is-refused-before-the-runner',
        # one flag apart: the fixture that asserts the top tier must fall to dev
        # when its destructive gate closes.
        entry = case("root-custom-api-from-a-destructive-prepare")
        result = self.assert_mutation_is_caught(
            MUTATIONS[TIER_ROOT_CUSTOM_API][1], entry
        )
        self.assertEqual(result.tier, TIER_DEV)
        self.assertEqual(result.audit[0]["errorCode"], 403)
        self.assertEqual(result.audit[0]["phase"], "refuse")

    def test_the_top_fixture_fails_when_no_probe_is_authorised(self) -> None:
        entry = case("root-custom-api-from-one-action-prepare")
        result = self.assert_mutation_is_caught(
            MUTATIONS[TIER_ROOT_CUSTOM_API][2], entry
        )
        self.assertEqual(result.tier, TIER_DEV)
        self.assertEqual(result.audit, ())

    def test_the_unknown_fixture_fails_when_the_device_answers(self) -> None:
        entry = case("unknown-from-an-unreachable-device")
        result = self.assert_mutation_is_caught(MUTATIONS[TIER_UNKNOWN][0], entry)
        self.assertEqual(result.tier, TIER_DEV)
        self.assertIs(result.report.evidence["apiReached"], True)


# --- What a reading costs, and what the verdict is not ------------------------


class TheProbeIsOptInTests(unittest.TestCase):
    """A tier question must not eat the budget a real action needs.

    The cost is measured on the device, in the fixture's action engine: its
    audit list, the rate-limit slots it has spent and the records it is holding.
    A client that always probed would look identical from the outside and be
    wrong by one slot per poll, which is why this is asserted rather than
    assumed.
    """

    #: A device whose action gate is open and whose caller authorises no probe.
    #: Not one of ``CASES``: it exists to measure what a reading costs, not to
    #: assert a tier a plugin would act on.
    READING = Case(
        name="reading-with-the-action-gate-open",
        expected=TIER_DEV,
        fixture=Fixture(actions_enabled=True),
        unseparated=(TIER_ROOT, TIER_ROOT_CUSTOM_API),
    )

    def test_a_reading_without_the_probe_spends_no_action_budget(self) -> None:
        device = start(self.READING.fixture)
        try:
            result = observe(self.READING, device)

            self.assertEqual(result.tier, TIER_DEV)
            # The gate was open, so every one of these *could* have moved; none
            # of them did.
            self.assertEqual(device.audit(), ())
            self.assertEqual(device.rate_usage(), {})
            self.assertEqual(device.prepared_records(), ())
        finally:
            device.stop()

    def test_the_opt_in_probe_costs_exactly_one_prepared_record(self) -> None:
        entry = case("root-custom-api-from-one-action-prepare")
        device = start(entry.fixture)
        try:
            result = observe(entry, device)

            self.assertEqual(result.tier, TIER_ROOT_CUSTOM_API)
            self.assertEqual(device.rate_usage(), {"grind_start": 1})
            # One record, prepared and never executed: the token is discarded.
            self.assertEqual(
                device.prepared_records(), (("prepared", "action_grind_start_gbw"),)
            )
            self.assertEqual([row["phase"] for row in device.audit()], ["prepare"])
        finally:
            device.stop()


class TheVerdictIsObservedTests(unittest.TestCase):
    """The tier comes from the wire, not from the fixture's own answer."""

    def test_the_fixtures_own_tier_never_becomes_the_verdict(self) -> None:
        # A state where the two genuinely disagree: the grinder's dev gate opens
        # after the local API was built, so the fixture's own
        # `syntheticUnlockTier` key (computed from `dev_gate_open`) still says
        # stock while the module now answers 200.  The plugin must report what
        # it observed, not what the document claimed about itself.
        device = start(Fixture(dev_gate_locked=True))
        try:
            device.grinder.dev_mode = True
            assert device.local_api is not None
            fixture_verdict = device.local_api.capabilities()["syntheticUnlockTier"]
            self.assertEqual(fixture_verdict["tier"], TIER_STOCK)

            result = observe(case("stock-from-the-dev-gate-refusing"), device)

            self.assertEqual(result.tier, TIER_DEV)
            self.assertNotEqual(result.tier, fixture_verdict["tier"])
        finally:
            device.stop()


# --- Unknown is not a fallback ----------------------------------------------


class UnknownIsNotAFallbackTests(unittest.TestCase):
    """``unknown`` and an exception are different answers, in both directions."""

    def test_unknown_is_returned_rather_than_raised(self) -> None:
        result = observe(case("unknown-from-an-unreachable-device"))

        # Nothing escaped: this is a report, with a verdict of 'unknown'.
        self.assertIsInstance(result.report, UnlockTierReport)
        self.assertEqual(result.tier, TIER_UNKNOWN)
        # ... and it is not a floor a caller can round up.
        self.assertFalse(result.report.at_least(TIER_STOCK))
        self.assertFalse(result.report.at_least(TIER_UNKNOWN))
        self.assertFalse(at_least(TIER_UNKNOWN, TIER_UNKNOWN))
        # The tier is the honest answer to an unanswered question, and the
        # device that refused the login is the observation behind it.
        self.assertIsNotNone(result.login_error)

    def test_a_transport_that_raises_is_not_turned_into_unknown(self) -> None:
        # The one shape a swallowing implementation would have: catch the
        # failure, report 'unknown', and look honest.
        with mock.patch.object(
            E64LocalAPI, "rest_probe", side_effect=RuntimeError("the socket blew up")
        ):
            with self.assertRaises(RuntimeError) as caught:
                observe(case("dev-from-the-reviewed-capabilities"))
        self.assertIn("the socket blew up", str(caught.exception))

    def test_a_detector_that_raises_is_not_turned_into_unknown(self) -> None:
        with mock.patch.object(
            unlock_tiers, "detect", side_effect=RuntimeError("the detector blew up")
        ):
            with self.assertRaises(RuntimeError) as caught:
                observe(case("dev-from-the-reviewed-capabilities"))
        self.assertIn("the detector blew up", str(caught.exception))

    def test_unknown_and_a_confident_tier_do_not_share_a_report_shape(self) -> None:
        # Same class, different verdict: the difference is the tier and the
        # evidence, never an exception versus a value.
        unknown = observe(case("unknown-from-an-unreachable-device"))
        dev = observe(case("dev-from-the-reviewed-capabilities"))

        self.assertIs(type(unknown.report), type(dev.report))
        self.assertNotEqual(unknown.tier, dev.tier)
        self.assertIs(unknown.report.evidence["apiReached"], False)
        self.assertIs(dev.report.evidence["apiReached"], True)


if __name__ == "__main__":
    unittest.main()
