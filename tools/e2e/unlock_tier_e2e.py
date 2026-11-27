#!/usr/bin/env python3
"""Observe the unlock tier of a simulated E64 WS, one fixture per outcome.

``tools/test_unlock_tiers.py`` proves the *rule*: it hands ``detect()`` a fact
set and checks the verdict, and it drives the adapter against a transport stub.
Neither shows that a plugin which opens a socket to a device gets the tier the
contract promises.  This module is that path, and nothing else:

    E64DecaidAdapter.unlock_tier()      (integrations/decaid/)
      -> detect_unlock_tier()           the consumer a plugin calls
      -> E64LocalAPI.rest_probe()       a real HTTP request over a real socket
      -> 127.0.0.1:<port>               SimulatedLocalApi behind the vendor envelope
      -> tools.unlock_tiers.detect()    the one definition of the tier rule

No test in this module calls ``detect()``.  The assertion is on the
``UnlockTierReport`` the plugin gets back, so a fixture that stops producing an
outcome fails here even when ``detect()`` is untouched.

The simulator is the one under ``tools/``, started through its own
``_http_server()`` on an ephemeral loopback port — the harness
``tools/test_e64ws_simulator.py`` already uses.  There is no second fixture and
no stubbed transport: the adapter is given a real :class:`E64LocalAPI`.

One fixture per outcome
-----------------------
``docs/UNLOCK_TIERS.md`` §2 defines the tiers by the observations that separate
them.  A fixture is a *device state*, so the interesting ones are the states the
rule has to tell apart:

========================  ==============================================  ==============
fixture                   device state                                    tier
========================  ==============================================  ==============
locked dev gate           ``dev=0``: HTTP 403 at the module's gate        ``stock``
default                   development image, module, action gate shut     ``dev``
owner channel             the same, plus an owner shell as uid 0          ``root``
action gate open          + one ``action_prepare`` answers HTTP 200       ``root-custom-api``
runner rule read          + the caller read ``/etc/sudoers.d/e64local``   ``root-custom-api``
destructive gate open     + the destructive flag, a destructive prepare   ``root-custom-api``
nothing listening         no responder on the port                        ``unknown``
wrong owner token         HTTP 401 with no reviewed document              ``unknown``
prerunner refusal         an open gate and an ``action_prepare`` 403      ``dev``
========================  ==============================================  ==============

What the simulator cannot represent is named in the docstrings of the cases
that need it (``LocalObservations`` cases) and in
``tools/test_unlock_tier_e2e.py``: it owns no SSH or dropbear channel, no
``/etc/sudoers.d/e64local`` file and no separate runner process, so the facts
those produce are supplied by the caller exactly as a plugin's own root channel
would supply them.

Usage::

    python3 tools/e2e/unlock_tier_e2e.py                       # every fixture
    python3 tools/e2e/unlock_tier_e2e.py --only stock-from     # by name prefix
    python3 tools/e2e/unlock_tier_e2e.py --json /tmp/tier.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:  # ``python tools/e2e/unlock_tier_e2e.py``
    sys.path.insert(0, str(ROOT))

from integrations.decaid.e64ws_adapter import (  # noqa: E402  (after the path guard)
    ActionProbe,
    E64DecaidAdapter,
    LocalObservations,
    UnlockTierReport,
)
from tools import unlock_tiers  # noqa: E402
from tools.e64ws_api import E64LocalAPI, E64WSAPIError  # noqa: E402
from tools.e64ws_simulator import (  # noqa: E402
    SimulatedAuth,
    SimulatedGrinder,
    SimulatedLocalApi,
    SimulatedScale,
    _http_server,
)
from tools.unlock_tiers import (  # noqa: E402
    TIER_DEV,
    TIER_ROOT,
    TIER_ROOT_CUSTOM_API,
    TIER_STOCK,
    TIER_UNKNOWN,
    TIERS,
)

#: The owner token ``/db/e64local/token`` holds on a device this repository
#: built.  Derived rather than random, so a transcript is reproducible; the
#: fixture accepts any string (``--api-token``), and 64 hex characters are what
#: a real ``OwnerToken`` looks like.
API_TOKEN = hashlib.sha256(b"e64-local-unlock-tier-e2e").hexdigest()

#: A token the fixture does not accept.  Used to make the module answer its
#: owner-token check, which is an answer that settles nothing (``unknown``).
REJECTED_TOKEN = hashlib.sha256(b"not-the-owner-token-of-this-device").hexdigest()

#: The fixture's session password (``docs/SIMULATOR.md``).  A plugin logs in
#: before it probes, because the module answers its session check first.
SESSION_PASSWORD = "sim-password"

#: The fixture's WSS bearer.  The tier path never opens a WebSocket; the client
#: needs *a* token to exist, and using the fixture value keeps it honest.
WSS_TOKEN = "mock-e64-token-0001"

#: The development line the fixture's ``/etc/issue`` carries.  Token 0 is
#: ``development`` and the line has 14 tokens, so ``isDevVersion()`` is true.
#: It is read here as a *caller observation* — never through the module's
#: ``file`` route, which ``integrations/decaid/unlock_tier.py`` refuses (§7.1).
ISSUE_LINE = SimulatedLocalApi.ISSUE_LINE


# --- The fixture -------------------------------------------------------------


@dataclass(frozen=True)
class Fixture:
    """One simulator device state, as far as tier discovery is concerned."""

    #: ``True`` makes the module answer HTTP 403 at its dev gate before any
    #: route runs — a shipped image (``SimulatedGrinder.dev_mode`` is false).
    dev_gate_locked: bool = False
    #: ``--enable-actions``: the policy file parsed, so the five meta routes
    #: exist and ``action_prepare`` can reach the runner.
    actions_enabled: bool = False
    #: ``--enable-destructive-actions``: the second flag, for the routes that
    #: need it.  Requires ``actions_enabled``.
    destructive_enabled: bool = False
    #: The owner token the module accepts.
    api_token: str = API_TOKEN
    #: ``False`` models a device that is not answering: the case is pointed at
    #: a port that was free a moment ago and nothing is bound to it, so the
    #: connection is refused instead of timing out.
    listening: bool = True

    def describe(self) -> str:
        """A short state description for the report."""
        if not self.listening:
            return "nothing listening"
        parts = ["dev gate locked" if self.dev_gate_locked else "development image"]
        parts.append("action gate open" if self.actions_enabled else "action gate shut")
        if self.destructive_enabled:
            parts.append("destructive gate open")
        return ", ".join(parts)


@dataclass
class Device:
    """A running (or deliberately silent) simulator, and how to reach it."""

    fixture: Fixture
    host: str = "127.0.0.1"
    port: int = 0
    grinder: SimulatedGrinder | None = None
    scale: SimulatedScale | None = None
    auth: SimulatedAuth | None = None
    local_api: SimulatedLocalApi | None = None
    server: Any = None

    @property
    def listening(self) -> bool:
        return self.server is not None

    def listen(self) -> None:
        """Start answering on this device, on a fresh ephemeral port.

        A ``Fixture(listening=False)`` device is silent; calling this is how a
        test proves the *silence* is what its assertion depends on.  The port
        changes, so anything already pointed at the old one keeps seeing a
        refused connection.
        """
        if self.listening:
            return
        assert self.grinder is not None and self.scale is not None
        assert self.auth is not None
        self.server = _http_server(
            self.host,
            0,
            self.grinder,
            self.scale,
            self.auth,
            actions_enabled=self.fixture.actions_enabled,
            destructive_enabled=self.fixture.destructive_enabled,
            api_token=self.fixture.api_token,
        )
        self.port = int(self.server.server_port)
        # ``_http_server()`` stores (grinder, scale, auth, apk, onboarding,
        # local_api); the handler reads it back in that order.
        self.local_api = self.server.simulator[-1]

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def audit(self) -> tuple[Mapping[str, Any], ...]:
        """The fixture's own action audit: what the plugin made this device do."""
        if self.local_api is None:
            return ()
        return tuple(self.local_api.actions.audit)

    def rate_usage(self) -> dict[str, int]:
        """Rate-limit slots spent, per bucket, as the action engine counts them."""
        if self.local_api is None:
            return {}
        return {bucket: len(slots) for bucket, slots in self.local_api.actions.rate.items()}

    def prepared_records(self) -> tuple[tuple[str, str], ...]:
        """``(state, route)`` for every action record the device is holding."""
        if self.local_api is None:
            return ()
        return tuple(
            (str(record.get("state")), str(record.get("route")))
            for record in self.local_api.actions.records.values()
        )


def free_port(host: str = "127.0.0.1") -> int:
    """A port nothing is bound to, once the socket that found it is closed.

    The same primitive ``tools/e2e/run_apps_e2e.py`` uses.  It is a reservation,
    not a lock: another process can take the port between the close and the
    probe.  The window is one statement wide, and the failure it would cause is
    a *reached* device in a case that asserts ``unknown``, which names the
    fixture rather than passing quietly.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


def start(fixture: Fixture) -> Device:
    """Build the fixture's device and, unless it is silent, start it."""
    grinder = SimulatedGrinder(dev_mode=not fixture.dev_gate_locked)
    device = Device(
        fixture=fixture,
        grinder=grinder,
        scale=SimulatedScale(),
        auth=SimulatedAuth(WSS_TOKEN),
    )
    if fixture.listening:
        device.listen()
    else:
        device.port = free_port(device.host)
    return device


# --- The cases ---------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    """One fixture plus the observations a plugin brings to it, and the tier."""

    name: str
    #: The tier ``E64DecaidAdapter.unlock_tier()`` must report.
    expected: str
    fixture: Fixture
    #: The neighbour(s) the observations cannot rule out, per ``detect()``.
    unseparated: tuple[str, ...] = ()
    #: What the caller observed over its own root channel, if it holds one.
    local: LocalObservations | None = None
    #: The one ``action_prepare`` the caller authorises, if any.
    probe: ActionProbe | None = None
    #: The owner token the plugin sends.  ``None`` sends none.
    owner_token: str | None = API_TOKEN
    #: ``True`` when the fixture must refuse the login too (nothing answered).
    login_fails: bool = False
    #: One sentence: the state this case turns on.
    turns_on: str = ""


CASES: tuple[Case, ...] = (
    Case(
        name="stock-from-the-dev-gate-refusing",
        expected=TIER_STOCK,
        fixture=Fixture(dev_gate_locked=True),
        unseparated=(TIER_ROOT, TIER_ROOT_CUSTOM_API),
        turns_on="HTTP 403 at the module's dev gate, which only a non-development "
        "image produces",
    ),
    Case(
        name="dev-from-the-reviewed-capabilities",
        expected=TIER_DEV,
        fixture=Fixture(),
        unseparated=(TIER_ROOT, TIER_ROOT_CUSTOM_API),
        turns_on="the reviewed schema answering a 200: the module runs past "
        "isDev(), and no owner channel was observed",
    ),
    Case(
        name="root-from-the-owner-channel",
        expected=TIER_ROOT,
        fixture=Fixture(),
        unseparated=(TIER_ROOT_CUSTOM_API,),
        local=LocalObservations(channel=True, issue=ISSUE_LINE),
        turns_on="an owner shell as uid 0 observed by the caller; the runner's "
        "rule is still unread, so the top tier stays in 'unseparated'",
    ),
    Case(
        name="root-custom-api-from-one-action-prepare",
        expected=TIER_ROOT_CUSTOM_API,
        fixture=Fixture(actions_enabled=True),
        unseparated=(),
        probe=ActionProbe("action_grind_start_gbw", {"targetWeightGr": 18}),
        turns_on="one action_prepare answering HTTP 200 through the open gate, "
        "with no root channel at all",
    ),
    Case(
        name="root-custom-api-from-the-sudoers-observation",
        expected=TIER_ROOT_CUSTOM_API,
        fixture=Fixture(actions_enabled=True),
        unseparated=(),
        local=LocalObservations(channel=True, issue=ISSUE_LINE, sudoers=True),
        turns_on="the caller read /etc/sudoers.d/e64local and found the runner "
        "rule, so the second half of the top tier is satisfied without a probe",
    ),
    Case(
        name="unknown-from-an-unreachable-device",
        expected=TIER_UNKNOWN,
        fixture=Fixture(listening=False),
        # No response also means no module answered, so the top tier *is*
        # excluded here; dev, stock and root are not, and none of them is
        # supported either.  'unknown' is the answer, not a fallback.
        unseparated=(TIER_STOCK, TIER_DEV, TIER_ROOT),
        login_fails=True,
        turns_on="nothing answering on the port: no response is not a device "
        "without the module, and it is not an exception either",
    ),
    Case(
        name="unknown-from-a-bare-401",
        expected=TIER_UNKNOWN,
        fixture=Fixture(),
        unseparated=TIERS,
        owner_token=REJECTED_TOKEN,
        turns_on="HTTP 401 with no reviewed document: the module's owner-token "
        "check runs after its dev gate, but an unidentified responder can say "
        "401 too",
    ),
    Case(
        name="root-custom-api-from-a-destructive-prepare",
        expected=TIER_ROOT_CUSTOM_API,
        fixture=Fixture(actions_enabled=True, destructive_enabled=True),
        unseparated=(),
        probe=ActionProbe("action_logs_clear"),
        turns_on="the same prepare as the refused one below, one flag apart: "
        "the destructive gate is open, so the runner answers",
    ),
    Case(
        name="dev-when-the-prepare-is-refused-before-the-runner",
        expected=TIER_DEV,
        fixture=Fixture(actions_enabled=True),
        unseparated=(TIER_ROOT, TIER_ROOT_CUSTOM_API),
        probe=ActionProbe("action_logs_clear"),
        turns_on="the same prepare, with the destructive flag shut: it answers "
        "403 before the runner is consulted, so that status excludes nothing "
        "and the top tier stays unseparated",
    ),
)


def case(name: str) -> Case:
    """The case with this name (or a unique prefix)."""
    matches = [entry for entry in CASES if entry.name == name]
    if not matches:
        matches = [entry for entry in CASES if entry.name.startswith(name)]
    if len(matches) != 1:
        raise KeyError(
            f"no unique fixture called {name!r}; known: "
            + ", ".join(entry.name for entry in CASES)
        )
    return matches[0]


# --- The observation ---------------------------------------------------------


@dataclass(frozen=True)
class CaseResult:
    """What the plugin reported, and what the device saw while it did."""

    case: Case
    report: UnlockTierReport
    #: The tier the plugin reported.  Lifted out so an assertion can name it
    #: without reaching into the report.
    tier: str
    #: The error the login raised, when the fixture refused it.  ``None`` when
    #: the session was established.
    login_error: E64WSAPIError | None = None
    #: The fixture's own action audit, taken after the probe.
    audit: tuple[Mapping[str, Any], ...] = ()

    def as_document(self) -> dict[str, Any]:
        return {
            "fixture": self.case.name,
            "device": self.case.fixture.describe(),
            "expected": self.case.expected,
            "observed": self.tier,
            "unseparated": list(self.report.unseparated),
            "notes": list(self.report.notes),
            "audit": [dict(entry) for entry in self.audit],
        }


def observe(case_to_run: Case, device: Device | None = None) -> CaseResult:
    """Run the plugin's tier path against ``device`` and return its report.

    ``device`` is explicit so a test can hand over a device it has modified;
    when it is omitted the case's own fixture is started (and stopped again).
    """
    owned = device is None
    if device is None:
        device = start(case_to_run.fixture)
    try:
        api = E64LocalAPI(
            device.host,
            scheme="ws",
            rest_port=device.port,
            token=WSS_TOKEN,
            timeout=5.0,
        )
        login_error: E64WSAPIError | None = None
        try:
            try:
                api.login("Owner", SESSION_PASSWORD)
            except E64WSAPIError as error:
                login_error = error
            adapter = E64DecaidAdapter(api, owner_token=case_to_run.owner_token)
            report = adapter.unlock_tier(
                local=case_to_run.local,
                action_probe=case_to_run.probe,
            )
        finally:
            api.close()
        return CaseResult(
            case=case_to_run,
            report=report,
            tier=report.tier,
            login_error=login_error,
            audit=device.audit(),
        )
    finally:
        if owned:
            device.stop()


def assert_case(case_to_run: Case, result: CaseResult) -> None:
    """Assert one case's outcome, naming the tier in every failure.

    This is the only assertion the end-to-end suite makes about a tier, so the
    passing tests and the mutation proofs cannot drift apart: both go through
    here.  A failure is an :class:`AssertionError` whose first sentence names
    the tier the case asserts, which is what makes a broken fixture readable in
    a CI log.
    """
    if result.tier != case_to_run.expected:
        raise AssertionError(
            f"unlock-tier e2e: the fixture {case_to_run.name!r} must report the "
            f"{case_to_run.expected!r} tier, but the plugin reported "
            f"{result.tier!r}. The fixture is {case_to_run.fixture.describe()!r} "
            f"and it turns on: {case_to_run.turns_on}. The device's reasons were: "
            + " | ".join(result.report.reasons)
        )
    if tuple(result.report.unseparated) != tuple(case_to_run.unseparated):
        raise AssertionError(
            f"unlock-tier e2e: the fixture {case_to_run.name!r} asserts the "
            f"{case_to_run.expected!r} tier and the neighbours "
            f"{list(case_to_run.unseparated)!r}, but the report left "
            f"{list(result.report.unseparated)!r} unseparated"
        )
    if case_to_run.login_fails and result.login_error is None:
        raise AssertionError(
            f"unlock-tier e2e: the fixture {case_to_run.name!r} asserts the "
            f"{case_to_run.expected!r} tier because nothing answered, but the "
            "login succeeded: this device is reachable"
        )
    if not case_to_run.login_fails and result.login_error is not None:
        raise AssertionError(
            f"unlock-tier e2e: the fixture {case_to_run.name!r} asserts the "
            f"{case_to_run.expected!r} tier from an established session, but the "
            f"login failed: {result.login_error}"
        )
    if case_to_run.expected == TIER_UNKNOWN:
        # 'unknown' is not a floor: it is never at least anything, including
        # itself, and a caller that rounds it to a tier is claiming an
        # observation nobody made.
        if result.report.at_least(TIER_STOCK):
            raise AssertionError(
                f"unlock-tier e2e: the fixture {case_to_run.name!r} reports the "
                "'unknown' tier, which must never be at least 'stock'"
            )
        return
    if not result.report.at_least(case_to_run.expected):
        raise AssertionError(
            f"unlock-tier e2e: the fixture {case_to_run.name!r} reports the "
            f"{result.tier!r} tier, which is not at least the "
            f"{case_to_run.expected!r} tier it asserts"
        )


def run(cases: tuple[Case, ...] = CASES) -> list[tuple[CaseResult, AssertionError | None]]:
    """Observe and assert every case; never stop at the first failure."""
    outcomes: list[tuple[CaseResult, AssertionError | None]] = []
    for entry in cases:
        result = observe(entry)
        failure: AssertionError | None = None
        try:
            assert_case(entry, result)
        except AssertionError as error:  # collected so one break does not hide four
            failure = error
        outcomes.append((result, failure))
    return outcomes


def evidence_table(cases: tuple[Case, ...] = CASES) -> str:
    """The per-tier evidence table, rendered from the case table."""
    rows = [("fixture", "device state", "expected", "unseparated")]
    for entry in cases:
        rows.append(
            (
                entry.name,
                entry.fixture.describe(),
                entry.expected,
                ", ".join(entry.unseparated) or "-",
            )
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    return "\n".join(
        "  ".join(value.ljust(widths[column]) for column, value in enumerate(row)).rstrip()
        for row in rows
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observe the unlock tier of a simulated E64 WS.")
    parser.add_argument("--only", help="run the fixtures whose name starts with this")
    parser.add_argument("--json", type=Path, help="write the report here")
    parser.add_argument("--table", action="store_true", help="print the evidence table and stop")
    args = parser.parse_args(argv)

    if args.table:
        print(evidence_table())
        return 0

    selected = (
        CASES
        if not args.only
        else tuple(entry for entry in CASES if entry.name.startswith(args.only))
    )
    if not selected:
        print(f"E2E FAIL no fixture starts with {args.only!r}", file=sys.stderr)
        return 2

    outcomes = run(selected)
    failures = [(result, failure) for result, failure in outcomes if failure is not None]
    report = {
        "cases": [result.as_document() for result, _ in outcomes],
        "passed": len(outcomes) - len(failures),
        "failed": len(failures),
    }
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    for result, failure in outcomes:
        verdict = "FAIL" if failure else "ok"
        print(f"{verdict:<4} {result.case.name:<48} {result.tier}")
        if failure:
            print(f"     {failure}")

    if failures:
        print(f"E2E FAIL {len(failures)} of {len(outcomes)} fixtures", file=sys.stderr)
        return 1
    print(f"E2E PASS {len(outcomes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
