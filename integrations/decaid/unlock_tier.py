"""The unlock tier of a connected E64 WS, observed rather than assumed.

``tools/unlock_tiers.detect()`` is the single definition of the tier rule, and
``docs/UNLOCK_TIERS.md`` is its contract.  This module is the consumer for a
*real* connection: it gathers the facts an owner-side client can justify, hands
them to ``detect()``, and returns the verdict unchanged — the tier, the
evidence behind it, the reasons, and the ``unseparated`` neighbour.

What it gathers, and what it refuses to gather:

``capabilities``
    One ``POST /rest_api/capabilities`` with the owner token.  The answer is
    mapped with ``facts_from_capabilities()``, so a key the device did not send
    stays absent instead of becoming ``False``.  A ``403`` is the dev gate
    refusing, a ``401`` is the owner-token check, a ``404`` is a vendor
    dispatcher that does not know the route, and no response at all is
    ``reached: False``.  Each one is passed on as what it is.

the ``action_*`` answer
    Off by default, and never inferred.  An ``action_prepare`` for a route the
    caller names is the only way to see whether the action composition answers
    without a root channel, and it is not free: it spends one rate-limit slot of
    that route's bucket and leaves one prepared record that expires.  That is why
    it is opt-in — a tier probe that spent a slot per call would eat the budget
    the device's real actions need, so "what tier is this?" must not be able to
    block "grind 18 g".  Only ``HTTP 200`` — the module actually prepared an
    action, which it can only do after its preconditions ran through the runner —
    sets ``action_answered``.
    ``503`` sets ``action_answered: False`` and ``sudoers: False``, because the
    runner did not start.  Every other status is reported in ``notes`` and
    supplies *nothing*: a ``400``/``403``/``404``/``409``/``429`` is produced
    before the runner is consulted, so it would not justify the detector's "the
    runner ran as root through its sudoers rule" reason.

the local facts
    ``root.channel``, ``root.issue`` and ``api.sudoers`` are the caller's own
    observations, passed in as :class:`LocalObservations`.  They are never
    derived from an API answer here, and ``/etc/issue`` in particular is never
    read through the module's ``file`` route: ``detect()`` takes ``root.issue``
    at face value with no schema gate in front of it, so only a real local
    channel may fill it.  Anything that can answer HTTP could otherwise forge a
    development line and raise the verdict.

A fact that could not be observed stays absent, and ``detect()`` returns
``unknown``.  That is the feature, not a fallback: an unanswered question is not
a weak device (``docs/UNLOCK_TIERS.md`` §3).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from tools import unlock_tiers

__all__ = [
    "ACTION_PROBE_ROUTE",
    "CAPABILITIES_ROUTE",
    "ActionProbe",
    "LocalObservations",
    "UnlockTierReport",
    "detect_unlock_tier",
]

#: The module's own handshake (``docs/LOCAL_API.md`` §4.1).
CAPABILITIES_ROUTE = "capabilities"

#: The meta route ``docs/UNLOCK_TIERS.md`` §2.4 names as the probe.  It
#: validates and returns a single-use token; it never dispatches anything.
ACTION_PROBE_ROUTE = "action_prepare"

#: The status the module answers when the action runner did not start —
#: ``LOCAL_API.md`` §12.2, the missing sudoers rule.
HTTP_UNAVAILABLE = 503


@dataclass(frozen=True)
class LocalObservations:
    """The facts only a local channel can supply, as the caller saw them.

    Every field is three-state on purpose.  ``None`` means "not observed" and
    never becomes ``False``: a device with no channel that was probed is not the
    same device as one that was never probed (``tools/unlock_tiers.py``
    ``_tri()``).  A caller that has no channel leaves all three at ``None``.
    """

    #: An owner SSH or dropbear session answered as uid 0.
    channel: bool | None = None
    #: The first line of ``/etc/issue``, verbatim, read over that channel.
    issue: str | None = None
    #: ``www-data`` may start the action runner — ``/etc/sudoers.d/e64local``
    #: is present — read over that channel.  A direct look at the rule wins
    #: over the action probe's 503 reading, which is an inference from one
    #: refusal.
    sudoers: bool | None = None

    def __post_init__(self) -> None:
        for name in ("channel", "sudoers"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, bool):
                raise TypeError(
                    f"{name} is a three-state fact: pass True, False or None, not {value!r}"
                )
        if self.issue is not None and not isinstance(self.issue, str):
            raise TypeError(f"issue is the /etc/issue line as text, not {self.issue!r}")


@dataclass(frozen=True)
class ActionProbe:
    """One ``action_prepare`` the caller authorises, and its cost.

    There is no default route.  Preparing an action spends a rate-limit slot in
    that route's bucket and leaves one prepared record that expires on its own,
    so which route to spend it on is the owner's decision, not this module's.
    ``action_prepare`` never actuates: execution is ``action_execute`` with the
    returned single-use token, which this module discards.
    """

    #: A catalog action that reaches the runner through its preconditions,
    #: for example ``action_grind_start_gbw``.
    route: str
    params: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.route, str) or not self.route:
            raise TypeError("route must be a non-empty action identifier")
        if not isinstance(self.params, Mapping):
            raise TypeError("params must be a mapping")


@dataclass(frozen=True)
class UnlockTierReport:
    """What ``detect()`` answered, plus the facts it answered from.

    ``tier``, ``evidence`` and ``reasons`` are the detector's own document,
    unchanged: this class never re-derives a tier, so a caller cannot read one
    here that ``detect()`` did not return.  ``unseparated`` is the same
    document's ``evidence["unseparated"]``, lifted out because it is the field a
    caller acts on — it names the neighbour that one more observation would
    settle.
    """

    #: ``stock``, ``dev``, ``root``, ``root-custom-api`` or ``unknown``.
    tier: str
    #: ``detect()``'s evidence block, verbatim.
    evidence: Mapping[str, Any]
    #: ``detect()``'s ordered reasons, verbatim.
    reasons: tuple[str, ...]
    #: The facts handed to ``detect()``, so a caller can show its work.  These
    #: are observations, not a second verdict, and contain no credential.
    facts: Mapping[str, Any]
    #: This module's own notes: what could not be observed and why.  The
    #: detector never sees them and they never change the tier.
    notes: tuple[str, ...] = ()

    @property
    def unseparated(self) -> tuple[str, ...]:
        """The tiers the observations could not rule out, per the detector."""
        return tuple(str(name) for name in self.evidence.get("unseparated", ()))

    @property
    def is_unknown(self) -> bool:
        """True when the observations did not settle the question."""
        return self.tier == unlock_tiers.TIER_UNKNOWN

    def at_least(self, floor: str) -> bool:
        """``unlock_tiers.at_least()`` for this tier; unknown never passes."""
        return unlock_tiers.at_least(self.tier, floor)

    def as_document(self) -> dict[str, Any]:
        """JSON-serialisable form: the detector's document plus the notes."""
        return {
            "tier": self.tier,
            "evidence": dict(self.evidence),
            "reasons": list(self.reasons),
            "notes": list(self.notes),
        }


def _owner_headers(owner_token: str | None) -> dict[str, str] | None:
    """The owner-token header, or ``None`` when there is no token to send."""
    if not owner_token:
        return None
    return {unlock_tiers.OWNER_TOKEN_HEADER: owner_token}


def _status(response: Any) -> int | None:
    """The HTTP status of a probe response, or ``None`` when it is not one."""
    status = getattr(response, "status", None)
    if isinstance(status, bool) or not isinstance(status, int):
        return None
    return status


def _document(response: Any) -> Any:
    """Decode a probe response body, or ``None`` when it is not JSON."""
    decode = getattr(response, "json", None)
    if not callable(decode):
        return None
    try:
        return decode()
    except Exception:  # a non-JSON body is an answer without a document
        return None


def _capabilities_facts(
    probe: Any, owner_token: str | None
) -> tuple[dict[str, Any], str | None]:
    """The ``api`` facts one ``capabilities`` call justifies, and a note."""
    response = probe(CAPABILITIES_ROUTE, {}, headers=_owner_headers(owner_token))
    if response is None:
        return (
            {"reached": False},
            "the capabilities request got no HTTP response: nothing answered on "
            "that port, which is not the same observation as a device without "
            "the module",
        )

    status = _status(response)
    facts = unlock_tiers.facts_from_capabilities(_document(response), status=status)
    api_facts = dict(facts.get("api") or {})
    # ``facts_from_capabilities()`` returns before it copies the status when the
    # body is not a JSON object — a 500 from the vendor dispatcher, an HTML error
    # page.  The status is a fact in its own right and must not be lost with the
    # body: it is what separates "the dev gate refused" from "nobody answered".
    if status is not None and "status" not in api_facts:
        api_facts["status"] = status
    note: str | None = None
    if status == unlock_tiers.HTTP_UNAUTHORIZED:
        note = (
            "the module answered its owner-token check, which runs after its dev "
            "gate, but without the reviewed document nothing attributes that 401 "
            "to the module"
        )
    elif status == unlock_tiers.HTTP_FORBIDDEN:
        note = "the module refused at its dev gate, so the image is not a development image"
    return api_facts, note


def _action_probe_facts(
    probe: Any,
    owner_token: str | None,
    probe_spec: ActionProbe,
) -> tuple[dict[str, Any], str]:
    """The facts one ``action_prepare`` justifies, and a note."""
    if not owner_token:
        return (
            {},
            "the action probe was not sent: it needs the owner token, and a "
            "prepare without one answers 401 before the action layer is reached",
        )

    body = {
        "route": probe_spec.route,
        "params": dict(probe_spec.params),
        "requestId": uuid.uuid4().hex,
    }
    response = probe(ACTION_PROBE_ROUTE, body, headers=_owner_headers(owner_token))
    if response is None:
        return (
            {},
            "the action probe got no HTTP response, so whether an action_* route "
            "answers is not observed",
        )

    status = _status(response)
    if status == unlock_tiers.HTTP_OK:
        return (
            {"action_answered": True},
            f"an action_prepare for {probe_spec.route} answered HTTP 200, so the "
            "module prepared an action after its preconditions ran through the runner",
        )
    if status == HTTP_UNAVAILABLE:
        return (
            {"action_answered": False, "sudoers": False},
            f"an action_prepare for {probe_spec.route} answered HTTP 503: the "
            "runner did not start, which the contract reads as the runner's "
            "sudoers rule being absent",
        )
    return (
        {},
        f"an action_prepare for {probe_spec.route} answered HTTP {status}, which "
        "the module produces before the runner is consulted; it does not "
        "establish the sudoers rule, so no action_answered fact was supplied",
    )


def detect_unlock_tier(
    api: Any,
    *,
    owner_token: str | None = None,
    local: LocalObservations | None = None,
    action_probe: ActionProbe | None = None,
) -> UnlockTierReport:
    """Classify a connected device with ``tools.unlock_tiers.detect()``.

    ``api`` is any object with ``rest_probe(route, body, *, headers)`` returning
    a response with ``status`` and ``json()`` — normally
    :class:`tools.e64ws_api.E64LocalAPI`, and a stub in the tests.  ``local``
    carries the caller's own channel observations; ``action_probe`` authorises
    the one call that can establish the action layer without root.

    The detector's verdict is returned as it came back, including ``unknown``:
    no branch here names a tier of its own.
    """
    observations = local or LocalObservations()
    notes: list[str] = []
    api_facts: dict[str, Any] = {}

    probe = getattr(api, "rest_probe", None)
    if not callable(probe):
        notes.append(
            "the API client cannot probe REST routes, so no capability was observed"
        )
    else:
        api_facts, capabilities_note = _capabilities_facts(probe, owner_token)
        if capabilities_note is not None:
            notes.append(capabilities_note)
        if action_probe is not None:
            probe_facts, probe_note = _action_probe_facts(probe, owner_token, action_probe)
            api_facts.update(probe_facts)
            notes.append(probe_note)

    if observations.sudoers is not None or "sudoers" in api_facts:
        # A ``False`` from either side wins.  The action probe's 503 says the
        # runner did not start; a caller's root read says the rule file is (or
        # is not) there.  Where they disagree, the tier is a claim about what
        # can answer, so the observation that something did not answer is the
        # one that must not be erased — a present rule with a runner that
        # refuses is ``root``, not ``root-custom-api`` (docs/UNLOCK_TIERS.md
        # §2.4, "Runner binary removed").
        if observations.sudoers is False or api_facts.get("sudoers") is False:
            api_facts["sudoers"] = False
        else:
            api_facts["sudoers"] = True

    facts: dict[str, Any] = {
        "api": api_facts,
        "root": {"channel": observations.channel, "issue": observations.issue},
    }

    verdict = unlock_tiers.detect(facts)
    return UnlockTierReport(
        tier=str(verdict["tier"]),
        evidence=dict(verdict["evidence"]),
        reasons=tuple(str(reason) for reason in verdict["reasons"]),
        facts=facts,
        notes=tuple(notes),
    )
