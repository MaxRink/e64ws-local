#!/usr/bin/env python3
"""The unlock tier of an E64 WS: what a device currently allows, and why.

Four tiers, and no others (``docs/UNLOCK_TIERS.md`` is the contract):

``stock``
    A shipped grinder: no root channel, no development profile.  The vendor
    REST and WSS surfaces answer; the 44 ``dev=1`` WSS records are skipped, and
    no ``action_*`` route answers because the reviewed module calls ``isDev()``
    before it handles anything and refuses with HTTP 403 when that is false.

``dev``
    ``/etc/issue`` begins with ``development`` and has exactly 14
    space-separated tokens, so ``isDevVersion()`` is true and the 44 ``dev=1``
    records dispatch.  Actions are still gated four more ways: the owner token,
    ``/db/e64local/actions.json``, the runner's sudoers rule, and — for the
    destructive class only — ``destructiveEnabled``.

``root``
    An owner SSH or dropbear channel answers as uid 0 (the FW-01/FW-02 paths).
    Root is what makes ``/etc/issue`` writable, so it is the only tier that can
    *become* dev on a stock image, but it is not dev: it opens no WSS record and
    no ``action_*`` route by itself.

``root-custom-api``
    Root plus the local owner API module installed and the runner's sudoers
    rule present — the state this repository builds.  Read routes answer, the
    five ``action_*`` meta routes answer, and the gate composition (token,
    policy file, sudoers, destructive flag) is actually able to answer instead
    of collapsing to ``503``.

``unknown`` is not a tier.  It is the honest answer when the observations do
not settle the question, and it always comes with ``reasons``.

This module is the single definition of the tier rule.  It is pure: no ``os``,
no ``socket``, no ``subprocess``, no clock, no file access.  The caller
observes the device — a ``capabilities`` response, an ``/etc/issue`` line, an
owner channel — and passes what it saw as *facts*.  A fact that was not
observed is absent or ``None``; a fact is never defaulted to ``False``, because
"the device said no" and "nobody asked" are different observations and the
second one must not be able to produce ``stock``.

Fact shape::

    {
        "api": {                      # what the local API answered
            "reached": bool,          # an HTTP response came back at all
            "status": int,            # HTTP status of the capabilities request
            "error_code": int,        # the envelope's errorCode
            "schema": str,            # data.schema
            "api_version": str,       # data.apiVersion
            "routes": [str],          # data.routes
            "read_routes_ok": bool,   # a read route (grind_log) answered
            "actions_enabled": bool,  # features.actions / data.actions.enabled
            "destructive_actions": bool,  # features.destructiveActions
            "action_answered": bool,  # an action_* route answered for the token
            "sudoers": bool,          # www-data may start the runner
        },
        "root": {                     # facts only a local channel can supply
            "channel": bool,          # an owner SSH/dropbear session answers
            "issue": str,             # the first line of /etc/issue, verbatim
        },
    }

``sudoers`` may be filled from an action probe (a ``503`` body) or from a root
read of ``/etc/sudoers.d/e64local``; ``issue`` from the owner's own read of
``/etc/issue``.  Both are local observations, not API facts.

``detect()`` returns ``{"tier", "evidence", "reasons"}`` and nothing else.
``evidence`` records what was used, so a caller can show its work — including
``unseparated``, the tiers the observations could not rule out.  ``reasons`` is
an ordered list of plain sentences that also states what the tier does not
grant.

Usage::

    from tools.unlock_tiers import detect, facts_from_capabilities

    facts = facts_from_capabilities(capabilities_json, status=200)
    facts["root"] = {"channel": None, "issue": issue_line}
    verdict = detect(facts)
    verdict["tier"]  # "stock" | "dev" | "root" | "root-custom-api" | "unknown"
"""

from __future__ import annotations

from typing import Any, Mapping

__all__ = [
    "TIER_STOCK",
    "TIER_DEV",
    "TIER_ROOT",
    "TIER_ROOT_CUSTOM_API",
    "TIER_UNKNOWN",
    "TIERS",
    "TIER_ORDER",
    "DEV_TOKEN",
    "DEV_TOKEN_COUNT",
    "REVIEWED_SCHEMAS",
    "OWNER_TOKEN_HEADER",
    "REVIEWED_API_VERSIONS",
    "ACTION_META_ROUTES",
    "READ_ROUTES",
    "rank",
    "at_least",
    "issue_tokens",
    "token_is_development",
    "issue_is_development",
    "facts_from_capabilities",
    "detect",
]

# --- The tier vocabulary ---------------------------------------------------------

TIER_STOCK = "stock"
TIER_DEV = "dev"
TIER_ROOT = "root"
#: Root plus the module and its runner rule; the document calls it
#: "root+custom API" and the identifier stays ASCII and shell-safe.
TIER_ROOT_CUSTOM_API = "root-custom-api"

#: Not a tier: the answer when the observations do not settle the question.
TIER_UNKNOWN = "unknown"

#: Exactly four tiers, weakest first.  Order is the monotonicity contract.
TIERS: tuple[str, str, str, str] = (TIER_STOCK, TIER_DEV, TIER_ROOT, TIER_ROOT_CUSTOM_API)

TIER_ORDER: dict[str, int] = {
    TIER_STOCK: 0,
    TIER_DEV: 1,
    TIER_ROOT: 2,
    TIER_ROOT_CUSTOM_API: 3,
}

# --- The dev-gate predicate ------------------------------------------------------
#
# ``RootfsVersionReader::isDevVersion`` (libNgxUi.so 0x233b08) compares token 0
# of the first line of /etc/issue with "development", case-insensitively, and
# ``readIssueFile`` (0x234168) only fills the field when the split yields
# exactly 14 tokens.  One word "development" does not unlock anything.
# See docs/DEV_MODE_AND_LOCAL_CONTROL.md and docs/bible/protocols.md 2.4.

DEV_TOKEN = "development"
DEV_TOKEN_COUNT = 14

# --- Module identity -------------------------------------------------------------
#
# ``capabilities`` is the module's own handshake.  Anything that is not this
# schema is not the reviewed module, so it proves nothing about the action
# layer or about the dev gate.

REVIEWED_SCHEMAS = frozenset({"e64local-api-v1"})
REVIEWED_API_VERSIONS = frozenset({"1"})

#: The read-only routes the module publishes (``$E64LOCAL_ROUTES``).
READ_ROUTES = frozenset(
    {
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
    }
)

#: The five meta routes.  Present in ``data.routes`` only when the gate is open.
ACTION_META_ROUTES = frozenset(
    {
        "action_audit",
        "action_cancel",
        "action_execute",
        "action_prepare",
        "action_status",
    }
)

#: HTTP statuses that mean something specific in this contract.
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
#: ``LOCAL_API.md`` §4.2: the dev-gate refusal is the only response that sets
#: HTTP 403 directly, because it exits before the vendor envelope.
HTTP_FORBIDDEN = 403
#: A route the vendor dispatcher does not know: the module is not installed.
HTTP_NOT_FOUND = 404


# --- Small helpers ---------------------------------------------------------------


def rank(tier: Any) -> int | None:
    """Return the position of ``tier`` in :data:`TIERS`, or ``None``."""
    return TIER_ORDER.get(tier) if isinstance(tier, str) else None


def at_least(tier: Any, floor: Any) -> bool:
    """True when ``tier`` is at least as strong as ``floor``.

    ``unknown`` is never at least anything, including itself: an unobserved
    device is not a weaker device, it is an unanswered question.
    """
    tier_rank = rank(tier)
    floor_rank = rank(floor)
    return tier_rank is not None and floor_rank is not None and tier_rank >= floor_rank


def issue_tokens(line: Any) -> list[str]:
    """Split the first line of ``/etc/issue`` the way the vendor parser does.

    Only the first line counts: the device reads one line and splits it on
    spaces with empty parts skipped.  A multi-line string is truncated, not
    concatenated.
    """
    if not isinstance(line, str):
        return []
    lines = line.splitlines()
    if not lines:
        return []
    return lines[0].split()


def token_is_development(token: Any) -> bool:
    """True when this single token is ``development``, case-insensitively.

    The vendor compares with ``Qt::CaseInsensitive``, so ``DEVELOPMENT`` and
    ``DeVeLoPmEnT`` are the same word.  Exact equality is required otherwise:
    ``develop`` is a different word and does not unlock anything.
    """
    return isinstance(token, str) and token.lower() == DEV_TOKEN


def issue_is_development(line: Any) -> bool:
    """True when this ``/etc/issue`` line opens the 14-token dev gate.

    Both halves are required, and both are load-bearing: token 0 must be
    ``development`` (case-insensitive) *and* the count must be exactly
    :data:`DEV_TOKEN_COUNT`.  ``development`` alone, ``develop image, ...`` and
    a 13- or 15-token line all return ``False``.
    """
    tokens = issue_tokens(line)
    if len(tokens) != DEV_TOKEN_COUNT:
        return False
    return token_is_development(tokens[0])


#: The header the module reads the owner token from (``LOCAL_API.md`` §2.3).
OWNER_TOKEN_HEADER = "X-E64-Local-Token"


# --- Fact normalisation ----------------------------------------------------------


def _block(facts: Any, name: str) -> Mapping[str, Any]:
    """Return one fact group, or an empty mapping when it was not supplied."""
    if not isinstance(facts, Mapping):
        return {}
    value = facts.get(name)
    return value if isinstance(value, Mapping) else {}


def _tri(value: Any) -> bool | None:
    """A three-state fact: ``True``, ``False`` or ``None`` (not observed).

    Only a real boolean counts.  A truthy string such as ``"false"`` is not an
    observation and must not be read as one, so it normalises to ``None``.
    """
    return value if isinstance(value, bool) else None


def _status(value: Any) -> int | None:
    """An HTTP status or ``errorCode``, or ``None`` when absent or not an int."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _routes(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _module_markers(api: Mapping[str, Any]) -> list[str]:
    """Return the observations that only the reviewed module can produce.

    Every marker sits behind one gate: the responder must identify itself with a
    reviewed schema.  Without that, the rest of an answer is worth nothing,
    because every part of it is trivially reproducible by anything that can
    serve HTTP on the device — a ``routes`` array, an ``apiVersion``, an enabled
    action gate, or a 200 from an ``action_*`` path.  A stranger's 200 must not
    raise the tier, so ``schema`` is checked first and an unrecognised (or
    missing) schema returns no markers at all.

    A marker is a positive statement about the module having answered, which
    means ``isDev()`` was true for that request.  A marker is never inferred
    from silence: a route that did not answer produces no marker.
    """
    schema = _text(api.get("schema"))
    if schema is None or schema not in REVIEWED_SCHEMAS:
        return []

    markers: list[str] = ["schema"]

    version = _text(api.get("api_version"))
    if version is not None and version in REVIEWED_API_VERSIONS and _status(api.get("status")) == HTTP_OK:
        markers.append("apiVersion")

    # 401 is the owner-token check, which lives in the module's dispatcher and
    # therefore runs after the dev gate.  A token failure proves the gate passed.
    if (
        _status(api.get("status")) == HTTP_UNAUTHORIZED
        or _status(api.get("error_code")) == HTTP_UNAUTHORIZED
    ):
        markers.append("ownerTokenCheck")

    routes = _routes(api.get("routes"))
    if any(route in ACTION_META_ROUTES for route in routes) or "capabilities" in routes:
        markers.append("routes")

    if _tri(api.get("action_answered")) is True:
        markers.append("actionAnswered")

    actions_enabled = _tri(api.get("actions_enabled"))
    if actions_enabled is True:
        markers.append("actionsEnabled")
    elif actions_enabled is False:
        markers.append("actionsDisabled")

    if _tri(api.get("destructive_actions")) is True:
        markers.append("destructiveActions")

    return markers


# --- The rule --------------------------------------------------------------------


def _decide(dev: bool, stock: bool, root: bool, custom_api: bool) -> str:
    """The whole tier rule, in six lines.

    Precedence is the monotonicity contract: a tier outranks every tier below
    it, and a contradiction is resolved upwards, so a device that reported a
    dev signal can never be classified stock.
    """
    if custom_api:
        return TIER_ROOT_CUSTOM_API
    if root:
        return TIER_ROOT
    if dev:
        return TIER_DEV
    if stock:
        return TIER_STOCK
    return TIER_UNKNOWN


def _unseparated(
    tier: str,
    *,
    dev_excluded: bool,
    root_excluded: bool,
    custom_excluded: bool,
) -> list[str]:
    """Tiers above ``tier`` that the observations could not rule out.

    This is how "cannot separate two adjacent tiers" is reported: the tier is
    the strongest one with positive support, and this list names the neighbour
    that would need one more observation.
    """
    above = {
        TIER_STOCK: (TIER_DEV, TIER_ROOT, TIER_ROOT_CUSTOM_API),
        TIER_DEV: (TIER_ROOT, TIER_ROOT_CUSTOM_API),
        TIER_ROOT: (TIER_ROOT_CUSTOM_API,),
        TIER_ROOT_CUSTOM_API: (),
        TIER_UNKNOWN: TIERS,
    }[tier]
    excluded: set[str] = set()
    if dev_excluded:
        excluded.add(TIER_DEV)
    if root_excluded:
        excluded.add(TIER_ROOT)
    if custom_excluded:
        excluded.add(TIER_ROOT_CUSTOM_API)
    return [candidate for candidate in above if candidate not in excluded]


def _action_notes(
    reasons: list[str],
    *,
    actions_enabled: bool | None,
    destructive: bool | None,
    sudoers: bool | None,
) -> None:
    """Append what the tier does *not* grant about the action layer."""
    if actions_enabled is True:
        reasons.append(
            "the action gate is open, so the five action_* meta routes exist, but every call "
            "still needs the owner token and still fails closed when the policy file changes"
        )
        if sudoers is False:
            reasons.append(
                "the runner's sudoers rule is absent, so every action_* route answers "
                "errorCode 503 even with the gate open"
            )
        elif sudoers is None:
            reasons.append(
                "whether www-data may start the runner was not observed, so the action layer "
                "may still answer errorCode 503"
            )
        if destructive is False:
            reasons.append(
                "the destructive gate is closed, so destructive routes are reported as "
                "blocked and are not dispatchable"
            )
        elif destructive is None:
            reasons.append("the destructive gate state was not observed")
    elif actions_enabled is False:
        reasons.append(
            "the action gate is closed (/db/e64local/actions.json is missing or not enabled), "
            "so every action_* route answers errorCode 403 before any parameter is parsed"
        )
    else:
        reasons.append(
            "the action gate state was not observed, so this tier says nothing about whether "
            "an action_* route would answer"
        )


def detect(facts: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Classify a device from what was actually observed.

    Returns ``{"tier", "evidence", "reasons"}``.  ``tier`` is one of
    :data:`TIERS` or ``"unknown"``.  The function never guesses: every branch
    that returns a tier has at least one observed signal behind it, the reasons
    name it, and ``evidence["unseparated"]`` names the neighbour that would
    take one more observation to rule out.
    """
    api = _block(facts, "api")
    root = _block(facts, "root")

    status = _status(api.get("status"))
    error_code = _status(api.get("error_code"))
    schema = _text(api.get("schema"))
    api_version = _text(api.get("api_version"))
    routes = _routes(api.get("routes"))
    reached = _tri(api.get("reached"))
    read_routes_ok = _tri(api.get("read_routes_ok"))
    actions_enabled = _tri(api.get("actions_enabled"))
    destructive = _tri(api.get("destructive_actions"))
    action_answered = _tri(api.get("action_answered"))
    sudoers = _tri(api.get("sudoers"))
    channel = _tri(root.get("channel"))
    issue = _text(root.get("issue"))

    tokens: list[str] | None = issue_tokens(issue) if issue is not None else None
    dev_issue: bool | None = issue_is_development(issue) if issue is not None else None
    markers = _module_markers(api)
    module_present = bool(markers)
    # A definitive "no": a route the vendor dispatcher does not know, or no PHP
    # answer at all.  A 500 is not definitive — a dev image without the module
    # answers the same way as a stock image without it.
    module_absent = bool(
        not module_present
        and (reached is False or status == HTTP_NOT_FOUND)
    )
    gate_refused = status == HTTP_FORBIDDEN

    evidence: dict[str, Any] = {
        "apiReached": reached,
        "apiStatus": status,
        "apiErrorCode": error_code,
        "apiSchema": schema,
        "apiVersion": api_version,
        "apiRoutes": list(routes),
        "readRoutesOk": read_routes_ok,
        "actionsEnabled": actions_enabled,
        "destructiveActions": destructive,
        "actionAnswered": action_answered,
        "sudoers": sudoers,
        "modulePresent": module_present,
        "moduleAbsent": module_absent,
        "moduleMarkers": list(markers),
        "devGateRefused": gate_refused,
        "rootChannel": channel,
        "issue": issue,
        "issueTokens": len(tokens) if tokens is not None else None,
        "devGateOpen": dev_issue,
        "unseparated": [],
    }

    # Positive support for each tier, strongest first.  ``custom_api`` is the
    # only tier that needs two facts (the module and its runner rule), unless an
    # action actually answered — which proves both at once.  Both branches stay
    # behind the schema gate: an ``action_answered`` fact from a responder that
    # never identified itself as the reviewed module is somebody else's 200.
    custom_support = module_present and (
        action_answered is True or (channel is True and sudoers is True)
    )
    root_support = channel is True
    dev_support = dev_issue is True or module_present
    stock_support = gate_refused or dev_issue is False

    reasons: list[str] = []
    tier = _decide(dev_support, stock_support, root_support, custom_support)

    dev_excluded = gate_refused or dev_issue is False
    root_excluded = channel is False
    custom_excluded = module_absent or sudoers is False
    evidence["unseparated"] = _unseparated(
        tier,
        dev_excluded=dev_excluded,
        root_excluded=root_excluded,
        custom_excluded=custom_excluded,
    )

    if tier == TIER_ROOT_CUSTOM_API:
        if action_answered is True:
            reasons.append(
                "an action_* route answered with the owner token, which proves the module is "
                "installed, the policy file parsed and the runner ran as root through its "
                "sudoers rule"
            )
        if channel is True:
            reasons.append(
                "an owner root channel answered as uid 0; that is what makes /etc/issue "
                "writable, so this device can also be moved to dev at will"
            )
        elif channel is None:
            reasons.append(
                "no owner root channel was observed; the action_* answer is what places this "
                "device at the top tier, not an interactive shell"
            )
        if module_present:
            reasons.append(
                "the reviewed module answered (" + ", ".join(markers) + "), so read routes and "
                "the five action_* meta routes are live"
            )
        if sudoers is True:
            reasons.append(
                "the runner's sudoers rule is present, so the action layer answers instead of "
                "collapsing to errorCode 503"
            )
        elif action_answered is True and sudoers is False:
            reasons.append(
                "the observations disagree: an action_* route answered without errorCode 503, "
                "which the runner's sudoers rule is what makes possible, while that rule was "
                "reported absent; the answer wins because a device that answered an action must "
                "not be classified below root-custom-api, and the colliding fact is recorded "
                "here rather than used"
            )
        if channel is False and action_answered is True:
            reasons.append(
                "no owner root channel was found, which does not contradict the answer: the "
                "runner is started by www-data through its sudoers rule, not through a shell"
            )
        reasons.append(
            "the gate composition still decides every call: the owner token, the policy file's "
            "enabled flag, the rate limits and — for destructive routes — the second flag"
        )
        _action_notes(
            reasons,
            actions_enabled=actions_enabled,
            destructive=destructive,
            sudoers=sudoers,
        )
    elif tier == TIER_ROOT:
        reasons.append(
            "an owner root channel answered as uid 0; that is the only signal that makes "
            "/etc/issue writable, so the dev tier is one edit away"
        )
        if dev_issue is True:
            reasons.append(
                "the observed /etc/issue is itself a development line with 14 tokens, so the "
                "WSS dev gate is already open"
            )
        elif dev_issue is False:
            reasons.append(
                "the observed /etc/issue does not open the WSS dev gate: token 0 is not "
                "'development' or the line does not have exactly 14 tokens"
            )
        else:
            reasons.append(
                "the /etc/issue line was not observed, so whether the WSS dev gate is open is "
                "unknown even with root"
            )
        if module_present and sudoers is not True:
            reasons.append(
                "the module answered but its runner rule was not confirmed, so this may be "
                "root-custom-api; an action_prepare, or a read of /etc/sudoers.d/e64local, "
                "would settle it"
            )
        elif not module_present and not module_absent:
            reasons.append(
                "the local API was not probed or answered ambiguously, so this may be "
                "root-custom-api; a capabilities call would settle it"
            )
        reasons.append(
            "root grants no action dispatch and no dev-gated WSS record by itself: the owner "
            "token, the policy file, the sudoers rule and the dev gate are separate"
        )
        _action_notes(
            reasons,
            actions_enabled=actions_enabled,
            destructive=destructive,
            sudoers=sudoers,
        )
    elif tier == TIER_DEV:
        if dev_issue is True:
            reasons.append(
                "the observed /etc/issue begins with 'development' and has exactly 14 tokens, "
                "so isDevVersion() is true"
            )
        if module_present:
            reasons.append(
                "the reviewed module answered past its dev gate (" + ", ".join(markers) + "), "
                "which it only does when isDev() is true"
            )
        reasons.append(
            "the 44 dev=1 WSS records dispatch on this image, including the 39 action records, "
            "and the shipped image refuses them"
        )
        reasons.append(
            "dev is not dev-mode-with-actions: an action still needs the owner token, an "
            "enabled policy file and the sudoers rule, and a destructive action needs the "
            "second flag"
        )
        _action_notes(
            reasons,
            actions_enabled=actions_enabled,
            destructive=destructive,
            sudoers=sudoers,
        )
        if channel is not False:
            reasons.append(
                "no root channel was excluded, so this may be root or root-custom-api; an "
                "owner SSH or dropbear login would settle it"
            )
        if gate_refused:
            reasons.append(
                "the observations disagree: the dev gate refused a request while a dev signal "
                "was reported, and the dev signal wins because a device that reported dev must "
                "never be classified stock"
            )
    elif tier == TIER_STOCK:
        if gate_refused:
            reasons.append(
                "the module answered HTTP 403 at its dev gate, so it is installed and the "
                "image is not a development image"
            )
        if dev_issue is False:
            reasons.append(
                "the observed /etc/issue is not a development line: token 0 is not "
                "'development' or the line does not have exactly 14 tokens, so "
                "isDevVersion() is false"
            )
        reasons.append(
            "stock grants the vendor REST and WSS surface and nothing else: the 44 dev=1 "
            "records are skipped and no action_* route answers"
        )
        if actions_enabled is True or destructive is True or action_answered is True:
            reasons.append(
                "the report also claimed the action layer answered, which a stock image "
                "cannot do; that claim was not used"
            )
    else:
        reasons.append(
            "no dev, stock or root signal was observed, so the tier is not decidable from "
            "these facts"
        )
        if not module_present:
            if status is None:
                reasons.append("the local API was not probed, so module presence is unknown")
            elif schema is not None:
                reasons.append(
                    f"the responder used schema {schema!r}, which is not a reviewed module "
                    f"schema ({', '.join(sorted(REVIEWED_SCHEMAS))}), so it proves nothing "
                    "about the dev gate or the action layer"
                )
            elif status == HTTP_OK:
                reasons.append(
                    f"the local API answered HTTP {status} without the reviewed schema "
                    f"({', '.join(sorted(REVIEWED_SCHEMAS))}), so the responder is not the "
                    "reviewed module"
                )
            elif error_code == HTTP_UNAUTHORIZED or status == HTTP_UNAUTHORIZED:
                reasons.append(
                    f"the responder answered errorCode {HTTP_UNAUTHORIZED}, which the reviewed "
                    "module only does at its owner-token check — after its dev gate — but an "
                    "unidentified responder can say 401 too, so the answer cannot be attributed "
                    f"to the module; read /etc/issue or send the owner token in "
                    f"{OWNER_TOKEN_HEADER} and the reviewed document will settle it"
                )
            else:
                reasons.append(
                    f"the local API answered HTTP {status} with no reviewed schema and no "
                    "module errorCode, and a stock image without the module answers the same "
                    "way as a development image without it, so this observation does not "
                    "settle which image it is"
                )
        if issue is None:
            reasons.append(
                "no /etc/issue line was supplied, so the token count and token 0 are unknown; "
                "a local or root channel is the only way to read it"
            )
        if channel is None:
            reasons.append(
                "no root channel fact was supplied, so whether an owner SSH or dropbear "
                "session answers is unknown"
            )
        if read_routes_ok is False:
            reasons.append(
                "the read routes did not answer, which is consistent with either a stock image "
                "or a development image that has no module installed"
            )

    return {"tier": tier, "evidence": evidence, "reasons": reasons}


# --- Caller helper ---------------------------------------------------------------


def facts_from_capabilities(
    document: Mapping[str, Any] | None,
    *,
    status: int | None = HTTP_OK,
) -> dict[str, Any]:
    """Build the ``api`` half of a fact set from a ``capabilities`` response.

    ``document`` may be the whole envelope (``{"data": {...}, "success": ...}``)
    or the ``data`` object alone.  Only keys the device actually sent become
    facts: a missing ``features.actions`` stays missing instead of becoming
    ``False``, because "the gate is closed" and "this firmware has no gate"
    are different observations.  The caller adds ``root`` facts itself and may
    add ``sudoers``, ``action_answered`` or ``read_routes_ok`` from its own
    probes.
    """
    api: dict[str, Any] = {"reached": True}
    if not isinstance(document, Mapping):
        return {"api": api}

    if status is not None:
        api["status"] = status
    if "errorCode" in document:
        code = _status(document.get("errorCode"))
        if code is not None:
            api["error_code"] = code

    data = document.get("data")
    if not isinstance(data, Mapping):
        data = document

    schema = _text(data.get("schema"))
    if schema is not None:
        api["schema"] = schema
    version = _text(data.get("apiVersion"))
    if version is not None:
        api["api_version"] = version
    routes = _routes(data.get("routes"))
    if routes:
        api["routes"] = list(routes)

    actions_enabled: bool | None = None
    destructive: bool | None = None

    features = data.get("features")
    if isinstance(features, Mapping):
        if "actions" in features:
            actions_enabled = _tri(features.get("actions"))
        if "destructiveActions" in features:
            destructive = _tri(features.get("destructiveActions"))

    # ``data.actions`` is the more specific document, so it wins when both exist.
    catalog = data.get("actions")
    if isinstance(catalog, Mapping):
        if "enabled" in catalog:
            actions_enabled = _tri(catalog.get("enabled"))
        if "destructiveEnabled" in catalog:
            destructive = _tri(catalog.get("destructiveEnabled"))

    if actions_enabled is not None:
        api["actions_enabled"] = actions_enabled
    if destructive is not None:
        api["destructive_actions"] = destructive
    return {"api": api}
