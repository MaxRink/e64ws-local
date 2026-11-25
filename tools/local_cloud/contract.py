"""Machine-readable record of what the local cloud may and may not answer.

Why this module exists
----------------------

``docs/LOCAL_CLOUD_DESIGN.md`` records ten device-service routes (D01-D10) at
very different evidence levels.  Some carry observed request and response
literals (D01, D05, D07), some have an observed path and nothing else (D03,
D06, D09), and some leave the very shape of the reply open (D04, D08, D10).

A skeleton that answers every route with a plausible-looking JSON body would
invent a wire format, and the firmware would happily parse the invention into a
wrong decision.  So the evidence state is data here, not prose: every route
carries the field paths the design marks ``unknown — needs capture``, and the
service refuses those fields with ``501`` plus a stable reason token and the
D-id.  Tests read this table, so a route cannot gain or lose an unknown field
without a test noticing.

Nothing in this module is a claim about the vendor.  Each entry quotes the
design document's own confidence wording (its §2.1 table and §5 per-route
sections); the ``evidence`` strings are kept close to the document's "Conf"
column on purpose.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: The literal marker the design document uses for "no evidence".
UNKNOWN_MARKER = "unknown — needs capture"

#: Pointer appended to every refusal so a log line leads to the gap.
DESIGN_POINTER = "docs/LOCAL_CLOUD_DESIGN.md"


@dataclass(frozen=True)
class Unknown:
    """One field the design leaves unrecorded, and why it cannot be guessed."""

    field: str
    """Stable path, e.g. ``D10.response.format``.  Used by tests and logs."""

    reason: str
    """Machine-readable reason token carried in the 501 body."""

    detail: str
    """One sentence: what is missing and why a guess would be unsafe."""


@dataclass(frozen=True)
class Route:
    """A recorded device-service route and its evidence state."""

    d_id: str
    path: str
    methods: tuple[str, ...]
    evidence: str
    summary: str
    unknown: tuple[Unknown, ...]


#: D01..D10 in the order the design documents them (its §2.1 table).
#:
#: ``methods`` is the *local* acceptance set.  Where the design records a
#: method as unknown (D03, D06: firmware ``requestType 3``) both GET and POST
#: are accepted, exactly as §5 asks, instead of betting on one.
ROUTES: tuple[Route, ...] = (
    Route(
        d_id="D01",
        path="/api/device-service/brew-event/find",
        methods=("POST",),
        evidence="route and request wrapper observed; element fields observed; "
        "remaining wrapper keys unknown",
        summary="Brew events for Grind-by-Sync.",
        unknown=(
            Unknown(
                field="D01.response.wrapper-extra-keys",
                reason="wrapper-extra-keys-unknown",
                detail="Only the `payload` key of each array element is recorded; "
                "whether the vendor wrapper carries a second key (a count, a "
                "cursor) was never captured, so only `payload` is emitted.",
            ),
            Unknown(
                field="D01.element.cloudDate.format",
                reason="cloud-date-format-unknown",
                detail="`cloudDate` (API_REFERENCE.md §4.4) has no recorded format; "
                "the local server emits the ISO-8601 UTC shape it sees in the "
                "observed `deviceDateRange.from` cursor, which the firmware is not "
                "known to accept.",
            ),
        ),
    ),
    Route(
        d_id="D02",
        path="/api/device-service/brewer-binding/find",
        methods=("GET",),
        evidence="route observed; GET method and query keys inferred",
        summary="Scale/brewer bindings; empty until an owner creates one.",
        unknown=(
            Unknown(
                field="D02.query.keys",
                reason="query-keys-unknown",
                detail="The binding query object's key names were never captured, so "
                "the server ignores the query string instead of binding to "
                "invented parameter names; the reply is the recorded empty array.",
            ),
        ),
    ),
    Route(
        d_id="D03",
        path="/api/device-service/system/device-cert-download",
        methods=("GET", "POST"),
        evidence="route observed; method and payload unknown; PEM body inferred",
        summary="Client-certificate provisioning.",
        unknown=(
            Unknown(
                field="D03.request.method",
                reason="method-unknown",
                detail="The firmware uses requestType 3 and the wire effect is not "
                "recovered; both GET and POST are accepted rather than choosing.",
            ),
            Unknown(
                field="D03.no-update.response",
                reason="no-update-response-unknown",
                detail="The firmware has a 'no certificate update' path, but which "
                "wire response triggers it (204, 304, an empty 200 or a JSON flag) "
                "is unrecorded, so an empty queue is refused instead of answered.",
            ),
        ),
    ),
    Route(
        d_id="D04",
        path="/api/device-service/cloud-recipe-slot/find",
        methods=("GET",),
        evidence="route and query keys observed; encoding inferred; element schema unknown",
        summary="Published recipe slots for this device.",
        unknown=(
            Unknown(
                field="D04.response.element-schema",
                reason="element-schema-unknown",
                detail="No published-recipe element was ever captured, so a "
                "non-empty slot list cannot be serialised; the empty array the "
                "design prescribes is served instead.",
            ),
        ),
    ),
    Route(
        d_id="D05",
        path="/api/device-service/device-event/fire",
        methods=("POST",),
        evidence="route, event type literals and base fields observed; discriminator key unknown",
        summary="Grind, service, error and settings event upload.",
        unknown=(
            Unknown(
                field="D05.request.discriminator-key",
                reason="discriminator-key-unknown",
                detail="The key that carries the event type is not pinned, so the "
                "stored type is detected by matching the observed type literals "
                "anywhere in the body instead of assuming a key name.",
            ),
            Unknown(
                field="D05.response.body",
                reason="reply-body-unknown",
                detail="The design records no response body for this route; an "
                "empty JSON object is returned and the choice is logged as "
                "unverified.",
            ),
        ),
    ),
    Route(
        d_id="D06",
        path="/api/device-service/device-event/status",
        methods=("GET", "POST"),
        evidence="route and request keys observed; method and response shape unknown",
        summary="Device heartbeat.",
        unknown=(
            Unknown(
                field="D06.request.method",
                reason="method-unknown",
                detail="requestType 3 has no recovered wire method; both GET and "
                "POST are accepted and the heartbeat is recorded either way.",
            ),
            Unknown(
                field="D06.response.shape",
                reason="response-shape-unknown",
                detail="The recorded key set is DEVICE_STATUS and interval only; "
                "the reply shape was never captured, so the design's explicit "
                "empty JSON object is sent rather than a guessed status document.",
            ),
        ),
    ),
    Route(
        d_id="D07",
        path="/api/device-service/firmware/checkUpdate",
        methods=("GET",),
        evidence="route, query and reply keys observed; no-update shape unknown",
        summary="Firmware update notification.",
        unknown=(
            Unknown(
                field="D07.no-update.response",
                reason="no-update-response-unknown",
                detail="Whether 'nothing to install' is an empty object or the same "
                "version echoed back was never captured, so with no admitted "
                "artifact the route refuses instead of answering.",
            ),
            Unknown(
                field="D07.download.auth",
                reason="download-auth-unknown",
                detail="The `downloadUrl` fetch is a separate QUrl and no client "
                "certificate or token is known to be attached to it.",
            ),
        ),
    ),
    Route(
        d_id="D08",
        path="/api/device-service/recipe-preset/update",
        methods=("POST",),
        evidence="key names observed; value types and reply value unknown",
        summary="Recipe preset pushed by the device.",
        unknown=(
            Unknown(
                field="D08.request.value-types",
                reason="value-types-unknown",
                detail="m2mLinked, gbsInitCoarseness, weightTolerance, lastChange and "
                "portaFilters are observed as key names only; the payload is stored "
                "verbatim and never re-typed.",
            ),
            Unknown(
                field="D08.reply.value",
                reason="reply-value-unknown",
                detail="The value the firmware's recipeChangeSucceeded(qulonglong) "
                "consumes (a lastChange echo?) is unrecorded, so the revision is "
                "stored and the reply is withheld.",
            ),
        ),
    ),
    Route(
        d_id="D09",
        path="/api/device-service/system/onboarding",
        methods=("POST",),
        evidence="route and method observed; request schema unknown",
        summary="Device registration.",
        unknown=(
            Unknown(
                field="D09.request.keys",
                reason="request-keys-unknown",
                detail="The onboarding JSON keys were never captured; the body is "
                "stored verbatim and the device is identified from its certificate, "
                "never from the body.",
            ),
        ),
    ),
    Route(
        d_id="D10",
        path="/api/device-service/system/time",
        methods=("GET",),
        evidence="route observed; response format unknown",
        summary="Cloud wall clock - the device's only cloud time source.",
        unknown=(
            Unknown(
                field="D10.response.format",
                reason="timestamp-format-unknown",
                detail="Epoch seconds, an ISO string and a bare number are all "
                "consistent with the evidence; picking one would set the grinder's "
                "clock - and therefore its TLS validity window - from a guess.",
            ),
        ),
    ),
)

ROUTE_BY_PATH: dict[str, Route] = {route.path: route for route in ROUTES}

ROUTE_BY_ID: dict[str, Route] = {route.d_id: route for route in ROUTES}

UNKNOWN_BY_FIELD: dict[str, Unknown] = {
    unknown.field: unknown for route in ROUTES for unknown in route.unknown
}


def unknown(field: str) -> Unknown:
    """Return the recorded gap for ``field``.

    Raises :class:`KeyError` for an unrecorded field: a 501 may only quote a
    gap the design actually documents, never a convenient one.
    """

    return UNKNOWN_BY_FIELD[field]


def d_id_for_field(field: str) -> str:
    """Return the D-id a field path belongs to (``D10.response.format`` -> ``D10``)."""

    return field.split(".", 1)[0]


def error_payload(
    code: str,
    message: str,
    *,
    reason: str | None = None,
    d_id: str | None = None,
    fields: tuple[str, ...] = (),
    status: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build the local error body described in the design's §5 error model.

    The documented minimum is ``{"error": {"code": ..., "message": ...}}``.
    The extra keys are additive and machine-readable: ``reason`` is a stable
    token, ``d_id`` points at the design section, and ``unverified_fields``
    lists the exact gaps a caller is looking at.
    """

    error: dict[str, Any] = {"code": code, "message": message}
    if reason is not None:
        error["reason"] = reason
    if d_id is not None:
        error["d_id"] = d_id
    if fields:
        error["unverified_fields"] = list(fields)
    if status is not None:
        error["status"] = status
    error.update(extra)
    return {"error": error}


def unknown_response(field: str) -> dict[str, Any]:
    """Build the 501 body for one unrecorded field.

    The message always contains the design's own marker, so a log grep for
    ``unknown — needs capture`` finds every behaviour that is still a gap.
    """

    gap = unknown(field)
    d_id = d_id_for_field(field)
    route = ROUTE_BY_ID[d_id]
    return error_payload(
        "unsupported",
        f"{route.path} {gap.field}: {UNKNOWN_MARKER} - {gap.detail} "
        f"See {d_id} in {DESIGN_POINTER}.",
        reason=gap.reason,
        d_id=d_id,
        fields=(gap.field,),
        status=501,
    )


def contract_document() -> dict[str, Any]:
    """Serialise the registry, for ``--print-contract`` and for tests."""

    return {
        "design": DESIGN_POINTER,
        "marker": UNKNOWN_MARKER,
        "routes": [
            {
                "d_id": route.d_id,
                "path": route.path,
                "methods": list(route.methods),
                "evidence": route.evidence,
                "summary": route.summary,
                "unknown": [
                    {"field": gap.field, "reason": gap.reason, "detail": gap.detail}
                    for gap in route.unknown
                ],
            }
            for route in ROUTES
        ],
    }
