"""Typed, local-first scale-event boundaries.

The E64 image contains a strict ``RequestorBrewEventFind`` parser, but no
complete local scale transport.  The exact cloud event object and query
payload are represented here for offline fixtures; no cloud request is sent.
The wire units recovered from the parser are milliseconds for ``duration`` and
milligrams for ``mass``.  The generic ``normalize_scale_event`` function still
requires explicit units when fed a non-vendor/local event so a host cannot
silently guess a convention.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from numbers import Real
from datetime import datetime
from typing import Any, Iterable, Mapping


VENDOR_BREW_EVENT_KEYS = (
    "eventUuid",
    "deviceId",
    "brewer",
    "groupNumber",
    "doseIndex",
    "doseType",
    "validity",
    "duration",
    "volume",
    "mass",
    "grindEventUuid",
    "stopTarget",
    "cloudDate",
)
BREW_EVENT_FIND_OPERATION = "brew-event/find"
BREW_EVENT_FIND_REQUEST_KEYS = ("grinderId", "deviceDateRange")
CLOUD_REQUEST_ENVELOPE_KEYS = ("operation", "payload")

BREWER_DISCRIMINATORS = frozenset({"lm", "scale", "flow", "wmf"})
BREW_DOSE_TYPES = frozenset(
    {"bottomlessCup", "doubleCup", "doublePortafilter", "singleCup", "singlePortafilter"}
)
BREW_DOSE_INDEXES = frozenset(
    {"singleShot", "doubleShot", "singleLongShot", "doubleLongShot", "custom"}
)

_INT32_MIN = -(2**31)
_INT32_MAX = 2**31 - 1

_IDENTITY_KEYS = frozenset({"eventUuid", "deviceId", "grindEventUuid"})
_NUMERIC_KEYS = frozenset({"duration", "volume", "mass"})


class ScaleEventValidationError(ValueError):
    """Raised when a scale event cannot cross a typed local boundary."""

    def __init__(self, message: str, *, field: str | None = None) -> None:
        self.field = field
        prefix = f"{field}: " if field else ""
        super().__init__(prefix + message)


def _finite_number(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ScaleEventValidationError("expected a finite JSON number", field=field)
    converted = float(value)
    if not isfinite(converted):
        raise ScaleEventValidationError("expected a finite JSON number", field=field)
    return converted


def _nonempty_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScaleEventValidationError("expected a non-empty JSON string", field=field)
    return value


def _int32(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScaleEventValidationError("expected an integral Qt int", field=field)
    if not _INT32_MIN <= value <= _INT32_MAX:
        raise ScaleEventValidationError("outside signed 32-bit range", field=field)
    return value


def build_brew_event_find_payload(
    grinder_id: str,
    from_timestamp: datetime | str,
) -> dict[str, Any]:
    """Build the exact inner ``brew-event/find`` payload offline.

    The surrounding CloudRequestor envelope carries the operation name and a
    ``payload`` member; ``payload`` is not a third member of this object.
    """

    identifier = _nonempty_string(grinder_id, field="grinderId")
    if isinstance(from_timestamp, datetime):
        if from_timestamp.tzinfo is None:
            raise ScaleEventValidationError("timestamp must be timezone-aware", field="from")
        stamp = from_timestamp.isoformat()
    else:
        stamp = _nonempty_string(from_timestamp, field="from")
    return {"grinderId": identifier, "deviceDateRange": {"from": stamp}}


@dataclass(frozen=True)
class VendorBrewEvent:
    """A validated copy of an E64-side brew-event JSON object.

    The raw mapping is retained because the exact per-brewer required-field
    matrix and several value types remain unresolved.  Consumers should use
    ``normalize_scale_event`` before feeding the event into Decaid models.
    """

    payload: Mapping[str, Any]

    def value(self, key: str, default: Any = None) -> Any:
        return self.payload.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def parse_vendor_brew_event(
    payload: Mapping[str, Any],
    *,
    required_fields: Iterable[str] = (),
) -> VendorBrewEvent:
    """Validate a recovered E64-side event without guessing its wire units.

    ``required_fields`` is intentionally caller-supplied.  Static analysis
    proved the key literals and negative paths, but not one universal
    required-field set for Scale/FLOW/La Marzocco/WMF variants.
    """

    if (
        isinstance(payload, Mapping)
        and isinstance(payload.get("brewer"), Mapping)
        and "brewer" in payload["brewer"]
    ):
        return parse_cloud_brew_event(payload)
    if not isinstance(payload, Mapping):
        raise ScaleEventValidationError("event must be a JSON object")
    copied = dict(payload)
    for field in required_fields:
        if field not in copied or copied[field] is None:
            raise ScaleEventValidationError("required field is missing", field=field)

    for field in _IDENTITY_KEYS.intersection(copied):
        if copied[field] is not None:
            _nonempty_string(copied[field], field=field)
    for field in _NUMERIC_KEYS.intersection(copied):
        if copied[field] is not None:
            _finite_number(copied[field], field=field)
    if "validity" in copied and not isinstance(copied["validity"], bool):
        raise ScaleEventValidationError("expected a JSON boolean", field="validity")
    return VendorBrewEvent(copied)


def parse_cloud_brew_event(payload: Mapping[str, Any]) -> VendorBrewEvent:
    """Parse the exact nested E64 cloud brew-event object.

    The discriminator is nested at ``brewer.brewer`` and is case-sensitive:
    ``lm``, ``scale``, ``flow``, or ``wmf``.  Common identity/duration checks
    and variant-specific integral fields mirror the recovered Qt conversion
    paths.  This function only parses; it never forwards the event to GBS.
    """

    if not isinstance(payload, Mapping):
        raise ScaleEventValidationError("event must be a JSON object")
    event_uuid = _nonempty_string(payload.get("eventUuid"), field="eventUuid")
    device_id = _nonempty_string(payload.get("deviceId"), field="deviceId")
    brewer = payload.get("brewer")
    if not isinstance(brewer, Mapping) or not brewer:
        raise ScaleEventValidationError("nested brewer object is required", field="brewer")
    # The recovered response nests grindEventUuid with the brewer fields. Keep
    # a top-level fallback for captures/fixtures from adjacent API versions.
    grind_uuid = _nonempty_string(
        brewer.get("grindEventUuid", payload.get("grindEventUuid")),
        field="brewer.grindEventUuid",
    )
    kind = _nonempty_string(brewer.get("brewer"), field="brewer.brewer")
    if kind not in BREWER_DISCRIMINATORS:
        raise ScaleEventValidationError("unknown brewer discriminator", field="brewer.brewer")
    duration = _int32(brewer.get("duration"), field="brewer.duration")
    flat: dict[str, Any] = {
        "eventUuid": event_uuid,
        "deviceId": device_id,
        "brewer": kind,
        "brewerObject": dict(brewer),
        "groupNumber": brewer.get("groupNumber"),
        "doseIndex": brewer.get("doseIndex"),
        "doseType": brewer.get("doseType"),
        "validity": brewer.get("validity"),
        "duration": duration,
        "volume": brewer.get("volume"),
        "mass": brewer.get("mass"),
        "grindEventUuid": grind_uuid,
        "stopTarget": brewer.get("stopTarget", 0.0),
        "cloudDate": payload.get("cloudDate"),
        "rawCloudEvent": dict(payload),
    }
    if kind == "lm":
        if not isinstance(flat["validity"], bool):
            raise ScaleEventValidationError("expected a JSON boolean", field="brewer.validity")
        flat["volume"] = _int32(flat["volume"], field="brewer.volume")
        dose_type = flat["doseType"]
        if dose_type is not None and dose_type not in BREW_DOSE_TYPES:
            raise ScaleEventValidationError("unknown doseType", field="brewer.doseType")
    else:
        flat["mass"] = _int32(flat["mass"], field="brewer.mass")
        flat["groupNumber"] = "0"
        flat["doseType"] = "MassType"
        flat["validity"] = True
    if flat["stopTarget"] is not None:
        if isinstance(flat["stopTarget"], bool) or not isinstance(flat["stopTarget"], Real):
            flat["stopTarget"] = 0.0
        else:
            flat["stopTarget"] = float(flat["stopTarget"]) * 1000.0
    return VendorBrewEvent(flat)


@dataclass(frozen=True)
class NormalizedScaleEvent:
    """Decaid-side event with explicit, normalized units."""

    event_uuid: str
    device_id: str
    duration_s: float
    mass_g: float
    validity: bool
    volume_ml: float | None = None
    group_number: int | None = None
    dose_index: int | None = None
    dose_type: Any = None
    grind_event_uuid: str | None = None
    stop_target: Any = None
    cloud_date: Any = None
    raw: Mapping[str, Any] | None = None


def _unit_multiplier(unit: str, *, field: str) -> float:
    units = {
        "s": 1.0,
        "sec": 1.0,
        "seconds": 1.0,
        "ms": 0.001,
        "millisecond": 0.001,
        "milliseconds": 0.001,
        "g": 1.0,
        "gram": 1.0,
        "grams": 1.0,
        "mg": 0.001,
        "milligram": 0.001,
        "milligrams": 0.001,
        "ml": 1.0,
        "millilitre": 1.0,
        "millilitres": 1.0,
        "milliliter": 1.0,
        "milliliters": 1.0,
    }
    try:
        return units[unit.lower()]
    except KeyError as exc:
        raise ScaleEventValidationError("unsupported explicit unit", field=field) from exc


def normalize_scale_event(
    event: VendorBrewEvent | Mapping[str, Any],
    *,
    duration_unit: str,
    mass_unit: str,
    volume_unit: str = "ml",
) -> NormalizedScaleEvent:
    """Convert an event after the caller has established its wire units.

    The explicit unit arguments are mandatory for duration and mass so a
    guessed vendor convention cannot silently affect a grinder recommendation.
    ``volume`` remains optional because it is not required by every event
    variant.
    """

    parsed = event if isinstance(event, VendorBrewEvent) else parse_vendor_brew_event(event)
    payload = parsed.payload
    for field in ("eventUuid", "deviceId", "duration", "mass", "validity"):
        if field not in payload or payload[field] is None:
            raise ScaleEventValidationError("required normalization field is missing", field=field)

    event_uuid = _nonempty_string(payload["eventUuid"], field="eventUuid")
    device_id = _nonempty_string(payload["deviceId"], field="deviceId")
    if not isinstance(payload["validity"], bool):
        raise ScaleEventValidationError("expected a JSON boolean", field="validity")
    duration = _finite_number(payload["duration"], field="duration")
    mass = _finite_number(payload["mass"], field="mass")
    duration_s = duration * _unit_multiplier(duration_unit, field="duration_unit")
    mass_g = mass * _unit_multiplier(mass_unit, field="mass_unit")
    volume_ml: float | None = None
    if payload.get("volume") is not None:
        volume_ml = _finite_number(payload["volume"], field="volume")
        volume_ml *= _unit_multiplier(volume_unit, field="volume_unit")

    grind_uuid = payload.get("grindEventUuid")
    if grind_uuid is not None:
        grind_uuid = _nonempty_string(grind_uuid, field="grindEventUuid")
    return NormalizedScaleEvent(
        event_uuid=event_uuid,
        device_id=device_id,
        duration_s=duration_s,
        mass_g=mass_g,
        validity=payload["validity"],
        volume_ml=volume_ml,
        group_number=payload.get("groupNumber"),
        dose_index=payload.get("doseIndex"),
        dose_type=payload.get("doseType"),
        grind_event_uuid=grind_uuid,
        stop_target=payload.get("stopTarget"),
        cloud_date=payload.get("cloudDate"),
        raw=dict(payload),
    )


__all__ = [
    "BREWER_DISCRIMINATORS",
    "BREW_DOSE_INDEXES",
    "BREW_DOSE_TYPES",
    "BREW_EVENT_FIND_OPERATION",
    "BREW_EVENT_FIND_REQUEST_KEYS",
    "CLOUD_REQUEST_ENVELOPE_KEYS",
    "NormalizedScaleEvent",
    "ScaleEventValidationError",
    "VENDOR_BREW_EVENT_KEYS",
    "VendorBrewEvent",
    "normalize_scale_event",
    "build_brew_event_find_payload",
    "parse_cloud_brew_event",
    "parse_vendor_brew_event",
]
