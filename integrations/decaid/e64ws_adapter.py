"""Small Decaid-facing adapter built on the local E64 API client.

This is a reference sidecar, not a drop-in Decaid Dart package.  It keeps the
device credential and hazardous operation policy in Python and exposes plain
data structures that a Decaid bridge can translate into its typed device and
shot event models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import isfinite
from numbers import Real
from time import monotonic
from typing import Any, Mapping

from tools.e64ws_api import E64LocalAPI, E64WSAPIError
from tools.gbs_model import proposed_dd_from_weight


@dataclass(frozen=True)
class GrinderSnapshot:
    """Normalized, read-only snapshot suitable for a host/plugin event."""

    observed_at: datetime
    raw: Mapping[str, Any]
    grind_state: Any = None
    grind_failure: Any = None
    current_weight_g: Any = None
    target_weight_g: Any = None
    dd_value: Any = None
    agsa_status: Any = None
    esp_alive: Any = None


@dataclass(frozen=True)
class BrewEvent:
    """Normalized mass shot before an explicitly validated wire conversion.

    ``wire_profile`` is intentionally required by the injection policy.  It
    names a locally validated firmware/unit mapping; it is not a claim that
    the static reverse engineering proved the mapping.
    """

    duration_ms: int
    mass_g: float
    volume_ml: float | None = None
    flow_ml_s: float | None = None
    valid: bool = True
    brewer_id: str = "decaid"
    brewer_serial: str = "decaid"
    brewer_type: str = "Scale"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    grind_uuid: str = ""
    machine_name: str = "Decaid"
    group_head: str = ""
    # E64 GBS-valid recipe types are 1, 2, 5, and 6. Use single-shot as the
    # safe normalized default instead of silently creating custom type 3.
    dose_index: int = 1
    source: str = "unknown"
    shot_id: str = ""
    wire_profile: str | None = None


@dataclass(frozen=True)
class DialRecommendation:
    """Recommendation-only result; it never moves the grinder."""

    direction: str
    confidence: float
    reasons: tuple[str, ...]
    delta_steps: int = 1
    requires_confirmation: bool = True


@dataclass(frozen=True)
class DecaidCapabilityPolicy:
    """Host-side permission and safety policy for this reference adapter.

    The firmware does not expose a proven physical DD range in the static
    artifacts.  Consequently ``dd_bounds`` is required before actuation can
    be enabled.  The defaults intentionally make the adapter useful for
    snapshots/recommendations while keeping event injection and movement off.
    """

    allow_read: bool = True
    allow_recommend: bool = True
    allow_event_injection: bool = False
    allow_actuation: bool = False
    dd_bounds: tuple[int, int] | None = None
    validated_brew_wire_profile: str | None = None
    max_event_duration_ms: int = 300_000
    min_event_duration_ms: int = 15_001
    max_event_mass_g: float = 200.0
    fresh_snapshot_s: float = 5.0
    min_actuation_interval_s: float = 30.0

    def __post_init__(self) -> None:
        if self.dd_bounds is not None:
            lower, upper = self.dd_bounds
            if lower > upper:
                raise ValueError("dd_bounds must be ordered low-to-high")
        if (
            self.max_event_duration_ms <= 0
            or self.min_event_duration_ms <= 0
            or self.min_event_duration_ms > self.max_event_duration_ms
            or self.max_event_mass_g <= 0
        ):
            raise ValueError("event limits must be positive")
        if self.fresh_snapshot_s <= 0 or self.min_actuation_interval_s < 0:
            raise ValueError("time limits are invalid")
        if self.allow_actuation and self.dd_bounds is None:
            raise ValueError("dd_bounds are required when actuation is enabled")


@dataclass(frozen=True)
class DecaidAuditEntry:
    """Redacted operation audit record suitable for a host event log."""

    operation: str
    allowed: bool
    reason: str
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class E64DecaidAdapter:
    """Read/record/recommend adapter with actuation disabled by default."""

    def __init__(
        self,
        api: E64LocalAPI,
        *,
        policy: DecaidCapabilityPolicy | None = None,
        allow_actuation: bool = False,
        allow_event_injection: bool = False,
    ) -> None:
        self.api = api
        if policy is not None and (allow_actuation or allow_event_injection):
            raise ValueError("pass operation permissions through policy, not both APIs")
        self.policy = policy or DecaidCapabilityPolicy(
            allow_actuation=allow_actuation,
            allow_event_injection=allow_event_injection,
        )
        # Compatibility attributes for the first reference-adapter revision.
        self.allow_actuation = self.policy.allow_actuation
        self.allow_event_injection = self.policy.allow_event_injection
        self.last_brew_event: BrewEvent | None = None
        self._last_snapshot: GrinderSnapshot | None = None
        self._last_actuation_monotonic: float | None = None
        self._recorded_shot_ids: set[str] = set()
        self._audit: list[DecaidAuditEntry] = []

    def audit_log(self) -> tuple[DecaidAuditEntry, ...]:
        """Return redacted policy decisions in chronological order."""

        return tuple(self._audit)

    def _decision(self, operation: str, allowed: bool, reason: str) -> None:
        self._audit.append(DecaidAuditEntry(operation, allowed, reason))

    def _require(self, operation: str, allowed: bool, reason: str) -> None:
        self._decision(operation, allowed, reason)
        if not allowed:
            raise E64WSAPIError(reason)

    def snapshot(self) -> GrinderSnapshot:
        self._require("grinder.read", self.policy.allow_read, "grinder reads are disabled")
        response = self.api.driver_state()
        state = response.get("data", response) if isinstance(response, dict) else {}
        if not isinstance(state, dict):
            state = {"value": state}
        snapshot = GrinderSnapshot(
            observed_at=datetime.now(timezone.utc),
            raw=state,
            grind_state=state.get("grindState"),
            grind_failure=state.get("grindFailure"),
            current_weight_g=state.get("grindCurrentWeightGr"),
            target_weight_g=state.get("grindTargetWeightGr"),
            dd_value=state.get("ddSensorAngle", state.get("ddValueDum")),
            agsa_status=state.get("agsaStatus"),
            esp_alive=state.get("espAlive"),
        )
        self._last_snapshot = snapshot
        return snapshot

    @staticmethod
    def recommend(
        *,
        target_brew_time_s: float,
        actual_brew_time_s: float,
        flavor: str | None = None,
        tolerance_s: float = 1.0,
    ) -> DialRecommendation:
        """Return a conservative recommendation from time and sensory input.

        The direction is a coffee-control convention, not a recovered E64
        internal rule.  Conflicting signals deliberately produce no automatic
        direction.  The caller should display this result and obtain consent.
        """

        flavor_text = (flavor or "").strip().lower()
        reasons: list[str] = []
        directions: list[str] = []
        if actual_brew_time_s < target_brew_time_s - tolerance_s:
            directions.append("finer")
            reasons.append("brew time is below target")
        elif actual_brew_time_s > target_brew_time_s + tolerance_s:
            directions.append("coarser")
            reasons.append("brew time is above target")
        if any(word in flavor_text for word in ("acidic", "sour", "sharp", "under-extracted")):
            directions.append("finer")
            reasons.append("sensory input suggests under-extraction")
        if any(word in flavor_text for word in ("bitter", "dry", "harsh", "over-extracted")):
            directions.append("coarser")
            reasons.append("sensory input suggests over-extraction")
        distinct = set(directions)
        if len(distinct) != 1:
            return DialRecommendation("none", 0.0, tuple(reasons) or ("no actionable signal",))
        confidence = min(0.95, 0.55 + 0.15 * (len(reasons) - 1))
        return DialRecommendation(next(iter(distinct)), confidence, tuple(reasons))

    def recommend_for_host(self, **kwargs: Any) -> DialRecommendation:
        """Apply the host recommendation permission before the pure model."""

        self._require(
            "grinder.recommend",
            self.policy.allow_recommend,
            "grinder recommendations are disabled",
        )
        return self.recommend(**kwargs)

    @staticmethod
    def proposed_dd(*, weight_mg: int, model: str, roast: str) -> int:
        """Return the decoded dial-in proposal without contacting the E64."""

        return proposed_dd_from_weight(weight_mg, model=model, roast=roast)

    def record_brew_event(self, event: BrewEvent) -> dict[str, Any]:
        """Send the recovered AddBrewEvent shape after explicit opt-in.

        AddBrewEvent is guarded separately from DD actuation because the
        firmware may feed an injected event into GBS and move the burrs on a
        later shot.  Scale-only metadata is retained in ``last_brew_event``
        but is not put on the wire: those extra keys were not proven part of
        the local AddBrewEvent schema.
        """

        self._require(
            "brew_event.inject",
            self.policy.allow_event_injection,
            "brew-event injection is disabled; enable it only after validating GBS behavior",
        )
        self._require(
            "brew_event.inject",
            event.valid is True,
            "only a locally valid mass shot may be injected",
        )
        self._require(
            "brew_event.inject",
            bool(event.shot_id.strip()),
            "a unique completed shot_id is required",
        )
        self._require(
            "brew_event.inject",
            event.shot_id not in self._recorded_shot_ids,
            "this shot_id was already injected",
        )
        self._require(
            "brew_event.inject",
            bool(event.source.strip()),
            "brew-event source metadata is required",
        )
        self._require(
            "brew_event.inject",
            bool(event.grind_uuid.strip()),
            "a correlated completed grinder UUID is required",
        )
        self._require(
            "brew_event.inject",
            event.dose_index in {1, 2, 5, 6},
            "dose_index is not a GBS-valid recipe type",
        )
        self._require(
            "brew_event.inject",
            self.policy.validated_brew_wire_profile is not None
            and event.wire_profile == self.policy.validated_brew_wire_profile,
            "no matching owner-validated E64 brew-event wire profile is configured",
        )
        self._require(
            "brew_event.inject",
            isinstance(event.timestamp, datetime) and event.timestamp.tzinfo is not None,
            "brew-event timestamp must be timezone-aware",
        )
        assert isinstance(event.timestamp, datetime)
        assert event.timestamp.tzinfo is not None
        age_s = (datetime.now(timezone.utc) - event.timestamp).total_seconds()
        self._require(
            "brew_event.inject",
            0 <= age_s <= self.policy.fresh_snapshot_s,
            "brew-event is stale or has a future timestamp",
        )
        if (
            not isinstance(event.duration_ms, int)
            or isinstance(event.duration_ms, bool)
            or event.duration_ms < self.policy.min_event_duration_ms
            or event.duration_ms > self.policy.max_event_duration_ms
        ):
            self._require(
                "brew_event.inject",
                False,
                "brew-event duration is outside the local policy bound",
            )
        if (
            isinstance(event.mass_g, bool)
            or not isinstance(event.mass_g, Real)
            or not isfinite(float(event.mass_g))
            or event.mass_g <= 0
            or event.mass_g > self.policy.max_event_mass_g
        ):
            self._require(
                "brew_event.inject",
                False,
                "brew-event mass is outside the local policy bound",
            )
        data: dict[str, Any] = {
            "grindUuid": event.grind_uuid,
            "machineName": event.machine_name,
            "groupHead": event.group_head,
            "doseIndex": event.dose_index,
            "validity": event.valid,
            "brewTimeMs": event.duration_ms,
            "brewWeightMg": round(event.mass_g * 1000),
        }
        response = self.api.ws_action("AddBrewEvent", data, allow_hazardous=True)
        self._recorded_shot_ids.add(event.shot_id)
        self.last_brew_event = event
        return response

    def set_agsa_target_dd(self, target_dd_value: int) -> dict[str, Any]:
        """Explicitly guarded native DD actuation; not a dial-number setter."""

        self._require(
            "grinder.actuate",
            self.policy.allow_actuation,
            "actuation is disabled; enable it only after live calibration",
        )
        if self.policy.dd_bounds is None:
            self._require(
                "grinder.actuate",
                False,
                "actuation bounds are not configured",
            )
        if not isinstance(target_dd_value, int) or isinstance(target_dd_value, bool):
            self._require("grinder.actuate", False, "DD target must be an integer")
        assert self.policy.dd_bounds is not None
        lower, upper = self.policy.dd_bounds
        if not lower <= target_dd_value <= upper:
            self._require("grinder.actuate", False, "DD target is outside the local policy bound")
        if self._last_snapshot is None:
            self._require(
                "grinder.actuate",
                False,
                "a fresh driver snapshot is required before actuation",
            )
        snapshot_age = (
            datetime.now(timezone.utc) - self._last_snapshot.observed_at
        ).total_seconds()
        if snapshot_age > self.policy.fresh_snapshot_s:
            self._require("grinder.actuate", False, "driver snapshot is stale")
        if self._last_snapshot.grind_failure:
            self._require("grinder.actuate", False, "driver reports a grind failure")
        now = monotonic()
        if (
            self._last_actuation_monotonic is not None
            and now - self._last_actuation_monotonic < self.policy.min_actuation_interval_s
        ):
            self._require("grinder.actuate", False, "actuation rate limit is active")
        response = self.api.ws_action(
            "SetAgsaTargetDdValue",
            {"targetDdValue": target_dd_value},
            allow_hazardous=True,
        )
        self._last_actuation_monotonic = now
        self._decision("grinder.actuate", True, "guarded action submitted")
        return response


__all__ = [
    "BrewEvent",
    "DecaidAuditEntry",
    "DecaidCapabilityPolicy",
    "DialRecommendation",
    "E64DecaidAdapter",
    "GrinderSnapshot",
]
