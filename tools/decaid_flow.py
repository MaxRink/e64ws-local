"""Typed flow-only events for Decaid machine telemetry.

This is intentionally separate from scale/mass events.  A Decent machine
flow stream can support timing, flow-shape, and recommendation features, but
it cannot prove yield, mass-derived flow, or Mahlkönig Sync Scale validity.
No E64 event envelope is produced by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite
from numbers import Real
from statistics import median
from typing import Any, Iterable, Mapping


class FlowValidationError(ValueError):
    """Raised when machine-flow data cannot cross the typed boundary."""


def _finite(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise FlowValidationError(f"{field} must be finite")
    result = float(value)
    if not isfinite(result):
        raise FlowValidationError(f"{field} must be finite")
    return result


@dataclass(frozen=True)
class MachineFlowSample:
    """One source-timestamped flow observation from the espresso machine."""

    flow_ml_s: float
    source_timestamp_ms: float
    received_at: datetime
    sequence: int
    connection_id: str
    source_device: str
    source_firmware: str | None = None
    declared_cadence_hz: float | None = None

    def __post_init__(self) -> None:
        if _finite(self.flow_ml_s, field="flow_ml_s") < 0:
            raise FlowValidationError("flow_ml_s must not be negative")
        if _finite(self.source_timestamp_ms, field="source_timestamp_ms") < 0:
            raise FlowValidationError("source_timestamp_ms must not be negative")
        if self.received_at.tzinfo is None:
            raise FlowValidationError("received_at must be timezone-aware")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 0:
            raise FlowValidationError("sequence must be a non-negative integer")
        if not self.connection_id.strip() or not self.source_device.strip():
            raise FlowValidationError("connection_id and source_device are required")
        if self.declared_cadence_hz is not None and _finite(self.declared_cadence_hz, field="declared_cadence_hz") <= 0:
            raise FlowValidationError("declared_cadence_hz must be positive")

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_ml_s": self.flow_ml_s,
            "source_timestamp_ms": self.source_timestamp_ms,
            "received_at": self.received_at.isoformat(),
            "sequence": self.sequence,
            "connection_id": self.connection_id,
            "source_device": self.source_device,
            "source_firmware": self.source_firmware,
            "declared_cadence_hz": self.declared_cadence_hz,
        }


@dataclass(frozen=True)
class MachineFlowOnlyEvent:
    """Flow event whose mass/yield and Sync validity are non-evaluable.

    ``samples`` always contains the source-preserved observations.  When a
    target analysis cadence is requested, ``analysis_samples`` contains the
    deterministic downsampled view; it never replaces the evidence stream.
    """

    samples: tuple[MachineFlowSample, ...]
    started_ms: float | None
    ended_ms: float | None
    duration_s: float | None
    valid: bool
    invalid_reason: str | None
    flow_source: str = "machine_telemetry"
    flow_unit: str = "ml/s"
    mass_g: float | None = None
    yield_g: float | None = None
    mass_derivative_g_s: float | None = None
    sync_scale_validity: str = "not_evaluable"
    e64_injection_eligible: bool = False
    declared_cadence_hz: float | None = None
    observed_cadence_hz: float | None = None
    resampling: str = "source_timestamps_preserved"
    metadata: Mapping[str, Any] | None = None
    analysis_samples: tuple[MachineFlowSample, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_source": self.flow_source,
            "flow_unit": self.flow_unit,
            "started_ms": self.started_ms,
            "ended_ms": self.ended_ms,
            "duration_s": self.duration_s,
            "valid": self.valid,
            "invalid_reason": self.invalid_reason,
            "mass_g": None,
            "yield_g": None,
            "mass_derivative_g_s": None,
            "sync_scale_validity": self.sync_scale_validity,
            "e64_injection_eligible": False,
            "declared_cadence_hz": self.declared_cadence_hz,
            "observed_cadence_hz": self.observed_cadence_hz,
            "resampling": self.resampling,
            "metadata": dict(self.metadata or {}),
            "samples": [sample.to_dict() for sample in self.samples],
            "analysis_samples": [sample.to_dict() for sample in self.analysis_samples],
        }

    @property
    def source(self) -> str:
        """Compatibility alias for hosts that call the provenance field source."""

        return self.flow_source


def observed_cadence_hz(samples: Iterable[MachineFlowSample]) -> float | None:
    ordered = tuple(samples)
    gaps = [
        right.source_timestamp_ms - left.source_timestamp_ms
        for left, right in zip(ordered, ordered[1:])
        if right.source_timestamp_ms > left.source_timestamp_ms
    ]
    return None if not gaps else 1000.0 / median(gaps)


def downsample_by_source_time(
    samples: Iterable[MachineFlowSample],
    *,
    target_hz: Real,
) -> tuple[MachineFlowSample, ...]:
    """Select the first sample in each source-time bucket deterministically.

    The source timestamp, never network arrival time, defines the bucket.  A
    target rate is an analysis transform; it does not change the raw event.
    """

    target = _finite(target_hz, field="target_hz")
    if target <= 0:
        raise FlowValidationError("target_hz must be positive")
    interval = 1000.0 / target
    result: list[MachineFlowSample] = []
    bucket_seen: set[int] = set()
    for sample in samples:
        bucket = int(sample.source_timestamp_ms // interval)
        if bucket not in bucket_seen:
            bucket_seen.add(bucket)
            result.append(sample)
    return tuple(result)


def build_flow_event(
    samples: Iterable[MachineFlowSample],
    *,
    max_gap_ms: Real | None = None,
    target_hz: Real | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> MachineFlowOnlyEvent:
    """Validate one source-timestamped flow shot without synthesizing mass."""

    ordered = tuple(samples)
    if not ordered:
        return MachineFlowOnlyEvent((), None, None, None, False, "no flow samples", metadata=metadata)
    gap_limit = None if max_gap_ms is None else _finite(max_gap_ms, field="max_gap_ms")
    if gap_limit is not None and gap_limit <= 0:
        raise FlowValidationError("max_gap_ms must be positive")
    reasons: list[str] = []
    previous: MachineFlowSample | None = None
    for sample in ordered:
        if previous is not None:
            if sample.connection_id != previous.connection_id:
                reasons.append("connection reset during flow event")
            if sample.source_device != previous.source_device:
                reasons.append("source device changed during flow event")
            if sample.source_firmware != previous.source_firmware:
                reasons.append("source firmware changed during flow event")
            if (
                sample.declared_cadence_hz is not None
                and previous.declared_cadence_hz is not None
                and sample.declared_cadence_hz != previous.declared_cadence_hz
            ):
                reasons.append("declared cadence changed during flow event")
            if sample.source_timestamp_ms <= previous.source_timestamp_ms:
                reasons.append("non-increasing source timestamp")
            if sample.sequence <= previous.sequence:
                reasons.append("non-increasing source sequence")
            if gap_limit is not None and sample.source_timestamp_ms - previous.source_timestamp_ms > gap_limit:
                reasons.append("flow sample gap exceeds configured stale limit")
        previous = sample
    started = ordered[0].source_timestamp_ms
    ended = ordered[-1].source_timestamp_ms
    duration_s = max(0.0, ended - started) / 1000.0
    if duration_s <= 0:
        reasons.append("flow duration is not positive")
    analysis_samples = (
        ordered
        if target_hz is None
        else downsample_by_source_time(ordered, target_hz=target_hz)
    )
    resampling = "source_timestamps_preserved" if target_hz is None else f"first_sample_per_{float(target_hz):g}Hz_source_bucket"
    declared = next((sample.declared_cadence_hz for sample in ordered if sample.declared_cadence_hz is not None), None)
    return MachineFlowOnlyEvent(
        samples=ordered,
        started_ms=started,
        ended_ms=ended,
        duration_s=duration_s,
        valid=not reasons,
        invalid_reason=None if not reasons else "; ".join(dict.fromkeys(reasons)),
        declared_cadence_hz=declared,
        observed_cadence_hz=observed_cadence_hz(ordered),
        resampling=resampling,
        metadata=metadata,
        analysis_samples=analysis_samples,
    )


def sample_now(
    *,
    flow_ml_s: Real,
    source_timestamp_ms: Real,
    sequence: int,
    connection_id: str,
    source_device: str = "decent-machine",
    source_firmware: str | None = None,
    declared_cadence_hz: Real | None = None,
) -> MachineFlowSample:
    """Convenience constructor using an explicit UTC receipt timestamp."""

    return MachineFlowSample(
        flow_ml_s=float(flow_ml_s),
        source_timestamp_ms=float(source_timestamp_ms),
        received_at=datetime.now(timezone.utc),
        sequence=sequence,
        connection_id=connection_id,
        source_device=source_device,
        source_firmware=source_firmware,
        declared_cadence_hz=None if declared_cadence_hz is None else float(declared_cadence_hz),
    )


__all__ = [
    "FlowValidationError",
    "MachineFlowOnlyEvent",
    "MachineFlowSample",
    "build_flow_event",
    "downsample_by_source_time",
    "observed_cadence_hz",
    "sample_now",
]
