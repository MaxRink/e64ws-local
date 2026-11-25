"""Standalone OpenScale shot boundaries and local JSON serialization.

OpenScale exposes measurements, not espresso-shot semantics.  This module
keeps those concerns separate: a caller explicitly starts and stops a shot,
and this accumulator records the samples in between.  It never infers a shot
from a non-zero weight, and an out-of-order sample or disconnect produces an
invalid result rather than silently repairing the timeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite
from numbers import Real
from typing import Any, Mapping

from tools.openscale_client import (
    OpenScaleProtocolError,
    OpenScaleSnapshot,
    parse_frame,
)


def _finite(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise OpenScaleProtocolError(f"{field} must be a finite number")
    result = float(value)
    if not isfinite(result):
        raise OpenScaleProtocolError(f"{field} must be a finite number")
    return result


@dataclass(frozen=True)
class OpenScaleShotSample:
    """One accepted frame plus host-side provenance."""

    snapshot: OpenScaleSnapshot
    received_at: datetime
    connection_id: str
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": dict(self.snapshot.raw),
            "received_at": self.received_at.isoformat(),
            "connection_id": self.connection_id,
            "sequence": self.sequence,
        }


@dataclass(frozen=True)
class OpenScaleShot:
    """A completed or invalid local shot record.

    ``milliseconds`` is the device timestamp from OpenScale.  It is retained
    as a device-local timeline and is not converted into an E64 wire field.
    The raw snapshots are retained for later analysis and reproducibility.
    """

    samples: tuple[OpenScaleShotSample, ...]
    started_ms: float | None
    ended_ms: float | None
    duration_ms: float | None
    final_grams: float | None
    valid: bool
    validity: str
    reason: str
    boundary_origin: str
    metadata: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_ms": self.started_ms,
            "ended_ms": self.ended_ms,
            "duration_ms": self.duration_ms,
            "final_grams": self.final_grams,
            "valid": self.valid,
            "validity": self.validity,
            "reason": self.reason,
            "boundary_origin": self.boundary_origin,
            "metadata": dict(self.metadata),
            "sample_count": len(self.samples),
            "samples": [sample.to_dict() for sample in self.samples],
        }


class OpenScaleShotAccumulator:
    """Explicit-start/explicit-stop accumulator usable without Decaid."""

    def __init__(
        self,
        *,
        metadata: Mapping[str, Any] | None = None,
        connection_id: str = "local-connection-0",
        max_gap_ms: Real | None = None,
        stable_sample_count: int = 3,
        stability_tolerance_g: Real = 0.2,
    ) -> None:
        self._default_metadata = dict(metadata or {})
        if not connection_id.strip():
            raise ValueError("connection_id must be non-empty")
        self._default_connection_id = connection_id
        self._max_gap_ms = None if max_gap_ms is None else _finite(max_gap_ms, field="max_gap_ms")
        if self._max_gap_ms is not None and self._max_gap_ms <= 0:
            raise ValueError("max_gap_ms must be positive")
        if stable_sample_count <= 0:
            raise ValueError("stable_sample_count must be positive")
        self._stable_sample_count = stable_sample_count
        self._stability_tolerance_g = _finite(stability_tolerance_g, field="stability_tolerance_g")
        if self._stability_tolerance_g < 0:
            raise ValueError("stability_tolerance_g must not be negative")
        self._samples: list[OpenScaleShotSample] = []
        self._started_ms: float | None = None
        self._last_ms: float | None = None
        self._last_sequence: int | None = None
        self._connection_id = connection_id
        self._metadata: dict[str, Any] = {}
        self._invalid_reason: str | None = None
        self._boundary_origin = "explicit_start_stop"
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    def start(
        self,
        *,
        started_ms: Real | None = None,
        metadata: Mapping[str, Any] | None = None,
        connection_id: str | None = None,
        boundary_origin: str = "explicit_start_stop",
    ) -> None:
        """Start a shot; the first accepted sample supplies the time if omitted."""

        if self._active:
            raise OpenScaleProtocolError("a shot is already active")
        self._samples = []
        self._started_ms = None if started_ms is None else _finite(started_ms, field="started_ms")
        self._last_ms = None
        self._last_sequence = None
        self._connection_id = connection_id or self._default_connection_id
        if not self._connection_id.strip():
            raise OpenScaleProtocolError("connection_id must be non-empty")
        self._metadata = {**self._default_metadata, **dict(metadata or {})}
        self._invalid_reason = None
        self._boundary_origin = boundary_origin
        self._active = True

    def add_snapshot(
        self,
        snapshot: OpenScaleSnapshot,
        *,
        received_at: datetime | None = None,
        connection_id: str | None = None,
        sequence: int | None = None,
    ) -> None:
        """Append one weight snapshot, rejecting non-monotonic device time."""

        if not self._active:
            raise OpenScaleProtocolError("start a shot before adding snapshots")
        if not isinstance(snapshot, OpenScaleSnapshot):
            raise OpenScaleProtocolError("shot samples must be OpenScale snapshots")
        timestamp = _finite(snapshot.milliseconds, field="snapshot.ms")
        grams = _finite(snapshot.grams, field="snapshot.grams")
        received = received_at or datetime.now(timezone.utc)
        if received.tzinfo is None:
            raise OpenScaleProtocolError("received_at must be timezone-aware")
        sample_connection = connection_id or self._connection_id
        sample_sequence = len(self._samples) if sequence is None else sequence
        if not isinstance(sample_sequence, int) or isinstance(sample_sequence, bool) or sample_sequence < 0:
            raise OpenScaleProtocolError("sequence must be a non-negative integer")
        sample = OpenScaleShotSample(snapshot, received, sample_connection, sample_sequence)
        self._samples.append(sample)
        if sample_connection != self._connection_id:
            self._invalid_reason = self._invalid_reason or "connection reset during shot"
        if grams < 0:
            self._invalid_reason = self._invalid_reason or "negative scale weight"
        if self._last_ms is not None:
            if timestamp <= self._last_ms:
                self._invalid_reason = self._invalid_reason or "non-increasing OpenScale device timestamp"
            elif self._max_gap_ms is not None and timestamp - self._last_ms > self._max_gap_ms:
                self._invalid_reason = self._invalid_reason or "scale sample gap exceeds configured stale limit"
        if self._last_sequence is not None and sample_sequence <= self._last_sequence:
            self._invalid_reason = self._invalid_reason or "non-increasing scale sample sequence"
        if self._started_ms is None:
            self._started_ms = timestamp
        self._last_ms = timestamp
        self._last_sequence = sample_sequence

    def add_frame(self, value: Mapping[str, Any] | str | bytes) -> OpenScaleSnapshot:
        """Parse and append a snapshot frame; typed status/event frames are rejected."""

        parsed = parse_frame(value)
        if not isinstance(parsed, OpenScaleSnapshot):
            raise OpenScaleProtocolError("shot capture requires an untyped weight snapshot")
        self.add_snapshot(parsed)
        return parsed

    def finish(
        self,
        *,
        ended_ms: Real | None = None,
        valid: bool = True,
        reason: str = "explicit shot stop",
    ) -> OpenScaleShot:
        """Finish an explicit shot and reset the accumulator for reuse."""

        if not self._active:
            raise OpenScaleProtocolError("no active shot")
        end = self._last_ms if ended_ms is None else _finite(ended_ms, field="ended_ms")
        if end is not None and self._started_ms is not None and end < self._started_ms:
            self._invalid_reason = "shot end precedes shot start"
        if not self._samples:
            self._invalid_reason = self._invalid_reason or "shot has no weight samples"
        final_grams = self._samples[-1].snapshot.grams if self._samples else None
        duration = (
            None
            if end is None or self._started_ms is None
            else max(0.0, end - self._started_ms)
        )
        if duration is not None and duration <= 0:
            self._invalid_reason = self._invalid_reason or "shot duration is not positive"
        if self._samples and len(self._samples) >= self._stable_sample_count:
            final_samples = self._samples[-self._stable_sample_count :]
            final_values = [sample.snapshot.grams for sample in final_samples]
            if max(final_values) - min(final_values) > self._stability_tolerance_g:
                self._invalid_reason = self._invalid_reason or "final scale window is not stable"
        elif self._samples:
            self._invalid_reason = self._invalid_reason or "not enough samples for final stability window"
        effective_reason = self._invalid_reason or reason
        is_valid = bool(valid) and self._invalid_reason is None
        shot = OpenScaleShot(
            samples=tuple(self._samples),
            started_ms=self._started_ms,
            ended_ms=end,
            duration_ms=duration,
            final_grams=final_grams,
            valid=is_valid,
            validity="valid" if is_valid else "invalid",
            reason=effective_reason,
            boundary_origin=self._boundary_origin,
            metadata=dict(self._metadata),
        )
        self._reset()
        return shot

    def abort(self, reason: str = "scale stream disconnected") -> OpenScaleShot:
        """Record an invalid shot after a transport or operator interruption."""

        return self.finish(valid=False, reason=reason)

    def _reset(self) -> None:
        self._samples = []
        self._started_ms = None
        self._last_ms = None
        self._metadata = {}
        self._invalid_reason = None
        self._active = False


__all__ = ["OpenScaleShot", "OpenScaleShotSample", "OpenScaleShotAccumulator"]
