"""Recommendation-only manual dial-in helper for DF54 and DF64 grinders.

This is deliberately not an E64 firmware port.  It combines explicit shot
time and sensory inputs into a relative direction and, only when the caller
supplies a calibrated step size, an optional numeric dial proposal.  It never
connects to or actuates a grinder.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from math import isfinite
from numbers import Real
from typing import Any, Mapping


@dataclass(frozen=True)
class GrinderProfile:
    key: str
    label: str
    burr_diameter_mm: int
    finer_direction: str
    direction_provenance: str
    numeric_finer_delta: int | None
    reference_range: tuple[float, float] | None
    range_confidence: str
    motor_on_adjustment: bool
    hardware_notes: tuple[str, ...]


PROFILES: dict[str, GrinderProfile] = {
    "df54": GrinderProfile(
        key="df54",
        label="Turin/DF54",
        burr_diameter_mm=54,
        finer_direction="counterclockwise",
        direction_provenance="Turin product guidance; verify the individual unit",
        numeric_finer_delta=None,
        reference_range=None,
        range_confidence="not hard-coded; verify this unit's zero and markings",
        motor_on_adjustment=True,
        hardware_notes=(
            "54 mm flat burrs and stepless micrometric adjustment",
            "true zero and useful dial calibration are unit-specific",
            "manufacturer/retailer sources conflict on some motor-power listings; power is not used by this model",
        ),
    ),
    "df64_gen1": GrinderProfile(
        key="df64_gen1",
        label="DF64 Gen 1",
        burr_diameter_mm=64,
        finer_direction="clockwise",
        direction_provenance="Clive DF64 manual; verify burr/collar configuration",
        numeric_finer_delta=None,
        reference_range=(0.0, 90.0),
        range_confidence="community reference only; verify the installed burrs and true zero",
        motor_on_adjustment=True,
        hardware_notes=(
            "64 mm flat burrs and a sensitive stepless collar",
            "SSP or other burr changes can make the factory sticker inaccurate",
            "Gen 1 hardware and parts must not be assumed interchangeable with Gen 2",
        ),
    ),
    "df64_gen2": GrinderProfile(
        key="df64_gen2",
        label="DF64 Gen 2",
        burr_diameter_mm=64,
        finer_direction="clockwise",
        direction_provenance="DF64 mechanical convention used as a starting profile; verify Gen 2 unit",
        numeric_finer_delta=None,
        reference_range=(0.0, 90.0),
        range_confidence="community reference only; verify the installed burrs and true zero",
        motor_on_adjustment=True,
        hardware_notes=(
            "64 mm flat burrs and stepless micrometric adjustment",
            "Gen 2 versions vary; current V2.5 listings describe chute/ionizer changes",
            "burr coating, alignment, seasoning, and zero point change the usable range",
        ),
    ),
}


@dataclass(frozen=True)
class DialRecommendation:
    profile: str
    direction: str
    physical_turn: str | None
    confidence: float
    reasons: tuple[str, ...]
    suggested_step_marks: float | None
    current_dial: float | None
    proposed_dial: float | None
    requires_confirmation: bool
    safety_notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["reasons"] = list(self.reasons)
        result["safety_notes"] = list(self.safety_notes)
        return result


def _finite(value: Real, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{field} must be finite")
    result = float(value)
    if not isfinite(result):
        raise ValueError(f"{field} must be finite")
    return result


def _profile(value: GrinderProfile | str) -> GrinderProfile:
    if isinstance(value, GrinderProfile):
        return value
    try:
        return PROFILES[value.strip().lower()]
    except KeyError as exc:
        raise ValueError(f"unknown grinder profile: {value!r}") from exc


_FINER_WORDS = ("acidic", "acid", "sour", "sharp", "under-extracted", "under extracted")
_COARSER_WORDS = ("bitter", "dry", "harsh", "astringent", "over-extracted", "over extracted")


def recommend_manual(
    *,
    profile: GrinderProfile | str,
    target_time_s: Real,
    actual_time_s: Real,
    flavor: str = "",
    tolerance_s: Real = 1.0,
    current_dial: Real | None = None,
    step_marks: Real | None = None,
    dose_g: Real | None = None,
    yield_g: Real | None = None,
    numeric_finer_delta: int | None = None,
    finer_direction: str | None = None,
) -> DialRecommendation:
    """Return a conservative, explainable relative dial recommendation.

    Time and sensory directions are intentionally treated as independent
    signals.  If they disagree, ``direction`` is ``none`` and the caller must
    ask the operator to resolve the conflict.  Dose/yield are retained only as
    context validation; no unsupported extraction model is inferred from
    them.
    """

    selected = _profile(profile)
    physical_finer_direction = finer_direction or selected.finer_direction
    if physical_finer_direction not in ("clockwise", "counterclockwise"):
        raise ValueError("finer_direction must be clockwise or counterclockwise")
    target = _finite(target_time_s, field="target_time_s")
    actual = _finite(actual_time_s, field="actual_time_s")
    tolerance = _finite(tolerance_s, field="tolerance_s")
    if target <= 0 or actual <= 0 or tolerance < 0:
        raise ValueError("shot times must be positive and tolerance non-negative")
    if current_dial is not None:
        current = _finite(current_dial, field="current_dial")
        if selected.reference_range is not None:
            lower, upper = selected.reference_range
            if not lower <= current <= upper:
                raise ValueError("current_dial is outside the selected reference range")
    else:
        current = None
    if step_marks is not None:
        step = _finite(step_marks, field="step_marks")
        if step <= 0:
            raise ValueError("step_marks must be positive")
    else:
        step = None
    if numeric_finer_delta not in (None, -1, 1):
        raise ValueError("numeric_finer_delta must be -1, 1, or omitted")
    if dose_g is not None and _finite(dose_g, field="dose_g") <= 0:
        raise ValueError("dose_g must be positive")
    if yield_g is not None and _finite(yield_g, field="yield_g") < 0:
        raise ValueError("yield_g must not be negative")

    directions: list[str] = []
    reasons: list[str] = []
    if actual < target - tolerance:
        directions.append("finer")
        reasons.append("brew time is below target")
    elif actual > target + tolerance:
        directions.append("coarser")
        reasons.append("brew time is above target")
    flavor_text = flavor.strip().lower()
    if any(word in flavor_text for word in _FINER_WORDS):
        directions.append("finer")
        reasons.append("sensory input suggests under-extraction")
    if any(word in flavor_text for word in _COARSER_WORDS):
        directions.append("coarser")
        reasons.append("sensory input suggests over-extraction")

    distinct = set(directions)
    if len(distinct) == 1:
        direction = next(iter(distinct))
        confidence = min(0.9, 0.55 + 0.15 * (len(reasons) - 1))
    elif len(distinct) > 1:
        direction = "none"
        confidence = 0.0
        reasons.append("time and sensory signals conflict; confirm before changing grind")
    else:
        direction = "none"
        confidence = 0.0
        reasons.append("no signal outside the time tolerance or recognized sensory vocabulary")

    physical_turn: str | None = None
    if direction == "finer":
        physical_turn = physical_finer_direction
    elif direction == "coarser":
        physical_turn = "counterclockwise" if physical_finer_direction == "clockwise" else "clockwise"

    proposed: float | None = None
    if direction != "none" and current is not None and step is not None and numeric_finer_delta is not None:
        delta = numeric_finer_delta * step
        if direction == "coarser":
            delta = -delta
        candidate = current + delta
        if selected.reference_range is None or selected.reference_range[0] <= candidate <= selected.reference_range[1]:
            proposed = candidate
        else:
            reasons.append("numeric proposal would leave the reference range; verify the physical dial")

    safety_notes = (
        "recommendation only; this tool never contacts or moves a grinder",
        "use a small calibrated step and re-measure the next shot",
        "verify true zero, burr set, alignment, and the sign of the physical dial on this unit",
    )
    if selected.motor_on_adjustment:
        safety_notes += ("follow the manufacturer's motor-running adjustment guidance",)
    return DialRecommendation(
        profile=selected.key,
        direction=direction,
        physical_turn=physical_turn,
        confidence=confidence,
        reasons=tuple(reasons),
        suggested_step_marks=step,
        current_dial=current,
        proposed_dial=proposed,
        requires_confirmation=True,
        safety_notes=safety_notes,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recommendation-only DF grinder dial helper")
    parser.add_argument("--profile", choices=tuple(PROFILES), required=False)
    parser.add_argument("--list-profiles", action="store_true")
    parser.add_argument("--target-time", type=float)
    parser.add_argument("--actual-time", type=float)
    parser.add_argument("--flavor", default="")
    parser.add_argument("--tolerance", type=float, default=1.0)
    parser.add_argument("--current-dial", type=float)
    parser.add_argument("--step-marks", type=float)
    parser.add_argument("--dose-g", type=float)
    parser.add_argument("--yield-g", type=float)
    parser.add_argument(
        "--numeric-finer-delta",
        type=int,
        choices=(-1, 1),
        help="calibrated numeric dial sign: -1 means finer decreases the displayed number",
    )
    parser.add_argument(
        "--finer-direction",
        choices=("clockwise", "counterclockwise"),
        help="override the profile's physical direction with a per-unit calibration",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.list_profiles:
        print(json.dumps({key: asdict(value) for key, value in PROFILES.items()}, indent=2, sort_keys=True))
        return 0
    if args.profile is None or args.target_time is None or args.actual_time is None:
        raise SystemExit("--profile, --target-time, and --actual-time are required")
    recommendation = recommend_manual(
        profile=args.profile,
        target_time_s=args.target_time,
        actual_time_s=args.actual_time,
        flavor=args.flavor,
        tolerance_s=args.tolerance,
        current_dial=args.current_dial,
        step_marks=args.step_marks,
        dose_g=args.dose_g,
        yield_g=args.yield_g,
        numeric_finer_delta=args.numeric_finer_delta,
        finer_direction=args.finer_direction,
    )
    print(json.dumps(recommendation.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DialRecommendation",
    "GrinderProfile",
    "PROFILES",
    "main",
    "recommend_manual",
]
