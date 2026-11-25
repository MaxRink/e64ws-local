"""Load a grind_capture JSONL trace for the simulator."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


def _dedupe(points: list[tuple[float, float]]) -> list[tuple[float, float]]:
    points.sort()
    deduped: list[tuple[float, float]] = []
    for point in points:
        if deduped and point[0] <= deduped[-1][0]:
            deduped[-1] = point
        else:
            deduped.append(point)
    return deduped


def load_capture_trace(path: str | Path,
                       baseline_gr: float = 0.0) -> list[tuple[float, float]]:
    """Return sorted (elapsed_s, grams) points from a grind capture.

    A real capture includes portafilter placement and removal, so when a
    ``Grind`` state is present the returned curve is trimmed to the first
    ``Grind`` through the last ``GbwPostGrind`` sample.  Weights are rebased on
    ``grindStartWeightGr`` and offset by ``baseline_gr`` so the simulator's
    idle weight is the curve's start.  Captures without a ``Grind`` state keep
    the old raw behavior.

    Samples without a numeric ``grindCurrentWeightGr`` are ignored.
    """
    rows: list[tuple[float, float, dict]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        state = record.get("state")
        if not isinstance(state, dict):
            continue
        t = record.get("t")
        weight = state.get("grindCurrentWeightGr")
        if isinstance(t, (int, float)) and isinstance(weight, (int, float)) \
                and not isinstance(weight, bool):
            rows.append((float(t), float(weight), state))
    if not rows:
        raise ValueError(f"no weight samples in {path}")
    rows.sort(key=lambda row: row[0])

    grind_index = next(
        (i for i, (_, _, state) in enumerate(rows)
         if state.get("grindState") == "Grind"),
        None,
    )
    if grind_index is not None:
        start_t, start_weight, start_state = rows[grind_index]
        start_ref = start_state.get("grindStartWeightGr")
        if not isinstance(start_ref, (int, float)) or isinstance(start_ref, bool):
            start_ref = start_weight
        window: list[tuple[float, float]] = []
        active = False
        for t, weight, state in rows[grind_index:]:
            name = state.get("grindState")
            if name in ("Grind", "GbwPostGrind"):
                active = True
                window.append((t, weight))
            elif active:
                break
        if window:
            return _dedupe([
                (t - start_t, (weight - float(start_ref)) + float(baseline_gr))
                for t, weight in window
            ])

    return _dedupe([(t, weight) for t, weight, _ in rows])


def load_capture_snapshot(path: str | Path) -> dict[str, Any]:
    """Return the first captured device state, or an empty dict.

    A capture starts while the grinder is idle, so its first sample is the
    closest record of the settings and sensors the simulator should use.
    """
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        state = record.get("state")
        if isinstance(state, dict):
            return state
    return {}


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def apply_capture_snapshot(state: Any, snapshot: dict[str, Any]) -> int:
    """Copy safe live fields from a capture sample into a simulator state.

    The static live profile is a snapshot too; a trace is newer.  Only
    read-only sensor/setup fields are copied, never credentials or config
    manager rows.  Returns the number of fields applied.
    """
    if not isinstance(snapshot, dict):
        return 0
    applied = 0

    def number(target: Any, attribute: str, key: str, cast=float) -> None:
        nonlocal applied
        value = snapshot.get(key)
        if _number(value):
            setattr(target, attribute, cast(value))
            applied += 1

    def boolean(target: Any, attribute: str, key: str) -> None:
        nonlocal applied
        value = snapshot.get(key)
        if isinstance(value, bool):
            setattr(target, attribute, value)
            applied += 1

    number(state.agsa, "dd_value", "ddValueDum")
    number(state.thermal, "ntc1_temp_degc", "ntc1TempDegC")
    number(state.thermal, "ntc2_temp_degc", "ntc2TempDegC")
    number(state.thermal, "cpu_temp_degc", "cpuTempDegC")
    number(state.grind, "overshoot_weight_gr", "overshootWeightGr")
    if state.fans:
        number(state.fans[0], "tacho_rpm", "fan1TachoRpm", int)
        number(state.fans[0], "duty", "fan1Duty", int)
    if _number(snapshot.get("configId")):
        state.config_id = int(snapshot["configId"])
        applied += 1
    if isinstance(snapshot.get("setupWizardState"), str):
        state.setup_wizard_state = snapshot["setupWizardState"]
        applied += 1
    if isinstance(snapshot.get("agsaStatus"), str):
        state.agsa.status = snapshot["agsaStatus"]
        applied += 1
    boolean(state.agsa, "sensor_failed", "ddSensorFailed")
    boolean(state.thermal, "has_ntc1", "hasNtc1")
    boolean(state.thermal, "ntc1_failed", "ntc1Failed")
    boolean(state.thermal, "ntc2_failed", "ntc2Failed")
    boolean(state.thermal, "cpu_temp_failed", "cpuTempFailed")
    return applied


def trace_summary(trace: Iterable[tuple[float, float]]) -> dict:
    rows = list(trace)
    return {
        "points": len(rows),
        "first_t": rows[0][0],
        "last_t": rows[-1][0],
        "first_weight_gr": rows[0][1],
        "last_weight_gr": rows[-1][1],
        "min_weight_gr": min(w for _, w in rows),
        "max_weight_gr": max(w for _, w in rows),
    }
