#!/usr/bin/env python3
"""Compare the Python GBS model with the committed Decaid JS plugin."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.gbs_model import (
    GbsV2State,
    GbsV3State,
    GbsV4State,
    V1MedianAverage,
    dd_eff_measurement_sequence,
    gbs_v2_adjust,
    gbs_v3_adjust,
    gbs_v4_adjust,
    v1_adjust,
)


def common(result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: result[key]
        for key in (
            "algorithm",
            "phase",
            "candidateDdDum",
            "returnedDdDum",
            "committed",
            "locked",
            "sequence",
            "index",
        )
        if key in result
    }


def python_outputs(test_case: dict[str, Any]) -> list[dict[str, Any]]:
    algorithm = test_case["algorithm"]
    calls = test_case["calls"]
    outputs: list[dict[str, Any]] = []
    if algorithm == "GbS1":
        history = V1MedianAverage()
        state = 1.0
        previous_output: int | None = None
        last_adjustment: int | None = None
        for call in calls:
            actual_ms = call["actualBrewTimeMs"]
            target_ms = call["targetBrewTimeMs"]
            estimated = call["estimatedDdDum"]
            tolerance = call["toleranceMs"]
            central = history.append(actual_ms * 0.001)
            result = v1_adjust(
                central=central,
                observation=target_ms * 0.001,
                previous_state=state,
                previous_output_tenths=previous_output,
            )
            state = result.state
            previous_output = result.output_tenths
            if last_adjustment is None:
                last_adjustment = estimated
            if abs(actual_ms - target_ms) < abs(tolerance):
                returned = last_adjustment
                committed = False
            else:
                last_adjustment = result.output_tenths
                returned = result.output_tenths
                committed = True
            outputs.append(
                common(
                    {
                        "algorithm": algorithm,
                        "phase": "within-error-window" if result.within_error_window else "adjust",
                        "candidateDdDum": result.output_tenths,
                        "returnedDdDum": returned,
                        "committed": committed,
                        "locked": False,
                    }
                )
            )
        return outputs

    if algorithm == "GbS2":
        state = GbsV2State()
        for call in calls:
            result = gbs_v2_adjust(
                state,
                actual_ms=call["actualBrewTimeMs"],
                target_ms=call["targetBrewTimeMs"],
                estimated_dd_dum=call["estimatedDdDum"],
                setpoint_dd_dum=call["setpointDdDum"],
                tolerance_ms=call["toleranceMs"],
            )
            outputs.append(
                common(
                    {
                        "algorithm": algorithm,
                        "phase": result.phase,
                        "candidateDdDum": result.candidate_dum,
                        "returnedDdDum": result.returned_dum,
                        "committed": result.committed,
                        "locked": result.locked,
                    }
                )
            )
        return outputs

    if algorithm == "GbS3":
        state = GbsV3State()
        for call in calls:
            result = gbs_v3_adjust(
                state,
                actual_ms=call["actualBrewTimeMs"],
                target_ms=call["targetBrewTimeMs"],
                estimated_dd_dum=call["estimatedDdDum"],
                setpoint_dd_dum=call["setpointDdDum"],
                tolerance_ms=call["toleranceMs"],
            )
            outputs.append(
                common(
                    {
                        "algorithm": algorithm,
                        "phase": result.phase,
                        "candidateDdDum": result.candidate_dum,
                        "returnedDdDum": result.returned_dum,
                        "committed": result.committed,
                        "locked": result.locked,
                    }
                )
            )
        return outputs

    if algorithm == "GbS4":
        state = GbsV4State()
        for call in calls:
            result = gbs_v4_adjust(
                state,
                actual_ms=call["actualBrewTimeMs"],
                target_ms=call["targetBrewTimeMs"],
                estimated_dd_dum=call["estimatedDdDum"],
                setpoint_dd_dum=call["setpointDdDum"],
                tolerance_ms=call["toleranceMs"],
            )
            outputs.append(
                common(
                    {
                        "algorithm": algorithm,
                        "phase": result.phase,
                        "candidateDdDum": result.candidate_dum,
                        "returnedDdDum": result.returned_dum,
                        "committed": result.committed,
                        "locked": result.locked,
                    }
                )
            )
        return outputs

    if algorithm == "DdEff":
        call = calls[0]
        sequence = list(dd_eff_measurement_sequence(call["estimatedDdDum"], call["calls"]))
        return [
            common(
                {
                    "algorithm": algorithm,
                    "phase": "measurement",
                    "sequence": sequence,
                    "candidateDdDum": sequence[-1],
                    "returnedDdDum": sequence[-1],
                    "committed": False,
                    "locked": False,
                    "index": len(sequence),
                }
            )
        ]

    raise ValueError(f"unsupported parity case: {algorithm}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    fixture_path = root / "tests" / "fixtures" / "gbs_parity.json"
    plugin_path = root / "decaid" / "test" / "fixtures" / "gbs" / "mahlkoenig-e64ws.reaplugin" / "plugin.js"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    actual = subprocess.run(
        ["node", "tools/gbs_parity_node.js", str(fixture_path), str(plugin_path)],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if actual.returncode:
        print(actual.stderr or actual.stdout, file=sys.stderr)
        return actual.returncode
    observed = json.loads(actual.stdout)
    if observed.get("firmware_build") != fixture["firmware_build"]:
        raise AssertionError("plugin fixture build tag mismatch")
    expected = {
        case["name"]: python_outputs(case) for case in fixture["cases"]
    }
    failures: list[str] = []
    for case in observed["cases"]:
        want = expected[case["name"]]
        got = case["outputs"]
        if got != want:
            failures.append(
                f"{case['name']}:\nexpected={json.dumps(want, sort_keys=True)}\n"
                f"observed={json.dumps(got, sort_keys=True)}"
            )
    if failures:
        print("GBS parity: FAIL")
        print("\n".join(failures))
        return 1
    print(f"GBS parity: PASS ({len(expected)} fixture cases; Python ↔ Node)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
