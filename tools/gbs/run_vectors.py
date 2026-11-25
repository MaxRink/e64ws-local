#!/usr/bin/env python3
"""Execute the GBS golden vectors against every available implementation.

The vectors in ``tools/gbs/vectors/`` are the goldens. This runner does not
derive expectations from an implementation: it executes each implementation
through a thin adapter and compares the normalized result with the vector's
hand-checked ``expected`` entries.

Exit codes:

* ``0`` -- every executed vector matched, and every pair of executed
  implementations agreed (or disagreed only where the vector declares it).
* ``1`` -- at least one vector failed, an adapter failed, or two
  implementations disagreed without a declaration.
* ``2`` -- the vector corpus or the runner configuration is invalid.

A skipped implementation is reported with its reason; it never changes the exit
code on its own.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_VECTOR_DIR = Path(__file__).resolve().parent / "vectors"
NODE_ADAPTER = Path(__file__).resolve().parent / "run_vectors_node.js"
DEFAULT_JS_FIXTURE = (
    ROOT / "decaid" / "test" / "fixtures" / "gbs" / "mahlkoenig-e64ws.reaplugin" / "plugin.js"
)


def js_fixture_path() -> Path:
    """Return the plugin path, overridable with ``GBS_JS_PLUGIN``.

    ``decaid/`` is a gitignored nested checkout, so a fresh worktree does not
    have it. A caller with the checkout can point the runner at it without
    copying anything into this repository.
    """

    override = os.environ.get("GBS_JS_PLUGIN")
    return Path(override).expanduser() if override else DEFAULT_JS_FIXTURE

IMPLEMENTATION_ORDER = ("python", "js", "cpp")
PROVENANCE = {"V", "I", "S"}

POST_STATE = "__postState__"

PASS = "pass"
FAIL = "fail"
SKIP = "skip"

# Pure-function vectors: which case inputs are operands and which key carries
# the observed value. The expected value lives under "expected" in the case.
FUNCTIONS: dict[str, tuple[str, ...]] = {
    "hysteretic_quantize": ("value", "previousOutputTenths"),
    "cxx_round": ("value",),
    "v1_adjust": ("central", "observation", "previousState"),
    "v2_inverse_regression": ("points", "targetSec", "currentUm"),
}


class VectorError(ValueError):
    """Raised when a vector file or the runner configuration is invalid."""


# --- vector loading -------------------------------------------------------


@dataclass(frozen=True)
class Vector:
    path: Path
    firmware_build: str
    body: Mapping[str, Any]

    @property
    def id(self) -> str:
        return str(self.body["id"])

    @property
    def provenance(self) -> str:
        return str(self.body["provenance"])

    @property
    def algorithm(self) -> str | None:
        return self.body.get("algorithm")

    @property
    def function(self) -> str | None:
        return self.body.get("function")

    @property
    def implementations(self) -> tuple[str, ...]:
        declared = self.body.get("implementations")
        return IMPLEMENTATION_ORDER if declared is None else tuple(declared)

    @property
    def expected_error(self) -> str | None:
        return self.body.get("expectedError")

    @property
    def capability_gaps(self) -> Mapping[str, str]:
        return self.body.get("capabilityGaps") or {}

    @property
    def known_defects(self) -> Mapping[str, str]:
        return self.body.get("knownDefects") or {}

    @property
    def divergences(self) -> Mapping[str, Mapping[str, Any]]:
        return self.body.get("divergences") or {}


def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise VectorError(f"{where}: missing required key {key!r}")
    return mapping[key]


def load_vectors(directory: Path = DEFAULT_VECTOR_DIR) -> list[Vector]:
    """Load and validate every ``*.json`` vector file in ``directory``."""

    if not directory.is_dir():
        raise VectorError(f"vector directory does not exist: {directory}")
    files = sorted(directory.glob("*.json"))
    if not files:
        raise VectorError(f"no vector files under {directory}")
    vectors: list[Vector] = []
    seen: dict[str, Path] = {}
    for path in files:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VectorError(f"{path.name}: cannot read JSON: {exc}") from exc
        if not isinstance(document, Mapping) or document.get("schema") != 1:
            raise VectorError(f"{path.name}: unsupported schema")
        firmware = str(_require(document, "firmware_build", path.name))
        entries = _require(document, "vectors", path.name)
        if not isinstance(entries, list):
            raise VectorError(f"{path.name}: 'vectors' must be a list")
        for index, body in enumerate(entries):
            where = f"{path.name}[{index}]"
            _validate_body(body, where)
            vector_id = str(body["id"])
            if vector_id in seen:
                raise VectorError(
                    f"{vector_id}: duplicate id in {path.name} and {seen[vector_id].name}"
                )
            seen[vector_id] = path
            vectors.append(Vector(path=path, firmware_build=firmware, body=body))
    return vectors


def _validate_divergences(
    body: Mapping[str, Any],
    where: str,
    *,
    observations: int,
    has_function: bool,
) -> Mapping[str, Mapping[str, Any]]:
    """Validate per-implementation policy overrides and return them."""

    divergences = body.get("divergences")
    if divergences is None:
        divergences = {}
    if not isinstance(divergences, Mapping):
        raise VectorError(f"{where}: 'divergences' must be an object")
    for name, divergence in divergences.items():
        if name not in IMPLEMENTATION_ORDER:
            raise VectorError(f"{where}: unknown divergence implementation {name!r}")
        if not isinstance(divergence, Mapping) or not divergence.get("policy"):
            raise VectorError(f"{where}.divergences[{name}]: 'policy' is required")
        has_expected = "expected" in divergence
        has_error = "expectedError" in divergence
        if has_expected == has_error:
            raise VectorError(
                f"{where}.divergences[{name}]: exactly one of 'expected' or "
                "'expectedError' is required"
            )
        if has_expected and (
            not isinstance(divergence["expected"], list)
            or len(divergence["expected"]) != observations
        ):
            raise VectorError(
                f"{where}.divergences[{name}]: 'expected' must match the "
                f"{observations} observation(s) one-to-one"
            )
        if has_error and (
            not isinstance(divergence["expectedError"], str)
            or not divergence["expectedError"]
        ):
            raise VectorError(
                f"{where}.divergences[{name}]: 'expectedError' must be a non-empty string"
            )
        if has_function and has_error:
            raise VectorError(
                f"{where}.divergences[{name}]: 'expectedError' is not supported "
                "for function vectors"
            )
    return divergences


def _validate_body(body: Any, where: str) -> None:
    if not isinstance(body, Mapping):
        raise VectorError(f"{where}: vector must be an object")
    _require(body, "id", where)
    provenance = str(_require(body, "provenance", where))
    if provenance not in PROVENANCE:
        raise VectorError(f"{where}: provenance must be one of {sorted(PROVENANCE)}")
    _require(body, "source", where)
    has_algorithm = "algorithm" in body
    has_function = "function" in body
    if has_algorithm == has_function:
        raise VectorError(f"{where}: exactly one of 'algorithm' or 'function' is required")
    declared = body.get("implementations")
    if declared is not None and (
        not isinstance(declared, list)
        or not declared
        or len(set(declared)) != len(declared)
        or any(name not in IMPLEMENTATION_ORDER for name in declared)
    ):
        raise VectorError(
            f"{where}: 'implementations' must be a non-empty subset of {list(IMPLEMENTATION_ORDER)} without duplicates"
        )
    for name in ("capabilityGaps", "knownDefects"):
        mapping = body.get(name)
        if mapping is None:
            mapping = {}
        if not isinstance(mapping, Mapping):
            raise VectorError(f"{where}: {name!r} must be an object")
        for key, value in mapping.items():
            if key not in IMPLEMENTATION_ORDER:
                raise VectorError(f"{where}.{name}[{key!r}]: unknown implementation")
            if not isinstance(value, str) or not value:
                raise VectorError(f"{where}.{name}[{key!r}]: a non-empty reason is required")
    post_state = body.get("postState")
    if post_state is not None and (
        not isinstance(post_state, Mapping) or not post_state
    ):
        raise VectorError(f"{where}: 'postState' must be a non-empty object")
    if has_function:
        if body["function"] not in FUNCTIONS:
            raise VectorError(f"{where}: unsupported function {body['function']!r}")
        if body.get("expectedError") is not None:
            raise VectorError(
                f"{where}: 'expectedError' is not supported for function vectors"
            )
        if post_state is not None:
            raise VectorError(
                f"{where}: 'postState' is not supported for function vectors"
            )
        cases = _require(body, "cases", where)
        if not isinstance(cases, list) or not cases:
            raise VectorError(f"{where}: 'cases' must be a non-empty list")
        for case_index, case in enumerate(cases):
            if not isinstance(case, Mapping) or "expected" not in case:
                raise VectorError(f"{where}.cases[{case_index}]: 'expected' is required")
            for operand in FUNCTIONS[body["function"]]:
                if operand not in case:
                    raise VectorError(f"{where}.cases[{case_index}]: missing {operand!r}")
        _validate_divergences(
            body,
            where,
            observations=len(cases),
            has_function=True,
        )
        return
    calls = _require(body, "calls", where)
    if not isinstance(calls, list) or not calls:
        raise VectorError(f"{where}: 'calls' must be a non-empty list")
    if not isinstance(body.get("preState", {}), Mapping):
        raise VectorError(f"{where}: 'preState' must be an object")
    expected_error = body.get("expectedError")
    if expected_error is not None and (not isinstance(expected_error, str) or not expected_error):
        raise VectorError(f"{where}: 'expectedError' must be a non-empty string")
    expected = body.get("expected")
    if expected_error and expected is not None:
        raise VectorError(f"{where}: 'expected' and 'expectedError' are mutually exclusive")
    if expected is not None:
        if not isinstance(expected, list) or len(expected) != len(calls):
            raise VectorError(f"{where}: 'expected' must match 'calls' one-to-one")
        for call_index, entry in enumerate(expected):
            if not isinstance(entry, Mapping) or not entry:
                raise VectorError(f"{where}.expected[{call_index}]: must be a non-empty object")
    divergences = _validate_divergences(
        body,
        where,
        observations=len(calls),
        has_function=False,
    )
    if expected is None and expected_error is None and not divergences:
        raise VectorError(f"{where}: 'expected', 'expectedError', or 'divergences' is required")


# --- adapters -------------------------------------------------------------


@dataclass(frozen=True)
class Implementation:
    """One implementation the runner can execute, or a recorded skip."""

    name: str
    label: str
    run: Callable[[Sequence[Vector]], dict[str, list[Any]]] | None
    skip_reason: str | None = None
    version: str | None = None

    @property
    def available(self) -> bool:
        return self.run is not None


def _algorithm_output(algorithm: str, result: Any) -> dict[str, Any]:
    return {
        "algorithm": algorithm,
        "phase": result.phase,
        "candidateDdDum": result.candidate_dum,
        "returnedDdDum": result.returned_dum,
        "committed": result.committed,
        "locked": result.locked,
    }


def _error_output(exc: BaseException) -> dict[str, str]:
    return {"error": type(exc).__name__}


def python_adapter(vectors: Sequence[Vector]) -> dict[str, list[Any]]:
    """Execute vectors against ``tools.gbs_model``.

    The adapter mirrors the recovered caller. V1 keeps its own continuous
    state and last output and applies the strict tolerance gate after the
    adjustment; V2-V4 use the stateful models; DdEff keeps the initial value
    and call counter. It returns observable values only.
    """

    from tools import gbs_model

    results: dict[str, list[Any]] = {}

    def run_v1(vector: Vector) -> tuple[list[Any], dict[str, Any]]:
        restored = vector.body.get("preState", {}).get("v1") or {}
        state = float(restored.get("state", gbs_model.GBS_V1_MIN_STATE))
        previous_output = restored.get("outputTenths")
        history = gbs_model.V1MedianAverage()
        last_adjustment: int | None = None
        outputs: list[Any] = []
        for call in vector.body["calls"]:
            actual_ms = int(call["actualMs"])
            target_ms = int(call["targetMs"])
            tolerance_ms = int(call["toleranceMs"])
            estimated = int(call["estimatedDdDum"])
            central = history.append(actual_ms * 0.001)
            try:
                adjustment = gbs_model.v1_adjust(
                    central=central,
                    observation=target_ms * 0.001,
                    previous_state=state,
                    previous_output_tenths=previous_output,
                )
            except ValueError as exc:
                outputs.append(_error_output(exc))
                continue
            state = adjustment.state
            previous_output = adjustment.output_tenths
            phase = "within-error-window" if adjustment.within_error_window else "adjust"
            if abs(actual_ms - target_ms) < abs(tolerance_ms):
                if last_adjustment is None:
                    last_adjustment = estimated
                outputs.append(
                    {
                        "algorithm": "GbS1",
                        "phase": phase,
                        "central": adjustment.central,
                        "correction": adjustment.correction,
                        "candidateDdDum": adjustment.output_tenths,
                        "returnedDdDum": last_adjustment,
                        "committed": False,
                    }
                )
                continue
            last_adjustment = adjustment.output_tenths
            outputs.append(
                {
                    "algorithm": "GbS1",
                    "phase": phase,
                    "central": adjustment.central,
                    "correction": adjustment.correction,
                    "candidateDdDum": adjustment.output_tenths,
                    "returnedDdDum": adjustment.output_tenths,
                    "committed": True,
                }
            )
        snapshot = {
            "records": [[record.value, record.age] for record in history.records()],
            "state": state,
            "outputTenths": previous_output,
        }
        return outputs, snapshot

    def run_v2(vector: Vector) -> tuple[list[Any], dict[str, Any]]:
        restored = vector.body.get("preState", {}).get("v2") or {}
        points = [
            gbs_model.SamplePoint(float(point[0]), float(point[1]))
            for point in restored.get("points", [])
        ]
        model = gbs_model.GbsV2State(
            history=gbs_model.SampleHistory(points),
            last_result_dum=restored.get("lastResultDum"),
        )
        outputs: list[Any] = []
        for call in vector.body["calls"]:
            try:
                outputs.append(
                    _algorithm_output(
                        "GbS2",
                        gbs_model.gbs_v2_adjust(
                            model,
                            actual_ms=int(call["actualMs"]),
                            target_ms=int(call["targetMs"]),
                            estimated_dd_dum=int(call["estimatedDdDum"]),
                            setpoint_dd_dum=int(call["setpointDdDum"]),
                            tolerance_ms=int(call["toleranceMs"]),
                        )
                    )
                )
            except RuntimeError as exc:
                outputs.append(_error_output(exc))
        snapshot = {
            "points": [[point.x, point.y] for point in model.history],
            "lastResultDum": model.last_result_dum,
        }
        return outputs, snapshot

    def run_v3_or_v4(vector: Vector) -> tuple[list[Any], dict[str, Any]]:
        is_v3 = vector.algorithm == "GbS3"
        state_class = gbs_model.GbsV3State if is_v3 else gbs_model.GbsV4State
        adjust = gbs_model.gbs_v3_adjust if is_v3 else gbs_model.gbs_v4_adjust
        restored = vector.body.get("preState", {}).get(
            {"GbS3": "v3", "GbS4": "v4"}[vector.algorithm]
        ) or {}
        kwargs: dict[str, Any] = {}
        if "history" in restored:
            kwargs["history"] = gbs_model.SampleHistory(
                gbs_model.SamplePoint(float(point[0]), float(point[1]))
                for point in restored["history"]
            )
        mappings = {
            "filteredDdTimesBrew": "filtered_dd_times_brew",
            "hold_cyclesRemaining": "hold_cycles_remaining",
            "lastTargetDum": "last_target_dum",
            "lastAdjustmentDum": "last_adjustment_dum",
            "farFactor": "far_factor",
            "midFactor": "mid_factor",
            "nearFactor": "near_factor",
        }
        for source, target in mappings.items():
            if source in restored:
                kwargs[target] = restored[source]
        model = state_class(**kwargs)
        outputs: list[Any] = []
        for call in vector.body["calls"]:
            try:
                outputs.append(
                    _algorithm_output(
                        vector.algorithm,
                        adjust(
                            model,
                            actual_ms=int(call["actualMs"]),
                            target_ms=int(call["targetMs"]),
                            estimated_dd_dum=int(call["estimatedDdDum"]),
                            setpoint_dd_dum=int(call["setpointDdDum"]),
                            tolerance_ms=int(call["toleranceMs"]),
                        )
                    )
                )
            except RuntimeError as exc:
                outputs.append(_error_output(exc))
        snapshot = {
            "history": [[point.x, point.y] for point in model.history],
            "farFactor": model.far_factor,
            "midFactor": model.mid_factor,
            "nearFactor": model.near_factor,
            "filterRetention": model.filter_retention,
            "holdCyclesSetting": model.hold_cycles_setting,
            "holdCyclesRemaining": model.hold_cycles_remaining,
            "lastTargetDum": model.last_target_dum,
            "lastAdjustmentDum": model.last_adjustment_dum,
            "filteredDdTimesBrew": model.filtered_dd_times_brew,
        }
        if is_v3:
            snapshot["nearThreshold"] = model.near_threshold_s
            snapshot["keepMediumInterval"] = model.keep_medium_interval_width
        return outputs, snapshot

    def run_dd_eff(vector: Vector) -> tuple[list[Any], dict[str, Any]]:
        restored = vector.body.get("preState", {}).get("ddeff") or {}
        initial = restored.get("initialCoarsenessDum")
        calls_so_far = int(restored.get("calls", 0))
        outputs: list[Any] = []
        for call in vector.body["calls"]:
            if call.get("reset", False) or initial is None:
                initial = int(call["estimatedDdDum"])
                calls_so_far = 0
            count = int(call.get("calls", 1))
            full = gbs_model.dd_eff_measurement_sequence(int(initial), calls_so_far + count)
            sequence = list(full[calls_so_far:])
            calls_so_far += count
            outputs.append(
                {
                    "algorithm": "DdEff",
                    "phase": "measurement",
                    "sequence": sequence,
                    "candidateDdDum": sequence[-1] if sequence else None,
                    "returnedDdDum": sequence[-1] if sequence else None,
                    "committed": False,
                    "index": calls_so_far,
                }
            )
        snapshot = {"initialDdDum": initial, "index": calls_so_far}
        return outputs, snapshot

    def run_function(vector: Vector) -> list[Any]:
        outputs: list[Any] = []
        for case in vector.body["cases"]:
            try:
                if vector.function == "hysteretic_quantize":
                    previous = case["previousOutputTenths"]
                    quantized = gbs_model.hysteretic_quantize(
                        case["value"], None if previous is None else previous / 10.0
                    )
                    outputs.append({"value": quantized})
                elif vector.function == "cxx_round":
                    outputs.append({"value": gbs_model.cxx_round(case["value"])})
                elif vector.function == "v1_adjust":
                    adjustment = gbs_model.v1_adjust(
                        central=case["central"],
                        observation=case["observation"],
                        previous_state=case["previousState"],
                        previous_output_tenths=case.get("previousOutputTenths"),
                    )
                    outputs.append(
                        {
                            "phase": "within-error-window"
                            if adjustment.within_error_window
                            else "adjust",
                            "central": adjustment.central,
                            "correction": adjustment.correction,
                            "candidateDdDum": adjustment.output_tenths,
                        }
                    )
                elif vector.function == "v2_inverse_regression":
                    points = tuple(
                        gbs_model.SamplePoint(float(x), float(y))
                        for x, y in case["points"]
                    )
                    prediction = gbs_model.firmware_linear_regression_predict(
                        points, case["targetSec"]
                    )
                    outputs.append(
                        {
                            "prediction": prediction,
                            "candidateDdDum": gbs_model.output_tenths(
                                gbs_model.blend_v2(case["currentUm"], prediction)
                            ),
                        }
                    )
                else:  # validated at load time
                    raise VectorError(f"{vector.id}: unsupported function {vector.function!r}")
            except (TypeError, ValueError) as exc:
                outputs.append(_error_output(exc))
        return outputs

    for vector in vectors:
        if vector.function:
            results[vector.id] = run_function(vector)
            continue
        if vector.algorithm == "GbS1":
            outputs, snapshot = run_v1(vector)
        elif vector.algorithm == "GbS2":
            outputs, snapshot = run_v2(vector)
        elif vector.algorithm in ("GbS3", "GbS4"):
            outputs, snapshot = run_v3_or_v4(vector)
        elif vector.algorithm == "DdEff":
            outputs, snapshot = run_dd_eff(vector)
        else:
            raise VectorError(f"{vector.id}: unsupported algorithm {vector.algorithm!r}")
        if vector.body.get("postState") and snapshot is not None:
            outputs.append({POST_STATE: snapshot})
        results[vector.id] = outputs
    return results


def node_adapter(vectors: Sequence[Vector]) -> dict[str, list[Any]]:
    """Execute vectors against the shipped Decaid plugin via ``node``."""

    payload = {
        "plugin": str(js_fixture_path()),
        "vectors": [
            {
                "id": vector.id,
                "algorithm": vector.algorithm,
                "function": vector.function,
                "preState": vector.body.get("preState") or {},
                "calls": vector.body.get("calls", []),
                "cases": vector.body.get("cases", []),
                "postState": vector.body.get("postState"),
            }
            for vector in vectors
        ],
    }
    completed = subprocess.run(
        ["node", str(NODE_ADAPTER)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=180,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"node adapter failed: {detail}")
    observed = json.loads(completed.stdout)
    if "fatal" in observed:
        raise RuntimeError(f"node adapter could not load the plugin: {observed['fatal']}")
    return observed["results"]


def _plugin_version(plugin: Path) -> str | None:
    try:
        manifest = plugin.parent / "manifest.json"
        return str(json.loads(manifest.read_text(encoding="utf-8")).get("version"))
    except (OSError, ValueError):
        return None


def detect_implementations() -> list[Implementation]:
    """Return the implementations in stable order, with a reason for each skip."""

    python = Implementation(
        "python",
        "Python (tools/gbs_model.py)",
        python_adapter,
        skip_reason=None,
    )
    try:
        import tools.gbs_model  # noqa: F401
    except Exception as exc:  # noqa: BLE001 - an unimportable model is a skip, not a crash
        python = Implementation(
            "python",
            "Python (tools/gbs_model.py)",
            None,
            skip_reason=f"tools.gbs_model is not importable: {exc}",
        )

    fixture = js_fixture_path()
    if not fixture.exists():
        js = Implementation(
            "js",
            "Node (Decaid plugin)",
            None,
            skip_reason=(
                f"{fixture} is absent; decaid/ is a gitignored nested checkout. "
                "Set GBS_JS_PLUGIN to a plugin.js path to run the Node side."
            ),
        )
    elif not shutil.which("node"):
        js = Implementation("js", "Node (Decaid plugin)", None, skip_reason="node is not installed")
    elif not NODE_ADAPTER.exists():
        js = Implementation(
            "js",
            "Node (Decaid plugin)",
            None,
            skip_reason=f"{NODE_ADAPTER.relative_to(ROOT)} is missing",
        )
    else:
        js = Implementation(
            "js",
            "Node (Decaid plugin)",
            node_adapter,
            version=_plugin_version(fixture),
        )

    cpp = Implementation(
        "cpp",
        "C++ (src/recovered)",
        None,
        skip_reason=(
            "src/recovered/gbs_algorithms.cpp is a static source reconstruction "
            "with no main(), no adapter entry point, and no build target. "
            "Compiling it would re-run the recovered source, not the vendor "
            "library, so it is not a parity implementation."
        ),
    )
    return [python, js, cpp]


# --- comparison -----------------------------------------------------------


@dataclass
class Cell:
    verdict: str
    detail: str = ""


@dataclass
class EvaluatedVector:
    vector: Vector
    cells: dict[str, Cell]
    executed: list[str] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)
    declared_gaps: list[str] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)
    diverged: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return FAIL if any(cell.verdict == FAIL for cell in self.cells.values()) else PASS

    @property
    def declared_divergence(self) -> bool:
        """True only when a passing divergence was cross-checked on both sides.

        ``diverged`` records the implementations whose own policy was asserted;
        a declared difference is only evidence when at least two implementations
        actually executed.  Otherwise the vector is unproven, not declared.
        """

        return (
            bool(self.diverged)
            and self.verdict == PASS
            and len(self.executed) > 1
        )


def _value_mismatches(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> list[str]:
    """Compare an expected fragment against its observed superset."""

    problems: list[str] = []
    for key, want in expected.items():
        if key not in actual:
            problems.append(f"{key} missing")
            continue
        got = actual[key]
        if isinstance(want, bool) or isinstance(got, bool):
            equal = want is got
        elif isinstance(want, int):
            # DD/Dum contract fields are integers: allow an exactly equal float
            # (JSON may surface 10.0) but no tolerance.
            equal = (
                isinstance(got, (int, float))
                and not isinstance(got, bool)
                and got == want
            )
        elif isinstance(want, (int, float)) and isinstance(got, (int, float)):
            equal = math.isclose(float(want), float(got), rel_tol=1e-12, abs_tol=1e-6)
        else:
            equal = want == got
        if not equal:
            problems.append(f"{key}: expected {want!r}, got {got!r}")
    return problems


def _is_error(output: Any) -> bool:
    return isinstance(output, Mapping) and set(output) == {"error"}


def evaluate(
    vector: Vector,
    outputs: Mapping[str, Sequence[Any]],
    implementations: Sequence[Implementation],
) -> EvaluatedVector:
    declared = set(vector.implementations)
    result = EvaluatedVector(vector=vector, cells={})
    for implementation in implementations:
        if not implementation.available:
            result.cells[implementation.name] = Cell(SKIP, implementation.skip_reason or "not available")
            continue
        gap = vector.capability_gaps.get(implementation.name)
        if implementation.name not in declared:
            result.cells[implementation.name] = Cell(
                SKIP, gap or "vector scoped to " + ", ".join(sorted(declared))
            )
            if gap:
                result.declared_gaps.append(implementation.name)
            continue
        observed = outputs.get(implementation.name)
        if observed is None:
            result.cells[implementation.name] = Cell(SKIP, "adapter returned no result")
            continue
        result.executed.append(implementation.name)
        divergence = vector.divergences.get(implementation.name)
        if divergence:
            result.diverged.append(implementation.name)
        cell = _evaluate_outputs(
            vector,
            observed,
            expected_override=divergence.get("expected") if divergence else None,
            error_override=divergence.get("expectedError") if divergence else None,
        )
        defect = vector.known_defects.get(implementation.name)
        if cell.verdict == FAIL and defect:
            cell.detail = f"{cell.detail} (known defect: {defect})"
            result.defects.append(implementation.name)
        result.cells[implementation.name] = cell
        if cell.verdict == FAIL:
            result.mismatches.append(f"{implementation.name}: {cell.detail}")
    return result


def _evaluate_outputs(
    vector: Vector,
    observed: Sequence[Any],
    *,
    expected_override: Sequence[Any] | None = None,
    error_override: str | None = None,
) -> Cell:
    if vector.function:
        entries = []
        for index, case in enumerate(vector.body["cases"]):
            copy = dict(case)
            if expected_override is not None:
                copy["expected"] = expected_override[index]
            entries.append(copy)
    else:
        entries = list(expected_override if expected_override is not None else vector.body.get("expected") or [])
    expected_error = error_override if error_override is not None else vector.expected_error
    expected_length = len(entries) if expected_error is None else len(vector.body["calls"])
    wants_post_state = bool(vector.body.get("postState"))
    if not vector.function and wants_post_state:
        expected_length += 1
    if len(observed) != expected_length:
        if wants_post_state and len(observed) == expected_length - 1:
            return Cell(FAIL, "post-state missing from adapter output")
        return Cell(FAIL, f"expected {expected_length} observations, adapter returned {len(observed)}")
    if expected_error:
        for index, output in enumerate(observed):
            if not _is_error(output):
                return Cell(
                    FAIL,
                    f"entry {index}: expected error {expected_error}, got {output!r}",
                )
            if output["error"] != expected_error:
                return Cell(
                    FAIL,
                    f"entry {index}: expected error {expected_error}, got {output['error']}",
                )
        return Cell(PASS)
    for index, (entry, output) in enumerate(zip(entries, observed)):
        if _is_error(output):
            return Cell(FAIL, f"entry {index}: unexpected error {output['error']}")
        if not isinstance(output, Mapping):
            return Cell(FAIL, f"entry {index}: adapter returned {output!r}")
        if vector.function:
            want = (
                entry["expected"]
                if isinstance(entry["expected"], Mapping)
                else {"value": entry["expected"]}
            )
        else:
            want = entry
        problems = _value_mismatches(want, output)
        if problems:
            return Cell(FAIL, f"entry {index}: " + "; ".join(problems))
    if wants_post_state:
        observed_state = observed[-1]
        if not isinstance(observed_state, Mapping) or POST_STATE not in observed_state:
            return Cell(FAIL, "post-state missing from adapter output")
        problems = _value_mismatches(vector.body["postState"], observed_state[POST_STATE])
        if problems:
            return Cell(FAIL, "post-state: " + "; ".join(problems))
    return Cell(PASS)


def contract_keys(vector: Vector) -> set[str]:
    """Return the fields a vector actually specifies."""

    if vector.function:
        keys: set[str] = set()
        for case in vector.body["cases"]:
            expected = case["expected"]
            keys.update(expected.keys() if isinstance(expected, Mapping) else {"value"})
        return keys
    keys = set()
    for entry in vector.body.get("expected") or []:
        keys.update(entry)
    return keys


def project(vector: Vector, outputs: Sequence[Any]) -> list[dict[str, Any]]:
    keys = contract_keys(vector)
    return [
        {key: output[key] for key in keys if isinstance(output, Mapping) and key in output}
        for output in outputs
    ]


def _projections_agree(
    left: Sequence[Mapping[str, Any]], right: Sequence[Mapping[str, Any]]
) -> bool:
    """Compare two contracted projections with the vector value rules."""

    if len(left) != len(right):
        return False
    for left_entry, right_entry in zip(left, right):
        if set(left_entry) != set(right_entry):
            return False
        if _value_mismatches(left_entry, right_entry) or _value_mismatches(
            right_entry, left_entry
        ):
            return False
    return True


def undeclared_disagreements(
    evaluated: EvaluatedVector, outputs: Mapping[str, Sequence[Any]]
) -> list[str]:
    """Return pairs of passed implementations whose contracted outputs differ."""

    names = [
        name
        for name in evaluated.executed
        if evaluated.cells[name].verdict == PASS and name not in evaluated.diverged
    ]
    problems: list[str] = []
    for position, left in enumerate(names):
        for right in names[position + 1 :]:
            if not _projections_agree(
                project(evaluated.vector, outputs[left]),
                project(evaluated.vector, outputs[right]),
            ):
                problems.append(f"{left} and {right} disagree without a declared divergence")
    return problems


# --- reporting ------------------------------------------------------------


def _column(value: str, width: int) -> str:
    if len(value) > width:
        value = value[: width - 1] + "…"
    return value.ljust(width)


def render_matrix(results: Sequence[EvaluatedVector], implementations: Sequence[Implementation]) -> str:
    widths = {item.name: max(14, len(item.label)) for item in implementations}
    header = _column("vector", 48) + _column("prov", 6)
    for item in implementations:
        header += _column(item.label, widths[item.name] + 2)
    header += "parity"
    lines = [header, "-" * len(header)]
    for result in results:
        row = _column(result.vector.id, 48) + _column(result.vector.provenance, 6)
        for item in implementations:
            cell = result.cells[item.name]
            text = cell.verdict
            if cell.verdict == FAIL and item.name in result.defects:
                text = "FAIL*"
            row += _column(text, widths[item.name] + 2)
        if result.verdict == FAIL:
            row += "no"
        elif result.declared_divergence:
            row += "declared"
        elif len(result.executed) > 1:
            row += "yes"
        elif result.executed:
            row += "n/a"
        else:
            row += "unproven"
        lines.append(row)
    lines.append("")
    for item in implementations:
        state = "available" if item.available else "skipped"
        version = f" {item.version}" if item.version else ""
        lines.append(f"  {item.name}: {item.label}{version} -> {state}")
        if item.skip_reason:
            lines.append(f"    reason: {item.skip_reason}")
        gaps = [
            result.vector.id for result in results if item.name in result.declared_gaps
        ]
        if gaps:
            lines.append(f"    declared capability gaps ({len(gaps)}):")
            for vector_id in gaps:
                lines.append(f"      {vector_id}: {gaps_detail(results, item.name, vector_id)}")
    return "\n".join(lines)


def gaps_detail(results: Sequence[EvaluatedVector], name: str, vector_id: str) -> str:
    for result in results:
        if result.vector.id == vector_id:
            return result.vector.capability_gaps.get(name, "")
    return ""


def summarize(
    results: Sequence[EvaluatedVector], implementations: Sequence[Implementation]
) -> dict[str, Any]:
    provenance: dict[str, int] = {}
    for result in results:
        provenance[result.vector.provenance] = provenance.get(result.vector.provenance, 0) + 1
    return {
        "vectors": len(results),
        "provenance": dict(sorted(provenance.items())),
        "failures": sorted(result.vector.id for result in results if result.verdict == FAIL),
        "known_defects": {
            result.vector.id: {
                name: result.vector.known_defects[name] for name in result.defects
            }
            for result in results
            if result.defects
        },
        "unproven": sorted(
            result.vector.id for result in results if len(result.executed) < 2
        ),
        "parity_vectors": sorted(
            result.vector.id
            for result in results
            if len(result.executed) > 1
            and not result.diverged
            and result.verdict == PASS
        ),
        "declared_divergences": {
            result.vector.id: sorted(result.diverged)
            for result in results
            if result.declared_divergence
        },
        "declared_gaps": {
            name: sorted(
                result.vector.id for result in results if name in result.declared_gaps
            )
            for name in IMPLEMENTATION_ORDER
        },
        "executed": {
            name: sorted(
                result.vector.id for result in results if name in result.executed
            )
            for name in IMPLEMENTATION_ORDER
        },
        "skipped": {
            item.name: item.skip_reason for item in implementations if not item.available
        },
    }


# --- command line ---------------------------------------------------------


def collect(
    implementations: Sequence[Implementation],
    vectors: Sequence[Vector],
) -> tuple[list[EvaluatedVector], dict[str, list[str]], dict[str, str]]:
    """Execute every available implementation and evaluate the corpus."""

    outputs: dict[str, dict[str, list[Any]]] = {}
    adapter_errors: dict[str, str] = {}
    for implementation in implementations:
        if not implementation.available:
            continue
        try:
            outputs[implementation.name] = implementation.run(vectors)  # type: ignore[misc]
        except Exception as exc:  # noqa: BLE001 - adapter failure is data, not a crash
            adapter_errors[implementation.name] = str(exc)

    results = [
        evaluate(
            vector,
            {name: values.get(vector.id, []) for name, values in outputs.items()},
            implementations,
        )
        for vector in vectors
    ]
    disagreements = {
        result.vector.id: undeclared_disagreements(
            result, {name: values.get(result.vector.id, []) for name, values in outputs.items()}
        )
        for result in results
    }
    return results, disagreements, adapter_errors


def run(
    implementations: Sequence[Implementation],
    vectors: Sequence[Vector],
    selected: Sequence[str] | None = None,
) -> int:
    """Run the corpus and print the matrix. Returns the process exit code."""

    if selected:
        implementations = [item for item in implementations if item.name in selected]
        if not implementations:
            print(f"unknown implementation selection: {list(selected)}", file=sys.stderr)
            return 2
    results, disagreements, adapter_errors = collect(implementations, vectors)

    print(render_matrix(results, implementations))
    print()
    summary = summarize(results, implementations)
    gap_count = sum(len(result.declared_gaps) for result in results)
    print(
        "vectors: {total} ({provenance}) | parity-proven: {parity} | unproven: {unproven} "
        "| declared gaps: {gaps} | declared divergences: {divergences} "
        "| known defects: {defects}".format(
            total=summary["vectors"],
            provenance=", ".join(f"[{key}] {value}" for key, value in summary["provenance"].items()),
            parity=len(summary["parity_vectors"]),
            unproven=len(summary["unproven"]),
            gaps=gap_count,
            divergences=sum(1 for result in results if result.declared_divergence),
            defects=sum(len(result.defects) for result in results),
        )
    )
    if summary["known_defects"]:
        print("\nknown defects (reported as failures, not waived):")
        for vector_id, entries in sorted(summary["known_defects"].items()):
            for name, reason in entries.items():
                print(f"  {vector_id} [{name}]: {reason}")
    if summary["unproven"]:
        print("\nunproven (fewer than two implementations executed):")
        for vector_id in summary["unproven"]:
            print(f"  {vector_id}")
    if summary["failures"]:
        print("\nfailed vectors:")
        for result in results:
            if result.verdict != FAIL:
                continue
            for problem in result.mismatches:
                print(f"  {result.vector.id}: {problem}")
    unexpected = {
        vector_id: problems
        for vector_id, problems in disagreements.items()
        if problems and vector_id not in summary["failures"]
    }
    if unexpected:
        print("\nundeclared divergences:")
        for vector_id, problems in sorted(unexpected.items()):
            for problem in problems:
                print(f"  {vector_id}: {problem}")
    if adapter_errors:
        print("\nadapter errors:")
        for name, detail in sorted(adapter_errors.items()):
            print(f"  {name}: {detail}")
    if summary["failures"] or unexpected or adapter_errors:
        return 1
    if not summary["parity_vectors"]:
        print(
            "\nNo vector executed on more than one implementation; cross-language "
            "parity is unproven."
        )
    return 0


def run_json(
    implementations: Sequence[Implementation],
    vectors: Sequence[Vector],
) -> int:
    """Emit the machine-readable summary. Returns the process exit code."""

    results, disagreements, adapter_errors = collect(implementations, vectors)
    summary = summarize(results, implementations)
    reported = {
        vector_id: problems
        for vector_id, problems in disagreements.items()
        if problems
    }
    summary["adapter_errors"] = adapter_errors
    summary["undeclared_disagreements"] = reported
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 1 if summary["failures"] or reported or adapter_errors else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--impl",
        action="append",
        choices=IMPLEMENTATION_ORDER,
        help="limit execution to this implementation (repeatable)",
    )
    parser.add_argument(
        "--vectors",
        type=Path,
        default=DEFAULT_VECTOR_DIR,
        help="vector directory (default: tools/gbs/vectors)",
    )
    parser.add_argument("--json", action="store_true", help="emit a machine-readable summary")
    arguments = parser.parse_args(argv)

    try:
        vectors = load_vectors(arguments.vectors)
    except VectorError as exc:
        print(f"vector corpus invalid: {exc}", file=sys.stderr)
        return 2
    implementations = detect_implementations()
    if arguments.impl:
        implementations = [
            item for item in implementations if item.name in set(arguments.impl)
        ]
        if not implementations:
            print(f"unknown implementation selection: {arguments.impl}", file=sys.stderr)
            return 2
    if arguments.json:
        return run_json(implementations, vectors)
    return run(implementations=implementations, vectors=vectors, selected=arguments.impl)


if __name__ == "__main__":
    raise SystemExit(main())
