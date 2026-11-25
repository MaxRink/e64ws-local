"""Reusable, evidence-labeled GBS calculations for local integrations.

This module contains the parts of E64 GBS that static analysis recovered well
enough to make executable. It does not claim cross-version or live-hardware
parity, but the V1 rolling median, cubic correction, hysteretic quantizer,
V2 regression blend/state, shared regression helper, V3/V4 state transitions,
DdEff sequence, and signed rounding below are instruction-confirmed for the
named firmware build.

The constants and formulas correspond to ``libNgxUi.so`` from
HEM-HSG-HMI-S01 ``V01.16-24``.  They are not guaranteed to match another
firmware revision. Stateful V2 exposes both a transparent host replay format
and the recovered canonical algorithm JSON object. Neither is a claim about
the still-unresolved SQLite BLOB/container encoding used around that object.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from math import ceil, floor, isfinite, isnan, trunc
from numbers import Real
from typing import Any, Iterable, Mapping, Sequence


GBS_FIRMWARE_BUILD = "HEM-HSG-HMI-S01 V01.16-24"
GBS_SAMPLE_LIMIT = 6
GBS_V1_ERROR_WINDOW = 0.5
GBS_V1_CENTER = 5.0
GBS_V1_CORRECTION_SCALE = 32768.0
GBS_V1_CORRECTION_OFFSET = 0.2
GBS_V1_CORRECTION_LIMIT = 5.0
GBS_V1_MIN_STATE = 1.0
GBS_V1_HISTORY_SIZE = 4
GBS_V1_MEDIAN_WIDTH = 2
GBS_V1_QUANTUM = 0.2
GBS_V1_HYSTERESIS_FACTOR = 0.8
GBS_V1_HYSTERESIS_BAND = GBS_V1_QUANTUM * GBS_V1_HYSTERESIS_FACTOR
GBS_V3_V4_DD_CHANGE_LIMIT = 500
GBS_LEARNING_ERROR_LIMIT_S = 3.0
GBS_V3_NEAR_THRESHOLD_S = 2.0
GBS_V3_FAR_THRESHOLD_S = 5.0
GBS_V3_MEDIUM_WIDTH_S = 3.0
GBS_V4_FAR_THRESHOLD_S = 5.0
GBS_V2_CURRENT_WEIGHT = 0.1
GBS_V2_PREDICTION_WEIGHT = 0.9
GBS_V3_V4_CURRENT_WEIGHT = 0.4
GBS_V3_V4_PREDICTION_WEIGHT = 0.6
GBS_OUTPUT_SCALE = 10.0
GBS_LINEAR_REGRESSION_VARIANCE_LIMIT = 0.001
GBS_LINEAR_REGRESSION_FALLBACK_SLOPE = -2.0
GBS_LINEAR_REGRESSION_SLOPE_MAX = -0.5

# Exact ``DialInWizardHelper::ModelType`` and roast-selection values recovered
# from the V01.16-24 ARM binary.  The enum is one-based; the roast selector is
# zero-based.  Values outside these maps take the firmware's warning/failure
# path and are intentionally not coerced by the host helpers.
MODEL_TYPE_ENUM_TO_NAME = {1: "e64", 2: "e65", 3: "e80"}
ROAST_DEGREE_INDEX_TO_NAME = {0: "light", 1: "medium", 2: "dark"}


@dataclass(frozen=True)
class DialInRow:
    """One decoded one-row dial-in table entry."""

    model: str
    roast: str
    coefficient: float
    offset: float
    threshold: float = float("inf")


DIAL_IN_ROWS: dict[tuple[str, str], DialInRow] = {
    ("e80", "dark"): DialInRow("e80", "dark", 6.0, 20.0),
    ("e80", "medium"): DialInRow("e80", "medium", 6.0, 0.0),
    ("e80", "light"): DialInRow("e80", "light", 6.0, -20.0),
    ("e65", "dark"): DialInRow("e65", "dark", 4.0, 20.0),
    ("e65", "medium"): DialInRow("e65", "medium", 4.0, 0.0),
    ("e65", "light"): DialInRow("e65", "light", 4.0, -20.0),
    ("e64", "dark"): DialInRow("e64", "dark", 3.5, 20.0),
    ("e64", "medium"): DialInRow("e64", "medium", 3.5, 0.0),
    ("e64", "light"): DialInRow("e64", "light", 3.5, -20.0),
}


def _finite(value: Real, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{name} must be a finite number")
    result = float(value)
    if not isfinite(result):
        raise ValueError(f"{name} must be a finite number")
    return result


def cxx_round(value: Real) -> int:
    """Return C/C++ ``round``/``lround`` behavior for finite inputs."""

    number = _finite(value, name="value")
    return floor(number + 0.5) if number >= 0.0 else ceil(number - 0.5)


@dataclass(frozen=True)
class MedianRecord:
    """One V1 ``MedianAverage<double>`` record: value plus sample age."""

    value: float
    age: int


class V1MedianAverage:
    """Output-equivalent normal-state V1 rolling median container."""

    def __init__(
        self,
        *,
        capacity: int = GBS_V1_HISTORY_SIZE,
        window_width: int = GBS_V1_MEDIAN_WIDTH,
    ) -> None:
        if capacity <= 0 or window_width <= 0 or window_width > capacity:
            raise ValueError("require capacity >= window_width > 0")
        self.capacity = capacity
        self.window_width = window_width
        self._records: list[MedianRecord] = []

    def append(self, value: Real) -> float:
        sample = _finite(value, name="value")
        if not self._records:
            self._records = [MedianRecord(sample, age) for age in range(self.capacity)]
        else:
            self._records = [
                MedianRecord(record.value, record.age + 1)
                for record in self._records
                if record.age != self.capacity - 1
            ]
            self._records.append(MedianRecord(sample, 0))
        self._records.sort(key=lambda record: record.value)
        return self.average()

    def average(self) -> float:
        if not self._records:
            raise ValueError("median history is empty")
        return v1_central_window_average(
            tuple(record.value for record in self._records),
            window_width=self.window_width,
        )

    def records(self) -> tuple[MedianRecord, ...]:
        return tuple(self._records)


def hysteretic_quantize(
    value: Real,
    previous: Real | None,
    *,
    quantum: Real = GBS_V1_QUANTUM,
    hysteresis_factor: Real = GBS_V1_HYSTERESIS_FACTOR,
) -> float:
    """Mirror ``HystereticQuantization::quantize`` at ELF ``0x44abcc``.

    Inclusive band boundaries retain the old value. Outside the band, or
    when the old value is NaN/unset, use C ``round(value/q) * q``.
    """

    current = _finite(value, name="value")
    q = _finite(quantum, name="quantum")
    factor = _finite(hysteresis_factor, name="hysteresis_factor")
    if q <= 0.0 or factor < 0.0:
        raise ValueError("quantum must be positive and hysteresis_factor non-negative")
    old = float("nan") if previous is None else float(previous)
    band = q * factor
    if isnan(old) or current < old - band or current > old + band:
        return cxx_round(current / q) * q
    return old


def v1_central_window_average(
    sorted_observations: Sequence[Real],
    *,
    window_width: int,
) -> float:
    """Return the recovered V1 central-window average.

    The firmware keeps observations ordered and computes ``available = N -
    (W - 1)``. It starts at zero when ``available < 2``; otherwise it starts
    at ``available // 2`` and averages exactly ``W`` entries. Repeated values
    are distinct samples. The firmware's malformed/underfilled-container behavior is
    not a useful host API, so this helper rejects ``N < W`` explicitly.
    """

    if (
        isinstance(window_width, bool)
        or not isinstance(window_width, int)
        or window_width <= 0
    ):
        raise ValueError("window_width must be a positive integer")
    values = tuple(
        _finite(value, name="sorted_observations item")
        for value in sorted_observations
    )
    if len(values) < window_width:
        raise ValueError("sorted_observations must contain at least window_width items")
    available = len(values) - (window_width - 1)
    start = 0 if available < 2 else available // 2
    end = start + window_width
    return sum(values[start:end]) / float(window_width)


def v1_adjust_from_history(
    sorted_observations: Sequence[Real],
    *,
    window_width: int,
    observation: Real,
    previous_state: Real,
    previous_output_tenths: int | None = None,
) -> V1Adjustment:
    """Run the recovered V1 window selection followed by its adjustment."""

    central = v1_central_window_average(
        sorted_observations,
        window_width=window_width,
    )
    return v1_adjust(
        central=central,
        observation=observation,
        previous_state=previous_state,
        previous_output_tenths=previous_output_tenths,
    )


def proposed_dd_from_weight(
    weight_mg: Real,
    *,
    model: str,
    roast: str,
) -> int:
    """Apply the decoded ``DialInWizardHelper`` one-row formula.

    The firmware ABI represents the input as a milligram quantity and uses
    ``trunc(offset + coefficient * weight_mg * 0.001 + 0.5)``. The
    ``model``/``roast`` arguments are the readable form of the exact firmware mapping:
    model enum ``1/2/3`` is E64/E65/E80 and roast index ``0/1/2`` is
    light/medium/dark.  Use :func:`proposed_dd_from_selection` when the
    caller has the original numeric selections.
    """

    weight = _finite(weight_mg, name="weight_mg")
    if weight < 0:
        raise ValueError("weight_mg must not be negative")
    key = (model.strip().lower(), roast.strip().lower())
    try:
        row = DIAL_IN_ROWS[key]
    except KeyError as exc:
        raise ValueError(f"no decoded dial-in row for {model!r}/{roast!r}") from exc
    return int(trunc(row.offset + row.coefficient * weight * 0.001 + 0.5))


def proposed_dd_from_selection(
    weight_mg: Real,
    *,
    model_enum: int,
    roast_degree_index: int,
) -> int:
    """Mirror the decoded helper's normal model/roast dispatch.

    ``ModelType::isValid`` accepts exactly enum values 1, 2, and 3.  The
    dial-in helper accepts roast indices 0, 1, and 2; its normal table rows
    are light, medium, and dark in that order.  The firmware rejects invalid
    selections through a warning/failure path, so this host function raises
    ``ValueError`` instead of silently selecting a neighboring row.
    """

    if (
        isinstance(model_enum, bool)
        or not isinstance(model_enum, int)
        or model_enum not in MODEL_TYPE_ENUM_TO_NAME
    ):
        raise ValueError("model_enum must be one of the firmware values 1, 2, 3")
    if (
        isinstance(roast_degree_index, bool)
        or not isinstance(roast_degree_index, int)
        or roast_degree_index not in ROAST_DEGREE_INDEX_TO_NAME
    ):
        raise ValueError("roast_degree_index must be one of the firmware values 0, 1, 2")
    return proposed_dd_from_weight(
        weight_mg,
        model=MODEL_TYPE_ENUM_TO_NAME[model_enum],
        roast=ROAST_DEGREE_INDEX_TO_NAME[roast_degree_index],
    )


def v1_correction(*, central: Real, observation: Real) -> float:
    """Return the exact decoded V1 nonlinear correction before clamping."""

    central_value = _finite(central, name="central")
    observation_value = _finite(observation, name="observation")
    denominator = (central_value - GBS_V1_CENTER) ** 3
    if denominator == 0:
        raise ValueError("V1 correction is singular at central=5.0")
    return -(
        (GBS_V1_CORRECTION_SCALE / denominator) + GBS_V1_CORRECTION_OFFSET
    ) * (observation_value - central_value)


@dataclass(frozen=True)
class V1Adjustment:
    central: float
    observation: float
    correction: float
    state: float
    output_tenths: int
    within_error_window: bool


def v1_adjust(
    *,
    central: Real,
    observation: Real,
    previous_state: Real,
    previous_output_tenths: int | None = None,
) -> V1Adjustment:
    """Apply recovered V1 correction/clamps for a caller-supplied central.

    ``central`` is the median actual brew time in seconds and ``observation``
    is the target brew time in seconds. The output uses the recovered 0.2-unit
    quantum and 0.16-unit inclusive hysteresis band.
    """

    central_value = _finite(central, name="central")
    observation_value = _finite(observation, name="observation")
    state = max(GBS_V1_MIN_STATE, _finite(previous_state, name="previous_state"))
    if previous_output_tenths is not None and (
        not isinstance(previous_output_tenths, int)
        or isinstance(previous_output_tenths, bool)
    ):
        raise ValueError("previous_output_tenths must be an integer")
    within_window = abs(central_value - observation_value) <= GBS_V1_ERROR_WINDOW
    if within_window:
        correction = 0.0
        output = (
            previous_output_tenths
            if previous_output_tenths is not None
            else cxx_round(state / GBS_V1_QUANTUM) * 2
        )
        return V1Adjustment(
            central_value,
            observation_value,
            correction,
            state,
            output,
            True,
        )
    correction = max(
        -GBS_V1_CORRECTION_LIMIT,
        min(GBS_V1_CORRECTION_LIMIT, v1_correction(central=central_value, observation=observation_value)),
    )
    state = max(GBS_V1_MIN_STATE, state + correction)
    previous_quantized = (
        None
        if previous_output_tenths is None
        else previous_output_tenths / GBS_OUTPUT_SCALE
    )
    quantized = hysteretic_quantize(state, previous_quantized)
    return V1Adjustment(
        central_value,
        observation_value,
        correction,
        state,
        cxx_round(quantized * GBS_OUTPUT_SCALE),
        False,
    )


@dataclass(frozen=True)
class SamplePoint:
    x: float
    y: float


class SampleHistory:
    """Six-point history boundary observed in V2/V3/V4 queue paths."""

    def __init__(self, points: Iterable[SamplePoint] = (), *, limit: int = GBS_SAMPLE_LIMIT) -> None:
        if limit <= 0:
            raise ValueError("history limit must be positive")
        self.limit = limit
        self._points: deque[SamplePoint] = deque(maxlen=limit)
        for point in points:
            self.append(point)

    def append(self, point: SamplePoint) -> None:
        self._points.append(
            SamplePoint(
                _finite(point.x, name="sample.x"),
                _finite(point.y, name="sample.y"),
            )
        )

    def __len__(self) -> int:
        return len(self._points)

    def __iter__(self):
        return iter(tuple(self._points))

    def as_tuple(self) -> tuple[SamplePoint, ...]:
        return tuple(self._points)

    def clear(self) -> None:
        self._points.clear()


def linear_regression_predict(points: Sequence[SamplePoint], x: Real) -> float:
    """Predict from ordinary least squares over the recovered sample shape.

    The firmware calls a ``LinearRegression::predict`` helper and retains at
    most six points.  This standard calculation is a reusable host-side
    implementation of that mathematical operation; coefficient fallback and
    any firmware-specific outlier handling remain unproven.
    """

    if not points:
        raise ValueError("at least one sample is required")
    x_value = _finite(x, name="x")
    validated_points = tuple(
        SamplePoint(
            _finite(point.x, name="sample.x"),
            _finite(point.y, name="sample.y"),
        )
        for point in points
    )
    if len(validated_points) == 1:
        return validated_points[0].y
    mean_x = sum(point.x for point in validated_points) / len(validated_points)
    mean_y = sum(point.y for point in validated_points) / len(validated_points)
    denominator = sum((point.x - mean_x) ** 2 for point in validated_points)
    if denominator == 0:
        return mean_y
    slope = sum(
        (point.x - mean_x) * (point.y - mean_y) for point in validated_points
    ) / denominator
    return mean_y + slope * (x_value - mean_x)


def firmware_linear_regression_predict(
    points: Sequence[SamplePoint],
    target_y: Real,
) -> float:
    """Reproduce the recovered ``Gbs::LinearRegression::predict`` orientation.

    The firmware stores each point as ``(predicted_coordinate, observed_y)``
    and receives the target observed ``y``. It returns the predicted first
    coordinate. For one point the decompilation uses a slope of ``-2.0``;
    for multiple points it computes the covariance/variance slope, falls back
    when variance is at most ``0.001``, and clamps slopes greater than
    ``-0.5`` to ``-0.5``. This is distinct from the generic OLS helper above.
    """

    if not points:
        raise ValueError("at least one sample is required")
    target = _finite(target_y, name="target_y")
    validated = tuple(
        SamplePoint(
            _finite(point.x, name="sample.x"),
            _finite(point.y, name="sample.y"),
        )
        for point in points
    )
    mean_x = sum(point.x for point in validated) / len(validated)
    mean_y_delta = sum(point.y - target for point in validated) / len(validated)
    if len(validated) == 1:
        slope = GBS_LINEAR_REGRESSION_FALLBACK_SLOPE
        return mean_x - mean_y_delta / slope
    variance = sum((point.x - mean_x) ** 2 for point in validated)
    if variance <= GBS_LINEAR_REGRESSION_VARIANCE_LIMIT:
        slope = GBS_LINEAR_REGRESSION_FALLBACK_SLOPE
    else:
        covariance = sum(
            (point.x - mean_x) * ((point.y - target) - mean_y_delta)
            for point in validated
        )
        slope = covariance / variance
        if slope > GBS_LINEAR_REGRESSION_SLOPE_MAX:
            slope = GBS_LINEAR_REGRESSION_SLOPE_MAX
    return mean_x - mean_y_delta / slope


def blend_v2(current: Real, prediction: Real) -> float:
    """Apply V2's bounded same-sign or explicit weighted blend.

    For ordinary finite values both firmware branches have the same algebra.
    The same-strict-sign branch additionally bounds the interpolation to the
    closed interval between its endpoints, while zero/opposite-sign inputs
    use the explicit weighted sum.
    """

    current_value = _finite(current, name="current")
    prediction_value = _finite(prediction, name="prediction")
    blended = current_value + (prediction_value - current_value) * GBS_V2_PREDICTION_WEIGHT
    if current_value * prediction_value > 0.0:
        return max(
            min(blended, max(current_value, prediction_value)),
            min(current_value, prediction_value),
        )
    return 0.1 * current_value + 0.9 * prediction_value


def blend_v3_v4(current: Real, prediction: Real) -> float:
    """Apply the decoded V3/V4 40% current / 60% prediction blend."""

    current_value = _finite(current, name="current")
    prediction_value = _finite(prediction, name="prediction")
    return current_value + (prediction_value - current_value) * GBS_V3_V4_PREDICTION_WEIGHT


def output_tenths(value: Real) -> int:
    """Scale a continuous DD estimate by ten using C ``lround`` semantics."""

    return cxx_round(_finite(value, name="value") * GBS_OUTPUT_SCALE)


def dd_eff_measurement_sequence(initial_dd_dum: int, calls: int = 18) -> tuple[int, ...]:
    """Return the call-driven DdEff coroutine sequence for ``calls`` steps.

    The recovered actor yields the initial DD six times, then initial-200 six
    times, then initial+200 six times, repeating. Its five brew-adjustment
    arguments are ignored by the firmware; this helper exposes only the
    observable sequence and performs no device I/O.
    """

    if isinstance(initial_dd_dum, bool) or not isinstance(initial_dd_dum, int):
        raise ValueError("initial_dd_dum must be an integer")
    if isinstance(calls, bool) or not isinstance(calls, int) or calls < 0:
        raise ValueError("calls must be a non-negative integer")
    offsets = (0, -200, 200)
    return tuple(
        initial_dd_dum + offsets[(index // 6) % len(offsets)]
        for index in range(calls)
    )


@dataclass(frozen=True)
class GbsStateResult:
    """One observable result from the reusable V2/V3/V4 state models."""

    phase: str
    candidate_dum: int
    returned_dum: int
    committed: bool
    locked: bool = False


@dataclass
class GbsV2State:
    """Reusable state for the recovered V2 six-point inverse regression.

    ``last_result_dum`` is the commit-gated output. ``to_json`` and
    ``from_json`` use a transparent host replay format. ``to_vendor_json``
    emits the canonical V01.16-24 algorithm JSON key shape recovered from the
    serializer; it is not the surrounding SQLite BLOB/container format.
    """

    history: SampleHistory = field(default_factory=SampleHistory)
    last_result_dum: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "history": [
                {"x": point.x, "y": point.y}
                for point in self.history
            ],
            "lastResultDum": self.last_result_dum,
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "GbsV2State":
        if not isinstance(value, Mapping):
            raise ValueError("V2 state must be an object")
        raw_history = value.get("history", [])
        if not isinstance(raw_history, list):
            raise ValueError("V2 history must be a list")
        if len(raw_history) > GBS_SAMPLE_LIMIT:
            raise ValueError("V2 host history must contain at most six points")
        points: list[SamplePoint] = []
        for raw_point in raw_history:
            if not isinstance(raw_point, Mapping):
                raise ValueError("V2 history points must be objects")
            points.append(
                SamplePoint(
                    _finite(raw_point.get("x"), name="V2 point.x"),
                    _finite(raw_point.get("y"), name="V2 point.y"),
                )
            )
        raw_last = value.get("lastResultDum")
        if raw_last is not None and (
            isinstance(raw_last, bool) or not isinstance(raw_last, int)
        ):
            raise ValueError("V2 lastResultDum must be an integer or null")
        return cls(history=SampleHistory(points), last_result_dum=raw_last)

    def to_vendor_json(self) -> dict[str, Any]:
        """Emit the recovered canonical V2 algorithm-state JSON object.

        The exact key spellings and field set are static serializer evidence
        for ``V01.16-24``. The normal V2 serializer emits ``type``, ``version``
        and ``history``; it does not emit the adjacent
        ``lastResultInDeciMicroMeter`` literal. This method deliberately does
        not encode a database BLOB or claim malformed-input parity with Qt.
        """

        result: dict[str, Any] = {
            "type": "GbS2",
            "version": 1,
            "history": [
                {
                    "effectiveGrindSizeUm": point.x,
                    "brewDurationSec": point.y,
                }
                for point in self.history
            ],
        }
        return result

    @classmethod
    def from_vendor_json(cls, value: Mapping[str, Any]) -> "GbsV2State":
        """Read the supported canonical subset emitted by ``to_vendor_json``.

        The firmware's behavior for malformed, overlong, non-finite, and
        non-canonical JSON is intentionally outside this host API. Rejecting
        those inputs is a host safety policy, not a reconstructed Qt failure
        mode.
        """

        if not isinstance(value, Mapping):
            raise ValueError("vendor V2 state must be an object")
        if value.get("type") != "GbS2":
            raise ValueError("vendor V2 state type must be 'GbS2'")
        version = value.get("version")
        if isinstance(version, bool) or version != 1:
            raise ValueError("vendor V2 state version must be 1")
        raw_history = value.get("history")
        if not isinstance(raw_history, list):
            raise ValueError("vendor V2 history must be a list")
        if len(raw_history) > GBS_SAMPLE_LIMIT:
            raise ValueError("vendor V2 history must contain at most six points")
        points: list[SamplePoint] = []
        for raw_point in raw_history:
            if not isinstance(raw_point, Mapping):
                raise ValueError("vendor V2 history points must be objects")
            points.append(
                SamplePoint(
                    _finite(
                        raw_point.get("effectiveGrindSizeUm"),
                        name="effectiveGrindSizeUm",
                    ),
                    _finite(
                        raw_point.get("brewDurationSec"),
                        name="brewDurationSec",
                    ),
                )
            )
        return cls(history=SampleHistory(points))

    def reset(self) -> None:
        self.history.clear()
        self.last_result_dum = None


def gbs_v2_adjust(
    state: GbsV2State,
    *,
    actual_ms: int,
    target_ms: int,
    estimated_dd_dum: int,
    setpoint_dd_dum: int,
    tolerance_ms: int,
) -> GbsStateResult:
    """Execute V2's recovered stateful normal-input transition."""

    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in (
            actual_ms,
            target_ms,
            estimated_dd_dum,
            setpoint_dd_dum,
            tolerance_ms,
        )
    ):
        raise ValueError("V2 millisecond, DD, and tolerance values must be integers")
    state.history.append(
        SamplePoint(setpoint_dd_dum * 0.1, actual_ms * 0.001)
    )
    prediction_um = firmware_linear_regression_predict(
        state.history.as_tuple(), target_ms * 0.001
    )
    candidate_dum = output_tenths(
        blend_v2(setpoint_dd_dum * 0.1, prediction_um)
    )
    if state.last_result_dum is None:
        state.last_result_dum = estimated_dd_dum
    if abs(actual_ms - target_ms) < abs(tolerance_ms):
        return GbsStateResult(
            "regression", candidate_dum, state.last_result_dum, False
        )
    state.last_result_dum = candidate_dum
    return GbsStateResult("regression", candidate_dum, candidate_dum, True)


@dataclass
class GbsV3State:
    history: SampleHistory = field(default_factory=SampleHistory)
    far_factor: float = 0.0
    mid_factor: float = 0.5
    near_factor: float = 1.0
    filter_retention: float = 0.5
    hold_cycles_setting: int = 2
    hold_cycles_remaining: int = 2
    last_target_dum: int | None = None
    last_adjustment_dum: int | None = None
    filtered_dd_times_brew: float | None = None
    near_threshold_s: float = GBS_V3_NEAR_THRESHOLD_S
    keep_medium_interval_width: bool = False

    def to_vendor_json(self) -> dict[str, Any]:
        """Emit the recovered native ``GbS3`` JSON field set.

        This is a schema-level host implementation for the named firmware
        build. It deliberately emits no SQLite wrapper and omits optional
        fields whose native engagement flags are clear.
        """

        result: dict[str, Any] = {
            "type": "GbS3",
            "version": 2,
            "history": [
                {
                    "effectiveGrindSizeUm": point.x,
                    "brewDurationSec": point.y,
                }
                for point in self.history
            ],
            "farFactor": _finite(self.far_factor, name="far_factor"),
            "midFactor": _finite(self.mid_factor, name="mid_factor"),
            "nearFactor": _finite(self.near_factor, name="near_factor"),
            "ddTimesBrewFilter": _finite(
                self.filter_retention, name="filter_retention"
            ),
            "nearPhaseHoldCyclesSetting": self.hold_cycles_setting,
            "nearPhaseHoldCyclesRemaining": self.hold_cycles_remaining,
            "thresBrewDurationErrorNearSec": _finite(
                self.near_threshold_s, name="near_threshold_s"
            ),
            "keepMediumIntervalWidth": self.keep_medium_interval_width,
        }
        if self.filtered_dd_times_brew is not None:
            result["filteredDdTimesBrew"] = _finite(
                self.filtered_dd_times_brew, name="filtered_dd_times_brew"
            )
        if self.last_adjustment_dum is not None:
            result["lastAdjustmentInDeciMicroMeters"] = self.last_adjustment_dum
        if self.last_target_dum is not None:
            result["lastTargetDdInDeciMicroMeters"] = self.last_target_dum
        return result

    @classmethod
    def from_vendor_json(cls, value: Mapping[str, Any]) -> "GbsV3State":
        """Read a conservative finite subset of the native ``GbS3`` schema."""

        if not isinstance(value, Mapping) or value.get("type") != "GbS3":
            raise ValueError("vendor V3 state type must be 'GbS3'")
        if isinstance(value.get("version"), bool) or value.get("version") != 2:
            raise ValueError("vendor V3 state version must be 2")
        raw_history = value.get("history")
        if not isinstance(raw_history, list) or len(raw_history) > GBS_SAMPLE_LIMIT:
            raise ValueError("vendor V3 history must contain at most six points")
        points: list[SamplePoint] = []
        for raw_point in raw_history:
            if not isinstance(raw_point, Mapping):
                raise ValueError("vendor V3 history points must be objects")
            points.append(
                SamplePoint(
                    _finite(raw_point.get("effectiveGrindSizeUm"), name="effectiveGrindSizeUm"),
                    _finite(raw_point.get("brewDurationSec"), name="brewDurationSec"),
                )
            )

        def required_int(name: str) -> int:
            raw = value.get(name)
            if isinstance(raw, bool) or not isinstance(raw, int):
                raise ValueError(f"vendor V3 {name} must be an integer")
            return raw

        raw_keep = value.get("keepMediumIntervalWidth")
        if not isinstance(raw_keep, bool):
            raise ValueError("vendor V3 keepMediumIntervalWidth must be boolean")
        raw_filtered = value.get("filteredDdTimesBrew")
        raw_last_adjustment = value.get("lastAdjustmentInDeciMicroMeters")
        raw_last_target = value.get("lastTargetDdInDeciMicroMeters")
        for name, raw in (
            ("lastAdjustmentInDeciMicroMeters", raw_last_adjustment),
            ("lastTargetDdInDeciMicroMeters", raw_last_target),
        ):
            if raw is not None and (isinstance(raw, bool) or not isinstance(raw, int)):
                raise ValueError(f"vendor V3 {name} must be an integer when present")
        return cls(
            history=SampleHistory(points),
            far_factor=_finite(value.get("farFactor"), name="farFactor"),
            mid_factor=_finite(value.get("midFactor"), name="midFactor"),
            near_factor=_finite(value.get("nearFactor"), name="nearFactor"),
            filter_retention=_finite(
                value.get("ddTimesBrewFilter"), name="ddTimesBrewFilter"
            ),
            hold_cycles_setting=required_int("nearPhaseHoldCyclesSetting"),
            hold_cycles_remaining=required_int("nearPhaseHoldCyclesRemaining"),
            last_target_dum=raw_last_target,
            last_adjustment_dum=raw_last_adjustment,
            filtered_dd_times_brew=(
                None
                if raw_filtered is None
                else _finite(raw_filtered, name="filteredDdTimesBrew")
            ),
            near_threshold_s=_finite(
                value.get("thresBrewDurationErrorNearSec"),
                name="thresBrewDurationErrorNearSec",
            ),
            keep_medium_interval_width=raw_keep,
        )


@dataclass
class GbsV4State:
    history: SampleHistory = field(default_factory=SampleHistory)
    far_factor: float = 0.0
    mid_factor: float = 0.5
    near_factor: float = 1.0
    filter_retention: float = 0.5
    hold_cycles_setting: int = 2
    hold_cycles_remaining: int = 2
    last_target_dum: int | None = None
    last_adjustment_dum: int | None = None
    filtered_dd_times_brew: float | None = None

    def to_vendor_json(self) -> dict[str, Any]:
        """Emit the recovered native ``GbS4`` JSON field set."""

        result: dict[str, Any] = {
            "type": "GbS4",
            "version": 2,
            "history": [
                {
                    "effectiveGrindSizeUm": point.x,
                    "brewDurationSec": point.y,
                }
                for point in self.history
            ],
            "nearPhaseHoldCyclesRemaining": self.hold_cycles_remaining,
        }
        if self.filtered_dd_times_brew is not None:
            result["filteredDdTimesBrew"] = _finite(
                self.filtered_dd_times_brew, name="filtered_dd_times_brew"
            )
        if self.last_target_dum is not None:
            result["lastTargetDdInDeciMicroMeters"] = self.last_target_dum
        if self.last_adjustment_dum is not None:
            result["lastAdjustmentInDeciMicroMeters"] = self.last_adjustment_dum
        return result

    @classmethod
    def from_vendor_json(cls, value: Mapping[str, Any]) -> "GbsV4State":
        """Read a conservative finite subset of the native ``GbS4`` schema."""

        if not isinstance(value, Mapping) or value.get("type") != "GbS4":
            raise ValueError("vendor V4 state type must be 'GbS4'")
        if isinstance(value.get("version"), bool) or value.get("version") != 2:
            raise ValueError("vendor V4 state version must be 2")
        raw_history = value.get("history")
        if not isinstance(raw_history, list) or len(raw_history) > GBS_SAMPLE_LIMIT:
            raise ValueError("vendor V4 history must contain at most six points")
        points: list[SamplePoint] = []
        for raw_point in raw_history:
            if not isinstance(raw_point, Mapping):
                raise ValueError("vendor V4 history points must be objects")
            points.append(
                SamplePoint(
                    _finite(raw_point.get("effectiveGrindSizeUm"), name="effectiveGrindSizeUm"),
                    _finite(raw_point.get("brewDurationSec"), name="brewDurationSec"),
                )
            )
        raw_remaining = value.get("nearPhaseHoldCyclesRemaining")
        if isinstance(raw_remaining, bool) or not isinstance(raw_remaining, int):
            raise ValueError("vendor V4 nearPhaseHoldCyclesRemaining must be an integer")
        raw_last_adjustment = value.get("lastAdjustmentInDeciMicroMeters")
        raw_last_target = value.get("lastTargetDdInDeciMicroMeters")
        for name, raw in (
            ("lastAdjustmentInDeciMicroMeters", raw_last_adjustment),
            ("lastTargetDdInDeciMicroMeters", raw_last_target),
        ):
            if raw is not None and (isinstance(raw, bool) or not isinstance(raw, int)):
                raise ValueError(f"vendor V4 {name} must be an integer when present")
        raw_filtered = value.get("filteredDdTimesBrew")
        return cls(
            history=SampleHistory(points),
            hold_cycles_remaining=raw_remaining,
            last_target_dum=raw_last_target,
            last_adjustment_dum=raw_last_adjustment,
            filtered_dd_times_brew=(
                None
                if raw_filtered is None
                else _finite(raw_filtered, name="filteredDdTimesBrew")
            ),
        )


@dataclass
class DdEffState:
    """Persistent host view of the native DdEff initial value.

    The vendor serializer persists only ``initialCoarsenessDum``. The
    coroutine phase is service state and intentionally restarts at phase zero
    after restoration in this conservative host model.
    """

    initial_coarseness_dum: int
    calls: int = 0

    def next(self) -> int:
        value = dd_eff_measurement_sequence(self.initial_coarseness_dum, self.calls + 1)[-1]
        self.calls += 1
        return value

    def to_vendor_json(self) -> dict[str, Any]:
        if isinstance(self.initial_coarseness_dum, bool) or not isinstance(
            self.initial_coarseness_dum, int
        ):
            raise ValueError("initial_coarseness_dum must be an integer")
        return {
            "type": "DdEff",
            "version": 1,
            "initialCoarsenessDum": self.initial_coarseness_dum,
        }

    @classmethod
    def from_vendor_json(cls, value: Mapping[str, Any]) -> "DdEffState":
        if not isinstance(value, Mapping) or value.get("type") != "DdEff":
            raise ValueError("vendor DdEff state type must be 'DdEff'")
        if isinstance(value.get("version"), bool) or value.get("version") != 1:
            raise ValueError("vendor DdEff state version must be 1")
        initial = value.get("initialCoarsenessDum")
        if isinstance(initial, bool) or not isinstance(initial, int):
            raise ValueError("initialCoarsenessDum must be an integer")
        return cls(initial_coarseness_dum=initial)


def v3_far_threshold(state: GbsV3State) -> float:
    """Return V3's exact configurable far threshold."""

    near = _finite(state.near_threshold_s, name="near_threshold_s")
    return (
        near + GBS_V3_MEDIUM_WIDTH_S
        if state.keep_medium_interval_width
        else GBS_V3_FAR_THRESHOLD_S
    )


def _v3_v4_calculate(
    state: GbsV3State | GbsV4State,
    *,
    phase: str,
    actual_ms: int,
    target_ms: int,
    estimated_dd_dum: int,
    setpoint_dd_dum: int,
) -> int:
    actual_s = actual_ms * 0.001
    target_s = target_ms * 0.001
    estimated_um = estimated_dd_dum * 0.1
    setpoint_um = setpoint_dd_dum * 0.1
    if phase != "far":
        state.history.append(SamplePoint(setpoint_um, actual_s))

    effective = estimated_um * actual_s
    retention = _finite(state.filter_retention, name="filter_retention")
    if state.filtered_dd_times_brew is None:
        state.filtered_dd_times_brew = effective
    else:
        old = state.filtered_dd_times_brew
        state.filtered_dd_times_brew = effective + retention * (old - effective)
    hyperbolic = state.filtered_dd_times_brew / target_s

    if len(state.history) < 2:
        linear = hyperbolic
    else:
        predicted = firmware_linear_regression_predict(
            state.history.as_tuple(), target_s
        )
        linear = blend_v3_v4(setpoint_um, predicted)
    factor = {
        "far": state.far_factor,
        "mid": state.mid_factor,
        "near": state.near_factor,
    }[phase]
    result_um = hyperbolic + (linear - hyperbolic) * _finite(
        factor, name=f"{phase}_factor"
    )
    return output_tenths(result_um)


def _commit_state_result(
    state: GbsV3State | GbsV4State,
    *,
    phase: str,
    candidate_dum: int,
    actual_ms: int,
    target_ms: int,
    estimated_dd_dum: int,
    tolerance_ms: int,
) -> GbsStateResult:
    if state.last_target_dum is None:
        state.last_target_dum = estimated_dd_dum
    if state.last_adjustment_dum is None:
        state.last_adjustment_dum = estimated_dd_dum
    if abs(actual_ms - target_ms) < abs(tolerance_ms):
        return GbsStateResult(
            phase, candidate_dum, state.last_adjustment_dum, False
        )
    state.last_target_dum = estimated_dd_dum
    state.last_adjustment_dum = candidate_dum
    return GbsStateResult(phase, candidate_dum, candidate_dum, True)


def gbs_v3_adjust(
    state: GbsV3State,
    *,
    actual_ms: int,
    target_ms: int,
    estimated_dd_dum: int,
    setpoint_dd_dum: int,
    tolerance_ms: int,
) -> GbsStateResult:
    """Execute V3's recovered normal finite-input state transition."""

    if (
        state.last_target_dum is not None
        and state.last_adjustment_dum is not None
        and abs(estimated_dd_dum - state.last_target_dum)
        > GBS_V3_V4_DD_CHANGE_LIMIT
    ):
        state.last_target_dum = estimated_dd_dum
        return GbsStateResult(
            "cancel", state.last_adjustment_dum, state.last_adjustment_dum, False, True
        )
    error_s = abs(actual_ms - target_ms) * 0.001
    if error_s <= state.near_threshold_s and len(state.history) > 2:
        phase = "near"
        state.hold_cycles_remaining = state.hold_cycles_setting
    elif state.hold_cycles_remaining > 0:
        state.hold_cycles_remaining -= 1
        phase = "near"
    elif error_s <= v3_far_threshold(state):
        phase = "mid"
    else:
        phase = "far"
        state.history.clear()
    candidate = _v3_v4_calculate(
        state,
        phase=phase,
        actual_ms=actual_ms,
        target_ms=target_ms,
        estimated_dd_dum=estimated_dd_dum,
        setpoint_dd_dum=setpoint_dd_dum,
    )
    return _commit_state_result(
        state,
        phase=phase,
        candidate_dum=candidate,
        actual_ms=actual_ms,
        target_ms=target_ms,
        estimated_dd_dum=estimated_dd_dum,
        tolerance_ms=tolerance_ms,
    )


def gbs_v4_adjust(
    state: GbsV4State,
    *,
    actual_ms: int,
    target_ms: int,
    estimated_dd_dum: int,
    setpoint_dd_dum: int,
    tolerance_ms: int,
) -> GbsStateResult:
    """Execute V4's recovered normal finite-input state transition."""

    if (
        state.last_target_dum is not None
        and state.last_adjustment_dum is not None
        and abs(estimated_dd_dum - state.last_target_dum)
        > GBS_V3_V4_DD_CHANGE_LIMIT
    ):
        state.last_target_dum = estimated_dd_dum
        return GbsStateResult(
            "cancel", state.last_adjustment_dum, state.last_adjustment_dum, False, True
        )
    error_s = abs(actual_ms - target_ms) * 0.001
    if error_s < GBS_LEARNING_ERROR_LIMIT_S and len(state.history) > 2:
        state.last_target_dum = estimated_dd_dum
        if state.last_adjustment_dum is None:
            raise RuntimeError("firmware would throw bad_optional_access")
        return GbsStateResult(
            "near", state.last_adjustment_dum, state.last_adjustment_dum, False, True
        )
    if state.hold_cycles_remaining > 0:
        state.hold_cycles_remaining -= 1
        phase = "near"
    elif error_s <= GBS_V4_FAR_THRESHOLD_S:
        phase = "mid"
    else:
        phase = "far"
        state.history.clear()
    candidate = _v3_v4_calculate(
        state,
        phase=phase,
        actual_ms=actual_ms,
        target_ms=target_ms,
        estimated_dd_dum=estimated_dd_dum,
        setpoint_dd_dum=setpoint_dd_dum,
    )
    return _commit_state_result(
        state,
        phase=phase,
        candidate_dum=candidate,
        actual_ms=actual_ms,
        target_ms=target_ms,
        estimated_dd_dum=estimated_dd_dum,
        tolerance_ms=tolerance_ms,
    )


def should_commit_adjustment(error: Real, threshold: Real) -> bool:
    """Return the recovered absolute-error commit condition."""

    threshold_value = _finite(threshold, name="threshold")
    if threshold_value < 0:
        raise ValueError("threshold must not be negative")
    return abs(_finite(error, name="error")) >= threshold_value


def dd_change_requires_history_reset(previous_dd: int, current_dd: int) -> bool:
    """Return the V3/V4 branch condition ``abs(change) > 500``."""

    if isinstance(previous_dd, bool) or isinstance(current_dd, bool):
        raise ValueError("DD values must be integers")
    if not isinstance(previous_dd, int) or not isinstance(current_dd, int):
        raise ValueError("DD values must be integers")
    return abs(current_dd - previous_dd) > GBS_V3_V4_DD_CHANGE_LIMIT


def learning_error_is_near(error_s: Real) -> bool:
    """Return V4's fixed near guard ``abs(error) < 3.0``.

    V3 instead uses its configurable near threshold and an inclusive
    comparison; see the Track C report.
    """

    return abs(_finite(error_s, name="error_s")) < GBS_LEARNING_ERROR_LIMIT_S


__all__ = [
    "DIAL_IN_ROWS",
    "GBS_FIRMWARE_BUILD",
    "GBS_LEARNING_ERROR_LIMIT_S",
    "GBS_LINEAR_REGRESSION_FALLBACK_SLOPE",
    "GBS_LINEAR_REGRESSION_SLOPE_MAX",
    "GBS_LINEAR_REGRESSION_VARIANCE_LIMIT",
    "GBS_OUTPUT_SCALE",
    "GBS_SAMPLE_LIMIT",
    "GBS_V1_CENTER",
    "GBS_V1_CORRECTION_LIMIT",
    "GBS_V1_CORRECTION_OFFSET",
    "GBS_V1_CORRECTION_SCALE",
    "GBS_V1_ERROR_WINDOW",
    "GBS_V1_HYSTERESIS_BAND",
    "GBS_V1_HYSTERESIS_FACTOR",
    "GBS_V1_HISTORY_SIZE",
    "GBS_V1_MEDIAN_WIDTH",
    "GBS_V1_MIN_STATE",
    "GBS_V1_QUANTUM",
    "GBS_V3_FAR_THRESHOLD_S",
    "GBS_V3_MEDIUM_WIDTH_S",
    "GBS_V3_NEAR_THRESHOLD_S",
    "GBS_V4_FAR_THRESHOLD_S",
    "DialInRow",
    "DdEffState",
    "GbsStateResult",
    "GbsV2State",
    "GbsV3State",
    "GbsV4State",
    "MedianRecord",
    "SampleHistory",
    "SamplePoint",
    "V1Adjustment",
    "V1MedianAverage",
    "blend_v2",
    "blend_v3_v4",
    "cxx_round",
    "dd_change_requires_history_reset",
    "dd_eff_measurement_sequence",
    "learning_error_is_near",
    "linear_regression_predict",
    "firmware_linear_regression_predict",
    "gbs_v2_adjust",
    "gbs_v3_adjust",
    "gbs_v4_adjust",
    "hysteretic_quantize",
    "output_tenths",
    "proposed_dd_from_weight",
    "should_commit_adjustment",
    "v1_adjust",
    "v1_correction",
    "v3_far_threshold",
]
