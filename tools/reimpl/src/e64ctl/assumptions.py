"""Evidence-linked assumptions for the HSG (E64 WS) profile.

The control service models the protocol and state machine.  This module records
the *hardware-profile* assumptions that came out of the decompilation, and
applies the ones that affect a simulated driver state.  Each row names the
vendor artifact/function it came from and how the simulator should behave when
the assumption is not proven.

The rule is: an assumption may simplify a fixture, but it must never turn an
unobserved hardware path into a fabricated success.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .state import DeviceState


@dataclass(frozen=True)
class Assumption:
    id: str
    claim: str
    source: str
    confidence: str
    simulator: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "claim": self.claim,
            "source": self.source,
            "confidence": self.confidence,
            "simulator": self.simulator,
        }


ASSUMPTIONS: tuple[Assumption, ...] = (
    Assumption(
        "HSG-01",
        "The E64 WS (HSG) profile configures one NTC circuit; the second NtcDriver is NG2-only.",
        "NgxUiApp/functions/0001d358_main.c:1731-1756 (decompiled main)",
        "high",
        "ntc2Failed=true, ntc2TempDegC=-999; no NTC2 success is fabricated.",
    ),
    Assumption(
        "HSG-02",
        "HSG DD uses the PWM/A1330 path plus the locked DD store, not the DddAnalog ADC channel.",
        "NgxUiApp main.c:1205-1303 (PwmCaptureDriver), :3019-3024 (A1330 chip type); db/lockedDdStore.json",
        "medium",
        "ddValueDum comes from the locked store; ddSensorAngle stays 0 until an A1330 model is supplied.",
    ),
    Assumption(
        "HSG-03",
        "The DddAnalogVoltageIn object is created but never opened by this profile.",
        "NgxUiApp main.c:1680-1730; /proc/<NgxUiApp>/fd observation and hw.log",
        "high",
        "A DddAnalog fixture may exist but is not treated as a valid sensor.",
    ),
    Assumption(
        "HSG-04",
        "Fan calibration can complete, but RequestDriverState.fan1TachoRpm reads the FanManager's null driver and stays 0.",
        "docs/VIRTUAL_HARDWARE_GAPS.md G8; FanManager ctor signature and calibration capture",
        "high",
        "CalibrateFan1/2 sets duty and reports success; tacho_rpm remains 0.",
    ),
    Assumption(
        "HSG-05",
        "The vendor userland has no touch driver; pointer input is emulation-only.",
        "docs/VM_INPUT_AND_CALIBRATION.md; QML input contract",
        "high",
        "The simulator rejects touch as unsupported; keys/rotary remain available.",
    ),
    Assumption(
        "HSG-06",
        "The load-cell raw value maps through C0 + C1*raw, with C0=2974.494926 and C1=-0.091416034.",
        "docs/GbW/GBS notes and the vendor config capture; HMI 0 g at rest",
        "high",
        "A raw ADC fixture is converted to grams for the driver state.",
    ),
    Assumption(
        "HSG-07",
        "Only eight WSS commands are always-on; grind/GBS actions are dev=1.",
        "docs/API_REGISTRY.md; live stock AddBrewEvent close",
        "high",
        "Stock simulator rejects dev-only actions; --dev-mode enables them.",
    ),
    Assumption(
        "HSG-08",
        "AddBrewEvent is dev-only and returns success in development mode.",
        "API_REGISTRY.md; live QEMU AddBrewEvent success true",
        "high",
        "Development-mode simulator accepts the event; stock mode closes/rejects.",
    ),
    Assumption(
        "HSG-09",
        "NTC1 is valid at the 25 C fixture point and NTC2 is not populated on HSG.",
        "docs/VIRTUAL_HARDWARE_GAPS.md G5/G6; main.c NTC branch",
        "high",
        "ntc1TempDegC=25.0, ntc1Failed=false; ntc2Failed=true.",
    ),
    Assumption(
        "HSG-10",
        "CalibrateDdSensor brings agsaStatus to Normal and ddSensorFailed=false on the locked-store profile.",
        "docs/VM_INPUT_AND_CALIBRATION.md; CalibrateDdSensor live result",
        "high",
        "apply_hsg_profile(calibrated=True) sets that state.",
    ),
    Assumption(
        "HSG-11",
        "The A1330 PWM duty-to-angle scale is not recovered; a linear 0..100 % -> 0..360000 millideg model is a simulator hypothesis only.",
        "docs/VIRTUAL_HARDWARE_GAPS.md G7; AllegroA1330Driver::processPwmDutyCycle (0x1c0ee4) and setSensorAngleMilliDeg (0x1c0e80)",
        "low",
        "apply_dd_pwm() can drive ddSensorAngle for GBS experiments, explicitly flagged as hypothetical.",
    ),
)


def assumptions_json() -> list[dict[str, str]]:
    return [item.as_dict() for item in ASSUMPTIONS]


def apply_hsg_profile(state: DeviceState, *, calibrated: bool = True) -> None:
    """Apply only the assumptions the HSG profile actually supports.

    NTC2 is explicitly failed; the DD value comes from the locked store.  The
    fan tacho is left at 0 because the vendor does not publish it even when
    calibration succeeds.
    """
    state.thermal.ntc2_failed = True
    state.thermal.ntc2_temp_degc = -999.0
    state.thermal.overheat_ntc2 = False
    state.agsa.dd_value = 12000.0
    state.agsa.dd_angle = 0.0
    if calibrated:
        state.agsa.status = "Normal"
        state.agsa.sensor_failed = False
    else:
        state.agsa.status = "Disc calibration missing"
        state.agsa.sensor_failed = True
    state.fans[0].tacho_rpm = 0
    state.fans[1].tacho_rpm = 0


def calibrate_fan(state: DeviceState, fan: int = 0, duty: int = 40) -> dict[str, Any]:
    """Model the vendor calibration result: duty changes, RPM publication does not."""
    if fan not in (0, 1):
        raise ValueError("fan must be 0 or 1")
    state.fans[fan].duty = max(0, min(100, duty))
    state.fans[fan].calibrating = False
    state.fans[fan].failed = False
    return {
        "success": True,
        "fan": fan + 1,
        "duty": state.fans[fan].duty,
        "tachoRpm": state.fans[fan].tacho_rpm,
        "note": "calibration-only; FanManager does not publish RPM",
    }


def raw_to_grams(raw: float, *, c0: float = 2974.494926,
                 c1: float = -0.091416034) -> float:
    """Vendor load-cell conversion (HSG config capture).

    The defaults are the documented fixture capture.  The 2026-11-18 live unit
    reported different coefficients (``LIVE_LOAD_CELL``), so callers must pass
    the per-device values when they have them.
    """
    return c0 + (c1 * raw)


#: Per-device coefficients observed in the live 2026-11-18 RequestDriverConfig.
LIVE_LOAD_CELL: dict[str, float] = {
    "c0": 2393.920401128173,
    "c1": -0.07834534628643058,
}


def pwm_duty_to_angle_millideg(duty_percent: float) -> int:
    """Simulator hypothesis for the missing A1330 PWM angle scale.

    The decompiled vendor path clamps the PWM duty and calls
    ``setSensorAngleMilliDeg``, but the exact scale was not recovered.  This is
    deliberately a low-confidence linear model (100 % = one revolution), not a
    claim about the hardware.  Callers must treat the result as hypothetical.
    """
    if duty_percent < 0 or duty_percent > 100:
        raise ValueError("duty_percent must be in 0..100")
    return int(round((duty_percent / 100.0) * 360000.0))


def apply_dd_pwm(state: DeviceState, duty_percent: float) -> dict[str, Any]:
    """Apply the hypothetical A1330 PWM model to a simulator state."""
    angle = pwm_duty_to_angle_millideg(duty_percent)
    state.agsa.dd_angle = float(angle)
    state.agsa.sensor_failed = False
    return {
        "assumed": True,
        "dutyPercent": duty_percent,
        "ddSensorAngle": angle,
        "note": "HSG-11 linear hypothesis; not the recovered vendor scale",
    }


def touch_supported() -> bool:
    return False


__all__ = [
    "ASSUMPTIONS",
    "Assumption",
    "LIVE_LOAD_CELL",
    "apply_hsg_profile",
    "assumptions_json",
    "calibrate_fan",
    "pwm_duty_to_angle_millideg",
    "apply_dd_pwm",
    "raw_to_grams",
    "touch_supported",
]


if __name__ == "__main__":
    import json

    print(json.dumps(assumptions_json(), indent=2, sort_keys=True))
