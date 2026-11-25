"""Parity against the recorded vendor response.

`tools/virtual-grinder/docs/evidence/wss-driver-state.json` in the research
repository is a real `RequestDriverState` reply captured from the vendor HMI.
This test pins the field set, types, key order, and Qt JSON layout to it.
"""
from __future__ import annotations

import json
import os
import unittest

from harness import Harness  # noqa: F401  (sys.path setup)
from e64ctl import jsonfmt
from e64ctl.state import DeviceState

CAPTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data",
    "wss-driver-state.json")

#: Types observed in the vendor capture (bool is checked before int).
EXPECTED_TYPES = {
    "agsaHallSensorCounts": int,
    "agsaStatus": str,
    "configId": int,
    "cpuTempDegC": (int, float),
    "cpuTempFailed": bool,
    "ddSensorAngle": (int, float),
    "ddSensorFailed": bool,
    "ddValueDum": (int, float),
    "enduranceTestCycle": int,
    "enduranceTestDuration": str,
    "enduranceTestStartTime": str,
    "enduranceTestState": str,
    "espAlive": bool,
    "espFuseFailed": bool,
    "espSdioState": int,
    "espUartFailed": bool,
    "espUpdateRequired": bool,
    "espVersionNo": str,
    "fan1Duty": int,
    "fan1Failed": bool,
    "fan1TachoRpm": int,
    "fan2Duty": int,
    "fan2Failed": bool,
    "fan2TachoRpm": int,
    "fanTemperatureCtrlEnabled": bool,
    "grindCurrentWeightGr": (int, float),
    "grindFailure": str,
    "grindFinalWeightGr": (int, float),
    "grindResultWeightGr": (int, float),
    "grindStartWeightGr": (int, float),
    "grindState": str,
    "grindTargetWeightGr": (int, float),
    "grinderType": str,
    "hasNtc1": bool,
    "hmiProdDate": str,
    "hmiTime": str,
    "language": str,
    "motorRunTimeMs": (int, float),
    "ntc1Failed": bool,
    "ntc1TempDegC": (int, float),
    "ntc2Failed": bool,
    "ntc2TempDegC": (int, float),
    "overheatNtc1": bool,
    "overheatNtc2": bool,
    "overshootWeightGr": (int, float),
    "sessionId": str,
    "setupWizardState": str,
    "shiftCompensationFailed": bool,
}


class CaptureParityTests(unittest.TestCase):
    def setUp(self) -> None:
        with open(CAPTURE, "r", encoding="utf-8") as handle:
            self.capture = json.load(handle)["reply"]

    def test_field_set_and_types(self) -> None:
        data = DeviceState().driver_state_json()
        self.assertEqual(set(data), set(EXPECTED_TYPES))
        self.assertEqual(set(data), set(self.capture["data"]))
        for key, expected in EXPECTED_TYPES.items():
            with self.subTest(key=key):
                self.assertIsInstance(data[key], expected, key)

    def test_static_values(self) -> None:
        data = DeviceState().driver_state_json()
        self.assertEqual(data["grindFailure"], self.capture["data"]["grindFailure"])
        self.assertEqual(data["grinderType"], self.capture["data"]["grinderType"])
        self.assertEqual(data["language"], self.capture["data"]["language"])
        self.assertEqual(data["setupWizardState"],
                         self.capture["data"]["setupWizardState"])
        self.assertEqual(data["espVersionNo"], self.capture["data"]["espVersionNo"])

    def test_key_order_matches_qt(self) -> None:
        envelope = {"type": "RequestDriverStateResult", "refId": 1,
                    "data": DeviceState().driver_state_json()}
        text = jsonfmt.dumps(envelope)
        top, nested = [], []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith('"') or ":" not in stripped:
                continue
            key = stripped.split(":", 1)[0].strip('"')
            if line.startswith('    "') and not line.startswith('        "'):
                top.append(key)
            elif line.startswith('        "'):
                nested.append(key)
        self.assertEqual(top, ["data", "refId", "type"])
        self.assertEqual(nested, sorted(nested))
        self.assertEqual(nested, sorted(self.capture["data"]))


if __name__ == "__main__":
    unittest.main()
