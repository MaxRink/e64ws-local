"""Tests for the evidence-linked HSG assumptions and sensor simulator."""
from __future__ import annotations

import unittest

from harness import Harness  # noqa: F401  (sys.path setup)
from e64ctl.assumptions import (
    ASSUMPTIONS,
    apply_dd_pwm,
    apply_hsg_profile,
    assumptions_json,
    calibrate_fan,
    pwm_duty_to_angle_millideg,
    raw_to_grams,
    touch_supported,
)
from e64ctl.state import DeviceState


class AssumptionLedgerTests(unittest.TestCase):
    def test_every_row_has_evidence_and_a_simulator_rule(self):
        self.assertGreaterEqual(len(ASSUMPTIONS), 10)
        ids = {a.id for a in ASSUMPTIONS}
        for required in ("HSG-01", "HSG-02", "HSG-04", "HSG-05", "HSG-07", "HSG-11"):
            self.assertIn(required, ids)
        for item in ASSUMPTIONS:
            self.assertTrue(item.source)
            self.assertIn(item.confidence, ("high", "medium", "low"))
            self.assertTrue(item.simulator)

    def test_json_shape(self):
        rows = assumptions_json()
        self.assertEqual(rows[0]["id"], "HSG-01")
        self.assertEqual(set(rows[0]), {"id", "claim", "source", "confidence", "simulator"})


class HsgProfileTests(unittest.TestCase):
    def test_ntc2_is_explicitly_failed(self):
        state = DeviceState()
        apply_hsg_profile(state)
        self.assertTrue(state.thermal.ntc2_failed)
        self.assertEqual(state.thermal.ntc2_temp_degc, -999)
        self.assertFalse(state.thermal.overheat_ntc2)

    def test_locked_dd_store_and_calibration(self):
        state = DeviceState()
        apply_hsg_profile(state, calibrated=True)
        self.assertEqual(state.agsa.dd_value, 12000.0)
        self.assertEqual(state.agsa.dd_angle, 0.0)
        self.assertEqual(state.agsa.status, "Normal")
        self.assertFalse(state.agsa.sensor_failed)

    def test_uncalibrated_profile_keeps_safe_gate(self):
        state = DeviceState()
        apply_hsg_profile(state, calibrated=False)
        self.assertEqual(state.agsa.status, "Disc calibration missing")
        self.assertTrue(state.agsa.sensor_failed)

    def test_fan_calibration_publishes_no_rpm(self):
        state = DeviceState()
        result = calibrate_fan(state, fan=0, duty=40)
        self.assertTrue(result["success"])
        self.assertEqual(state.fans[0].duty, 40)
        self.assertEqual(state.fans[0].tacho_rpm, 0)
        self.assertEqual(state.fans[0].failed, False)
        self.assertIn("does not publish", result["note"])

    def test_fan_argument_validation(self):
        state = DeviceState()
        with self.assertRaises(ValueError):
            calibrate_fan(state, fan=2)

    def test_load_cell_conversion(self):
        self.assertAlmostEqual(raw_to_grams(0), 2974.494926, places=5)
        self.assertAlmostEqual(raw_to_grams(1000), 2883.078892, places=4)

    def test_pwm_angle_hypothesis_is_flagged(self):
        self.assertEqual(pwm_duty_to_angle_millideg(0), 0)
        self.assertEqual(pwm_duty_to_angle_millideg(25), 90000)
        self.assertEqual(pwm_duty_to_angle_millideg(100), 360000)
        with self.assertRaises(ValueError):
            pwm_duty_to_angle_millideg(101)
        state = DeviceState()
        result = apply_dd_pwm(state, 25)
        self.assertTrue(result["assumed"])
        self.assertEqual(result["ddSensorAngle"], 90000)
        self.assertEqual(state.agsa.dd_angle, 90000.0)
        self.assertFalse(state.agsa.sensor_failed)

    def test_touch_is_not_claimed(self):
        self.assertFalse(touch_supported())


if __name__ == "__main__":
    unittest.main()
