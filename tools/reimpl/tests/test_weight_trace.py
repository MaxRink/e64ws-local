"""Tests for captured weight-trace replay."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from harness import Harness, free_port  # noqa: F401  (sys.path setup)
from e64ctl.main import Service, ServiceConfig
from e64ctl.state import DeviceState, GRIND_RUNNING
from e64ctl.weight_trace import (apply_capture_snapshot,
                                 load_capture_snapshot, load_capture_trace,
                                 trace_summary)


class TraceReplayTests(unittest.TestCase):
    def test_interpolates_captured_points(self) -> None:
        state = DeviceState(clock=lambda: 100.0)
        state.grind.weight_trace = [(0.0, 0.0), (1.0, 10.0), (2.0, 18.0)]
        state.grind.state = GRIND_RUNNING
        state.grind.started_at = 100.0
        state.grind.start_delay_s = 0.0
        state._advance_grind(100.5)
        self.assertEqual(state.grind.current_weight_gr, 5.0)
        state._advance_grind(101.5)
        self.assertEqual(state.grind.current_weight_gr, 14.0)
        state._advance_grind(110.0)
        self.assertEqual(state.grind.current_weight_gr, 18.0)

    def test_replays_a_normalized_capture_to_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            rows = [
                {"t": 0, "state": {"grindState": "Idle", "grindCurrentWeightGr": 486.0}},
                {"t": 1, "state": {"grindState": "Grind", "grindStartWeightGr": 486.0,
                                   "grindCurrentWeightGr": 486.0}},
                {"t": 2, "state": {"grindState": "Grind", "grindStartWeightGr": 486.0,
                                   "grindCurrentWeightGr": 495.0}},
                {"t": 3, "state": {"grindState": "Grind", "grindStartWeightGr": 486.0,
                                   "grindCurrentWeightGr": 504.0}},
                {"t": 4, "state": {"grindState": "Idle", "grindCurrentWeightGr": -0.5}},
            ]
            with open(path, "w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row) + "\n")
            state = DeviceState(clock=lambda: 100.0)
            state.grind.weight_trace = load_capture_trace(path)
            state.grind.start_delay_s = 0.0
            state.start_grind("gbw", 18.0)
            state._advance_grind(101.0)
            state._advance_grind(102.0)
            self.assertEqual(state.grind.state, "Done")
            self.assertAlmostEqual(state.grind.result_weight_gr, 18.0)

    def test_finish_uses_the_trace_result(self) -> None:
        state = DeviceState(clock=lambda: 100.0)
        state.grind.weight_trace = [(0.0, -0.5), (1.0, 10.0), (2.0, 18.0)]
        state.grind.state = GRIND_RUNNING
        state.grind.started_at = 100.0
        state.grind.start_delay_s = 0.0
        state.grind.start_weight_gr = -0.5
        state.grind.target_weight_gr = 18.0
        state._advance_grind(102.0)
        state.grind.stopped_at = 102.0
        state._finish_grind("test")
        self.assertEqual(state.grind.result_weight_gr, 18.5)
        self.assertEqual(state.grind.final_weight_gr, 18.0)


class ServiceProfileTests(unittest.TestCase):
    def test_service_applies_live_profile_and_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps({"t": 0.0, "state": {
                    "ddValueDum": 817, "ntc1TempDegC": 34.3,
                    "fan1TachoRpm": 0, "grindCurrentWeightGr": -0.5,
                    "setupWizardState": "Completed"}}) + "\n")
                handle.write(json.dumps({"t": 1.0, "state": {
                    "ddValueDum": 817, "grindCurrentWeightGr": 18.0}}) + "\n")
            config = ServiceConfig(state_dir=tmp, wss_port=free_port(),
                                   http_port=free_port(), dev_mode=False,
                                   live_profile=True, weight_trace=path)
            service = Service(config)
            try:
                self.assertEqual(service.state.machine.grinder_type, 5)
                self.assertEqual(service.state.setup_wizard_state, "Completed")
                self.assertEqual(service.state.agsa.dd_value, 817)
                self.assertAlmostEqual(service.state.thermal.ntc1_temp_degc, 34.3)
                self.assertEqual(service.state.fans[0].tacho_rpm, 0)
                self.assertEqual(len(service.state.grind.weight_trace), 2)
            finally:
                service.stop()


class CaptureWindowTests(unittest.TestCase):
    def test_trims_portafilter_and_rebases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            rows = [
                {"t": 0, "state": {"grindState": "Idle", "grindCurrentWeightGr": 486.0}},
                {"t": 1, "state": {"grindState": "Grind", "grindStartWeightGr": 486.0,
                                   "grindCurrentWeightGr": 486.0}},
                {"t": 2, "state": {"grindState": "Grind", "grindStartWeightGr": 486.0,
                                   "grindCurrentWeightGr": 495.0}},
                {"t": 3, "state": {"grindState": "GbwPostGrind",
                                   "grindStartWeightGr": 486.0,
                                   "grindCurrentWeightGr": 504.0}},
                {"t": 4, "state": {"grindState": "Idle", "grindCurrentWeightGr": -0.5}},
                {"t": 5, "state": {"grindState": "Idle", "grindCurrentWeightGr": 601.0}},
            ]
            with open(path, "w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row) + "\n")
            self.assertEqual(
                load_capture_trace(path, baseline_gr=-0.5),
                [(0.0, -0.5), (1.0, 8.5), (2.0, 17.5)],
            )
            self.assertEqual(
                load_capture_trace(path),
                [(0.0, 0.0), (1.0, 9.0), (2.0, 18.0)],
            )

    def test_first_grind_weight_is_the_fallback_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            rows = [
                {"t": 0, "state": {"grindState": "Idle", "grindCurrentWeightGr": 10.0}},
                {"t": 1, "state": {"grindState": "Grind", "grindCurrentWeightGr": 10.0}},
                {"t": 2, "state": {"grindState": "Grind", "grindCurrentWeightGr": 20.0}},
                {"t": 3, "state": {"grindState": "GbwPostGrind",
                                   "grindCurrentWeightGr": 28.0}},
            ]
            with open(path, "w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row) + "\n")
            self.assertEqual(load_capture_trace(path), [(0.0, 0.0), (1.0, 10.0), (2.0, 18.0)])


class CaptureSnapshotTests(unittest.TestCase):
    def test_loads_the_first_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps({"t": 0.0, "state": {"ddValueDum": 900}}) + "\n")
                handle.write(json.dumps({"t": 1.0, "state": {"ddValueDum": 1}}) + "\n")
            self.assertEqual(load_capture_snapshot(path)["ddValueDum"], 900)

    def test_applies_safe_device_fields(self) -> None:
        state = DeviceState()
        applied = apply_capture_snapshot(state, {
            "ddValueDum": 817,
            "ddSensorFailed": False,
            "agsaStatus": "Normal",
            "ntc1TempDegC": 34.3,
            "hasNtc1": False,
            "ntc1Failed": False,
            "ntc2TempDegC": -999,
            "ntc2Failed": True,
            "cpuTempDegC": -88.5,
            "cpuTempFailed": False,
            "fan1TachoRpm": 1200,
            "fan1Duty": 3,
            "overshootWeightGr": 0.519351,
            "configId": 7,
            "setupWizardState": "Completed",
        })
        self.assertGreaterEqual(applied, 13)
        self.assertEqual(state.agsa.dd_value, 817)
        self.assertEqual(state.agsa.status, "Normal")
        self.assertFalse(state.agsa.sensor_failed)
        self.assertAlmostEqual(state.thermal.ntc1_temp_degc, 34.3)
        self.assertFalse(state.thermal.ntc1_failed)
        self.assertTrue(state.thermal.ntc2_failed)
        self.assertEqual(state.thermal.ntc2_temp_degc, -999)
        self.assertAlmostEqual(state.thermal.cpu_temp_degc, -88.5)
        self.assertFalse(state.thermal.cpu_temp_failed)
        self.assertEqual(state.fans[0].tacho_rpm, 1200)
        self.assertEqual(state.fans[0].duty, 3)
        self.assertAlmostEqual(state.grind.overshoot_weight_gr, 0.519351)
        self.assertEqual(state.config_id, 7)
        self.assertEqual(state.setup_wizard_state, "Completed")

    def test_strings_are_not_accepted_as_numbers(self) -> None:
        state = DeviceState()
        self.assertEqual(apply_capture_snapshot(state, {"ddValueDum": "817"}), 0)


class CaptureLoaderTests(unittest.TestCase):
    def test_loads_and_dedupes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                for row in (
                    {"t": 0.0, "state": {"grindCurrentWeightGr": 0.0}},
                    {"t": 1.0, "state": {"grindCurrentWeightGr": 10.0}},
                    {"t": 1.0, "state": {"grindCurrentWeightGr": 11.0}},
                    {"t": 2.0, "state": {}},
                ):
                    handle.write(json.dumps(row) + "\n")
            trace = load_capture_trace(path)
            self.assertEqual(trace, [(0.0, 0.0), (1.0, 11.0)])
            self.assertEqual(trace_summary(trace)["max_weight_gr"], 11.0)
            self.assertEqual(trace_summary(trace)["points"], 2)

    def test_empty_capture_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.jsonl")
            open(path, "w", encoding="utf-8").close()
            with self.assertRaises(ValueError):
                load_capture_trace(path)


if __name__ == "__main__":
    unittest.main()
