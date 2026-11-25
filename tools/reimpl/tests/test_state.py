"""State model tests: grind FSM, AGSA, fans, endurance, ESP liveness."""
from __future__ import annotations

import unittest

from harness import Harness  # noqa: F401  (sys.path setup)
from e64ctl.state import DeviceState, GRIND_DONE, GRIND_IDLE, GRIND_RUNNING


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class GrindTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.state = DeviceState(clock=self.clock)

    def test_gbw_reaches_target(self) -> None:
        ok, _ = self.state.start_grind("gbw", target_weight_gr=5.0)
        self.assertTrue(ok)
        self.assertEqual(self.state.grind.state, "Starting")
        self.clock.advance(0.2)
        self.state.tick()
        self.assertEqual(self.state.grind.state, GRIND_RUNNING)
        self.clock.advance(3.0)
        self.state.tick()
        self.assertEqual(self.state.grind.state, GRIND_DONE)
        self.assertGreaterEqual(self.state.grind.result_weight_gr, 5.0)
        self.assertFalse(self.state.grind.failure)

    def test_gbt_stops_on_time(self) -> None:
        self.state.start_grind("gbt", target_time_s=1.0)
        self.clock.advance(0.2)
        self.state.tick()
        self.clock.advance(1.4)
        self.state.tick()
        self.assertEqual(self.state.grind.state, GRIND_DONE)

    def test_stop(self) -> None:
        self.state.start_grind("manual")
        self.clock.advance(0.3)
        self.state.tick()
        self.assertTrue(self.state.stop_grind("test"))
        self.assertEqual(self.state.grind.state, GRIND_DONE)
        self.assertFalse(self.state.stop_grind("again"))

    def test_double_start_rejected(self) -> None:
        self.assertTrue(self.state.start_grind("manual")[0])
        self.assertFalse(self.state.start_grind("gbw", 3.0)[0])

    def test_max_run_time_failure(self) -> None:
        self.state.driver_config["motorMaxRunTimeMs"] = 500
        self.state.start_grind("manual")
        self.clock.advance(0.2)
        self.state.tick()
        self.clock.advance(0.6)
        self.state.tick()
        self.assertTrue(self.state.grind.failure)

    def test_overheat_blocks_start(self) -> None:
        self.state.thermal.overheat_ntc1 = True
        self.assertFalse(self.state.start_grind("manual")[0])

    def test_esp_dead_blocks_start(self) -> None:
        self.state.esp.alive = False
        self.assertFalse(self.state.start_grind("manual")[0])


class DriverStateTests(unittest.TestCase):
    def test_field_set(self) -> None:
        state = DeviceState(clock=Clock())
        data = state.driver_state_json()
        expected = {
            "sessionId", "configId", "grindState", "grindFailure",
            "grindCurrentWeightGr", "grindResultWeightGr", "grindStartWeightGr",
            "grindFinalWeightGr", "grindTargetWeightGr", "motorRunTimeMs",
            "overshootWeightGr", "cpuTempFailed", "cpuTempDegC", "hasNtc1",
            "ntc1Failed", "ntc1TempDegC", "ntc2Failed", "ntc2TempDegC",
            "overheatNtc1", "overheatNtc2", "hmiTime", "hmiProdDate",
            "fanTemperatureCtrlEnabled", "fan1Duty", "fan2Duty",
            "fan1TachoRpm", "fan2TachoRpm", "fan1Failed", "fan2Failed",
            "ddValueDum", "agsaHallSensorCounts", "ddSensorAngle",
            "ddSensorFailed", "agsaStatus", "shiftCompensationFailed",
            "espUartFailed", "espSdioState", "espFuseFailed", "espAlive",
            "espVersionNo", "espUpdateRequired", "enduranceTestCycle",
            "enduranceTestState", "enduranceTestStartTime",
            "enduranceTestDuration", "language", "setupWizardState",
            "grinderType",
        }
        self.assertEqual(set(data), expected)
        self.assertEqual(data["grindState"], GRIND_IDLE)
        self.assertEqual(data["espSdioState"], 2)
        # Values/types from the vendor capture
        # (tools/virtual-grinder/docs/evidence/wss-driver-state.json).
        self.assertEqual(data["grindFailure"], "None")
        self.assertEqual(data["configId"], 1)
        self.assertIsInstance(data["sessionId"], str)
        self.assertEqual(data["enduranceTestDuration"], "00h:00m:00s")
        self.assertEqual(data["language"], "en_US")
        self.assertEqual(data["setupWizardState"], "NotRun")

    def test_machine_info(self) -> None:
        state = DeviceState(clock=Clock())
        data = state.machine_info_json()
        self.assertEqual(set(data), {"sessionId", "grinderType"})
        self.assertEqual(data["grinderType"], "E64 WS")


class FanTests(unittest.TestCase):
    def test_clamp(self) -> None:
        state = DeviceState(clock=Clock())
        state.set_fan_duty(0, 250)
        self.assertEqual(state.fans[0].duty, 100)
        state.set_fan_duty(0, -5)
        self.assertEqual(state.fans[0].duty, 0)
        self.assertFalse(state.fans[0].power_enabled)
        state.set_fan_duty(1, 40)
        self.assertEqual(state.fans[1].duty, 40)
        self.assertTrue(state.fans[1].power_enabled)
        self.assertGreater(state.fans[1].tacho_rpm, 0)


class AgsaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.state = DeviceState(clock=self.clock)
        # A commissioned machine has a configured DD sensor.
        self.state.agsa.sensor_configured = True
        self.state.agsa.sensor_failed = False
        self.state.agsa.status = "Idle"

    def test_move_reaches_target(self) -> None:
        ok, _ = self.state.set_agsa_target(2.0)
        self.assertTrue(ok)
        self.assertEqual(self.state.agsa.status, "Moving")
        # timeout formula: 10000 + |d/20|*1000*1.5
        self.assertEqual(self.state.agsa.timeout_ms, 10150)
        self.clock.advance(0.2)
        self.state.tick()
        self.clock.advance(1.2)
        self.state.tick()
        self.assertEqual(self.state.agsa.status, "Idle")
        self.assertAlmostEqual(self.state.agsa.dd_value, 2.0, places=2)

    def test_timeout(self) -> None:
        self.state.agsa.speed_dd_per_s = 0.0
        self.state.set_agsa_target(5.0)
        self.assertEqual(self.state.agsa.timeout_ms, 10000)
        self.clock.advance(10.5)
        self.state.tick()
        self.assertEqual(self.state.agsa.status, "Fault")

    def test_unconfigured_sensor(self) -> None:
        self.state.agsa.sensor_configured = False
        ok, reason = self.state.set_agsa_target(1.0)
        self.assertFalse(ok)
        self.assertIn("sensor type not selected", reason)

    def test_stop_agsa(self) -> None:
        self.state.set_agsa_target(3.0)
        self.assertTrue(self.state.stop_agsa())
        self.assertFalse(self.state.stop_agsa())


class EnduranceTests(unittest.TestCase):
    def test_cycle_accounting(self) -> None:
        clock = Clock()
        state = DeviceState(clock=clock)
        self.assertTrue(state.start_endurance(2, 1))
        clock.advance(7)
        state.tick()
        self.assertEqual(state.endurance.cycle, 2)
        self.assertEqual(state.endurance.duration, 7)
        self.assertTrue(state.stop_endurance())
        self.assertEqual(state.endurance.state, "Stopped")


class EspLivenessTests(unittest.TestCase):
    def test_three_missed_heartbeats(self) -> None:
        clock = Clock()
        state = DeviceState(clock=clock)
        self.assertTrue(state.esp.alive)
        clock.advance(3.5)
        state.tick()
        self.assertFalse(state.esp.alive)
        self.assertTrue(state.esp.uart_failed)
        state.esp_heartbeat(1)
        self.assertTrue(state.esp.alive)


if __name__ == "__main__":
    unittest.main()
