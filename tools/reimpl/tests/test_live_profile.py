"""Tests for the sanitized 2026-11-18 live HSG profile."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from harness import Harness  # noqa: F401  (sys.path setup)
from e64ctl.assumptions import LIVE_LOAD_CELL, raw_to_grams
from e64ctl.live_profile import (
    LIVE_DB_SETTINGS,
    LIVE_DERIVED,
    REDACTED_SETTING_KEYS,
    apply_live_hsg_profile,
    seed_live_settings,
)
from e64ctl.persistence import (
    GRIND_CSV_COLUMNS,
    Persistence,
)
from e64ctl.state import DeviceState


class LiveProfileShapeTests(unittest.TestCase):
    def test_observed_key_set_and_values(self):
        self.assertEqual(len(LIVE_DB_SETTINGS), 27)
        self.assertEqual(LIVE_DB_SETTINGS["Version"], "31")
        self.assertEqual(LIVE_DB_SETTINGS["Role.Owner.LoginData"], "")
        self.assertEqual(LIVE_DB_SETTINGS["Grinding.OvershootWeight"], "536960")
        self.assertEqual(LIVE_DB_SETTINGS["Standby.ActivationTimeSec"], "600")
        self.assertEqual(LIVE_DB_SETTINGS["Wifi.Mode"], "2")
        self.assertEqual(LIVE_DB_SETTINGS["System.SetupWizard.State"], "Completed")
        self.assertEqual(LIVE_DB_SETTINGS["timezoneId"], "Europe/Berlin")

    def test_credentials_are_not_retained(self):
        for key in REDACTED_SETTING_KEYS:
            self.assertEqual(LIVE_DB_SETTINGS[key], "")
        blob = " ".join(LIVE_DB_SETTINGS).lower()
        for marker in ("stheinternet", "192.168.", "serial", "mac"):
            self.assertNotIn(marker, blob)

    def test_derived_values(self):
        self.assertAlmostEqual(LIVE_DERIVED["overshootWeightGr"], 0.53696)
        self.assertEqual(LIVE_DERIVED["standbyActivationSec"], 600)
        self.assertEqual(LIVE_DERIVED["activeRecipeIndex"], 2)
        self.assertAlmostEqual(LIVE_DERIVED["idleWeightGr"], -0.52)

    def test_live_load_cell_coefficients(self):
        grams = raw_to_grams(1000, c0=LIVE_LOAD_CELL["c0"],
                             c1=LIVE_LOAD_CELL["c1"])
        self.assertAlmostEqual(grams, 2315.5750548417425)
        self.assertNotAlmostEqual(
            grams, raw_to_grams(1000), places=3,
            msg="live coefficients must differ from the fixture constants")

    def test_profile_matches_committed_evidence(self):
        evidence = (Path(__file__).resolve().parents[3] / "docs" / "evidence" /
                    "live-2026-11-18" / "database.json")
        values = json.loads(evidence.read_text())["settings"]["values"]
        self.assertEqual(values, LIVE_DB_SETTINGS)


class LiveProfileStateTests(unittest.TestCase):
    def test_apply_sets_used_device_state_and_config(self):
        state = DeviceState()
        apply_live_hsg_profile(state)
        self.assertEqual(state.language, "en_US")
        self.assertEqual(state.setup_wizard_state, "Completed")
        self.assertAlmostEqual(state.grind.overshoot_weight_gr, 0.53696)
        self.assertAlmostEqual(state.grind.current_weight_gr, -0.52)
        self.assertEqual(state.agsa.dd_value, 819)
        self.assertEqual(state.agsa.status, "Normal")
        self.assertFalse(state.agsa.sensor_failed)
        self.assertFalse(state.thermal.ntc1_failed)
        self.assertAlmostEqual(state.thermal.ntc1_temp_degc, 34.3)
        self.assertFalse(state.thermal.has_ntc1)
        self.assertTrue(state.thermal.ntc2_failed)
        self.assertEqual(state.thermal.ntc2_temp_degc, -999)
        self.assertFalse(state.thermal.cpu_temp_failed)
        self.assertAlmostEqual(state.thermal.cpu_temp_degc, -88.5)
        for fan in state.fans:
            self.assertEqual(fan.duty, -1)
            self.assertEqual(fan.tacho_rpm, 0)
        self.assertEqual(state.config_id, 7)
        self.assertAlmostEqual(state.driver_config["gbwAdcToWeightC0"],
                               2393.920401128173)
        self.assertAlmostEqual(state.driver_config["gbwAdcToWeightC1"],
                               -0.07834534628643058)
        self.assertEqual(state.driver_config["buttonAction"], 2)
        self.assertTrue(state.driver_config["productionLineTestCompleted"])
        driven = state.driver_state_json()
        self.assertAlmostEqual(driven["overshootWeightGr"], 0.53696)
        self.assertEqual(driven["ddValueDum"], 819)
        self.assertEqual(driven["fan1TachoRpm"], 0)
        self.assertFalse(driven["ntc1Failed"])
        self.assertTrue(driven["ntc2Failed"])
        config = state.config_manager_json()
        self.assertEqual(config["Grinding.OvershootWeight"], "0.536960g")
        self.assertEqual(config["Standby.ActivationTimeSec"], "600.0s")
        self.assertEqual(config["Gbw.Sensitivity"], "Medium")
        self.assertTrue(config["Cloud.ConnectionEnabled"])
        self.assertTrue(config["Cloud.TermsAcknowledged"])
        self.assertTrue(config["Agsa.AgsaUponRecipeChange"])
        self.assertTrue(config["Agsa.ShowRecipeDdEnabled"])
        self.assertEqual(config["timezoneId"], "Europe/Berlin")
        self.assertTrue(config["timezoneIdWasEntered"])

    def test_pristine_overshoot_is_unchanged(self):
        state = DeviceState()
        self.assertEqual(state.config_manager_json()["Grinding.OvershootWeight"],
                         "0.600000g")

    def test_live_state_matches_captured_driver_state(self):
        evidence = (Path(__file__).resolve().parents[3] / "docs" / "evidence" /
                    "live-2026-11-18" / "wss-reads.json")
        captured = json.loads(evidence.read_text())["reads"][
            "RequestDriverState"]["data"]
        state = DeviceState()
        apply_live_hsg_profile(state)
        live = state.driver_state_json()
        # The wss-reads fixture is from the first session.  A later clean
        # token session saw a dial change and a slightly different NTC/CPU
        # reading; the static profile tracks the later values.
        later = {
            "cpuTempDegC": LIVE_DERIVED["cpuTempDegC"],
            "ddValueDum": LIVE_DERIVED["ddValueDum"],
            "ntc1TempDegC": LIVE_DERIVED["ntc1TempDegC"],
        }
        for key in (
            "agsaHallSensorCounts", "agsaStatus", "configId", "cpuTempDegC",
            "cpuTempFailed", "ddSensorAngle", "ddSensorFailed", "ddValueDum",
            "espAlive", "espFuseFailed", "espSdioState", "espUartFailed",
            "espUpdateRequired", "espVersionNo", "fan1Duty", "fan1Failed",
            "fan1TachoRpm", "fan2Duty", "fan2Failed", "fan2TachoRpm",
            "fanTemperatureCtrlEnabled", "grindFailure", "grindState",
            "grinderType", "hasNtc1", "language", "ntc1Failed", "ntc1TempDegC",
            "ntc2Failed", "ntc2TempDegC", "overheatNtc1", "overheatNtc2",
            "overshootWeightGr", "setupWizardState", "shiftCompensationFailed",
        ):
            with self.subTest(key=key):
                expected = later.get(key, captured[key])
                self.assertEqual(live[key], expected, key)

    def test_live_driver_config_has_the_full_captured_field_set(self):
        evidence = (Path(__file__).resolve().parents[3] / "docs" / "evidence" /
                    "live-2026-11-18" / "wss-reads.json")
        captured = json.loads(evidence.read_text())["reads"][
            "RequestDriverConfig"]["data"]
        state = DeviceState()
        apply_live_hsg_profile(state)
        live = state.driver_config_json()
        self.assertEqual(set(live), set(captured))
        for key in ("buttonAction", "gbwAdcToWeightC0", "gbwAdcToWeightC1",
                    "id", "productionLineTestCompleted", "configVersion",
                    "grinderType", "grinderSubType", "gbsAlgorithm",
                    "targetWeightGr"):
            with self.subTest(key=key):
                self.assertEqual(live[key], captured[key], key)


class LiveProfilePersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="e64-live-profile-")
        self.persistence = Persistence(self.dir)

    def tearDown(self) -> None:
        self.persistence.conn.close()
        shutil.rmtree(self.dir)

    def test_seed_writes_the_observed_rows(self):
        written = seed_live_settings(self.persistence)
        self.assertEqual(written, 27)
        for key, value in LIVE_DB_SETTINGS.items():
            self.assertEqual(self.persistence.get_setting(key), value)

    def test_save_config_uses_vendor_database_units(self):
        state = DeviceState()
        apply_live_hsg_profile(state)
        self.persistence.save_config(state)
        self.assertEqual(self.persistence.get_setting("Grinding.OvershootWeight"),
                         "536960")
        self.assertEqual(self.persistence.get_setting("Standby.ActivationTimeSec"),
                         "600")
        self.assertEqual(self.persistence.get_setting("Cloud.ConnectionEnabled"),
                         "true")
        self.assertEqual(self.persistence.get_setting("Agsa.ShowRecipeDdEnabled"),
                         "true")

    def test_grind_uuid_uses_the_live_blob_storage_class(self):
        state = DeviceState()
        apply_live_hsg_profile(state)
        grind_id = self.persistence.add_grind(state)
        row = self.persistence.conn.execute(
            "SELECT typeof(grind_uuid), length(grind_uuid), grind_uuid"
            " FROM grind_log WHERE grind_id=?", (grind_id,)).fetchone()
        self.assertEqual(row[0], "blob")
        self.assertEqual(row[1], 36)
        text = row[2].decode("ascii")
        self.assertEqual(len(text), 36)
        self.assertIn(text, self.persistence.export_csv(
            self.persistence.grind_rows(), GRIND_CSV_COLUMNS))


if __name__ == "__main__":
    unittest.main()
