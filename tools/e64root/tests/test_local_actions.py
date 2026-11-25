"""Focused tests for the gated local-API action layer.

These cover the parts the module-level suite does not:

* the in-memory :class:`~e64local_actions.ActionEngine` gate, destructive gate,
  bounds, unknown/ESP/credential refusals and the catalog shape;
* the ``e64root api deploy/revert`` policy and runner wiring;
* simulator parity for the five action meta routes.

The PHP module itself is exercised in ``test_local_api.py``.  No device, no
network beyond the loopback simulator, no new dependency.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import FIXTURES  # noqa: F401  (sets sys.path)
from test_local_api import DOCKER_IMAGE, LOCAL_API_FIXTURES, MODULE, OWNER, RUNNER, docker_ready

from e64local_actions import (
    ACTION_CATALOG,
    ACTION_META_ROUTES,
    DEFAULT_RATES,
    ActionEngine,
    ActionError,
    canonical,
    params_hash,
)
from e64root import commands

REPO = Path(__file__).resolve().parents[3]
SECRET = "ab" * 32
REQUEST_ID = "request-0001"


class EngineFixture(unittest.TestCase):
    """An engine with a small deterministic machine behind it."""

    def setUp(self) -> None:
        self.now = 1_767_225_600.0
        self.engine = ActionEngine(
            settings={
                "Gbw.LastGbwCalibrationDate": "2026-01-01",
                "Grinding.PurgeValueMs": "200",
            },
            portafilters=[{"weight": 0}],
            clock=lambda: self.now,
            secret=SECRET,
        )
        self.grinder = _FakeGrinder()

    def enable(self, *, destructive: bool = False) -> None:
        self.engine.enabled = True
        self.engine.destructive_enabled = destructive

    def prepare(self, route: str, params: dict | None = None, request_id: str = REQUEST_ID) -> dict:
        return self.engine.prepare(
            self.grinder, {"route": route, "params": params or {}, "requestId": request_id}
        )


class _FakeGrinder:
    """Minimal stand-in for SimulatedGrinder used by the engine."""

    def __init__(self) -> None:
        self.firmware_update_state = "Idle"
        self.grind_state = "Idle"
        self.grind_failure = False
        self.grind_target_weight_gr = 0.0
        self.grind_time_sec = 0.0
        self.motor_runtime_ms = 0
        self.dd_value_dum = 5000
        self.target_dd_dum = 5000
        self.agsa_status = "Ready"
        self.fan1_duty = 0
        self.fan2_duty = 0
        self.fan_temperature_ctrl_enabled = True
        self.backlight_brightness = 100
        self.backlight_on = True
        self.language = "en"
        self.grind_log: list[dict] = []
        self.service_log: list[dict] = []
        self.last_brew_event: dict = {}
        self.recipes = [
            {"recipe_index": 1, "recipe_data_id": 1, "recipe_active": 1},
            {"recipe_index": 2, "recipe_data_id": 2, "recipe_active": 0},
        ]

    def snapshot(self) -> dict:
        return {
            "grindState": "Grind" if self.grind_state == "Grind" else "Idle",
            "grindFailure": self.grind_failure,
            "overheatNtc1": False,
            "overheatNtc2": False,
            "ddValueDum": self.dd_value_dum,
            "ddSensorFailed": False,
            "setupWizardState": "Completed",
        }

    def log_grind(self, ddd, duration_ms, weight_gr) -> None:
        self.grind_log.append({
            "grind_uuid": "00000000-0000-4000-8000-0000000000aa",
            "grind_ddd": ddd,
            "grind_duration": duration_ms,
            "grind_weight": weight_gr,
        })


class GateTests(EngineFixture):
    def test_gate_off_refuses_every_action_route(self) -> None:
        self.assertFalse(self.engine.enabled)
        with self.assertRaises(ActionError) as caught:
            self.prepare("action_grind_start_gbw", {"targetWeightGr": 18.0})
        self.assertEqual(caught.exception.code, 403)
        self.assertIn("not enabled", caught.exception.message)
        # A read-only action route is gated too, not only actuators.
        with self.assertRaises(ActionError) as caught:
            self.engine.status({"actionId": "0" * 8 + "-" + "0" * 4 + "-" + "0" * 4 + "-" + "0" * 4 + "-" + "0" * 12})
        self.assertEqual(caught.exception.code, 403)

    def test_gate_on_reports_routes_and_policy(self) -> None:
        off = self.engine.capabilities()
        self.assertFalse(off["enabled"])
        self.assertEqual(off["actionRoutes"], [])
        self.assertIn("reason", off)

        self.enable()
        on = self.engine.capabilities()
        self.assertTrue(on["enabled"])
        implemented = sorted(
            route
            for route, entry in ACTION_CATALOG.items()
            if entry["status"] == "implemented" and not entry.get("destructive")
        )
        self.assertEqual(sorted(on["actionRoutes"]), implemented)
        self.assertEqual(on["policy"]["version"], 1)
        self.assertEqual(on["policy"]["bounds"]["targetWeightGr"], {"min": 0.1, "max": 50.0})

        # A destructive route is not dispatchable while the second gate is off,
        # so capabilities must not advertise it as one.
        destructive = {
            route
            for route, entry in ACTION_CATALOG.items()
            if entry["status"] == "implemented" and entry.get("destructive")
        }
        self.assertTrue(destructive)
        self.assertFalse(on["destructiveEnabled"])
        self.assertEqual(destructive & set(on["actionRoutes"]), set())
        blocked = {entry["route"] for entry in on["catalog"] if "blocked" in entry}
        self.assertEqual(blocked, destructive)

        self.engine.destructive_enabled = True
        everything = self.engine.capabilities()
        self.assertTrue(everything["destructiveEnabled"])
        self.assertTrue(destructive <= set(everything["actionRoutes"]))
        self.assertEqual(
            [entry for entry in everything["catalog"] if "blocked" in entry], []
        )


class DestructiveGateTests(EngineFixture):
    def test_destructive_action_needs_the_second_gate(self) -> None:
        self.enable(destructive=False)
        with self.assertRaises(ActionError) as caught:
            self.prepare("action_recipe_delete", {"recipeIndex": 2})
        self.assertEqual(caught.exception.code, 403)
        self.assertIn("destructive", caught.exception.message)

    def test_destructive_action_runs_when_enabled(self) -> None:
        self.enable(destructive=True)
        prepared = self.prepare("action_recipe_delete", {"recipeIndex": 2})
        self.assertEqual(prepared["state"], "prepared")
        result = self.engine.execute(
            self.grinder, {"actionId": prepared["actionId"], "confirmToken": prepared["confirmToken"]}
        )
        self.assertEqual(result["state"], "completed")
        self.assertEqual([r["recipe_index"] for r in self.grinder.recipes], [1])

    def test_non_destructive_action_unaffected_by_destructive_gate(self) -> None:
        self.enable(destructive=False)
        prepared = self.prepare("action_settings_set", {"settings": {"System.UseAmPm": True}})
        self.assertEqual(prepared["state"], "prepared")


class BoundsTests(EngineFixture):
    def test_bounds_rejection(self) -> None:
        self.enable()
        cases = (
            ("action_grind_start_gbw", {"targetWeightGr": 0.05}),
            ("action_grind_start_gbw", {"targetWeightGr": 50.1}),
            ("action_grind_start_gbt", {"grindTimeSec": 0.4}),
            ("action_grind_start_gbt", {"grindTimeSec": 60.5}),
            ("action_grind_start_manual", {"durationMs": 5001}),
            ("action_agsa_move", {"targetDdValue": 10001}),
            ("action_fan_set", {"fan": 1, "dutyPercent": 101}),
            ("action_display_backlight", {"brightness": -1}),
            ("action_language_set", {"language": "xx"}),
            ("action_brew_event_add", {"grindUuid": "not-a-uuid"}),
        )
        for route, params in cases:
            with self.subTest(route=route, params=params):
                with self.assertRaises(ActionError) as caught:
                    self.prepare(route, params, request_id="req-" + route)
                self.assertEqual(caught.exception.code, 422, caught.exception.message)

    def test_type_confusion_is_rejected(self) -> None:
        self.enable()
        for params in ({"targetWeightGr": "18"}, {"targetWeightGr": True}, {"targetWeightGr": 18, "x": 1}):
            with self.subTest(params=params):
                with self.assertRaises(ActionError) as caught:
                    self.prepare("action_grind_start_gbw", params)
                self.assertEqual(caught.exception.code, 422)

    def test_engine_caps_are_fixed_and_refuse_beyond_them(self) -> None:
        # The offline engine has no policy loader; its bounds are the absolute
        # caps.  Mutating its copy must not change what normalize() enforces
        # for a fresh engine, and the cap is enforced at the boundary value.
        self.enable()
        self.engine.bounds["targetWeightGr"]["max"] = 999.0
        fresh = ActionEngine(settings={}, portafilters=[], clock=lambda: self.now, secret=SECRET)
        fresh.enabled = True
        with self.assertRaises(ActionError) as caught:
            fresh.normalize("action_grind_start_gbw", {"targetWeightGr": 60.0}, self.grinder)
        self.assertEqual(caught.exception.code, 422)
        self.assertEqual(
            fresh.normalize("action_grind_start_gbw", {"targetWeightGr": 50.0}, self.grinder),
            {"targetWeightGr": 50.0},
        )

    def test_policy_bounds_are_clamped_module_side(self) -> None:
        # A policy whose minimum sits above the absolute maximum must not
        # invert the range and hand out a bound wider than the code allows.
        engine = ActionEngine(settings={}, portafilters=[], clock=lambda: self.now, secret=SECRET)
        engine.enabled = True
        engine.bounds["targetWeightGr"] = {"min": 999.0, "max": 999.0}
        effective = engine.effective_bounds()["targetWeightGr"]
        self.assertEqual(effective, {"min": 0.1, "max": 50.0})
        engine.bounds["targetWeightGr"] = {"min": -100.0, "max": 0.05}
        self.assertEqual(engine.effective_bounds()["targetWeightGr"], {"min": 0.1, "max": 50.0})
        engine.bounds["targetWeightGr"] = {"min": 0.1, "max": 10.0}
        self.assertEqual(engine.effective_bounds()["targetWeightGr"], {"min": 0.1, "max": 10.0})
        engine.bounds["targetWeightGr"] = {"min": 0.1, "max": 999.0}
        self.assertEqual(engine.effective_bounds()["targetWeightGr"], {"min": 0.1, "max": 50.0})
        # The capabilities document reports the clamped value, not the policy's.
        self.assertEqual(
            engine.capabilities()["policy"]["bounds"]["targetWeightGr"], {"min": 0.1, "max": 50.0}
        )

    def test_policy_rate_limits_only_tighten(self) -> None:
        engine = ActionEngine(settings={}, portafilters=[], clock=lambda: self.now, secret=SECRET)
        engine.rates["display"] = {"perMinute": 9999, "perHour": 9999}
        self.assertEqual(
            engine.effective_rates()["display"],
            {"perMinute": DEFAULT_RATES["display"]["perMinute"], "perHour": DEFAULT_RATES["display"]["perHour"]},
        )
        engine.rates["display"] = {"perMinute": 1, "perHour": 1}
        self.assertEqual(engine.effective_rates()["display"], {"perMinute": 1, "perHour": 1})
        engine.rates["display"] = {"perMinute": -5, "perHour": -5}
        self.assertEqual(engine.effective_rates()["display"], {"perMinute": 0, "perHour": 0})


class UnknownAndExcludedTests(EngineFixture):
    def test_unknown_action_is_404(self) -> None:
        self.enable()
        with self.assertRaises(ActionError) as caught:
            self.prepare("action_does_not_exist")
        self.assertEqual(caught.exception.code, 404)

    def test_esp_actions_refused_by_boundary(self) -> None:
        self.enable()
        for route in (
            "action_esp_reset",
            "action_esp_flash",
            "action_wifi_provision",
            "action_firmware_update",
            "action_bootloader_enter",
            "action_fuse_write",
            "action_pairing_start",
            "action_onboarding_start",
            "action_cloud_pair",
        ):
            with self.subTest(route=route):
                with self.assertRaises(ActionError) as caught:
                    self.prepare(route)
                self.assertEqual(caught.exception.code, 403)
                self.assertIn("outside this API", caught.exception.message)

    def test_credential_actions_absent_and_refused(self) -> None:
        self.enable()
        for name in sorted(ACTION_CATALOG):
            self.assertNotRegex(name, r"action_(role|password|credential|login)_")
        # The refusal is name-based, so one generic name covers the class.
        with self.assertRaises(ActionError) as caught:
            self.prepare("action_credential_write")
        self.assertEqual(caught.exception.code, 403)
        self.assertIn("credential", caught.exception.message)

    def test_catalog_has_no_esp_or_nozzle_entry(self) -> None:
        for name, entry in ACTION_CATALOG.items():
            self.assertNotRegex(name, r"^action_(esp|wifi|firmware|fuse|otp|bootloader|pairing|onboarding|cloud)_")
            self.assertNotIn("nozzle", name)
            self.assertNotIn("NozzleLight", json.dumps(entry))
            self.assertNotRegex(name, r"action_(role|password|credential|login)_")

    def test_every_catalog_entry_has_evidence_and_a_reason(self) -> None:
        for name, entry in ACTION_CATALOG.items():
            with self.subTest(route=name):
                self.assertIn(entry["status"], ("implemented", "unavailable"))
                self.assertTrue(entry["evidence"], name)
                if entry["status"] == "unavailable":
                    self.assertTrue(entry["reason"], name)
                    self.assertIn(entry["code"], (403, 422), name)
                else:
                    self.assertIn(entry["surface"], ("wss", "sqlite"), name)


class ProtocolTests(EngineFixture):
    def test_prepare_execute_happy_path(self) -> None:
        self.enable()
        prepared = self.prepare("action_grind_start_gbw", {"targetWeightGr": 18.0})
        self.assertEqual(prepared["state"], "prepared")
        self.assertEqual(prepared["actionRoute"], "action_grind_start_gbw")
        self.assertRegex(prepared["confirmToken"], r"^[0-9a-f]{64}$")
        expected = hmac.new(
            SECRET.encode(),
            "|".join([
                prepared["actionId"],
                "action_grind_start_gbw",
                params_hash({"targetWeightGr": 18.0}),
                str(prepared["expires"]),
                REQUEST_ID,
            ]).encode(),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(prepared["confirmToken"], expected)

        executed = self.engine.execute(
            self.grinder,
            {"actionId": prepared["actionId"], "confirmToken": prepared["confirmToken"]},
        )
        self.assertEqual(executed["state"], "completed")
        self.assertEqual(executed["actionRoute"], "action_grind_start_gbw")

    def test_replay_is_rejected(self) -> None:
        self.enable()
        prepared = self.prepare("action_settings_set", {"settings": {"System.UseAmPm": True}})
        body = {"actionId": prepared["actionId"], "confirmToken": prepared["confirmToken"]}
        self.engine.execute(self.grinder, body)
        with self.assertRaises(ActionError) as caught:
            self.engine.execute(self.grinder, body)
        self.assertEqual(caught.exception.code, 409)

    def test_expired_token_is_rejected(self) -> None:
        self.enable()
        prepared = self.prepare("action_settings_set", {"settings": {"System.UseAmPm": True}})
        self.now = prepared["expires"] + 1
        with self.assertRaises(ActionError) as caught:
            self.engine.execute(
                self.grinder, {"actionId": prepared["actionId"], "confirmToken": prepared["confirmToken"]}
            )
        self.assertEqual(caught.exception.code, 409)
        self.assertIn("expired", caught.exception.message)

    def test_tampered_token_is_rejected(self) -> None:
        self.enable()
        prepared = self.prepare("action_settings_set", {"settings": {"System.UseAmPm": True}})
        with self.assertRaises(ActionError) as caught:
            self.engine.execute(self.grinder, {"actionId": prepared["actionId"], "confirmToken": "0" * 64})
        self.assertEqual(caught.exception.code, 403)

    def test_idempotent_prepare_returns_the_same_action(self) -> None:
        self.enable()
        first = self.prepare("action_language_set", {"language": "de"})
        second = self.prepare("action_language_set", {"language": "de"})
        self.assertEqual(first["actionId"], second["actionId"])
        self.assertTrue(second["idempotent"])

    def test_unsafe_state_is_refused(self) -> None:
        self.enable()
        self.grinder.grind_state = "Grind"
        with self.assertRaises(ActionError) as caught:
            self.prepare("action_grind_start_gbw", {"targetWeightGr": 18.0})
        self.assertEqual(caught.exception.code, 409)
        self.assertIn("not idle", caught.exception.message)

    def test_audit_records_every_phase_without_params(self) -> None:
        self.enable()
        prepared = self.prepare("action_language_set", {"language": "de"})
        self.engine.execute(
            self.grinder, {"actionId": prepared["actionId"], "confirmToken": prepared["confirmToken"]}
        )
        page = self.engine.audit_page(50, 0)
        phases = {row["phase"] for row in page["rows"]}
        self.assertTrue({"prepare", "execute", "result"} <= phases, phases)
        encoded = json.dumps(page)
        for row in page["rows"]:
            self.assertNotIn("params", row)
            self.assertNotIn("confirmToken", row)
            self.assertRegex(row["paramsHash"] or "0" * 64, r"^[0-9a-f]{64}$")
        self.assertNotIn(SECRET, encoded)
        self.assertNotIn("confirmToken", encoded)


class CancelTests(EngineFixture):
    """``action_cancel`` was implemented but had no test at all.

    It is the path a live grinder depends on, so the states matter: cancelled
    before execute must not execute, cancelling during execute must send the
    stop and finish terminal, and a finished action must stay finished.
    """

    def test_cancel_before_execute_prevents_execution(self) -> None:
        self.enable()
        prepared = self.prepare("action_grind_start_gbw", {"targetWeightGr": 18.0})
        cancelled = self.engine.cancel(self.grinder, {"actionId": prepared["actionId"]})
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertTrue(cancelled["cancelled"])
        self.assertFalse(cancelled["stopSent"])
        with self.assertRaises(ActionError) as caught:
            self.engine.execute(
                self.grinder,
                {"actionId": prepared["actionId"], "confirmToken": prepared["confirmToken"]},
            )
        self.assertEqual(caught.exception.code, 409)
        self.assertEqual(
            self.engine.records[prepared["actionId"]]["state"], "cancelled"
        )

    def test_cancel_while_executing_stops_the_grind(self) -> None:
        self.enable()
        prepared = self.prepare("action_grind_start_gbw", {"targetWeightGr": 18.0})
        record = self.engine.records[prepared["actionId"]]
        record["state"] = "executing"
        self.grinder.grind_state = "Grind"

        cancelled = self.engine.cancel(self.grinder, {"actionId": prepared["actionId"]})

        self.assertEqual(cancelled["state"], "cancelling")
        self.assertFalse(cancelled["cancelled"])
        self.assertTrue(cancelled["stopSent"])
        self.assertEqual(self.grinder.grind_state, "Idle")
        self.assertTrue(record["cancelRequested"])

    def test_cancel_while_executing_sends_no_stop_for_a_setting(self) -> None:
        self.enable()
        prepared = self.prepare("action_language_set", {"language": "de"})
        self.engine.records[prepared["actionId"]]["state"] = "executing"
        cancelled = self.engine.cancel(self.grinder, {"actionId": prepared["actionId"]})
        self.assertEqual(cancelled["state"], "cancelling")
        self.assertFalse(cancelled["stopSent"])

    def test_cancel_after_a_finished_action_changes_nothing(self) -> None:
        self.enable()
        prepared = self.prepare("action_settings_set", {"settings": {"System.UseAmPm": True}})
        self.engine.execute(
            self.grinder,
            {"actionId": prepared["actionId"], "confirmToken": prepared["confirmToken"]},
        )
        first = self.engine.cancel(self.grinder, {"actionId": prepared["actionId"]})
        second = self.engine.cancel(self.grinder, {"actionId": prepared["actionId"]})
        for response in (first, second):
            self.assertEqual(response["state"], "completed")
            self.assertFalse(response["cancelled"])
            self.assertFalse(response["stopSent"])
            self.assertIn("terminal", response["note"])

    def test_cancel_requires_the_gate(self) -> None:
        self.enable()
        prepared = self.prepare("action_language_set", {"language": "de"})
        self.engine.enabled = False
        with self.assertRaises(ActionError) as caught:
            self.engine.cancel(self.grinder, {"actionId": prepared["actionId"]})
        self.assertEqual(caught.exception.code, 403)

    def test_cancel_validates_the_identifier(self) -> None:
        self.enable()
        with self.assertRaises(ActionError) as caught:
            self.engine.cancel(self.grinder, {"actionId": "not-a-uuid"})
        self.assertEqual(caught.exception.code, 400)
        with self.assertRaises(ActionError) as caught:
            self.engine.cancel(
                self.grinder, {"actionId": "11111111-2222-3333-4444-555555555555"}
            )
        self.assertEqual(caught.exception.code, 404)

    def test_cancel_writes_one_audit_row_without_params(self) -> None:
        self.enable()
        prepared = self.prepare("action_grind_start_gbw", {"targetWeightGr": 18.0})
        self.engine.cancel(self.grinder, {"actionId": prepared["actionId"]})
        rows = [
            row
            for row in self.engine.audit_page(50, 0)["rows"]
            if row["phase"] == "cancel"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["result"], "cancelled_before_execute")
        self.assertRegex(rows[0]["paramsHash"], r"^[0-9a-f]{64}$")
        self.assertNotIn("params", rows[0])
        self.assertNotIn("18.0", json.dumps(rows[0]))


class MonotonicRateTests(EngineFixture):
    """The rate window lives in a monotonic domain and fails closed."""

    def test_stored_event_in_the_future_is_refused(self) -> None:
        self.enable()
        self.engine.monotonic = lambda: 100.0
        self.engine.rate["display"] = [999_000]
        with self.assertRaises(ActionError) as caught:
            self.prepare("action_display_backlight", {"brightness": 40}, request_id="mono-0001")
        self.assertEqual(caught.exception.code, 500)
        self.assertIn("unusable", caught.exception.message)
        # The bad bucket is not pruned away, so a retry is refused the same way.
        with self.assertRaises(ActionError) as caught:
            self.prepare("action_display_backlight", {"brightness": 41}, request_id="mono-0002")
        self.assertEqual(caught.exception.code, 500)

    def test_backwards_clock_is_refused_and_kept(self) -> None:
        self.enable()
        now = {"ms": 5_000_000}
        self.engine.monotonic = lambda: now["ms"] / 1000.0
        self.engine.rates["display"] = {"perMinute": 1, "perHour": 1}
        self.prepare("action_display_backlight", {"brightness": 40}, request_id="mono-0003")
        self.assertEqual(self.engine.rate["display"], [5_000_000])
        now["ms"] = 4_900_000
        with self.assertRaises(ActionError) as caught:
            self.prepare("action_display_backlight", {"brightness": 41}, request_id="mono-0004")
        self.assertEqual(caught.exception.code, 500)


class BootBindingTests(EngineFixture):
    def test_a_token_does_not_survive_a_reboot(self) -> None:
        self.enable()
        prepared = self.prepare("action_language_set", {"language": "de"})
        body = {"actionId": prepared["actionId"], "confirmToken": prepared["confirmToken"]}
        self.engine.boot_id = "11111111-1111-4111-8111-111111111111"
        with self.assertRaises(ActionError) as caught:
            self.engine.execute(self.grinder, body)
        self.assertEqual(caught.exception.code, 409)
        self.assertIn("rebooted", caught.exception.message)
        self.assertEqual(self.engine.records[prepared["actionId"]]["state"], "expired")

    def test_retry_in_a_new_boot_prepares_a_new_action(self) -> None:
        self.enable()
        prepared = self.prepare("action_language_set", {"language": "de"})
        self.engine.boot_id = "11111111-1111-4111-8111-111111111111"
        again = self.prepare("action_language_set", {"language": "de"})
        self.assertNotIn("idempotent", again)
        self.assertNotEqual(again["actionId"], prepared["actionId"])
        self.assertEqual(self.engine.records[prepared["actionId"]]["state"], "expired")
        result = self.engine.execute(
            self.grinder, {"actionId": again["actionId"], "confirmToken": again["confirmToken"]}
        )
        self.assertEqual(result["state"], "completed")

    def test_normal_path_still_executes_in_the_same_boot(self) -> None:
        self.enable()
        prepared = self.prepare("action_language_set", {"language": "de"})
        result = self.engine.execute(
            self.grinder, {"actionId": prepared["actionId"], "confirmToken": prepared["confirmToken"]}
        )
        self.assertEqual(result["state"], "completed")


class DeployPolicyTests(unittest.TestCase):
    """`e64root api deploy/revert` writes and removes the gate files."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = commands._api_module_path()

    def test_deploy_embeds_runner_and_valid_policy_secret(self) -> None:
        script = commands._api_deploy_script(
            self.module, None, enable_actions=True, destructive=False, secret=SECRET
        )
        self.assertIn("e64local-action-run", script)
        self.assertIn("/db/e64local/actions.json", script)
        match = re.search(r'"secret": "([0-9a-f]{64})"', script)
        self.assertIsNotNone(match, "policy must carry a 64-hex HMAC secret")
        self.assertEqual(match.group(1), SECRET)
        self.assertNotIn("__E64LOCAL_RUNNER_CONTENT__", script)
        self.assertIn("php -l", script)

    def test_policy_secret_is_redacted_when_printed(self) -> None:
        script = commands._api_deploy_script(
            self.module, None, enable_actions=True, secret=SECRET
        )
        redacted = commands._redact_script_secrets(script)
        self.assertNotIn(SECRET, redacted)
        self.assertIn("<generated at deploy time>", redacted)

    def test_destructive_flag_is_written_and_off_by_default(self) -> None:
        off = commands._api_deploy_script(self.module, None, enable_actions=True, secret=SECRET)
        self.assertIn('"destructiveEnabled": false', off)
        on = commands._api_deploy_script(
            self.module, None, enable_actions=True, destructive=True, secret=SECRET
        )
        self.assertIn('"destructiveEnabled": true', on)

    def test_destructive_requires_actions(self) -> None:
        with self.assertRaises(commands.UsageError):
            commands._api_deploy_script(self.module, None, destructive=True)

    def test_deploy_clears_rate_buckets_and_refuses_a_placeholder(self) -> None:
        script = commands._api_deploy_script(self.module, None, enable_actions=True, secret=SECRET)
        # Monotonic buckets cannot be re-based across a release, so a re-deploy
        # clears them; the placeholder guard keeps a preview out of the gate.
        self.assertIn("rm -f /db/e64local/rate/*.json", script)
        self.assertIn("grep -q '<generated at deploy time>'", script)
        self.assertNotIn("<generated at deploy time>\n\npolicy_mode", script)
        preview = commands._api_deploy_script(self.module, None, enable_actions=True)
        self.assertIn('"secret": "<generated at deploy time>"', preview)
        self.assertIn("refusing to install a policy with a placeholder secret", preview)

    def test_generated_scripts_pass_a_shell_syntax_check(self) -> None:
        scripts = {
            "deploy": commands._api_deploy_script(
                self.module, None, enable_actions=True, destructive=True, secret=SECRET
            ),
            "revert": commands._api_revert_script(purge_audit=True),
        }
        for name, script in scripts.items():
            with self.subTest(script=name):
                result = subprocess.run(
                    ["sh", "-n"], input=script, capture_output=True, text=True, timeout=30
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_revert_removes_the_gate_and_runner(self) -> None:
        script = commands._api_revert_script()
        self.assertIn("rm -f /db/e64local/actions.json", script)
        self.assertIn("rm -f /usr/local/bin/e64local-action-run", script)
        self.assertNotIn("audit.jsonl", script)

    def test_revert_purge_audit_removes_the_trail(self) -> None:
        script = commands._api_revert_script(purge_audit=True)
        self.assertIn("/db/e64local/audit.jsonl", script)


class SimulatorActionParityTests(unittest.TestCase):
    """The simulator answers the action meta routes with the module's contract."""

    def setUp(self) -> None:
        import urllib.request

        from e64ws_simulator import (
            SimulatedAuth,
            SimulatedGrinder,
            SimulatedLocalApi,
            SimulatedScale,
            _http_server,
        )

        self.urllib = urllib.request
        grinder = SimulatedGrinder()
        local = SimulatedLocalApi()
        self.local = local
        self.server = _http_server("127.0.0.1", 0, grinder, SimulatedScale(), SimulatedAuth("fixture-token"))
        self.server.simulator = (
            grinder, self.server.simulator[1], self.server.simulator[2],
            self.server.simulator[3], self.server.simulator[4], local,
        )
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.cookie = self._login()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _login(self) -> str:
        status, _body, headers = self.post(
            "/rest_api/login", {"userRole": "Owner", "password": "sim-password"}, cookie=""
        )
        self.assertEqual(status, 200)
        return headers["Set-Cookie"].split(";", 1)[0]

    def post(self, path, payload, cookie=None):
        import json as _json

        headers = {"Content-Type": "application/json", "X-E64-Local-Token": "sim-local-api-token"}
        headers["Cookie"] = self.cookie if cookie is None else cookie
        request = self.urllib.Request(
            self.base + path, data=_json.dumps(payload).encode(), headers=headers, method="POST"
        )
        try:
            with self.urllib.urlopen(request, timeout=5) as response:
                return response.status, _json.loads(response.read()), dict(response.headers)
        except self.urllib.HTTPError as error:
            try:
                return error.code, _json.loads(error.read()), dict(error.headers)
            finally:
                error.close()

    def test_action_routes_are_gated_off_by_default(self) -> None:
        status, body, _ = self.post("/rest_api/action_prepare", {"route": "action_grind_stop", "requestId": "req-0001"})
        self.assertEqual((status, body["errorCode"]), (403, 403))

    def test_capabilities_lists_no_role_or_esp_action(self) -> None:
        _status, body, _ = self.post("/rest_api/capabilities", {})
        encoded = json.dumps(body["data"])
        self.assertNotRegex(encoded, r"action_(role|password|credential|login)_")
        self.assertNotIn("action_nozzle_light", encoded)
        self.assertNotIn("action_esp_", encoded)

    def test_prepare_execute_over_http(self) -> None:
        self.local.actions.enabled = True
        status, body, _ = self.post(
            "/rest_api/action_prepare",
            {"route": "action_language_set", "params": {"language": "de"}, "requestId": "req-0002"},
        )
        self.assertEqual((status, body["success"]), (200, True), body)
        data = body["data"]
        self.assertEqual(data["state"], "prepared")

        status, body, _ = self.post(
            "/rest_api/action_execute",
            {"actionId": data["actionId"], "confirmToken": data["confirmToken"]},
        )
        self.assertEqual((status, body["success"]), (200, True), body)
        self.assertEqual(body["data"]["state"], "completed")

        status, body, _ = self.post("/rest_api/action_audit", {"limit": 10})
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["data"]["total"], 2)

    def test_simulator_rate_limit_and_expiry_over_http(self) -> None:
        # A one-per-minute display bucket: the second prepare is limited.
        self.local.actions.enabled = True
        self.local.actions.rates["display"] = {"perMinute": 1, "perHour": 1}
        status, body, _ = self.post(
            "/rest_api/action_prepare",
            {"route": "action_display_backlight", "params": {"brightness": 40}, "requestId": "sim-rate-1"},
        )
        self.assertEqual(status, 200, body)
        status, body, _ = self.post(
            "/rest_api/action_prepare",
            {"route": "action_display_backlight", "params": {"brightness": 41}, "requestId": "sim-rate-2"},
        )
        self.assertEqual((status, body["errorCode"]), (429, 429), body)
        self.assertIn("rate limit", body["error"])

        # Expiry: move the engine's clock past the token TTL before executing.
        clock = {"now": 1_767_225_600.0}
        self.local.actions.clock = lambda: clock["now"]
        self.local.actions.rate = {}
        status, body, _ = self.post(
            "/rest_api/action_prepare",
            {"route": "action_language_set", "params": {"language": "fr"}, "requestId": "sim-exp-1"},
        )
        self.assertEqual(status, 200, body)
        clock["now"] += 10_000
        status, body, _ = self.post(
            "/rest_api/action_execute",
            {"actionId": body["data"]["actionId"], "confirmToken": body["data"]["confirmToken"]},
        )
        self.assertEqual((status, body["errorCode"]), (409, 409), body)
        self.assertIn("expired", body["error"])

    def test_bare_action_path_is_not_a_route(self) -> None:
        status, body, _ = self.post("/rest_api/action_grind_start_gbw", {})
        self.assertEqual((status, body["errorCode"]), (404, 404))

    def test_esp_action_path_is_refused(self) -> None:
        status, body, _ = self.post("/rest_api/action_esp_reset", {})
        self.assertEqual((status, body["errorCode"]), (403, 403))

    def test_credential_action_path_is_refused(self) -> None:
        status, body, _ = self.post("/rest_api/action_credential_write", {})
        self.assertEqual((status, body["errorCode"]), (403, 403))

    def test_capabilities_match_the_destructive_gate(self) -> None:
        self.local.actions.enabled = True
        _status, body, _ = self.post("/rest_api/capabilities", {})
        data = body["data"]["actions"]
        self.assertFalse(data["destructiveEnabled"])
        advertised = set(data["actionRoutes"])
        destructive = {
            route
            for route, entry in ACTION_CATALOG.items()
            if entry["status"] == "implemented" and entry.get("destructive")
        }
        self.assertTrue(destructive)
        self.assertEqual(destructive & advertised, set())

        self.local.actions.destructive_enabled = True
        _status, body, _ = self.post("/rest_api/capabilities", {})
        data = body["data"]["actions"]
        self.assertTrue(data["destructiveEnabled"])
        self.assertTrue(destructive <= set(data["actionRoutes"]))


class RunnerJobValidationTests(unittest.TestCase):
    """The bounded runner re-validates its own job file; that is tested directly.

    The PHP harness runs the real ``ondevice/e64local_action_run.php`` with
    attacker-shaped job files, so this is the privilege boundary itself, not a
    Python mirror of it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        if not docker_ready():
            raise unittest.SkipTest("php:8.3-cli is not available; runner tests skipped")
        cls.temporary = tempfile.TemporaryDirectory()
        root = Path(cls.temporary.name)
        (root / "bin").mkdir()
        shutil.copy(LOCAL_API_FIXTURES / "sudo_passthrough.php", root / "bin" / "sudo")
        (root / "bin" / "sudo").chmod(0o755)
        shutil.copy(LOCAL_API_FIXTURES / "sqlite3_stub.php", root / "bin" / "sqlite3")
        (root / "bin" / "sqlite3").chmod(0o755)
        shutil.copy(RUNNER, root / "runner.php")
        (root / "runner.php").chmod(0o755)
        shutil.copy(LOCAL_API_FIXTURES / "wss_fixture.php", root / "wss_fixture.php")
        shutil.copy(LOCAL_API_FIXTURES / "harness.php", root / "harness.php")
        shutil.copy(MODULE, root / "module.php")
        for stub in ("sessionHelper.php", "constants.php", "systemInfo.php"):
            (root / stub).write_text("<?php\n", encoding="utf-8")
        # A real database the runner may write, created with the CPython module.
        import sqlite3 as _sqlite3

        (root / "db").mkdir()
        connection = _sqlite3.connect(root / "db" / "HsgSqlite.db")
        connection.executescript(
            """
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE portafilters (portafilter_id INTEGER PRIMARY KEY, weight INTEGER);
            """
        )
        connection.commit()
        connection.close()
        (root / "scenario.json").write_text(json.dumps(cls._scenario()), encoding="utf-8")
        (root / "state.json").write_text('{"grindState":"Idle"}', encoding="utf-8")
        cls.root = root
        cls.results = cls._run(root)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    @classmethod
    def _job(cls, **overrides) -> dict:
        job = {
            "schema": "e64local-action-job-v1",
            "verb": "wss",
            "timeoutMs": 8000,
            "endpoint": "wss://127.0.0.1:9997/?token=harness-ws-token",
            "command": "Stop",
            "params": {},
        }
        job.update(overrides)
        return job

    @classmethod
    def _scenario(cls) -> list[dict]:
        owner = {"headerToken": OWNER}
        return [
            {"id": "job_ok", "route": "__runner_job", "body": {"job": cls._job()}, **owner},
            {
                "id": "job_followup_invalid",
                "route": "__runner_job",
                "body": {"job": cls._job(
                    command="StartGrindManual",
                    followUp={"command": "Stop", "afterMs": 999999},
                )},
                **owner,
            },
            {
                "id": "job_header_injection",
                "route": "__runner_job",
                "body": {"job": cls._job(
                    endpoint=(
                        "wss://127.0.0.1:9997/?token=harness-ws-token%0d%0a"
                        "X-Injected: 1%0d%0a%0d%0aPOST /evil HTTP/1.1"
                    )
                )},
                **owner,
            },
            {
                "id": "job_extra_query",
                "route": "__runner_job",
                "body": {"job": cls._job(
                    endpoint="wss://127.0.0.1:9997/?token=harness-ws-token&cmd=EspReset"
                )},
                **owner,
            },
            {
                "id": "job_unknown_command",
                "route": "__runner_job",
                "body": {"job": cls._job(command="EspReset")},
                **owner,
            },
            {
                "id": "job_sql_outside_allowlist",
                "route": "__runner_job",
                "body": {"job": cls._job(
                    verb="sqlite",
                    command=None,
                    sqlite3="/usr/bin/sqlite3",
                    dbPath="/db/HsgSqlite.db",
                    backupDir="/db/e64local/backup",
                    sql={"kind": "settings_set_bulk", "params": {"entries": [
                        {"key": "Role.Owner.LoginData", "value": "x"}
                    ]}},
                )},
                **owner,
            },
            {"id": "wss_log_after_jobs", "route": "__wss_log", "body": {}, **owner},
        ]

    @classmethod
    def _run(cls, root: Path) -> dict[str, dict]:
        script = """
set -eu
mkdir -p /db/e64local/actions /db/e64local/backup /usr/local/bin
cp /work/bin/sudo /usr/bin/sudo
cp /work/bin/sqlite3 /usr/bin/sqlite3
cp /work/runner.php /usr/local/bin/e64local-action-run
chmod 755 /usr/bin/sudo /usr/bin/sqlite3 /usr/local/bin/e64local-action-run
cp /work/db/HsgSqlite.db /db/HsgSqlite.db
printf 'harness-owner-token\\n' > /db/e64local/token
chmod 600 /db/e64local/token
php /work/wss_fixture.php 9997 /work/state.json /work/wss.log --self-signed &
wss_pid=$!
trap 'kill $wss_pid 2>/dev/null || true' EXIT
i=0
while [ $i -lt 50 ]; do
  if php -r '$s=@stream_socket_client("tcp://127.0.0.1:9997",$e,$m,1); if($s){fclose($s);exit(0);} exit(1);'; then
    break
  fi
  i=$((i + 1))
  sleep 0.1
done
php /work/harness.php /work/module.php /work/scenario.json
"""
        result = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{root}:/work", DOCKER_IMAGE, "sh", "-c", script],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise AssertionError(f"runner harness failed:\n{result.stderr}\n{result.stdout}")
        outcomes = {}
        for line in result.stdout.splitlines():
            if line.strip():
                outcome = json.loads(line)
                outcomes[outcome["id"]] = outcome
        return outcomes

    def data(self, case_id: str) -> dict:
        self.assertIn(case_id, self.results, sorted(self.results))
        return self.results[case_id]["json"]["data"]

    def test_runner_rejects_a_followup_it_would_not_send(self) -> None:
        # The follow-up is the only thing that bounds a manual grind; it must be
        # refused before the start command is sent, not after.
        body = self.data("job_followup_invalid")
        self.assertEqual(body["result"]["errorCode"], 422)
        self.assertFalse(body["result"]["ok"])
        frames = self.data("wss_log_after_jobs")["frames"]
        started = [
            frame for frame in frames
            if frame.get("type") == "GrinderAction"
            and frame.get("data", {}).get("actionType") == "StartGrindManual"
        ]
        self.assertEqual(started, [])
        self.assertNotIn("X-Injected", json.dumps(frames))

    def test_runner_rejects_control_characters_in_the_endpoint(self) -> None:
        body = self.data("job_header_injection")
        self.assertEqual(body["result"]["errorCode"], 422)
        self.assertIn("control", body["result"]["error"])
        encoded = json.dumps(self.data("wss_log_after_jobs"))
        self.assertNotIn("X-Injected", encoded)

    def test_runner_allowlists_commands_and_sql(self) -> None:
        self.assertTrue(self.data("job_ok")["result"]["ok"])
        self.assertEqual(self.data("job_unknown_command")["result"]["errorCode"], 403)
        # Only the one token query parameter the module writes is accepted.
        extra = self.data("job_extra_query")["result"]
        self.assertEqual(extra["errorCode"], 503)
        self.assertIn("exactly one token", extra["error"])
        sql = self.data("job_sql_outside_allowlist")["result"]
        self.assertEqual(sql["errorCode"], 403)
        self.assertIn("not allowlisted", sql["error"])
        self.assertFalse((self.root / "db" / "HsgSqlite.db").read_bytes() == b"")


if __name__ == "__main__":
    unittest.main()
