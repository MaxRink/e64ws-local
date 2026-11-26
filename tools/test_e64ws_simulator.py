from __future__ import annotations

import hashlib
import json
import os
import unittest
import unittest.mock
import urllib.error
import urllib.request

try:
    from . import e64ws_simulator as simulator
    from .e64local_actions import ActionError
    from .e64ws_simulator import (
        SYNTHETIC_APK_NETWORK_SCHEMA,
        SYNTHETIC_APK_PASSWORD,
        SYNTHETIC_OFFICIAL_E64_ONBOARDING_SCHEMA,
        SimulatedApkProvisioning,
        SimulatedAuth,
        vendor_hash,
        dev_gated,
        GRIND_LOG_COLUMNS,
        SimulatedGrinder,
        SimulatedLocalApi,
        SimulatedOfficialE64Onboarding,
        SimulatedScale,
        _http_server,
    )
except ImportError:
    import e64ws_simulator as simulator
    from e64local_actions import ActionError
    from e64ws_simulator import (
        SYNTHETIC_APK_NETWORK_SCHEMA,
        SYNTHETIC_APK_PASSWORD,
        SYNTHETIC_OFFICIAL_E64_ONBOARDING_SCHEMA,
        SimulatedApkProvisioning,
        SimulatedAuth,
        vendor_hash,
        dev_gated,
        GRIND_LOG_COLUMNS,
        SimulatedGrinder,
        SimulatedLocalApi,
        SimulatedOfficialE64Onboarding,
        SimulatedScale,
        _http_server,
    )


class SimulatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.grinder = SimulatedGrinder()
        self.scale = SimulatedScale()

    def test_driver_state_correlates_msg_id(self) -> None:
        response = self.grinder.handle({"type": "RequestDriverState", "msgId": 7})
        self.assertEqual(response["type"], "RequestDriverStateResult")
        self.assertEqual(response["refId"], 7)
        self.assertEqual(response["data"]["ddValueDum"], 5000)

    def test_action_changes_state_and_gbs_has_special_envelope(self) -> None:
        response = self.grinder.handle(
            {
                "type": "GrinderAction",
                "msgId": 8,
                "data": {"actionType": "SetAgsaTargetDdValue", "targetDdValue": 5100},
            }
        )
        self.assertEqual(response["data"]["success"], True)
        state = self.grinder.handle({"type": "RequestDriverState", "msgId": 9})
        self.assertEqual(state["data"]["ddValueDum"], 5100)
        report = self.grinder.handle(
            {"type": "GrinderAction", "msgId": 10, "data": {"actionType": "GbsCreateReport"}}
        )
        self.assertEqual(report["type"], "GbsCreateReport")
        self.assertNotIn("refId", report)

    def test_simulator_bounds_are_explicit(self) -> None:
        response = self.grinder.handle(
            {
                "type": "GrinderAction",
                "msgId": 11,
                "data": {"actionType": "SetAgsaTargetDdValue", "targetDdValue": 10001},
            }
        )
        self.assertFalse(response["data"]["success"])

    def test_scale_sequence_is_monotonic_for_normal_samples(self) -> None:
        self.scale.set_sample(1.2, 100)
        self.scale.set_sample(2.4, 200)
        self.assertEqual(self.scale.frame()["sequence"], 2)
        self.assertEqual(self.scale.frame()["ms"], 200.0)

    def test_rest_fixture_session_issues_the_wss_token_and_expires(self) -> None:
        auth = SimulatedAuth("fixture-token", session_ttl_seconds=900)
        result = auth.login("User", "sim-password")
        self.assertTrue(result["success"])
        self.assertTrue(auth.accepts({"Authorization": "Bearer fixture-token"}))
        self.assertTrue(auth.accepts({"Cookie": f"PHPSESSID={auth.cookie}"}))
        self.assertTrue(auth.accepts({"authorization": "Bearer fixture-token"}))
        self.assertTrue(auth.accepts({"cookie": f"PHPSESSID={auth.cookie}"}))
        auth.logout()
        self.assertFalse(auth.accepts({"Authorization": "Bearer fixture-token"}))

    def test_owner_role_and_fw01_login_construction(self) -> None:
        auth = SimulatedAuth("fixture-token")
        self.assertEqual(auth.login("Owner", "sim-password")["role"], "Owner")
        role = 'x" UNION SELECT "1$1000$abcd$' + vendor_hash("random", "abcd", 1000) + '" -- '
        with self.assertRaises(ValueError):
            auth.login(role, "random")
        auth = SimulatedAuth("fixture-token", fw01_login=True)
        self.assertEqual(auth.login(role, "random")["role"], "Owner")
        with self.assertRaises(ValueError):
            auth.login(role, "other")

    def test_rest_login_accepts_a_chunked_body(self) -> None:
        import http.client
        server = _http_server("127.0.0.1", 0, self.grinder, self.scale, SimulatedAuth("fixture-token"))
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            body = json.dumps({"userRole": "Owner", "password": "sim-password"}).encode()
            connection.request("POST", "/rest_api/login", body=iter([body[:10], body[10:]]),
                               headers={"Content-Type": "application/json", "Transfer-Encoding": "chunked"},
                               encode_chunked=True)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Authorization"), "Bearer fixture-token")
        finally:
            server.shutdown()
            server.server_close()

    def test_dev_gate_backlight_and_machine_info(self) -> None:
        self.assertTrue(dev_gated({"type": "GrinderAction", "data": {"actionType": "Stop"}}))
        self.assertTrue(dev_gated({"type": "RequestLogMessages"}))
        self.assertFalse(dev_gated({"type": "GrinderAction", "data": {"actionType": "EspReset"}}))
        self.assertFalse(dev_gated({"type": "RequestDriverState"}))
        info = self.grinder.handle({"type": "RequestNachineInfo", "msgId": 1})
        self.assertEqual(info["data"]["grinderType"], "Unknown")
        locked = SimulatedGrinder(dev_mode=False)
        self.assertEqual(locked.handle({"type": "RequestNachineInfo", "msgId": 1})["data"]["grinderType"], "E64 WS")
        result = self.grinder.handle({"type": "GrinderAction", "msgId": 2,
                                      "data": {"actionType": "SetBacklightBrightness", "brightness": 0}})
        self.assertTrue(result["data"]["success"])
        self.assertEqual(self.grinder.backlight_brightness, 0)
        self.assertEqual(self.grinder.events[-1], {"event": "backlight", "brightness": 0})

    def test_machine_logs_zip_records_each_completed_grind(self) -> None:
        import csv as csv_module
        import io as io_module
        import zipfile as zip_module
        act = lambda suffix, **data: self.grinder.handle({"type": "GrinderAction", "msgId": 1, "data": {"actionType": suffix, **data}})
        act("StartGrindGbw", targetWeightGr=18.0)
        act("Stop")
        act("Stop")
        name, payload = self.grinder.machine_logs_zip()
        self.assertRegex(name, r"^HemroE64WSMachineLogs_SN000000_\d{8}_\d{6}\.zip$")
        with zip_module.ZipFile(io_module.BytesIO(payload)) as package:
            infos = {info.filename: info for info in package.infolist()}
            grind = next(n for n in infos if "GrindLogs" in n)
            self.assertTrue(any("ServiceLogs" in n for n in infos))
            self.assertEqual(infos[grind].compress_type, zip_module.ZIP_DEFLATED)
            rows = list(csv_module.DictReader(io_module.StringIO(package.read(grind).decode())))
        self.assertEqual(len(rows), 1)
        self.assertEqual(tuple(rows[0].keys()), GRIND_LOG_COLUMNS)
        self.assertEqual(rows[0]["grind_ddd"], "5000")
        self.assertEqual(rows[0]["grind_weight"], "18000")
        self.assertEqual(rows[0]["recipe_type"], "Espresso, double")
        self.grinder.seed_service_log()
        self.grinder.log_service("LogIn", "Role Owner logged in")
        _, payload = self.grinder.machine_logs_zip()
        with zip_module.ZipFile(io_module.BytesIO(payload)) as package:
            service = next(n for n in package.namelist() if "ServiceLogs" in n)
            events = list(csv_module.DictReader(io_module.StringIO(package.read(service).decode())))
        self.assertEqual([e["event_type"] for e in events], ["PowerOn", "WifiConnected", "SerialNumberRead", "LogIn"])
        self.assertEqual(list(events[0].keys()), ["event_id", "event_type_id", "event_type", "event_date_time", "event_details"])

    def test_replay_serves_captured_states_by_position(self) -> None:
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            trace.write_text(
                '{"t":0,"state":{"grindState":"Idle","ddValueDum":819}}\n'
                '{"t":2.5,"state":{"grindState":"Grind","ddValueDum":819}}\n'
            )
            self.grinder.load_replay(str(trace))
        self.assertEqual(self.grinder.snapshot()["grindState"], "Idle")
        self.grinder.advance(2500)
        self.assertEqual(self.grinder.snapshot()["grindState"], "Grind")
        self.grinder.seek_replay(1)
        self.assertEqual(self.grinder.snapshot()["grindState"], "Idle")
        self.assertEqual(len(self.grinder.grind_log), 1)
        self.grinder.reset()
        self.assertEqual(self.grinder.snapshot()["grindState"], "Idle")

    def test_synthetic_apk_fixture_is_deterministic_and_never_retains_password(self) -> None:
        apk = SimulatedApkProvisioning()
        first = apk.list_networks()
        second = apk.list_networks()
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], SYNTHETIC_APK_NETWORK_SCHEMA)
        self.assertTrue(first["synthetic"])
        self.assertEqual(
            [network["ssid"] for network in first["networks"]],
            ["E64-SIM-SETUP", "E64-SIM-LAB", "E64-SIM-OPEN"],
        )
        self.assertTrue(all(network["ssid"].startswith("E64-SIM-") for network in first["networks"]))
        self.assertNotIn("password", json.dumps(first).lower())

        connected = apk.connect({"ssid": "E64-SIM-SETUP", "password": SYNTHETIC_APK_PASSWORD})
        self.assertTrue(connected["connected"])
        self.assertNotIn(SYNTHETIC_APK_PASSWORD, json.dumps(connected))
        self.assertNotIn("password", json.dumps(apk.status()).lower())

    def test_synthetic_apk_fixture_rejects_unknown_networks_and_real_credentials(self) -> None:
        apk = SimulatedApkProvisioning()
        with self.assertRaisesRegex(ValueError, "synthetic E64-SIM"):
            apk.connect({"ssid": "home-network", "password": "real-looking-secret"})
        with self.assertRaisesRegex(ValueError, "no real credential"):
            apk.connect({"ssid": "E64-SIM-SETUP", "password": "real-looking-secret"})
        self.assertEqual(apk.status()["connected"], False)

    def test_official_app_candidate_fixture_redacts_request_values(self) -> None:
        fixture = SimulatedOfficialE64Onboarding()
        response = fixture.request_onboarding(
            {
                "token": "should-not-appear",
                "wifiConfig": {"ssid": "E64-SIM-SETUP", "password": "should-not-appear"},
                "subType": "E64_WS",
            }
        )
        encoded = json.dumps(response)
        self.assertEqual(response["schema"], SYNTHETIC_OFFICIAL_E64_ONBOARDING_SCHEMA)
        self.assertTrue(response["synthetic"])
        self.assertEqual(response["wireCompatibility"], "candidate-only")
        self.assertNotIn("should-not-appear", encoded)
        self.assertTrue(response["requestShape"]["fieldPresence"]["token"])
        self.assertTrue(response["requestShape"]["fieldPresence"]["wifiConfig"])
        self.assertEqual(fixture.status()["requestCount"], 1)


class HttpSimulatorTest(unittest.TestCase):
    """HTTP/state contract tests for the local synthetic APK fixture."""

    def setUp(self) -> None:
        self.grinder = SimulatedGrinder()
        self.scale = SimulatedScale()
        self.auth = SimulatedAuth("fixture-token")
        self.apk = SimulatedApkProvisioning()
        self.server = _http_server(
            "127.0.0.1", 0, self.grinder, self.scale, self.auth, self.apk
        )
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def request(
        self,
        path: str,
        method: str = "GET",
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object], dict[str, str]]:
        request_body = None if payload is None else json.dumps(payload).encode("utf-8")
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        request = urllib.request.Request(
            self.base_url + path,
            data=request_body,
            headers=request_headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read()), dict(response.headers)
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read()), dict(error.headers)
            finally:
                error.close()

    def test_apk_network_routes_have_synthetic_schema_and_stable_state_transitions(self) -> None:
        status, initial, _ = self.request("/api/v2/network")
        self.assertEqual(status, 200)
        self.assertEqual(initial["schema"], SYNTHETIC_APK_NETWORK_SCHEMA)
        self.assertTrue(initial["synthetic"])
        self.assertFalse(initial["connected"])
        self.assertEqual(initial["scanGeneration"], 0)

        status, listed, _ = self.request("/api/v2/network/list")
        self.assertEqual(status, 200)
        status, listed_again, _ = self.request("/api/v2/network/list")
        self.assertEqual(status, 200)
        self.assertEqual(listed, listed_again)
        self.assertEqual(listed["scanGeneration"], 0)
        self.assertTrue(all(item["ssid"].startswith("E64-SIM-") for item in listed["networks"]))
        self.assertNotIn("password", json.dumps(listed).lower())

        status, scanned, _ = self.request("/api/v2/network/forcescan", "POST", {})
        self.assertEqual(status, 200)
        self.assertEqual(scanned["operation"], "forcescan")
        self.assertEqual(scanned["scanGeneration"], 1)
        self.assertEqual(scanned["networks"], listed["networks"])

        status, connected, _ = self.request(
            "/api/v2/network/connect",
            "POST",
            {"ssid": "E64-SIM-SETUP", "password": SYNTHETIC_APK_PASSWORD},
        )
        self.assertEqual(status, 200)
        self.assertTrue(connected["connected"])
        self.assertEqual(connected["ssid"], "E64-SIM-SETUP")
        self.assertNotIn(SYNTHETIC_APK_PASSWORD, json.dumps(connected))

        status, state, _ = self.request("/sim/state")
        self.assertEqual(status, 200)
        self.assertEqual(state["apkProvisioning"]["schema"], SYNTHETIC_APK_NETWORK_SCHEMA)
        self.assertTrue(state["apkProvisioning"]["connected"])
        self.assertEqual(state["apkProvisioning"]["ssid"], "E64-SIM-SETUP")

    def test_apk_connect_validation_is_atomic_and_reset_restores_initial_state(self) -> None:
        status, before, _ = self.request("/api/v2/network")
        self.assertEqual(status, 200)
        status, error, _ = self.request(
            "/api/v2/network/connect",
            "POST",
            {"ssid": "E64-SIM-SETUP", "password": "not-a-fixture-secret"},
        )
        self.assertEqual(status, 422)
        self.assertEqual(error["schema"], SYNTHETIC_APK_NETWORK_SCHEMA)
        self.assertFalse(error["connected"])
        self.assertNotIn("not-a-fixture-secret", json.dumps(error))
        status, after, _ = self.request("/api/v2/network")
        self.assertEqual(status, 200)
        self.assertEqual(after, before)

        self.request("/api/v2/network/forcescan", "POST", {})
        self.request(
            "/api/v2/network/connect",
            "POST",
            {"ssid": "E64-SIM-OPEN"},
        )
        status, reset, _ = self.request("/sim/reset", "POST", {})
        self.assertEqual(status, 200)
        self.assertFalse(reset["apkProvisioning"]["connected"])
        self.assertEqual(reset["apkProvisioning"]["scanGeneration"], 0)
        self.assertEqual(reset["apkProvisioning"]["lastOperation"], "initial")

    def test_firmware_rest_placeholders_are_tagged_and_separate_from_apk_schema(self) -> None:
        status, _login, headers = self.request(
            "/rest_api/login", "POST", {"userRole": "User", "password": "sim-password"}
        )
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, onboarding, _ = self.request(
            "/rest_api/request_onboarding",
            "POST",
            {"ssid": "E64-SIM-SETUP", "password": "secret-not-returned"},
            {"Cookie": cookie},
        )
        self.assertEqual(status, 200)
        self.assertEqual(onboarding["schema"], "synthetic-firmware-rest-placeholder-v1")
        self.assertNotEqual(onboarding["schema"], SYNTHETIC_APK_NETWORK_SCHEMA)
        self.assertEqual(onboarding["forwardedType"], "RequestOnboarding")
        self.assertEqual(onboarding["dataKeys"], ["password", "ssid"])
        self.assertIsNone(onboarding["deviceResponse"])
        self.assertNotIn("secret-not-returned", json.dumps(onboarding))

        status, scan, _ = self.request(
            "/rest_api/scan_wifi", "POST", {}, {"Cookie": cookie}
        )
        self.assertEqual(status, 200)
        self.assertEqual(scan["schema"], "synthetic-firmware-rest-placeholder-v1")
        self.assertIsNone(scan["deviceResponse"])
        self.assertEqual(scan["networkFixture"], "/api/v2/network/list")

    def test_official_app_candidate_routes_are_opt_in_and_tagged(self) -> None:
        candidate = SimulatedOfficialE64Onboarding()
        self.server.shutdown()
        self.server.server_close()
        self.server = _http_server(
            "127.0.0.1", 0, self.grinder, self.scale, self.auth, self.apk, candidate
        )
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        status, _login, headers = self.request(
            "/rest_api/login", "POST", {"userRole": "User", "password": "sim-password"}
        )
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, onboarding, _ = self.request(
            "/rest_api/request_onboarding",
            "POST",
            {"token": "redacted", "wifiConfig": {"password": "redacted"}},
            {"Cookie": cookie},
        )
        self.assertEqual(status, 200)
        self.assertEqual(onboarding["schema"], SYNTHETIC_OFFICIAL_E64_ONBOARDING_SCHEMA)
        self.assertEqual(onboarding["wireCompatibility"], "candidate-only")
        self.assertNotIn("redacted", json.dumps(onboarding))
        self.assertEqual(onboarding["deviceResponse"]["type"], "RequestOnboardingResult")
        status, scan, _ = self.request("/rest_api/scan_wifi", "POST", {}, {"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertEqual(scan["schema"], SYNTHETIC_OFFICIAL_E64_ONBOARDING_SCHEMA)
        self.assertTrue(scan["data"])


class ActionGateFixtureTest(unittest.TestCase):
    """The fixture's action gate must be closed by default and openable.

    The end-to-end app suites need the five meta routes to answer, and a
    shipped image needs them refused. Both directions are asserted here so the
    fixture cannot silently drift into either state.
    """

    def test_the_action_gate_is_closed_by_default(self):
        api = SimulatedLocalApi()
        capabilities = api.capabilities()
        self.assertFalse(capabilities["actions"]["enabled"])
        self.assertNotIn("action_prepare", capabilities["routes"])
        with self.assertRaises(ActionError) as caught:
            api.actions.prepare(
                SimulatedGrinder(),
                {"route": "action_language_set", "params": {"language": "de"},
                 "requestId": "e2e-0001"},
            )
        self.assertEqual(caught.exception.code, 403)

    def test_enabling_actions_opens_prepare(self):
        api = SimulatedLocalApi(actions_enabled=True)
        capabilities = api.capabilities()
        self.assertTrue(capabilities["actions"]["enabled"])
        self.assertIn("action_prepare", capabilities["routes"])
        prepared = api.actions.prepare(
            SimulatedGrinder(),
            {"route": "action_language_set", "params": {"language": "de"},
             "requestId": "e2e-0001"},
        )
        self.assertEqual(prepared["state"], "prepared")
        self.assertRegex(prepared["confirmToken"], r"^[0-9a-f]{64}$")

    def test_the_destructive_gate_requires_the_action_gate(self):
        closed = SimulatedLocalApi(destructive_enabled=True)
        self.assertFalse(closed.actions.destructive_enabled)
        opened = SimulatedLocalApi(actions_enabled=True, destructive_enabled=True)
        self.assertTrue(opened.actions.destructive_enabled)


#: Every optional fixture fallback this module documents.  The tests below own
#: the environment: they clear these names, then put back what was there.
E64_SIM_VARIABLES = (
    "E64_SIM_REST_PASSWORD",
    "E64_SIM_SERIAL",
    "E64_SIM_GRINDER_TYPE",
    "E64_SIM_WIFI_SSID",
    "E64_SIM_WIFI_STA_PASSWORD",
    "E64_SIM_WIFI_PRODUCTION_PASSWORD",
    "E64_SIM_ROLE_LOGIN_DATA",
)


class FixtureEnvFallbackTest(unittest.TestCase):
    """The ``E64_SIM_*`` fallbacks are opt-in and must never move a default.

    Three directions per value, because each can regress alone: unset keeps the
    documented default, set replaces it, and an explicit value (which is what
    every CLI flag becomes) beats both.  The first test is the contract: with
    the environment clear the fixture is the one the source documents, so no
    existing reader, suite or capture can be affected by this feature.
    """

    def setUp(self) -> None:
        saved = {name: os.environ.get(name) for name in E64_SIM_VARIABLES}
        for name in E64_SIM_VARIABLES:
            os.environ.pop(name, None)

        def restore() -> None:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        self.addCleanup(restore)

    def test_the_environment_clear_leaves_every_documented_default(self) -> None:
        # Instantiated twice: a default mutated in place would leak into the second.
        first, second = SimulatedLocalApi(), SimulatedLocalApi()
        for api in (first, second):
            self.assertEqual(api.serial, "SIM0000000001")
            self.assertEqual(api.grinder_type, 5)
            self.assertEqual(api.token, "sim-local-api-token")
            self.assertEqual(api.settings["Wifi.StaPassword"], "sim-wifi-secret")
            self.assertEqual(api.settings["productionWifiSsid"], "factory-net")
            self.assertEqual(api.settings["Role.Owner.LoginData"], "should-not-appear")
            self.assertEqual(api.settings["Role.Technician.LoginData"], "should-not-appear")
            self.assertEqual(api.settings["Role.Barista.LoginData"], "should-not-appear")
            self.assertEqual(api.settings["M2m.CoffeeMachinesConfig"], "should-not-appear")
            self.assertEqual(api.settings["System.Language"], "en_US")
            self.assertEqual(api.config["grinderSn"], "SIM0000000001")
            self.assertEqual(api.config["grinderType"], 5)
            self.assertEqual(api.config["productionWifiSsid"], "factory-net")
            self.assertEqual(api.config["productionWifiPassword"], "factory-secret")
            self.assertEqual(api.config["cloudBaseUrl"], "https://example.com")
        self.assertIsNot(first.settings, second.settings)
        self.assertIsNot(first.config, second.config)
        self.assertEqual(SimulatedAuth("fixture-token").password, "sim-password")

    def test_an_empty_variable_is_the_same_as_unset(self) -> None:
        os.environ["E64_SIM_REST_PASSWORD"] = ""
        os.environ["E64_SIM_SERIAL"] = ""
        os.environ["E64_SIM_WIFI_STA_PASSWORD"] = ""
        self.assertEqual(SimulatedAuth("fixture-token").password, "sim-password")
        api = SimulatedLocalApi()
        self.assertEqual(api.serial, "SIM0000000001")
        self.assertEqual(api.settings["Wifi.StaPassword"], "sim-wifi-secret")

    def test_the_rest_password_falls_back_to_the_environment(self) -> None:
        os.environ["E64_SIM_REST_PASSWORD"] = "env-only-password"
        auth = SimulatedAuth("fixture-token")
        self.assertEqual(auth.password, "env-only-password")
        self.assertTrue(auth.login("Owner", "env-only-password")["success"])
        with self.assertRaises(ValueError):
            SimulatedAuth("fixture-token").login("Owner", "sim-password")

    def test_the_serial_and_grinder_type_fall_back_to_the_environment(self) -> None:
        os.environ["E64_SIM_SERIAL"] = "ENV0000000042"
        os.environ["E64_SIM_GRINDER_TYPE"] = "2"
        api = SimulatedLocalApi()
        self.assertEqual(api.serial, "ENV0000000042")
        self.assertEqual(api.grinder_type, 2)
        # The two documents describe one machine, so they move together.
        self.assertEqual(api.config["grinderSn"], "ENV0000000042")
        self.assertEqual(api.config["grinderType"], 2)
        machine = api.machine(SimulatedGrinder())
        self.assertEqual(machine["grinderType"], 2)
        self.assertEqual(machine["grinderTypeName"], "E65W GbS")
        self.assertTrue(machine["serialPresent"])
        self.assertEqual(
            machine["serialSha256"], hashlib.sha256(b"ENV0000000042").hexdigest()
        )

    def test_the_credential_rows_fall_back_to_the_environment(self) -> None:
        os.environ["E64_SIM_WIFI_SSID"] = "env-net"
        os.environ["E64_SIM_WIFI_STA_PASSWORD"] = "env-sta-psk"
        os.environ["E64_SIM_WIFI_PRODUCTION_PASSWORD"] = "env-prod-password"
        os.environ["E64_SIM_ROLE_LOGIN_DATA"] = "env-login-data"
        api = SimulatedLocalApi()
        self.assertEqual(api.settings["Wifi.StaPassword"], "env-sta-psk")
        self.assertEqual(api.settings["productionWifiSsid"], "env-net")
        for role in ("Owner", "Technician", "Barista"):
            self.assertEqual(api.settings[f"Role.{role}.LoginData"], "env-login-data")
        self.assertEqual(api.config["productionWifiSsid"], "env-net")
        self.assertEqual(api.config["productionWifiPassword"], "env-prod-password")
        # Rows that are not credentials keep their fixture values.
        self.assertEqual(api.settings["M2m.CoffeeMachinesConfig"], "should-not-appear")
        self.assertEqual(api.settings["System.Language"], "en_US")

    def test_an_explicit_value_beats_the_environment(self) -> None:
        os.environ["E64_SIM_REST_PASSWORD"] = "env-only-password"
        os.environ["E64_SIM_SERIAL"] = "ENV0000000042"
        os.environ["E64_SIM_GRINDER_TYPE"] = "2"
        os.environ["E64_SIM_WIFI_STA_PASSWORD"] = "env-sta-psk"
        self.assertEqual(SimulatedAuth("fixture-token", password="explicit").password, "explicit")
        api = SimulatedLocalApi(
            serial="CLI0000000007",
            grinder_type=1,
            settings={"Wifi.StaPassword": "explicit"},
        )
        self.assertEqual(api.serial, "CLI0000000007")
        self.assertEqual(api.grinder_type, 1)
        self.assertEqual(api.settings["Wifi.StaPassword"], "explicit")
        self.assertEqual(api.config["grinderSn"], "CLI0000000007")
        self.assertEqual(api.config["grinderType"], 1)

    def test_the_cli_flags_still_beat_the_environment(self) -> None:
        """``main`` builds the fixture from flags.

        A flag must win over the environment for the field it names, and the
        environment must fill only what no flag covers.
        """
        os.environ["E64_SIM_REST_PASSWORD"] = "env-only-password"
        captured: dict[str, object] = {}

        class FakeHttp:
            def shutdown(self) -> None:
                return None

            def server_close(self) -> None:
                return None

        def fake_http_server(host, port, grinder, scale, auth, *_args, **kwargs):
            captured["auth"] = auth
            captured["api_token"] = kwargs.get("api_token")
            return FakeHttp()

        async def fake_run_servers(_args, _grinder, _scale):
            return None

        with unittest.mock.patch.object(simulator, "_http_server", fake_http_server), \
                unittest.mock.patch.object(simulator, "_run_servers", fake_run_servers):
            code = simulator.main(
                ["--token", "cli-wss-token", "--api-token", "cli-api-token"]
            )
        self.assertEqual(code, 0)
        auth = captured["auth"]
        self.assertEqual(auth.wss_token, "cli-wss-token")
        self.assertEqual(auth.password, "env-only-password")
        self.assertEqual(captured["api_token"], "cli-api-token")

    def test_a_bad_grinder_type_fails_loudly_only_when_set(self) -> None:
        os.environ["E64_SIM_GRINDER_TYPE"] = "not-a-number"
        with self.assertRaisesRegex(ValueError, "E64_SIM_GRINDER_TYPE"):
            SimulatedLocalApi()


if __name__ == "__main__":
    unittest.main()
