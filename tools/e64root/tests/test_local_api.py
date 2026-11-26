"""Offline tests for the Local Owner API v1.

Two layers are covered:

* the simulator HTTP fixture, which mirrors the documented contract and is the
  always-available offline parity test;
* the PHP module itself, executed in a disposable PHP container with a SQLite
  fixture and a stubbed ``sudo sqlite3``.  The container half needs the
  ``php:8.3-cli`` image in the local Docker daemon (``docker pull php:8.3-cli``);
  it never contacts a device.  ``tools/run_tests.py`` fails the ``e64root``
  suite when the image is missing instead of quietly collecting fewer tests.

No real SSH, grinder, or network is used.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from helpers import FIXTURES  # noqa: F401  (sets sys.path)
from host_requirements import PHP_IMAGE, php_image_problem, php_image_ready

from e64ws_simulator import (
    SimulatedAuth,
    SimulatedGrinder,
    SimulatedLocalApi,
    SimulatedScale,
    _http_server,
)

TOKEN = "sim-local-api-token"
OWNER = "harness-owner-token"
DOCKER_IMAGE = PHP_IMAGE
LOCAL_API_FIXTURES = FIXTURES / "local_api"
REPO = Path(__file__).resolve().parents[3]
MODULE = REPO / "ondevice" / "rest_api_dev.php"
RUNNER = REPO / "ondevice" / "e64local_action_run.php"
ACTION_SECRET = "ab" * 32
OPENAPI = REPO / "docs" / "openapi" / "local-api.yaml"


def action_policy(*, destructive: bool = False, rates: dict | None = None) -> dict:
    """A valid /db/e64local/actions.json for the harness."""
    return {
        "schema": "e64local-actions-v1",
        "version": 1,
        "enabled": True,
        "destructiveEnabled": destructive,
        "secret": ACTION_SECRET,
        "bounds": {
            "targetWeightGr": {"min": 0.1, "max": 50.0},
            "grindTimeSec": {"min": 0.5, "max": 60.0},
            "manualGrindMs": {"min": 100, "max": 5000},
            "purgeMs": {"min": 100, "max": 10000},
            "agsaStepDd": {"min": 1, "max": 300},
            "fanDuty": {"min": 0, "max": 100},
            "brightness": {"min": 0, "max": 100},
            "brewTimeMs": {"min": 0, "max": 120000},
            "brewWeightMg": {"min": 0, "max": 200000},
            "recipeAmountMg": {"min": 100, "max": 100000},
            "recipeCoarseness": {"min": 0, "max": 10000},
            "standbySec": {"min": 0, "max": 86400},
            "settingsEntries": {"min": 1, "max": 8},
        },
        "rateLimits": rates or {},
        "tokenTtlSec": {"actuator": 60, "stateChanging": 600, "destructive": 60},
        "audit": {"file": "/db/e64local/audit.jsonl", "maxBytes": 1048576, "keep": 3},
    }


def docker_ready() -> bool:
    """True when the local ``php:8.3-cli`` image can run the container tests.

    The requirement itself lives in ``host_requirements`` so that the skip
    reason here, in ``test_local_actions`` and the runner's preflight all name
    the same image and the same ``docker pull`` command.
    """
    return php_image_ready(DOCKER_IMAGE)


class SimulatorCase(unittest.TestCase):
    """Shared HTTP fixture with deterministic rows."""

    def setUp(self) -> None:
        self.grinder = SimulatedGrinder()
        self.grinder.seed_service_log()

        for day in range(1, 6):
            self.grinder.grind_log.append({
                "grind_id": day,
                "grind_uuid": f"00000000-0000-4000-8000-00000000000{day}",
                "grind_date_time": f"2026-01-0{day} 12:00:00",
                "recipe_index": 1,
                "recipe_cpr_id": 1,
                "recipe_data_id": 1,
                "grind_ddd": 500,
                "grind_duration": 25000,
                "grind_duration_noload": 0,
                "grind_weight": 18000,
                "grind_successfull": 1,
                "grind_trigger_id": 1,
                "grind_trigger": "Button",
                "recipe_gbs_enabled": 0,
                "grind_debug_data": (
                    "password=debug-secret ip 192.168.1.5 "
                    "mac 02:00:5e:10:00:01 SN 000000123456"
                ),
                "recipe_uuid": "00000000-0000-4000-8000-000000000001",
                "recipe_mode_id": 2,
                "recipe_mode": "GbW",
                "recipe_amount": 18000,
                "recipe_type_id": 1,
                "recipe_type": "Espresso, double",
                "recipe_icon_id": 1,
                "recipe_icon": "cup",
                "recipe_coarseness": 500,
                "recipe_brew_time": 27000,
                "recipe_brew_weight": 36000,
            })

        self.local = SimulatedLocalApi()
        self.local.alert_log = [
            {
                "alert_id": index,
                "alert_type_id": 1,
                "alert_type": "WaterEmpty",
                "alert_date_time": f"2026-01-0{index} 12:00:00",
                "alert_details": "Tank empty",
                "alert_active": 0,
            }
            for index in range(1, 4)
        ]
        self.scale = SimulatedScale()
        self.auth = SimulatedAuth("fixture-token")
        self.server = _http_server(
            "127.0.0.1", 0, self.grinder, self.scale, self.auth
        )
        self.server.simulator = (
            self.grinder, self.scale, self.auth, self.server.simulator[3],
            self.server.simulator[4], self.local,
        )
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.cookie = self.login()
        # Login appends a LogIn event; drop it so the fixture dates stay fixed.
        self.grinder.service_log = self.grinder.service_log[:3]
        for index, row in enumerate(self.grinder.service_log, 1):
            row["event_date_time"] = f"2026-01-0{index} 12:00:00"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def login(self) -> str:
        status, _body, headers = self.post(
            "/rest_api/login",
            {"userRole": "Owner", "password": "sim-password"},
            token=None,
            cookie="",
        )
        self.assertEqual(status, 200)
        return headers["Set-Cookie"].split(";", 1)[0]

    def post(
        self,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        token: str | None = TOKEN,
        cookie: str | None = None,
        raw: bytes | None = None,
    ) -> tuple[int, dict[str, object], dict[str, str]]:
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["X-E64-Local-Token"] = token
        if cookie is None:
            cookie = self.cookie
        if cookie:
            headers["Cookie"] = cookie
        body = raw if raw is not None else json.dumps(payload or {}).encode()
        request = urllib.request.Request(
            self.base + path, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read()), dict(response.headers)
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read()), dict(error.headers)
            finally:
                error.close()

    def data(self, route: str, payload: dict[str, object] | None = None) -> dict[str, object]:
        status, body, _headers = self.post(f"/rest_api/{route}", payload)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["success"], body)
        return body["data"]  # type: ignore[return-value]

    # -- route behaviour -------------------------------------------------

    def test_capabilities_and_auth(self) -> None:
        status, body, _ = self.post("/rest_api/capabilities", {})
        self.assertEqual(status, 200)
        self.assertEqual(body["data"]["apiVersion"], "1")
        self.assertEqual(set(body["data"]["routes"]), set(SimulatedLocalApi.ROUTES))
        self.assertFalse(body["data"]["features"]["actions"])
        self.assertEqual(
            body["data"]["limits"]["maxRequestBytes"],
            SimulatedLocalApi.MAX_REQUEST_BYTES,
        )

        status, body, _ = self.post("/rest_api/capabilities", {}, token=None)
        self.assertEqual(status, 401)
        self.assertEqual(body["errorCode"], 401)

        status, body, _ = self.post("/rest_api/capabilities", {}, token="wrong")
        self.assertEqual(status, 401)
        self.assertEqual(body["errorCode"], 401)
        self.assertNotIn("wrong", json.dumps(body))

        status, body, _ = self.post(
            "/rest_api/capabilities", {"token": TOKEN}, token=None
        )
        self.assertEqual(status, 200)

    def test_vendor_session_is_required(self) -> None:
        status, body, _ = self.post("/rest_api/capabilities", {}, cookie="")
        self.assertEqual(status, 401)
        self.assertIn("session", body["error"].lower())

    def test_every_route_requires_both_credentials(self) -> None:
        for route in SimulatedLocalApi.ROUTES:
            with self.subTest(route=route, credential="missing"):
                status, body, _ = self.post(f"/rest_api/{route}", {}, token=None)
                self.assertEqual((status, body["errorCode"]), (401, 401))
            with self.subTest(route=route, credential="wrong"):
                status, body, _ = self.post(f"/rest_api/{route}", {}, token="wrong")
                self.assertEqual((status, body["errorCode"]), (401, 401))
            with self.subTest(route=route, credential="no-session"):
                status, _body, _ = self.post(f"/rest_api/{route}", {}, cookie="")
                self.assertEqual(status, 401)

    def test_every_route_succeeds_with_valid_credentials(self) -> None:
        for route in SimulatedLocalApi.ROUTES:
            with self.subTest(route=route):
                payload = {"path": "/etc/issue"} if route == "file" else {}
                status, body, _ = self.post(f"/rest_api/{route}", payload)
                self.assertEqual(status, 200, body)
                self.assertTrue(body["success"], body)

    def test_no_known_secret_leaks_on_any_route(self) -> None:
        secrets = (
            "should-not-appear",
            "sim-wifi-secret",
            "factory-secret",
            "sim-log-secret",
            "debug-secret",
            "event-secret",
            self.local.serial,
            "sim-password",
        )
        for route in SimulatedLocalApi.ROUTES:
            with self.subTest(route=route):
                payload = {"path": "/log/sample.log"} if route == "file" else {}
                status, body, _ = self.post(f"/rest_api/{route}", payload)
                self.assertEqual(status, 200, body)
                encoded = json.dumps(body)
                for secret in secrets:
                    self.assertNotIn(secret, encoded)

    def test_machine_identity_hashes_the_serial(self) -> None:
        data = self.data("machine")
        expected = hashlib.sha256(self.local.serial.encode()).hexdigest()
        self.assertEqual(data["serialSha256"], expected)
        self.assertTrue(data["serialPresent"])
        self.assertNotIn(self.local.serial, json.dumps(data))
        self.assertEqual(data["model"], "E64 WS")
        self.assertEqual(data["variant"], "Hsg")
        self.assertEqual(data["firmware"], self.grinder.firmware_build)

    def test_grind_log_pagination_is_stable_and_newest_first(self) -> None:
        first = self.data("grind_log", {"limit": 2})
        self.assertEqual([row["grind_id"] for row in first["rows"]], ["5", "4"])
        self.assertEqual(first["offset"], 0)
        self.assertTrue(first["hasMore"])

        second = self.data("grind_log", {"limit": 2, "offset": 2})
        self.assertEqual([row["grind_id"] for row in second["rows"]], ["3", "2"])
        self.assertEqual(second["offset"], 2)

        last = self.data("grind_log", {"limit": 2, "offset": 4})
        self.assertEqual([row["grind_id"] for row in last["rows"]], ["1"])
        self.assertFalse(last["hasMore"])

        clamped = self.data("grind_log", {"limit": 99999, "offset": -5})
        self.assertEqual(clamped["limit"], 5000)
        self.assertEqual(clamped["offset"], 0)
        defaulted = self.data("grind_log", {"limit": 0, "offset": "not-a-number"})
        self.assertEqual(defaulted["limit"], 20)
        self.assertEqual(defaulted["offset"], 0)

    def test_grind_log_time_filters_and_validation(self) -> None:
        data = self.data("grind_log", {"since": "2026-01-04"})
        self.assertEqual([row["grind_id"] for row in data["rows"]], ["5", "4"])
        self.assertEqual(data["since"], "2026-01-04 00:00:00")

        data = self.data("grind_log", {"until": "2026-01-02"})
        self.assertEqual([row["grind_id"] for row in data["rows"]], ["2", "1"])
        self.assertEqual(data["until"], "2026-01-02 23:59:59")

        data = self.data(
            "grind_log",
            {"since": "2026-01-02 12:00:00", "until": "2026-01-04 12:00:00"},
        )
        self.assertEqual([row["grind_id"] for row in data["rows"]], ["4", "3", "2"])

        status, body, _ = self.post("/rest_api/grind_log", {"since": "yesterday"})
        self.assertEqual(status, 400)
        self.assertEqual(body["errorCode"], 400)
        self.assertTrue(body["error"])

        status, body, _ = self.post(
            "/rest_api/grind_log", {"since": "2026-01-05", "until": "2026-01-01"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["errorCode"], 400)

    def test_service_log_pagination_and_filters(self) -> None:
        data = self.data("service_log", {"limit": 2})
        self.assertEqual([row["event_id"] for row in data["rows"]], ["3", "2"])
        data = self.data("service_log", {"since": "2026-01-02"})
        self.assertEqual([row["event_id"] for row in data["rows"]], ["3", "2"])
        status, body, _ = self.post("/rest_api/service_log", {"since": "bad"})
        self.assertEqual(status, 400)

    def test_alert_log_pagination_and_filters(self) -> None:
        data = self.data("alert_log", {"limit": 2})
        self.assertEqual([row["alert_id"] for row in data["rows"]], ["3", "2"])
        data = self.data("alert_log", {"since": "2026-01-03"})
        self.assertEqual([row["alert_id"] for row in data["rows"]], ["3"])

    def test_log_rows_are_strings_and_redacted(self) -> None:
        data = self.data("grind_log", {"limit": 1})
        row = data["rows"][0]
        self.assertIsInstance(row["grind_id"], str)
        self.assertNotIn("debug-secret", row["grind_debug_data"])
        self.assertNotIn("192.168.1.5", row["grind_debug_data"])
        self.assertNotIn("02:00:5e:10:00:01", row["grind_debug_data"])
        self.assertNotIn("000000123456", row["grind_debug_data"])
        self.assertIn("<redacted>", row["grind_debug_data"])

    def test_portafilters_and_recipes_are_exportable(self) -> None:
        portafilters = self.data("portafilters")
        self.assertEqual(portafilters["count"], 1)
        self.assertEqual(portafilters["rows"][0]["weight"], "0")

        recipes = self.data("recipes")
        self.assertEqual(recipes["count"], 1)
        self.assertEqual(recipes["rows"][0]["recipe_amount"], "18000")
        self.assertEqual(recipes["rows"][0]["recipe_mode"], "GbW")

    def test_settings_redaction(self) -> None:
        data = self.data("settings")
        encoded = json.dumps(data)
        for secret_key in (
            "Role.Owner.LoginData",
            "Role.Technician.LoginData",
            "Wifi.StaPassword",
            "M2m.CoffeeMachinesConfig",
            "productionWifiSsid",
        ):
            self.assertNotIn(secret_key, data["settings"])
            self.assertIn(secret_key, data["redacted"])
        self.assertNotIn("should-not-appear", encoded)
        self.assertNotIn("sim-wifi-secret", encoded)
        self.assertEqual(data["settings"]["System.Language"], "en_US")

    def test_config_redaction(self) -> None:
        data = self.data("config")
        encoded = json.dumps(data)
        self.assertEqual(data["config"]["productionWifiPassword"], "<redacted>")
        self.assertEqual(data["config"]["productionWifiSsid"], "<redacted>")
        self.assertEqual(data["config"]["cloudBaseUrl"], "<redacted>")
        self.assertEqual(data["config"]["grinderSn"], "<redacted>")
        self.assertIn("productionWifiPassword", data["redacted"])
        self.assertIn("grinderSn", data["redacted"])
        self.assertNotIn("factory-secret", encoded)
        self.assertNotIn("https://example.com", encoded)
        self.assertNotIn(self.local.serial, encoded)
        self.assertEqual(data["config"]["grinderType"], 5)

    def test_file_allowlist_and_redaction(self) -> None:
        data = self.data("file", {"path": "/log/sample.log"})
        encoded = json.dumps(data)
        self.assertEqual(data["encoding"], "text")
        self.assertNotIn("sim-log-secret", encoded)
        self.assertNotIn("192.168.77.23", encoded)
        self.assertNotIn("02:00:5e:10:00:01", encoded)
        self.assertNotIn("000000123456", encoded)
        self.assertIn("<redacted>", data["content"])

        issue = self.data("file", {"path": "/etc/issue"})
        self.assertEqual(issue["encoding"], "text")
        self.assertIn("development", issue["content"])

    def test_file_rejects_non_allowlisted_paths(self) -> None:
        for path in (
            "/etc/passwd",
            "/log/../db/token",
            "/log/../../etc/passwd",
            "relative/path",
            "/log/link",
            "/log/hardlink",
        ):
            with self.subTest(path=path):
                status, body, _ = self.post("/rest_api/file", {"path": path})
                self.assertEqual(status, 400)
                self.assertEqual(body["errorCode"], 400)

        status, body, _ = self.post("/rest_api/file", {})
        self.assertEqual(status, 400)
        self.assertEqual(body["errorCode"], 400)
        status, body, _ = self.post("/rest_api/file", {"path": 3})
        self.assertEqual(status, 400)

    def test_ws_token_is_minted_and_flagged(self) -> None:
        data = self.data("ws_token")
        self.assertIn(data["token"], self.local.ws_tokens)
        self.assertIn("warning", data)
        self.assertIn("WSS", data["warning"])

    def test_request_body_limit(self) -> None:
        status, body, _ = self.post(
            "/rest_api/capabilities", raw=b"{" + b" " * 20000 + b"}"
        )
        self.assertEqual(status, 413)
        self.assertEqual(body["errorCode"], 413)

    def test_unknown_route_is_not_a_local_route(self) -> None:
        status, body, _ = self.post("/rest_api/not_a_local_route", {})
        self.assertEqual(status, 404)

    def test_dev_gate_locked_blocks_local_routes(self) -> None:
        grinder = SimulatedGrinder(dev_mode=False)
        server = _http_server("127.0.0.1", 0, grinder, SimulatedScale(), SimulatedAuth("fixture-token"))
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            login = urllib.request.Request(
                base + "/rest_api/login",
                data=json.dumps({"userRole": "Owner", "password": "sim-password"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(login, timeout=5) as response:
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            request = urllib.request.Request(
                base + "/rest_api/capabilities",
                data=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "X-E64-Local-Token": TOKEN,
                },
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=5)
            try:
                self.assertEqual(caught.exception.code, 403)
            finally:
                caught.exception.close()
        finally:
            server.shutdown()
            server.server_close()


class PhpModuleCase(unittest.TestCase):
    """Execute the actual PHP module in a throwaway container."""

    results: dict[str, dict[str, object]]

    @classmethod
    def setUpClass(cls) -> None:
        problem = php_image_problem(DOCKER_IMAGE)
        if problem is not None:
            raise unittest.SkipTest(problem)

        cls.temporary = tempfile.TemporaryDirectory()
        root = Path(cls.temporary.name)
        (root / "bin").mkdir()
        (root / "db").mkdir()
        shutil.copy(LOCAL_API_FIXTURES / "harness.php", root / "harness.php")
        shutil.copy(LOCAL_API_FIXTURES / "sudo_passthrough.php", root / "bin" / "sudo")
        (root / "bin" / "sudo").chmod(0o755)
        shutil.copy(LOCAL_API_FIXTURES / "sqlite3_stub.php", root / "bin" / "sqlite3")
        (root / "bin" / "sqlite3").chmod(0o755)
        shutil.copy(RUNNER, root / "runner.php")
        (root / "runner.php").chmod(0o755)
        shutil.copy(LOCAL_API_FIXTURES / "wss_fixture.php", root / "wss_fixture.php")
        shutil.copy(MODULE, root / "module.php")
        for stub in ("sessionHelper.php", "constants.php", "systemInfo.php"):
            (root / stub).write_text("<?php\n", encoding="utf-8")

        (root / "dev_gate.php").write_text(
            "<?php\nfunction isDev() { return false; }\nrequire '/work/module.php';\n",
            encoding="utf-8",
        )
        (root / "etc_issue").write_text(
            "development image, VERSION: HEM-HSG.140-git-g273ab65 "
            "(built at 192.168.1.5)\n",
            encoding="utf-8",
        )
        (root / "tmp_state.json").write_text('{"state":"Idle"}', encoding="utf-8")
        (root / "log_sample.log").write_text(
            "boot ok password=file-secret ip 192.168.1.5 "
            "mac 02:00:5e:10:00:01 SN 000000123456\n",
            encoding="utf-8",
        )
        (root / "db" / "HsgConfig.json").write_text(
            json.dumps({
                "configVersion": 1,
                "grinderType": 5,
                "grinderSubType": 0,
                "grinderSn": "HMI12345678",
                "productionWifiSsid": "factory-net",
                "productionWifiPassword": "factory-secret",
                "cloudBaseUrl": "https://cloud.example",
                "nested": {"password": "nested-secret", "keep": "ok", "serial": "NESTED-WRONG"},
            }),
            encoding="utf-8",
        )
        cls._create_database(root / "db" / "HsgSqlite.db")

        cls.scenario = cls._scenario()
        (root / "scenario.json").write_text(json.dumps(cls.scenario), encoding="utf-8")
        cls.root = root
        cls.results = cls._run_harness(root)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    @classmethod
    def _create_database(cls, path: Path) -> None:
        connection = sqlite3.connect(path)
        connection.executescript(
            """
            CREATE TABLE recipe_modes (recipe_mode_id INTEGER PRIMARY KEY, recipe_mode_name TEXT);
            CREATE TABLE recipe_types (recipe_type_id INTEGER PRIMARY KEY, recipe_type_name TEXT);
            CREATE TABLE recipe_icons (recipe_icon_id INTEGER PRIMARY KEY, recipe_icon_name TEXT);
            CREATE TABLE grind_trigger_modes (grind_trigger_id INTEGER PRIMARY KEY, grind_trigger_name TEXT);
            CREATE TABLE recipe_data (
                recipe_data_id INTEGER PRIMARY KEY, recipe_uuid TEXT, recipe_mode_id INTEGER,
                recipe_amount INTEGER, recipe_type_id INTEGER, recipe_icon_id INTEGER,
                recipe_coarseness INTEGER, recipe_brew_time INTEGER, recipe_brew_weight INTEGER
            );
            CREATE TABLE grind_log (
                grind_id INTEGER PRIMARY KEY, grind_uuid TEXT, grind_date_time TEXT,
                recipe_index INTEGER, recipe_cpr_id INTEGER, recipe_data_id INTEGER,
                grind_ddd INTEGER, grind_duration INTEGER, grind_duration_noload INTEGER,
                grind_weight INTEGER, grind_successfull INTEGER, grind_trigger_id INTEGER,
                recipe_gbs_enabled INTEGER, grind_debug_data TEXT
            );
            CREATE TABLE recipe_entries (
                recipe_index INTEGER PRIMARY KEY, recipe_data_id INTEGER,
                recipe_active INTEGER, recipe_cpr_id INTEGER
            );
            CREATE TABLE portafilters (
                portafilter_id INTEGER PRIMARY KEY, weight INTEGER,
                weight_tolerance INTEGER, recipe_index INTEGER
            );
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE event_types (event_type_id INTEGER PRIMARY KEY, event_type_name TEXT);
            CREATE TABLE event_log (
                event_id INTEGER PRIMARY KEY, event_type_id INTEGER,
                event_date_time TEXT, event_details TEXT
            );
            CREATE TABLE alert_types (alert_type_id INTEGER PRIMARY KEY, alert_type_name TEXT);
            CREATE TABLE alert_log (
                alert_id INTEGER PRIMARY KEY, alert_type_id INTEGER,
                alert_date_time TEXT, alert_details TEXT, alert_active INTEGER
            );
            """
        )
        connection.executemany(
            "INSERT INTO recipe_modes VALUES (?, ?)",
            [(1, "Time"), (2, "GbW")],
        )
        connection.executemany(
            "INSERT INTO recipe_types VALUES (?, ?)",
            [(1, "Espresso, double"), (2, "Filter")],
        )
        connection.executemany(
            "INSERT INTO recipe_icons VALUES (?, ?)",
            [(1, "cup"), (2, "filter")],
        )
        connection.executemany(
            "INSERT INTO grind_trigger_modes VALUES (?, ?)",
            [(1, "Button"), (2, "Wss")],
        )
        connection.execute(
            "INSERT INTO recipe_data VALUES (1, '00000000-0000-4000-8000-000000000001', 2, 18000, 1, 1, 500, 27000, 36000)"
        )
        connection.execute(
            "INSERT INTO recipe_entries VALUES (1, 1, 1, 1)"
        )
        connection.execute(
            "INSERT INTO recipe_data VALUES (2, '00000000-0000-4000-8000-000000000002', 1, 25000, 2, 2, 700, 30000, 50000)"
        )
        connection.execute(
            "INSERT INTO recipe_entries VALUES (2, 2, 0, 2)"
        )
        connection.execute(
            "INSERT INTO portafilters VALUES (1, 0, 5, 1)"
        )
        connection.executemany(
            "INSERT INTO settings VALUES (?, ?)",
            [
                ("System.Language", "en_US"),
                ("Gbw.LastGbwCalibrationDate", "2026-01-01"),
                ("Grinding.PurgeValueMs", "200"),
                ("Role.Owner.LoginData", "should-not-appear"),
                ("Role.Technician.LoginData", "should-not-appear"),
                ("Role.OwnerPasswordProtectionEnabled", "true"),
                ("Wifi.StaPassword", "sim-wifi-secret"),
                ("M2m.CoffeeMachinesConfig", "should-not-appear"),
                ("productionWifiSsid", "factory-net"),
            ],
        )
        connection.executemany(
            "INSERT INTO event_types VALUES (?, ?)",
            [(1, "PowerOn"), (2, "WifiConnected")],
        )
        for day in range(1, 6):
            connection.execute(
                "INSERT INTO grind_log VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    day,
                    f"00000000-0000-4000-8000-00000000000{day}",
                    f"2026-01-0{day} 12:00:00",
                    1, 1, 1, 500, 25000, 0, 18000, 1, 1, 0,
                    "password=debug-secret ip 192.168.1.5 mac 02:00:5e:10:00:01 SN 000000123456",
                ),
            )
            connection.execute(
                "INSERT INTO event_log VALUES (?, ?, ?, ?)",
                (
                    day,
                    1 if day % 2 else 2,
                    f"2026-01-0{day} 12:00:00",
                    "password=event-secret ip 192.168.1.5",
                ),
            )
        connection.executemany(
            "INSERT INTO alert_types VALUES (?, ?)",
            [(1, "WaterEmpty"), (2, "BeanEmpty")],
        )
        connection.executemany(
            "INSERT INTO alert_log VALUES (?, ?, ?, ?, ?)",
            [
                (1, 1, "2026-01-01 12:00:00", "Tank empty", 0),
                (2, 2, "2026-01-02 12:00:00", "Hopper empty", 0),
                (3, 1, "2026-01-03 12:00:00", "Tank empty", 0),
            ],
        )
        connection.commit()
        connection.close()

    @classmethod
    def _scenario(cls) -> list[dict[str, object]]:
        header = {"token": OWNER}
        cases: list[dict[str, object]] = [
            {"id": "capabilities_ok", "route": "capabilities", "body": {}, "headerToken": OWNER},
            {"id": "capabilities_missing", "route": "capabilities", "body": {}},
            {"id": "capabilities_wrong", "route": "capabilities", "body": {}, "headerToken": "wrong"},
            {"id": "capabilities_body_token", "route": "capabilities", "body": header},
            {"id": "capabilities_mobile", "route": "capabilities", "body": {}, "mobile": True},
            {"id": "token_file_missing", "route": "capabilities", "body": {}, "headerToken": OWNER, "hide_token": True},
            {"id": "token_file_empty", "route": "capabilities", "body": {}, "headerToken": OWNER, "empty_token": True},
            {"id": "machine_ok", "route": "machine", "body": {}, "headerToken": OWNER},
            {"id": "machine_hidden_config", "route": "machine", "body": {}, "headerToken": OWNER, "hide_config": True},
            {"id": "grind_default", "route": "grind_log", "body": {}, "headerToken": OWNER},
            {"id": "grind_offset", "route": "grind_log", "body": {"limit": 2, "offset": 1}, "headerToken": OWNER},
            {"id": "grind_since", "route": "grind_log", "body": {"since": "2026-01-04"}, "headerToken": OWNER},
            {"id": "grind_until", "route": "grind_log", "body": {"until": "2026-01-02"}, "headerToken": OWNER},
            {"id": "grind_window", "route": "grind_log", "body": {"since": "2026-01-02 12:00:00", "until": "2026-01-04 12:00:00"}, "headerToken": OWNER},
            {"id": "grind_invalid_since", "route": "grind_log", "body": {"since": "yesterday"}, "headerToken": OWNER},
            {"id": "grind_inverted", "route": "grind_log", "body": {"since": "2026-01-05", "until": "2026-01-01"}, "headerToken": OWNER},
            {"id": "grind_clamp", "route": "grind_log", "body": {"limit": 99999}, "headerToken": OWNER},
            {"id": "grind_missing", "route": "grind_log", "body": {}, "headerToken": None},
            {"id": "service_offset", "route": "service_log", "body": {"limit": 2, "offset": 1}, "headerToken": OWNER},
            {"id": "service_since", "route": "service_log", "body": {"since": "2026-01-03"}, "headerToken": OWNER},
            {"id": "service_invalid", "route": "service_log", "body": {"until": "nope"}, "headerToken": OWNER},
            {"id": "alert_ok", "route": "alert_log", "body": {"limit": 2}, "headerToken": OWNER},
            {"id": "alert_missing_table", "route": "alert_log", "body": {}, "headerToken": OWNER, "drop_alert_log": True},
            {"id": "portafilters_ok", "route": "portafilters", "body": {}, "headerToken": OWNER},
            {"id": "recipes_ok", "route": "recipes", "body": {}, "headerToken": OWNER},
            {"id": "settings_ok", "route": "settings", "body": {}, "headerToken": OWNER},
            {"id": "config_ok", "route": "config", "body": {}, "headerToken": OWNER},
            {"id": "file_issue", "route": "file", "body": {"path": "/etc/issue"}, "headerToken": OWNER},
            {"id": "file_log", "route": "file", "body": {"path": "/log/sample.log"}, "headerToken": OWNER},
            {"id": "file_binary", "route": "file", "body": {"path": "/log/blob.bin"}, "headerToken": OWNER},
            {"id": "file_traversal", "route": "file", "body": {"path": "/log/../db/HsgConfig.json"}, "headerToken": OWNER},
            {"id": "file_passwd", "route": "file", "body": {"path": "/etc/passwd"}, "headerToken": OWNER},
            {"id": "file_hardlink", "route": "file", "body": {"path": "/log/hardlink"}, "headerToken": OWNER},
            {"id": "file_missing", "route": "file", "body": {}, "headerToken": OWNER},
            {"id": "ws_token", "route": "ws_token", "body": {}, "headerToken": OWNER},
            {"id": "too_large", "route": "capabilities", "body": {}, "headerToken": OWNER, "rawBody": "{" + " " * 20000 + "}"},
            {"id": "unknown_no_token", "route": "not_a_route", "body": {}},
            {"id": "unknown_with_token", "route": "not_a_route", "body": {}, "headerToken": OWNER},
            {"id": "db_missing", "route": "grind_log", "body": {}, "headerToken": OWNER, "hide_db": True},
            {"id": "config_missing", "route": "config", "body": {}, "headerToken": OWNER, "hide_config": True},
        ]
        cases.extend(cls._action_scenario())
        # The token gate is global; still assert it before every route's handler.
        for route in SimulatedLocalApi.ROUTES:
            cases.append({"id": f"{route}_auth_missing", "route": route, "body": {}, "headerToken": None})
            cases.append({"id": f"{route}_auth_wrong", "route": route, "body": {}, "headerToken": "wrong"})
        return cases

    @classmethod
    def _action_scenario(cls) -> list[dict[str, object]]:
        """Action-layer cases.

        Order matters: the gate-off cases run before a policy exists, then a
        prepare/execute pair and its failure modes, then the destructive pair.
        Every case that mutates durable state resets it first.
        """
        owner = {"headerToken": OWNER}
        cases: list[dict[str, object]] = [
            # -- gate ------------------------------------------------------
            {"id": "action_gate_missing", "route": "action_prepare", "policyMissing": True,
             "body": {"route": "action_grind_stop", "params": {}, "requestId": "gate-0001"}, **owner},
            {"id": "action_gate_invalid", "route": "action_prepare", "policyInvalid": True,
             "body": {"route": "action_grind_stop", "params": {}, "requestId": "gate-0002"}, **owner},
            {"id": "action_gate_disabled", "route": "action_prepare",
             "policy": {**action_policy(), "enabled": False},
             "body": {"route": "action_grind_stop", "params": {}, "requestId": "gate-0003"}, **owner},
            {"id": "action_status_gate_off", "route": "action_status", "policyMissing": True,
             "body": {"actionId": "00000000-0000-4000-8000-000000000000"}, **owner},

            # -- catalog ---------------------------------------------------
            {"id": "action_capabilities_off", "route": "capabilities", "policyMissing": True, "body": {}, **owner},
            {"id": "action_capabilities_on", "route": "capabilities", "policy": action_policy(), "body": {}, **owner},
            {"id": "action_capabilities_destructive_on", "route": "capabilities",
             "policy": action_policy(destructive=True), "body": {}, **owner},
            {"id": "action_capabilities_gate_reset", "route": "capabilities",
             "policy": action_policy(), "body": {}, **owner},

            # -- prepare / execute happy path (wss) ------------------------
            {"id": "action_reset_1", "route": "__reset_actions", "body": {}, **owner},
            {"id": "action_wss_idle_1", "route": "__wss_state",
             "body": {"grindState": "Idle", "ddValueDum": 5000, "setupWizardState": "Completed"}, **owner},
            {"id": "action_prepare_ok", "route": "action_prepare", "policy": action_policy(),
             "body": {"route": "action_grind_start_gbw", "params": {"targetWeightGr": 18.0},
                      "requestId": "happy-0001"},
             "capture": "prep", **owner},
            {"id": "action_status_prepared", "route": "action_status",
             "body": {"actionId": "@prep.data.actionId"}, **owner},
            {"id": "action_execute_ok", "route": "action_execute",
             "body": {"actionId": "@prep.data.actionId", "confirmToken": "@prep.data.confirmToken"},
             "capture": "exec", **owner},
            {"id": "action_status_completed", "route": "action_status",
             "body": {"actionId": "@prep.data.actionId"}, **owner},
            {"id": "action_wss_log", "route": "__wss_log", "body": {}, **owner},

            # -- replay, tamper, expiry -----------------------------------
            {"id": "action_replay", "route": "action_execute",
             "body": {"actionId": "@prep.data.actionId", "confirmToken": "@prep.data.confirmToken"}, **owner},
            {"id": "action_tamper_token", "route": "action_prepare",
             "body": {"route": "action_settings_set", "params": {"settings": {"System.UseAmPm": True}},
                      "requestId": "tamper-0001"},
             "capture": "tamper", **owner},
            {"id": "action_tamper_execute", "route": "action_execute",
             "body": {"actionId": "@tamper.data.actionId", "confirmToken": "0000000000000000000000000000000000000000000000000000000000000000"},
             "capture": "tampered", **owner},
            {"id": "action_tamper_record", "route": "__tamper_params",
             "body": {"actionId": "@tamper.data.actionId"}, **owner},
            {"id": "action_tamper_integrity", "route": "action_execute",
             "body": {"actionId": "@tamper.data.actionId", "confirmToken": "@tamper.data.confirmToken"}, **owner},
            {"id": "action_expire_prepare", "route": "action_prepare",
             "body": {"route": "action_language_set", "params": {"language": "de"},
                      "requestId": "expire-0001"},
             "capture": "exp", **owner},
            {"id": "action_expire_mark", "route": "__expire", "body": {"actionId": "@exp.data.actionId"}, **owner},
            {"id": "action_expire_execute", "route": "action_execute",
             "body": {"actionId": "@exp.data.actionId", "confirmToken": "@exp.data.confirmToken"}, **owner},

            # -- policy can narrow a bound but never widen it -------------
            {"id": "action_bounds_widen_attempt", "route": "action_prepare",
             "policy": {**action_policy(), "bounds": {"targetWeightGr": {"min": 0.1, "max": 999.0}}},
             "body": {"route": "action_grind_start_gbw", "params": {"targetWeightGr": 60.0},
                      "requestId": "widen-0001"}, **owner},
            {"id": "action_bounds_narrow", "route": "action_prepare",
             "policy": {**action_policy(), "bounds": {"targetWeightGr": {"min": 0.1, "max": 10.0}}},
             "body": {"route": "action_grind_start_gbw", "params": {"targetWeightGr": 18.0},
                      "requestId": "narrow-0001"}, **owner},
            {"id": "action_bounds_narrow_ok", "route": "action_prepare",
             "policy": {**action_policy(), "bounds": {"targetWeightGr": {"min": 0.1, "max": 10.0}}},
             "body": {"route": "action_grind_start_gbw", "params": {"targetWeightGr": 9.5},
                      "requestId": "narrow-0002"}, **owner},

            {"id": "action_bounds_invert_target", "route": "action_prepare",
             "policy": {**action_policy(), "bounds": {"targetWeightGr": {"min": 60.0, "max": 60.0}}},
             "body": {"route": "action_grind_start_gbw", "params": {"targetWeightGr": 60.0},
                      "requestId": "invert-0001"}, **owner},
            {"id": "action_bounds_invert_manual", "route": "action_prepare",
             "policy": {**action_policy(), "bounds": {"manualGrindMs": {"min": 60000, "max": 60000}}},
             "body": {"route": "action_grind_start_manual", "params": {"durationMs": 60000},
                      "requestId": "invert-0002"}, **owner},

            # -- validation and refusals ----------------------------------
            {"id": "action_bounds_low", "route": "action_prepare",
             "body": {"route": "action_grind_start_gbw", "params": {"targetWeightGr": 0.05},
                      "requestId": "bounds-0001"}, **owner},
            {"id": "action_unknown", "route": "action_prepare",
             "body": {"route": "action_does_not_exist", "params": {}, "requestId": "unknown-0001"}, **owner},
            {"id": "action_esp_reset", "route": "action_prepare",
             "body": {"route": "action_esp_reset", "params": {}, "requestId": "esp-0001"}, **owner},
            # Names outside the boundary regex must still be unknown, so the
            # regex is not the only thing standing between a caller and the
            # runner.
            {"id": "action_nvs_write", "route": "action_prepare",
             "body": {"route": "action_nvs_write", "params": {}, "requestId": "esp-0002"}, **owner},
            {"id": "action_nozzle_light", "route": "action_prepare",
             "body": {"route": "action_nozzle_light_run", "params": {}, "requestId": "esp-0003"}, **owner},
            {"id": "action_ota_update", "route": "action_prepare",
             "body": {"route": "action_ota_update", "params": {}, "requestId": "esp-0004"}, **owner},
            # Device-shaped names that the owner surface does not expose.
            {"id": "action_mqtt_publish", "route": "action_prepare",
             "body": {"route": "action_mqtt_publish", "params": {}, "requestId": "esp-0005"}, **owner},
            {"id": "action_dropbear_enable", "route": "action_prepare",
             "body": {"route": "action_dropbear_enable", "params": {}, "requestId": "esp-0006"}, **owner},
            # Credential writes are excluded; the refusal is name-based, so a
            # generic credential name covers the whole class without naming a
            # removed action.
            {"id": "action_credential", "route": "action_prepare",
             "body": {"route": "action_credential_write", "params": {}, "requestId": "cred-0001"}, **owner},
            {"id": "action_bare_path", "route": "action_grind_start_gbw", "body": {}, **owner},
            {"id": "action_bare_esp_path", "route": "action_esp_flash", "body": {}, **owner},

            # -- unsafe state ---------------------------------------------
            {"id": "action_wss_busy", "route": "__wss_state",
             "body": {"grindState": "Grind", "ddValueDum": 5000, "setupWizardState": "Completed"}, **owner},
            # Reset the policy: the bounds cases above leave a narrowed cap behind.
            {"id": "action_unsafe_state", "route": "action_prepare", "policy": action_policy(),
             "body": {"route": "action_grind_start_gbw", "params": {"targetWeightGr": 18.0},
                      "requestId": "unsafe-0001"}, **owner},
            {"id": "action_wss_idle_2", "route": "__wss_state",
             "body": {"grindState": "Idle", "ddValueDum": 5000, "setupWizardState": "Completed"}, **owner},

            # -- destructive gate -----------------------------------------
            {"id": "action_capabilities_destructive_off", "route": "capabilities",
             "policy": action_policy(destructive=False), "body": {}, **owner},
            {"id": "action_destructive_off", "route": "action_prepare", "policy": action_policy(destructive=False),
             "body": {"route": "action_recipe_delete", "params": {"recipeIndex": 2},
                      "requestId": "destroy-0001"}, **owner},
            {"id": "action_destructive_on", "route": "action_prepare",
             "policy": action_policy(destructive=True),
             "body": {"route": "action_recipe_delete", "params": {"recipeIndex": 2},
                      "requestId": "destroy-0002"},
             "capture": "destroy", **owner},
            {"id": "action_destructive_execute", "route": "action_execute",
             "body": {"actionId": "@destroy.data.actionId", "confirmToken": "@destroy.data.confirmToken"}, **owner},

            {"id": "action_claim_prepare", "route": "action_prepare",
             "body": {"route": "action_language_set", "params": {"language": "it"},
                      "requestId": "claim-0001"},
             "capture": "claim", **owner},
            {"id": "action_claim_first", "route": "__claim",
             "body": {"actionId": "@claim.data.actionId"}, **owner},
            {"id": "action_claim_second", "route": "__claim",
             "body": {"actionId": "@claim.data.actionId"}, **owner},
            {"id": "action_claim_execute", "route": "action_execute",
             "body": {"actionId": "@claim.data.actionId", "confirmToken": "@claim.data.confirmToken"}, **owner},

            # -- rate limit (own bucket, reset first) ---------------------
            {"id": "action_rate_reset", "route": "__reset_rate", "body": {}, **owner},
            {"id": "action_rate_prepare_1", "route": "action_prepare",
             "policy": action_policy(rates={"display": {"perMinute": 1, "perHour": 1}}),
             "body": {"route": "action_display_backlight", "params": {"brightness": 40},
                      "requestId": "rate-0001"}, **owner},
            {"id": "action_rate_prepare_2", "route": "action_prepare",
             "body": {"route": "action_display_backlight", "params": {"brightness": 41},
                      "requestId": "rate-0002"}, **owner},

            # -- monotonic rate limiting ----------------------------------
            # Pin the monotonic seam, fill one bucket, then turn the clock
            # backwards.  The stored event becomes "future" and the bucket must
            # be refused, never pruned, so the window cannot be wiped.
            {"id": "action_mono_clock_pin", "route": "__clock",
             "body": {"ms": 5000000}, **owner},
            {"id": "action_mono_rate_reset", "route": "__reset_rate", "body": {}, **owner},
            {"id": "action_mono_prepare_1", "route": "action_prepare",
             "policy": action_policy(rates={"display": {"perMinute": 1, "perHour": 1}}),
             "body": {"route": "action_display_backlight", "params": {"brightness": 41},
                      "requestId": "mono-0001"}, **owner},
            {"id": "action_mono_read", "route": "__rate_read", "body": {"bucket": "display"}, **owner},
            {"id": "action_mono_prepare_2", "route": "action_prepare",
             "body": {"route": "action_display_backlight", "params": {"brightness": 42},
                      "requestId": "mono-0002"}, **owner},
            {"id": "action_mono_clock_back", "route": "__clock",
             "body": {"ms": 4900000}, **owner},
            {"id": "action_mono_prepare_future", "route": "action_prepare",
             "body": {"route": "action_display_backlight", "params": {"brightness": 43},
                      "requestId": "mono-0003"}, **owner},
            {"id": "action_mono_legacy_file", "route": "__rate_file",
             "body": {"bucket": "display", "raw": "[1767225600]"}, **owner},
            {"id": "action_mono_legacy_prepare", "route": "action_prepare",
             "body": {"route": "action_display_backlight", "params": {"brightness": 44},
                      "requestId": "mono-0004"}, **owner},
            {"id": "action_mono_corrupt_file", "route": "__rate_file",
             "body": {"bucket": "display", "raw": "{not json"}, **owner},
            {"id": "action_mono_corrupt_prepare", "route": "action_prepare",
             "body": {"route": "action_display_backlight", "params": {"brightness": 45},
                      "requestId": "mono-0005"}, **owner},
            {"id": "action_mono_other_boot_file", "route": "__rate_file",
             "body": {"bucket": "display", "json": {
                 "schema": "e64local-action-rate-v2",
                 "bootId": "11111111-1111-4111-8111-111111111111",
                 "events": [4999999, 4999998]}}, **owner},
            {"id": "action_mono_other_boot_prepare", "route": "action_prepare",
             "body": {"route": "action_display_backlight", "params": {"brightness": 46},
                      "requestId": "mono-0006"}, **owner},
            {"id": "action_mono_clock_restore", "route": "__clock", "body": {"reset": True}, **owner},
            {"id": "action_mono_rate_restore", "route": "__reset_rate", "body": {}, **owner},

            # -- boot binding ---------------------------------------------
            {"id": "action_boot_prepare_1", "route": "action_prepare", "policy": action_policy(),
             "body": {"route": "action_language_set", "params": {"language": "pl"},
                      "requestId": "boot-0001"},
             "capture": "boot1", **owner},
            {"id": "action_boot_other", "route": "__boot_id",
             "body": {"id": "11111111-1111-4111-8111-111111111111"}, **owner},
            {"id": "action_boot_execute_other", "route": "action_execute",
             "body": {"actionId": "@boot1.data.actionId", "confirmToken": "@boot1.data.confirmToken"},
             **owner},
            {"id": "action_boot_status_after", "route": "action_status",
             "body": {"actionId": "@boot1.data.actionId"}, **owner},
            # Retrying the dead requestId in the new boot must prepare a fresh
            # action, not hand back the token that can never execute.
            {"id": "action_boot_reprepare", "route": "action_prepare",
             "body": {"route": "action_language_set", "params": {"language": "pl"},
                      "requestId": "boot-0001"},
             "capture": "boot1b", **owner},
            {"id": "action_boot_reprepare_execute", "route": "action_execute",
             "body": {"actionId": "@boot1b.data.actionId", "confirmToken": "@boot1b.data.confirmToken"},
             **owner},
            {"id": "action_boot_prepare_2", "route": "action_prepare",
             "body": {"route": "action_language_set", "params": {"language": "nl"},
                      "requestId": "boot-0002"},
             "capture": "boot2", **owner},
            {"id": "action_boot_unreadable", "route": "__boot_id",
             "body": {"unreadable": True}, **owner},
            {"id": "action_boot_unreadable_prepare", "route": "action_prepare",
             "body": {"route": "action_language_set", "params": {"language": "es"},
                      "requestId": "boot-0003"}, **owner},
            {"id": "action_boot_unreadable_execute", "route": "action_execute",
             "body": {"actionId": "@boot2.data.actionId", "confirmToken": "@boot2.data.confirmToken"},
             **owner},
            {"id": "action_boot_status_unreadable", "route": "action_status",
             "body": {"actionId": "@boot2.data.actionId"}, **owner},
            {"id": "action_boot_restore", "route": "__boot_id", "body": {"reset": True}, **owner},
            {"id": "action_boot_after_restore_execute", "route": "action_execute",
             "body": {"actionId": "@boot2.data.actionId", "confirmToken": "@boot2.data.confirmToken"},
             **owner},
            {"id": "action_boot_normal_prepare", "route": "action_prepare",
             "body": {"route": "action_language_set", "params": {"language": "tr"},
                      "requestId": "boot-0004"},
             "capture": "boot3", **owner},
            {"id": "action_boot_normal_execute", "route": "action_execute",
             "body": {"actionId": "@boot3.data.actionId", "confirmToken": "@boot3.data.confirmToken"},
             **owner},

            # -- audit read -----------------------------------------------
            {"id": "action_audit_read", "route": "action_audit", "body": {"limit": 1000}, **owner},
        ]
        return cases

    @classmethod
    def _run_harness(cls, root: Path) -> dict[str, dict[str, object]]:
        script = """
set -eu
mkdir -p /db/e64local /log /tmp /usr/local/bin
cp /work/bin/sudo /usr/bin/sudo
cp /work/bin/sqlite3 /usr/bin/sqlite3
cp /work/runner.php /usr/local/bin/e64local-action-run
chmod 755 /usr/bin/sudo /usr/bin/sqlite3 /usr/local/bin/e64local-action-run
cp /work/db/HsgSqlite.db /db/HsgSqlite.db
cp /work/db/HsgConfig.json /db/HsgConfig.json
cp /work/etc_issue /etc/issue
cp /work/tmp_state.json /tmp/FirmwareUpdateState.json
cp /work/log_sample.log /log/sample.log
printf '\\000\\001\\377binary' > /log/blob.bin
ln -sf /etc/passwd /log/link
ln /db/HsgConfig.json /log/hardlink
printf 'harness-owner-token\\n' > /db/e64local/token
chmod 600 /db/e64local/token
chmod +x /work/bin/sudo

# Loopback WSS fixture the bounded runner connects to for wss actions.
printf '{"grindState":"Idle","ddValueDum":5000,"setupWizardState":"Completed"}' > /work/state.json
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
            [
                "docker", "run", "--rm",
                "-v", f"{root}:/work",
                DOCKER_IMAGE, "sh", "-c", script,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"PHP harness failed ({result.returncode}):\n{result.stderr}\n{result.stdout}"
            )
        outcomes: dict[str, dict[str, object]] = {}
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            outcome = json.loads(line)
            outcomes[outcome["id"]] = outcome
        return outcomes

    def outcome(self, case_id: str) -> dict[str, object]:
        self.assertIn(case_id, self.results, sorted(self.results))
        return self.results[case_id]

    def payload(self, case_id: str) -> dict[str, object]:
        return self.outcome(case_id)["json"]  # type: ignore[return-value]

    # -- module behaviour -------------------------------------------------

    def test_php_module_lints(self) -> None:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{MODULE}:/module.php:ro",
                DOCKER_IMAGE, "php", "-l", "/module.php",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_php_dev_gate_fails_closed(self) -> None:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{self.root}:/work",
                DOCKER_IMAGE, "php", "/work/dev_gate.php",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(result.stdout)
        self.assertEqual(body["errorCode"], 403)
        self.assertFalse(body["success"])

    def test_php_capabilities_and_auth(self) -> None:
        payload = self.payload("capabilities_ok")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["data"]["apiVersion"], "1")
        self.assertEqual(set(payload["data"]["routes"]), set(SimulatedLocalApi.ROUTES))
        self.assertFalse(payload["data"]["features"]["actions"])

        for case_id in ("capabilities_missing", "capabilities_wrong"):
            with self.subTest(case=case_id):
                payload = self.payload(case_id)
                self.assertFalse(payload["success"])
                self.assertEqual(payload["errorCode"], 401)
        self.assertTrue(self.payload("capabilities_body_token")["success"])

        payload = self.payload("capabilities_mobile")
        self.assertEqual(payload["errorCode"], 403)

        for case_id in ("token_file_missing", "token_file_empty"):
            with self.subTest(case=case_id):
                payload = self.payload(case_id)
                self.assertFalse(payload["success"])
                self.assertEqual(payload["errorCode"], 401)
                self.assertIn("not configured", payload["error"])

    def test_php_every_route_requires_the_owner_token(self) -> None:
        for route in SimulatedLocalApi.ROUTES:
            for suffix in ("auth_missing", "auth_wrong"):
                with self.subTest(route=route, token=suffix):
                    payload = self.payload(f"{route}_{suffix}")
                    self.assertFalse(payload["success"])
                    self.assertEqual(payload["errorCode"], 401)

    def test_php_machine_hashes_serial(self) -> None:
        payload = self.payload("machine_ok")
        data = payload["data"]
        self.assertEqual(data["serialSha256"], hashlib.sha256(b"HMI12345678").hexdigest())
        self.assertTrue(data["serialPresent"])
        self.assertNotIn("HMI12345678", json.dumps(data))
        self.assertEqual(data["model"], "E64 WS")
        self.assertEqual(data["variant"], "Hsg")

        payload = self.payload("machine_hidden_config")
        self.assertEqual(payload["errorCode"], 500)

    def test_php_grind_log_pagination_and_filters(self) -> None:
        default = self.payload("grind_default")["data"]
        self.assertEqual([row["grind_id"] for row in default["rows"]], ["5", "4", "3", "2", "1"])
        self.assertEqual(default["count"], 5)
        self.assertEqual(default["limit"], 20)
        self.assertEqual(default["offset"], 0)

        offset = self.payload("grind_offset")["data"]
        self.assertEqual([row["grind_id"] for row in offset["rows"]], ["4", "3"])
        self.assertEqual(offset["offset"], 1)
        self.assertTrue(offset["hasMore"])

        since = self.payload("grind_since")["data"]
        self.assertEqual([row["grind_id"] for row in since["rows"]], ["5", "4"])
        self.assertEqual(since["since"], "2026-01-04 00:00:00")

        until = self.payload("grind_until")["data"]
        self.assertEqual([row["grind_id"] for row in until["rows"]], ["2", "1"])
        self.assertEqual(until["until"], "2026-01-02 23:59:59")

        window = self.payload("grind_window")["data"]
        self.assertEqual([row["grind_id"] for row in window["rows"]], ["4", "3", "2"])

        self.assertEqual(self.payload("grind_invalid_since")["errorCode"], 400)
        self.assertEqual(self.payload("grind_inverted")["errorCode"], 400)
        self.assertEqual(self.payload("grind_clamp")["data"]["limit"], 5000)
        self.assertEqual(self.payload("grind_missing")["errorCode"], 401)

    def test_php_service_and_alert_routes(self) -> None:
        service = self.payload("service_offset")["data"]
        self.assertEqual([row["event_id"] for row in service["rows"]], ["4", "3"])
        self.assertEqual(service["offset"], 1)
        self.assertEqual(self.payload("service_invalid")["errorCode"], 400)

        alert = self.payload("alert_ok")["data"]
        self.assertEqual([row["alert_id"] for row in alert["rows"]], ["3", "2"])
        missing = self.payload("alert_missing_table")
        self.assertTrue(missing["success"])
        self.assertEqual(missing["data"]["count"], 0)
        self.assertIn("note", missing["data"])

    def test_php_portafilters_and_recipes(self) -> None:
        portafilters = self.payload("portafilters_ok")["data"]
        self.assertEqual(portafilters["count"], 1)
        self.assertEqual(portafilters["rows"][0]["weight"], "0")

        recipes = self.payload("recipes_ok")["data"]
        self.assertEqual(recipes["count"], 2)
        self.assertEqual(recipes["rows"][0]["recipe_amount"], "18000")
        self.assertEqual(recipes["rows"][0]["recipe_mode"], "GbW")

    def test_php_settings_and_config_redaction(self) -> None:
        settings = self.payload("settings_ok")["data"]
        encoded = json.dumps(settings)
        self.assertNotIn("should-not-appear", encoded)
        self.assertNotIn("sim-wifi-secret", encoded)
        self.assertNotIn("Role.Owner.LoginData", settings["settings"])
        self.assertIn("Role.Owner.LoginData", settings["redacted"])
        self.assertEqual(settings["settings"]["Role.OwnerPasswordProtectionEnabled"], "true")

        config = self.payload("config_ok")["data"]
        encoded = json.dumps(config)
        self.assertEqual(config["config"]["productionWifiPassword"], "<redacted>")
        self.assertEqual(config["config"]["productionWifiSsid"], "<redacted>")
        self.assertEqual(config["config"]["cloudBaseUrl"], "<redacted>")
        self.assertEqual(config["config"]["grinderSn"], "<redacted>")
        self.assertEqual(config["config"]["nested"]["password"], "<redacted>")
        self.assertEqual(config["config"]["nested"]["keep"], "ok")
        self.assertIn("grinderSn", config["redacted"])
        self.assertIn("nested.serial", config["redacted"])
        self.assertNotIn("factory-secret", encoded)
        self.assertNotIn("nested-secret", encoded)
        self.assertNotIn("HMI12345678", encoded)
        self.assertNotIn("NESTED-WRONG", encoded)
        self.assertNotIn("https://cloud.example", encoded)

    def test_php_file_allowlist_and_redaction(self) -> None:
        issue = self.payload("file_issue")["data"]
        self.assertEqual(issue["encoding"], "text")
        self.assertNotIn("192.168.1.5", issue["content"])
        self.assertIn("<redacted>", issue["content"])

        log = self.payload("file_log")["data"]
        encoded = json.dumps(log)
        self.assertEqual(log["encoding"], "text")
        for secret in ("file-secret", "192.168.1.5", "02:00:5e:10:00:01", "000000123456"):
            self.assertNotIn(secret, encoded)
        self.assertIn("<redacted>", log["content"])

        binary = self.payload("file_binary")["data"]
        self.assertEqual(binary["encoding"], "base64")
        self.assertEqual(binary["content"], "AAH/YmluYXJ5")

        for case_id in ("file_traversal", "file_passwd", "file_hardlink", "file_missing"):
            with self.subTest(case=case_id):
                self.assertEqual(self.payload(case_id)["errorCode"], 400)

    def test_php_ws_token_and_limits(self) -> None:
        token = self.payload("ws_token")["data"]
        self.assertEqual(token["token"], "harness-ws-token")
        self.assertIn("warning", token)

        too_large = self.payload("too_large")
        self.assertEqual(too_large["errorCode"], 413)

        self.assertTrue(self.outcome("unknown_no_token")["handled"])
        self.assertEqual(self.payload("unknown_no_token")["errorCode"], 401)
        self.assertFalse(self.outcome("unknown_with_token")["handled"])
        self.assertEqual(self.payload("db_missing")["errorCode"], 500)
        self.assertEqual(self.payload("config_missing")["errorCode"], 500)

    # -- gated action layer ------------------------------------------------

    def test_php_action_gate_fails_closed(self) -> None:
        for case_id, reason in (
            ("action_gate_missing", "missing"),
            ("action_gate_invalid", "not valid JSON"),
            ("action_gate_disabled", "invalid or unsupported"),
            ("action_status_gate_off", "missing"),
        ):
            with self.subTest(case=case_id):
                payload = self.payload(case_id)
                self.assertFalse(payload["success"])
                self.assertEqual(payload["errorCode"], 403)
                self.assertIn(reason, payload["error"])

    def test_php_action_catalog_excludes_esp_and_credentials(self) -> None:
        off = self.payload("action_capabilities_off")["data"]
        self.assertFalse(off["actions"]["enabled"])
        self.assertEqual(off["actions"]["actionRoutes"], [])

        on = self.payload("action_capabilities_destructive_off")["data"]
        self.assertTrue(on["actions"]["enabled"])
        self.assertFalse(on["actions"]["destructiveEnabled"])
        self.assertIn("action_prepare", on["routes"])
        catalog = {entry["route"]: entry for entry in on["actions"]["catalog"]}
        # The removed owner decisions: no credential writes, no ESP-side driver.
        for route in catalog:
            self.assertNotRegex(route, r"action_(role|password|credential|login)_")
        self.assertNotIn("action_nozzle_light", catalog)
        for route, entry in catalog.items():
            self.assertNotRegex(route, r"^action_(esp|wifi|firmware|fuse|otp|bootloader|pairing|onboarding|cloud)_")
            self.assertIn(entry["status"], ("implemented", "unavailable"))
            self.assertTrue(entry["evidence"])
            if entry["status"] == "unavailable":
                self.assertTrue(entry["reason"])
        implemented = [r for r, e in catalog.items() if e["status"] == "implemented"]
        advertised = [r for r, e in catalog.items() if e["status"] == "implemented" and not e["destructive"]]
        self.assertEqual(sorted(on["actions"]["actionRoutes"]), sorted(advertised))
        self.assertEqual(
            sorted(r for r, e in catalog.items() if "blocked" in e),
            sorted(r for r, e in catalog.items() if e["status"] == "implemented" and e["destructive"]),
        )
        self.assertGreaterEqual(len(implemented), 20)

    def test_php_action_capabilities_hide_destructive_routes(self) -> None:
        # With the second gate off, capabilities must not advertise a route the
        # gate would refuse as dispatchable.
        off = self.payload("action_capabilities_destructive_off")["data"]["actions"]
        self.assertFalse(off["destructiveEnabled"])
        advertised = set(off["actionRoutes"])
        destructive = {
            entry["route"] for entry in off["catalog"]
            if entry["status"] == "implemented" and entry["destructive"]
        }
        self.assertTrue(destructive)
        self.assertEqual(destructive & advertised, set())
        self.assertEqual(
            {entry["route"] for entry in off["catalog"] if "blocked" in entry}, destructive
        )

        on = self.payload("action_capabilities_destructive_on")["data"]["actions"]
        self.assertTrue(on["destructiveEnabled"])
        self.assertTrue(destructive <= set(on["actionRoutes"]))
        self.assertEqual([e for e in on["catalog"] if "blocked" in e], [])

    def test_php_action_prepare_execute_happy_path(self) -> None:
        prepared = self.payload("action_prepare_ok")["data"]
        self.assertEqual(prepared["route"], "action_prepare")
        self.assertEqual(prepared["actionRoute"], "action_grind_start_gbw")
        self.assertEqual(prepared["state"], "prepared")
        self.assertRegex(prepared["confirmToken"], r"^[0-9a-f]{64}$")

        status = self.payload("action_status_prepared")["data"]
        self.assertEqual(status["state"], "prepared")

        executed = self.payload("action_execute_ok")["data"]
        self.assertEqual(executed["state"], "completed")
        self.assertEqual(executed["result"]["command"], "StartGrindGbw")

        completed = self.payload("action_status_completed")["data"]
        self.assertEqual(completed["state"], "completed")

        # The runner really sent the vendor command over the loopback WSS surface.
        frames = self.payload("action_wss_log")["data"]["frames"]
        action_types = [
            frame.get("data", {}).get("actionType")
            for frame in frames
            if frame.get("type") == "GrinderAction"
        ]
        self.assertEqual(action_types, ["StartGrindGbw"])
        target = [f["data"] for f in frames if f["type"] == "GrinderAction"][0]
        self.assertEqual(target["targetWeightGr"], 18)

    def test_php_action_replay_is_rejected(self) -> None:
        payload = self.payload("action_replay")
        self.assertEqual(payload["errorCode"], 409)
        self.assertEqual(payload["error"], "action is not in a state that allows execute")

    def test_php_action_expiry_is_rejected(self) -> None:
        self.assertLess(self.payload("action_expire_mark")["data"]["expires"], time.time())
        payload = self.payload("action_expire_execute")
        self.assertEqual(payload["errorCode"], 409)
        self.assertEqual(payload["error"], "the confirm token has expired")

    def test_php_action_hmac_tamper_is_rejected(self) -> None:
        bad_token = self.payload("action_tamper_execute")
        self.assertEqual(bad_token["errorCode"], 403)
        self.assertEqual(bad_token["error"], "confirm token does not match this action")

        # A record edited outside the protocol fails its integrity check.
        tampered = self.payload("action_tamper_integrity")
        self.assertEqual(tampered["errorCode"], 500)
        self.assertEqual(
            tampered["error"], "the prepared action record failed its integrity check"
        )

    def test_php_action_policy_narrows_but_never_widens(self) -> None:
        # A policy that asks for 999 g still refuses 60 g: the absolute cap wins.
        widen = self.payload("action_bounds_widen_attempt")
        self.assertEqual(widen["errorCode"], 422)
        self.assertEqual(widen["error"], "targetWeightGr must be between 0.1 and 50")
        # A policy that narrows to 10 g refuses 18 g ...
        narrow = self.payload("action_bounds_narrow")
        self.assertEqual(narrow["errorCode"], 422)
        self.assertEqual(narrow["error"], "targetWeightGr must be between 0.1 and 10")
        # ... and accepts 9.5 g, which is inside the narrowed range.
        self.assertTrue(self.payload("action_bounds_narrow_ok")["success"])

    def test_php_action_policy_cannot_invert_a_bound(self) -> None:
        # A policy whose minimum sits above the absolute maximum would invert
        # the range; the module clamps both ends back into the absolute range.
        low = self.payload("action_bounds_invert_target")
        self.assertEqual(low["errorCode"], 422)
        self.assertEqual(low["error"], "targetWeightGr must be between 0.1 and 50")
        manual = self.payload("action_bounds_invert_manual")
        self.assertEqual(manual["errorCode"], 422)
        self.assertEqual(manual["error"], "durationMs must be between 100 and 5000")

    def test_php_action_bounds_unknown_and_boundary(self) -> None:
        self.assertEqual(self.payload("action_bounds_low")["errorCode"], 422)
        self.assertEqual(self.payload("action_unknown")["errorCode"], 404)

        esp = self.payload("action_esp_reset")
        self.assertEqual(esp["errorCode"], 403)
        self.assertEqual(
            esp["error"],
            "ESP, WiFi, firmware, fuse and bootloader operations are outside this API by construction",
        )

        # Names the boundary regex does not list are still refused: the catalog
        # is the only source of dispatchable actions.
        for case_id in (
            "action_nvs_write", "action_nozzle_light", "action_ota_update",
            "action_mqtt_publish", "action_dropbear_enable",
        ):
            with self.subTest(case=case_id):
                payload = self.payload(case_id)
                self.assertEqual(payload["errorCode"], 404)
                self.assertEqual(payload["error"], "unknown action")
                self.assertNotIn("action_", payload["error"].replace("unknown action", ""))

        credential = self.payload("action_credential")
        self.assertEqual(credential["errorCode"], 403)
        self.assertEqual(
            credential["error"], "credential-bearing operations are outside this API by owner decision"
        )

        # A bare POST to an action name never actuates anything.
        bare = self.payload("action_bare_path")
        self.assertEqual(bare["errorCode"], 404)
        self.assertEqual(bare["error"], "action identifiers are not HTTP paths; use action_prepare")
        self.assertEqual(self.payload("action_bare_esp_path")["errorCode"], 403)

    def test_php_action_unsafe_state_is_refused(self) -> None:
        payload = self.payload("action_unsafe_state")
        self.assertEqual(payload["errorCode"], 409)
        self.assertEqual(payload["error"], "the grinder is not idle (grindState=Grind)")
        # The refusal happens before any vendor command is sent.
        frames = self.payload("action_wss_log")["data"]["frames"]
        action_types = [
            frame.get("data", {}).get("actionType")
            for frame in frames
            if frame.get("type") == "GrinderAction"
        ]
        self.assertNotIn("StartGrindGbt", action_types)

    def test_php_action_destructive_gate(self) -> None:
        off = self.payload("action_destructive_off")
        self.assertEqual(off["errorCode"], 403)
        self.assertEqual(
            off["error"], "destructive actions are disabled; re-deploy with --enable-destructive-actions"
        )

        executed = self.payload("action_destructive_execute")["data"]
        self.assertEqual(executed["state"], "completed")
        self.assertEqual(executed["result"]["recipeIndex"], 2)

    def test_php_action_claim_is_single_use(self) -> None:
        # The prepared -> executing transition is atomic: the second claimant
        # (a concurrent execute with the same token) is refused, and the record
        # stays in "executing" so a third request cannot actuate either.
        first = self.payload("action_claim_first")["data"]
        self.assertEqual(first["claim"]["state"], "executing")
        second = self.payload("action_claim_second")["data"]
        self.assertIsNone(second["claim"])
        self.assertEqual(second["code"], 409)
        self.assertEqual(second["error"], "action is not in a state that allows execute")
        executed = self.payload("action_claim_execute")
        self.assertEqual(executed["errorCode"], 409)
        self.assertEqual(executed["error"], "action is not in a state that allows execute")

    def test_php_action_rate_limit(self) -> None:
        self.assertTrue(self.payload("action_rate_prepare_1")["success"])
        limited = self.payload("action_rate_prepare_2")
        self.assertEqual(limited["errorCode"], 429)
        self.assertEqual(
            limited["error"],
            f"rate limit exceeded; retry after {limited['retryAfter']} seconds",
        )
        self.assertGreaterEqual(limited["retryAfter"], 1)
        self.assertLessEqual(limited["retryAfter"], 60)

    def test_php_action_rate_limit_uses_monotonic_time(self) -> None:
        # The stored event is monotonic milliseconds, not a wall-clock epoch.
        state = self.payload("action_mono_read")["data"]
        self.assertEqual(state["state"]["schema"], "e64local-action-rate-v2")
        self.assertEqual(state["state"]["bootId"], state["bootId"])
        self.assertEqual(state["state"]["events"], [5000000])
        self.assertLess(state["state"]["events"][0], 10**10)

        self.assertEqual(self.payload("action_mono_prepare_1")["errorCode"], 0)
        limited = self.payload("action_mono_prepare_2")
        self.assertEqual(limited["errorCode"], 429)

    def test_php_action_rate_limit_fails_closed(self) -> None:
        # The clock stepped backwards by 100 s: the stored event is now in the
        # future, so the bucket is unusable and the request is refused instead
        # of being pruned (which would silently reset the window).
        future = self.payload("action_mono_prepare_future")
        self.assertEqual(future["errorCode"], 503)
        self.assertEqual(
            future["error"],
            "rate-limit state is unavailable; refusing rather than exceeding the limit: "
            "rate-limit state is unusable",
        )

        # A bucket left by the pre-monotonic release holds wall-clock epochs.
        legacy = self.payload("action_mono_legacy_prepare")
        self.assertEqual(legacy["errorCode"], 503)
        self.assertIn("rate-limit state is unusable", legacy["error"])

        corrupt = self.payload("action_mono_corrupt_prepare")
        self.assertEqual(corrupt["errorCode"], 503)
        self.assertIn("rate-limit state is unusable", corrupt["error"])

        # A bucket from another boot starts a fresh window instead of locking
        # every action out after a reboot.
        other = self.payload("action_mono_other_boot_prepare")
        self.assertTrue(other["success"], other)

    def test_php_action_token_is_boot_bound(self) -> None:
        # A token prepared in this boot cannot be executed in another one.
        other = self.payload("action_boot_execute_other")
        self.assertEqual(other["errorCode"], 409)
        self.assertEqual(other["error"], "the device has rebooted since this action was prepared")
        # ... and it is spent, so the boot change cannot be retried later.
        status = self.payload("action_boot_status_after")["data"]
        self.assertEqual(status["state"], "expired")

        # Retrying the same requestId in the new boot prepares a new action
        # instead of returning the dead token.
        again = self.payload("action_boot_reprepare")["data"]
        self.assertNotIn("idempotent", again)
        self.assertNotEqual(again["actionId"], self.payload("action_boot_prepare_1")["data"]["actionId"])
        self.assertEqual(self.payload("action_boot_reprepare_execute")["data"]["state"], "completed")

        # A record prepared under a different boot is refused after a reset too.
        restored = self.payload("action_boot_after_restore_execute")
        self.assertEqual(restored["errorCode"], 409)
        self.assertEqual(restored["error"], "the device has rebooted since this action was prepared")

        # The normal path still works with the live boot id.
        normal = self.payload("action_boot_normal_execute")["data"]
        self.assertEqual(normal["state"], "completed")

    def test_php_action_boot_id_unreadable_fails_closed(self) -> None:
        prepare = self.payload("action_boot_unreadable_prepare")
        self.assertEqual(prepare["errorCode"], 503)
        self.assertEqual(
            prepare["error"],
            "the kernel boot id is unavailable; no action can be prepared",
        )
        execute = self.payload("action_boot_unreadable_execute")
        self.assertEqual(execute["errorCode"], 503)
        self.assertEqual(
            execute["error"],
            "the kernel boot id is unavailable; refusing to execute a prepared action",
        )
        # A transient read failure must not spend the prepared action.
        status = self.payload("action_boot_status_unreadable")["data"]
        self.assertEqual(status["state"], "prepared")

    def test_php_action_audit_write_and_read(self) -> None:
        data = self.payload("action_audit_read")["data"]
        self.assertGreaterEqual(data["total"], 3)
        phases = {row["phase"] for row in data["rows"]}
        self.assertTrue({"prepare", "execute", "result"} <= phases, phases)
        # Newest first, and every row carries a client tuple and a hash.
        epochs = [row["tsEpoch"] for row in data["rows"]]
        self.assertEqual(epochs, sorted(epochs, reverse=True))
        for row in data["rows"]:
            self.assertRegex(row["paramsHash"] or "0" * 64, r"^[0-9a-f]{64}$")
            self.assertIn("addr", row["client"])

    def test_php_action_audit_redacts_params_and_secrets(self) -> None:
        rows = self.payload("action_audit_read")["data"]["rows"]
        encoded = json.dumps(rows)
        # Only the hash is recorded, never the values or the HMAC key.
        self.assertNotIn(ACTION_SECRET, encoded)
        self.assertNotIn("confirmToken", encoded)
        self.assertNotIn("targetWeightGr", encoded)
        for row in rows:
            self.assertNotIn("params", row)
        # No response in the whole scenario leaks the action secret.
        for case_id, outcome in self.results.items():
            with self.subTest(case=case_id):
                self.assertNotIn(ACTION_SECRET, json.dumps(outcome))

    def test_php_log_rows_are_strings_and_redacted(self) -> None:
        row = self.payload("grind_default")["data"]["rows"][0]
        self.assertIsInstance(row["grind_id"], str)
        encoded = json.dumps(row)
        for secret in ("debug-secret", "192.168.1.5", "02:00:5e:10:00:01", "000000123456"):
            self.assertNotIn(secret, encoded)


class DocumentationCase(unittest.TestCase):
    def test_route_lists_agree(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        match = re.search(r"\$E64LOCAL_ROUTES\s*=\s*array\((.*?)\);", source, re.S)
        self.assertIsNotNone(match)
        php_routes = tuple(re.findall(r'"(\w+)"', match.group(1)))
        self.assertEqual(set(php_routes), set(SimulatedLocalApi.ROUTES))

        # Only the restApiDev() dispatcher: helper switches also use case labels.
        dispatcher = source[source.index("function restApiDev("):]
        dispatch = re.findall(r'case "(\w+)":', dispatcher)
        self.assertEqual(
            set(dispatch),
            set(SimulatedLocalApi.ROUTES) | set(SimulatedLocalApi.ACTION_ROUTES),
        )

    def test_openapi_parses_and_covers_every_route(self) -> None:
        # This repository is the published subset of the research tree, and the
        # export gate classes docs/ as research-prose / publish with changes, so
        # docs/openapi/local-api.yaml is withheld and not carried here. Where it
        # exists (the research tree) the document is still asserted; where it does
        # not, skip with that reason instead of failing on a file this checkout
        # was never meant to contain.
        if not OPENAPI.is_file():
            self.skipTest(
                "docs/openapi/local-api.yaml is withheld by the export gate "
                "(research-prose / publish with changes), so it is not carried "
                "in this checkout"
            )
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            self.skipTest("PyYAML is not installed; OpenAPI YAML parse check skipped")
        document = yaml.safe_load(OPENAPI.read_text(encoding="utf-8"))
        self.assertTrue(str(document["openapi"]).startswith("3.1"))
        self.assertEqual(document["info"]["version"], "1")
        paths = set(document["paths"])
        self.assertEqual(
            paths,
            {
                f"/rest_api/{route}"
                for route in SimulatedLocalApi.ROUTES + SimulatedLocalApi.ACTION_ROUTES
            },
        )
        for path in paths:
            operation = document["paths"][path]["post"]
            self.assertIn("responses", operation)
            self.assertIn("200", operation["responses"])

        # Resolve every local $ref so a renamed schema cannot silently rot.
        def check_refs(node: object) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "$ref":
                        target = document
                        for part in str(value).lstrip("#/").split("/"):
                            target = target[part]
                    else:
                        check_refs(value)
            elif isinstance(node, list):
                for value in node:
                    check_refs(value)

        check_refs(document)
        schemes = document["components"]["securitySchemes"]
        self.assertEqual(set(schemes), {"cookieAuth", "ownerToken"})


if __name__ == "__main__":
    unittest.main()
