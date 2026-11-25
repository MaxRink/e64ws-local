"""REST surface tests: all 13 routes, auth matrix and error strings."""
from __future__ import annotations

import io
import json
import os
import time
import unittest
import urllib.error
import urllib.request
import zipfile

from harness import Harness

from e64ctl.persistence import _infozip_archive


def call(port: int, route: str, body=None, cookie=None, method="POST"):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/rest_api/{route}", data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if cookie:
        request.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers)


def login(port: int, role: str = "Owner", password: str = "") -> tuple[int, dict, str]:
    status, body, headers = call(port, "login",
                                 {"userRole": role, "password": password})
    cookie = ""
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookie = value.split(";")[0]
    return status, json.loads(body), cookie


class RestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness(dev_mode=False)
        self.h.__enter__()

    def tearDown(self) -> None:
        self.h.__exit__(None, None, None)

    # -- public routes ----------------------------------------------------
    def test_ping(self) -> None:
        status, body, headers = call(self.h.http_port, "ping", method="GET")
        self.assertEqual((status, body), (200, b"expired\n"))
        self.assertTrue(headers["Content-Type"].startswith("text/plain"))
        _, _, cookie = login(self.h.http_port)
        status, body, _ = call(self.h.http_port, "ping", cookie=cookie)
        self.assertEqual((status, body), (200, b"pong\n"))

    def test_check_session(self) -> None:
        status, body, _ = call(self.h.http_port, "check_session")
        self.assertEqual((status, body), (200, b"session_invalid\n"))
        _, _, cookie = login(self.h.http_port)
        status, body, _ = call(self.h.http_port, "check_session", cookie=cookie)
        self.assertEqual((status, body), (200, b"session_valid\n"))

    def test_get_machine_info(self) -> None:
        status, body, _ = call(self.h.http_port, "get_machine_info", method="GET")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["grinderType"], 0)
        self.assertEqual(payload["grinderTypeName"], "E64 WS")
        self.assertEqual(payload["error"], "")
        # pretty printed like the PHP json_encode with PRETTY_PRINT
        self.assertIn(b"\n", body)

    def test_login_and_logout(self) -> None:
        status, payload, cookie = login(self.h.http_port)
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"success": True, "errorCode": 0})
        self.assertTrue(cookie.startswith("PHPSESSID="))
        status, body, _ = call(self.h.http_port, "logout", cookie=cookie)
        payload = json.loads(body)
        self.assertEqual((status, payload["success"]), (200, True))
        status, body, _ = call(self.h.http_port, "check_session", cookie=cookie)
        self.assertEqual(body, b"session_invalid\n")

    def test_login_failures(self) -> None:
        status, body, _ = call(self.h.http_port, "login", {})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["console"], "Missing parameter!")
        status, body, _ = call(self.h.http_port, "login",
                               {"userRole": "Owner", "password": "x"},
                               method="POST")
        self.assertEqual(status, 200)          # owner with no stored password
        status, body, _ = call(self.h.http_port, "login",
                               {"userRole": "Nope", "password": "x"})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["console"], "Wrong password!")

    def test_unknown_route_and_query_string(self) -> None:
        status, body, _ = call(self.h.http_port, "nope")
        self.assertEqual(status, 400)
        # The PHP script reaches its session gate before the command switch.
        self.assertEqual(json.loads(body)["console"], "Access denied!")
        # basename() keeps the query string -> unknown route
        status, body, _ = call(self.h.http_port, "ping?x=1")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["console"], "Access denied!")

    def test_method_not_checked(self) -> None:
        for method in ("GET", "POST", "PUT", "DELETE"):
            status, body, _ = call(self.h.http_port, "check_session",
                                   method=method)
            self.assertEqual(status, 200)

    # -- protected routes -------------------------------------------------
    def test_protected_requires_session(self) -> None:
        for route in ("logout", "update_session", "get_wifi_info", "scan_wifi",
                      "request_onboarding", "reboot", "get_fw_update_state",
                      "download_database", "download_machine_logs"):
            with self.subTest(route=route):
                status, body, _ = call(self.h.http_port, route, {})
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body)["console"], "Access denied!")

    def test_update_session(self) -> None:
        _, _, cookie = login(self.h.http_port)
        status, body, _ = call(self.h.http_port, "update_session", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body),
                         {"console": "", "success": True, "errorCode": 0})

    def test_get_wifi_info(self) -> None:
        _, _, cookie = login(self.h.http_port)
        status, body, _ = call(self.h.http_port, "get_wifi_info", cookie=cookie)
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertTrue(payload["success"])
        # The vendor forwards the guest `ifconfig` snapshot (AP + STA up).
        self.assertEqual(payload["data"]["mode"], "Access Point/Station")
        self.assertIn("hostname", payload["data"])

    def test_scan_wifi_helper_failure(self) -> None:
        # The HMI owns /dev/esps0, so EspWifiConfig -u cannot open the driver
        # interface; the vendor route returns this exact 400 envelope.
        _, _, cookie = login(self.h.http_port)
        status, body, _ = call(self.h.http_port, "scan_wifi", cookie=cookie)
        payload = json.loads(body)
        self.assertEqual(status, 400)
        self.assertEqual(payload["errorCode"], 247)
        self.assertIn("Failed to open driver interface", payload["console"])

    def test_request_onboarding(self) -> None:
        _, _, cookie = login(self.h.http_port)
        status, body, _ = call(self.h.http_port, "request_onboarding",
                               {"token": "abc"}, cookie=cookie)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["success"])
        status, body, _ = call(self.h.http_port, "request_onboarding",
                               None, cookie=cookie)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["console"], "Error, JSON empty!")

    def test_reboot_rejects_mobile(self) -> None:
        status, payload, cookie = login(self.h.http_port, "MobileApp",
                                        "whatever")
        # Fixed MobileApp hash does not verify -> wrong password
        self.assertEqual(status, 400)
        _, _, cookie = login(self.h.http_port)
        status, body, _ = call(self.h.http_port, "reboot", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["success"])

    def test_fw_update_state_fallback(self) -> None:
        _, _, cookie = login(self.h.http_port)
        status, body, _ = call(self.h.http_port, "get_fw_update_state",
                               cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body),
                         {"state": "ERROR", "progress": "0%",
                          "errorReason": "No state file existing"})
        self.h.service.persistence.write_json(
            "/tmp/FirmwareUpdateState.json",
            {"state": "UPLOAD_IN_PROGRESS", "progress": 42, "errorReason": ""})
        status, body, _ = call(self.h.http_port, "get_fw_update_state",
                               cookie=cookie)
        self.assertEqual(json.loads(body)["progress"], 42)

    def test_download_database(self) -> None:
        _, _, cookie = login(self.h.http_port)
        status, body, headers = call(self.h.http_port, "download_database",
                                     cookie=cookie)
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"SQLite format 3"))
        self.assertIn("attachment; filename=\"HsgSqlite_SN123456_",
                      headers["Content-Disposition"])

    def test_download_machine_logs(self) -> None:
        self.h.service.persistence.add_grind(self.h.state)
        self.h.service.persistence.add_event(3, "test")
        _, _, cookie = login(self.h.http_port)
        status, body, headers = call(self.h.http_port, "download_machine_logs",
                                     cookie=cookie)
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"PK"))
        self.assertIn("HemroHsgMachineLogs_SN123456_",
                      headers["Content-Disposition"])

    def test_download_machine_logs_empty_export(self) -> None:
        """Pristine DB: both CSVs are 0 bytes and stored, not deflated.

        The vendor's export query names columns the shipped schema does not
        have, so ``sqlite3 -header -csv`` writes nothing and ``zip -j`` stores
        two empty members (490 bytes for the 12-character serial).
        """
        _, _, cookie = login(self.h.http_port)
        status, body, headers = call(self.h.http_port, "download_machine_logs",
                                     cookie=cookie)
        self.assertEqual(status, 200)
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            infos = archive.infolist()
        self.assertEqual(len(infos), 2)
        for info in infos:
            self.assertEqual(info.file_size, 0)
            self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
        self.assertEqual(
            len(_infozip_archive(
                [(f"HemroHsg{kind}Logs_SN0123456789AB_20261031_012235.csv",
                  b"") for kind in ("Grind", "Service")], time.time())), 490)

    def test_upload_esp_illegal_call(self) -> None:
        """No uploaded file: 200, PHP session cookie, 151-byte body + '@'."""
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.h.http_port}/upload_esp.php",
            data=b"", method="POST")
        request.add_header("Content-Type", "multipart/form-data; boundary=x")
        with urllib.request.urlopen(request, timeout=5) as response:
            status, body, headers = (response.status, response.read(),
                                    dict(response.headers))
        expected = (
            '{\n    "message": "<font color=\'red\'>Upload failed!<br\\/>'
            'Illegal command call!<\\/font>",\n    "error": true,\n'
            '    "uploadDone": true,\n    "file": null\n}@\n')
        self.assertEqual(status, 200)
        self.assertEqual(body, expected.encode())
        self.assertEqual(len(body), 151)
        self.assertEqual(headers["Content-Type"], "text/html; charset=UTF-8")
        self.assertIn("PHPSESSID=", headers["Set-Cookie"])
        with open(os.path.join(self.h.dir, "tmp",
                               "FirmwareUpdateState.json")) as handle:
            self.assertEqual(json.load(handle),
                             {"state": "UPLOAD_STARTED", "progress": 0,
                              "errorReason": ""})


if __name__ == "__main__":
    unittest.main()
