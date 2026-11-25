from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from tools.official_app_cloud_fixture import (
    CloudFixtureHandler,
    FIXTURE_PASSWORD,
    FIXTURE_USERNAME,
    FixtureState,
)


class OfficialAppCloudFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.state = FixtureState(query_empty_count=1)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CloudFixtureHandler)
        cls.server.fixture_state = cls.state  # type: ignore[attr-defined]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path: str, *, body: dict | None = None, token: str | None = None) -> tuple[int, dict]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method="POST" if data else "GET")
        if data:
            request.add_header("Content-Type", "application/json")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_fixture_auth_and_pairing_poll_shape(self) -> None:
        status, rejected = self.request(
            "/security-service/auth/token",
            body={"username": FIXTURE_USERNAME, "password": "wrong"},
        )
        self.assertEqual(status, 401)
        self.assertTrue(rejected["synthetic"])

        status, login = self.request(
            "/api/security-service/auth/token",
            body={"username": FIXTURE_USERNAME, "password": FIXTURE_PASSWORD},
        )
        self.assertEqual(status, 200)
        token = login["accessToken"]
        self.assertEqual(token.count("."), 2)
        self.assertNotIn(token, json.dumps(self.state.snapshot()))

        status, config = self.request("/api/mobile-service/settings/app-config", token=token)
        self.assertEqual(status, 200)
        self.assertTrue(config["synthetic"])
        self.assertTrue(config["disable_lm_paring"])

        status, first = self.request("/api/mobile-service/device/query", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(first["items"], [])
        status, second = self.request("/api/mobile-service/device/query", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(len(second["items"]), 1)
        self.assertEqual(second["items"][0]["deviceType"], "flow")

        status, missing = self.request("/mobile-service/device/query")
        self.assertEqual(status, 401)
        self.assertTrue(missing["synthetic"])


if __name__ == "__main__":
    unittest.main()
