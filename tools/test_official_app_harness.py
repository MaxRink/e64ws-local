from __future__ import annotations

import http.client
import http.server
import json
import threading
import unittest

try:
    from .run_official_app_sim_test import ContainedProxy, Transcript
except ImportError:
    from run_official_app_sim_test import ContainedProxy, Transcript


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = json.dumps({"path": self.path, "simulator": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OfficialAppProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        self.fixture_thread = threading.Thread(target=self.fixture.serve_forever, daemon=True)
        self.fixture_thread.start()
        self.transcript = Transcript()
        self.proxy = ContainedProxy(
            ("127.0.0.1", 0), self.transcript, self.fixture.server_address[1]
        )
        self.proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.proxy_thread.start()

    def tearDown(self) -> None:
        self.proxy.shutdown()
        self.proxy.server_close()
        self.fixture.shutdown()
        self.fixture.server_close()

    def request(self, method: str, target: str) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection(*self.proxy.server_address, timeout=3)
        connection.request(method, target)
        response = connection.getresponse()
        body = response.read()
        connection.close()
        return response.status, body

    def test_grinder_ap_alias_is_forwarded_to_local_simulator(self) -> None:
        status, body = self.request("GET", "http://192.168.4.1/rest_api/ping")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["path"], "/rest_api/ping")
        event = self.transcript.snapshot()[-1]
        self.assertEqual(event["kind"], "local_request")
        self.assertTrue(event["grinder_ap_alias"])
        self.assertEqual(event["target"], "http://192.168.4.1:80/rest_api/ping")

    def test_second_grinder_ap_alias_is_forwarded(self) -> None:
        status, _ = self.request("GET", "http://172.16.0.1/api/v2/network/list")
        self.assertEqual(status, 200)
        self.assertTrue(self.transcript.snapshot()[-1]["grinder_ap_alias"])

    def test_cloud_host_is_rejected(self) -> None:
        status, _ = self.request("GET", "http://example.invalid/path")
        self.assertEqual(status, 403)
        self.assertEqual(self.transcript.snapshot()[-1]["kind"], "cloud_blocked")

    def test_grinder_https_connect_is_not_mislabeled_as_cloud(self) -> None:
        status, _ = self.request("CONNECT", "192.168.4.1:443")
        self.assertEqual(status, 403)
        self.assertEqual(
            self.transcript.snapshot()[-1]["kind"], "local_tls_unavailable"
        )


if __name__ == "__main__":
    unittest.main()
