"""Offline checks for the recording proxy.

The proxy is tested against a loopback upstream only: no external network, no
TLS interception, and no claim that a device can be intercepted at all.
"""

from __future__ import annotations

import hashlib
import http.client
import http.server
import importlib.util
import sys
import json
import socket
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BODY = b"hello-capture"


def _load(path: Path = ROOT / "tools" / "capture_proxy.py"):
    spec = importlib.util.spec_from_file_location("capture_proxy", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args) -> None:  # silence the test output
        pass


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.log = Path(cls.temporary.name) / "capture.jsonl"

        cls.upstream = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
        cls.upstream_port = cls.upstream.server_address[1]
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()

        cls.recorder = cls.tool.Recorder(cls.log)
        cls.proxy = cls.tool.ProxyServer(("127.0.0.1", 0), cls.recorder, 5.0)
        cls.proxy_port = cls.proxy.server_address[1]
        threading.Thread(target=cls.proxy.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.shutdown()
        cls.proxy.server_close()
        cls.upstream.shutdown()
        cls.upstream.server_close()
        cls.temporary.cleanup()

    def _records(self) -> list[dict]:
        if not self.log.is_file():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line]

    def test_plain_http_is_recorded_with_redacted_credentials(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=5)
        connection.request(
            "GET",
            f"http://127.0.0.1:{self.upstream_port}/probe?x=1",
            headers={"Authorization": "Bearer super-secret", "X-Trace": "abc"},
        )
        response = connection.getresponse()
        payload = response.read()
        connection.close()

        self.assertEqual(response.status, 200)
        self.assertEqual(payload, BODY)

        records = [
            record
            for record in self._records()
            if record["kind"] == "http" and "x=1" in record["url"]
        ]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["method"], "GET")
        self.assertIn(f"127.0.0.1:{self.upstream_port}/probe", record["url"])
        self.assertEqual(record["request"]["headers"]["Authorization"], "<redacted>")
        self.assertEqual(record["request"]["headers"]["X-Trace"], "abc")
        self.assertEqual(record["response"]["status"], 200)
        self.assertEqual(record["response"]["bodySha256"], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(record["response"]["bodyBytes"], len(BODY))
        self.assertNotIn("super-secret", self.log.read_text())
        self.assertNotIn("body", record["request"])

    def test_connect_is_metadata_only_and_fails_closed(self):
        client = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
        client.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
        reply = client.recv(1024)
        client.close()
        self.assertIn(b"502", reply)

        records = [record for record in self._records() if record["kind"] == "connect"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["authority"], "127.0.0.1:1")
        self.assertEqual(records[0]["error"], "unreachable")
        self.assertIn("not intercepted", records[0]["note"])

    def test_redaction_covers_every_credential_header(self):
        redacted = self.tool.redact(
            {
                "Authorization": "Bearer x",
                "Cookie": "a=b",
                "Set-Cookie": "c=d",
                "X-E64-Local-Token": "deadbeef",
                "X-Api-Key": "k",
                "X-Auth-Token": "also-secret",
                "Accept": "application/json",
            }
        )
        for name in (
            "Authorization",
            "Cookie",
            "Set-Cookie",
            "X-E64-Local-Token",
            "X-Api-Key",
            "X-Auth-Token",
        ):
            self.assertEqual(redacted[name], "<redacted>", name)
        self.assertEqual(redacted["Accept"], "application/json")

    def test_userinfo_and_credential_query_values_never_reach_the_log(self):
        url = self.tool.redact_url(
            "http://owner:hunter2@127.0.0.1:9/probe?access_token=abc123&limit=5"
        )
        self.assertIn("<redacted>@127.0.0.1:9", url)
        self.assertIn("access_token=<redacted>", url)
        self.assertIn("limit=5", url)
        for secret in ("hunter2", "abc123", "owner:"):
            self.assertNotIn(secret, url)

    def test_body_previews_are_redacted(self):
        preview = self.tool.redact_body(
            '{"password": "hunter2", "X-Auth-Token": "abc", "keep": "visible"}'
        )
        self.assertNotIn("hunter2", preview)
        self.assertNotIn('"abc"', preview)
        self.assertIn('"keep": "visible"', preview.replace("'", '"'))

    def test_ipv6_authorities_parse(self):
        self.assertEqual(self.tool.split_authority("[::1]:443"), ("::1", 443))
        self.assertEqual(self.tool.split_authority("example.test"), ("example.test", 443))
        self.assertEqual(self.tool.split_authority("127.0.0.1:8080"), ("127.0.0.1", 8080))

    def test_a_malformed_content_length_is_recorded_not_crashed(self):
        client = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=5)
        client.sendall(
            f"POST http://127.0.0.1:{self.upstream_port}/probe HTTP/1.1\r\n"
            "Host: x\r\nContent-Length: abc\r\n\r\n".encode()
        )
        reply = client.recv(2048)
        client.close()
        self.assertTrue(reply.startswith(b"HTTP/1.1 "), reply[:40])

        records = [record for record in self._records() if record["kind"] == "http"]
        malformed = [record for record in records if "malformed Content-Length" in record.get("note", "")]
        self.assertEqual(len(malformed), 1)

    def test_bodies_are_off_by_default(self):
        self.assertFalse(self.recorder.dump_bodies)


if __name__ == "__main__":
    unittest.main()
