from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from helpers import fixture

from e64root.httpclient import HTTPClient, TLSConfig
from e64root.target import Endpoint, parse_login_page


class Handler(BaseHTTPRequestHandler):
    posts: list[tuple[str, bytes, dict[str, str]]] = []

    def log_message(self, *_args):  # noqa: D401 - test server
        return

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/login.php":
            body = fixture("login.html").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).posts.append((self.path, body, dict(self.headers)))
        response = b'{"message":"Upload successful!","error":false}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class HttpClientFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Handler.posts = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]
        cls.client = HTTPClient(
            Endpoint("127.0.0.1", cls.port), scheme="http", tls=TLSConfig(), timeout=3
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_get_login_page_and_parse(self):
        response = self.client.get("/login.php")
        self.assertEqual(response.status, 200)
        fingerprint = parse_login_page(response.text, self.client.url("/login.php"), 200)
        self.assertEqual(fingerprint.model, "E64")
        self.assertEqual(fingerprint.serial, "0123456789AB")

    def test_post_form_is_urlencoded(self):
        response = self.client.post_form("/login.php", {"login": "1", "userRole": "Owner"})
        self.assertEqual(response.status, 200)
        path, body, headers = Handler.posts[-1]
        self.assertEqual(path, "/login.php")
        self.assertIn("login=1", body.decode())
        self.assertIn("Content-Type", headers)

    def test_post_multipart(self):
        payload = b"PK\x03\x04fake-zip"
        response = self.client.post_multipart(
            "/upload_esp.php", "espFile", "payload.zip", payload, boundary="test-boundary"
        )
        self.assertEqual(response.status, 200)
        path, body, headers = Handler.posts[-1]
        self.assertEqual(path, "/upload_esp.php")
        self.assertIn(b'test-boundary', body)
        self.assertIn(b'name="espFile"', body)
        self.assertIn(payload, body)
        self.assertIn("multipart/form-data", headers["Content-Type"])

    def test_404_is_response_not_exception(self):
        response = self.client.get("/missing")
        self.assertEqual(response.status, 404)


if __name__ == "__main__":
    unittest.main()
