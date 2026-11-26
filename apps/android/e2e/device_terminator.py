#!/usr/bin/env python3
"""Test-only TLS terminator in front of ``tools/e64ws_simulator.py``.

Why this exists
---------------
The Android app is TLS-only and pins the leaf certificate, so the simulator has
to be reached over TLS: that is why the simulator is started with
``--http-tls-cert/--http-tls-key`` and the app pins that certificate. Two things
the simulator deliberately does *not* model stand between the app and a run:

1. ``/login.php``. On a real grinder the vendor dispatcher answers that route
   and sets ``PHPSESSID``; the module in ``ondevice/rest_api_dev.php`` then
   believes the session. The simulator only has the fixture session route
   ``POST /rest_api/login`` (JSON), and the JVM suite asserts that ``/login.php``
   is absent, so the app's own vendor-login path cannot succeed against it.
2. The owner token. The app only ever stores a 64-hex token generated on the
   phone (``OwnerToken.isValid``); the simulator accepts one hard-coded literal
   (``sim-local-api-token``). The JVM suite sidesteps this by injecting the
   token as a lambda, so the storage invariant is never exercised there.

This terminator supplies exactly those two device-side behaviours and nothing
else. It terminates TLS with the pinned certificate, answers ``/login.php`` by
delegating to ``POST /rest_api/login`` so the *simulator's* session cookie is
what the app stores, and maps the app's 64-hex token to the fixture token on
the upstream leg. Every other byte goes to the simulator unchanged.

Nothing here is production code and nothing weakens the app: the app still
performs a real TLS handshake against a pinned leaf, still stores a real 64-hex
token, still sends ``X-E64-Local-Token`` and still keeps its own cookie jar.

Usage (host side, loopback only)::

    python3 apps/android/e2e/device_terminator.py \\
        --listen-port 18788 --cert .tools/e2e.crt --key .tools/e2e.key \\
        --upstream-host 127.0.0.1 --upstream-port 18787 \\
        --fixture-token sim-local-api-token
"""

from __future__ import annotations

import argparse
import http.client
import json
import ssl
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: Routes the simulator serves behind its own session; everything else is
#: forwarded verbatim.
LOGIN_PATH = "/login.php"
FIXTURE_SESSION_PATH = "/rest_api/login"
TOKEN_HEADER = "X-E64-Local-Token"


def _one_line(value: object, limit: int = 200) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:limit] + "…"


class Terminator(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "e64-e2e-terminator"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D401
        sys.stderr.write("terminator: " + (fmt % args) + "\n")

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _reply(self, status: int, body: bytes, headers: list[tuple[str, str]]) -> None:
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _upstream(self, method: str, path: str, body: bytes, headers: dict[str, str]) -> tuple[int, list[tuple[str, str]], bytes]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(
            self.server.upstream_host, self.server.upstream_port, timeout=15, context=context
        )
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            return response.status, [(k, v) for k, v in response.getheaders()], payload
        finally:
            connection.close()

    # -- routes -----------------------------------------------------------

    def _handle_login(self, body: bytes) -> None:
        """Answer the vendor form: create the simulator session, relay its cookie."""
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        password = (form.get("password") or [""])[0]
        role = (form.get("userRole") or ["Owner"])[0]
        payload = json.dumps({"userRole": role, "password": password}).encode()
        try:
            status, headers, answer = self._upstream(
                "POST",
                FIXTURE_SESSION_PATH,
                payload,
                {"Content-Type": "application/json", "Content-Length": str(len(payload))},
            )
        except OSError as exc:
            self._reply(
                502,
                json.dumps({"error": f"terminator cannot reach the simulator: {_one_line(exc)}"}).encode(),
                [("Content-Type", "application/json")],
            )
            return

        cookies = [v for k, v in headers if k.lower() == "set-cookie"]
        if status != 200 or not any(c.startswith("PHPSESSID=") for c in cookies):
            # Fail closed, exactly as the vendor dispatcher would: no session,
            # no cookie, so the app reports the login as refused.
            self._reply(
                status if status >= 400 else 502,
                answer or b'{"success":false}',
                [("Content-Type", "application/json")],
            )
            return

        page = (
            b"<html><head><title>E64</title></head><body>"
            b"<div id=\"model\">SIM</div></body></html>"
        )
        self._reply(
            200,
            page,
            [("Content-Type", "text/html; charset=utf-8")] + [("Set-Cookie", c) for c in cookies],
        )

    def _handle_proxy(self, method: str) -> None:
        body = self._read_body()
        headers: dict[str, str] = {}
        for name in ("Content-Type", "Accept", "Cookie", "User-Agent"):
            value = self.headers.get(name)
            if value is not None:
                headers[name] = value
        # The app sends the 64-hex owner token it generated; the fixture only
        # knows one literal. Map it here, on the device-side leg only.
        # ...but only the one the device would accept: a different 64-hex token
        # is refused 401 here, exactly as the module refuses an unknown token,
        # so the app's token invariant is still load-bearing.
        token = self.headers.get(TOKEN_HEADER)
        if token is not None:
            if token != self.server.accept_token:
                self._reply(
                    401,
                    json.dumps({"success": False, "errorCode": 401, "error": "owner token required"}).encode(),
                    [("Content-Type", "application/json")],
                )
                return
            headers[TOKEN_HEADER] = self.server.fixture_token
        if body:
            headers["Content-Length"] = str(len(body))

        path = self.path
        try:
            status, response_headers, answer = self._upstream(method, path, body, headers)
        except OSError as exc:
            self._reply(
                502,
                json.dumps(
                    {"success": False, "errorCode": 502, "error": f"terminator: {_one_line(exc)}"}
                ).encode(),
                [("Content-Type", "application/json")],
            )
            return

        relay = [
            (k, v)
            for k, v in response_headers
            if k.lower()
            in ("content-type", "set-cookie", "location", "content-disposition", "authorization")
        ]
        self._reply(status, answer, relay)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if urllib.parse.urlparse(self.path).path == LOGIN_PATH:
            self._handle_login(self._read_body())
            return
        self._handle_proxy("POST")

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if urllib.parse.urlparse(self.path).path == LOGIN_PATH:
            # The setup wizard probes GET /login.php for model/firmware.
            self._handle_proxy("GET")
            return
        self._handle_proxy("GET")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=18788)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=18787)
    parser.add_argument("--fixture-token", default="sim-local-api-token")
    parser.add_argument(
        "--accept-token",
        required=True,
        help="the 64-hex owner token the app generated and this fixture accepts",
    )
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.listen_host, args.listen_port), Terminator)
    server.upstream_host = args.upstream_host
    server.upstream_port = args.upstream_port
    server.fixture_token = args.fixture_token
    server.accept_token = args.accept_token
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(
        f"terminator: https://{args.listen_host}:{server.server_address[1]} -> "
        f"https://{args.upstream_host}:{args.upstream_port}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
