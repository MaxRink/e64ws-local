#!/usr/bin/env python3
"""Owner-local HTTPS fixture for the official Sync app's cloud boundary.

This server is deliberately synthetic.  It accepts only fixture credentials,
returns a three-part JWT-shaped access token, and implements the small
auth/profile/config/device-query surface needed to exercise the app's
post-onboarding state transition.  It never contacts Mahlkönig services and
never writes request bodies or bearer values to a transcript.

The official app uses a production hostname, so an isolated emulator test must
combine this server with an exact emulator-only DNS/DNAT route. See
``docs/ANDROID_LOCAL_APP_SETUP.md``.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit


SCHEMA = "synthetic-official-app-cloud-v1"
FIXTURE_USERNAME = "fixture@example.invalid"
FIXTURE_PASSWORD = "fixture-only-password"
FIXTURE_REFRESH_TOKEN = "fixture-refresh-token"


def _b64(value: Mapping[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def fixture_jwt() -> str:
    """Return a deterministic JWT-shaped value for Dart JwtDecoder tests.

    The signature is intentionally not presented as a production trust
    boundary.  The official client decodes the payload locally; all fixture
    endpoints still require this exact bearer value.
    """

    now = int(time.time())
    return ".".join(
        (
            _b64({"alg": "HS256", "typ": "JWT"}),
            _b64(
                {
                    "sub": "fixture-user",
                    "username": FIXTURE_USERNAME,
                    "scope": ["fixture"],
                    "roles": ["user"],
                    "iat": now,
                    "exp": now + 3600,
                    "iss": "local-fixture",
                }
            ),
            "fixture-signature",
        )
    )


def _normalize(path: str) -> str:
    path = urlsplit(path).path.rstrip("/") or "/"
    for prefix in ("/api", "/api/v1", "/api/v2"):
        if path == prefix:
            return "/"
        if path.startswith(prefix + "/"):
            return path[len(prefix) :]
    return path


def _safe_method_path(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    return {
        "method": handler.command,
        "path": _normalize(handler.path),
    }


@dataclass
class FixtureState:
    query_empty_count: int = 1
    query_calls: int = 0
    authenticated_requests: int = 0
    access_token: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, **event: Any) -> None:
        with self.lock:
            self.events.append(event)
            del self.events[:-200]

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "schema": SCHEMA,
                "synthetic": True,
                "queryCalls": self.query_calls,
                "authenticatedRequests": self.authenticated_requests,
                "tokenIssued": self.access_token is not None,
                "events": list(self.events),
            }


class CloudFixtureHandler(BaseHTTPRequestHandler):
    server_version = "OfficialAppCloudFixture/1"
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> FixtureState:
        return self.server.fixture_state  # type: ignore[attr-defined]

    def log_message(self, _format: str, *_args: Any) -> None:
        # Bodies, authorization headers, and credentials must never reach the
        # default HTTP logger.
        return

    def _json(self, status: int, value: Any, headers: Mapping[str, str] | None = None) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for key, header in (headers or {}).items():
            self.send_header(key, header)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 1024 * 1024:
            raise ValueError("fixture body exceeds 1 MiB")
        raw = self.rfile.read(length) if length else b"{}"
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("fixture JSON body must be an object")
        return value

    def _auth(self) -> bool:
        header = self.headers.get("Authorization", "")
        with self.state.lock:
            expected = self.state.access_token
        accepted = expected is not None and header == f"Bearer {expected}"
        cookie_header = self.headers.get("Cookie", "")
        if expected is not None and f"access_token={expected}" in cookie_header:
            accepted = True
        if accepted:
            with self.state.lock:
                self.state.authenticated_requests += 1
            return True
        self._json(401, {"schema": SCHEMA, "synthetic": True, "error": "fixture bearer required"})
        self.state.record(
            **_safe_method_path(self),
            status=401,
            auth="missing-or-invalid",
            authorizationPresent=bool(header),
            authorizationShape=("bearer" if header.startswith("Bearer ") else "other") if header else "absent",
            cookiePresent=bool(cookie_header),
        )
        return False

    @staticmethod
    def _envelope(**values: Any) -> dict[str, Any]:
        return {"schema": SCHEMA, "synthetic": True, **values}

    @staticmethod
    def _profile() -> dict[str, Any]:
        return {
            "id": "fixture-user",
            "username": FIXTURE_USERNAME,
            "email": FIXTURE_USERNAME,
            "firstName": "Local",
            "lastName": "Fixture",
            "groups": [],
            "roles": ["user"],
        }

    @classmethod
    def _query_payload(cls, path: str) -> dict[str, Any]:
        if path in {"/profile/query", "/mobile-service/profile/query", "/profile/count", "/mobile-service/profile/count"}:
            items = [cls._profile()] if path.endswith("/query") else []
        elif path in {
            "/device/query",
            "/mobile-service/device/query",
            "/device-union/query",
            "/mobile-service/device-union/query",
            "/brewer/query",
            "/mobile-service/brewer/query",
        }:
            items = [cls._device()]
        else:
            items = []
        return {
            "hasMore": False,
            "items": items,
            "messages": [],
            "op": "query",
            "rows": len(items),
            "stamp": int(time.time() * 1000),
            "took": 0,
        }

    @staticmethod
    def _app_config() -> dict[str, Any]:
        # The misspelling in disable_lm_paring is retained because it is the
        # exact static AOT key, not corrected documentation prose.
        return {
            "disable_lm_paring": True,
            "lm_connection_url": "",
            "lm_avail": False,
            "manual_hmi_input": True,
            "maxGrindersPerStandardBrewer": 4,
            "maxScalesPerGrinder": 2,
            "disable_group_head_assignment": False,
        }

    @staticmethod
    def _device() -> dict[str, Any]:
        # Keys are the retained HemroDevice serializer names.  Nullable
        # object fields are supplied as null/empty containers so the fixture is
        # useful for parser testing without inventing a real machine identity.
        return {
            "id": "fixture-e64ws-001",
            # The app's retained HemroDeviceType enum contains flow/xenia/wmf;
            # E64 is represented by the flow family in the static helper.
            "deviceType": "flow",
            "channelId": "fixture-channel",
            "serial": "E64WS-SIM-0001",
            "storeId": None,
            "regionName": "local-fixture",
            "testDevice": True,
            "change": None,
            "subType": "E64_WS",
            "fixedFirmware": False,
            "productionDate": None,
            "assemblyDate": None,
            "hmiHwProductId": "fixture-hmi",
            "bindingCode": "fixture-binding",
            "bindings": [],
            "status": "ONLINE",
            "store": None,
        }

    def _query_result(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        return self._envelope(
            hasMore=False,
            items=items,
            messages=[],
            op="query",
            rows=len(items),
            stamp=int(time.time() * 1000),
            took=0,
        )

    def _handle(self) -> None:
        path = _normalize(self.path)
        if path == "/__fixture__/state":
            self._json(200, self.state.snapshot())
            return
        if path == "/security-service/auth/token":
            body = self._body()
            # Accept only the documented disposable fixture credentials.  A
            # production/vendor password is never needed for this test.
            if body.get("username") != FIXTURE_USERNAME or body.get("password") != FIXTURE_PASSWORD:
                self.state.record(**_safe_method_path(self), status=401, auth="fixture-credentials-rejected")
                self._json(401, self._envelope(error="use the documented fixture credentials"))
                return
            token = fixture_jwt()
            with self.state.lock:
                self.state.access_token = token
            self.state.record(**_safe_method_path(self), status=200, response="token-issued")
            self._json(
                200,
                self._envelope(
                    # The AOT model names are camelCase; OAuth-compatible
                    # aliases are included because the static pass also
                    # retains access_token/refresh_token interceptor keys.
                    accessToken=token,
                    refreshToken=FIXTURE_REFRESH_TOKEN,
                    access_token=token,
                    refresh_token=FIXTURE_REFRESH_TOKEN,
                    tokenType="Bearer",
                    token_type="Bearer",
                    expiresIn=3600,
                    expires_in=3600,
                ),
                {"Set-Cookie": f"access_token={token}; Path=/; HttpOnly"},
            )
            return
        if path == "/security-service/auth/refresh":
            body = self._body()
            if body.get("refreshToken", body.get("refresh_token")) != FIXTURE_REFRESH_TOKEN:
                self._json(401, self._envelope(error="fixture refresh token required"))
                self.state.record(**_safe_method_path(self), status=401, auth="refresh-rejected")
                return
            token = fixture_jwt()
            with self.state.lock:
                self.state.access_token = token
            self.state.record(**_safe_method_path(self), status=200, response="token-refreshed")
            self._json(
                200,
                self._envelope(
                    accessToken=token,
                    refreshToken=FIXTURE_REFRESH_TOKEN,
                    access_token=token,
                    refresh_token=FIXTURE_REFRESH_TOKEN,
                    tokenType="Bearer",
                    token_type="Bearer",
                    expiresIn=3600,
                    expires_in=3600,
                ),
                {"Set-Cookie": f"access_token={token}; Path=/; HttpOnly"},
            )
            return

        if not self._auth():
            return

        if path in {"/settings/app-config", "/mobile-service/settings/app-config"}:
            self.state.record(**_safe_method_path(self), status=200, response="app-config")
            self._json(200, self._envelope(**self._app_config()))
            return
        if path in {"/profile/my-profile", "/profile/self", "/mobile-service/profile/my-profile"}:
            self.state.record(**_safe_method_path(self), status=200, response="profile")
            self._json(200, self._envelope(**self._profile()))
            return
        if path in {
            "/profile/query",
            "/mobile-service/profile/query",
            "/profile/count",
            "/mobile-service/profile/count",
            "/device-union/query",
            "/mobile-service/device-union/query",
            "/brewer/query",
            "/mobile-service/brewer/query",
        }:
            payload = self._query_payload(path)
            self.state.record(**_safe_method_path(self), status=200, response="query", itemCount=len(payload["items"]))
            self._json(200, self._envelope(**payload))
            return
        if path in {"/device/query", "/mobile-service/device/query"}:
            with self.state.lock:
                self.state.query_calls += 1
                call = self.state.query_calls
            items = [] if call <= self.state.query_empty_count else [self._device()]
            self.state.record(**_safe_method_path(self), status=200, response="device-query", itemCount=len(items))
            self._json(200, self._query_result(items))
            return
        if path == "/scale/chart/pool" or path.startswith("/device/") or path.startswith("/grinder/") or path.startswith("/brew-event/"):
            self.state.record(**_safe_method_path(self), status=200, response="empty-fixture-envelope")
            self._json(200, self._envelope(items=[], messages=[], rows=0))
            return

        # Known mobile-service routes are intentionally answered with an
        # empty, parser-shaped envelope so the fixture can expose the next UI
        # state without pretending to implement the vendor backend. Unknown
        # non-mobile paths remain 404 and are recorded as such.
        if path.startswith("/mobile-service/"):
            self.state.record(**_safe_method_path(self), status=200, response="generic-mobile-envelope")
            self._json(200, self._envelope(items=[], messages=[], rows=0))
            return

        self.state.record(**_safe_method_path(self), status=404, response="unknown-route")
        self._json(404, self._envelope(error="route not implemented by fixture"))

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            self._handle()
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self.state.record(**_safe_method_path(self), status=400, error=type(exc).__name__)
            self._json(400, self._envelope(error=str(exc)))

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            self._handle()
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self.state.record(**_safe_method_path(self), status=400, error=type(exc).__name__)
            self._json(400, self._envelope(error=str(exc)))

    do_PUT = do_POST
    do_PATCH = do_POST


def serve(args: argparse.Namespace) -> None:
    state = FixtureState(query_empty_count=args.query_empty_count)
    server = ThreadingHTTPServer((args.host, args.port), CloudFixtureHandler)
    server.daemon_threads = True
    server.fixture_state = state  # type: ignore[attr-defined]
    if bool(args.tls_cert) != bool(args.tls_key):
        raise SystemExit("--tls-cert and --tls-key must be supplied together")
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Official-app cloud fixture: {'https' if args.tls_cert else 'http'}://{args.host}:{args.port}")
    print(f"Fixture username: {FIXTURE_USERNAME}")
    print(f"Fixture password: {FIXTURE_PASSWORD}")
    print("No request body or bearer value is logged.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if args.transcript:
            Path(args.transcript).write_text(json.dumps(state.snapshot(), indent=2) + "\n", encoding="utf-8")
        server.shutdown()
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8444)
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--query-empty-count", type=int, default=1)
    parser.add_argument("--transcript", type=Path)
    args = parser.parse_args(argv)
    if args.query_empty_count < 0 or args.query_empty_count > 30:
        parser.error("--query-empty-count must be between 0 and 30")
    logging.getLogger().setLevel(logging.CRITICAL)
    serve(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
