#!/usr/bin/env python3
"""Loopback-only HTTP proxy for testing the official Sync app against a mock.

This proxy deliberately routes plain HTTP requests to the local simulator and
rejects CONNECT/TLS. It cannot reach the Mahlkönig cloud. It is intended for
an owner-controlled emulator with ``adb reverse`` and a temporary Android
global proxy setting, not for general-purpose traffic interception.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class LocalOnlyProxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    simulator_host = "127.0.0.1"
    simulator_port = 8787

    def log_message(self, format: str, *args: object) -> None:
        # Keep the transcript machine-readable and avoid leaking bodies.
        print(format % args, file=sys.stderr, flush=True)

    def _record(self, *, target: str, status: int | str) -> None:
        print(
            json.dumps(
                {"method": self.command, "target": target, "status": status},
                sort_keys=True,
            ),
            flush=True,
        )

    def _plain_request(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.scheme and parsed.scheme != "http":
            self.send_error(400, "only plain HTTP is supported")
            self._record(target=self.path, status=400)
            return

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else None
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower()
            not in {"connection", "proxy-connection", "keep-alive", "host"}
        }
        headers["Host"] = f"{self.simulator_host}:{self.simulator_port}"
        headers["Connection"] = "close"

        connection = http.client.HTTPConnection(
            self.simulator_host, self.simulator_port, timeout=5
        )
        try:
            connection.request(self.command, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() in {"connection", "keep-alive", "transfer-encoding"}:
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self._record(target=self.path, status=response.status)
        except OSError as error:
            self.send_error(502, f"local simulator unavailable: {error}")
            self._record(target=self.path, status=502)
        finally:
            connection.close()

    def do_CONNECT(self) -> None:  # noqa: N802 - stdlib handler API
        # Never tunnel TLS: this guarantees that no cloud request can escape.
        self.send_error(403, "TLS/CONNECT disabled by local-only test proxy")
        self._record(target=self.path, status=403)

    do_GET = _plain_request
    do_POST = _plain_request
    do_PUT = _plain_request
    do_PATCH = _plain_request
    do_DELETE = _plain_request
    do_OPTIONS = _plain_request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--simulator-host", default="127.0.0.1")
    parser.add_argument("--simulator-port", type=int, default=8787)
    args = parser.parse_args()
    LocalOnlyProxy.simulator_host = args.simulator_host
    LocalOnlyProxy.simulator_port = args.simulator_port
    server = ThreadingHTTPServer((args.host, args.port), LocalOnlyProxy)
    print(
        f"local-only proxy listening on {args.host}:{args.port}; "
        f"plain HTTP -> {args.simulator_host}:{args.simulator_port}; "
        "CONNECT/TLS rejected",
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
