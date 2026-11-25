#!/usr/bin/env python3
"""Record HTTP traffic from an app or host through a local forward proxy.

The point is to answer "which route, which method, which body shape" for the
uncaptured cloud wire details, without pretending to break TLS. The device pins
two vendor certificates, so a device-side MITM is not possible from here; the
official app is the useful client, and what it sends over TLS can only be seen
if the app trusts a CA we install. Until then this proxy records:

* plain-HTTP exchanges in full metadata — method, absolute URL, headers with
  credential headers redacted, request and response body sizes and digests;
* HTTPS ``CONNECT`` tunnels as metadata only — authority, byte counts in each
  direction, duration. No inspection, no interception, no forged certificate.

Bodies are never stored by default (``--dump-bodies`` keeps a capped copy), so
a capture cannot become a credential dump.

Usage:
    python3 tools/capture_proxy.py --port 8888 --log captures/app.jsonl
    # then point the client at 127.0.0.1:8888 (HTTP proxy or HTTPS CONNECT)
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import re
import select
import socket
import socketserver
import threading
import time
import urllib.parse
from pathlib import Path

REDACTED = "<redacted>"
SENSITIVE = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-e64-local-token",
    "x-api-key",
}
SENSITIVE_NAME = re.compile(r"(?i)(token|key|secret|password|passwd|auth|cookie|code|sig)")
BODY_SECRET = re.compile(
    r"""(?i)("?(?:authorization|cookie|set-cookie|token|access_token|refresh_token|"""
    r"""password|secret|api[_-]?key|x-api-key|x-e64-local-token)"?\s*[:=]\s*)"""
    r"""("[^"]*"|'[^']*'|[^\s,;&}]+)"""
)
MAX_HEADER = 64 * 1024
MAX_BODY = 4 * 1024 * 1024
MAX_PREVIEW = 4096
RECORD_FLUSH = True


def redact(headers: dict[str, str]) -> dict[str, str]:
    """Return the headers with credential-bearing values removed."""
    return {
        name: (REDACTED if name.lower() in SENSITIVE or SENSITIVE_NAME.search(name) else value)
        for name, value in headers.items()
    }


def redact_url(url: str) -> str:
    """Drop userinfo and redact credential-looking query values."""
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    if parsed.username or parsed.password:
        netloc = f"{REDACTED}@{netloc}"
    query = "&".join(
        f"{name}={REDACTED}" if SENSITIVE_NAME.search(name) else f"{name}={value}"
        for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    )
    return urllib.parse.urlunsplit(("", netloc, parsed.path or "/", query, ""))


def redact_body(text: str) -> str:
    """Redact credential-looking fields in a body preview."""
    return BODY_SECRET.sub(r'\1"<redacted>"', text)


def split_authority(authority: str) -> tuple[str, int]:
    """Split ``host:port`` including IPv6 bracket form."""
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        port_text = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port_text = authority.partition(":")
    return host, int(port_text or 443)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest() if data else ""


class Recorder:
    """Append one JSON object per exchange to a JSONL file."""

    def __init__(self, path: Path | None, dump_bodies: bool = False) -> None:
        self.path = path
        self.dump_bodies = dump_bodies
        self.records: list[dict] = []
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        with self._lock:
            self.records.append(record)
            if self.path is None:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
                if RECORD_FLUSH:
                    handle.flush()


def _read_headers(sock: socket.socket) -> tuple[str, dict[str, str], bytes]:
    """Read the request line and headers, returning any already-read body."""
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(MAX_HEADER)
        if not chunk:
            raise ConnectionError("client closed before the headers")
        buffer += chunk
        if len(buffer) > MAX_HEADER:
            raise ConnectionError("headers too large")
    head, _, rest = buffer.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    request_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()
    return request_line, headers, rest


def _forward_http(
    method: str, url: str, headers: dict[str, str], body: bytes, timeout: float
) -> tuple[int, dict[str, str], bytes]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ConnectionError(f"unsupported target: {url}")
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    sent = {name: value for name, value in headers.items() if name.lower() != "proxy-connection"}
    try:
        conn.request(method, path, body=body or None, headers=sent)
        response = conn.getresponse()
        data = response.read()
        return response.status, {k: v for k, v in response.getheaders()}, data
    finally:
        conn.close()


class ProxyHandler(socketserver.BaseRequestHandler):
    """Handle one client connection; HTTP in full, CONNECT as a tunnel."""

    def handle(self) -> None:  # noqa: C901 - one flat protocol loop is clearer
        recorder: Recorder = self.server.recorder  # type: ignore[attr-defined]
        timeout: float = self.server.timeout_seconds  # type: ignore[attr-defined]
        started = time.time()
        try:
            request_line, headers, rest = _read_headers(self.request)
        except (ConnectionError, OSError):
            return

        parts = request_line.split()
        if len(parts) != 3:
            return
        method, target, version = parts
        if version not in ("HTTP/1.1", "HTTP/1.0"):
            self.request.sendall(b"HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 0\r\n\r\n")
            return

        if method.upper() == "CONNECT":
            self._tunnel(target, recorder, started)
            return

        try:
            length = int(headers.get("Content-Length", "0") or 0)
            note = ""
        except ValueError:
            length = 0
            note = "malformed Content-Length; body read from the buffer only"
        length = max(0, min(length, MAX_BODY))
        body = rest
        while len(body) < length:
            chunk = self.request.recv(min(65536, length - len(body)))
            if not chunk:
                break
            body += chunk
        body = body[:MAX_BODY]

        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
            "kind": "http",
            "method": method,
            "url": redact_url(target),
            "request": {
                "headers": redact(headers),
                "bodyBytes": len(body),
                "bodySha256": digest(body),
            },
        }
        if note:
            record["note"] = note
        if recorder.dump_bodies and body:
            record["request"]["body"] = redact_body(body[:MAX_PREVIEW].decode("latin-1"))

        try:
            status, response_headers, data = _forward_http(
                method, target, headers, body, timeout
            )
        except (OSError, http.client.HTTPException, ConnectionError) as error:
            record["error"] = type(error).__name__
            record["durationMs"] = int((time.time() - started) * 1000)
            recorder.write(record)
            self._respond(502, "Bad Gateway", {"Content-Type": "text/plain"}, b"upstream failed")
            return

        record["response"] = {
            "status": status,
            "headers": redact(response_headers),
            "bodyBytes": len(data),
            "bodySha256": digest(data),
        }
        if recorder.dump_bodies and data:
            record["response"]["body"] = redact_body(data[:MAX_PREVIEW].decode("latin-1"))
        record["durationMs"] = int((time.time() - started) * 1000)
        recorder.write(record)

        self._respond(status, "OK", response_headers, data)

    def _respond(self, status: int, reason: str, headers: dict[str, str], body: bytes) -> None:
        lines = [f"HTTP/1.1 {status} {reason}"]
        for name, value in headers.items():
            if name.lower() in {"content-length", "connection", "transfer-encoding"}:
                continue
            lines.append(f"{name}: {value}")
        lines.append(f"Content-Length: {len(body)}")
        lines.append("Connection: close")
        self.request.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)

    def _tunnel(self, authority: str, recorder: Recorder, started: float) -> None:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
            "kind": "connect",
            "authority": authority,
            "note": "tunnel metadata only; TLS is not intercepted",
        }
        host, port = ("", 0)
        try:
            host, port = split_authority(authority)
        except ValueError:
            record["error"] = "bad_authority"
            record["durationMs"] = int((time.time() - started) * 1000)
            recorder.write(record)
            self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            record["error"] = "unreachable"
            record["durationMs"] = int((time.time() - started) * 1000)
            recorder.write(record)
            self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return

        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        up = down = 0
        try:
            while True:
                readable, _, _ = select.select([self.request, upstream], [], [], 30)
                if not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        raise ConnectionError("closed")
                    if source is self.request:
                        up += len(data)
                        upstream.sendall(data)
                    else:
                        down += len(data)
                        self.request.sendall(data)
        except (OSError, ConnectionError):
            pass
        finally:
            upstream.close()
        record["bytesUp"] = up
        record["bytesDown"] = down
        record["durationMs"] = int((time.time() - started) * 1000)
        recorder.write(record)


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, recorder: Recorder, timeout_seconds: float = 15.0):
        self.recorder = recorder
        self.timeout_seconds = timeout_seconds
        super().__init__(address, ProxyHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record HTTP traffic through a local proxy.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--log", type=Path, default=Path("captures/proxy.jsonl"))
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--dump-bodies",
        action="store_true",
        help="keep a 4 KiB preview of each body (off by default: captures must not become credential dumps)",
    )
    args = parser.parse_args(argv)

    recorder = Recorder(args.log, dump_bodies=args.dump_bodies)
    server = ProxyServer((args.host, args.port), recorder, args.timeout)
    print(f"proxy listening on {args.host}:{args.port}; records -> {args.log}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print(f"\n{len(recorder.records)} exchange(s) recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
