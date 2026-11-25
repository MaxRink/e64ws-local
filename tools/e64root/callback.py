"""One-shot HTTP callback used to retrieve command output from the grinder.

The vendor application partition is mounted read-only at ``/usr/local``, so a
marker written under the web root is not a reliable output channel.  Instead the
remote payload posts its captured output back to a short-lived listener on the
owner's host.  The vendor rootfs ships BusyBox ``wget`` with ``--post-file``.
"""

from __future__ import annotations

import os
import socket
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .errors import PreconditionError, VerificationError


@dataclass(frozen=True)
class CallbackResult:
    body: bytes
    path: str
    remote_address: str


class _CallbackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    expected_path = ""
    event: threading.Event
    result: CallbackResult | None


class _Handler(BaseHTTPRequestHandler):
    server_version = "e64root-callback"

    def log_message(self, *_args):  # noqa: D401 - intentionally quiet
        return

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        server: _CallbackServer = self.server  # type: ignore[assignment]
        if self.path != server.expected_path:
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > 1024 * 1024:
            self.send_response(413)
            self.end_headers()
            return
        body = self.rfile.read(max(0, length))
        server.result = CallbackResult(
            body=body,
            path=self.path,
            remote_address=self.client_address[0] if self.client_address else "",
        )
        server.event.set()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")


class CallbackServer:
    """A listener that accepts exactly one POST and returns its body."""

    def __init__(
        self,
        advertise_host: str,
        port: int = 0,
        timeout: float = 60.0,
        token: str | None = None,
    ) -> None:
        if not advertise_host:
            raise PreconditionError("callback advertise host is empty")
        if not 0 <= port <= 65535:
            raise PreconditionError("callback port is out of range")
        self.advertise_host = advertise_host
        self.requested_port = port
        self.timeout = timeout
        self.token = token or os.urandom(12).hex()
        self.path = f"/e64root/{self.token}"
        self._server: _CallbackServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "CallbackServer":
        bind_host = self.advertise_host
        try:
            server = _CallbackServer((bind_host, self.requested_port), _Handler)
        except OSError:
            # An address that is routable from the device may not be bindable
            # on every host (for example a link-local address without a zone).
            # Fall back to all interfaces; the token still protects the path.
            try:
                server = _CallbackServer(("", self.requested_port), _Handler)
            except OSError as exc:
                raise PreconditionError(f"cannot start callback listener: {exc}") from exc
        server.expected_path = self.path
        server.event = threading.Event()
        server.result = None
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def port(self) -> int:
        if not self._server:
            raise PreconditionError("callback listener is not started")
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        host = self.advertise_host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{self.port}{self.path}"

    def wait(self, timeout: float | None = None) -> CallbackResult:
        if not self._server:
            raise PreconditionError("callback listener is not started")
        if not self._server.event.wait(timeout if timeout is not None else self.timeout):
            raise VerificationError(
                f"no callback from the grinder within {timeout or self.timeout:.0f}s; "
                "check that the device can reach this host and port (firewall), "
                "or inspect /tmp/e64root-last.out over an existing shell"
            )
        if self._server.result is None:
            raise VerificationError("callback fired without a result")
        return self._server.result

    def close(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None

    def __enter__(self) -> "CallbackServer":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.close()


def detect_callback_host(device_host: str, device_port: int) -> str:
    """Return the local address the device would use to reach this host."""
    try:
        infos = socket.getaddrinfo(device_host, device_port, type=socket.SOCK_DGRAM)
        if not infos:
            raise OSError("no address")
        family, _socktype, _proto, _canon, sockaddr = infos[0]
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect(sockaddr)
            return sock.getsockname()[0]
    except OSError as exc:
        raise PreconditionError(
            "could not determine the local callback address; "
            "pass --callback-host with the LAN IP the grinder can reach"
        ) from exc
