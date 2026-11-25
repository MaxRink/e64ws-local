"""Small HTTP/TLS client tuned for the vendor web UI.

No third-party dependency is used: the CLI must run from a plain Python 3
install on the owner's laptop.  Proxy environment variables are deliberately
ignored so a device on the LAN is never reached through a corporate proxy.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .errors import TransportError, UsageError
from .target import Endpoint


@dataclass(frozen=True)
class TLSConfig:
    insecure: bool = False
    ca_file: str | None = None

    def __post_init__(self) -> None:
        if self.insecure and self.ca_file:
            raise UsageError("choose either --insecure or --ca-file, not both")
        if self.ca_file and not Path(self.ca_file).is_file():
            raise UsageError(f"--ca-file does not exist: {self.ca_file}")

    @property
    def mode(self) -> str:
        if self.insecure:
            return "unverified (owner opted out with --insecure)"
        if self.ca_file:
            return f"verified against {self.ca_file}"
        return "verified against the system trust store"

    def context(self) -> ssl.SSLContext:
        if self.insecure:
            return ssl._create_unverified_context()  # noqa: SLF001 - explicit opt-in
        if self.ca_file:
            return ssl.create_default_context(cafile=self.ca_file)
        return ssl.create_default_context()


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except json.JSONDecodeError as exc:
            raise TransportError(f"response from {self.url} is not JSON: {exc}") from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class HTTPClient:
    """Bounded HTTP(S) client for one device endpoint."""

    def __init__(
        self,
        endpoint: Endpoint,
        scheme: str = "https",
        tls: TLSConfig | None = None,
        timeout: float = 15.0,
        follow_redirects: bool = True,
    ) -> None:
        if scheme not in ("http", "https"):
            raise UsageError(f"unsupported scheme: {scheme}")
        if timeout <= 0:
            raise UsageError("timeout must be positive")
        self.endpoint = endpoint
        self.scheme = scheme
        self.tls = tls or TLSConfig()
        self.timeout = timeout
        handlers: list[urllib.request.BaseHandler] = [urllib.request.ProxyHandler({})]
        if scheme == "https":
            handlers.append(urllib.request.HTTPSHandler(context=self.tls.context()))
        if not follow_redirects:
            handlers.append(_NoRedirect())
        self._opener = urllib.request.build_opener(*handlers)

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.endpoint.authority}"

    def url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def request(
        self,
        method: str,
        path: str,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        url = self.url(path)
        request = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}))
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return Response(
                    status=response.status,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=response.read(),
                    url=response.geturl(),
                )
        except urllib.error.HTTPError as exc:
            body = exc.read()
            status = exc.code
            headers = {key.lower(): value for key, value in exc.headers.items()}
            url = exc.geturl()
            exc.close()
            return Response(status=status, headers=headers, body=body, url=url)
        except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError) as exc:
            reason = getattr(exc, "reason", exc)
            raise TransportError(f"{method} {url} failed: {reason}") from exc

    def get(self, path: str) -> Response:
        return self.request("GET", path)

    def post_form(self, path: str, fields: Mapping[str, str]) -> Response:
        body = urllib.parse.urlencode(fields).encode()
        return self.request(
            "POST",
            path,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def post_multipart(
        self,
        path: str,
        field_name: str,
        filename: str,
        content: bytes,
        content_type: str = "application/zip",
        boundary: str | None = None,
    ) -> Response:
        boundary = boundary or "----e64root" + os.urandom(12).hex()
        head = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode()
        tail = f"\r\n--{boundary}--\r\n".encode()
        body = head + content + tail
        return self.request(
            "POST",
            path,
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )


# --- low-level probes -------------------------------------------------------

@dataclass(frozen=True)
class TLSProbe:
    open: bool
    error: str = ""
    tls_version: str = ""
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    certificate_sha256: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "open": self.open,
            "error": self.error,
            "tls_version": self.tls_version,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_after": self.not_after,
            "certificate_sha256": self.certificate_sha256,
        }


def probe_tls(host: str, port: int, timeout: float = 5.0) -> TLSProbe:
    """Open a TLS connection and describe the peer certificate.

    Verification is intentionally disabled here: the vendor certificate is
    self-signed, and this is a fingerprint, not a trusted channel.  The HTTP
    client used for actions has its own explicit ``--insecure``/``--ca-file``
    choice.
    """
    context = ssl._create_unverified_context()  # noqa: SLF001 - fingerprint only
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            server_hostname = None if _is_ip(host) else host
            with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
                cert = tls.getpeercert() or {}
                der = tls.getpeercert(binary_form=True) or b""
                import hashlib

                return TLSProbe(
                    open=True,
                    tls_version=tls.version() or "",
                    subject=_name(cert.get("subject", ())) or "unavailable without verification",
                    issuer=_name(cert.get("issuer", ())) or "unavailable without verification",
                    not_after=str(cert.get("notAfter", "")) or "unavailable without verification",
                    certificate_sha256=hashlib.sha256(der).hexdigest(),
                )
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return TLSProbe(False, error=str(exc))


@dataclass(frozen=True)
class WebSocketProbe:
    open: bool
    status_line: str = ""
    error: str = ""

    def as_dict(self) -> dict[str, object]:
        return {"open": self.open, "status_line": self.status_line, "error": self.error}


def probe_websocket(host: str, port: int, timeout: float = 5.0) -> WebSocketProbe:
    """Send a token-less RFC 6455 upgrade and report the status line.

    A valid server answers ``101`` and then closes because the token is absent.
    Any HTTP status proves that a WebSocket server is listening; a timeout or
    TCP error does not.
    """
    context = ssl._create_unverified_context()  # noqa: SLF001 - fingerprint only
    key = os.urandom(16).hex()
    request = (
        "GET /?token= HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            server_hostname = None if _is_ip(host) else host
            with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
                tls.sendall(request)
                data = tls.recv(4096)
        line = data.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        return WebSocketProbe(bool(line), status_line=line)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return WebSocketProbe(False, error=str(exc))


@dataclass(frozen=True)
class BannerProbe:
    open: bool
    banner: str = ""
    error: str = ""

    def as_dict(self) -> dict[str, object]:
        return {"open": self.open, "banner": self.banner, "error": self.error}


def probe_banner(host: str, port: int, timeout: float = 3.0) -> BannerProbe:
    """Read an SSH identification banner without authenticating."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
        return BannerProbe(True, data.decode("latin-1", errors="replace").strip())
    except (OSError, TimeoutError) as exc:
        return BannerProbe(False, error=str(exc))


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _name(parts: object) -> str:
    if not parts:
        return ""
    try:
        return ", ".join(f"{key}={value}" for rdn in parts for key, value in rdn)
    except (TypeError, ValueError):
        return str(parts)
