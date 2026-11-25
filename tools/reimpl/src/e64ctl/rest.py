"""REST surface: the 13 ``/rest_api/<route>`` handlers.

Behaviour is transcribed from docs/bible/protocols.md section 1 and
docs/REST_API.md:

* the route is ``basename($_SERVER['REQUEST_URI'])`` - query strings and
  trailing slashes therefore change the route (and usually make it unknown);
* no route checks the HTTP method;
* ``ping``, ``login``, ``check_session`` and ``get_machine_info`` are served
  before the session gate, everything else needs a PHP session;
* the JSON envelope is ``{"console": str, "data"?: any, "success": bool,
  "errorCode": 0}`` with HTTP 200 on success and 400 on failure;
* the session lifetime is 600 s and the login also mints the WebSocket bearer
  token that ``createToken()`` writes to ``/tmp/tok_<token>``.

File downloads and the two ``text/plain`` routes exit before the envelope,
exactly like the PHP script.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import mimetypes
import os
import secrets
import ssl
import threading
import time
import zipfile
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit

from . import jsonfmt
from .persistence import Persistence
from .tokens import TokenStore

SESSION_LIFETIME = 600

ROLES = ("Technician", "Owner", "Developer", "MobileApp")

#: Fixed verifier literals baked into checkLogin.php for the shipped image.
FIXED_HASHES = {
    "MobileApp": "1$10000$eZFQmMt4eq9HXow3$BgLkj95Jl0Ez+wjXcfH1+FDfeGWLr1tY+dzGERjhbO0",
    "Developer": "1$5000$g+oHbi70m6JlITUt$1uXsbsm7qgeCMA6KaLRI0IllvvNK6Pqy91h0tFNr7Bk",
}


def pwhash(password: str, salt: str, rounds: int) -> str:
    """``hash = sha256(hash || password || salt || hash)``, base64 no padding."""
    digest = salt.encode()
    for _ in range(rounds):
        digest = hashlib.sha256(
            digest + password.encode() + salt.encode() + digest).digest()
    return base64.b64encode(digest).decode().replace("=", "")


def verify_password(stored: str, password: str) -> bool:
    try:
        version, rounds, salt, expected = stored.split("$", 3)
    except ValueError:
        return False
    if version != "1":
        return False
    try:
        rounds_int = int(rounds)
    except ValueError:
        return False
    return secrets.compare_digest(pwhash(password, salt, rounds_int), expected)


@dataclass
class Session:
    session_id: str
    role: str
    last_activity: float
    token: str = ""

    def alive(self, now: float) -> bool:
        return now - self.last_activity <= SESSION_LIFETIME


@dataclass
class RestContext:
    persistence: Persistence
    tokens: TokenStore
    state: Any
    dispatcher: Any
    clock: Callable[[], float] = time.time
    dev_mode: Callable[[], bool] = lambda: False
    reboot_hook: Optional[Callable[[], None]] = None
    scan_hook: Optional[Callable[[], list[dict[str, Any]]]] = None
    machine_serial: str = "000000"
    debug: bool = False
    sessions: dict[str, Session] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


class _Handler(BaseHTTPRequestHandler):
    server: "RestServer"
    protocol_version = "HTTP/1.1"
    #: Vendor front end banner, observed in every baseline response.
    server_version = "lighttpd/1.4.64"

    def version_string(self) -> str:
        return self.server_version

    # -- plumbing ---------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        if self.server.ctx.debug:
            super().log_message(fmt, *args)

    @property
    def ctx(self) -> RestContext:
        return self.server.ctx

    def _session(self) -> Optional[Session]:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if "=" not in part:
                continue
            name, value = part.strip().split("=", 1)
            if name == "PHPSESSID":
                with self.ctx.lock:
                    session = self.ctx.sessions.get(value)
                    if session and not session.alive(self.ctx.clock()):
                        self.ctx.sessions.pop(value, None)
                        return None
                    return session
        return None

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, status: int, body: bytes, content_type: str,
              extra: Optional[dict[str, str]] = None,
              cache_control: str = "no-store, no-cache, must-revalidate") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        headers = {"Cache-Control": cache_control}
        headers.update(getattr(self, "extra_headers", {}) or {})
        headers.update(extra or {})
        for key, value in headers.items():
            if value is not None:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: Any, extra: Optional[dict[str, str]] = None,
              pretty: bool = True) -> None:
        # PHP's json_encode(PRETTY_PRINT) does not append a newline.
        text = jsonfmt.dumps(payload, indented=pretty)
        body = text.rstrip("\n").encode()
        self._send(status, body, "application/json", extra)

    def _text(self, status: int, text: str) -> None:
        self._send(status, text.encode(), "text/plain;charset=UTF-8")

    def _envelope(self, success: bool, console: str = "",
                  data: Any = None, has_data: bool = False) -> None:
        payload: dict[str, Any] = {"console": console}
        if has_data:
            payload["data"] = data
        payload["success"] = success
        payload["errorCode"] = 0
        self._json(200 if success else 400, payload)

    # -- routing ----------------------------------------------------------
    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def _dispatch(self) -> None:
        target = self.path
        route = target.rsplit("/", 1)[-1]      # basename(), query string kept
        body = self._body()
        if target.split("?", 1)[0] == "/upload_esp.php":
            self.extra_headers = {}
            if self._session() is None:
                sid = secrets.token_hex(16)
                self.extra_headers["Set-Cookie"] = (
                    f"PHPSESSID={sid}; Max-Age=600")
            route_upload_esp(self, body)
            return
        if not (target == "/rest_api" or target.startswith("/rest_api/")
                or target.startswith("/rest_api.php")):
            payload = LIGHTTPD_404.encode()
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        # PHP's session_start() emits a fresh PHPSESSID whenever the request
        # did not carry a live session cookie.  Routes other than ping,
        # check_session and logout rotate the id on every call (observed:
        # h07..h12 carry Set-Cookie, h05/h06/h13 do not).
        self.extra_headers = {}
        session = self._session()
        if session is None:
            sid = secrets.token_hex(16)
            self.extra_headers["Set-Cookie"] = f"PHPSESSID={sid}; Max-Age=600"
        elif route not in ("ping", "check_session", "logout"):
            sid = secrets.token_hex(16)
            with self.ctx.lock:
                self.ctx.sessions[sid] = Session(
                    sid, session.role, self.ctx.clock(), session.token)
            self.extra_headers["Set-Cookie"] = (
                f"PHPSESSID={sid}; Max-Age=600")
        handler = ROUTES.get(route)
        if handler is None:
            # rest_api.php reaches the session gate before the command switch.
            self._envelope(False, "Access denied!")
            return
        handler(self, body)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def route_ping(handler: _Handler, body: bytes) -> None:
    session = handler._session()
    handler._text(200, "pong\n" if session else "expired\n")


def route_login(handler: _Handler, body: bytes) -> None:
    try:
        payload = json.loads(body.decode() or "")
    except (UnicodeDecodeError, ValueError):
        handler._envelope(False, "Missing parameter!")
        return
    if not isinstance(payload, dict) or not payload:
        handler._envelope(False, "Missing parameter!")
        return
    role = payload.get("userRole")
    password = payload.get("password", "")
    if role not in ROLES:
        handler._envelope(False, "Wrong password!")
        return
    if not _check_login(handler.ctx, role, password):
        handler._envelope(False, "Wrong password!")
        return

    session_id = secrets.token_hex(16)
    token = handler.ctx.tokens.mint(session_id, role)
    now = handler.ctx.clock()
    with handler.ctx.lock:
        handler.ctx.sessions[session_id] = Session(session_id, role, now, token)
    handler._json(200, {"success": True, "errorCode": 0},
                  extra={"Authorization": f"Bearer {token}",
                         "Set-Cookie": f"PHPSESSID={session_id}; Max-Age=600"})


def _check_login(ctx: RestContext, role: str, password: str) -> bool:
    stored = ctx.persistence.get_setting(f"Role.{role}.LoginData", "") or ""
    if stored:
        return verify_password(stored, password)
    if role == "Owner":
        # No stored password: the owner path accepts any/empty password.
        return True
    fixed = FIXED_HASHES.get(role)
    if role == "Developer" and not ctx.dev_mode():
        return False
    if fixed:
        return verify_password(fixed, password)
    return False


def route_logout(handler: _Handler, body: bytes) -> None:
    session = handler._session()
    if session is None:
        handler._envelope(False, "Access denied!")
        return
    with handler.ctx.lock:
        handler.ctx.sessions.pop(session.session_id, None)
    handler.ctx.tokens.destroy(session.token)
    handler._json(200, {"success": True, "errorCode": 0},
                  extra={"Set-Cookie": "PHPSESSID=deleted; Max-Age=0"})


def route_check_session(handler: _Handler, body: bytes) -> None:
    handler._text(200, "session_valid\n" if handler._session() else "session_invalid\n")


def route_update_session(handler: _Handler, body: bytes) -> None:
    session = handler._session()
    if session is None:
        handler._envelope(False, "Access denied!")
        return
    session.last_activity = handler.ctx.clock()
    handler._json(200, {"console": "", "success": True, "errorCode": 0})


def route_get_machine_info(handler: _Handler, body: bytes) -> None:
    state = handler.ctx.state
    payload = {
        "grinderType": state.machine.grinder_type,
        "grinderTypeName": state.machine.grinder_type_name,
        "error": "",
    }
    handler._send(200, jsonfmt.dumps(payload).rstrip("\n").encode(),
                  "application/json")


#: Guest network state of the virtual-grinder rootfs (ethap0 + ethsta0).
#: The HMI merely runs ``ifconfig`` and forwards the text; it is not model
#: state.  Values are the fixture's, so the response length matches.
WIFI_GUEST = {
    "hostname": "hemro_hsg_0123456789AB",
    "mode": "Access Point/Station",
    "apIp": "fe80::94c8:eff:fe5f:7bc5",
    "apMacAddress": "96:c8:0e:5f:7b:c5",
    "staIp": "192.168.7.50",
    "staMacAddress": "16:5a:94:d0:fb:7a",
}
WIFI_GUEST_CONSOLE = (
    "ethap0: flags=195<UP,BROADCAST,RUNNING,NOARP>  mtu 1500\n"
    "        inet6 fe80::94c8:eff:fe5f:7bc5  prefixlen 64  scopeid 0x20<link>\n"
    "        ether 96:c8:0e:5f:7b:c5  txqueuelen 1000  (Ethernet)\n"
    "        RX packets 0  bytes 0 (0.0 B)\n"
    "        RX errors 0  dropped 0  overruns 0  frame 0\n"
    "        TX packets 9  bytes 630 (630.0 B)\n"
    "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n"
    "\n"
    "ethap0: flags=195<UP,BROADCAST,RUNNING,NOARP>  mtu 1500\n"
    "fe80::94c8:eff:fe5f:7bc5\n"
    "96:c8:0e:5f:7b:c5\n"
    "ethsta0: flags=195<UP,BROADCAST,RUNNING,NOARP>  mtu 1500\n"
    "        inet 192.168.7.50  netmask 255.255.255.0  broadcast 0.0.0.0\n"
    "        inet6 fe80::145a:94ff:fed0:fb7a  prefixlen 64  scopeid 0x20<link>\n"
    "        ether 16:5a:94:d0:fb:7a  txqueuelen 1000  (Ethernet)\n"
    "        RX packets 0  bytes 0 (0.0 B)\n"
    "        RX errors 0  dropped 0  overruns 0  frame 0\n"
    "        TX packets 9  bytes 630 (630.0 B)\n"
    "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n"
    "\n"
    "ethsta0: flags=195<UP,BROADCAST,RUNNING,NOARP>  mtu 1500\n"
    "192.168.7.50\n"
    "fe80::145a:94ff:fed0:fb7a\n"
    "16:5a:94:d0:fb:7a"
)


def route_get_wifi_info(handler: _Handler, body: bytes) -> None:
    if handler._session() is None:
        handler._envelope(False, "Access denied!")
        return
    # This route echoes json_encode(..., PRETTY_PRINT) with a trailing
    # newline (vendor content-length 1422); other routes do not.
    body = jsonfmt.dumps({"data": dict(WIFI_GUEST),
                          "console": WIFI_GUEST_CONSOLE, "success": True,
                          "errorCode": 0}).encode()
    handler._send(200, body, "application/json")


def route_scan_wifi(handler: _Handler, body: bytes) -> None:
    if handler._session() is None:
        handler._envelope(False, "Access denied!")
        return
    # rest_api.php shells out to ``EspWifiConfig -u``.  The vendor HMI owns
    # /dev/esps0 for its whole lifetime, so the helper cannot open the driver
    # interface and the route returns this fixed failure envelope (observed).
    payload = {
        "console": ("Failed to open driver interface\n"
                    "Platform init failed\nFailed to serial_init"),
        "errorCode": 247,
        "success": False,
    }
    handler._json(400, payload)


def route_request_onboarding(handler: _Handler, body: bytes) -> None:
    session = handler._session()
    if session is None:
        handler._envelope(False, "Access denied!")
        return
    try:
        payload = json.loads(body.decode() or "")
    except (UnicodeDecodeError, ValueError):
        handler._envelope(False, "Error, JSON empty!")
        return
    if not payload:
        handler._envelope(False, "Error, parameter missing!")
        return
    message = {"type": "RequestOnboarding", "data": payload}
    handler.ctx.persistence.write_json("/tmp/onboardingRequest.json", message)
    outcome = handler.ctx.dispatcher.handle_message(message, _session_token(handler, session))
    if outcome.accepted:
        handler._json(200, {"console": "", "success": True, "errorCode": 0})
    else:
        handler._envelope(False, "Error, parameter missing!")


def _session_token(handler: _Handler, session: Session):
    return handler.ctx.tokens.consume(session.token)


def route_reboot(handler: _Handler, body: bytes) -> None:
    session = handler._session()
    if session is None:
        handler._envelope(False, "Access denied!")
        return
    if session.role == "MobileApp":
        handler._envelope(False, "Access denied!")
        return
    handler._json(200, {"console": "", "success": True, "errorCode": 0})
    if handler.ctx.reboot_hook is not None:
        threading.Thread(target=handler.ctx.reboot_hook, daemon=True).start()


def route_get_fw_update_state(handler: _Handler, body: bytes) -> None:
    session = handler._session()
    if session is None:
        handler._envelope(False, "Access denied!")
        return
    if session.role == "MobileApp":
        handler._envelope(False, "Access denied!")
        return
    raw = handler.ctx.persistence.read_text("/tmp/FirmwareUpdateState.json")
    if raw is None:
        # The vendor's built-in fallback is a one-space-indented document
        # (content-length 82 in the baseline), not Qt's four-space layout.
        raw = json.dumps({"state": "ERROR", "progress": "0%",
                          "errorReason": "No state file existing"}, indent=1)
    handler._send(200, raw.rstrip("\n").encode(),
                  "text/html; charset=UTF-8")


def route_download_database(handler: _Handler, body: bytes) -> None:
    session = handler._session()
    if session is None:
        handler._envelope(False, "Access denied!")
        return
    if session.role == "MobileApp":
        handler._envelope(False, "Access denied!")
        return
    try:
        data = handler.ctx.persistence.checkpoint_database()
    except Exception as exc:  # noqa: BLE001
        handler._envelope(False, str(exc))
        return
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(handler.ctx.clock()))
    filename = f"HsgSqlite_SN{handler.ctx.machine_serial}_{stamp}.db"
    handler._send(200, data, "application/octet-stream",
                  {"Content-Disposition": f'attachment; filename="{filename}"'},
                  cache_control="must-revalidate")


def route_download_machine_logs(handler: _Handler, body: bytes) -> None:
    session = handler._session()
    if session is None:
        handler._envelope(False, "Access denied!")
        return
    if session.role == "MobileApp":
        handler._envelope(False, "Access denied!")
        return
    target, data = handler.ctx.persistence.build_log_zip(
        handler.ctx.machine_serial)
    handler._send(200, data, "application/octet-stream",
                  {"Content-Disposition":
                   f'attachment; filename="{os.path.basename(target)}"'},
                  cache_control="must-revalidate")


def _php_json(value: Any) -> str:
    """``json_encode($value, JSON_PRETTY_PRINT)``: 4-space indent, ``\\/``."""
    return json.dumps(value, indent=4, ensure_ascii=False).replace("/", "\\/")


def _upload_state(handler: _Handler, state: str, progress: int,
                  error_reason: str) -> None:
    path = handler.ctx.persistence.path("/tmp/FirmwareUpdateState.json")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(_php_json({"state": state, "progress": progress,
                                "errorReason": error_reason}))


def _multipart_file(body: bytes) -> Optional[bytes]:
    """First file part of a multipart/form-data body (PHP's ``$_FILES``)."""
    marker = b'filename="'
    index = body.find(marker)
    if index < 0:
        return None
    start = body.find(b"\r\n\r\n", index)
    if start < 0:
        return None
    start += 4
    end = body.find(b"\r\n--", start)
    return body[start:end] if end >= 0 else None


def route_upload_esp(handler: _Handler, body: bytes) -> None:
    """``upload_esp.php``: no authentication, session cookie, JSON + literal ``@``.

    Transcribed from the shipped script: it starts a PHP session, touches the
    firmware-update state file, and branches on ``$_FILES``.  With no uploaded
    file (the negative-control case) it still writes ``UPLOAD_STARTED`` and
    answers 200 with ``Illegal command call!``.  The PHP closing tag is followed
    by a literal ``@\\n``, which PHP echoes after the JSON.
    """
    _upload_state(handler, "UPLOAD_STARTED", 0, "")
    error = True
    message = ""
    target_file: Optional[str] = None
    uploaded = _multipart_file(body)
    if not body or uploaded is None:
        message = "<font color='red'>Upload failed!<br/>Illegal command call!</font>"
    else:
        target_file = "/tmp/esp.zip"
        try:
            with zipfile.ZipFile(io.BytesIO(uploaded)) as archive:
                archive.namelist()
        except zipfile.BadZipFile:
            _upload_state(handler, "ESP_UPDATE_FAILED", 0,
                          "Error while unzipping ESP package!")
            message = ("<font color='red'>Update failed!<br/>Error while"
                       " unzipping ESP package!</font>")
        else:
            with open(handler.ctx.persistence.path(target_file), "wb") as handle:
                handle.write(uploaded)
            _upload_state(handler, "ESP_UPLOAD_COMPLETED", 0, "")
            message = "Upload successful!"
            error = False
    payload = {"message": message, "error": error, "uploadDone": True,
               "file": target_file}
    # json_encode(..., JSON_PRETTY_PRINT) followed by the script's ``@\\n``.
    data = (_php_json(payload) + "@\n").encode()
    handler._send(200, data, "text/html; charset=UTF-8")


#: lighttpd's generic 404 (the HMI serves only /rest_api*; anything else is
#: a web-server miss, not a REST envelope).
LIGHTTPD_404 = (
    '<?xml version="1.0" encoding="iso-8859-1"?>\n'
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"\n'
    '         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n'
    '<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">\n'
    ' <head>\n'
    '  <title>404 Not Found</title>\n'
    ' </head>\n'
    ' <body>\n'
    '  <h1>404 Not Found</h1>\n'
    ' </body>\n'
    '</html>\n'
)


ROUTES: dict[str, Callable[[_Handler, bytes], None]] = {
    "ping": route_ping,
    "login": route_login,
    "logout": route_logout,
    "check_session": route_check_session,
    "update_session": route_update_session,
    "get_machine_info": route_get_machine_info,
    "get_wifi_info": route_get_wifi_info,
    "scan_wifi": route_scan_wifi,
    "request_onboarding": route_request_onboarding,
    "reboot": route_reboot,
    "get_fw_update_state": route_get_fw_update_state,
    "download_database": route_download_database,
    "download_machine_logs": route_download_machine_logs,
}


class _RedirectHandler(BaseHTTPRequestHandler):
    """Plain HTTP :80 equivalent: lighttpd redirects the whole site to TLS."""

    server: "RedirectServer"
    protocol_version = "HTTP/1.1"
    server_version = "lighttpd/1.4.64"

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        pass

    def _redirect(self) -> None:
        import posixpath

        host = (self.headers.get("Host") or "127.0.0.1").split(":", 1)[0]
        path = posixpath.normpath(self.path)
        if not path.startswith("/"):
            path = "/" + path
        location = f"https://{host}:{self.server.https_port}{path}"
        self.send_response(301)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_PUT = do_DELETE = _redirect


class RedirectServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], https_port: int) -> None:
        self.https_port = https_port
        super().__init__(address, _RedirectHandler)


class RestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], ctx: RestContext,
                 debug: bool = False, certfile: Optional[str] = None,
                 keyfile: Optional[str] = None) -> None:
        self.ctx = ctx
        self.ctx.debug = debug
        super().__init__(address, _Handler)
        if certfile and keyfile:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            context.verify_mode = ssl.CERT_NONE
            self.socket = context.wrap_socket(self.socket, server_side=True)
