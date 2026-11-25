"""Shared fakes for the offline e64root tests.  No device or network is used."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[2]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from e64root.callback import CallbackResult
from e64root.httpclient import Response
from e64root.target import Endpoint
from e64root.transports import SSHResult

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def response(body: str | bytes = "", status: int = 200, url: str = "https://127.0.0.1/login.php") -> Response:
    data = body.encode() if isinstance(body, str) else body
    return Response(status=status, headers={}, body=data, url=url)


class FakeClient:
    """Minimal HTTPClient lookalike for command-level tests."""

    def __init__(self, login_html: str | None = None) -> None:
        self.endpoint = Endpoint("127.0.0.1", 443)
        self.scheme = "https"
        self.timeout = 5
        self.login_html = login_html if login_html is not None else fixture("login.html")
        self.posts: list[tuple[str, dict[str, str]]] = []
        self.gets: list[str] = []
        self.upload_status = 200
        self.upload_body = (
            '{"message":"Upload successful!","error":false,'
            '"uploadDone":true,"file":"/tmp/esp.zip"}'
        )
        self.files: dict[str, Response] = {}

    def url(self, path: str) -> str:
        return f"https://{self.endpoint.authority}{path}"

    def get(self, path: str) -> Response:
        self.gets.append(path)
        if path == "/login.php":
            return response(self.login_html)
        if path in self.files:
            return self.files[path]
        return response("not found", status=404)

    def post_form(self, path: str, fields: dict[str, str]) -> Response:
        self.posts.append((path, dict(fields)))
        return response("ok", status=200)

    def post_multipart(self, path: str, field_name: str, filename: str,
                       content: bytes, content_type: str = "application/zip",
                       boundary: str | None = None) -> Response:
        self.posts.append((path, {"_field": field_name, "_bytes": str(len(content))}))
        return response(self.upload_body, status=self.upload_status, url=f"https://127.0.0.1{path}")


@dataclass
class FakeWeb:
    capture_body: str = (
        "uid=0\nlog_stat=777 logdata logdata\nlog_www_writable=yes\n"
        "tty_stm5=yes\nflash_script=yes\nset_bootmode=yes\n"
        "unset_bootmode=yes\nunzip=yes\nsudo=yes\n"
    )
    scripts: list[str] = field(default_factory=list)
    injections: list[str] = field(default_factory=list)

    def inject(self, command: str):
        self.injections.append(command)
        return None

    def run_script(self, script: str) -> int:
        self.scripts.append(script)
        return 3

    def run_capture(self, script: str, callback, timeout: float = 60.0) -> str:
        self.scripts.append(script)
        return self.capture_body


@dataclass
class FakeCallback:
    url: str = "http://127.0.0.1:9/e64root/test"
    body: bytes = b"uid=0(root) gid=0(root) groups=0(root),10(wheel)\n"
    closed: bool = False

    def wait(self, timeout: float = 60.0) -> CallbackResult:
        return CallbackResult(self.body, "/e64root/test", "127.0.0.1")

    def close(self) -> None:
        self.closed = True


def callback_factory(*bodies: bytes):
    queue = list(bodies)

    def make() -> FakeCallback:
        body = queue.pop(0) if queue else b"uid=0(root)\n"
        return FakeCallback(body=body)

    return make


@dataclass
class FakeEsp:
    payloads: list[bytes] = field(default_factory=list)
    reply: str = '{"message":"Upload successful!","error":false,"uploadDone":true}'

    def upload(self, payload: bytes) -> str:
        self.payloads.append(payload)
        return self.reply


@dataclass
class FakeSSH:
    host: str = "127.0.0.1"
    port: int = 22
    inventory: dict[str, str] = field(default_factory=dict)
    id_output: str = "uid=0(root) gid=0(root) groups=0(root),10(wheel)\n"
    run_output: str = "revert=done\n"
    executed: list[str] = field(default_factory=list)
    waited: bool = False

    def wait_ready(self, timeout: float = 60.0, interval: float = 2.0) -> None:
        self.waited = True

    def read_inventory(self, script: str) -> dict[str, str]:
        return dict(self.inventory)

    def run(self, script: str) -> SSHResult:
        self.executed.append(script)
        if script.strip().startswith("id;"):
            return SSHResult(0, self.id_output, "")
        return SSHResult(0, self.run_output, "")


def args_for(command: str, **overrides) -> argparse.Namespace:
    values = dict(
        command=command,
        host="127.0.0.1",
        port=443,
        scheme="https",
        allow_http=False,
        insecure=True,
        ca_file=None,
        timeout=5.0,
        allow_public=False,
        allow_unverified_target=False,
        json=False,
        yes=True,
        dry_run=False,
        cmd="id",
        command_timeout=20,
        callback_timeout=1.0,
        callback_host="127.0.0.1",
        callback_port=0,
        http_port=80,
        wss_port=9997,
        esp_request=False,
        ssh_key=None,
        ssh_host=None,
        ssh_port=22,
        strict_host_key=False,
        ssh_wait=1.0,
        pubkey_file=None,
        preflight="web",
        zip_out=None,
        via="web",
        dropbear=None,
        existing_daemon=None,
        daemon_port=22,
        purge_backups=False,
        keep_daemon=False,
        show_script=False,
        print_script=False,
        # API subcommand defaults
        api_subcommand="deploy",
        token=None,
        generate_token=False,
        enable_actions=False,
        enable_destructive_actions=False,
        purge_audit=False,
    )
    values.update(overrides)
    return argparse.Namespace(**values)
