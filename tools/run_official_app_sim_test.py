#!/usr/bin/env python3
"""Run a no-login, no-cloud official-app/local-simulator smoke test.

The harness forwards only loopback HTTP requests, rejects every CONNECT and
every non-loopback HTTP target, and restores Android proxy/reverse settings.
It never enters credentials or calls a cloud endpoint.
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import json
import re
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


PACKAGE = "com.mahlkoenig.sync.app.android"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
LOCAL_GRINDER_AP_HOSTS = {"192.168.4.1", "172.16.0.1"}
SECRET_RE = re.compile(
    r"(?i)(bearer\s+|token[=:/ ]+|password[=:/ ]+|passwd[=:/ ]+|"
    r"authorization[=:/ ]+|cookie[=:/ ]+)([^\s&;,]+)"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def redact(value: str) -> str:
    value = SECRET_RE.sub(lambda match: f"{match.group(1)}<redacted>", value)
    return EMAIL_RE.sub("<email-redacted>", value)


def simulator_interpreter() -> str:
    """Use the repository environment when the system Python lacks websockets."""
    candidate = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python"
    return str(candidate) if candidate.exists() else sys.executable


class Transcript:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.events: list[dict[str, Any]] = []

    def add(self, **event: Any) -> None:
        event["time"] = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.events.append(json.loads(redact(json.dumps(event))))

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.events)


class ContainedProxy(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(
        self, address: tuple[str, int], transcript: Transcript, simulator_port: int
    ):
        super().__init__(address, ProxyHandler)
        self.transcript = transcript
        self.simulator_port = simulator_port
        self.daemon_threads = True


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_CONNECT(self) -> None:  # noqa: N802
        target_host = self.path.rsplit(":", 1)[0].strip("[]").lower()
        kind = "local_tls_unavailable" if target_host in LOCAL_GRINDER_AP_HOSTS else "cloud_blocked"
        self.server.transcript.add(  # type: ignore[attr-defined]
            kind=kind, method="CONNECT", target=self.path, status=403
        )
        self.send_error(403, "CONNECT disabled by local-only harness")
        self.close_connection = True

    def _forward(self) -> None:
        target = urlsplit(self.path)
        host = target.hostname
        port = target.port or 80
        if not host:
            self.server.transcript.add(  # type: ignore[attr-defined]
                kind="rejected", method=self.command, target=self.path, status=400
            )
            self.send_error(400, "absolute-form proxy request required")
            return
        is_grinder_alias = host in LOCAL_GRINDER_AP_HOSTS
        if host not in LOCAL_HOSTS and not is_grinder_alias:
            self.server.transcript.add(  # type: ignore[attr-defined]
                kind="cloud_blocked", method=self.command,
                target=f"{target.scheme}://{host}:{port}{target.path}", status=403,
            )
            self.send_error(403, "non-loopback target blocked by local-only harness")
            self.close_connection = True
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(min(length, 1024 * 1024)) if length else None
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"proxy-connection", "connection", "host"}
        }
        headers["Host"] = target.netloc
        forward_host = "127.0.0.1" if is_grinder_alias else host
        forward_port = self.server.simulator_port if is_grinder_alias else port  # type: ignore[attr-defined]
        try:
            connection = http.client.HTTPConnection(forward_host, forward_port, timeout=3)
            connection.request(self.command, path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(1024 * 1024)
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "transfer-encoding", "content-length"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            # Record before the body reaches the client: the harness reads the
            # transcript as soon as the response completes, and a client that
            # wins the race would otherwise see an empty snapshot.
            self.server.transcript.add(  # type: ignore[attr-defined]
                kind="local_request", method=self.command,
                target=f"http://{host}:{port}{path}", status=response.status,
                forwarded_to=f"http://{forward_host}:{forward_port}{path}",
                grinder_ap_alias=is_grinder_alias,
                request_bytes=length, response_bytes=len(response_body),
            )
            self.wfile.write(response_body)
            connection.close()
        except (OSError, http.client.HTTPException) as exc:
            self.server.transcript.add(  # type: ignore[attr-defined]
                kind="local_error", method=self.command, target=self.path,
                error=type(exc).__name__,
            )
            self.send_error(502, "local target unavailable")

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_PATCH = _forward
    do_DELETE = _forward
    do_OPTIONS = _forward


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=check)


def adb(serial: str | None, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    command = ["adb"]
    if serial:
        command += ["-s", serial]
    return run(command + list(args), check=check)


def choose_device(serial: str | None) -> str:
    if serial:
        result = adb(serial, "get-state", check=False)
        if result.stdout.strip() == "device":
            return serial
        raise RuntimeError(f"ADB serial is not ready: {serial}")
    result = run(["adb", "devices"], check=False)
    devices = [
        line.split("\t", 1)[0]
        for line in result.stdout.splitlines()
        if "\tdevice" in line
    ]
    if len(devices) != 1:
        raise RuntimeError(f"expected exactly one ready ADB device, found {devices!r}")
    return devices[0]


def reverse_mappings(serial: str) -> set[str]:
    result = adb(serial, "reverse", "--list", check=False)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def add_reverse(serial: str, port: int, existing: set[str]) -> bool:
    marker = f"tcp:{port} tcp:{port}"
    if any(marker in line for line in existing):
        return False
    adb(serial, "reverse", f"tcp:{port}", f"tcp:{port}")
    return True


def restore_reverse(serial: str, added: list[int]) -> None:
    for port in added:
        adb(serial, "reverse", "--remove", f"tcp:{port}", check=False)


def simulator_probe(port: int) -> tuple[str, dict[str, Any] | None]:
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request("GET", "/sim/state")
        response = connection.getresponse()
        body = json.loads(response.read().decode())
        connection.close()
        simulator_marker = (
            body.get("simulator") is True
            or body.get("config", {}).get("simulator") is True
            or body.get("grinder", {}).get("simulator") is True
        )
        if response.status == 200 and simulator_marker:
            return "PASS", body
        return "FAIL", {"http_status": response.status}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return "FAIL", {"error": type(exc).__name__}


def start_logcat(serial: str) -> subprocess.Popen[str] | None:
    try:
        return subprocess.Popen(
            ["adb", "-s", serial, "logcat", "-v", "threadtime"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
    except OSError:
        return None


def stop_logcat(process: subprocess.Popen[str] | None) -> str:
    if process is None or process.stdout is None:
        return ""
    process.terminate()
    try:
        output, _ = process.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
    return redact(output)


def activity_is_foreground(serial: str, package: str) -> bool:
    result = adb(serial, "shell", "dumpsys", "activity", "activities", check=False)
    return package in result.stdout and "ResumedActivity" in result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="ADB serial; otherwise require exactly one device")
    parser.add_argument("--package", default=PACKAGE)
    parser.add_argument("--duration", type=float, default=15.0)
    parser.add_argument("--sim-port", type=int, default=8787)
    parser.add_argument("--sim-ws-port", type=int, default=9997)
    parser.add_argument("--scale-port", type=int, default=8765)
    parser.add_argument("--proxy-port", type=int, default=0)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--no-start-simulator", action="store_true")
    args = parser.parse_args()

    output_dir = args.output_dir or Path(
        tempfile.mkdtemp(prefix="mahlkoenig-official-app-")
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    transcript = Transcript()
    simulator_process: subprocess.Popen[str] | None = None
    logcat_process: subprocess.Popen[str] | None = None
    serial: str | None = None
    added_reverse: list[int] = []
    original_proxy: str | None = None
    proxy_changed = False
    report: dict[str, Any] = {
        "policy": {
            "login": False,
            "cloud_connect": False,
            "non_loopback_forwarding": False,
        },
        "output_dir": str(output_dir),
    }
    proxy: ContainedProxy | None = None
    try:
        if not args.no_start_simulator:
            simulator_process = subprocess.Popen(
                [
                    simulator_interpreter(),
                    str(Path(__file__).with_name("e64ws_simulator.py")),
                    "--host", "127.0.0.1",
                    "--port", str(args.sim_ws_port),
                    "--scale-port", str(args.scale_port),
                    "--http-port", str(args.sim_port),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                text=True,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status, state = simulator_probe(args.sim_port)
                if status == "PASS":
                    break
                time.sleep(0.1)
            else:
                status, state = simulator_probe(args.sim_port)
        else:
            status, state = simulator_probe(args.sim_port)
        report["simulator"] = {"status": status, "evidence": state}
        if status != "PASS":
            raise RuntimeError("local simulator did not pass its state probe")

        proxy = ContainedProxy(
            ("127.0.0.1", args.proxy_port), transcript, args.sim_port
        )
        proxy_port = proxy.server_address[1]
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        serial = choose_device(args.serial)
        existing_reverse = reverse_mappings(serial)
        for port in (args.sim_port, args.sim_ws_port, proxy_port):
            if add_reverse(serial, port, existing_reverse):
                added_reverse.append(port)
        original_proxy = adb(
            serial, "shell", "settings", "get", "global", "http_proxy"
        ).stdout.strip()
        if original_proxy in {"", "null", "None"}:
            original_proxy = None
        adb(
            serial, "shell", "settings", "put", "global", "http_proxy",
            f"127.0.0.1:{proxy_port}",
        )
        proxy_changed = True
        transcript.add(
            kind="harness", event="adb_configured", serial=serial,
            proxy=f"127.0.0.1:{proxy_port}", reverse_ports=added_reverse,
        )

        logcat_process = start_logcat(serial)
        launch = adb(
            serial, "shell", "monkey", "-p", args.package, "1", check=False
        )
        transcript.add(
            kind="harness", event="package_launched", package=args.package,
            returncode=launch.returncode,
            output=redact((launch.stdout + launch.stderr)[-2000:]),
        )
        report["app_launch"] = {
            "status": "PASS" if activity_is_foreground(serial, args.package) else "FAIL",
            "monkey_returncode": launch.returncode,
        }
        time.sleep(max(0.0, args.duration))
        logs = stop_logcat(logcat_process)
        (output_dir / "logcat.redacted.txt").write_text(logs, encoding="utf-8")
        events = transcript.snapshot()
        local_events = [event for event in events if event.get("kind") == "local_request"]
        blocked_events = [event for event in events if event.get("kind") == "cloud_blocked"]
        local_tls_events = [
            event for event in events if event.get("kind") == "local_tls_unavailable"
        ]
        report["app_reachability"] = {
            "status": "PASS" if local_events else "NOT_OBSERVED",
            "local_requests": len(local_events),
            "evidence": local_events,
        }
        report["cloud_blocked"] = {
            "status": "BLOCKED" if blocked_events else "NOT_OBSERVED",
            "attempts_rejected": len(blocked_events),
            "evidence": blocked_events,
        }
        report["local_tls_unavailable"] = {
            "status": "OBSERVED" if local_tls_events else "NOT_OBSERVED",
            "attempts_rejected": len(local_tls_events),
            "evidence": local_tls_events,
        }
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        report.setdefault("harness", {})["error"] = redact(
            f"{type(exc).__name__}: {exc}"
        )
        report.setdefault("app_reachability", {"status": "BLOCKED_BY_HARNESS"})
        report.setdefault("cloud_blocked", {"status": "NOT_OBSERVED"})
        report.setdefault("local_tls_unavailable", {"status": "NOT_OBSERVED"})
    finally:
        if logcat_process is not None:
            logs = stop_logcat(logcat_process)
            (output_dir / "logcat.redacted.txt").write_text(logs, encoding="utf-8")
        if proxy is not None:
            proxy.shutdown()
            proxy.server_close()
        if serial:
            if proxy_changed:
                if original_proxy is None:
                    adb(
                        serial, "shell", "settings", "delete", "global",
                        "http_proxy", check=False,
                    )
                else:
                    adb(
                        serial, "shell", "settings", "put", "global",
                        "http_proxy", original_proxy, check=False,
                    )
            restore_reverse(serial, added_reverse)
        if simulator_process is not None:
            simulator_process.terminate()
            try:
                simulator_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                simulator_process.kill()
        report["transcript"] = transcript.snapshot()
        (output_dir / "network.redacted.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("simulator", {}).get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
