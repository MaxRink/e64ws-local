#!/usr/bin/env python3
"""Run both apps' end-to-end suites against the local simulator.

This is the only test path that exercises the apps' real HTTP stacks instead of
a stubbed transport. It starts ``tools/e64ws_simulator.py`` on free loopback
ports, waits for it to answer, then runs:

* ``swift run GrinderCoreE2E`` in ``apps/ios/GrinderCore``;
* ``./gradlew :app:testDebugUnitTest --tests de.mahlkoenig.e64local.e2e.*``
  in ``apps/android``.

Each suite follows one contract: ``E64_E2E_BASE_URL`` and ``E64_E2E_TOKEN`` in
the environment, ``E2E SKIP`` with exit 0 when the URL is absent, ``E2E PASS n``
on success, ``E2E FAIL`` on stderr with exit 1.

The emulator-based instrumented test is not run here: this host has no running
emulator, and the harness says so rather than pretending otherwise.

Usage:
    python3 tools/e2e/run_apps_e2e.py                 # both suites
    python3 tools/e2e/run_apps_e2e.py --only ios
    python3 tools/e2e/run_apps_e2e.py --json /tmp/e2e.json --keep
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIMULATOR = ROOT / "tools" / "e64ws_simulator.py"
IOS = ROOT / "apps" / "ios" / "GrinderCore"
ANDROID = ROOT / "apps" / "android"
#: The fixture accepts a 64-hex owner token, so a client whose OwnerToken
#: type requires one can send the credential it actually holds.  Derived, not
#: random, so a failure transcript is reproducible.
API_TOKEN = hashlib.sha256(b"e64-local-e2e-token").hexdigest()


def simulator_python() -> str:
    """Prefer the repository virtualenv: the simulator imports websockets."""
    candidate = ROOT / ".venv" / "bin" / "python"
    return str(candidate) if candidate.is_file() else sys.executable


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_ready(url: str, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    return False


def tail(text: str, lines: int = 25) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


class Simulator:
    def __init__(self, token: str, destructive: bool = False) -> None:
        self.token = token
        self.destructive = destructive
        self.http_port = free_port()
        self.ws_port = free_port()
        self.scale_port = free_port()
        self.process: subprocess.Popen | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    def start(self) -> bool:
        command = [
            simulator_python(),
            str(SIMULATOR),
            "--http-port", str(self.http_port),
            "--port", str(self.ws_port),
            "--scale-port", str(self.scale_port),
            # A shipped image has the action gate closed; the fixture opens it
            # explicitly so the apps can exercise the real five-route protocol.
            "--enable-actions",
            "--api-token", self.token,
        ]
        if self.destructive:
            command.append("--enable-destructive-actions")
        self.process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        return wait_ready(self.base_url + "/")

    def stop(self) -> str:
        if self.process is None:
            return ""
        self.process.terminate()
        try:
            output, _ = self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            output, _ = self.process.communicate(timeout=10)
        return output or ""


def run_suite(name: str, command: list[str], cwd: Path, env: dict[str, str]) -> dict:
    started = time.time()
    try:
        completed = subprocess.run(
            command, cwd=cwd, env=env, capture_output=True, text=True, timeout=1800
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        status = completed.returncode
    except FileNotFoundError:
        return {
            "suite": name,
            "status": "unavailable",
            "detail": f"{command[0]} not found",
            "durationSeconds": round(time.time() - started, 1),
        }
    except subprocess.TimeoutExpired:
        return {
            "suite": name,
            "status": "timeout",
            "detail": "suite exceeded 1800 s",
            "durationSeconds": round(time.time() - started, 1),
        }

    verdict = "fail"
    if "E2E SKIP" in output and status == 0:
        verdict = "skipped"
    elif status == 0 and "E2E PASS" in output:
        verdict = "pass"
    return {
        "suite": name,
        "status": verdict,
        "exitCode": status,
        "durationSeconds": round(time.time() - started, 1),
        "summary": next(
            (line for line in output.splitlines() if line.startswith("E2E ")), ""
        ),
        "tail": tail(output) if verdict != "pass" else "",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run both apps against the simulator.")
    parser.add_argument("--only", choices=("ios", "android"), help="run one suite")
    parser.add_argument("--json", type=Path, help="write the report here")
    parser.add_argument("--keep", action="store_true", help="leave the simulator running")
    parser.add_argument(
        "--destructive",
        action="store_true",
        help="also open the fixture's destructive gate",
    )
    parser.add_argument("--token", default=API_TOKEN)
    args = parser.parse_args(argv)

    simulator = Simulator(args.token, destructive=args.destructive)
    if not simulator.start():
        print("E2E FAIL simulator did not become ready", file=sys.stderr)
        print(tail(simulator.stop(), 12), file=sys.stderr)
        return 1

    env = os.environ.copy()
    env["E64_E2E_BASE_URL"] = simulator.base_url
    env["E64_E2E_TOKEN"] = args.token
    env.setdefault("ANDROID_HOME", str(Path.home() / "Library" / "Android" / "sdk"))

    results: list[dict] = []
    logs = ""
    try:
        if args.only in (None, "ios"):
            results.append(
                run_suite("ios", ["swift", "run", "GrinderCoreE2E"], IOS, env)
            )
        if args.only in (None, "android"):
            results.append(
                run_suite(
                    "android",
                    [
                        "./gradlew",
                        ":app:testDebugUnitTest",
                        "--tests",
                        "de.mahlkoenig.e64local.e2e.*",
                    ],
                    ANDROID,
                    env,
                )
            )
    finally:
        if args.keep:
            print(f"simulator left running at {simulator.base_url}")
        else:
            logs = simulator.stop()

    failed = [result for result in results if result["status"] not in ("pass", "skipped")]
    if failed and logs:
        print("simulator log tail:")
        print(tail(logs, 10))

    report = {
        "baseUrl": simulator.base_url,
        "results": results,
        "instrumented": "not run: no emulator on this host",
    }
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    for result in results:
        print(f"{result['suite']}: {result['status']} ({result['durationSeconds']}s) {result.get('summary', '')}".rstrip())
        if result.get("tail"):
            print(result["tail"])
    return 1 if failed or not results else 0


if __name__ == "__main__":
    raise SystemExit(main())
