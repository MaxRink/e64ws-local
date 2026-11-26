#!/usr/bin/env python3
"""Capture the images in docs/assets/setup from the real software, and record them.

Nothing here draws a picture of something that did not happen.  Every image is
one of three things:

``own capture``
    What a program printed or what a screen showed while the program ran: the
    fixture's own start-up banner, an ``adb exec-out screencap`` of the Android
    app on the emulator, a headless-Chromium frame of the simulator's control
    UI, or the stdout of the two GrinderCore executables.  A transcript image is
    a render of captured bytes, one fixed glyph per character, with no text
    added by the renderer.
``QML reconstruction``
    A frame of the reconstructed vendor HMI that already lives in
    ``tools/qml/shots`` (see ``tools/qml/README.md``).  Copied byte for byte,
    including the two empty states and the one frame with the vendor's 90-degree
    rotation baked in; the guide captions those for what they are.
``vendor manual extract``
    A page of the vendor manual.  This script neither copies nor creates one:
    those files stay in ``docs/assets`` and the guide links them by path, so
    ``docs/assets/setup`` holds nothing vendor-derived.

Each image is also labelled *reproducible* or *regenerable* in
``docs/assets/setup/PROVENANCE.md``:

*reproducible*
    Re-running the step on the same host writes the same bytes: the copies, the
    renders (fixed text, fixed font, no clock) and the control-UI and policy
    frames (the fixture reports a fixed ``hmiTime`` and those pages are a pure
    function of ``/sim/state`` and of the capability document).
*regenerable*
    The step is deterministic about *what* it shows, but the frame carries
    something this repository does not own - the duration ``am instrument``
    reported, the audit row timestamps a run wrote - so a later run can differ
    in those pixels.  ``--check`` reports the difference instead of failing.

Prerequisites, per step:

=============  ===========================================================
``hmi``        nothing
``simulator``  the repository virtualenv (``websockets``) and Pillow
``web``        the above and ``playwright`` + its Chromium build
``ios``        the above and the Swift toolchain (``swift build``)
``android``    ``adb``, ``openssl``, a booted AVD, and the two debug APKs
               (the step builds them when they are missing)
=============  ===========================================================

Exit status
-----------
0 when every requested step ran and wrote its images.  A step whose
prerequisites are missing is a *failure* by default: a requested image that was
not produced must not look like success.  Name it in ``--allow-skip`` (or pass
``--allow-skip all``) to accept the skip on a host that cannot run it.

Usage::

    python3 tools/capture_setup_screenshots.py
    python3 tools/capture_setup_screenshots.py --only hmi,simulator,web
    python3 tools/capture_setup_screenshots.py --allow-skip android
    python3 tools/capture_setup_screenshots.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets" / "setup"
PROVENANCE = OUT / "PROVENANCE.md"
QML_SHOTS = ROOT / "tools" / "qml" / "shots"
TOOLS = ROOT / "tools"
APPS = ROOT / "apps"

#: The owner token the fixture accepts for the read-only legs: 64 hex characters,
#: because both apps' ``OwnerToken`` type requires exactly that shape.
#: ``sha256("e64-local-setup-token")``, fixed rather than random so a transcript
#: is reproducible; a reader replaces it with ``openssl rand -hex 32``.  It is a
#: test fixture value and never a credential.
API_TOKEN = "f41f65daca76cc67cb3273462145a7deab38e5737a701ca591ed346098eb9a34"

#: Ports for the plain-HTTP instance the read-only legs use.
PLAIN = {"http": 8787, "ws": 9997, "scale": 8765}

#: Ports for the TLS instance the Android leg uses, as documented in
#: apps/android/E2E_EMULATOR.md: the app is TLS-only and pins the leaf.
TLS = {"http": 18787, "terminator": 18788, "ws": 19997, "scale": 18765}

#: The fixture token the terminator maps the app's 64-hex token onto.
FIXTURE_TOKEN = "sim-local-api-token"

#: How many trailing lines of each transcript a figure keeps: the summary has to
#: stay legible in a document, and the whole transcript is kept beside the image
#: as a git-ignored ``.<step>.txt``.
CHECKS_TAIL = 18
E2E_TAIL = 14

#: The audit row timestamp the fixture stamps into each row, e.g.
#: ``2026-11-25T23:00:56Z``.  Used to check the "newest first" claim.
AUDIT_STAMP = re.compile(r'text="(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)')

#: What figure 7's caption names, as exact uiautomator node text.
#:
#: Exact node text matters: ``text="Destructive actions"`` is the card's label
#: node, while the explanatory sentence below the card is a *different* node
#: whose text starts with the same two words.  A substring match would be
#: satisfied by the sentence, which is always rendered - so a screen with no
#: policy card at all would pass.  ``test_capture_setup_screenshots`` pins that.
POLICY_CARD_TEXT: tuple[str, ...] = (
    'text="Gate"',
    'text="Enabled"',
    'text="Destructive actions"',
    'text="Blocked"',
    'text="Dispatchable routes"',
    'text="18"',
)
POLICY_CATALOG_TEXT: tuple[str, ...] = ('text="implemented"',)
POLICY_SENTENCE_TEXT: tuple[str, ...] = ("--enable-destructive-actions",)

#: What figure 8's caption names.
AUDIT_TRAIL_TEXT: tuple[str, ...] = ('text="Audit trail"', 'text="4 (50 per page)"')
AUDIT_ROW_TEXT: tuple[str, ...] = (
    "action_language_set",
    "prepare",
    "execute",
    "completed",
)
AUDIT_CATALOG_TEXT: tuple[str, ...] = ("unavailable", "Unavailable:")

FONT_CANDIDATES = (
    "/System/Library/Fonts/SFNSMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
)

#: Seconds to wait for a simulator to print its banner.
BANNER_TIMEOUT = 60.0


class Skipped(Exception):
    """A step cannot run on this host; the reason is printed and it is skipped."""


class Failed(Exception):
    """A step ran and did not produce what it promises."""


def log(message: str) -> None:
    print(message, flush=True)


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise Skipped(reason)


def display(path: Path) -> str:
    """The path relative to the repository when it is inside it, else absolute."""
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def repo_python() -> str:
    """The repository virtualenv: the simulator needs its ``websockets``."""
    candidate = ROOT / ".venv" / "bin" / "python"
    return str(candidate) if candidate.is_file() else sys.executable


def have(command: str) -> bool:
    return shutil.which(command) is not None


def adb() -> str | None:
    if have("adb"):
        return "adb"
    for home in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")):
        if home and (Path(home) / "platform-tools" / "adb").is_file():
            return str(Path(home) / "platform-tools" / "adb")
    return None


def tail(text: str, lines: int = 20) -> str:
    return "\n".join((text or "").strip().splitlines()[-lines:])


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 3600,
    check: bool = True,
) -> subprocess.CompletedProcess:
    log("$ " + " ".join(command))
    completed = subprocess.run(
        command,
        cwd=cwd or ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise Failed(
            f"exited {completed.returncode}: {' '.join(command)}"
            f"\n{tail(completed.stdout, 15)}"
        )
    return completed


def run_bytes(command: list[str], *, timeout: float = 120) -> bytes:
    log("$ " + " ".join(command))
    completed = subprocess.run(
        command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise Failed(
            f"exited {completed.returncode}: {' '.join(command)}"
            f"\n{completed.stderr.decode('utf-8', 'replace')[-800:]}"
        )
    return completed.stdout


def required_port(port: int) -> int:
    """The documented port, or a failure: an image may not disagree with the guide.

    Every step that produces an image runs on the ports docs/SETUP.md prints, so
    the transcripts cannot show a port the reader was never told about.  A busy
    port is a failure with the command that finds the offender, not a silent
    fallback.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        # A previous run's connections can still be in TIME_WAIT; the fixture's
        # own server sets SO_REUSEADDR, so the probe has to as well or it would
        # report a port busy that the simulator can actually take.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            raise Failed(
                f"port {port} is already in use ({error}); "
                f"find it with: lsof -nP -iTCP:{port} -sTCP:LISTEN"
            ) from error
    return port


def wait_port(port: int, timeout: float = 30.0) -> bool:
    """TCP readiness: a TLS listener cannot answer a plain ``http://`` probe."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def wait_ready(url: str, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    return False


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# transcript renders


def _mono_font(size: int):
    from PIL import ImageFont  # noqa: PLC0415 - optional dependency, probed here

    for candidate in FONT_CANDIDATES:
        if Path(candidate).is_file():
            return ImageFont.truetype(candidate, size)
    raise Skipped("no monospaced TrueType font found; see FONT_CANDIDATES")


def render_transcript(path: Path, text: str) -> None:
    """Render captured output as a terminal frame, one glyph per character.

    The renderer adds no text of its own - not even a title, not even an
    ellipsis where lines were dropped - so every pixel of ink is a character a
    command printed.  The choice of which whole lines to keep is made by the
    caller and stated in the caption and in PROVENANCE.md.  The PNG carries no
    metadata chunk, which is what makes the same input produce the same file.
    """
    try:
        from PIL import Image, ImageDraw
    except ImportError as error:  # pragma: no cover - dependency probe
        raise Skipped("Pillow is not installed; .venv/bin/python -m pip install pillow") from error

    lines = text.replace("\t", "    ").rstrip("\n").splitlines() or [""]
    font = _mono_font(22)
    ascent, descent = font.getmetrics()
    cell = ascent + descent + 2
    widest = max(font.getlength(line) for line in lines)
    pad = int(font.getlength("MM"))
    image = Image.new(
        "RGB", (int(widest) + 2 * pad, len(lines) * cell + 2 * cell), (33, 31, 28)
    )
    draw = ImageDraw.Draw(image)
    for index, line in enumerate(lines):
        draw.text((pad, cell + index * cell), line, font=font, fill=(232, 238, 230))
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG", optimize=True)


def crop_status_bar(source: bytes, target: Path) -> None:
    """Drop the emulator's status bar: it carries the wall clock, not the app."""
    from io import BytesIO

    try:
        from PIL import Image
    except ImportError as error:  # pragma: no cover - dependency probe
        raise Skipped("Pillow is not installed; .venv/bin/python -m pip install pillow") from error

    image = Image.open(BytesIO(source))
    top = int(round(image.width * 0.102))
    image.crop((0, top, image.width, image.height)).save(target, format="PNG", optimize=True)


# ---------------------------------------------------------------------------
# the simulator


@dataclass
class Simulator:
    """One ``tools/e64ws_simulator.py`` instance, started and stopped by a leg."""

    name: str
    http_port: int
    ws_port: int
    scale_port: int
    extra: list[str] = field(default_factory=list)
    process: subprocess.Popen | None = None
    lines: list[str] = field(default_factory=list)
    _queue: queue.Queue = field(default_factory=queue.Queue)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    @property
    def tls(self) -> bool:
        return "--http-tls-cert" in self.extra

    def _pump(self) -> None:
        """Read the child's stdout into the queue, one line at a time."""
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            self._queue.put(line.rstrip("\n"))

    def wait_for(self, wanted: str, timeout: float = BANNER_TIMEOUT) -> bool:
        """Collect output until a line contains ``wanted``; False on timeout.

        A fixed sleep cannot do this job: how long the banner takes depends on
        host load, and the line either arrived or it did not.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if any(wanted in line for line in self.lines):
                return True
            try:
                line = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            self.lines.append(line)
        return any(wanted in line for line in self.lines)

    def start(self) -> "Simulator":
        command = [
            repo_python(),
            str(TOOLS / "e64ws_simulator.py"),
            "--host", "127.0.0.1",
            "--port", str(self.ws_port),
            "--scale-port", str(self.scale_port),
            "--http-port", str(self.http_port),
            *self.extra,
        ]
        log("$ " + " ".join(command))
        # PYTHONUNBUFFERED is what makes the banner readable at all: the child's
        # stdout is a pipe, and a block-buffered banner would arrive only when
        # the process exits.
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        self.process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        threading.Thread(target=self._pump, daemon=True).start()
        if not self.wait_for("Control UI:"):
            self.stop()
            raise Failed(
                f"the {self.name} simulator did not print its banner within "
                f"{BANNER_TIMEOUT:.0f}s; captured so far: {self.lines or 'nothing'}"
            )
        ready = wait_port(self.http_port) if self.tls else wait_ready(self.base_url + "/")
        if not ready:
            self.stop()
            raise Failed(f"the {self.name} simulator never answered on port {self.http_port}")
        return self

    def stop(self) -> str:
        if self.process is None:
            return ""
        self.process.terminate()
        try:
            self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate(timeout=10)
        self.process = None
        while True:
            try:
                self.lines.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return "\n".join(self.lines)

    def __enter__(self) -> "Simulator":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()


def plain_simulator() -> Simulator:
    """The read-only instance: plain HTTP, owner token a 64-hex value."""
    return Simulator(
        "plain",
        http_port=required_port(PLAIN["http"]),
        ws_port=required_port(PLAIN["ws"]),
        scale_port=required_port(PLAIN["scale"]),
        extra=["--enable-actions", "--api-token", API_TOKEN],
    )


# ---------------------------------------------------------------------------
# legs


def step_hmi(out: Path) -> list[Path]:
    """Copy the first-party HMI renders; re-rendering them needs a QEMU boot."""
    need(QML_SHOTS.is_dir(), f"missing {display(QML_SHOTS)}")
    written: list[Path] = []
    for source in sorted(QML_SHOTS.glob("*.png")):
        target = out / f"hmi-{source.stem.lower().replace('_', '-')}.png"
        shutil.copyfile(source, target)
        written.append(target)
    need(bool(written), "no PNG files in tools/qml/shots")
    return written


def step_simulator(out: Path) -> list[Path]:
    """Start the fixture, keep the banner it printed, render that banner."""
    simulator = plain_simulator()
    try:
        simulator.start()
    finally:
        banner = simulator.stop()
    text = "\n".join(
        line for line in banner.splitlines() if line.strip() and "Traceback" not in line
    )
    need("Control UI:" in text, f"unexpected simulator banner: {tail(text, 5)}")
    write_text(out / ".simulator-banner.txt", text + "\n")
    render_transcript(out / "01-simulator-start.png", text)
    return [out / "01-simulator-start.png"]


def step_web(out: Path) -> list[Path]:
    """Screenshot the control UI the simulator serves, in headless Chromium."""
    need(have("npx") or have("playwright"), "neither npx nor playwright is on PATH")
    launcher = ["npx", "--no-install", "playwright"] if have("npx") else ["playwright"]
    target = out / "02-simulator-web-surface.png"
    with plain_simulator() as simulator:
        # A fixed starting point: the page is a pure function of /sim/state.
        request = urllib.request.Request(
            simulator.base_url + "/sim/reset", data=b"{}", method="POST"
        )
        request.add_header("content-type", "application/json")
        urllib.request.urlopen(request, timeout=10).read()
        run(
            [
                *launcher,
                "screenshot",
                "--browser", "chromium",
                "--viewport-size", "1100,1050",
                "--wait-for-timeout", "2500",
                simulator.base_url + "/",
                str(target),
            ],
            timeout=300,
        )
    need(target.is_file() and target.stat().st_size > 0, "playwright wrote no file")
    return [target]


def _tail_lines(text: str, count: int) -> str:
    lines = text.rstrip("\n").splitlines()
    return "\n".join(lines[-count:])


def step_ios(out: Path) -> list[Path]:
    """Build GrinderCore, then run its two executables and keep what they print.

    The build and the program are separate commands on purpose: ``swift run``
    interleaves SwiftPM's own progress lines with the program's stdout, and a
    figure that claims to be the program's output must contain only that.
    """
    need(have("swift"), "swift is not on PATH (install the Xcode command line tools)")
    core = APPS / "ios" / "GrinderCore"
    need(core.is_dir(), "missing apps/ios/GrinderCore")
    checks_binary = core / ".build" / "debug" / "GrinderCoreChecks"
    e2e_binary = core / ".build" / "debug" / "GrinderCoreE2E"
    written: list[Path] = []

    run(["swift", "build", "--build-tests"], cwd=core)
    need(checks_binary.is_file(), f"missing {display(checks_binary)} after the build")
    need(e2e_binary.is_file(), f"missing {display(e2e_binary)} after the build")

    checks = run([str(checks_binary)], cwd=core).stdout.rstrip("\n")
    need("checks passed" in checks, f"the checks did not pass: {tail(checks, 5)}")
    write_text(out / ".ios-core-checks.txt", checks + "\n")
    render_transcript(out / "03-ios-core-checks.png", _tail_lines(checks, CHECKS_TAIL))
    written.append(out / "03-ios-core-checks.png")

    with plain_simulator() as simulator:
        environment = os.environ.copy()
        environment["E64_E2E_BASE_URL"] = simulator.base_url
        environment["E64_E2E_TOKEN"] = API_TOKEN
        environment["E64_E2E_VERBOSE"] = "1"
        e2e = run([str(e2e_binary)], cwd=core, env=environment).stdout.rstrip("\n")
    need("E2E PASS" in e2e, f"the E2E suite did not pass: {tail(e2e, 5)}")
    write_text(out / ".ios-e2e.txt", e2e + "\n")
    render_transcript(out / "04-ios-e2e-pass.png", _tail_lines(e2e, E2E_TAIL))
    written.append(out / "04-ios-e2e-pass.png")
    return written


def _certificate() -> tuple[Path, Path, str]:
    """The terminator's certificate and the fingerprint the app pins."""
    need(have("openssl"), "openssl is not on PATH")
    directory = ROOT / ".tools"
    directory.mkdir(parents=True, exist_ok=True)
    cert, key = directory / "e2e.crt", directory / "e2e.key"
    if not (cert.is_file() and key.is_file()):
        run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                "-days", "30", "-nodes", "-subj", "/CN=e64-e2e-terminator",
                "-keyout", str(key), "-out", str(cert),
            ]
        )
    shown = run(["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"])
    match = re.search(r"=([0-9A-F:]{95})", shown.stdout)
    need(match is not None, f"cannot read a SHA-256 fingerprint out of {display(cert)}")
    return cert, key, match.group(1)


def _android_apks() -> tuple[Path, Path]:
    """The debug and instrumented-test APKs, built when they are not there."""
    app = APPS / "android" / "app" / "build" / "outputs" / "apk"
    debug = app / "debug" / "app-debug.apk"
    test = app / "androidTest" / "debug" / "app-debug-androidTest.apk"
    if debug.is_file() and test.is_file():
        return debug, test
    need((APPS / "android" / "gradlew").is_file(), "no gradlew in apps/android")
    environment = os.environ.copy()
    environment.setdefault("ANDROID_HOME", str(Path.home() / "Library" / "Android" / "sdk"))
    environment.setdefault("ANDROID_SDK_ROOT", environment["ANDROID_HOME"])
    run(
        ["./gradlew", "--console=plain", ":app:assembleDebug", ":app:assembleDebugAndroidTest"],
        cwd=APPS / "android",
        env=environment,
    )
    need(debug.is_file() and test.is_file(), "gradle produced neither APK")
    return debug, test


def _emulator_serial(binary: str) -> str:
    listing = run([binary, "devices"]).stdout
    serials = [
        line.split()[0]
        for line in listing.splitlines()
        if line.startswith("emulator-") and line.endswith("device")
    ]
    need(len(serials) == 1, f"expected exactly one running emulator, found {serials or 'none'}")
    return serials[0]


def _dump_ui(binary: str, serial: str) -> str:
    run([binary, "-s", serial, "shell", "uiautomator", "dump", "/sdcard/setup-ui.xml"], check=False)
    return run([binary, "-s", serial, "shell", "cat", "/sdcard/setup-ui.xml"], check=False).stdout


def _missing(dump: str, wanted: tuple[str, ...]) -> list[str]:
    return [item for item in wanted if item not in dump]


def require_policy_card(dump: str) -> None:
    """Refuse figure 7 unless every value its caption names is on the screen.

    ``Failed``, not ``Skipped``: a wrong screen is a defect in the run, and
    ``--allow-skip`` must not be able to turn it into a shipped caption.  That
    flag exists for a host without an emulator, not for a frame that disagrees
    with its text.
    """
    missing = _missing(
        dump, POLICY_CARD_TEXT + POLICY_CATALOG_TEXT + POLICY_SENTENCE_TEXT
    )
    if missing:
        raise Failed(
            "the Actions policy card is not on screen: the dump does not show "
            f"{missing}. Figure 7's caption names the gate, the destructive class, "
            "the dispatchable-route count and the catalog status, so capturing now "
            "would ship a caption the pixels do not support."
        )


def require_audit_trail(dump: str) -> None:
    """Refuse figure 8 unless its audit trail, row count and catalog are there."""
    missing = _missing(dump, AUDIT_TRAIL_TEXT + AUDIT_ROW_TEXT + AUDIT_CATALOG_TEXT)
    if missing:
        raise Failed(
            "the audit trail is not on screen: the dump does not show "
            f"{missing}. Figure 8's caption names the trail, its row count and the "
            "catalog reasons, so capturing now would ship a caption the pixels do "
            "not support."
        )
    stamps = AUDIT_STAMP.findall(dump)
    if len(stamps) < 2:
        raise Failed(
            "the audit trail shows fewer than two timestamped rows, so figure 8's "
            f"caption cannot claim 'newest first': {stamps}"
        )
    if stamps != sorted(stamps, reverse=True):
        raise Failed(f"the audit rows are not newest first: {stamps}")


def _capture_frame(
    dump: str,
    check,
    screenshot,
    target: Path,
    *,
    what: str,
    redump=None,
    crop=crop_status_bar,
) -> None:
    """Check the screen, capture it, then check it again and crop it.

    The second check covers the gap between the dump and the screencap: a drag or
    a refresh can move the content after the first check passed.
    """
    check(dump)
    frame = screenshot()
    if redump is not None:
        try:
            check(redump())
        except Failed as moved:
            raise Failed(
                f"{what}: the screen changed between the dump and the capture ({moved})"
            ) from moved
    crop(frame, target)


def _tap_text(binary: str, serial: str, wanted: str, *, bottom: bool) -> None:
    """Tap the node whose text is ``wanted``; ``bottom`` restricts it to the tab bar."""
    dump = _dump_ui(binary, serial)
    candidates = []
    for match in re.finditer(r"<node[^>]*>", dump):
        tag = match.group(0)
        text = re.search(r'text="([^"]*)"', tag)
        bounds = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', tag)
        if not bounds or not text or text.group(1).strip() != wanted:
            continue
        x1, y1, x2, y2 = (int(value) for value in bounds.groups())
        candidates.append((x1, y1, x2, y2))
    need(bool(candidates), f"no node with text {wanted!r} on screen")
    if bottom:
        screen_height = max(node[3] for node in candidates)
        candidates = [node for node in candidates if node[1] > screen_height * 0.8] or candidates
    x1, y1, x2, y2 = candidates[-1]
    run(
        [binary, "-s", serial, "shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2)]
    )


@contextmanager
def _terminator(cert: Path, key: Path, upstream_port: int) -> Iterator[int]:
    """Run ``apps/android/e2e/device_terminator.py`` for the duration of the block."""
    port = required_port(TLS["terminator"])
    command = [
        sys.executable,
        str(APPS / "android" / "e2e" / "device_terminator.py"),
        "--listen-port", str(port),
        "--cert", str(cert),
        "--key", str(key),
        "--upstream-port", str(upstream_port),
        "--fixture-token", FIXTURE_TOKEN,
        "--accept-token", API_TOKEN,
    ]
    log("$ " + " ".join(command))
    process = subprocess.Popen(
        command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    try:
        # The terminator speaks TLS by design, so readiness is a TCP connect.
        need(wait_port(port), "the terminator never answered on its port")
        yield port
    finally:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)


def step_android(out: Path) -> list[Path]:
    """Install the app, run its instrumented suite, screenshot the live screens."""
    binary = adb()
    need(binary is not None, "adb is not on PATH and not under $ANDROID_HOME/platform-tools")
    need(_pillow(), "Pillow is not installed; pip install pillow")
    serial = _emulator_serial(binary)
    cert, key, fingerprint = _certificate()
    debug, test = _android_apks()

    written: list[Path] = []
    tls = Simulator(
        "tls",
        http_port=required_port(TLS["http"]),
        ws_port=required_port(TLS["ws"]),
        scale_port=required_port(TLS["scale"]),
        extra=[
            "--enable-actions",
            "--api-token", FIXTURE_TOKEN,
            "--http-tls-cert", str(cert),
            "--http-tls-key", str(key),
        ],
    )
    with tls, _terminator(cert, key, tls.http_port) as terminator_port:
        for apk in (debug, test):
            run([binary, "-s", serial, "install", "-r", "-t", str(apk)])

        # The suite writes the owner's stored settings the way the setup wizard
        # does, then drives the real Compose UI; its own stdout is the evidence.
        instrumented = run(
            [
                binary, "-s", serial, "shell", "am", "instrument", "-w",
                "-e", "class", "de.mahlkoenig.e64local.ActionsE2E",
                "-e", "e2ePort", str(terminator_port),
                "-e", "e2eToken", API_TOKEN,
                "-e", "e2ePassword", "sim-password",
                "-e", "e2eCertSha256", fingerprint,
                "de.mahlkoenig.e64local.test/androidx.test.runner.AndroidJUnitRunner",
            ],
            timeout=900,
        )
        need(
            "OK (1 test)" in instrumented.stdout,
            f"the instrumented suite did not pass: {tail(instrumented.stdout, 8)}",
        )
        write_text(out / ".android-instrumented.txt", instrumented.stdout.strip() + "\n")
        render_transcript(out / "05-android-instrumented-e2e.png", instrumented.stdout.strip())
        written.append(out / "05-android-instrumented-e2e.png")

        launch = [
            binary, "-s", serial, "shell", "am", "start",
            "-n", "de.mahlkoenig.e64local/.MainActivity",
        ]
        run(launch)
        time.sleep(5)
        screen = _dump_ui(binary, serial)
        need(
            "V01.16-24-mock" in screen,
            "the dashboard did not report the simulator's firmware; is the app still connected?",
        )
        crop_status_bar(
            run_bytes([binary, "-s", serial, "exec-out", "screencap", "-p"]),
            out / "06-android-dashboard.png",
        )
        written.append(out / "06-android-dashboard.png")

        # The policy card sits at the top of the Actions tab and scrolls away, so
        # it gets its own frame rather than being described in a caption about a
        # viewport it is not in.
        _tap_text(binary, serial, "Actions", bottom=True)
        time.sleep(4)
        _capture_frame(
            _dump_ui(binary, serial),
            require_policy_card,
            lambda: run_bytes([binary, "-s", serial, "exec-out", "screencap", "-p"]),
            out / "07-android-actions-policy.png",
            what="figure 7 (Actions policy)",
            redump=lambda: _dump_ui(binary, serial),
        )
        written.append(out / "07-android-actions-policy.png")

        for _ in range(8):
            run([binary, "-s", serial, "shell", "input", "swipe", "540", "1900", "540", "600", "250"])
            time.sleep(0.6)
        audit = _dump_ui(binary, serial)
        for _ in range(4):
            run([binary, "-s", serial, "shell", "input", "swipe", "540", "700", "540", "900", "250"])
            time.sleep(0.6)
            audit = _dump_ui(binary, serial)
            if 'text="Audit trail"' in audit and "completed" in audit:
                break
        _capture_frame(
            audit,
            require_audit_trail,
            lambda: run_bytes([binary, "-s", serial, "exec-out", "screencap", "-p"]),
            out / "08-android-action-audit.png",
            what="figure 8 (audit trail)",
            redump=lambda: _dump_ui(binary, serial),
        )
        written.append(out / "08-android-action-audit.png")
    return written


def _pillow() -> bool:
    return subprocess.run(
        [repo_python(), "-c", "import PIL"], capture_output=True, check=False
    ).returncode == 0


# ---------------------------------------------------------------------------
# determinism and completeness check


def read_provenance() -> dict[str, tuple[str, str]]:
    """``file -> (reproducibility, sha256)`` from the markdown table."""
    if not PROVENANCE.is_file():
        return {}
    rows: dict[str, tuple[str, str]] = {}
    for line in PROVENANCE.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 7:
            continue
        name = cells[0].strip("`")
        if name.startswith("../"):
            # A file this directory links but does not hold, e.g. a vendor page.
            continue
        rows[name] = (cells[6], cells[5].strip("`"))
    return rows


def check(args: argparse.Namespace) -> int:
    if not PROVENANCE.is_file():
        log(f"no {display(PROVENANCE)} to check against")
        return 1
    recorded = read_provenance()
    if not recorded:
        log(f"{display(PROVENANCE)} records no rows")
        return 1
    failures = 0
    for name, (reputation, expected) in sorted(recorded.items()):
        path = args.out / name
        if not path.is_file():
            # A whole directory can go missing; a row with no file is a failure,
            # never a silent zero.
            failures += 1
            log(f"  MISSING {name}  (recorded as {reputation}, not on disk)")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest == expected:
            log(f"  OK      {name}  {reputation}")
        elif reputation.startswith("reproducible"):
            failures += 1
            log(f"  DRIFT   {name}: {digest} != {expected}")
        else:
            log(f"  changed {name}  (regenerable, not a failure)")
    extra = {path.name for path in args.out.glob("*.png")} - set(recorded)
    for name in sorted(extra):
        failures += 1
        log(f"  UNRECORDED {name}  (no row in {display(PROVENANCE)})")
    log("")
    log(f"{len(recorded)} row(s) checked, {failures} failure(s)")
    return 1 if failures else 0


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--only",
        default="hmi,simulator,web,ios,android",
        help="comma-separated subset of hmi, simulator, web, ios, android",
    )
    parser.add_argument("--out", type=Path, default=OUT, help="image directory")
    parser.add_argument("--check", action="store_true", help="compare with PROVENANCE.md")
    parser.add_argument(
        "--allow-skip",
        default="",
        help="comma-separated steps whose skip is acceptable, or 'all'",
    )
    args = parser.parse_args(argv)

    args.out = args.out.resolve()
    allowed_skips = {name.strip() for name in args.allow_skip.split(",") if name.strip()}
    if args.check:
        try:
            return check(args)
        except Skipped as skipped:
            log(f"SKIP {skipped}")
            return 1

    if not _pillow():
        log("Pillow is not installed: the transcript renders and the phone crops")
        log("will be skipped. Install it in the repository virtualenv with")
        log("  .venv/bin/python -m pip install pillow")

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    steps = {
        "hmi": step_hmi,
        "simulator": step_simulator,
        "web": step_web,
        "ios": step_ios,
        "android": step_android,
    }
    selected = [name.strip() for name in args.only.split(",") if name.strip()]
    written: list[Path] = []
    failures = 0
    for name in selected:
        step = steps.get(name)
        if step is None:
            log(f"unknown step {name}; known steps are {', '.join(sorted(steps))}")
            failures += 1
            continue
        log(f"== {name}")
        try:
            written.extend(step(out))
        except Skipped as skipped:
            # A requested image that was not produced is a failure unless the
            # caller said this host cannot produce it.
            if "all" in allowed_skips or name in allowed_skips:
                log(f"  SKIP {name}: {skipped} (allowed by --allow-skip)")
            else:
                failures += 1
                log(f"  FAIL {name}: {skipped} (name it in --allow-skip to accept the skip)")
        except Failed as failed:
            failures += 1
            log(f"  FAIL {name}: {failed}")

    log("")
    log(f"wrote {len(written)} image(s) into {display(out)}:")
    for path in written:
        log(f"  {path.name:34s} {path.stat().st_size:8d} B")
    if failures:
        log(f"{failures} step(s) failed or were skipped without --allow-skip")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
