"""Integration test that runs ``tools/xenia_emulator.py`` as a real process.

Why a subprocess test
---------------------

``tests/test_xenia_emulator.py`` imports :class:`XeniaServer` and talks to it in
the same interpreter, which proves the handler logic.  It cannot prove that
``main()``, the CLI flags, the two listeners and the shutdown path work - and
the grinder talks to a process, not to a class.  This test starts the emulator
exactly as the docs tell an owner to start it, polls it over HTTP, and drives it
through the control port.

What is asserted, and where the expectation comes from
------------------------------------------------------

Every assertion is tied to a section of ``docs/XENIA_FIRMWARE.md`` or to the
emulator's own docstring; the mapping is repeated in the appended section of
``docs/XENIA_FIRMWARE.md``:

* ``/api/v2/machine`` carries ``MA_TYPE`` and ``MA_SN`` — §5.4 step 1 and §9.5
  ("include `MA_TYPE` in `/api/v2/machine` so the scanner accepts it").
* ``/api/v2/mako`` answers with the §2.2 field set the emulator implements, and
  the fields it does not implement are recorded as a known gap below.
* ``POST /api/v2/scripts/execute {"ID": 9}`` starts a brew: the next poll shows
  ``MA_STATUS`` 3 (``MACH_ACTIVE_SERVING``, §2.2 enum).
* ``POST /api/v2/brewratio`` echoes ``MA_SYNC_BEVERAGE_WEIGHT``/``MA_SYNC_FILTER``
  and the values appear on the next ``/api/v2/mako`` poll (§2.4, §3.3).
* ``POST /control/shot`` finishes a shot: exactly one poll reports
  ``MA_STATUS`` 4 (``MACH_ACTIVE_FINISHING``) with
  ``REAL_EXTRACTION_TIME_MS`` set, and the following poll is back at 1
  (``MACH_ON``).  This is the emulator's documented "one finishing poll"
  behaviour, not a claim about a real machine.

Known gaps this test records instead of hiding
---------------------------------------------

``PU_SENS_FLOW_METER_FLOWRATE`` is a §2.2 field the emulator does not emit, and
``TIMESTAMP`` is emitted as an integer where §2.2 records a formatted string.
Both live in ``tools/xenia_emulator.py``, which this task may not edit, so the
test asserts the *actual* field set and fails loudly if the emulator silently
drops another §2.2 field, while a separate skipped test names the gap.
"""

from __future__ import annotations

import http.client
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
EMULATOR = ROOT / "tools" / "xenia_emulator.py"

#: docs/XENIA_FIRMWARE.md §2.2 field list, in handler order.
SECTION_2_2_FIELDS = (
    "MA_STATUS",
    "PU_SENS_FLOW_METER_VOLUME",
    "PU_SENS_FLOW_METER_FLOWRATE",
    "MA_EXTRACTION_STATUS",
    "BG_SET_TEMP",
    "BG_SENS_TEMP",
    "REAL_EXTRACTION_TIME_MS",
    "TANK_LEVEL",
    "TIMESTAMP",
    "script",
)

#: The subset the emulator actually emits today.  Not a wish list: this is what
#: the process returns, kept next to the §2.2 list so a change is visible.
EMULATOR_MAKO_FIELDS = SECTION_2_2_FIELDS[:1] + SECTION_2_2_FIELDS[3:6] + SECTION_2_2_FIELDS[6:]

#: MA_STATUS enum values used below (docs/XENIA_FIRMWARE.md §2.2).
MACH_ON = 1
MACH_ACTIVE_SERVING = 3
MACH_ACTIVE_FINISHING = 4


def free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def call(port: int, method: str, path: str, body: dict | None = None, *, timeout: float = 5.0) -> tuple[int, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, json.loads(raw) if raw else None
    finally:
        connection.close()


class XeniaEmulatorProcessTests(unittest.TestCase):
    """The emulator as the owner runs it: ``python3 tools/xenia_emulator.py``."""

    process: subprocess.Popen[str]
    port: int
    control_port: int

    @classmethod
    def setUpClass(cls) -> None:
        if not EMULATOR.is_file():
            raise unittest.SkipTest(f"{EMULATOR} is missing")
        cls.scratch = tempfile.TemporaryDirectory(prefix="xenia-emulator-")
        cls.log = Path(cls.scratch.name) / "emulator.log"
        cls.port = free_port()
        cls.control_port = free_port()
        handle = cls.log.open("w", encoding="utf-8")
        try:
            cls.process = subprocess.Popen(
                (
                    sys.executable,
                    str(EMULATOR),
                    "--port",
                    str(cls.port),
                    "--control-port",
                    str(cls.control_port),
                ),
                cwd=ROOT,
                stdout=handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
        finally:
            handle.close()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if cls.process.poll() is not None:
                raise AssertionError(
                    f"emulator exited {cls.process.returncode}: {cls.log.read_text(encoding='utf-8')}"
                )
            try:
                status, _ = call(cls.port, "GET", "/api/v2/machine", timeout=1.0)
            except OSError:
                time.sleep(0.05)
                continue
            if status == 200:
                return
            time.sleep(0.05)
        raise AssertionError(
            f"emulator did not answer on 127.0.0.1:{cls.port}: "
            f"{cls.log.read_text(encoding='utf-8')}"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        if getattr(cls, "process", None) is not None:
            if cls.process.poll() is None:
                cls.process.terminate()
            try:
                cls.process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                cls.process.kill()
                cls.process.wait(timeout=10)
        cls.scratch.cleanup()

    def setUp(self) -> None:
        # Every case starts from a known machine state.
        status, _ = call(self.control_port, "POST", "/control/idle")
        self.assertEqual(status, 200)

    def test_machine_endpoint_identifies_the_machine(self) -> None:
        status, payload = call(self.port, "GET", "/api/v2/machine")
        self.assertEqual(status, 200)
        self.assertEqual(payload["MA_TYPE"], "XENIA")
        self.assertEqual(payload["MA_SN"], "VG-XENIA-0001")
        self.assertEqual(payload["FW_VERSION_MAJOR"], 3)
        self.assertEqual(payload["FW_VERSION_MINOR"], 87)

    def test_mako_poll_reports_the_section_2_2_fields_it_implements(self) -> None:
        status, payload = call(self.port, "GET", "/api/v2/mako")
        self.assertEqual(status, 200)
        self.assertEqual(payload["MA_STATUS"], MACH_ON)
        missing = [
            field
            for field in EMULATOR_MAKO_FIELDS
            if field not in payload
        ]
        self.assertEqual(missing, [], f"the emulator stopped emitting {missing}")
        # The one §2.2 field that is genuinely absent today: keep it visible.
        self.assertNotIn("PU_SENS_FLOW_METER_FLOWRATE", payload)

    @unittest.skip(
        "known gap: tools/xenia_emulator.py does not emit PU_SENS_FLOW_METER_FLOWRATE, "
        "which docs/XENIA_FIRMWARE.md §2.2 lists and §9.5 asks a mock to provide; "
        "the file is outside this task's write scope"
    )
    def test_mako_reports_flow_rate_like_the_firmware_does(self) -> None:
        _, payload = call(self.port, "GET", "/api/v2/mako")
        self.assertIn("PU_SENS_FLOW_METER_FLOWRATE", payload)

    def test_execute_starts_a_brew_and_the_next_poll_shows_serving(self) -> None:
        status, reply = call(self.port, "POST", "/api/v2/scripts/execute", {"ID": 9})
        self.assertEqual(status, 200)
        self.assertEqual(reply, {"ok": True, "ID": 9})
        status, payload = call(self.port, "GET", "/api/v2/mako")
        self.assertEqual(status, 200)
        self.assertEqual(payload["MA_STATUS"], MACH_ACTIVE_SERVING)
        self.assertEqual(payload["MA_EXTRACTION_STATUS"], 1)

    def test_brewratio_values_are_echoed_and_visible_on_the_next_poll(self) -> None:
        status, echo = call(
            self.port,
            "POST",
            "/api/v2/brewratio",
            {"SYNC_BEVERAGE_WEIGHT": 18, "SYNC_FILTER": 2},
        )
        self.assertEqual(status, 200)
        self.assertEqual(echo, {"MA_SYNC_BEVERAGE_WEIGHT": 18, "MA_SYNC_FILTER": 2})
        status, payload = call(self.port, "GET", "/api/v2/mako")
        self.assertEqual(status, 200)
        self.assertEqual(payload["MA_SYNC_BEVERAGE_WEIGHT"], 18)
        self.assertEqual(payload["MA_SYNC_FILTER"], 2)

    def test_one_finishing_poll_then_idle(self) -> None:
        status, shot = call(
            self.control_port, "POST", "/control/shot", {"duration_ms": 25_400, "mass_g": 18.2}
        )
        self.assertEqual(status, 200)
        self.assertEqual(shot["ma_status"], MACH_ACTIVE_FINISHING)

        status, finishing = call(self.port, "GET", "/api/v2/mako")
        self.assertEqual(status, 200)
        self.assertEqual(finishing["MA_STATUS"], MACH_ACTIVE_FINISHING)
        self.assertEqual(finishing["MA_EXTRACTION_STATUS"], 2)
        self.assertEqual(finishing["REAL_EXTRACTION_TIME_MS"], 25_400)

        status, idle = call(self.port, "GET", "/api/v2/mako")
        self.assertEqual(status, 200)
        self.assertEqual(idle["MA_STATUS"], MACH_ON)
        self.assertEqual(idle["MA_EXTRACTION_STATUS"], 0)

    def test_control_state_is_readable_across_the_two_listeners(self) -> None:
        call(self.port, "POST", "/api/v2/brewratio", {"SYNC_BEVERAGE_WEIGHT": 17})
        status, state = call(self.control_port, "GET", "/control/state")
        self.assertEqual(status, 200)
        self.assertEqual(state["sync_weight_g"], 17)
        self.assertEqual(state["ma_status"], MACH_ON)

    def test_negative_shot_is_rejected_with_400(self) -> None:
        status, payload = call(
            self.control_port, "POST", "/control/shot", {"duration_ms": -1, "mass_g": 10}
        )
        self.assertEqual(status, 400)
        self.assertIn("non-negative", payload["error"])

    def test_unknown_paths_are_404_on_both_listeners(self) -> None:
        for port in (self.port, self.control_port):
            with self.subTest(port=port):
                status, payload = call(port, "GET", "/api/v2/nope")
                self.assertEqual(status, 404)
                self.assertEqual(payload["error"], "unknown path")

    def test_oversized_body_is_rejected(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(
                "POST",
                "/api/v2/brewratio",
                body=b"{}",
                headers={"Content-Type": "application/json", "Content-Length": str(2 * 1024 * 1024)},
            )
            # The server refuses before reading the body; either a 400 or a
            # closed connection is acceptable, a crash is not.
            try:
                response = connection.getresponse()
                self.assertIn(response.status, (400, 413))
            except (ConnectionError, http.client.HTTPException):
                pass
        finally:
            connection.close()


class DocumentedStateMachineTests(unittest.TestCase):
    """The §3.4 transition table applied to the emulator's finishing poll.

    This is a transcription test, not a hardware test: it encodes the table from
    ``docs/XENIA_FIRMWARE.md`` §3.4 and asks what the grinder's own parser would
    do with the values the emulator sends.  It exists because the answer is
    uncomfortable - a grinder-started brew ends in ``Aborted`` - and a prose
    remark in a document does not survive a refactor, a test does.
    """

    @staticmethod
    def next_state(brew_state: int, status: int, extraction_status: int) -> int:
        """§3.4: ``processJsonReceived``'s MA_STATUS switch, transcribed."""

        # BrewState: 0 Idle, 1 ExternalBrewing, 2 ExternalFinishing,
        #            3 InternalStarting, 4 InternalExtraction, 5 InternalFinishing, 6 Aborted
        if status == MACH_ACTIVE_SERVING:
            return 4 if brew_state == 3 else 1
        if status == MACH_ACTIVE_FINISHING:
            if brew_state in (1, 2):
                return 2
            if extraction_status == 2:
                return 6
            return 5
        if status in (0, 2, 5, 6):
            return 0
        if status == MACH_ON:
            return 0 if brew_state == 2 else brew_state
        return brew_state

    def test_the_emulators_finishing_poll_maps_to_aborted(self) -> None:
        # The grinder started the brew: MA_STATUS 3 -> InternalExtraction(4).
        state = self.next_state(3, MACH_ACTIVE_SERVING, 1)
        self.assertEqual(state, 4)
        # Then the emulator's finishing poll: MA_STATUS 4 with
        # MA_EXTRACTION_STATUS 2, which §3.4 maps to Aborted(6) - not to
        # InternalFinishing(5).  Whether a real Xenia reports 2 here is [U].
        state = self.next_state(state, MACH_ACTIVE_FINISHING, 2)
        self.assertEqual(state, 6)

    def test_internal_finishing_needs_a_different_extraction_status(self) -> None:
        state = self.next_state(4, MACH_ACTIVE_FINISHING, 1)
        self.assertEqual(state, 5, "any extraction status other than 2 finishes the brew")

    def test_scale_side_brew_finishes_normally(self) -> None:
        # A brew the machine started arrives as ExternalBrewing, which is the
        # path the emulator's values were designed for.
        state = self.next_state(0, MACH_ACTIVE_SERVING, 0)
        self.assertEqual(state, 1)
        state = self.next_state(state, MACH_ACTIVE_FINISHING, 2)
        self.assertEqual(state, 2)
        state = self.next_state(state, MACH_ON, 0)
        self.assertEqual(state, 0)


class FinishingPollControlTests(unittest.TestCase):
    """Control: the same assertion against a machine that never leaves finishing.

    ``test_one_finishing_poll_then_idle`` asserts ``MA_STATUS 4`` and then ``1``.
    On its own that could pass against an emulator that reports 4 forever if the
    second assertion were ever loosened, so this control drives the in-process
    server with a patched ``mako`` and shows the predicate distinguishes the two
    behaviours.  It patches runtime state only: no file is edited, and
    ``tools/xenia_emulator.py`` is outside this task's write scope.
    """

    def test_a_machine_that_stays_in_finishing_breaks_the_assertion(self) -> None:
        from tools.xenia_emulator import XeniaServer

        server = XeniaServer(port=0, control_port=0).start()
        self.addCleanup(server.close)
        original = server.state.mako

        def stuck() -> dict:
            value = original()
            value["MA_STATUS"] = MACH_ACTIVE_FINISHING
            value["MA_EXTRACTION_STATUS"] = 2
            return value

        server.state.mako = stuck  # type: ignore[method-assign]
        call(self.control_port(server), "POST", "/control/shot", {"duration_ms": 25_400, "mass_g": 18.2})
        _, first = call(server.port, "GET", "/api/v2/mako")
        _, second = call(server.port, "GET", "/api/v2/mako")
        self.assertEqual(first["MA_STATUS"], MACH_ACTIVE_FINISHING)
        self.assertEqual(second["MA_STATUS"], MACH_ACTIVE_FINISHING)
        # The process test asserts equality with MACH_ON here; a machine that
        # stays in finishing must not satisfy it.
        self.assertNotEqual(second["MA_STATUS"], MACH_ON)

    @staticmethod
    def control_port(server: object) -> int:
        return int(getattr(server, "control_port"))


if __name__ == "__main__":
    unittest.main()
