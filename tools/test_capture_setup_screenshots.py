"""The caption guards in ``tools/capture_setup_screenshots.py``.

Every figure in ``docs/SETUP.md`` carries a caption that names values on screen.
Nothing in the guide can re-read a PNG, so the guard has to run when the frame is
taken - and it has to keep running after somebody edits it.  ``--check`` compares
hashes after the fact; it cannot tell a caption from its pixels.

These tests therefore feed the guards the dumps that would otherwise slip
through, and drive the capture path itself:

* a screen with the always-rendered explanatory sentence but no policy card -
  the case a substring match would have accepted;
* stubbed values (``Disabled`` / ``Allowed`` / ``0`` / ``unavailable``);
* a card with the route count missing, and an audit trail whose rows are out of
  order;
* a content mismatch must raise ``Failed``, not ``Skipped``, so ``--allow-skip``
  cannot turn it into a shipped caption;
* the frame must not be written when its check fails, and must be re-checked
  after the capture.

Delete a guard, weaken it to a substring, or let it raise ``Skipped`` again, and
one of these fails.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import tools.capture_setup_screenshots as capture
from tools.capture_setup_screenshots import (
    Failed,
    Skipped,
    _capture_frame,
    require_audit_trail,
    require_policy_card,
    step_android,
)


def node(text: str) -> str:
    return f'<node text="{text}" />'


def dump(*texts: str) -> str:
    return "<hierarchy>" + "".join(node(text) for text in texts) + "</hierarchy>"


#: The policy card as the app renders it, plus the sentence that is always there.
POLICY_SENTENCE = (
    "Destructive actions stay blocked until an owner re-deploys the policy with "
    "--enable-destructive-actions. This app cannot enable them."
)
REAL_POLICY = dump(
    "Action layer",
    "Gate",
    "Enabled",
    "Destructive actions",
    "Blocked",
    "Dispatchable routes",
    "18",
    POLICY_SENTENCE,
    "Catalog",
    "action_grind_start_gbw",
    "implemented",
)

REAL_AUDIT = dump(
    "Unavailable: GbsCreateReport replies with a non-standard envelope",
    "action_recipe_clone",
    "state-changing",
    "unavailable",
    "Unavailable: no vendor surface; deferred compound read+create",
    "Audit trail",
    "Rows on the device",
    "4 (50 per page)",
    "2026-11-26T00:03:56Z  prepare",
    "action_language_set  prepared",
    "2026-11-26T00:03:50Z  result",
    "action_language_set  0 ms  completed",
    "2026-11-26T00:03:49Z  execute",
    "action_language_set  executing",
)


class PolicyCardGuardTests(unittest.TestCase):
    """Figure 7 must not be captured unless the card is really in the frame."""

    def test_accepts_the_card_the_app_actually_renders(self) -> None:
        require_policy_card(REAL_POLICY)

    def test_refuses_an_empty_screen(self) -> None:
        with self.assertRaises(Failed) as raised:
            require_policy_card(dump())
        self.assertIn("policy card is not on screen", str(raised.exception))

    def test_refuses_the_explanatory_sentence_alone(self) -> None:
        """The trap: the sentence is always rendered and names two of the rows."""
        screen = dump("Action layer", POLICY_SENTENCE, "Catalog", "action_grind_purge")
        with self.assertRaises(Failed) as raised:
            require_policy_card(screen)
        self.assertIn('text="Gate"', str(raised.exception))

    def test_refuses_stubbed_values(self) -> None:
        screen = dump(
            "Gate",
            "Disabled",
            "Destructive actions",
            "Allowed",
            "Dispatchable routes",
            "0",
            "implemented",
            POLICY_SENTENCE,
        )
        with self.assertRaises(Failed) as raised:
            require_policy_card(screen)
        message = str(raised.exception)
        self.assertIn('text="Enabled"', message)
        self.assertIn('text="Blocked"', message)
        self.assertIn('text="18"', message)

    def test_refuses_when_the_route_count_is_missing(self) -> None:
        screen = REAL_POLICY.replace(node("18"), "")
        with self.assertRaises(Failed) as raised:
            require_policy_card(screen)
        self.assertIn('text="18"', str(raised.exception))

    def test_refuses_when_the_catalog_status_is_missing(self) -> None:
        screen = REAL_POLICY.replace(node("implemented"), "")
        with self.assertRaises(Failed) as raised:
            require_policy_card(screen)
        self.assertIn('text="implemented"', str(raised.exception))

    def test_a_wrong_screen_is_a_failure_not_a_skip(self) -> None:
        """``--allow-skip`` covers an absent tool, never a wrong frame."""
        with self.assertRaises(Failed) as raised:
            require_policy_card(dump("Action layer"))
        self.assertNotIsInstance(raised.exception, Skipped)


class AuditTrailGuardTests(unittest.TestCase):
    def test_accepts_the_trail_the_app_actually_renders(self) -> None:
        require_audit_trail(REAL_AUDIT)

    def test_refuses_a_screen_without_the_trail(self) -> None:
        with self.assertRaises(Failed) as raised:
            require_audit_trail(dump("Action layer", "Gate", "Enabled"))
        self.assertIn("audit trail is not on screen", str(raised.exception))

    def test_refuses_rows_that_are_not_newest_first(self) -> None:
        screen = REAL_AUDIT.replace("2026-11-26T00:03:56Z", "2026-11-26T00:03:00Z")
        with self.assertRaises(Failed) as raised:
            require_audit_trail(screen)
        self.assertIn("not newest first", str(raised.exception))

    def test_refuses_a_trail_with_fewer_than_two_rows(self) -> None:
        # Every caption string is present, but only one row carries a timestamp:
        # the "newest first" claim has nothing to order by.
        screen = dump(
            "Unavailable: no vendor surface",
            "unavailable",
            "Audit trail",
            "4 (50 per page)",
            "2026-11-26T00:03:56Z  prepare",
            "action_language_set  prepared",
            "action_language_set  executing",
            "action_language_set  completed",
            "execute",
        )
        with self.assertRaises(Failed) as raised:
            require_audit_trail(screen)
        self.assertIn("fewer than two timestamped rows", str(raised.exception))

    def test_a_wrong_screen_is_a_failure_not_a_skip(self) -> None:
        with self.assertRaises(Failed) as raised:
            require_audit_trail(dump("Audit trail"))
        self.assertNotIsInstance(raised.exception, Skipped)


class CaptureFrameTests(unittest.TestCase):
    """The capture path: check, shoot, check again, then write."""

    def test_writes_the_frame_when_the_check_passes(self) -> None:
        written: list[bytes] = []

        def crop(frame: bytes, target: Path) -> None:
            written.append(frame)
            target.write_bytes(frame)

        with TemporaryDirectory() as directory:
            target = Path(directory) / "07.png"
            _capture_frame(
                REAL_POLICY,
                require_policy_card,
                lambda: b"frame-bytes",
                target,
                what="figure 7 (Actions policy)",
                redump=lambda: REAL_POLICY,
                crop=crop,
            )
            self.assertTrue(target.is_file())
            self.assertEqual(target.read_bytes(), b"frame-bytes")
        self.assertEqual(written, [b"frame-bytes"])

    def test_writes_nothing_when_the_check_fails(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "07.png"
            with self.assertRaises(Failed):
                _capture_frame(
                    dump("Action layer"),
                    require_policy_card,
                    lambda: b"frame-bytes",
                    target,
                    what="figure 7 (Actions policy)",
                    crop=lambda frame, path: path.write_bytes(frame),
                )
            self.assertFalse(target.exists(), "a refused frame must not reach the guide")

    def test_refuses_when_the_screen_moved_after_the_capture(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "07.png"
            with self.assertRaises(Failed) as raised:
                _capture_frame(
                    REAL_POLICY,
                    require_policy_card,
                    lambda: b"frame-bytes",
                    target,
                    what="figure 7 (Actions policy)",
                    redump=lambda: dump("Action layer"),
                    crop=lambda frame, path: path.write_bytes(frame),
                )
            self.assertIn("screen changed between the dump and the capture", str(raised.exception))
            self.assertFalse(target.exists())


class WiringTests(unittest.TestCase):
    """The guards must stay wired into the step that takes the frames.

    Weakening a guard is caught by the tests above; dropping its call site would
    otherwise be invisible, because nothing else in the repository runs this
    script.  These read the compiled function, so a removed call is a failure
    rather than a silent loss of the check.
    """

    def test_step_android_calls_both_guards(self) -> None:
        names = step_android.__code__.co_names
        self.assertIn("require_policy_card", names)
        self.assertIn("require_audit_trail", names)

    def test_step_android_targets_both_figures(self) -> None:
        constants = step_android.__code__.co_consts
        self.assertIn("07-android-actions-policy.png", constants)
        self.assertIn("08-android-action-audit.png", constants)


class AllowSkipTests(unittest.TestCase):
    """``--allow-skip`` is for a host without a tool, never for a wrong screen."""

    def run_main(self, step, argv: list[str]) -> int:
        with mock.patch.object(capture, "step_hmi", step), redirect_stdout(io.StringIO()):
            with TemporaryDirectory() as directory:
                return capture.main(["--only", "hmi", "--out", directory, *argv])

    def test_a_missing_tool_may_be_accepted(self) -> None:
        def step(out):  # noqa: ANN001 - signature of a capture step
            raise Skipped("adb is not on PATH")

        self.assertEqual(self.run_main(step, ["--allow-skip", "hmi"]), 0)

    def test_a_missing_tool_without_the_flag_is_a_failure(self) -> None:
        def step(out):  # noqa: ANN001
            raise Skipped("adb is not on PATH")

        self.assertEqual(self.run_main(step, []), 1)

    def test_a_content_failure_cannot_be_allowed_away(self) -> None:
        def step(out):  # noqa: ANN001
            raise Failed("the Actions policy card is not on screen")

        self.assertEqual(
            self.run_main(step, ["--allow-skip", "hmi", "--allow-skip", "all"]),
            1,
            "a content mismatch must fail the run even when the step is allow-listed",
        )


if __name__ == "__main__":
    unittest.main()
