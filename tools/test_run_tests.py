"""The repository runner states host requirements instead of losing tests.

``e64root`` runs its PHP layer in a ``php:8.3-cli`` container.  Before the fix
a host without that image failed the suite as ``ran 234 tests, expected at
least 269``, which is what a deletion looks like; now the runner fails the suite
before collection with ``php:8.3-cli is not available; docker pull php:8.3-cli``.

Everything here is hermetic: a fake ``docker`` on ``PATH`` answers
``image inspect``, so no daemon and no image are needed, and the suite itself is
never executed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import os
import sys
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools" / "run_tests.py"
HOST_REQUIREMENTS = ROOT / "tools" / "e64root" / "tests" / "host_requirements.py"

IMAGE = "php:8.3-cli"
PULL = f"docker pull {IMAGE}"
ABSENT = f"{IMAGE} is not available; {PULL}"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def fake_docker(*, present: bool) -> Iterator[None]:
    """A ``docker`` on ``PATH`` that reports the image present or absent."""
    with tempfile.TemporaryDirectory(prefix="phptrap_") as scratch:
        binary = Path(scratch) / "docker"
        binary.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then\n'
            f"  exit {0 if present else 1}\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": scratch}):
            yield


class RunnerImagePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = _load("_phptrap_run_tests", RUNNER)
        cls.suite = next(
            suite for suite in cls.runner.SUITES if suite.name == "e64root"
        )

    def test_e64root_declares_the_image_its_container_tests_need(self) -> None:
        self.assertEqual(self.suite.docker_images, (IMAGE,))

    def test_the_floor_is_not_lowered_for_a_missing_image(self) -> None:
        # 269 was the floor before this change and 234 is what a host without
        # the image collects; the floor must stay above the second number so the
        # loss can never pass silently.
        self.assertGreaterEqual(self.suite.minimum, 269)
        self.assertGreater(self.suite.minimum, 234)

    def test_missing_image_fails_with_the_pull_command_not_a_count(self) -> None:
        with fake_docker(present=False):
            result = self.runner._run_unittest(self.suite, verbose=False)
        self.assertIn(result.status, ("FAIL", "ERROR"))
        self.assertEqual(result.detail, ABSENT)
        self.assertEqual(result.ran, 0, "the suite must not run and lose 35 tests")
        self.assertNotIn("expected at least", result.detail)

    def test_present_image_clears_the_preflight(self) -> None:
        with fake_docker(present=True):
            self.assertIsNone(self.runner._preflight(self.suite))

    def test_the_runner_and_the_suite_word_the_requirement_identically(self) -> None:
        host_requirements = _load("_phptrap_host_requirements", HOST_REQUIREMENTS)
        with fake_docker(present=False):
            self.assertEqual(
                self.runner.docker_image_problem(IMAGE),
                host_requirements.php_image_problem(IMAGE),
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
