"""The container half of the suite names its host requirement.

``PhpModuleCase`` (32 tests) and ``RunnerJobValidationTests`` (3 tests) execute
the real PHP module and the real runner inside a ``php:8.3-cli`` container.  On
a host without that image ``setUpClass`` skips each class as a whole, and the
suite collects 234 tests instead of 269 -- exactly what deleting those 35 tests
looks like.

These tests pin the two halves of the fix, hermetically: a fake ``docker`` on
``PATH`` that reports the image missing must produce one actionable sentence
naming the image and the pull command, and the two optional classes must still
hold their tests whether or not the image is installed.
"""

from __future__ import annotations

import contextlib
import importlib
import os
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

import host_requirements
import test_local_actions
import test_local_api

PHP_IMAGE = "php:8.3-cli"
PULL = "docker pull php:8.3-cli"
ABSENT = f"{PHP_IMAGE} is not available; {PULL}"
PACKAGE = Path(__file__).resolve().parent


@contextlib.contextmanager
def fake_docker(*, present: bool) -> Iterator[None]:
    """Put a ``docker`` first on ``PATH`` that answers ``image inspect``.

    Every other subcommand succeeds, so a test can pick which half of the probe
    it exercises without a Docker daemon, and without touching a real image.
    """
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


@contextlib.contextmanager
def no_docker() -> Iterator[None]:
    """An empty ``PATH``, i.e. a host with no Docker CLI at all."""
    with tempfile.TemporaryDirectory(prefix="phptrap_") as scratch:
        with mock.patch.dict(os.environ, {"PATH": scratch}):
            yield


class ImageProbeTests(unittest.TestCase):
    """The probe returns a remedy, not a bare boolean."""

    def test_absent_image_names_the_image_and_the_pull_command(self) -> None:
        with fake_docker(present=False):
            self.assertEqual(host_requirements.php_image_problem(), ABSENT)
            self.assertFalse(host_requirements.php_image_ready())
            # The container classes share this probe, so the 234-vs-269
            # difference always comes with the same sentence.
            self.assertFalse(test_local_api.docker_ready())

    def test_present_image_is_not_a_problem(self) -> None:
        with fake_docker(present=True):
            self.assertIsNone(host_requirements.php_image_problem())
            self.assertTrue(host_requirements.php_image_ready())
            self.assertTrue(test_local_api.docker_ready())

    def test_no_docker_cli_says_so_and_still_names_the_pull_command(self) -> None:
        with no_docker():
            problem = host_requirements.php_image_problem()
        self.assertIsNotNone(problem)
        self.assertTrue(problem.startswith("docker is not installed;"), problem)
        self.assertIn(PULL, problem)


class SkipWordingTests(unittest.TestCase):
    """A skipped class says why, in the same words as the runner's preflight."""

    def test_php_module_class_skips_with_the_actionable_reason(self) -> None:
        with fake_docker(present=False):
            with self.assertRaises(unittest.SkipTest) as caught:
                test_local_api.PhpModuleCase.setUpClass()
        self.assertEqual(str(caught.exception), ABSENT)

    def test_runner_job_class_skips_with_the_actionable_reason(self) -> None:
        with fake_docker(present=False):
            with self.assertRaises(unittest.SkipTest) as caught:
                test_local_actions.RunnerJobValidationTests.setUpClass()
        self.assertEqual(str(caught.exception), ABSENT)


class OptionalClassInventoryTests(unittest.TestCase):
    """The 35 container tests still exist when the image does not.

    Counted statically, from the class definitions rather than from a run, so
    these assertions hold on a host with no image.  A deletion changes the
    numbers; a missing image does not.  That is what separates the two cases.
    """

    def test_the_two_container_classes_still_own_their_tests(self) -> None:
        loader = unittest.TestLoader()
        self.assertEqual(len(loader.getTestCaseNames(test_local_api.PhpModuleCase)), 32)
        self.assertEqual(
            len(loader.getTestCaseNames(test_local_actions.RunnerJobValidationTests)),
            3,
        )

    def test_static_collection_still_reaches_the_runner_floor(self) -> None:
        import run_tests  # tools/ is on sys.path via tests/__init__.py

        floors = {
            suite.name: suite.minimum
            for suite in run_tests.SUITES
            if isinstance(suite, run_tests.UnittestSuite)
        }
        self.assertGreaterEqual(_static_total(), floors["e64root"])


def _static_total() -> int:
    """Every ``test_*`` method defined in this package, without running one."""
    total = 0
    loader = unittest.TestLoader()
    for path in sorted(PACKAGE.glob("test_*.py")):
        module = importlib.import_module(path.stem)
        for value in vars(module).values():
            if (
                isinstance(value, type)
                and issubclass(value, unittest.TestCase)
                and value.__module__ == module.__name__
            ):
                total += len(loader.getTestCaseNames(value))
    return total
