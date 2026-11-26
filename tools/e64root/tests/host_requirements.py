"""Host requirements the offline e64root tests share with the runner.

The PHP layer of this suite executes the real ``ondevice/rest_api_dev.php`` and
``ondevice/e64local_action_run.php`` inside a disposable ``php:8.3-cli``
container.  ``PhpModuleCase`` and ``RunnerJobValidationTests`` therefore need
that image to exist in the local Docker daemon.

A missing image used to be invisible: ``setUpClass`` skipped the whole class, so
the suite collected 35 fewer tests (234 instead of 269) and the only symptom was
``ran 234 tests, expected at least 269`` in ``tools/run_tests.py`` -- exactly
what a deleted test file looks like.

The requirement, the probe and the remedy are named in this one module so the
test classes and the runner cannot drift apart:

    docker pull php:8.3-cli

Nothing here talks to a device or to the network; ``docker image inspect`` reads
the local daemon only.
"""

from __future__ import annotations

import shutil
import subprocess

PHP_IMAGE = "php:8.3-cli"
PHP_IMAGE_PULL = f"docker pull {PHP_IMAGE}"


def php_image_problem(image: str = PHP_IMAGE) -> str | None:
    """Why ``image`` cannot be used for the container tests, or ``None``.

    ``None`` means ``docker image inspect`` succeeded, so a later
    ``docker run <image>`` in these tests runs the local copy.  Any other
    outcome returns one actionable sentence: what is missing and the exact
    command that installs it.
    """
    pull = f"docker pull {image}"
    if shutil.which("docker") is None:
        return f"docker is not installed; install Docker, then run: {pull}"
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return f"{image} is not available; {pull}"
    if completed.returncode != 0:
        return f"{image} is not available; {pull}"
    return None


def php_image_ready(image: str = PHP_IMAGE) -> bool:
    """True when the container tests can run; see :func:`php_image_problem`."""
    return php_image_problem(image) is None
