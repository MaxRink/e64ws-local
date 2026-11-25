#!/usr/bin/env python3
"""Offline checks for the boot.scr slot/ustate harness.

Run: python3 tests/test_boot_scr.py
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "boot.scr"


def run(
    fw: Path, *args: str, rdev: str = "/dev/mmcblk1p4"
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, BOOT_FIRMWARE_DIR=str(fw), BOOT_RDEV=rdev)
    return subprocess.run(
        ["sh", str(HARNESS), *args], env=env, text=True, capture_output=True
    )


def setup(tmp: Path) -> Path:
    fw = tmp / "fw"
    fw.mkdir()
    (fw / "bootA.scr").write_text("A-script\n")
    (fw / "bootB.scr").write_text("B-script\n")
    (fw / "boot.scr").write_text("A-script\n")
    return fw


def env_value(fw: Path, key: str) -> str:
    for line in (fw / "env-harness.txt").read_text().splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    return ""


def test_invocation() -> None:
    with tempfile.TemporaryDirectory() as td:
        fw = setup(Path(td))
        status = run(fw, "status")
        assert status.returncode == 0, status.stderr
        assert "Active slot: A" in status.stdout
        usage = run(fw)
        assert usage.returncode == 0
        assert "Usage:" in usage.stdout


def test_select_updates_state() -> None:
    with tempfile.TemporaryDirectory() as td:
        fw = setup(Path(td))
        result = run(fw, "select", "B", "--ustate", "1", "--dest-dev", "/dev/mmcblk1p5")
        assert result.returncode == 0, result.stderr
        assert (fw / "boot.scr").read_text() == "B-script\n"
        assert env_value(fw, "ustate") == "1"
        assert env_value(fw, "dest_dev") == "/dev/mmcblk1p5"
        assert not list(fw.glob("*.bak"))


def test_invalid_value_is_rejected_before_install() -> None:
    with tempfile.TemporaryDirectory() as td:
        fw = setup(Path(td))
        assert run(fw, "select", "B").returncode == 0
        result = run(fw, "select", "A", "--ustate", "9")
        assert result.returncode != 0
        assert (fw / "boot.scr").read_text() == "B-script\n"


def test_verify_pass_and_fail() -> None:
    with tempfile.TemporaryDirectory() as td:
        fw = setup(Path(td))
        assert run(fw, "select", "A", "--ustate", "1", "--dest-dev", "/dev/mmcblk1p4").returncode == 0
        passed = run(fw, "verify", rdev="/dev/mmcblk1p4")
        assert passed.returncode == 0, passed.stderr
        assert "Verification PASS" in passed.stdout
        assert env_value(fw, "ustate") == "2"
        assert not (fw / "rollback.scr").exists()

    with tempfile.TemporaryDirectory() as td:
        fw = setup(Path(td))
        assert run(fw, "select", "B", "--ustate", "1", "--dest-dev", "/dev/mmcblk1p5").returncode == 0
        failed = run(fw, "verify", rdev="/dev/mmcblk1p4")
        assert failed.returncode == 0, failed.stderr
        assert "Verification FAIL" in failed.stdout
        assert env_value(fw, "ustate") == "3"
        assert (fw / "boot.scr").read_text() == "A-script\n"
        assert not (fw / "rollback.scr").exists()


def test_predict_truth_table() -> None:
    cases = (
        ("WDOG", "", "do_rollback runs: yes"),
        ("WDOG", "true", "do_rollback runs: no"),
        ("SOFTWARE", "", "do_rollback runs: yes"),
        ("SOFTWARE", "true", "do_rollback runs: yes"),
    )
    with tempfile.TemporaryDirectory() as td:
        fw = setup(Path(td))
        for resetcause, rollback, expected in cases:
            result = run(fw, "predict", "--resetcause", resetcause, "--rollback", rollback)
            assert result.returncode == 0, result.stderr
            assert expected in result.stdout, (resetcause, rollback, result.stdout)


def test_sourcing_keeps_caller_options() -> None:
    with tempfile.TemporaryDirectory() as td:
        setup(Path(td))
        result = subprocess.run(
            ["sh", "-c", '. "$1"; case $- in *e*|*u*) exit 1 ;; esac', "sh", str(HARNESS)],
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr


if __name__ == "__main__":
    test_invocation()
    test_select_updates_state()
    test_invalid_value_is_rejected_before_install()
    test_verify_pass_and_fail()
    test_predict_truth_table()
    test_sourcing_keeps_caller_options()
    print("boot.scr tests: OK")
