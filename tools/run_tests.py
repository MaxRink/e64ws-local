#!/usr/bin/env python3
"""Run every offline test suite in this repository and summarise the result.

This is the implementation behind ``tools/run_tests.sh``.  Only the Python
standard library is used so the runner works from a clean checkout; the C++
gateway suite shells out to the compiler that the repository's own build
scripts already require.

Each unittest suite runs in its own process, with its own working directory and
``PYTHONPATH``.  The virtual-grinder suite is a plain script with ``test_*``
functions rather than a ``unittest`` case, so it is loaded and run directly.
Command suites are entry points that report failure through their exit status.

A suite that collects zero tests, or fewer tests than the minimum recorded for
it in ``SUITES``, is a failure: a discovery mistake or a deleted test file must
not look like a green run.  Update the minimum in the same commit that removes
or renames tests.  Test files that no suite covers are a failure too, so a new
suite cannot be dropped silently.  Files that are deliberately not run are
listed in ``EXCLUDED`` with the reason, and printed with every run.

A suite whose collection depends on a local Docker image declares it in
``docker_images``.  The image is checked before the suite starts and a missing
one fails the suite with the command that pulls it, so a host that was never
provisioned cannot be mistaken for a suite that lost its tests.

A suite whose input this checkout does not carry declares it in
``requires_paths``.  This tree is the published subset of a larger research
tree, and the export gate withholds vendor firmware, captured evidence and
research prose; a suite that reads those paths has no input here.  That is a
property of the checkout, not a regression, so the suite is reported as ``SKIP``
with the withheld path.  It is deliberately neither a ``PASS`` (nothing ran) nor
a ``FAIL`` (nothing broke).
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class UnittestSuite:
    """A suite discovered or imported by ``python -m unittest``."""

    name: str
    cwd: Path
    note: str
    minimum: int
    start: str | None = None
    pattern: str = "test_*.py"
    top: str | None = None
    modules: tuple[str, ...] = ()
    pythonpath: tuple[str, ...] = ()
    # Local Docker images the suite needs.  A missing image is a host problem,
    # not a lost test, so it is reported before collection with the command
    # that pulls it.  Without this field the suite would skip a whole class in
    # ``setUpClass`` and look exactly like a suite whose tests were deleted.
    docker_images: tuple[str, ...] = ()
    # Paths this suite reads that the tree does not produce.  A suite whose
    # input is withheld by the export gate cannot run in a published subset, and
    # that is not the same finding as a suite whose tests failed: it is reported
    # as SKIP with the withheld path and the gate's verdict, and it never counts
    # as a lost test or as a green run.
    requires_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionSuite:
    """A script that exposes ``test_*`` functions instead of TestCases."""

    name: str
    cwd: Path
    note: str
    minimum: int
    path: str
    requires_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class CommandSuite:
    """An entry point that signals failure through its exit status."""

    name: str
    cwd: Path
    note: str
    commands: tuple[tuple[str, ...], ...]
    requires_paths: tuple[str, ...] = ()


# Test files that exist in the tree but are deliberately not part of the
# offline run.  Keep this list explicit: a suite that is dropped silently is
# worse than a suite that is documented as not run.
EXCLUDED_FILES: tuple[tuple[str, str], ...] = (
    (
        "tools/test_gbs_parity.py",
        "Python/Node parity harness, not a unittest suite; needs Node and the "
        "gitignored decaid/ plugin checkout, which a clean checkout lacks.",
    ),
    (
        "tools/test_hacks_doc.py",
        "reads docs/HACKS.md; this mirror carries no docs/ because the export "
        "gate classes it research-prose / publish with changes. The file is "
        "published, the document it checks is not.",
    ),
    (
        "tools/test_unlock_tiers.py",
        "reads docs/UNLOCK_TIERS.md, docs/LOCAL_API.md and "
        "docs/openapi/local-api.yaml; this mirror carries no docs/ because the "
        "export gate classes it research-prose / publish with changes.",
    ),
    (
        "tools/test_public_export_policy.py",
        "imports tools/public_export.py, which the gate classes own-code / "
        "never: the gate quotes the deny patterns it refuses, so it cannot "
        "publish itself. Published test, withheld subject.",
    ),
    (
        "tools/official_app_cloud_ui_test.py",
        "manual Android harness; needs an emulator, adb, the installed Sync "
        "APK and the local cloud/DNS bridges.",
    ),
    (
        "tools/run_official_app_sim_test.py",
        "manual Android smoke harness; needs an emulator plus its proxy and "
        "reverse setup.",
    ),
)

EXCLUDED_OTHER: tuple[tuple[str, str], ...] = (
    (
        "tools/equiv/run.sh determinism and compare",
        "offline gates that rewrite committed baseline artifacts "
        "(runs/vendor/determinism.json, runs/compare-vendor-vs-recon.json) with "
        "absolute paths; the read-only comparator self-test runs instead.",
    ),
    (
        "e64ws-scale-bridge and decaid plugin suites",
        "separate repositories, not part of this checkout.",
    ),
)

EXCLUDED: tuple[tuple[str, str], ...] = EXCLUDED_FILES + EXCLUDED_OTHER

SUITES: tuple[UnittestSuite | FunctionSuite | CommandSuite, ...] = (
    UnittestSuite(
        "tests",
        ROOT,
        note="root client, ESP BLE, bridge and fixture tests",
        minimum=63,
        start="tests",
    ),
    UnittestSuite(
        "tools",
        ROOT,
        note="unit modules under tools/",
        # Measured on this tree, not copied from the research repository.  Four
        # modules that the research runner registers are absent here because the
        # export gate withholds what they import: tools/test_firmware_triage.py
        # and tools/test_public_export.py are `never`, so they are not in this
        # tree at all and cannot be named here; tools/test_hacks_doc.py and
        # tools/test_unlock_tiers.py are published but read documents under
        # docs/, which is `research-prose` / `publish with changes` and absent
        # here, so they are listed in EXCLUDED with that reason instead.
        # 163 is what is left of the research runner's 339; measured on this tree.
        minimum=163,
        modules=(
            "tools.test_e64ws_client",
            "tools.test_e64ws_simulator",
            "tools.test_grind_capture",
            "tools.test_official_app_harness",
            "tools.test_verify_evidence",
            "tools.test_findings_reproduction",
            "tools.test_todo_status",
            "tools.test_capture_proxy",
            "tools.test_api_coverage",
            "tools.test_capture_setup_screenshots",
            "tools.test_run_tests",
        ),
    ),
    UnittestSuite(
        "e64root",
        ROOT / "tools" / "e64root",
        note="owner root/SSH CLI",
        minimum=276,
        start="tests",
        top=".",
        docker_images=("php:8.3-cli",),
    ),
    UnittestSuite(
        "reimpl",
        ROOT / "tools" / "reimpl",
        note="clean-room reimplementation",
        minimum=124,
        start="tests",
        pythonpath=("src",),
    ),
    UnittestSuite(
        "local-cloud",
        ROOT,
        note="local-cloud service, contract refusals, deploy pins and deployment files",
        minimum=135,
        start="tools/local_cloud/tests",
        pattern="*_test.py",
    ),
    UnittestSuite(
        "android-patch",
        ROOT,
        note="offline Android patch pipeline",
        minimum=5,
        start="tools/android_patch",
    ),
    FunctionSuite(
        "virtual-grinder",
        ROOT / "tools" / "virtual-grinder",
        path="tests/test_proto.py",
        note="virtual grinder protocol checks",
        minimum=4,
    ),
    UnittestSuite(
        "esp-image",
        ROOT,
        note="ESP image and partition-table parser",
        minimum=55,
        start="tools/tests",
    ),
    UnittestSuite(
        "gbs-vectors",
        ROOT,
        note="GBS golden vectors and parity runner",
        minimum=32,
        start="tools/gbs",
    ),
    CommandSuite(
        "boot-script",
        ROOT / "tools" / "virtual-grinder",
        note="boot.scr slot and ustate harness",
        commands=(
            (sys.executable, "tests/test_boot_scr.py"),
            ("sh", "tests/rehearse_recovery.sh"),
        ),
        # The harness sources the built boot script; the gate classes it
        # build-artifact / never, so it is produced by the build and not shipped.
        requires_paths=("tools/virtual-grinder/boot.scr",),
    ),
    CommandSuite(
        "equiv-selftest",
        ROOT,
        note="differential harness comparator self-test",
        commands=((sys.executable, "tools/equiv/tools/selftest.py"),),
        # Mutates a copy of the vendor capture baseline, which only a real device
        # run produces.  Not tracked in any tree, so not carried here.
        requires_paths=("runs/vendor/02_readonly",),
    ),
    CommandSuite(
        "recon-cxx",
        ROOT / "tools" / "rebuild" / "esp-app" / "recon",
        note="host C++ scale and BLE gateway tests",
        commands=(
            ("sh", "tests/run_scale_gateway_test.sh"),
            ("sh", "tests/run_host_gateway_test.sh"),
        ),
        # Reconstructed vendor sources: vendor-derived-code / never, withheld.
        requires_paths=("tools/rebuild/esp-app/recon/scale_gateway.cpp",),
    ),
)

# Directories scanned for test files that no suite covers.
SCAN_SKIP = frozenset(
    {".git", "__pycache__", ".tools", "decaid", "node_modules", ".venv", "venv", "build", "dist"}
)


@dataclass
class Result:
    name: str
    note: str
    status: str = "ERROR"
    ran: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    output: str = ""
    detail: str = ""


RAN_RE = re.compile(r"^Ran (\d+) tests? in [\d.]+s$", re.MULTILINE)
STATUS_RE = re.compile(r"^(OK|FAILED)(?: \((.*)\))?$", re.MULTILINE)


def _unittest_command(suite: UnittestSuite) -> list[str]:
    command = [sys.executable, "-m", "unittest"]
    if suite.modules:
        command.extend(suite.modules)
    else:
        assert suite.start is not None
        command.extend(["discover", "-s", suite.start, "-p", suite.pattern])
        if suite.top:
            command.extend(["-t", suite.top])
    command.append("-q")
    return command


def _environment(suite: UnittestSuite) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if suite.pythonpath:
        paths = [str((suite.cwd / entry).resolve()) for entry in suite.pythonpath]
        inherited = env.get("PYTHONPATH")
        if inherited:
            paths.append(inherited)
        env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


def docker_image_problem(image: str) -> str | None:
    """Why a local Docker image cannot be used, or ``None`` when it is there.

    A suite that silently collects fewer tests because an image was never
    pulled is indistinguishable from a suite whose tests were deleted, so the
    missing image is reported as itself, with the command that fixes it, and
    before anything is collected.
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


def not_carried(suite: UnittestSuite | FunctionSuite | CommandSuite) -> str | None:
    """Why this checkout cannot run the suite at all, or ``None`` when it can.

    A published tree is a subset of the tree the suite was written for: the
    export gate withholds vendor firmware, captured evidence and research prose,
    and code that reads those paths has no input here.  That is a property of
    the checkout, not a regression, so it is reported as SKIP with the reason
    rather than as a silent zero, a failed assertion or a green run.
    """
    for path in suite.requires_paths:
        if not (ROOT / path).exists():
            return f"not carried by this checkout: {path}"
    return None


def _preflight(suite: UnittestSuite | FunctionSuite) -> str | None:
    """Return why the suite cannot start, or ``None`` when its inputs exist."""
    if not suite.cwd.is_dir():
        return f"missing directory {suite.cwd}"
    if isinstance(suite, UnittestSuite):
        if suite.start and not (suite.cwd / suite.start).is_dir():
            return f"missing directory {suite.cwd / suite.start}"
        for module in suite.modules:
            path = suite.cwd / (module.replace(".", "/") + ".py")
            if not path.is_file():
                return f"missing module {path.relative_to(ROOT)}"
        for image in suite.docker_images:
            problem = docker_image_problem(image)
            if problem is not None:
                return problem
    else:
        path = suite.cwd / suite.path
        if not path.is_file():
            return f"missing file {path.relative_to(ROOT)}"
    return None


def _run_unittest(suite: UnittestSuite, verbose: bool) -> Result:
    result = Result(name=suite.name, note=suite.note)
    withheld = not_carried(suite)
    if withheld is not None:
        result.status = "SKIP"
        result.detail = withheld
        result.output = withheld
        return result
    missing = _preflight(suite)
    if missing is not None:
        result.detail = missing
        result.output = missing
        return result

    command = _unittest_command(suite)
    if verbose:
        print(f"$ (cd {suite.cwd} && {' '.join(command)})")
    completed = subprocess.run(
        command,
        cwd=suite.cwd,
        env=_environment(suite),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = completed.stdout
    result.output = output

    ran_match = None
    for ran_match in RAN_RE.finditer(output):
        pass
    result.ran = int(ran_match.group(1)) if ran_match else 0

    status = None
    details = ""
    for status in STATUS_RE.finditer(output):
        details = status.group(2) or ""
    status_word = status.group(1) if status else ""
    counts: dict[str, int] = {}
    for part in details.split(","):
        key, separator, value = part.partition("=")
        if separator:
            try:
                counts[key.strip()] = int(value)
            except ValueError:
                pass

    result.failed = counts.get("failures", 0) + counts.get("unexpected successes", 0)
    result.errors = counts.get("errors", 0)
    result.skipped = counts.get("skipped", 0)
    expected_failures = counts.get("expected failures", 0)
    result.passed = max(
        result.ran - result.failed - result.errors - result.skipped - expected_failures,
        0,
    )

    if result.ran == 0:
        result.status = "EMPTY"
        result.detail = "collected zero tests"
    elif result.ran < suite.minimum:
        result.status = "FAIL"
        result.detail = f"ran {result.ran} tests, expected at least {suite.minimum}"
    elif completed.returncode == 0 and status_word == "OK":
        result.status = "PASS"
    elif status_word == "FAILED":
        result.status = "FAIL"
    else:
        result.status = "ERROR"
        result.detail = f"unittest exited {completed.returncode} without a summary"
    return result


def _run_functions(suite: FunctionSuite, verbose: bool) -> Result:
    result = Result(name=suite.name, note=suite.note)
    withheld = not_carried(suite)
    if withheld is not None:
        result.status = "SKIP"
        result.detail = withheld
        result.output = withheld
        return result
    missing = _preflight(suite)
    if missing is not None:
        result.detail = missing
        result.output = missing
        return result

    path = suite.cwd / suite.path
    if verbose:
        print(f"$ load {path}")

    module_name = "_run_tests_" + re.sub(r"\W+", "_", suite.name)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        result.output = f"cannot load {path}"
        result.detail = result.output
        return result

    module = importlib.util.module_from_spec(spec)
    try:
        sys.path.insert(0, str(suite.cwd))
        spec.loader.exec_module(module)
    except (Exception, SystemExit):
        result.output = traceback.format_exc()
        result.errors = 1
        result.detail = f"could not import {suite.path}"
        return result
    finally:
        try:
            sys.path.remove(str(suite.cwd))
        except ValueError:
            pass

    names = sorted(
        name
        for name in vars(module)
        if name.startswith("test_") and callable(getattr(module, name))
    )
    result.ran = len(names)
    if not names:
        result.status = "EMPTY"
        result.detail = "collected zero tests"
        return result

    lines: list[str] = []
    for name in names:
        try:
            getattr(module, name)()
        except (Exception, SystemExit):
            result.failed += 1
            lines.append(f"FAIL {name}")
            lines.append(traceback.format_exc())
        else:
            result.passed += 1
            lines.append(f"ok   {name}")
    result.output = "\n".join(lines)
    if result.ran < suite.minimum:
        result.status = "FAIL"
        result.detail = f"ran {result.ran} tests, expected at least {suite.minimum}"
    else:
        result.status = "FAIL" if result.failed else "PASS"
    return result


def _run_commands(suite: CommandSuite, verbose: bool) -> Result:
    result = Result(name=suite.name, note=suite.note)
    withheld = not_carried(suite)
    if withheld is not None:
        result.status = "SKIP"
        result.detail = withheld
        result.output = withheld
        return result
    if not suite.cwd.is_dir():
        result.detail = f"missing directory {suite.cwd}"
        result.output = result.detail
        return result

    lines: list[str] = []
    for command in suite.commands:
        result.ran += 1
        if verbose:
            print(f"$ (cd {suite.cwd} && {' '.join(command)})")
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            # A private TMPDIR keeps concurrent runs from sharing build output;
            # the gateway harness writes a fixed binary name into TMPDIR.
            with tempfile.TemporaryDirectory(prefix="run_tests_") as scratch:
                env["TMPDIR"] = scratch
                completed = subprocess.run(
                    command,
                    cwd=suite.cwd,
                    env=env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
        except OSError as error:
            result.failed += 1
            lines.append(f"FAIL {' '.join(command)}: {error}")
            continue
        lines.append(f"$ {' '.join(command)}")
        lines.append(completed.stdout.rstrip())
        if completed.returncode == 0:
            result.passed += 1
        else:
            result.failed += 1
            lines.append(f"exit {completed.returncode}")
    result.output = "\n".join(lines)
    if result.ran == 0:
        result.status = "EMPTY"
        result.detail = "no commands configured"
    else:
        result.status = "FAIL" if result.failed else "PASS"
    return result


def _test_files() -> list[Path]:
    """Every ``test_*.py`` outside the skipped directories, without walking .git."""
    found: list[Path] = []
    for directory, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(name for name in dirnames if name not in SCAN_SKIP)
        for filename in sorted(filenames):
            if filename.startswith("test_") and filename.endswith(".py"):
                found.append(Path(directory) / filename)
    return found


def _manifest_problems() -> list[str]:
    """Report test files no suite covers and stale EXCLUDED entries."""
    problems: list[str] = []
    covered: set[Path] = {ROOT / path for path, _ in EXCLUDED_FILES}
    starts: list[Path] = []
    for suite in SUITES:
        if isinstance(suite, UnittestSuite):
            for module in suite.modules:
                covered.add(suite.cwd / (module.replace(".", "/") + ".py"))
            if suite.start:
                starts.append(suite.cwd / suite.start)
        elif isinstance(suite, FunctionSuite):
            covered.add(suite.cwd / suite.path)
        elif isinstance(suite, CommandSuite):
            for command in suite.commands:
                for part in command:
                    if part.endswith(".py"):
                        covered.add(suite.cwd / part)

    for path in _test_files():
        relative = path.relative_to(ROOT)
        if path in covered or any(start in path.parents for start in starts):
            continue
        problems.append(
            f"{relative.as_posix()}: not covered by a suite and not in EXCLUDED"
        )
    for path, _ in EXCLUDED_FILES:
        if not (ROOT / path).is_file():
            problems.append(f"{path}: listed in EXCLUDED but missing from the tree")
    return problems


def _print_result(result: Result, verbose: bool) -> None:
    print(f"== {result.name} ==")
    print(
        f"  {result.status}: ran {result.ran}, passed {result.passed}, "
        f"failed {result.failed}, errors {result.errors}, skipped {result.skipped}"
        + (f" ({result.detail})" if result.detail else "")
    )
    if verbose or result.status != "PASS":
        if result.output:
            for line in result.output.rstrip().splitlines():
                print(f"  | {line}")


def _print_summary(results: list[Result]) -> bool:
    print()
    print(f"{'suite':<18} {'status':<7} {'ran':>5} {'pass':>5} {'fail':>5} {'error':>6} {'skip':>5}")
    print("-" * 62)
    for result in results:
        print(
            f"{result.name:<18} {result.status:<7} {result.ran:>5} {result.passed:>5} "
            f"{result.failed:>5} {result.errors:>6} {result.skipped:>5}"
        )
    print("-" * 62)
    total_ran = sum(result.ran for result in results)
    total_passed = sum(result.passed for result in results)
    total_failed = sum(result.failed for result in results)
    total_errors = sum(result.errors for result in results)
    total_skipped = sum(result.skipped for result in results)
    print(
        f"{'total':<18} {'':<7} {total_ran:>5} {total_passed:>5} "
        f"{total_failed:>5} {total_errors:>6} {total_skipped:>5}"
    )

    # SKIP means "this checkout does not carry the input", declared by the suite
    # and reported above.  It is not a pass -- nothing ran -- and it is not a
    # failure of the tree that was published.
    ok = all(result.status in ("PASS", "SKIP") for result in results)
    print()
    print("Result:", "PASS" if ok else "FAIL")
    return ok


def _print_excluded() -> None:
    print()
    print("Not run (explicit, with reason):")
    for name, reason in EXCLUDED:
        print(f"  - {name}: {reason}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print every suite's output, including passing runs",
    )
    args = parser.parse_args()

    print(f"Python {sys.version.split()[0]} at {sys.executable}")
    print(f"Repository root: {ROOT}")
    print()

    problems = _manifest_problems()
    if problems:
        print("Coverage manifest problems:")
        for problem in problems:
            print(f"  - {problem}")
        print()
        print("Add the suite to SUITES or list the file in EXCLUDED in tools/run_tests.py.")
        _print_excluded()
        return 1

    results: list[Result] = []
    for suite in SUITES:
        if isinstance(suite, UnittestSuite):
            result = _run_unittest(suite, args.verbose)
        elif isinstance(suite, FunctionSuite):
            result = _run_functions(suite, args.verbose)
        else:
            result = _run_commands(suite, args.verbose)
        results.append(result)
        _print_result(result, args.verbose)
        print()

    ok = _print_summary(results)
    _print_excluded()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
