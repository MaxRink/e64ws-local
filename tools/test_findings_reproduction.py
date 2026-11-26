"""Offline checks for the findings harness, its record and its document.

These tests never boot the VM.  They assert that the committed results file,
the generated sections of ``docs/FINDINGS_REPRODUCTION.md`` and the status
table in ``run.py`` agree, and that the fixture preparation records and
restores what it changes.
"""

from __future__ import annotations

import importlib.util
import sys
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FINDINGS = ROOT / "tools" / "verify_findings"
RESULTS = FINDINGS / "results-fresh-swu.json"
DOC = ROOT / "docs" / "FINDINGS_REPRODUCTION.md"
STATUSES = {"reproduced", "partly", "static-only", "not reproduced", "latent", "superseded"}

from tools.required_inputs import skip_without  # noqa: E402  (ROOT is on sys.path)


def setUpModule() -> None:
    """Every case here reads the recorded results or the generated document.

    Both are withheld from the published subset -- the results are `evidence`
    and the document is research prose -- so the module is skipped there with
    the first missing path named.  Here both exist and nothing is skipped.
    """
    skip_without(["tools/verify_findings/results-fresh-swu.json", "docs/FINDINGS_REPRODUCTION.md"])


# Advisory findings that a live check bears on.  A finding-level status that
# disagrees with its own checks is the defect this mapping exists to catch.
FINDING_CHECKS = {
    "FW-01": ("http.fw01_root", "http.fw01_plain"),
    "FW-02": ("http.fw02_sqli",),
    "FW-03": ("fw03_sudo",),
    "FW-04": ("http.fw04_upload", "http.fw04_prepare"),
    "FW-05": ("esp.archive_exec",),
    "FW-07": ("http.tls_key_exposed",),
    "FW-09": ("http.fw09_password_echo",),
    "FW-10": ("http.state_forgery",),
    "FW-11": ("http.fw11_wifi_perm",),
    "FW-13": ("fw13_php_ini",),
    "FW-14": ("http.fw14_splash",),
    "FW-17": ("http.state_forgery",),
    "FW-24": ("http.fw24_literal_bearer",),
    "FW-26": ("fw26_libs",),
    "FW-27": ("fw27_esps0",),
    "FW-33": ("http.presession_ping", "http.presession_machine_info", "http.rest_api_dev"),
    "SW-04": ("http.sw04_reflect",),
    "SW-08": ("sw08_db_perms",),
    "SW-10": ("http.sw10_trailing_at",),
    "SW-11": ("http.fw14_splash",),
    "SW-13": ("sw13_avahi",),
    "SW-14": ("sw14_tokens",),
    "SW-15": ("sw15_psk",),
    "SW-16": ("sw16_fastcgi",),
    "WSS-01": ("wss.ping", "wss.dev_dispatch", "wss.token_mint"),
}


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeShell:
    """Record commands and answer the fixture probes prepare/restore make."""

    def __init__(self, fail_chmod: bool = False) -> None:
        self.commands: list[str] = []
        self.fail_chmod = fail_chmod
        self.modes = {
            "/db": "0755",
            "/storage": "0755",
            "/tmp/php-fastcgi.socket-0": "0755",
            "/tmp/php-fastcgi.socket-1": "0644",
        }
        self.config = (
            '"dddCalibrationAngleMilliDeg": 0\n'
            '"productionLineTestCompleted": false'
        )

    def __call__(self, command: str) -> tuple[int, str, str]:
        self.commands.append(command)
        if command.startswith("stat -c '%n %a'"):
            lines = [
                f"{path} {mode}"
                for path, mode in self.modes.items()
                if "php-fastcgi" in path
            ]
            return 0, "\n".join(lines), ""
        if command.startswith("stat -c %a "):
            target = command[len("stat -c %a "):].split(" 2>/dev/null")[0]
            return 0, self.modes.get(target, ""), ""
        if command.startswith("chmod "):
            if self.fail_chmod:
                return 1, "", "denied"
            _, mode, target = command.split()[:3]
            if target.endswith("*"):
                prefix = target.rstrip("*")
                for path in list(self.modes):
                    if path.startswith(prefix):
                        self.modes[path] = mode
            else:
                self.modes[target] = mode
            return 0, "", ""
        if command.startswith("cp -n"):
            return 0, "", ""
        if command.startswith("grep -oE"):
            return 0, self.config, ""
        if command.startswith("sed -i"):
            self.config = (
                '"dddCalibrationAngleMilliDeg": 1200\n'
                '"productionLineTestCompleted": true'
            )
            return 0, "", ""
        return 0, "", ""


class ResultsFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(RESULTS.read_text(encoding="utf-8"))
        cls.runner = _load("verify_findings_run", FINDINGS / "run.py")

    def test_counts_agree_with_the_check_list(self):
        checks = self.document["checks"]
        counts = self.document["counts"]
        self.assertEqual(len(checks), 58)
        self.assertEqual(sum(counts.values()), len(checks))
        for status in ("pass", "fail", "skip"):
            self.assertEqual(
                counts[status],
                sum(1 for check in checks if check["status"] == status),
                status,
            )

    def test_every_check_has_a_known_status_and_an_identifier(self):
        identifiers = [check["id"] for check in self.document["checks"]]
        self.assertEqual(len(identifiers), len(set(identifiers)), "duplicate check id")
        for check in self.document["checks"]:
            self.assertIn(check["status"], {"pass", "fail", "skip"})
            self.assertTrue(check["id"])
            self.assertTrue(check["evidence"])

    def test_provenance_is_present_and_honest(self):
        provenance = self.document.get("provenance")
        self.assertIsNotNone(provenance, "provenance block is missing")
        self.assertIn("mode", provenance)
        self.assertEqual(set(provenance["ports"]), {"http", "https", "wss", "ssh"})
        if provenance.get("recorded"):
            self.assertIn(provenance["mode"], {"live", "static"})
            self.assertEqual(
                set(provenance["git"]), {"commit", "branch", "dirty"}
            )
            self.assertTrue(provenance["git"]["commit"])
        else:
            self.assertTrue(
                provenance.get("note"),
                "an unrecorded provenance block must say why it is empty",
            )

    def test_matrix_agrees_with_the_checks_it_cites(self):
        statuses = {check["id"]: check["status"] for check in self.document["checks"]}
        for finding, check_ids in FINDING_CHECKS.items():
            mapped = [statuses[check] for check in check_ids if check in statuses]
            self.assertTrue(mapped, f"{finding}: no mapped check ran")
            status, _ = self.runner.MATRIX[finding]
            if "fail" in mapped:
                self.assertEqual(status, "not reproduced", finding)
            elif all(state == "pass" for state in mapped):
                self.assertIn(status, {"reproduced", "partly"}, finding)
            elif all(state == "skip" for state in mapped):
                self.assertIn(status, {"not reproduced", "partly", "static-only"}, finding)

    def test_known_defects_name_real_checks(self):
        identifiers = {check["id"] for check in self.document["checks"]}
        for defect in self.document.get("known_defects") or []:
            self.assertIn(defect["check"], identifiers)
            self.assertTrue(defect["issue"])
            self.assertTrue(defect["authoritative"])

    def test_matrix_covers_every_advisory_row(self):
        rows = self.runner.parse_findings()
        self.assertEqual(len(rows), 63)
        unclassified = [row["id"] for row in rows if row["id"] not in self.runner.MATRIX]
        self.assertEqual(unclassified, [], "advisory rows without a matrix status")
        for identifier, (status, evidence) in self.runner.MATRIX.items():
            self.assertIn(status, STATUSES | {"unclassified"}, identifier)
            self.assertTrue(evidence, identifier)


class DocumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(RESULTS.read_text(encoding="utf-8"))
        cls.runner = _load("verify_findings_run", FINDINGS / "run.py")
        cls.renderer = _load("verify_findings_render", FINDINGS / "render_doc.py")
        cls.text = DOC.read_text(encoding="utf-8")

    def test_generated_sections_are_current(self):
        rendered = self.renderer.render(self.document, self.text, self.runner)
        self.assertEqual(
            rendered,
            self.text,
            "docs/FINDINGS_REPRODUCTION.md is stale: run render_doc.py --write",
        )

    def test_duplicate_markers_are_rejected(self):
        doubled = self.text.replace(
            self.renderer.SUMMARY_START, self.renderer.SUMMARY_START + "\n" + self.renderer.SUMMARY_START, 1
        )
        with self.assertRaises(ValueError):
            self.renderer.render(self.document, doubled, self.runner)

    def test_counts_that_contradict_the_checks_are_rejected(self):
        broken = json.loads(json.dumps(self.document))
        broken["counts"] = {"pass": 0, "fail": 58, "skip": 0}
        with self.assertRaises(ValueError):
            self.renderer.validate(broken)

    def test_unknown_statuses_are_rejected(self):
        broken = json.loads(json.dumps(self.document))
        broken["checks"][0]["status"] = "PASS"
        with self.assertRaises(ValueError):
            self.renderer.validate(broken)

    def test_missing_surface_is_rejected(self):
        broken = json.loads(json.dumps(self.document))
        broken["checks"][0]["surface"] = ""
        with self.assertRaises(ValueError):
            self.renderer.validate(broken)

    def test_headline_numbers_match_the_results_file(self):
        counts = self.document["counts"]
        for label, value in (
            ("Checks run", len(self.document["checks"])),
            ("Pass", counts["pass"]),
            ("Fail", counts["fail"]),
            ("Skip", counts["skip"]),
        ):
            self.assertIn(f"| {label} | **{value}** |", self.text, label)

    def test_no_documented_failure_is_recorded_as_a_pass(self):
        failed = [check["id"] for check in self.document["checks"] if check["status"] == "fail"]
        section = self.text.split("### Failed checks", 1)[1].split("###", 1)[0]
        for identifier in failed:
            self.assertIn(f"`{identifier}`", section)
        if not failed:
            self.assertIn("None.", section)

    def test_retraction_count_matches_the_reconciliation_table(self):
        section = self.text.split("## 3. Reconciled with the first pass", 1)[1]
        section = section.split("## 4.", 1)[0]
        rows = [line for line in section.splitlines() if line.startswith("| ") and re.match(r"\| \d+ \|", line)]
        self.assertEqual(len(rows), 12, "reconciliation table lost a row")
        retracted = [line for line in rows if "Retracted" in line]
        partly = [line for line in rows if "Partly" in line]
        self.assertEqual(len(retracted), 3, "retraction count drifted")
        self.assertEqual(len(partly), 2, "partial count drifted")


class FixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = _load("verify_findings_run", FINDINGS / "run.py")
        self.runner.MUTATIONS.clear()
        self.runner.FIXTURE_PREPARED = False

    def test_prepare_records_every_change(self):
        shell = FakeShell()
        changes = self.runner.prepare_fixtures(shell)
        self.assertEqual(len(changes), 4)
        self.assertEqual(
            [change["target"] for change in changes],
            ["/db", "/storage", "/tmp/php-fastcgi.socket*", "/db/HsgConfig.json"],
        )
        self.assertTrue(self.runner.FIXTURE_PREPARED)
        commands = "\n".join(shell.commands)
        for expected in (
            "chmod 0777 /db",
            "chmod 0777 /storage",
            "chmod 0777 /tmp/php-fastcgi.socket*",
            "sed -i -E",
        ):
            self.assertIn(expected, commands)
        self.assertIn('"dddCalibrationAngleMilliDeg": 1200', shell.config)
        self.assertIn('"productionLineTestCompleted": true', shell.config)

    def test_prepare_records_the_previous_value(self):
        shell = FakeShell()
        changes = self.runner.prepare_fixtures(shell)
        by_target = {change["target"]: change for change in changes}
        self.assertEqual(by_target["/db"]["before"], "0755")
        self.assertEqual(by_target["/db"]["after"], "0777")
        self.assertIn("dddCalibrationAngleMilliDeg", by_target["/db/HsgConfig.json"]["before"])

    def test_restore_puts_the_previous_modes_back(self):
        shell = FakeShell()
        self.runner.prepare_fixtures(shell)
        self.runner.restore_fixtures(shell)
        self.assertEqual(shell.modes["/db"], "0755")
        self.assertEqual(shell.modes["/storage"], "0755")
        self.assertEqual(shell.modes["/tmp/php-fastcgi.socket-0"], "0755")
        self.assertEqual(shell.modes["/tmp/php-fastcgi.socket-1"], "0644")
        commands = "\n".join(shell.commands)
        self.assertIn("chmod 0755 /tmp/php-fastcgi.socket-0", commands)
        self.assertIn("chmod 0644 /tmp/php-fastcgi.socket-1", commands)
        self.assertTrue(any(command.startswith("cp /tmp/vgverify-HsgConfig.") for command in shell.commands))
        self.assertEqual(self.runner.MUTATIONS, [], "the record must not survive a restore")

    def test_a_failed_chmod_is_recorded_and_blocks_the_prepared_flag(self):
        shell = FakeShell(fail_chmod=True)
        changes = self.runner.prepare_fixtures(shell)
        self.assertFalse(self.runner.FIXTURE_PREPARED)
        self.assertTrue(all(change.get("error") for change in changes if change["step"] == "chmod"))
        self.assertIn("exited 1", changes[0]["error"])

    def test_an_unreadable_config_is_left_alone(self):
        shell = FakeShell()
        shell.config = ""
        changes = self.runner.prepare_fixtures(shell)
        config = [change for change in changes if change["step"] == "config"][0]
        self.assertIn("error", config)
        self.assertFalse(self.runner.FIXTURE_PREPARED)

    def test_fixture_note_explains_a_prepared_value(self):
        shell = FakeShell()
        self.runner.prepare_fixtures(shell)
        note = self.runner.fixture_note("/db")
        self.assertIn("prepared by the harness", note)
        self.assertIn("0755", note)
        self.assertEqual(self.runner.fixture_note("/not/prepared"), "")
        self.runner.restore_fixtures(shell)
        self.assertEqual(self.runner.fixture_note("/db"), "")


class SwuResolutionTests(unittest.TestCase):
    def test_tracked_swu_path_is_preferred(self):
        runner = _load("verify_findings_run", FINDINGS / "run.py")
        self.assertTrue(str(runner.SWU).endswith("HEM-HSG-HMI-S01-V01.16-24.swu"))
        self.assertIn("firmware", str(runner.SWU).split("/"))


if __name__ == "__main__":
    unittest.main()
