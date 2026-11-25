#!/usr/bin/env python3
"""Unit tests for tools/verify_evidence.py on a synthetic evidence tree."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "verify_evidence.py"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class VerifyEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.extraction = base / "extraction"
        self.repo = base / "repo"
        self.manifests = self.repo / "docs" / "evidence" / "manifests"
        self.extraction.mkdir()
        self.manifests.mkdir(parents=True)

    def write(self, relative: str, data: bytes) -> Path:
        path = self.extraction / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def write_repo(self, relative: str, data: bytes) -> Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def entry(self, name: str, data: bytes, **extra: object) -> dict:
        entry = {
            "logical_name": name,
            "local_path": f"class/{name}.bin",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        entry.update(extra)
        return entry

    def write_manifest(self, entries: list[dict], **extra: object) -> Path:
        document = {
            "schema_version": 1,
            "artifact_class": "test",
            "title": "Synthetic evidence manifest",
            "entries": entries,
            **extra,
        }
        path = self.manifests / "test.json"
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        return path

    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--manifests",
                str(self.manifests),
                "--root",
                str(self.extraction),
                "--repo-root",
                str(self.repo),
                *arguments,
            ],
            text=True,
            check=False,
            capture_output=True,
            timeout=60,
        )

    def test_present_and_missing_are_reported(self) -> None:
        self.write("class/present.bin", b"alpha")
        self.write_manifest(
            [
                self.entry("present", b"alpha"),
                self.entry("absent", b"beta"),
            ]
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("present", result.stdout)
        self.assertIn("match", result.stdout)
        self.assertIn("absent", result.stdout)
        self.assertIn("missing", result.stdout)
        self.assertIn("PASS", result.stdout)

    def test_hash_mismatch_fails(self) -> None:
        self.write("class/changed.bin", b"actual")
        self.write_manifest(
            [
                {
                    "logical_name": "changed",
                    "local_path": "class/changed.bin",
                    "size": len(b"expected"),
                    "sha256": hashlib.sha256(b"expected").hexdigest(),
                }
            ]
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 1)
        self.assertIn("mismatch", result.stdout)
        self.assertIn("FAIL", result.stdout)

    def test_size_mismatch_fails_even_when_hash_matches(self) -> None:
        entry = self.entry("sized", b"same bytes")
        entry["size"] = len(b"same bytes") + 1
        self.write("class/sized.bin", b"same bytes")
        self.write_manifest([entry])
        result = self.run_tool()
        self.assertEqual(result.returncode, 1)
        self.assertIn("mismatch", result.stdout)

    def test_strict_missing_fails(self) -> None:
        self.write_manifest([self.entry("absent", b"anything")])
        result = self.run_tool("--strict")
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing", result.stdout)
        self.assertIn("--strict", result.stdout)

    def test_entry_count_check_failure(self) -> None:
        self.write("class/only.bin", b"one")
        self.write_manifest(
            [self.entry("only", b"one", kind="apk")],
            count_checks=[
                {
                    "label": "APK entries",
                    "filter": {"kind": "apk"},
                    "expected": 2,
                }
            ],
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 1)
        self.assertIn("APK entries", result.stdout)
        self.assertIn("expected 2, observed 1", result.stdout)

    def test_entry_count_check_passes(self) -> None:
        self.write("class/only.bin", b"one")
        self.write_manifest(
            [self.entry("only", b"one", kind="apk")],
            count_checks=[
                {
                    "label": "APK entries",
                    "filter": {"kind": "apk"},
                    "expected": 1,
                }
            ],
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok   APK entries", result.stdout)

    def test_sum_count_check(self) -> None:
        self.write("class/a.bin", b"a")
        self.write("class/b.bin", b"b")
        self.write_manifest(
            [
                self.entry("a", b"a", kind="csv", expected_functions=5),
                self.entry("b", b"b", kind="csv", expected_functions=7),
            ],
            count_checks=[
                {
                    "label": "functions",
                    "filter": {"kind": "csv"},
                    "sum_field": "expected_functions",
                    "expected": 12,
                }
            ],
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("expected 12, observed 12", result.stdout)

    def test_row_count_mismatch_fails(self) -> None:
        self.write("class/rows.csv", b"header\none\ntwo\n")
        entry = self.entry("rows", b"header\none\ntwo\n", expected_rows=2)
        entry["local_path"] = "class/rows.csv"
        self.write_manifest([entry])
        result = self.run_tool()
        self.assertEqual(result.returncode, 1)
        self.assertIn("rows rows", result.stdout)
        self.assertIn("expected 2, observed 3", result.stdout)

    def test_row_count_matches_and_final_line_without_newline(self) -> None:
        self.write("class/rows.csv", b"header\none\ntwo")
        entry = self.entry("rows", b"header\none\ntwo", expected_rows=3)
        entry["local_path"] = "class/rows.csv"
        self.write_manifest([entry])
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("expected 3, observed 3", result.stdout)

    def test_missing_file_skips_row_count(self) -> None:
        self.write_manifest(
            [self.entry("rows", b"header\none\n", expected_rows=2)]
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("rows rows", result.stdout)

    def test_repository_root_location(self) -> None:
        self.write_repo("vendor/package.swu", b"vendor bytes")
        self.write_manifest(
            [
                {
                    "logical_name": "vendor-package",
                    "local_path": "vendor/package.swu",
                    "location": "repo",
                    "size": len(b"vendor bytes"),
                    "sha256": hashlib.sha256(b"vendor bytes").hexdigest(),
                }
            ]
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("match", result.stdout)

    def test_path_escape_is_rejected(self) -> None:
        self.write_manifest(
            [
                {
                    "logical_name": "escape",
                    "local_path": "../outside.bin",
                    "size": 0,
                    "sha256": EMPTY_SHA256,
                }
            ]
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("must stay inside", result.stderr)

    def test_duplicate_logical_name_is_rejected(self) -> None:
        self.write("class/a.bin", b"a")
        self.write_manifest([self.entry("same", b"a"), self.entry("same", b"a")])
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate logical_name", result.stderr)

    def test_missing_manifest_directory_is_rejected(self) -> None:
        self.manifests.rmdir()
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("manifest directory does not exist", result.stderr)

    def test_empty_manifest_directory_is_rejected(self) -> None:
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("no JSON manifests found", result.stderr)

    def test_null_hash_is_rejected(self) -> None:
        self.write("class/a.bin", b"a")
        entry = self.entry("a", b"a")
        entry["sha256"] = None
        self.write_manifest([entry])
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("sha256 must be 64 lowercase hex characters", result.stderr)

    def test_malformed_unverifiable_item_is_rejected(self) -> None:
        self.write("class/a.bin", b"a")
        self.write_manifest([self.entry("a", b"a")], unverifiable=["not an object"])
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("unverifiable[0]: item must be an object", result.stderr)

    def test_negative_expected_functions_is_rejected(self) -> None:
        self.write("class/a.bin", b"a")
        entry = self.entry("a", b"a")
        entry["expected_functions"] = -1
        self.write_manifest([entry])
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("expected_functions must be a non-negative integer", result.stderr)

    def test_short_flag_abbreviates_hashes(self) -> None:
        self.write("class/a.bin", b"a")
        digest = hashlib.sha256(b"a").hexdigest()
        self.write_manifest([self.entry("a", b"a")])
        result = self.run_tool("--short")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(digest[:16], result.stdout)
        self.assertNotIn(digest, result.stdout)

    def test_quiet_omits_the_table(self) -> None:
        self.write("class/a.bin", b"a")
        self.write_manifest(
            [self.entry("a", b"a")],
            count_checks=[
                {"label": "entries", "filter": {"kind": "apk"}, "expected": 0}
            ],
        )
        result = self.run_tool("--quiet")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("test.json: 1 match, 0 mismatch, 0 missing", result.stdout)
        self.assertNotIn("expected hash", result.stdout)
        self.assertNotIn("unverifiable", result.stdout)


if __name__ == "__main__":
    unittest.main()
