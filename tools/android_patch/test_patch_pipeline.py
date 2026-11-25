from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from common import (
    BLOCKED_HOST,
    CLOUD_HOST,
    CLOUD_HOST_OFFSETS,
    LIBAPP_SHA256,
    PatchError,
    load_gate_patch,
    offsets,
)


class PatchPipelineTests(unittest.TestCase):
    def test_cloud_replacement_is_length_preserving(self) -> None:
        self.assertEqual(len(CLOUD_HOST), len(BLOCKED_HOST))

    def test_pinned_cloud_offsets_are_disjoint(self) -> None:
        self.assertEqual(tuple(sorted(set(CLOUD_HOST_OFFSETS))), CLOUD_HOST_OFFSETS)
        self.assertTrue(all(right - left >= len(CLOUD_HOST) for left, right in zip(CLOUD_HOST_OFFSETS, CLOUD_HOST_OFFSETS[1:])))

    def test_offset_scanner_finds_overlapping_candidates(self) -> None:
        self.assertEqual(offsets(b"aaaa", b"aa"), [0, 1, 2])

    def test_gate_patch_fails_closed_without_evidence_status(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "gate.json"
            path.write_text(
                json.dumps(
                    {
                        "input_libapp_sha256": LIBAPP_SHA256,
                        "status": "blocked",
                        "patches": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PatchError, "status"):
                load_gate_patch(path, b"test")

    def test_gate_patch_checks_expected_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "gate.json"
            path.write_text(
                json.dumps(
                    {
                        "input_libapp_sha256": LIBAPP_SHA256,
                        "status": "evidence_supported",
                        "patches": [
                            {
                                "purpose": "account_gate",
                                "offset": "0x1",
                                "expected_hex": "ffff",
                                "replacement_hex": "0000",
                                "confidence": "high",
                                "evidence": "synthetic unit-test fixture",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PatchError, "expected bytes"):
                load_gate_patch(path, b"abcd")


if __name__ == "__main__":
    unittest.main()
