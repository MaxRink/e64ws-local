"""Tests for the read-only grind capture helper."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.grind_capture import _read_token, summarize


def sample(t: float, state: str, weight: float, dd: int = 854,
           ntc1: float = 34.32, fan1: int = 0,
           failure: str = "None") -> dict:
    return {
        "t": t,
        "wall": "2026-11-18T16:00:00Z",
        "state": {
            "grindState": state,
            "grindCurrentWeightGr": weight,
            "ddValueDum": dd,
            "ntc1TempDegC": ntc1,
            "fan1TachoRpm": fan1,
            "grindFailure": failure,
        },
    }


class SummaryTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(summarize([]), {"samples": 0})

    def test_transitions_and_ranges(self) -> None:
        samples = [
            sample(0.0, "Idle", -0.5),
            sample(1.0, "Grinding", 2.0, dd=850, ntc1=34.4),
            sample(2.0, "Grinding", 18.2, dd=854, ntc1=34.6, fan1=0),
            sample(3.0, "Idle", 17.9, dd=854, ntc1=34.5),
        ]
        summary = summarize(samples)
        self.assertEqual(summary["samples"], 4)
        self.assertEqual(summary["duration_s"], 3.0)
        self.assertEqual([s["state"] for s in summary["states"]],
                         ["Idle", "Grinding", "Idle"])
        self.assertEqual(summary["weight_gr"], {
            "min": -0.5, "max": 18.2, "first": -0.5, "last": 17.9})
        self.assertEqual(summary["ddValueDum"], {"min": 850, "max": 854})
        self.assertEqual(summary["ntc1TempDegC"], {"min": 34.32, "max": 34.6})
        self.assertEqual(summary["failures"], [])

    def test_grind_window_is_reported(self) -> None:
        samples = [
            sample(0.0, "Idle", 486.0),
            {**sample(1.0, "Grind", 486.0),
             "state": {**sample(1.0, "Grind", 486.0)["state"],
                       "grindStartWeightGr": 486.0, "grindTargetWeightGr": 18}},
            {**sample(2.0, "GbwPostGrind", 504.0),
             "state": {**sample(2.0, "GbwPostGrind", 504.0)["state"],
                       "grindStartWeightGr": 486.0, "grindTargetWeightGr": 18}},
            {**sample(3.0, "Idle", -0.5),
             "state": {**sample(3.0, "Idle", -0.5)["state"],
                       "grindStartWeightGr": 486.0, "grindResultWeightGr": 18.085,
                       "grindFinalWeightGr": 504.689}},
        ]
        grind = summarize(samples)["grind"]
        self.assertEqual(grind["duration_s"], 1.0)
        self.assertEqual(grind["start_weight_gr"], 486.0)
        self.assertEqual(grind["target_weight_gr"], 18)
        self.assertAlmostEqual(grind["result_weight_gr"], 18.085)
        self.assertAlmostEqual(grind["final_weight_gr"], 504.689)

    def test_failure_is_recorded(self) -> None:
        summary = summarize([sample(0.0, "Idle", 0.0, failure="AdcTimeout")])
        self.assertEqual(summary["failures"], ["AdcTimeout"])


class TokenTests(unittest.TestCase):
    def test_token_file_is_stripped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "token"
            path.write_text("abcd\n")
            self.assertEqual(_read_token(str(path), None), "abcd")

    def test_literal_token(self) -> None:
        self.assertEqual(_read_token(None, "abcd"), "abcd")

    def test_empty_token_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "token"
            path.write_text("\n")
            with self.assertRaises(SystemExit):
                _read_token(str(path), None)


if __name__ == "__main__":
    unittest.main()
