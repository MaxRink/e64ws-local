#!/usr/bin/env python3
"""Self-tests for the GBS vector runner using fake implementations.

These tests do not need node, decaid/, or a grinder. They prove that the
runner detects matches, mismatches, undeclared divergences, declared policy
divergences, capability gaps, known defects, and error contracts.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.gbs.run_vectors import (  # noqa: E402
    FAIL,
    POST_STATE,
    PASS,
    SKIP,
    Implementation,
    VectorError,
    evaluate,
    load_vectors,
    render_matrix,
    run,
    run_json,
    summarize,
    undeclared_disagreements,
)


def vector(**overrides):
    body = {
        "id": "v/one",
        "provenance": "I",
        "source": "test",
        "algorithm": "GbS1",
        "calls": [{"actualMs": 30000, "targetMs": 28000, "toleranceMs": 0, "estimatedDdDum": 500}],
        "expected": [{"phase": "adjust", "candidateDdDum": 10}],
    }
    body.update(overrides)
    return body


def adapter(outputs):
    def execute(vectors):
        return {
            item.id: outputs.get(item.id, [])
            for item in vectors
        }

    return execute


def make_implementation(name, outputs):
    return Implementation(name, name, adapter(outputs))


class LoaderTest(unittest.TestCase):
    def write(self, directory: str, document: dict) -> Path:
        path = Path(directory) / "vectors.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_valid_document_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp, {"schema": 1, "firmware_build": "x", "vectors": [vector()]})
            loaded = load_vectors(Path(tmp))
        self.assertEqual([item.id for item in loaded], ["v/one"])
        self.assertEqual(loaded[0].provenance, "I")

    def test_unknown_provenance_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp, {"schema": 1, "firmware_build": "x", "vectors": [vector(provenance="Z")]})
            with self.assertRaises(VectorError):
                load_vectors(Path(tmp))

    def test_expected_length_must_match_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            document = {"schema": 1, "firmware_build": "x", "vectors": [vector(expected=[])]}
            self.write(tmp, document)
            with self.assertRaises(VectorError):
                load_vectors(Path(tmp))

    def test_duplicate_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            document = {"schema": 1, "firmware_build": "x", "vectors": [vector(), vector()]}
            self.write(tmp, document)
            with self.assertRaises(VectorError):
                load_vectors(Path(tmp))

    def test_function_and_algorithm_are_mutually_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            body = vector(function="cxx_round", cases=[{"value": 1, "expected": 1}])
            self.write(tmp, {"schema": 1, "firmware_build": "x", "vectors": [body]})
            with self.assertRaises(VectorError):
                load_vectors(Path(tmp))

    def test_malformed_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "broken.json").write_text("{", encoding="utf-8")
            with self.assertRaises(VectorError):
                load_vectors(Path(tmp))

    def test_capability_gap_requires_known_implementation_and_reason(self) -> None:
        for gaps in ({"node": "no path"}, {"js": ""}, {"js": None}):
            with tempfile.TemporaryDirectory() as tmp:
                body = vector(implementations=["python"], capabilityGaps=gaps)
                self.write(tmp, {"schema": 1, "firmware_build": "x", "vectors": [body]})
                with self.assertRaises(VectorError):
                    load_vectors(Path(tmp))

    def test_known_defect_requires_known_implementation_and_reason(self) -> None:
        for defects in ({"node": "bug"}, {"js": ""}):
            with tempfile.TemporaryDirectory() as tmp:
                body = vector(knownDefects=defects)
                self.write(tmp, {"schema": 1, "firmware_build": "x", "vectors": [body]})
                with self.assertRaises(VectorError):
                    load_vectors(Path(tmp))

    def test_function_vectors_reject_expected_error(self) -> None:
        body = {
            "id": "v/fn",
            "provenance": "I",
            "source": "test",
            "function": "cxx_round",
            "cases": [{"value": 1, "expected": 1}],
            "expectedError": "ValueError",
        }
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp, {"schema": 1, "firmware_build": "x", "vectors": [body]})
            with self.assertRaises(VectorError):
                load_vectors(Path(tmp))

    def test_post_state_must_be_a_non_empty_object(self) -> None:
        for post_state in ([], {}, "state"):
            with tempfile.TemporaryDirectory() as tmp:
                body = vector(postState=post_state)
                self.write(tmp, {"schema": 1, "firmware_build": "x", "vectors": [body]})
                with self.assertRaises(VectorError):
                    load_vectors(Path(tmp))

    def test_implementations_must_be_unique(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            body = vector(implementations=["python", "python"])
            self.write(tmp, {"schema": 1, "firmware_build": "x", "vectors": [body]})
            with self.assertRaises(VectorError):
                load_vectors(Path(tmp))


class EvaluationTest(unittest.TestCase):
    def load(self, body: dict) -> object:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "v.json").write_text(
                json.dumps({"schema": 1, "firmware_build": "x", "vectors": [body]}),
                encoding="utf-8",
            )
            return load_vectors(Path(tmp))[0]

    def test_matching_implementations_pass_and_count_as_parity(self) -> None:
        item = self.load(vector())
        expected = [{"phase": "adjust", "candidateDdDum": 10}]
        outputs = {"v/one": expected}
        python = make_implementation("python", outputs)
        js = make_implementation("js", outputs)
        result = evaluate(item, {"python": expected, "js": expected}, [python, js])
        self.assertEqual(result.cells["python"].verdict, PASS)
        self.assertEqual(result.cells["js"].verdict, PASS)
        self.assertEqual(sorted(result.executed), ["js", "python"])
        summary = summarize([result], [python, js])
        self.assertEqual(summary["parity_vectors"], ["v/one"])

    def test_wrong_value_fails(self) -> None:
        item = self.load(vector())
        outputs = {"v/one": [{"phase": "adjust", "candidateDdDum": 11}]}
        result = evaluate(
            item, {"python": outputs["v/one"]}, [make_implementation("python", outputs)]
        )
        self.assertEqual(result.cells["python"].verdict, FAIL)
        self.assertIn("candidateDdDum", result.mismatches[0])

    def test_float_values_compare_at_vector_precision(self) -> None:
        body = vector(expected=[{"correction": -3.307519}])
        item = self.load(body)
        outputs = {"v/one": [{"correction": -3.3075185887155563}]}
        result = evaluate(
            item, {"python": outputs["v/one"]}, [make_implementation("python", outputs)]
        )
        self.assertEqual(result.cells["python"].verdict, PASS)

    def test_integer_values_are_exact(self) -> None:
        body = vector(expected=[{"candidateDdDum": 10}])
        item = self.load(body)
        outputs = {"v/one": [{"candidateDdDum": 10.4}]}
        result = evaluate(
            item, {"python": outputs["v/one"]}, [make_implementation("python", outputs)]
        )
        self.assertEqual(result.cells["python"].verdict, FAIL)

    def test_integer_values_allow_only_exact_float_equivalents(self) -> None:
        item = self.load(vector(expected=[{"candidateDdDum": 10}]))
        for got, verdict in ((10, PASS), (10.0, PASS), (10.0000001, FAIL)):
            outputs = {"v/one": [{"candidateDdDum": got}]}
            result = evaluate(
                item, {"python": outputs["v/one"]}, [make_implementation("python", outputs)]
            )
            self.assertEqual(result.cells["python"].verdict, verdict, msg=repr(got))

    def test_extra_diagnostic_fields_are_ignored(self) -> None:
        item = self.load(vector())
        left = {"v/one": [{"phase": "adjust", "candidateDdDum": 10, "central": 30.0}]}
        right = {"v/one": [{"phase": "adjust", "candidateDdDum": 10}]}
        implementations = [
            make_implementation("python", left),
            make_implementation("js", right),
        ]
        result = evaluate(
            item, {"python": left["v/one"], "js": right["v/one"]}, implementations
        )
        self.assertEqual(result.verdict, PASS)
        from tools.gbs.run_vectors import undeclared_disagreements  # noqa: PLC0415

        self.assertEqual(
            undeclared_disagreements(result, {"python": left["v/one"], "js": right["v/one"]}),
            [],
        )

    def test_declared_capability_gap_is_skipped_with_reason(self) -> None:
        body = vector(implementations=["python"], capabilityGaps={"js": "no public path"})
        item = self.load(body)
        outputs = {"v/one": [{"phase": "adjust", "candidateDdDum": 10}]}
        result = evaluate(
            item,
            {"python": outputs["v/one"], "js": outputs["v/one"]},
            [make_implementation("python", outputs), make_implementation("js", outputs)],
        )
        self.assertEqual(result.cells["python"].verdict, PASS)
        self.assertEqual(result.cells["js"].verdict, SKIP)
        self.assertIn("no public path", result.cells["js"].detail)
        self.assertIn("js", result.declared_gaps)

    def test_unavailable_implementation_is_reported_not_hidden(self) -> None:
        item = self.load(vector())
        outputs = {"v/one": [{"phase": "adjust", "candidateDdDum": 10}]}
        cpp = Implementation("cpp", "cpp", None, skip_reason="no entry point")
        result = evaluate(item, {"python": outputs["v/one"]}, [make_implementation("python", outputs), cpp])
        self.assertEqual(result.cells["cpp"].verdict, SKIP)
        self.assertEqual(result.cells["cpp"].detail, "no entry point")
        summary = summarize([result], [cpp])
        self.assertEqual(summary["skipped"], {"cpp": "no entry point"})

    def test_declared_divergence_uses_each_policy(self) -> None:
        body = vector(
            expected=None,
            divergences={
                "python": {"policy": "reject", "expectedError": "ValueError"},
                "js": {"policy": "safe null", "expected": [{"phase": "singular-central", "candidateDdDum": None}]},
            },
        )
        body.pop("expected")
        item = self.load(body)
        python_outputs = {"v/one": [{"error": "ValueError"}]}
        js_outputs = {
            "v/one": [{"phase": "singular-central", "candidateDdDum": None}]
        }
        python = make_implementation("python", python_outputs)
        js = make_implementation("js", js_outputs)
        result = evaluate(
            item,
            {"python": python_outputs["v/one"], "js": js_outputs["v/one"]},
            [python, js],
        )
        self.assertEqual(result.cells["python"].verdict, PASS)
        self.assertEqual(result.cells["js"].verdict, PASS)
        self.assertEqual(result.executed, ["python", "js"])
        self.assertEqual(result.diverged, ["python", "js"])
        self.assertTrue(result.declared_divergence)
        self.assertEqual(
            summarize([result], [python, js])["declared_divergences"],
            {"v/one": ["js", "python"]},
        )

    def test_post_state_matches_and_mismatches(self) -> None:
        body = vector(postState={"points": [[50, 30]], "lastResultDum": 10})
        item = self.load(body)
        matching = [
            {"phase": "adjust", "candidateDdDum": 10},
            {POST_STATE: {"points": [[50.0, 30.0]], "lastResultDum": 10}},
        ]
        result = evaluate(item, {"python": matching}, [make_implementation("python", {"v/one": matching})])
        self.assertEqual(result.cells["python"].verdict, PASS)

        mismatched = [
            {"phase": "adjust", "candidateDdDum": 10},
            {POST_STATE: {"points": [[50.0, 30.0]], "lastResultDum": 11}},
        ]
        failed = evaluate(
            item, {"python": mismatched}, [make_implementation("python", {"v/one": mismatched})]
        )
        self.assertEqual(failed.cells["python"].verdict, FAIL)
        self.assertIn("post-state", failed.mismatches[0])

    def test_missing_post_state_fails(self) -> None:
        body = vector(postState={"lastResultDum": 10})
        item = self.load(body)
        outputs = [{"phase": "adjust", "candidateDdDum": 10}]
        result = evaluate(
            item, {"python": outputs}, [make_implementation("python", {"v/one": outputs})]
        )
        self.assertEqual(result.cells["python"].verdict, FAIL)
        self.assertIn("post-state missing", result.mismatches[0])

    def test_expected_error_contract(self) -> None:
        body = vector(expected=None, expectedError="RuntimeError")
        body.pop("expected")
        item = self.load(body)
        outputs = {"v/one": [{"error": "RuntimeError"}]}
        result = evaluate(
            item, {"python": outputs["v/one"]}, [make_implementation("python", outputs)]
        )
        self.assertEqual(result.cells["python"].verdict, PASS)
        wrong = {"v/one": [{"error": "ValueError"}]}
        failed = evaluate(
            item, {"python": wrong["v/one"]}, [make_implementation("python", wrong)]
        )
        self.assertEqual(failed.cells["python"].verdict, FAIL)

    def test_float_tolerance_is_not_an_undeclared_disagreement(self) -> None:
        item = self.load(vector(expected=[{"correction": 1.0}]))
        left = {"v/one": [{"correction": 1.0000001}]}
        right = {"v/one": [{"correction": 1.0}]}
        result = evaluate(
            item,
            {"python": left["v/one"], "js": right["v/one"]},
            [make_implementation("python", left), make_implementation("js", right)],
        )
        self.assertEqual(result.verdict, PASS)
        self.assertEqual(
            undeclared_disagreements(
                result, {"python": left["v/one"], "js": right["v/one"]}
            ),
            [],
        )

    def test_difference_beyond_tolerance_is_an_undeclared_disagreement(self) -> None:
        item = self.load(vector(expected=[{"correction": 1.0}]))
        left = {"v/one": [{"correction": 0.9999994}]}
        right = {"v/one": [{"correction": 1.0000006}]}
        result = evaluate(
            item,
            {"python": left["v/one"], "js": right["v/one"]},
            [make_implementation("python", left), make_implementation("js", right)],
        )
        self.assertEqual(result.verdict, PASS)
        self.assertEqual(
            undeclared_disagreements(
                result, {"python": left["v/one"], "js": right["v/one"]}
            ),
            ["python and js disagree without a declared divergence"],
        )

    def test_divergence_with_one_executed_side_is_unproven(self) -> None:
        body = vector(
            expected=None,
            implementations=["python"],
            divergences={
                "python": {"policy": "reject", "expectedError": "ValueError"},
                "js": {"policy": "safe", "expected": [{"phase": "safe"}]},
            },
        )
        item = self.load(body)
        observed = [{"error": "ValueError"}]
        outputs = {"v/one": observed}
        implementations = [make_implementation("python", outputs)]
        result = evaluate(item, {"python": observed}, implementations)
        self.assertEqual(result.verdict, PASS)
        self.assertEqual(result.executed, ["python"])
        self.assertEqual(result.diverged, ["python"])
        self.assertFalse(result.declared_divergence)
        summary = summarize([result], implementations)
        self.assertEqual(summary["declared_divergences"], {})
        self.assertEqual(summary["unproven"], ["v/one"])
        self.assertIn("n/a", render_matrix([result], implementations))

    def test_known_defect_is_labelled_but_still_fails(self) -> None:
        body = vector(knownDefects={"js": "eviction off by one"})
        item = self.load(body)
        outputs = {"v/one": [{"phase": "adjust", "candidateDdDum": 11}]}
        js = make_implementation("js", outputs)
        result = evaluate(item, {"js": outputs["v/one"]}, [js])
        self.assertEqual(result.cells["js"].verdict, FAIL)
        self.assertEqual(result.defects, ["js"])
        self.assertIn("known defect: eviction off by one", result.mismatches[0])
        summary = summarize([result], [js])
        self.assertEqual(summary["failures"], ["v/one"])
        self.assertIn("v/one", summary["known_defects"])


class RunTest(unittest.TestCase):
    def execute(self, vectors, implementations) -> tuple[int, str]:
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = run(implementations=implementations, vectors=vectors)
        return code, stream.getvalue()

    def load(self, bodies) -> list:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "v.json").write_text(
                json.dumps({"schema": 1, "firmware_build": "x", "vectors": bodies}),
                encoding="utf-8",
            )
            return load_vectors(Path(tmp))

    def test_agreeing_run_exits_zero(self) -> None:
        item = self.load([vector()])
        outputs = {"v/one": [{"phase": "adjust", "candidateDdDum": 10}]}
        code, text = self.execute(
            item, [make_implementation("python", outputs), make_implementation("js", outputs)]
        )
        self.assertEqual(code, 0)
        self.assertIn("parity-proven: 1", text)

    def test_mismatch_exits_nonzero(self) -> None:
        item = self.load([vector()])
        outputs = {"v/one": [{"phase": "adjust", "candidateDdDum": 11}]}
        code, text = self.execute(item, [make_implementation("python", outputs)])
        self.assertEqual(code, 1)
        self.assertIn("failed vectors", text)

    def test_undeclared_disagreement_exits_nonzero(self) -> None:
        item = self.load([vector(expected=[{"correction": 1.0}])])
        left = {"v/one": [{"correction": 0.9999994}]}
        right = {"v/one": [{"correction": 1.0000006}]}
        code, text = self.execute(
            item, [make_implementation("python", left), make_implementation("js", right)]
        )
        self.assertEqual(code, 1)
        self.assertIn("undeclared divergences", text)
        self.assertIn("python and js disagree", text)

    def test_json_mode_reports_undeclared_disagreement(self) -> None:
        item = self.load([vector(expected=[{"correction": 1.0}])])
        left = {"v/one": [{"correction": 0.9999994}]}
        right = {"v/one": [{"correction": 1.0000006}]}
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = run_json(
                [make_implementation("python", left), make_implementation("js", right)],
                item,
            )
        self.assertEqual(code, 1)
        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["failures"], [])
        self.assertIn("v/one", payload["undeclared_disagreements"])

        stream = io.StringIO()
        with redirect_stdout(stream):
            code = run_json(
                [make_implementation("python", left), make_implementation("js", left)],
                item,
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue())["undeclared_disagreements"], {})

    def test_skip_only_run_exits_zero_but_says_unproven(self) -> None:
        item = self.load([vector()])
        code, text = self.execute(
            item, [Implementation("js", "js", None, skip_reason="decaid absent")]
        )
        self.assertEqual(code, 0)
        self.assertIn("parity is unproven", text)


if __name__ == "__main__":
    unittest.main()
