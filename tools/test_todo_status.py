"""Checks for the tracked backlog rules and its archive."""

from __future__ import annotations

import contextlib
import importlib.util
import sys
import io
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
from tools.required_inputs import skip_without  # noqa: E402  (ROOT is on sys.path)
TOOL = ROOT / "tools" / "todo_status.py"
TODO = ROOT / "todo.md"
ARCHIVE = ROOT / "docs" / "archive" / "todo-2026-10-31.md"
GOAL = ROOT / "GOAL.md"


def _load(path: Path = TOOL):
    spec = importlib.util.spec_from_file_location("todo_status", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BacklogTests(unittest.TestCase):
    def setUp(self) -> None:
        # todo.md and GOAL.md are research prose; the gate withholds them.  The
        # backlog is re-read per test rather than per class so that a skip still
        # counts the case: a class-level skip would drop these tests out of the
        # run entirely and quietly lower the suite total.
        skip_without(["todo.md", "GOAL.md"])
        self.tool = _load()
        self.lines = self.tool.load(TODO)
        self.entries = self.tool.items(self.lines)

    def test_tracked_backlog_has_no_problems(self):
        self.assertEqual(self.tool.problems(self.lines), [])

    def test_counts_line_is_current_and_unique(self):
        markers = [line for line in self.lines if self.tool.COUNTS_ANY.search(line)]
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0], self.tool.marker(self.tool.counts(self.lines)))

    def test_every_item_has_one_tag_and_a_known_state(self):
        self.assertGreaterEqual(len(self.entries), 25)
        for number, state, _, block in self.entries:
            self.assertIn(state, self.tool.STATES, f"line {number}")
            self.assertIn(self.tool.item_tag(block), self.tool.TAGS, f"line {number}")

    def test_blocked_items_name_what_blocks_them(self):
        blocked = [entry for entry in self.entries if entry[1] == "!"]
        self.assertGreaterEqual(len(blocked), 5)
        for number, _, _, block in blocked:
            self.assertRegex(block, r"BLOCKED-(HW|CLOUD|VENDOR|ACCOUNT)", f"line {number}")

    def test_every_cited_path_exists(self):
        for number, _, _, block in self.entries:
            for token in self.tool.cited_paths(block):
                self.assertIsNone(self.tool.path_problem(token), f"line {number}")

    def test_delivery_rows_cite_existing_evidence(self):
        rows = self.tool.delivery_rows(self.lines)
        self.assertGreaterEqual(len(rows), 8)
        for number, row in rows:
            self.assertTrue(self.tool.cited_paths(row), f"line {number}")
            for token in self.tool.cited_paths(row):
                self.assertIsNone(self.tool.path_problem(token), f"line {number}")

    def test_tag_taxonomy_matches_the_goal(self):
        goal = GOAL.read_text(encoding="utf-8")
        block = goal.split("Stock vs dev separation", 1)[1].split("\n\n", 1)[0]
        documented = set(re.findall(r"`\[([A-Z]+)\]`", block))
        self.assertEqual(documented, set(self.tool.TAGS))


class RuleTests(unittest.TestCase):
    """The rules the documentation promises, asserted against synthetic input."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load()

    def problems(self, *lines: str) -> list[str]:
        return self.tool.problems(list(lines))

    def test_a_second_tag_is_rejected(self):
        found = self.problems("- [ ] [STOCK] [DEV] two tags `docs/LOCAL_API.md`")
        self.assertTrue(any("exactly one tag" in problem for problem in found), found)

    def test_an_untagged_item_is_rejected(self):
        found = self.problems("- [ ] no tag at all")
        self.assertTrue(any("exactly one tag" in problem for problem in found), found)

    def test_fenced_examples_are_not_items(self):
        found = self.problems("```", "- [ ] example inside a fence", "```")
        self.assertEqual([problem for problem in found if "tag" in problem], [])

    def test_star_and_indented_items_are_seen(self):
        self.assertEqual(len(self.tool.items(["  * [ ] [CI] indented item"])), 1)
        self.assertEqual(len(self.tool.items(["  - [~] [HW] indented vm-only"])), 1)

    def test_vm_only_items_need_a_path(self):
        found = self.problems("- [~] [HW] no evidence here")
        self.assertTrue(any("without an evidence path" in problem for problem in found), found)

    def test_done_items_need_an_existing_path(self):
        found = self.problems("- [x] [CI] done but imaginary `docs/not-a-file.md`")
        self.assertTrue(any("does not exist" in problem for problem in found), found)

    def test_paths_outside_the_repository_are_rejected(self):
        found = self.problems("- [x] [CI] escapes `../../etc/hosts`")
        self.assertTrue(any("outside the repository" in problem for problem in found), found)

    def test_prose_brackets_are_not_tags(self):
        found = self.problems("- [ ] [CI] P2 an item that mentions [NOTE] in prose `docs/LOCAL_API.md`")
        self.assertEqual([problem for problem in found if "tag" in problem], [])

    def test_a_second_tag_on_a_continuation_line_is_rejected(self):
        found = self.problems(
            "- [ ] [STOCK] an item that wraps here",
            "      and sneaks in [DEV] on the next line `docs/LOCAL_API.md`",
        )
        self.assertTrue(any("exactly one tag" in problem for problem in found), found)

    def test_write_refuses_a_backlog_that_has_problems(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "todo.md"
            original = "\n".join(
                [
                    "<!-- counts: open=2 vm-only=0 blocked=0 done=0 -->",
                    "- [ ] [STOCK] one `docs/LOCAL_API.md`",
                    "- [ ] no tag",
                ]
            )
            path.write_text(original + "\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = self.tool.main(["--write", "--path", str(path)])
            self.assertEqual(code, 1)
            self.assertEqual(path.read_text(encoding="utf-8"), original + "\n")

    def test_two_counts_lines_are_rejected(self):
        found = self.problems(
            self.tool.marker({"open": 1, "vm-only": 0, "blocked": 0, "done": 0}),
            self.tool.marker({"open": 1, "vm-only": 0, "blocked": 0, "done": 0}),
        )
        self.assertTrue(any("exactly one counts line" in problem for problem in found), found)

    def test_a_trailing_prose_counts_line_is_malformed(self):
        found = self.problems("<!-- counts: open=1 vm-only=0 blocked=0 done=0 --> and more")
        self.assertTrue(any("malformed" in problem for problem in found), found)

    def test_a_delivery_row_without_evidence_is_rejected(self):
        found = self.problems(
            "## 1. Delivery record",
            "| Delivered | Evidence |",
            "|---|---|",
            "| Something shipped | nothing here |",
            "## 2. Open",
        )
        self.assertTrue(any("without an evidence path" in problem for problem in found), found)


class ArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        # The archive and the backlog it was split from are both withheld.
        skip_without(["todo.md", "docs/archive/todo-2026-10-31.md"])

    def test_archive_preserves_the_old_checklist(self):
        self.assertTrue(ARCHIVE.is_file(), "the archived checklist is missing")
        lines = ARCHIVE.read_text(encoding="utf-8").splitlines()
        boxes = [line for line in lines if re.match(r"^\s*[-*] \[[ x~!]\]", line)]
        self.assertEqual(len(boxes), 368)
        self.assertTrue(any("Audited 2026-10-31" in line for line in lines))

    def test_archive_is_reachable_from_the_backlog(self):
        self.assertIn("docs/archive/todo-2026-10-31.md", TODO.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
