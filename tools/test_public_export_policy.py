"""Policy regressions for ``tools/public_export.py``.

``test_public_export.py`` is a frozen contract and must not be edited, so the
rules that cannot be expressed as a byte pattern live here: the verdicts that
depend on what a file does rather than where it lives, the deny list that must
not be reachable by changing case, and the git entry type that is refused
instead of being copied.

Nothing here touches the network, writes into the repository, or publishes.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "public_export.py"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.required_inputs import skip_without  # noqa: E402  (path set above)


def setUpModule() -> None:
    """Skip when the gate itself is not carried here.

    ``tools/public_export.py`` is ``own-code`` / ``never``: it quotes the deny
    patterns it refuses, so it cannot publish itself.  The policy it enforces is
    still pinned here, where both files exist.
    """
    skip_without(["tools/public_export.py"])

# Exploit and root tooling is published on purpose: the owner's decision, and
# the already-published mirror (github.com/MaxRink/e64ws-local) ships it.  This
# test pins that decision so a later reviewer cannot withhold it by accident.
EXPLOIT_PATHS = (
    "tools/web_root.py",
    "tools/esp_root.py",
    "tools/e64root/README.md",
    "tools/e64root/payloads.py",
    "tools/e64root/commands.py",
)

# The one subtree inside tools/e64root/ that the mirror does not ship: a
# third-party README and a dropbear binary, which stay vendor-derived.
WITHHELD_INSIDE_EXPLOITS = (
    "tools/e64root/vendor/README.md",
    "tools/e64root/vendor/dropbear-armhf",
)


def run_export(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        check=False,
    )


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout


class SyntheticRepo:
    """A throwaway git repository that can also carry a submodule entry."""

    def __init__(self, files: dict[str, bytes | str]) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="public-export-policy-")
        self.root = Path(self._tmp.name) / "repo"
        self.root.mkdir()
        git(self.root, "init", "-q")
        self.add(files)

    def add(self, files: dict[str, bytes | str]) -> None:
        for relative, content in files.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content.encode() if isinstance(content, str) else content)
        git(self.root, "add", "-A")

    def add_gitlink(self, path: str) -> None:
        """Record ``path`` as a submodule entry, which has no file behind it."""
        git(
            self.root,
            "-c",
            "user.name=policy test",
            "-c",
            "user.email=policy@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "base",
        )
        commit = git(self.root, "rev-parse", "HEAD").strip()
        git(self.root, "update-index", "--add", "--cacheinfo", f"160000,{commit},{path}")

    def cleanup(self) -> None:
        self._tmp.cleanup()


class ExploitToolingPolicyTests(unittest.TestCase):
    def test_root_exploits_are_published_on_purpose(self) -> None:
        """The owner publishes root tooling; the table must not withhold it."""
        for path in EXPLOIT_PATHS:
            with self.subTest(path=path):
                self.assertTrue(
                    (ROOT / path).is_file(),
                    msg=f"{path} is missing; this test must not pass vacuously",
                )

        proc = run_export("--check", "--json")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        document = json.loads(proc.stdout)
        published = {entry["path"]: entry["class"] for entry in document["files"]}
        withheld = {entry["path"]: entry["class"] for entry in document["excluded"]}

        for path in EXPLOIT_PATHS:
            with self.subTest(path=path):
                self.assertTrue(
                    path in published,
                    msg=f"{path} is withheld, but the owner publishes it",
                )
                self.assertEqual(published.get(path), "exploit-tooling")

        # The vendor subtree the mirror does not ship stays withheld: publishing
        # our own tooling is not the same as publishing somebody else's binary.
        for path in WITHHELD_INSIDE_EXPLOITS:
            with self.subTest(path=path):
                self.assertFalse(
                    path in published, msg=f"{path} is third-party material"
                )
                self.assertEqual(withheld.get(path), "vendor-derived-code")


class DenyPathTests(unittest.TestCase):
    def test_case_variant_denied_prefix_is_refused(self) -> None:
        """`docs/BIBLE/` is the same area as `docs/bible/`."""
        repo = SyntheticRepo({"docs/BIBLE/catalogue.md": "vendor catalogue\n"})
        self.addCleanup(repo.cleanup)
        proc = run_export(
            "--check", "--repo", str(repo.root), "--allow-glob", "docs/BIBLE/**"
        )
        self.assertEqual(
            proc.returncode, 1, msg=f"expected a refusal:\n{proc.stdout}\n{proc.stderr}"
        )
        offending = [
            line
            for line in proc.stderr.splitlines()
            if "docs/BIBLE/catalogue.md" in line and "deny-path" in line
        ]
        self.assertTrue(offending, msg=proc.stderr)
        self.assertIn("nothing was written", proc.stderr)


class GitlinkTests(unittest.TestCase):
    def test_submodule_entry_is_refused_not_copied(self) -> None:
        """A gitlink is a commit id; copying it would fake a file."""
        repo = SyntheticRepo({"apps/README.md": "our own client\n"})
        self.addCleanup(repo.cleanup)
        repo.add_gitlink("apps/plugin")

        proc = run_export("--check", "--repo", str(repo.root))
        self.assertEqual(
            proc.returncode, 1, msg=f"expected a refusal:\n{proc.stdout}\n{proc.stderr}"
        )
        offending = [
            line
            for line in proc.stderr.splitlines()
            if "apps/plugin" in line and "gitlink" in line
        ]
        self.assertTrue(offending, msg=proc.stderr)
        self.assertIn("nothing was written", proc.stderr)

        with tempfile.TemporaryDirectory(prefix="public-export-gitlink-") as temporary:
            out = Path(temporary) / "out"
            proc = run_export("--repo", str(repo.root), "--out", str(out))
            self.assertEqual(proc.returncode, 1, msg=proc.stderr)
            self.assertFalse(
                out.exists(), msg="a refused run created the output directory"
            )


if __name__ == "__main__":
    unittest.main()
