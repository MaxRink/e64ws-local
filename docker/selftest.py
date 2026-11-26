#!/usr/bin/env python3
"""Static checks for the container build targets under ``docker/``.

Why this exists: a digest pin that quietly loses its hash, a compose service
pointing at a deleted Dockerfile, a target that ``verify.sh`` forgets, or a
table row that ``docs/REPRODUCIBLE_BUILDS.md`` stops mentioning are all
failures that a green ``docker build`` would not catch - and that neither a
human nor a build log notices.  These checks read files only, never call
docker, and finish in well under a second, so they can gate a change that
touches docker/ without a network round trip.

This suite is intentionally not registered in ``tools/run_tests.py``: the
runner only accepts suites listed there, and it treats an unregistered
``test_*.py`` as a failure.  ``docker/verify.sh --selftest`` runs it instead.
The file is therefore named ``selftest.py`` and not ``test_*.py``.

Run:
    python3 docker/selftest.py -v
    sh docker/verify.sh --selftest
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

DOCKER = Path(__file__).resolve().parent
REPO = DOCKER.parent
DOC = REPO / "docs" / "REPRODUCIBLE_BUILDS.md"

# The interactive development container that predates this scaffold.  It is not
# one of the build targets, it is not owned by this change, and its single
# `FROM debian:bookworm-slim` is deliberately unpinned, so it is excluded here
# rather than silently treated as pinned.
PRE_EXISTING = {"dev-env"}

# Every target verify.sh knows about, split the way verify.sh splits them.
ENABLED = {"py311", "py313", "py315", "firmware-triage", "php", "node26"}
HEAVY = {"android", "ios-grindercore"}
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
ENV_LINE = re.compile(r"^([A-Z0-9_]+)=(\S+)$")


def dockerfiles() -> list[Path]:
    """Every Dockerfile under docker/, minus the pre-existing dev container."""
    found = []
    for path in sorted(DOCKER.rglob("Dockerfile")):
        if path.parent.name in PRE_EXISTING:
            continue
        found.append(path)
    return found


def statements(path: Path) -> list[str]:
    """Dockerfile instructions with comments and blank lines removed."""
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def env_pins() -> dict[str, str]:
    """The KEY=VALUE pins in docker/images.env."""
    pins: dict[str, str] = {}
    for line in (DOCKER / "images.env").read_text(encoding="utf-8").splitlines():
        match = ENV_LINE.match(line)
        if match:
            pins[match.group(1)] = match.group(2)
    return pins


def stage_aliases(path: Path) -> set[str]:
    """The ``AS <name>`` aliases of a Dockerfile, so a stage is not mistaken for a base image."""
    aliases = set()
    for statement in statements(path):
        match = re.match(r"^FROM\s+\S+\s+AS\s+(\S+)$", statement, re.IGNORECASE)
        if match:
            aliases.add(match.group(1).lower())
    return aliases


class ImagePinTests(unittest.TestCase):
    """Every FROM must resolve to a digest, directly or through images.env."""

    def test_there_are_dockerfiles_to_check(self) -> None:
        # A glob that matches nothing would make every test below vacuous.
        self.assertGreaterEqual(len(dockerfiles()), 5, [p.name for p in dockerfiles()])

    def test_every_literal_from_is_pinned_by_digest(self) -> None:
        seen = 0
        for path in dockerfiles():
            aliases = stage_aliases(path)
            for statement in statements(path):
                if not statement.upper().startswith("FROM "):
                    continue
                seen += 1
                reference = statement.split(None, 1)[1].strip().split()[0]
                if reference.startswith("${") or reference.lower() in aliases:
                    continue
                with self.subTest(dockerfile=str(path.relative_to(REPO))):
                    self.assertRegex(
                        reference,
                        DIGEST,
                        f"{path} FROM {reference} is not pinned by digest",
                    )
        self.assertGreater(seen, 0, "no FROM instruction was found at all")

    def test_parameterised_from_is_supplied_from_images_env(self) -> None:
        """A ${ARG} base image is only pinned if its caller passes a real digest."""
        pins = env_pins()
        verify_text = (DOCKER / "verify.sh").read_text(encoding="utf-8")
        compose_text = (DOCKER / "compose.yaml").read_text(encoding="utf-8")
        supplied: dict[str, str] = {}
        # compose:             PYTHON_IMAGE: ${PYTHON_311:?...
        supplied.update(
            re.findall(r"^\s+([A-Z0-9_]+): \$\{([A-Z0-9_]+)", compose_text, re.MULTILINE)
        )
        # verify.sh:           --build-arg "DEBIAN_IMAGE=$DEBIAN_BOOKWORM"
        supplied.update(
            re.findall(r'--build-arg "([A-Z0-9_]+)=\$([A-Z0-9_]+)"', verify_text)
        )
        parameterised = 0
        for path in dockerfiles():
            for statement in statements(path):
                if not statement.upper().startswith("FROM "):
                    continue
                reference = statement.split(None, 1)[1].strip().split()[0]
                if not (reference.startswith("${") and reference.endswith("}")):
                    continue
                parameterised += 1
                argument = reference[2:-1]
                with self.subTest(dockerfile=str(path.relative_to(REPO)), argument=argument):
                    self.assertIn(
                        argument,
                        supplied,
                        f"nothing supplies --build-arg {argument} for {path.name}",
                    )
                    pin_name = supplied[argument]
                    self.assertIn(pin_name, pins, f"{argument} is fed from unknown pin {pin_name}")
                    self.assertRegex(pins[pin_name], DIGEST, f"{pin_name} is not digest-pinned")
        self.assertGreater(parameterised, 0, "no parameterised FROM was found to check")

    def test_images_env_values_are_pinned_and_named(self) -> None:
        pins = env_pins()
        self.assertGreaterEqual(len(pins), 6, sorted(pins))
        for name, value in pins.items():
            with self.subTest(pin=name):
                self.assertRegex(name, r"^[A-Z0-9_]+$")
                self.assertRegex(value, r"^[a-z0-9._/-]+:[A-Za-z0-9._-]+" + DIGEST.pattern)


class ComposeTests(unittest.TestCase):
    """compose.yaml must describe real Dockerfiles and use the pinned names."""

    def test_dockerfile_references_exist(self) -> None:
        text = (DOCKER / "compose.yaml").read_text(encoding="utf-8")
        references = re.findall(r"^\s*dockerfile:\s*(\S+)$", text, re.MULTILINE)
        self.assertGreaterEqual(len(references), 6, references)
        for reference in references:
            with self.subTest(dockerfile=reference):
                candidate = (DOCKER / reference).resolve()
                if not candidate.is_file():
                    # ios-grindercore is relative to the repository root because
                    # its build context is the repository, not docker/.
                    candidate = (REPO / reference).resolve()
                self.assertTrue(candidate.is_file(), f"missing {reference}")

    def test_every_service_uses_a_pinned_argument(self) -> None:
        text = (DOCKER / "compose.yaml").read_text(encoding="utf-8")
        pins = env_pins()
        used = set(re.findall(r"\$\{([A-Z0-9_]+)", text))
        self.assertTrue(used, "compose.yaml interpolates no image pins")
        for name in used:
            with self.subTest(pin=name):
                self.assertIn(name, pins)

    def test_heavy_services_are_behind_a_profile(self) -> None:
        text = (DOCKER / "compose.yaml").read_text(encoding="utf-8")
        for service in ("android", "ios-grindercore"):
            block = text.split(f"\n  {service}:", 1)
            self.assertEqual(len(block), 2, f"{service} service missing")
            head = block[1].split("\n\n  ", 1)[0]
            with self.subTest(service=service):
                self.assertIn('profiles: ["heavy"]', head)


class VerifyScriptTests(unittest.TestCase):
    """verify.sh must know exactly the targets the rest of the scaffold names."""

    def test_targets_are_declared_once(self) -> None:
        text = (DOCKER / "verify.sh").read_text(encoding="utf-8")
        enabled = re.search(r"^DEFAULT_TARGETS='([^']+)'$", text, re.MULTILINE)
        heavy = re.search(r"^HEAVY_TARGETS='([^']+)'$", text, re.MULTILINE)
        self.assertIsNotNone(enabled)
        self.assertIsNotNone(heavy)
        assert enabled and heavy
        self.assertEqual(set(enabled.group(1).split()), ENABLED)
        self.assertEqual(set(heavy.group(1).split()), HEAVY)

    def test_every_target_has_an_image_and_a_build_rule(self) -> None:
        text = (DOCKER / "verify.sh").read_text(encoding="utf-8")
        for target in sorted(ENABLED):
            with self.subTest(target=target):
                self.assertIn(f"{target})", text, f"{target} has no case arm")
                self.assertRegex(
                    text,
                    rf"{re.escape(target)}\) printf 'e64-",
                    f"{target} has no image name",
                )

    def test_shell_scripts_parse(self) -> None:
        scripts = [DOCKER / "verify.sh", *(DOCKER.rglob("*.sh"))]
        for script in sorted(set(scripts)):
            with self.subTest(script=script.name):
                completed = subprocess.run(
                    ["sh", "-n", str(script)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)


class DocumentationTests(unittest.TestCase):
    """The document has to name every target and every real path it cites."""

    def test_document_exists(self) -> None:
        self.assertTrue(DOC.is_file(), f"missing {DOC}")

    def test_document_names_every_target(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        for target in sorted(ENABLED | HEAVY):
            with self.subTest(target=target):
                self.assertIn(target, text, f"{DOC.name} does not mention {target}")

    def test_document_names_every_image(self) -> None:
        """Target names appear in prose; image names only in the table.

        Checking the image names is what makes a deleted table row fail: the
        target name would still be found in a link or a skip message.
        """
        text = DOC.read_text(encoding="utf-8")
        verify = (DOCKER / "verify.sh").read_text(encoding="utf-8")
        images = re.findall(r"\)\s*printf\s*'(e64-[^'\\]+)\\n'", verify)
        self.assertGreaterEqual(len(images), 8, images)
        for image in images:
            with self.subTest(image=image):
                self.assertIn(image, text, f"{DOC.name} does not document {image}")

    def test_document_links_to_real_paths(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        links = re.findall(r"\]\(([^)#]+)\)", text)
        self.assertTrue(links, "the document links to nothing")
        for link in links:
            if link.startswith(("http://", "https://", "mailto:")):
                continue
            with self.subTest(link=link):
                # Links are written relative to docs/.
                candidate = (DOC.parent / link).resolve()
                self.assertTrue(candidate.exists(), f"{link} does not resolve from docs/")

    def test_document_states_unverified_targets(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        for word in ("unverified", "Unverified"):
            if word in text:
                return
        self.fail("the document never says what is unverified")


if __name__ == "__main__":
    unittest.main()
