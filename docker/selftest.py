#!/usr/bin/env python3
"""Static checks for the container build targets under ``docker/``.

Why this exists: a digest pin that quietly loses its hash, a compose service
pointing at a deleted Dockerfile, a target that ``verify.sh`` forgets, or a
table row that ``docs/REPRODUCIBLE_BUILDS.md`` stops mentioning are all
failures that a green ``docker build`` would not catch - and that neither a
human nor a build log notices.  These checks read files only, never call
docker, and take a few seconds (two of them shell out to verify.sh), so they can
gate a change that touches docker/ without a network round trip.

This suite is intentionally not registered in ``tools/run_tests.py``: the
runner only accepts suites listed there, and it treats an unregistered
``test_*.py`` as a failure.  ``docker/verify.sh --selftest`` runs it instead.
The file is therefore named ``selftest.py`` and not ``test_*.py``.

Run:
    python3 docker/selftest.py -v
    sh docker/verify.sh --selftest
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import tempfile
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

    def run_verify(
        self, *arguments: str, docker_stub: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Run verify.sh with a stub `docker` on PATH so nothing is built."""
        environ = dict(os.environ)
        if docker_stub is not None:
            environ["PATH"] = f"{docker_stub.parent}{os.pathsep}{environ['PATH']}"
        return subprocess.run(
            ["sh", str(DOCKER / "verify.sh"), *arguments],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(REPO),
            env=environ,
        )

    def test_skipping_every_target_is_not_a_pass(self) -> None:
        """`--only android` builds nothing, so a 0 exit would be a fake pass.

        The review of this scaffold found exactly that: `--only android` exited 0
        with "passed 0, failed 0, skipped 1".  A skip line is not evidence about
        an image, so the run has to refuse unless --allow-skip says otherwise.
        """
        with tempfile.TemporaryDirectory(prefix="verify-stub-") as scratch:
            stub = Path(scratch) / "docker"
            stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            stub.chmod(0o755)
            refused = self.run_verify("--only", "android", docker_stub=stub)
            allowed = self.run_verify("--only", "android", "--allow-skip", docker_stub=stub)
        combined = refused.stdout + refused.stderr
        self.assertNotEqual(refused.returncode, 0, combined)
        self.assertIn("passed 0, failed 0, skipped 1", combined)
        self.assertIn("--allow-skip", refused.stderr)
        self.assertIn("SKIP android", refused.stdout)
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
        self.assertIn("SKIP android", allowed.stdout)

    def test_every_declared_only_target_prints_a_skip_line(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verify-stub-") as scratch:
            stub = Path(scratch) / "docker"
            stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            stub.chmod(0o755)
            for target in sorted(HEAVY):
                with self.subTest(target=target):
                    completed = self.run_verify(
                        "--only", target, "--allow-skip", docker_stub=stub
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn(f"SKIP {target}", completed.stdout)

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


class SuiteOrderTests(unittest.TestCase):
    """The tolerated hang is only tolerable if it is still the last suite.

    tools/run_tests.py prints a suite header after the suite finishes, so a
    bounded run reports every suite except the one that hung.  verify.sh relies
    on that (it compares the number of headers with the runner's own order) and
    on KNOWN_HANG naming the last suite, so the two files have to agree.
    """

    RUNNER = REPO / "tools" / "run_tests.py"

    def test_known_hang_is_the_last_suite(self) -> None:
        text = self.RUNNER.read_text(encoding="utf-8")
        block = text.split("SUITES: tuple[", 1)
        self.assertEqual(len(block), 2, "SUITES not found in tools/run_tests.py")
        suites = re.findall(
            r"(?:Unittest|Function|Command)Suite\(\s*\n\s*\"([^\"]+)\"", block[1]
        )
        self.assertGreaterEqual(len(suites), 5, suites)
        verify = (DOCKER / "verify.sh").read_text(encoding="utf-8")
        known = re.search(r"^KNOWN_HANG='([^']+)'$", verify, re.MULTILINE)
        self.assertIsNotNone(known, "verify.sh declares no KNOWN_HANG")
        assert known is not None
        self.assertEqual(known.group(1), suites[-1], suites)
        self.assertIn("bounded_run_is_the_known_hang", verify)
        self.assertIn("run_tests.SUITES", verify, "verify.sh hard-codes the suite order")


class GradleWrapperTests(unittest.TestCase):
    """The Android image runs ./gradlew, so the wrapper must pin its download.

    `distributionSha256Sum` is what makes the Gradle distribution a pin rather
    than a URL: without it the wrapper trusts whatever services.gradle.org
    serves.  The checksum below was read from
    https://services.gradle.org/distributions/gradle-9.9.2-bin.zip.sha256.
    """

    PROPERTIES = REPO / "apps" / "android" / "gradle" / "wrapper" / "gradle-wrapper.properties"
    SHA256 = re.compile(r"^[0-9a-f]{64}$")

    def test_distribution_is_pinned_by_checksum(self) -> None:
        text = self.PROPERTIES.read_text(encoding="utf-8")
        values = {
            line.split("=", 1)[0]: line.split("=", 1)[1]
            for line in text.splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        }
        with self.subTest(key="distributionSha256Sum"):
            self.assertIn("distributionSha256Sum", values, text)
            self.assertRegex(values["distributionSha256Sum"], self.SHA256)
        with self.subTest(key="distributionUrl"):
            url = values["distributionUrl"].replace("\\", "")
            self.assertRegex(url, r"/gradle-[0-9]+(\.[0-9]+)+-bin\.zip$")
            # The checksum is for the distribution the URL names; a bump that
            # changes one and not the other is the failure this catches.
            version = re.search(r"/gradle-([0-9.]+)-bin\.zip$", url)
            assert version is not None
            self.assertIn(
                f"Gradle {version.group(1)}",
                DOC.read_text(encoding="utf-8"),
                f"docs/REPRODUCIBLE_BUILDS.md does not name Gradle {version.group(1)}",
            )


class DockerignoreTests(unittest.TestCase):
    """The repository-root contexts must not ship the research tree.

    docker/ios-grindercore/Dockerfile and `docker compose --profile heavy` build
    with the repository root as context, so without a .dockerignore every build
    sends firmware/ (507 MB of .swu here), decaid/, captures/, the Xcode .build/
    trees, the Gradle app build and any local .env to the daemon.
    """

    IGNORE = REPO / ".dockerignore"
    REQUIRED = (
        "firmware/",
        ".tools/",
        "decaid/",
        "captures/",
        # Both are needed: `apps/*/build/` matches apps/android/build, and only
        # `apps/*/*/build/` matches apps/android/app/build, which is the exact
        # path §1 names as the Android artifact.
        "apps/*/build/",
        "apps/*/*/build/",
        # `**/` compiles to `(.*/)?`, so these cover the context root too and a
        # bare `.env` line would be redundant rather than load-bearing.
        "**/.env",
        "**/.env.*",
    )
    # Copied by docker/ios-grindercore/Dockerfile and therefore never excluded.
    COPIED = (
        "apps/ios/GrinderCore/Package.swift",
        "apps/ios/GrinderCore/Sources/GrinderCore/HTTP/SHA256.swift",
        "apps/ios/GrinderCore/Tests/GrinderCoreTests/GeneratedCases.swift",
    )
    # Paths that must be excluded, with the reason they are here.  These are what
    # make the patterns load-bearing: a pattern list can be present and still
    # miss the path that matters (`apps/*/build/` did).
    EXCLUDED = (
        ("firmware/HEM-HSG-HMI-S01-V01.16-24.swu", "vendor payload"),
        (".tools/jdk/bin/java", "locally extracted toolchain"),
        ("decaid/test/plugins/settings_skin_updates_test.cjs", "separate checkout"),
        ("captures/2026-11-19/session.har", "capture output"),
        ("apps/android/build/tmp/compile.txt", "Gradle module output"),
        (
            "apps/android/app/build/outputs/apk/debug/app-debug.apk",
            "Gradle app output - the artifact §1 names",
        ),
        ("apps/ios/GrinderCore/.build/arm64/Release/Objects/x.o", "SwiftPM output"),
        (".env", "local credentials"),
        ("deploy/local-cloud/.env", "local credentials, the documented cp target"),
    )

    def patterns(self) -> list[str]:
        text = self.IGNORE.read_text(encoding="utf-8")
        return [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    @staticmethod
    def pattern_regex(pattern: str) -> str:
        """A .dockerignore pattern as a regex, segment by segment.

        Docker matches `*` within one path segment and `**` across segments, which
        is the whole point of this test: the previous helper used fnmatch, whose
        `*` crosses `/`, so it reported `apps/*/build` as covering
        `apps/android/app/build/...` when Docker's matcher did not.
        """
        out = []
        index = 0
        while index < len(pattern):
            character = pattern[index]
            if character == "*":
                if pattern[index : index + 2] == "**":
                    out.append(".*")
                    index += 2
                    # `**/` also matches zero directories in Docker.
                    if pattern[index : index + 1] == "/":
                        out.append("")
                        index += 1
                    continue
                out.append("[^/]*")
            elif character == "?":
                out.append("[^/]")
            else:
                out.append(re.escape(character))
            index += 1
        return "".join(out)

    @classmethod
    def matches(cls, pattern: str, path: str) -> bool:
        """True when the pattern excludes the path, directly or as a directory."""
        candidate = pattern.rstrip("/")
        if not candidate:
            return False
        regex = cls.pattern_regex(candidate)
        if re.fullmatch(regex, path):
            return True
        return re.fullmatch(regex + "/.*", path) is not None

    def test_context_exclusions_are_present(self) -> None:
        self.assertTrue(self.IGNORE.is_file(), "missing .dockerignore at the repository root")
        patterns = self.patterns()
        for required in self.REQUIRED:
            with self.subTest(pattern=required):
                self.assertIn(required, patterns)
        # A positive control: the patterns must actually match a real payload, or
        # every assertion above would pass on a file that excludes nothing.
        self.assertTrue(self.matches("firmware/", "firmware/HEM-HSG-HMI-S01-V01.16-24.swu"))

    def test_context_exclusions_match_the_paths_that_matter(self) -> None:
        patterns = self.patterns()
        for path, reason in self.EXCLUDED:
            with self.subTest(path=path):
                covering = [pattern for pattern in patterns if self.matches(pattern, path)]
                self.assertNotEqual(covering, [], f"no pattern excludes {path} ({reason})")

    def test_exclusions_do_not_hide_what_the_ios_image_copies(self) -> None:
        patterns = self.patterns()
        for path in self.COPIED:
            with self.subTest(path=path):
                covering = [pattern for pattern in patterns if self.matches(pattern, path)]
                self.assertEqual(covering, [], f"{covering} excludes {path}")
                self.assertTrue((REPO / path).is_file(), f"{path} does not exist")


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
        """Target names appear in prose; image names belong in the table.

        Checking the image names is what makes a deleted table row fail: the
        target name would still be found in a link or a skip message.  The image
        has to sit in a table row, because naming it in prose (as the negative
        control table in section 4 does) would keep the check green after the row
        it is meant to protect was deleted.
        """
        text = DOC.read_text(encoding="utf-8")
        # Scope the search to §1.  The image names also appear in the run-user
        # table of §2.4, so a whole-file search would keep passing after the
        # target row it is meant to protect was deleted.
        section = text.split("## 1.", 1)
        self.assertEqual(len(section), 2, "§1 heading not found")
        target_table = section[1].split("\n## ", 1)[0]
        verify = (DOCKER / "verify.sh").read_text(encoding="utf-8")
        images = re.findall(r"\)\s*printf\s*'(e64-[^'\\]+)\\n'", verify)
        self.assertGreaterEqual(len(images), 8, images)
        for image in images:
            with self.subTest(image=image):
                # assertRegex cannot take flags, and the row assertion has to be
                # line-anchored, so search explicitly.
                row = re.search(rf"^\|.*`{re.escape(image)}`", target_table, re.MULTILINE)
                self.assertTrue(row, f"§1 of {DOC.name} has no table row for {image}")

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
