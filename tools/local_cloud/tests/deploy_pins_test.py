"""Offline checks that the Compose stack is pinned and stays documented.

Why this file exists
--------------------

``deploy/local-cloud/Dockerfile`` used to say "the tag is floating, pin it by
digest before using this for anything real".  A committed digest that nothing
checks drifts back to a floating tag the first time someone bumps a version, and
a README service table drifts from the Compose file the same way.  Both are
pure text, so both are checked here without Docker, a registry or a network:
the suite that runs this must stay offline.

What is covered
---------------

* every registry image reference in ``docker-compose.yml`` *and* in
  ``docker-compose.templates.yml`` (the ``db`` template lives there, because it
  must not be interpolated by `docker compose config` unless its credential is
  set) carries a tag *and* an ``@sha256:`` digest (the one built-from-source
  service is exempt and must keep declaring ``build:``), and the tag is asserted
  on the part *before* the ``@`` - ``caddy@sha256:...`` has no tag even though it
  contains a colon;
* no reference is on ``latest``, the one tag that cannot be pinned in spirit;
* no two different repositories share a digest, and no single reference carries
  two different digests: that is the copy-paste shape of a "consistent wrong
  digest", which is the one pinning mistake a file can catch offline;
* the ``Verify image pins`` table in ``README.md`` carries the same digest for
  each reference as the Compose file does, so the two cannot drift apart;
* the ``FROM`` in ``Dockerfile`` is pinned by digest too;
* ``README.md``'s service table lists exactly the Compose services of *both*
  files, with the same image strings - no row for a service that is not there,
  no service without a row;
* ``db`` still mounts ``pgdata`` at ``/var/lib/postgresql``, because PostgreSQL
  18 keeps PGDATA in ``/var/lib/postgresql/18/docker`` and mounting ``.../data``
  makes the container exit 1.

This does not prove a digest is the *right* digest for its tag, or still
pullable - only a registry can answer that (``skopeo inspect``, ``crane digest``,
``docker pull <ref>@sha256:...``).  It proves nobody quietly replaced a pin with
a tag, pasted one repository's digest onto another, or edited one document and
not the other.  The README's "Verify image pins" transcripts are the network half
of that check, and they cannot be automated here without giving up the offline
suite.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEPLOY = ROOT / "deploy" / "local-cloud"
COMPOSE = DEPLOY / "docker-compose.yml"
TEMPLATES = DEPLOY / "docker-compose.templates.yml"
# Both files are part of the stack, and both are checked: a digest that is only
# pinned in the file a reader happens to open is not pinned.
COMPOSE_FILES = (COMPOSE, TEMPLATES)
DOCKERFILE = DEPLOY / "Dockerfile"
README = DEPLOY / "README.md"

DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
# service block: two spaces of indent, a bare key, then ':' at end of line
SERVICE = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):\s*$")
IMAGE = re.compile(r"^    image:\s*(.+?)\s*$")
BUILD = re.compile(r"^    build:\s*$")
MOUNT = re.compile(r"^\s+- ([A-Za-z0-9_-]+):(/[^\s:]+)")


def compose_services() -> dict[str, dict[str, object]]:
    """Every service in every Compose file in this directory, by name."""

    services: dict[str, dict[str, object]] = {}
    for path in COMPOSE_FILES:
        for name, service in _services_in(path).items():
            if name in services:
                raise AssertionError(f"{name} is defined in more than one Compose file")
            services[name] = service
    return services


def _services_in(path: Path) -> dict[str, dict[str, object]]:
    """Minimal reader for exactly the Compose keys asserted below.

    A YAML parser would be nicer, but this repository's test suites are
    standard-library-only by design, so this reads the two-space layout the
    file actually uses.  It fails loudly if the layout stops matching, rather
    than silently checking nothing.
    """

    services: dict[str, dict[str, object]] = {}
    current: dict[str, object] | None = None
    in_services = False

    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(" "):
            in_services = line.strip() == "services:"
            current = None
            continue
        if not in_services:
            continue

        match = SERVICE.match(line)
        if match:
            current = {"image": None, "build": False, "mounts": []}
            services[match.group(1)] = current
            continue
        if current is None:
            continue

        match = IMAGE.match(line)
        if match:
            current["image"] = match.group(1).strip("\"'")
            continue
        if BUILD.match(line):
            current["build"] = True
            continue
        match = MOUNT.match(line)
        if match:
            current["mounts"].append((match.group(1), match.group(2)))

    if not services:
        raise AssertionError(f"no services parsed out of {path}")
    return services


def readme_rows() -> dict[str, str]:
    """service name -> the raw second column of its row in the README table.

    Scoped to the one table whose header is ``| Service | Image |``: the README
    also carries a pin table (``| Reference | Tag published | ...``), and an
    unscoped reader would treat its rows as phantom services.
    """

    lines = README.read_text(encoding="utf-8").splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.startswith("| Service ")),
        None,
    )
    if start is None:
        raise AssertionError(f"no '| Service |' table header in {README}")

    rows: dict[str, str] = {}
    for line in lines[start + 1 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        name = cells[0].strip("`").strip()
        if not name or set(name) <= set("-: "):
            continue
        rows[name] = cells[1]
    if not rows:
        raise AssertionError(f"service table in {README} has no rows")
    return rows


def readme_pin_table() -> dict[str, str]:
    """image reference (``repo:tag``) -> the digest cell, from the pin table.

    This table is the human-readable record of what the registry returned, so
    comparing it with the Compose file is what stops the two drifting: editing
    one and not the other fails here rather than at the next `docker compose up`.
    """

    lines = README.read_text(encoding="utf-8").splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.startswith("| Reference ")),
        None,
    )
    if start is None:
        raise AssertionError(f"no '| Reference |' pin table in {README}")

    rows: dict[str, str] = {}
    for line in lines[start + 1 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        reference = cells[0].strip("`").strip()
        if not reference or set(reference) <= set("-: "):
            continue
        rows[reference] = cells[2]
    if not rows:
        raise AssertionError(f"pin table in {README} has no rows")
    return rows


class ComposeImagePinTest(unittest.TestCase):
    def setUp(self) -> None:
        self.services = compose_services()

    def registry_images(self) -> dict[str, str]:
        return {
            name: str(service["image"])
            for name, service in self.services.items()
            if not service["build"]
        }

    def test_registry_images_are_tagged_and_digested(self) -> None:
        images = self.registry_images()
        self.assertTrue(images, "expected at least one pulled image")
        by_digest: dict[str, set[str]] = {}
        by_name: dict[str, set[str]] = {}

        for name, reference in images.items():
            with self.subTest(service=name):
                # Split on '@' first: `caddy@sha256:...` contains a colon but has
                # no tag, and asserting `':' in reference` would pass on it.
                tagged, separator, digest = reference.partition("@")
                repository, _, tag = tagged.partition(":")
                self.assertTrue(separator, f"{name} ({reference}) has no @sha256 digest")
                self.assertTrue(tag, f"{name} ({reference}) has no tag before '@'")
                self.assertNotEqual(
                    "latest", tag, f"{name} ({reference}) is tagged 'latest'"
                )
                self.assertRegex(
                    "#" + digest,
                    r"#sha256:[0-9a-f]{64}$",
                    f"{name} ({reference}) is not pinned: append @sha256:<64 hex>",
                )
                self.assertGreater(
                    len(set(digest.split(":", 1)[1])),
                    1,
                    f"{name} ({reference}) has a placeholder digest",
                )
                by_digest.setdefault(digest, set()).add(repository)
                by_name.setdefault(repository, set()).add(tag + "@" + digest)

        for digest, repositories in by_digest.items():
            with self.subTest(digest=digest[:19]):
                self.assertEqual(
                    1,
                    len(repositories),
                    f"{digest} is used for more than one repository "
                    f"{sorted(repositories)}; one of them is a copy-paste",
                )
        for repository, pins in by_name.items():
            with self.subTest(repository=repository):
                self.assertEqual(
                    1,
                    len(pins),
                    f"{repository} is pinned two ways: {sorted(pins)}",
                )

    def test_no_image_is_on_latest(self) -> None:
        for name, reference in self.registry_images().items():
            with self.subTest(service=name):
                self.assertNotIn(
                    ":latest@",
                    reference,
                    f"{name} pins the tag 'latest', which means nothing to a reader",
                )
                self.assertNotIn(":latest", reference, f"{name} uses :latest")

    def test_built_service_declares_build(self) -> None:
        built = [n for n, s in self.services.items() if s["build"]]
        self.assertEqual(
            ["api"],
            built,
            "exactly the api service is built from this repository",
        )
        self.assertEqual("local-cloud-service:dev", self.services["api"]["image"])

    def test_dockerfile_base_image_is_pinned(self) -> None:
        from_lines = [
            line for line in DOCKERFILE.read_text(encoding="utf-8").splitlines() if line.startswith("FROM ")
        ]
        self.assertTrue(from_lines, "Dockerfile has no FROM line")
        for line in from_lines:
            with self.subTest(line=line):
                self.assertRegex(line, DIGEST, f"{line!r} is not pinned by digest")

    def test_postgres_mounts_the_parent_directory(self) -> None:
        mounts = self.services["db"]["mounts"]
        self.assertIn(
            ("pgdata", "/var/lib/postgresql"),
            mounts,
            "db must mount pgdata at /var/lib/postgresql; the 18 image keeps "
            "PGDATA in /var/lib/postgresql/18/docker and exits 1 when the "
            "volume is mounted on .../data",
        )
        self.assertNotIn(
            ("pgdata", "/var/lib/postgresql/data"),
            mounts,
            "mounting pgdata on .../data is the PostgreSQL 16 layout",
        )


class ReadmeMatchesComposeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.services = compose_services()
        self.rows = readme_rows()

    def test_every_compose_service_has_a_row(self) -> None:
        missing = sorted(set(self.services) - set(self.rows))
        self.assertEqual([], missing, f"README table has no row for: {missing}")

    def test_no_row_for_a_service_that_is_not_there(self) -> None:
        ghosts = sorted(set(self.rows) - set(self.services))
        self.assertEqual([], ghosts, f"README table documents absent services: {ghosts}")

    def test_image_strings_match_exactly(self) -> None:
        for name, service in self.services.items():
            if name not in self.rows:
                continue
            cell = self.rows[name]
            with self.subTest(service=name):
                if service["build"]:
                    self.assertIn(
                        "deploy/local-cloud/Dockerfile",
                        cell,
                        f"{name} is built here; say so in the table",
                    )
                else:
                    self.assertIn(
                        str(service["image"]),
                        cell,
                        f"{name}: README says {cell!r}, compose says "
                        f"{service['image']!r} - keep the digest in both",
                    )

        # Same digests in the human-readable pin table as in the Compose file
        # (and the Dockerfile FROM), so editing one document alone cannot pass.
        pins = readme_pin_table()
        for name, service in self.services.items():
            if service["build"]:
                continue
            reference = str(service["image"])
            tagged, _, digest = reference.partition("@")
            with self.subTest(reference=tagged):
                self.assertIn(
                    tagged,
                    pins,
                    f"{tagged} is in Compose but not in the README pin table",
                )
                self.assertIn(
                    digest,
                    pins[tagged],
                    f"{tagged}: Compose pins {digest}, README table says "
                    f"{pins[tagged]!r}",
                )

        from_lines = [
            line.split("FROM ", 1)[1].strip()
            for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
            if line.startswith("FROM ")
        ]
        for reference in from_lines:
            tagged, _, digest = reference.partition("@")
            with self.subTest(reference=tagged, source="Dockerfile"):
                self.assertIn(
                    tagged,
                    pins,
                    f"Dockerfile base {tagged} is not in the README pin table",
                )
                self.assertIn(
                    digest,
                    pins[tagged],
                    f"Dockerfile base {tagged}: FROM pins {digest}, README table "
                    f"says {pins[tagged]!r}",
                )


if __name__ == "__main__":  # pragma: no cover - run via tools/run_tests.py
    unittest.main()
