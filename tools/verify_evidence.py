#!/usr/bin/env python3
"""Verify published evidence manifests against a local, gitignored tree.

The manifests under ``docs/evidence/manifests/`` contain metadata only:
logical name, SHA-256, byte size and a path relative to the extraction root
(``.tools`` by default) or, for vendor packages kept at the repository root,
relative to the repository root.

This verifier is offline by design. It opens only local files, never follows
redirects, downloads nothing, and does not inspect artifact contents. It
reports one of three statuses per artifact:

``match``     the file exists and its SHA-256 (and recorded size, when known)
              equals the manifest value;
``mismatch``  the file exists but the hash or size differs;
``missing``   the file is absent.

A missing artifact does not fail the run: the manifests intentionally describe
optional local evidence, and a fresh clone has no ``.tools/`` tree. Use
``--strict`` when every artifact must be present. A mismatch always fails.

Exit status:

    0  all present artifacts and all count checks are consistent
    1  a hash/size mismatch or count check failed, or --strict found a missing
    2  the manifest directory or a manifest is unusable
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_DIR = REPO_ROOT / "docs" / "evidence" / "manifests"
DEFAULT_ROOT = REPO_ROOT / ".tools"

SCHEMA_VERSION = 1
CHUNK = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
LOCATIONS = ("extraction", "repo")


class ManifestError(Exception):
    """A manifest is missing, malformed or internally inconsistent."""


@dataclass(frozen=True)
class Row:
    manifest: str
    logical_name: str
    expected_digest: str
    observed_digest: str | None
    expected_size: int | None
    observed_size: int | None
    status: str
    path: Path


@dataclass(frozen=True)
class CountResult:
    label: str
    expected: int
    observed: int | None
    ok: bool


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of *path* without loading it whole."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def count_lines(path: Path) -> int:
    """Count newline-terminated lines, including a final unterminated line."""
    lines = 0
    tail = b""
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            lines += chunk.count(b"\n")
            tail = chunk
    if tail and not tail.endswith(b"\n"):
        lines += 1
    return lines


def load_manifests(directory: Path) -> list[tuple[Path, dict]]:
    if not directory.is_dir():
        raise ManifestError(f"manifest directory does not exist: {directory}")
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise ManifestError(f"no JSON manifests found in {directory}")
    manifests = []
    for path in paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ManifestError(f"{path.name}: cannot read JSON: {error}") from error
        validate_manifest(path.name, document)
        manifests.append((path, document))
    return manifests


def validate_manifest(name: str, document: object) -> None:
    if not isinstance(document, dict):
        raise ManifestError(f"{name}: top-level value must be an object")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError(
            f"{name}: schema_version must be {SCHEMA_VERSION}, "
            f"got {document.get('schema_version')!r}"
        )
    if not isinstance(document.get("artifact_class"), str) or not document["artifact_class"]:
        raise ManifestError(f"{name}: artifact_class must be a non-empty string")
    entries = document.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ManifestError(f"{name}: entries must be a non-empty list")

    seen: set[str] = set()
    for index, entry in enumerate(entries):
        where = f"{name}: entries[{index}]"
        if not isinstance(entry, dict):
            raise ManifestError(f"{where}: entry must be an object")
        logical_name = entry.get("logical_name")
        if not isinstance(logical_name, str) or not logical_name:
            raise ManifestError(f"{where}: logical_name must be a non-empty string")
        if logical_name in seen:
            raise ManifestError(f"{where}: duplicate logical_name {logical_name!r}")
        seen.add(logical_name)
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ManifestError(f"{where}: sha256 must be 64 lowercase hex characters")
        size = entry.get("size")
        if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
            raise ManifestError(f"{where}: size must be a non-negative integer or null")
        local_path = entry.get("local_path")
        if not isinstance(local_path, str) or not local_path:
            raise ManifestError(f"{where}: local_path must be a non-empty string")
        relative = PurePosixPath(local_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ManifestError(f"{where}: local_path must stay inside its root: {local_path!r}")
        location = entry.get("location", "extraction")
        if location not in LOCATIONS:
            raise ManifestError(f"{where}: location must be one of {LOCATIONS}, got {location!r}")
        for field_name in ("expected_rows", "expected_functions", "expected_failed_bodies"):
            value = entry.get(field_name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ManifestError(f"{where}: {field_name} must be a non-negative integer or null")

    checks = document.get("count_checks", [])
    if not isinstance(checks, list):
        raise ManifestError(f"{name}: count_checks must be a list")
    for index, check in enumerate(checks):
        where = f"{name}: count_checks[{index}]"
        if not isinstance(check, dict):
            raise ManifestError(f"{where}: check must be an object")
        if not isinstance(check.get("label"), str) or not check["label"]:
            raise ManifestError(f"{where}: label must be a non-empty string")
        expected = check.get("expected")
        if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
            raise ManifestError(f"{where}: expected must be a non-negative integer")
        if not isinstance(check.get("filter", {}), dict):
            raise ManifestError(f"{where}: filter must be an object")
        if "sum_field" in check and not isinstance(check["sum_field"], str):
            raise ManifestError(f"{where}: sum_field must be a string")

    unverifiable = document.get("unverifiable", [])
    if not isinstance(unverifiable, list):
        raise ManifestError(f"{name}: unverifiable must be a list")
    for index, item in enumerate(unverifiable):
        where = f"{name}: unverifiable[{index}]"
        if not isinstance(item, dict):
            raise ManifestError(f"{where}: item must be an object")
        if not isinstance(item.get("logical_name"), str) or not item["logical_name"]:
            raise ManifestError(f"{where}: logical_name must be a non-empty string")
        if not isinstance(item.get("reason"), str) or not item["reason"]:
            raise ManifestError(f"{where}: reason must be a non-empty string")
        count = item.get("expected_file_count")
        if count is not None and (
            not isinstance(count, int) or isinstance(count, bool) or count < 0
        ):
            raise ManifestError(f"{where}: expected_file_count must be a non-negative integer")


def resolve_entry(entry: dict, extraction_root: Path, repo_root: Path) -> Path:
    relative = PurePosixPath(entry["local_path"])
    base = repo_root if entry.get("location", "extraction") == "repo" else extraction_root
    return base.joinpath(*relative.parts)


def verify_entry(manifest_name: str, entry: dict, extraction_root: Path, repo_root: Path) -> Row:
    path = resolve_entry(entry, extraction_root, repo_root)
    expected_digest = entry["sha256"]
    expected_size = entry.get("size")
    if not path.is_file():
        return Row(
            manifest=manifest_name,
            logical_name=entry["logical_name"],
            expected_digest=expected_digest,
            observed_digest=None,
            expected_size=expected_size,
            observed_size=None,
            status="missing",
            path=path,
        )
    observed_digest = sha256_file(path)
    observed_size = path.stat().st_size
    size_ok = expected_size is None or observed_size == expected_size
    status = "match" if observed_digest == expected_digest and size_ok else "mismatch"
    return Row(
        manifest=manifest_name,
        logical_name=entry["logical_name"],
        expected_digest=expected_digest,
        observed_digest=observed_digest,
        expected_size=expected_size,
        observed_size=observed_size,
        status=status,
        path=path,
    )


def check_counts(document: dict) -> list[CountResult]:
    """Evaluate the manifest's declared entry/sum count checks."""
    entries = document["entries"]
    results: list[CountResult] = []
    for check in document.get("count_checks", []):
        selector = check.get("filter", {})
        selected = [
            entry
            for entry in entries
            if all(entry.get(key) == value for key, value in selector.items())
        ]
        if "sum_field" in check:
            field = check["sum_field"]
            observed = sum(
                entry[field]
                for entry in selected
                if isinstance(entry.get(field), int) and not isinstance(entry.get(field), bool)
            )
        else:
            observed = len(selected)
        results.append(
            CountResult(
                label=check["label"],
                expected=check["expected"],
                observed=observed,
                ok=observed == check["expected"],
            )
        )
    return results


def check_row_counts(document: dict, rows: list[Row]) -> list[CountResult]:
    expected_rows = {
        entry["logical_name"]: entry["expected_rows"]
        for entry in document["entries"]
        if entry.get("expected_rows") is not None
    }
    results = []
    for row in rows:
        expected = expected_rows.get(row.logical_name)
        if expected is None or row.status == "missing":
            continue
        observed = count_lines(row.path)
        results.append(
            CountResult(
                label=f"rows {row.logical_name}",
                expected=expected,
                observed=observed,
                ok=observed == expected,
            )
        )
    return results


def print_table(rows: list[Row], short: bool) -> None:
    digest_width = 16 if short else 64
    print(
        f"{'artifact':<58} "
        f"{'expected hash':<{digest_width}} "
        f"{'observed hash':<{digest_width}} status"
    )
    print(f"{'-' * 58} {'-' * digest_width} {'-' * digest_width} ------")
    for row in rows:
        expected = row.expected_digest[:digest_width] if short else row.expected_digest
        observed = row.observed_digest or "-"
        if short and row.observed_digest:
            observed = observed[:digest_width]
        print(
            f"{row.logical_name:<58} {expected:<{digest_width}} "
            f"{observed:<{digest_width}} {row.status}"
        )


def print_counts(results: list[CountResult]) -> None:
    if not results:
        return
    print("count checks:")
    for result in results:
        observed = "n/a (missing)" if result.observed is None else str(result.observed)
        verdict = "ok" if result.ok else "FAIL"
        print(f"  {verdict:<4} {result.label}: expected {result.expected}, observed {observed}")


def print_unverifiable(name: str, document: dict) -> None:
    items = document.get("unverifiable", [])
    if not items:
        return
    print("unverifiable (not hash-addressed; excluded from status):")
    for item in items:
        label = item.get("logical_name", "<unnamed>")
        reason = item.get("reason", "no reason recorded")
        count = item.get("expected_file_count")
        suffix = f" [expected files: {count}]" if isinstance(count, int) else ""
        print(f"  {name}: {label}{suffix} - {reason}")


def run(
    manifest_dir: Path,
    extraction_root: Path,
    repo_root: Path,
    strict: bool,
    short: bool,
    quiet: bool,
) -> int:
    try:
        manifests = load_manifests(manifest_dir)
    except ManifestError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print("Evidence manifests")
    print(f"  manifests:        {manifest_dir}")
    print(f"  extraction root:  {extraction_root}")
    print(f"  repository root:  {repo_root}")

    totals = {"match": 0, "mismatch": 0, "missing": 0}
    failed_counts = 0
    for path, document in manifests:
        title = document.get("title")
        try:
            rows = [
                verify_entry(path.name, entry, extraction_root, repo_root)
                for entry in document["entries"]
            ]
        except (OSError, ValueError) as error:
            print(f"error: {path.name}: {error}", file=sys.stderr)
            return 2
        for row in rows:
            totals[row.status] += 1
        counts = check_counts(document)
        counts += check_row_counts(document, rows)
        failed_counts += sum(1 for result in counts if not result.ok)

        if quiet:
            manifest_totals = {status: 0 for status in totals}
            for row in rows:
                manifest_totals[row.status] += 1
            print(
                f"{path.name}: {manifest_totals['match']} match, "
                f"{manifest_totals['mismatch']} mismatch, "
                f"{manifest_totals['missing']} missing"
            )
            for result in counts:
                if not result.ok:
                    print(
                        f"  FAIL {result.label}: expected {result.expected}, "
                        f"observed {result.observed}"
                    )
            continue

        print()
        print(f"== {path.name} ({document['artifact_class']}) ==")
        if title:
            print(title)
        print_table(rows, short=short)
        print_counts(counts)
        print_unverifiable(path.name, document)

    total = sum(totals.values())
    print()
    print(
        f"summary: {totals['match']} match, {totals['mismatch']} mismatch, "
        f"{totals['missing']} missing (of {total} artifacts)"
    )
    failed = totals["mismatch"] + failed_counts
    if strict:
        failed += totals["missing"]
    if failed:
        reasons = []
        if totals["mismatch"]:
            reasons.append(f"{totals['mismatch']} hash/size mismatch")
        if failed_counts:
            reasons.append(f"{failed_counts} count check failure")
        if strict and totals["missing"]:
            reasons.append(f"{totals['missing']} missing artifact (--strict)")
        print(f"result: FAIL - {', '.join(reasons)}")
        return 1
    if totals["missing"]:
        print("result: PASS - every present artifact matches; missing artifacts are allowed")
    else:
        print("result: PASS - every artifact matches")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline verification of the redacted evidence manifests.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=DEFAULT_ROOT,
        help=f"extraction root for path-relative entries (default: {DEFAULT_ROOT})",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="repository root for entries with location=repo (default: script's repository)",
    )
    parser.add_argument(
        "--manifests",
        type=Path,
        default=MANIFEST_DIR,
        help=f"manifest directory (default: {MANIFEST_DIR})",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail when an artifact is missing instead of only reporting it",
    )
    parser.add_argument(
        "--short",
        action="store_true",
        help="abbreviate hashes to 16 characters in the table",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print per-manifest totals and failures only, not the full table",
    )
    args = parser.parse_args(argv)
    return run(
        manifest_dir=args.manifests.expanduser().resolve(),
        extraction_root=args.root.expanduser().resolve(),
        repo_root=args.repo_root.expanduser().resolve(),
        strict=args.strict,
        short=args.short,
        quiet=args.quiet,
    )


if __name__ == "__main__":
    raise SystemExit(main())
