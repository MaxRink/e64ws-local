#!/usr/bin/env python3
"""Verify the firmware/ artifacts are tracked by Git LFS and match manifest.json.

This script checks:

1. Every *.swu file in firmware/ is listed in firmware/manifest.json.
2. The Git blob for each tracked *.swu is an LFS pointer (not a raw binary).
3. The LFS pointer's OID (SHA-256) matches the manifest.
4. If the working-tree file is a real file (smudged LFS content), its actual
   size and SHA-256 match the manifest.
5. firmware/SHA256SUMS is consistent with manifest.json.

Exit status: 0 if all checks pass, non-zero otherwise.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "firmware"
MANIFEST_PATH = FIRMWARE_DIR / "manifest.json"
SUMS_PATH = FIRMWARE_DIR / "SHA256SUMS"


def run(cmd: List[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
        check=check,
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_blob_content(relpath: str, ref: str = ":") -> str:
    """Return the text content of a git blob at the given ref.

    ref=":" uses the index (staged) version; ref="HEAD:<path>" uses HEAD.
    """
    spec = f"{ref}:{relpath}" if ref != ":" else f":{relpath}"
    result = run(["git", "cat-file", "-p", spec], check=False)
    if result.returncode != 0:
        return ""
    return result.stdout


def parse_lfs_pointer(text: str) -> Dict[str, str] | None:
    """Parse a Git LFS pointer and return its fields, or None if not a pointer."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith("version https://git-lfs.github.com/spec/"):
        return None
    fields: Dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        key, _, value = line.partition(" ")
        fields[key] = value
    return fields


def main() -> int:
    errors: List[str] = []

    if not MANIFEST_PATH.exists():
        print("ERROR: manifest.json not found", file=sys.stderr)
        return 1

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest_files = {entry["filename"]: entry for entry in manifest.get("files", [])}

    swu_files = sorted(p.name for p in FIRMWARE_DIR.glob("*.swu"))

    if not swu_files:
        print("ERROR: no *.swu files found in firmware/", file=sys.stderr)
        return 1

    # 1. Set equality between disk and manifest
    manifest_names = set(manifest_files)
    disk_names = set(swu_files)
    for name in disk_names - manifest_names:
        errors.append(f"firmware/{name} exists on disk but is missing from manifest.json")
    for name in manifest_names - disk_names:
        errors.append(f"firmware/{name} is in manifest.json but missing from disk")

    for name in swu_files:
        if name not in manifest_files:
            continue
        entry = manifest_files[name]
        relpath = f"firmware/{name}"
        disk_path = FIRMWARE_DIR / name

        # 2. Git blob must be an LFS pointer
        blob_text = git_blob_content(relpath, ref=":")
        if not blob_text:
            errors.append(f"firmware/{name}: not found in git index")
            continue
        pointer = parse_lfs_pointer(blob_text)
        if pointer is None:
            errors.append(
                f"firmware/{name}: git blob is not an LFS pointer "
                f"(first line: {blob_text.splitlines()[0]!r})"
            )
            continue

        # 3. LFS pointer OID must match manifest
        lfs_oid = pointer.get("oid", "")
        if lfs_oid.startswith("sha256:"):
            lfs_oid = lfs_oid[len("sha256:") :]
        expected_oid = entry.get("sha256", "")
        if lfs_oid.lower() != expected_oid.lower():
            errors.append(
                f"firmware/{name}: LFS pointer OID {lfs_oid} does not match "
                f"manifest {expected_oid}"
            )

        # 4. If the working-tree file is smudged (real binary), verify it
        if disk_path.is_file() and disk_path.stat().st_size > 0:
            actual_size = disk_path.stat().st_size
            if actual_size != entry.get("size"):
                errors.append(
                    f"firmware/{name}: working-tree size {actual_size} does not match "
                    f"manifest {entry.get('size')}"
                )
            actual_hash = sha256_file(disk_path)
            if actual_hash.lower() != expected_oid.lower():
                errors.append(
                    f"firmware/{name}: working-tree SHA-256 {actual_hash} does not match "
                    f"manifest {expected_oid}"
                )

    # 5. SHA256SUMS consistency
    if SUMS_PATH.exists():
        sums_entries: Dict[str, str] = {}
        for line in SUMS_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("  ", 1)
            if len(parts) != 2:
                errors.append(f"SHA256SUMS: malformed line: {line!r}")
                continue
            hsh, fname = parts
            sums_entries[fname] = hsh

        for name, entry in manifest_files.items():
            if name not in sums_entries:
                errors.append(f"SHA256SUMS: missing entry for {name}")
                continue
            if sums_entries[name].lower() != entry["sha256"].lower():
                errors.append(
                    f"SHA256SUMS: hash for {name} ({sums_entries[name]}) does not match "
                    f"manifest ({entry['sha256']})"
                )
        for name in sums_entries:
            if name not in manifest_files:
                errors.append(f"SHA256SUMS: {name} is not in manifest.json")
    else:
        errors.append("SHA256SUMS not found")

    if errors:
        print("firmware check FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"firmware check OK: {len(swu_files)} SWU files tracked by LFS, hashes match manifest.json and SHA256SUMS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
