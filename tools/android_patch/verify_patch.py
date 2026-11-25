#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path

from common import (
    ARM64_SPLIT,
    BLOCKED_HOST,
    CLOUD_HOST,
    LIBAPP_PATH,
    LOCAL_LITERALS,
    SPLIT_HASHES,
    PatchError,
    find_build_tool,
    offsets,
    run_checked,
    sha256_bytes,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a locally patched split APK set")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--apksigner", type=Path)
    parser.add_argument("--require-account-gate", action="store_true")
    args = parser.parse_args()
    try:
        report_path = args.output_dir / "patch-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if args.require_account_gate and not report.get("complete_account_bypass"):
            raise PatchError("output is cloud-only diagnostic; account gate was not patched")

        apksigner = args.apksigner or find_build_tool("apksigner")
        signer_digests: set[str] = set()
        for name in SPLIT_HASHES:
            apk = args.output_dir / name
            if not apk.is_file():
                raise PatchError(f"missing output split: {apk}")
            output = run_checked([str(apksigner), "verify", "--print-certs", str(apk)])
            match = re.search(r"certificate SHA-256 digest: ([0-9a-f]+)", output, re.I)
            if not match:
                raise PatchError(f"could not read signer digest for {name}")
            signer_digests.add(match.group(1).lower())
        if len(signer_digests) != 1:
            raise PatchError(f"output splits do not share one signer: {sorted(signer_digests)}")

        with zipfile.ZipFile(args.output_dir / ARM64_SPLIT) as archive:
            libapp = archive.read(LIBAPP_PATH)
        if CLOUD_HOST in libapp:
            raise PatchError("vendor cloud host remains in patched libapp")
        blocked_offsets = offsets(libapp, BLOCKED_HOST)
        if len(blocked_offsets) != 4:
            raise PatchError(f"expected four blocked cloud hosts, observed {len(blocked_offsets)}")
        missing_local = [value.decode() for value in LOCAL_LITERALS if value not in libapp]
        if missing_local:
            raise PatchError(f"local route literals were not preserved: {missing_local}")
        if sha256_bytes(libapp) != report.get("patched_libapp_sha256"):
            raise PatchError("patched libapp hash differs from patch report")

        result = {
            "status": "pass",
            "mode": report.get("mode"),
            "complete_account_bypass": report.get("complete_account_bypass"),
            "signer_sha256": next(iter(signer_digests)),
            "blocked_cloud_offsets": [hex(value) for value in blocked_offsets],
            "preserved_local_literals": [value.decode() for value in LOCAL_LITERALS],
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, KeyError, json.JSONDecodeError, zipfile.BadZipFile, PatchError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
