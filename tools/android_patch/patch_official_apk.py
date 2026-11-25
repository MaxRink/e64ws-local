#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from common import (
    ARM64_SPLIT,
    SPLIT_HASHES,
    PatchError,
    find_build_tool,
    load_gate_patch,
    patch_cloud_hosts,
    read_libapp,
    rewrite_apk,
    run_checked,
    sha256_bytes,
    sha256_file,
    verify_inputs,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Patch, align, and development-sign the pinned owner-supplied APK split set"
    )
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--key-alias", default="androiddebugkey")
    parser.add_argument("--password-env", default="ANDROID_PATCH_KEYSTORE_PASSWORD")
    parser.add_argument("--gate-patch", type=Path)
    parser.add_argument(
        "--allow-cloud-only-diagnostic",
        action="store_true",
        help="build an explicitly incomplete diagnostic; does not bypass the account gate",
    )
    parser.add_argument("--apksigner", type=Path)
    parser.add_argument("--zipalign", type=Path)
    args = parser.parse_args()

    try:
        verify_inputs(args.input_dir)
        if not args.keystore.is_file():
            raise PatchError(f"keystore does not exist: {args.keystore}")
        if not os.environ.get(args.password_env):
            raise PatchError(f"keystore password environment variable is unset: {args.password_env}")
        if not args.gate_patch and not args.allow_cloud_only_diagnostic:
            raise PatchError(
                "BLOCKED: no evidence-supported account-gate patch. Supply --gate-patch, "
                "or use --allow-cloud-only-diagnostic only to validate cloud blocking/signing."
            )

        original = read_libapp(args.input_dir / ARM64_SPLIT)
        patched = original
        gate_patches: list[dict[str, object]] = []
        mode = "cloud-only-diagnostic"
        if args.gate_patch:
            gate_patches, patched = load_gate_patch(args.gate_patch, original)
            mode = "account-gate-and-cloud-patched"
        patched, cloud_offsets = patch_cloud_hosts(patched)

        apksigner = args.apksigner or find_build_tool("apksigner")
        zipalign = args.zipalign or find_build_tool("zipalign")
        args.output_dir.mkdir(parents=True, exist_ok=True)
        signing_env = os.environ.copy()

        output_hashes: dict[str, str] = {}
        with tempfile.TemporaryDirectory(prefix="mahlkoenig-android-patch-") as temp_name:
            temp = Path(temp_name)
            for name in SPLIT_HASHES:
                unsigned = temp / f"unsigned-{name}"
                aligned = temp / f"aligned-{name}"
                destination = args.output_dir / name
                replacement = patched if name == ARM64_SPLIT else None
                rewrite_apk(args.input_dir / name, unsigned, replacement)
                run_checked([str(zipalign), "-P", "16", "-f", "4", str(unsigned), str(aligned)])
                run_checked(
                    [
                        str(apksigner),
                        "sign",
                        "--ks",
                        str(args.keystore),
                        "--ks-key-alias",
                        args.key_alias,
                        "--ks-pass",
                        f"env:{args.password_env}",
                        "--key-pass",
                        f"env:{args.password_env}",
                        "--out",
                        str(destination),
                        str(aligned),
                    ],
                    env=signing_env,
                )
                run_checked([str(apksigner), "verify", "--verbose", str(destination)])
                output_hashes[name] = sha256_file(destination)

        report = {
            "mode": mode,
            "complete_account_bypass": bool(gate_patches),
            "cloud_patch_offsets": [hex(value) for value in cloud_offsets],
            "gate_patches": gate_patches,
            "patched_libapp_sha256": sha256_bytes(patched),
            "output_sha256": output_hashes,
            "warning": (
                "Account gate remains unchanged; this output is diagnostic only."
                if not gate_patches
                else None
            ),
        }
        report_path = args.output_dir / "patch-report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except PatchError as exc:
        print(str(exc), file=os.sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
