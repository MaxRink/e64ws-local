#!/usr/bin/env python3
"""Read-only evidence audit for the locally extracted E64 WS firmware.

The default run reads regular files below .tools/firmware-1.16-24 and prints a
JSON report.  It never opens device nodes, uses the network, modifies firmware,
or writes a report unless --output is explicitly supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FW_ROOT = REPO_ROOT / ".tools" / "firmware-1.16-24"
DEFAULT_SWU = REPO_ROOT / "HEM-HSG-HMI-S01-V01.16-24.swu"

EXPECTED_SWU_SHA256 = (
    "4659b140d2b871ad98f1c0b8d88351708c3dbe20e5c638a4e5339dce89f3b5a2"
)
EXPECTED_DESCRIPTION_SHA256 = (
    "dd1f6c351c21d584f3c3ffb69539534dc46d8ed4e77469d91e5afdc2ee8376d9"
)

REQUIRED_TEXT = {
    "manifest": "raw/sw-description",
    "hsg_update_helper": "raw/tools.start_update.sh",
    "postinstall_helper": "raw/tools.postinstall_startupdate.sh",
    "inittab": "rootfs-tree-full/etc/inittab",
    "verify_update": "rootfs-tree-full/etc/init.d/S30verifyupdate",
    "esp_init": "rootfs-tree-full/etc/init.d/S50esp",
    "sudoers": "rootfs-tree-full/etc/sudoers",
    "web_swu": "www-tree/www/upload_swu.php",
    "web_esp": "www-tree/www/upload_esp.php",
    "login": "www-tree/www/checkLogin.php",
    "esp_zip_wrapper": "app-tree/bin/flashEspZip.sh",
    "efuse_helper": "app-tree/esp/burn_fuses_on_target.sh",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_socket() and not path.is_fifo()
    except OSError:
        return False


def read_text(path: Path) -> str:
    if not regular_file(path):
        raise ValueError(f"refusing non-regular or missing file: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def openssl_verify(public_key: Path, signature: Path, description: Path) -> dict[str, Any]:
    if not all(regular_file(path) for path in (public_key, signature, description)):
        return {"verified": False, "reason": "missing input"}
    try:
        result = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                os.fspath(public_key),
                "-signature",
                os.fspath(signature),
                os.fspath(description),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"verified": False, "reason": type(exc).__name__}
    return {
        "verified": result.returncode == 0,
        "returncode": result.returncode,
        "summary": (result.stdout.strip() or result.stderr.strip()).splitlines()[-1],
    }


def manifest_hashes(fw_root: Path, manifest_text: str) -> dict[str, Any]:
    pairs = sorted(
        set(
            re.findall(
                r'filename\s*=\s*"([^"]+)";\s*sha256\s*=\s*"([0-9a-fA-F]{64})";',
                manifest_text,
                flags=re.MULTILINE,
            )
        )
    )
    checks: list[dict[str, Any]] = []
    for filename, expected in pairs:
        candidate = fw_root / "raw" / filename
        present = regular_file(candidate)
        actual = sha256_file(candidate) if present else None
        checks.append(
            {
                "filename": filename,
                "present": present,
                "expected_sha256": expected.lower(),
                "actual_sha256": actual,
                "matches": present and actual == expected.lower(),
            }
        )
    return {
        "unique_entries": len(checks),
        "all_present_and_matching": bool(checks) and all(item["matches"] for item in checks),
        "checks": checks,
    }


def ascii_tokens(path: Path, tokens: list[str]) -> dict[str, bool]:
    if not regular_file(path):
        return {token: False for token in tokens}
    data = path.read_bytes()
    return {token: token.encode("ascii") in data for token in tokens}


def inspect(args: argparse.Namespace) -> dict[str, Any]:
    fw_root = args.firmware_root.resolve()
    swu = args.swu.resolve()
    if not fw_root.is_dir():
        raise ValueError(f"firmware root is not a directory: {fw_root}")
    if fw_root == Path("/dev") or Path("/dev") in fw_root.parents:
        raise ValueError("device-node paths are not accepted")

    texts: dict[str, str] = {}
    required: dict[str, dict[str, Any]] = {}
    for label, relative in REQUIRED_TEXT.items():
        path = fw_root / relative
        present = regular_file(path)
        required[label] = {"path": relative, "present": present}
        if present:
            texts[label] = read_text(path)

    rootfs = fw_root / "rootfs-tree-full"
    executable_names = {
        path.name
        for prefix in ("bin", "sbin", "usr/bin", "usr/sbin")
        for path in (rootfs / prefix).glob("*")
        if path.is_file() or path.is_symlink()
    }
    ssh_names = sorted(
        executable_names.intersection({"sshd", "dropbear", "dbclient", "scp", "sftp-server"})
    )

    manifest_path = fw_root / "raw/sw-description"
    signature_path = fw_root / "raw/sw-description.sig"
    hsg_key = rootfs / "etc/keys/hem-hsg-swupdate-key.pub"
    ux_key = rootfs / "etc/keys/ux-swupdate-key.pub"
    manifest_text = texts.get("manifest", "")

    swu_info: dict[str, Any] = {"path": os.fspath(swu), "present": regular_file(swu)}
    if regular_file(swu):
        swu_info.update(
            {
                "size": swu.stat().st_size,
                "sha256": sha256_file(swu),
                "matches_expected_sha256": sha256_file(swu) == EXPECTED_SWU_SHA256,
            }
        )

    report: dict[str, Any] = {
        "mode": "read-only-offline",
        "firmware_root": os.fspath(fw_root),
        "required_evidence": required,
        "supplied_swu": swu_info,
        "manifest": {
            "sha256": sha256_file(manifest_path) if regular_file(manifest_path) else None,
            "matches_expected_sha256": regular_file(manifest_path)
            and sha256_file(manifest_path) == EXPECTED_DESCRIPTION_SHA256,
            "payload_hashes": manifest_hashes(fw_root, manifest_text),
        },
        "signature": {
            "hsg_key": openssl_verify(hsg_key, signature_path, manifest_path),
            "ux_key": openssl_verify(ux_key, signature_path, manifest_path),
        },
        "ssh": {
            "server_or_client_executables": ssh_names,
            "authorized_keys_present": regular_file(rootfs / "root/.ssh/authorized_keys"),
            "serial_getty_ttySTM0_115200": "ttySTM0 115200" in texts.get("inittab", ""),
            "inetd_config_present": regular_file(rootfs / "etc/inetd.conf"),
        },
        "static_boundaries": {
            "www_data_nopasswd_all": "www-data ALL=(ALL) NOPASSWD: ALL"
            in texts.get("sudoers", ""),
            "tmp_update_script_mode_777": "chmod 777 /tmp/start_update.sh"
            in texts.get("postinstall_helper", ""),
            "swu_upload_uses_hsg_key": "hem-hsg-swupdate-key.pub"
            in texts.get("web_swu", ""),
            "esp_upload_executes_archive_script": "./do_flash.sh"
            in texts.get("esp_zip_wrapper", ""),
            "esp_upload_checks_archive_script_exit": bool(
                re.search(r'do_flash\.sh[^\n]*\n\s*(?:if|test)\b', texts.get("esp_zip_wrapper", ""))
            ),
            "login_role_interpolated_into_shell_sql": all(
                needle in texts.get("login", "")
                for needle in ("Role.$userRole.LoginData", "exec(", "'$query'")
            ),
            "esp_device_mode_0666": "chmod 666 /dev/esps0" in texts.get("esp_init", ""),
            "efuse_no_confirm": "--do-not-confirm" in texts.get("efuse_helper", ""),
        },
        "uboot_capability_strings": ascii_tokens(
            fw_root / "raw/images.standard.u-boot.img",
            ["bootcount", "bootlimit", "altbootcmd", "resetcause", "Enter fastboot!", "Enter UMS!"],
        ),
        "limitations": [
            "Static presence and string matches do not prove live reachability or code execution.",
            "This report does not read U-Boot environment, watchdog state, eFuse/OTP state, or listeners from hardware.",
            "No secret values, password hashes, private keys, cloud endpoints, or device nodes are inspected.",
        ],
    }
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-root", type=Path, default=DEFAULT_FW_ROOT)
    parser.add_argument("--swu", type=Path, default=DEFAULT_SWU)
    parser.add_argument(
        "--output",
        type=Path,
        help="write JSON to this regular host path; default is stdout only (dry run)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        report = inspect(args)
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output is None:
            sys.stdout.write(encoded)
        else:
            output = args.output.resolve()
            if output.exists() and not regular_file(output):
                raise ValueError(f"refusing non-regular output: {output}")
            output.write_text(encoded, encoding="utf-8")
            print(f"wrote {output}", file=sys.stderr)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
