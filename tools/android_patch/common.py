from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Iterable


SPLIT_HASHES = {
    "base.apk": "868f9dda9346d7c595dcf9c4dcbf0d7f13a209e15fa913497cc8e61d69223ad4",
    "split_config.arm64_v8a.apk": "40d1456a419434d42976dc7dc477b62971bba053a9c5bcfdab94837ebd890782",
    "split_config.de.apk": "f5ec8d0806bfe21d03ac7f978d55697c6c9ee4ab4ae73befe5b791f6e991610c",
    "split_config.en.apk": "222bc585981d975a5b1afddd69e9149ca9b1c3881d86dbca565d90619e9f692e",
    "split_config.xxhdpi.apk": "be719bc2aa67be32e2990d4fb9621ac01c5ef38fa6dfedd7efa02e50a6da1f5a",
}
ARM64_SPLIT = "split_config.arm64_v8a.apk"
LIBAPP_PATH = "lib/arm64-v8a/libapp.so"
LIBAPP_SHA256 = "66f08f1b88c9431b665166b7eb14808ef68ebc9131fd1c655cd4a48e836a0c8c"

CLOUD_HOST = b"sync.mahlkoenig.com"
BLOCKED_HOST = b"cloud-block.invalid"
CLOUD_HOST_OFFSETS = (0x6C1B2, 0x6FEDD, 0xC7465, 0x103B42)

LOCAL_LITERALS = (
    b"http://172.16.0.1/",
    b"http://192.168.4.1/",
    b"https://192.168.4.1/",
    b"/rest_api/login",
    b"/rest_api/request_onboarding",
    b"/rest_api/scan_wifi",
    b"/api/v2/network/connect",
    b"/api/v2/network/list",
    b"/api/v2/network/forcescan",
    b"/api/v2/network",
)

AUTH_LITERALS = (
    b"AuthState.notLoggedIn",
    b"AuthState.loggedIn",
)


class PatchError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def offsets(data: bytes, needle: bytes) -> list[int]:
    found: list[int] = []
    start = 0
    while True:
        position = data.find(needle, start)
        if position < 0:
            return found
        found.append(position)
        start = position + 1


def verify_inputs(input_dir: Path) -> dict[str, str]:
    observed: dict[str, str] = {}
    for name, expected in SPLIT_HASHES.items():
        path = input_dir / name
        if not path.is_file():
            raise PatchError(f"missing pinned input split: {path}")
        actual = sha256_file(path)
        observed[name] = actual
        if actual != expected:
            raise PatchError(
                f"input hash mismatch for {name}: expected {expected}, observed {actual}"
            )
    return observed


def read_libapp(apk_path: Path) -> bytes:
    with zipfile.ZipFile(apk_path) as archive:
        try:
            data = archive.read(LIBAPP_PATH)
        except KeyError as exc:
            raise PatchError(f"{apk_path} has no {LIBAPP_PATH}") from exc
    actual = sha256_bytes(data)
    if actual != LIBAPP_SHA256:
        raise PatchError(
            f"libapp hash mismatch: expected {LIBAPP_SHA256}, observed {actual}"
        )
    return data


def patch_cloud_hosts(libapp: bytes) -> tuple[bytes, list[int]]:
    if len(CLOUD_HOST) != len(BLOCKED_HOST):
        raise AssertionError("cloud-host patch must preserve the Dart string length")
    found = offsets(libapp, CLOUD_HOST)
    if tuple(found) != CLOUD_HOST_OFFSETS:
        raise PatchError(
            "cloud-host offsets differ from the pinned build: "
            f"expected {[hex(x) for x in CLOUD_HOST_OFFSETS]}, "
            f"observed {[hex(x) for x in found]}"
        )
    patched = libapp.replace(CLOUD_HOST, BLOCKED_HOST)
    if CLOUD_HOST in patched or offsets(patched, BLOCKED_HOST) != found:
        raise PatchError("cloud-host replacement postcondition failed")
    return patched, found


def load_gate_patch(path: Path, original: bytes) -> tuple[list[dict[str, Any]], bytes]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchError(f"cannot read gate patch {path}: {exc}") from exc

    if document.get("input_libapp_sha256") != LIBAPP_SHA256:
        raise PatchError("gate patch is not pinned to the analyzed libapp SHA-256")
    if document.get("status") != "evidence_supported":
        raise PatchError("gate patch status must be exactly 'evidence_supported'")
    patches = document.get("patches")
    if not isinstance(patches, list) or not patches:
        raise PatchError("gate patch contains no patches")
    if not any(item.get("purpose") == "account_gate" for item in patches if isinstance(item, dict)):
        raise PatchError("gate patch has no account_gate patch")

    result = bytearray(original)
    normalized: list[dict[str, Any]] = []
    occupied: list[range] = []
    for index, item in enumerate(patches):
        if not isinstance(item, dict):
            raise PatchError(f"gate patch item {index} is not an object")
        if item.get("confidence") != "high" or not str(item.get("evidence", "")).strip():
            raise PatchError(f"gate patch item {index} lacks high-confidence evidence")
        raw_offset = item.get("offset")
        try:
            patch_offset = int(raw_offset, 0) if isinstance(raw_offset, str) else int(raw_offset)
            expected = bytes.fromhex(item["expected_hex"])
            replacement = bytes.fromhex(item["replacement_hex"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PatchError(f"invalid gate patch item {index}: {exc}") from exc
        if not expected or len(expected) != len(replacement):
            raise PatchError(f"gate patch item {index} must be non-empty and length preserving")
        target = range(patch_offset, patch_offset + len(expected))
        if patch_offset < 0 or target.stop > len(result):
            raise PatchError(f"gate patch item {index} is outside libapp")
        if any(target.start < prior.stop and prior.start < target.stop for prior in occupied):
            raise PatchError(f"gate patch item {index} overlaps another patch")
        if bytes(result[target.start : target.stop]) != expected:
            raise PatchError(f"gate patch item {index} expected bytes do not match")
        result[target.start : target.stop] = replacement
        occupied.append(target)
        normalized.append(
            {
                "purpose": item.get("purpose"),
                "offset": patch_offset,
                "length": len(expected),
                "evidence": item["evidence"],
            }
        )
    return normalized, bytes(result)


def is_signature_entry(name: str) -> bool:
    upper = name.upper()
    if name == "stamp-cert-sha256":
        return True
    if upper == "META-INF/MANIFEST.MF":
        return True
    return bool(re.fullmatch(r"META-INF/[^/]+\.(SF|RSA|DSA|EC)", upper))


def rewrite_apk(source: Path, destination: Path, replacement_libapp: bytes | None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source, "r") as src, zipfile.ZipFile(destination, "w") as dst:
        dst.comment = src.comment
        for info in src.infolist():
            if is_signature_entry(info.filename):
                continue
            payload = src.read(info.filename)
            if info.filename == LIBAPP_PATH and replacement_libapp is not None:
                payload = replacement_libapp
            clone = zipfile.ZipInfo(info.filename, info.date_time)
            clone.compress_type = info.compress_type
            clone.comment = info.comment
            clone.extra = info.extra
            clone.create_system = info.create_system
            clone.create_version = info.create_version
            clone.extract_version = info.extract_version
            clone.flag_bits = info.flag_bits
            clone.volume = info.volume
            clone.internal_attr = info.internal_attr
            clone.external_attr = info.external_attr
            dst.writestr(clone, payload)


def find_build_tool(name: str) -> Path:
    from_path = shutil.which(name)
    if from_path:
        return Path(from_path)
    sdk_root = Path(os.environ.get("ANDROID_SDK_ROOT", Path.home() / "Library/Android/sdk"))
    candidates = sorted((sdk_root / "build-tools").glob(f"*/{name}"), reverse=True)
    if not candidates:
        raise PatchError(f"cannot find Android build tool: {name}")
    return candidates[0]


def run_checked(command: Iterable[str], *, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        list(command),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    if completed.returncode:
        raise PatchError(
            f"command failed ({completed.returncode}): {command}\n{completed.stdout.strip()}"
        )
    return completed.stdout
