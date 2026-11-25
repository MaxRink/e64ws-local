#!/usr/bin/env python3
"""Inventory ESP image segments and selected raw-string evidence.

ESP application/bootloader payloads are raw ESP image containers rather than
ELFs with symbols and relocations.  This tool therefore records exact image
segments, appended digest verification, and keyword-filtered ASCII strings
with segment-relative addresses.  It intentionally does not call a device,
execute image code, or label heuristic instruction starts as functions.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any


IMAGE_MAGIC = 0xE9
IMAGE_HEADER_SIZE = 24
SEGMENT_HEADER_SIZE = 8
KEYWORDS = (
    "heartbeat",
    "ota",
    "partition",
    "efuse",
    "secure",
    "rollback",
    "task",
    "queue",
    "wifi",
    "sdio",
    "flash",
    "reset",
    "gpio",
    "uart",
    "ctrlmsg",
    "ctrluart",
    "mainapplication",
    "freertos",
    "boot",
    "image",
)
SECRET_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|private\s+key|authorization|bearer|"
    r"-----begin|eyj[a-z0-9_-]+\.)"
)
ASCII_RE = re.compile(rb"[ -~]{4,}")


def segment_kind(load_address: int) -> str:
    if 0x3FF00000 <= load_address < 0x40000000:
        return "internal-data-or-iram"
    if 0x3F000000 <= load_address < 0x3FF00000:
        return "flash-data-or-rodata"
    if 0x400D0000 <= load_address < 0x40400000:
        return "mapped-flash-code"
    if 0x40000000 <= load_address < 0x40100000:
        return "internal-code-or-iram"
    if 0x50000000 <= load_address < 0x51000000:
        return "rtc-memory"
    return "unclassified-address"


def parse_image(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw = path.read_bytes()
    if len(raw) < IMAGE_HEADER_SIZE:
        raise ValueError(f"{path}: shorter than ESP image header")
    magic, segment_count, spi_mode, spi_speed_size = struct.unpack_from("<4B", raw, 0)
    if magic != IMAGE_MAGIC:
        raise ValueError(f"{path}: unexpected image magic 0x{magic:02x}")
    entry_address = struct.unpack_from("<I", raw, 4)[0]
    cursor = IMAGE_HEADER_SIZE
    segments: list[dict[str, Any]] = []
    for index in range(segment_count):
        if cursor + SEGMENT_HEADER_SIZE > len(raw):
            raise ValueError(f"{path}: truncated segment header {index}")
        load_address, length = struct.unpack_from("<II", raw, cursor)
        data_start = cursor + SEGMENT_HEADER_SIZE
        data_end = data_start + length
        if data_end > len(raw):
            raise ValueError(f"{path}: truncated segment {index}")
        segments.append(
            {
                "index": index,
                "load_address": f"0x{load_address:08x}",
                "load_address_int": load_address,
                "length": length,
                "header_file_offset": cursor,
                "data_file_offset": data_start,
                "data_end_offset": data_end,
                "kind": segment_kind(load_address),
            }
        )
        cursor = data_end
    digest_offset = len(raw) - 32
    digest_expected = raw[digest_offset:]
    digest_actual = hashlib.sha256(raw[:digest_offset]).digest() if len(raw) >= 32 else b""
    image = {
        "path": str(path),
        "filename": path.name,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "magic": f"0x{magic:02x}",
        "segment_count": segment_count,
        "spi_mode": spi_mode,
        "spi_speed_size": spi_speed_size,
        "entry_address": f"0x{entry_address:08x}",
        "parsed_end_offset": cursor,
        "trailing_digest_offset": digest_offset,
        "trailing_sha256_matches": digest_actual == digest_expected,
        "trailing_bytes_after_segments_before_digest": max(0, digest_offset - cursor),
    }
    return image, segments


def scan_strings(path: Path, segments: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    raw = path.read_bytes()
    rows: list[dict[str, Any]] = []
    redacted = 0
    for match in ASCII_RE.finditer(raw):
        value = match.group().decode("ascii", errors="replace")
        lower = value.lower()
        if not any(keyword in lower for keyword in KEYWORDS):
            continue
        if SECRET_RE.search(value):
            redacted += 1
            continue
        segment = next(
            (
                candidate
                for candidate in segments
                if int(candidate["data_file_offset"]) <= match.start() < int(candidate["data_end_offset"])
            ),
            None,
        )
        if segment is None:
            continue
        load_address = int(segment["load_address_int"]) + match.start() - int(segment["data_file_offset"])
        rows.append(
            {
                "image": path.name,
                "segment": segment["index"],
                "segment_kind": segment["kind"],
                "file_offset": f"0x{match.start():x}",
                "load_address": f"0x{load_address:08x}",
                "length": len(value),
                "value": value,
                "evidence": "raw ASCII keyword scan; no code xref claimed",
            }
        )
    rows.sort(key=lambda row: (row["image"], int(row["file_offset"], 16)))
    return rows, redacted


def write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True, help="ESP image; repeat for app and bootloader")
    parser.add_argument("--output", type=Path, default=Path("docs/generated/esp-static"))
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    image_rows: list[dict[str, Any]] = []
    segment_rows: list[dict[str, Any]] = []
    string_rows: list[dict[str, Any]] = []
    redacted_strings = 0
    for path in args.input:
        image, segments = parse_image(path)
        image_rows.append({key: value for key, value in image.items() if key != "path"})
        for segment in segments:
            segment_rows.append(
                {
                    "filename": path.name,
                    **{
                        key: value
                        for key, value in segment.items()
                        if key != "load_address_int"
                    },
                }
            )
        found, redacted = scan_strings(path, segments)
        string_rows.extend(found)
        redacted_strings += redacted
    write_csv(
        output / "esp_image_segments.csv",
        ["filename", "size", "sha256", "magic", "segment_count", "spi_mode", "spi_speed_size", "entry_address", "parsed_end_offset", "trailing_digest_offset", "trailing_sha256_matches", "trailing_bytes_after_segments_before_digest"],
        image_rows,
    )
    write_csv(
        output / "esp_segment_ledger.csv",
        ["filename", "index", "load_address", "length", "header_file_offset", "data_file_offset", "data_end_offset", "kind"],
        segment_rows,
    )
    write_csv(
        output / "esp_string_evidence.csv",
        ["image", "segment", "segment_kind", "file_offset", "load_address", "length", "value", "evidence"],
        string_rows,
    )
    summary = {
        "images": image_rows,
        "segment_count": len(segment_rows),
        "keyword_string_count": len(string_rows),
        "redacted_string_count": redacted_strings,
        "keyword_filter": list(KEYWORDS),
        "limitations": [
            "Raw ESP images have no linked symbols or relocations in this pass; no function names are inferred.",
            "ASCII strings are evidence of bytes in a segment, not proof of code xrefs, reachability, task ownership, or protocol semantics.",
            "Segment kind is an address-range classification for review, not a chip-specific linker map.",
            "Trailing SHA-256 consistency is image-integrity metadata, not proof of Secure Boot or flash encryption enablement.",
            "String values matching credential/private-key patterns are counted as redacted and never emitted.",
        ],
    }
    (output / "esp_static_ledger_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
