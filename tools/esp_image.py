#!/usr/bin/env python3
"""Parse ESP32 firmware images and partition tables into metadata.

The vendor `*Ng2EspApp.bin` and `*bootloader.bin` files are the ESP32
co-processor images that ship inside the grinder update package, and
`partition-table.bin` is the table those images are flashed against.  Earlier
analysis read both by hand; this tool makes the parse reproducible and emits
stable JSON so the segment map, entry point, app description, and partition
layout can be diffed across firmware versions.

Only metadata is printed.  Segment payloads and partition contents are never
written out: the repository does not carry vendor firmware blobs.

Image format (ESP-IDF ``esp_image_format.h``)::

    header      24 bytes  magic 0xE9, segment count, SPI mode/speed/size,
                          entry address, chip id, revision window, hash flag
    segments    N x (u32 load address, u32 length, payload)
    padding     0..15 zero bytes so the checksum is the last byte of a
                          16-byte block (esptool ``align_file_position``)
    checksum    1 byte XOR of every segment payload byte, seeded with 0xEF
    sha256      32 bytes when the header hash flag is set; covers the whole
                          image up to and including the checksum byte

The first segment of an application image starts with ``esp_app_desc_t``
(image offset 0x20, right after the 24-byte header and the first 8-byte
segment header).  That is where the version, project name, build stamp, and
IDF version come from.

Partition-table format (ESP-IDF ``esp_partition.h``)::

    entries     32 bytes each: u16 magic 0xAA50, u8 type, u8 subtype,
                u32 offset, u32 size, char label[16], u32 flags
    md5 entry   u16 magic 0xEBEB, 14 reserved bytes, 16-byte MD5
    end         0xFFFF magic (all-0xFF entry), or end of the input

The MD5 covers every byte before the MD5 entry.  The table is flashed at
0x8000 and must fit below the first partition (0x9000), i.e. at most 0xC00
bytes.

Usage::

    python3 tools/esp_image.py .tools/firmware-1.16-24/raw/images.standard.Ng2EspApp.bin
    python3 tools/esp_image.py --json <image> [<image> ...]
    python3 tools/esp_image.py --inventory docs/evidence/esp-images/inventory.json <image> ...
    python3 tools/esp_image.py --partitions <partition-table.bin> [...]
    python3 tools/esp_image.py --partitions --json <partition-table.bin>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Iterable

IMAGE_MAGIC = 0xE9
HEADER_LEN = 24
APP_DESC_MAGIC = 0xABCD5432
APP_DESC_LEN = 256
CHECKSUM_SEED = 0xEF

PARTITION_MAGIC = 0x50AA
PARTITION_MD5_MAGIC = 0xEBEB
PARTITION_END_MAGIC = 0xFFFF
PARTITION_ENTRY_LEN = 32
PARTITION_TABLE_MAX_LEN = 0xC00
UINT32_SPACE = 1 << 32

CHIP_NAMES = {
    0x0000: "ESP32",
    0x0002: "ESP32-S2",
    0x0005: "ESP32-C3",
    0x0009: "ESP32-S3",
    0x000C: "ESP32-C2",
    0x000D: "ESP32-C6",
    0x0010: "ESP32-H2",
    0x0012: "ESP32-P4",
}

SPI_MODES = {0: "QIO", 1: "QOUT", 2: "DIO", 3: "DOUT"}
SPI_SPEEDS = {
    0x0: "40 MHz",
    0x1: "26 MHz",
    0x2: "20 MHz",
    0xF: "80 MHz",
}
SPI_SIZES = {
    0x0: "1 MB",
    0x1: "2 MB",
    0x2: "4 MB",
    0x3: "8 MB",
    0x4: "16 MB",
    0x5: "32 MB",
    0x6: "64 MB",
    0x7: "128 MB",
}

PARTITION_TYPE_NAMES = {0x00: "app", 0x01: "data"}

PARTITION_APP_SUBTYPES = {0x00: "factory", 0x20: "test"}
for _ota_slot in range(16):
    PARTITION_APP_SUBTYPES[0x10 + _ota_slot] = f"ota_{_ota_slot}"

PARTITION_DATA_SUBTYPES = {
    0x00: "ota",
    0x01: "phy",
    0x02: "nvs",
    0x03: "coredump",
    0x04: "nvs_keys",
    0x05: "efuse",
    0x06: "undefined",
    0x80: "esphttpd",
    0x81: "fat",
    0x82: "spiffs",
    0x83: "littlefs",
}


class ImageError(ValueError):
    """Raised when the input is not a parseable ESP image."""


class PartitionTableError(ValueError):
    """Raised when the input is not a parseable ESP partition table."""


def _cstr(raw: bytes) -> str:
    """Decode a fixed-size NUL-padded field."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _hex(value: int, width: int) -> str:
    return f"0x{value:0{width}x}"


def _xor_bytes(payload: bytes, seed: int = 0) -> int:
    """XOR-fold every byte of ``payload`` into ``seed``."""
    result = seed
    for byte in payload:
        result ^= byte
    return result


def _parse_app_desc(segment: bytes) -> dict[str, Any] | None:
    """Return ``esp_app_desc_t`` from the first segment payload, if present.

    Field offsets follow the packed ESP-IDF struct: magic 0, secure_version 4,
    reserv1[2] 8, version[32] 16, project_name[32] 48, time[16] 80,
    date[16] 96, idf_ver[32] 112, app_elf_sha256[32] 144, reserv2[20] 176.
    """
    if len(segment) < APP_DESC_LEN:
        return None
    desc = segment[:APP_DESC_LEN]
    (magic,) = struct.unpack_from("<I", desc, 0)
    if magic != APP_DESC_MAGIC:
        return None
    (secure_version,) = struct.unpack_from("<I", desc, 4)
    return {
        "magic": "0xabcd5432",
        "secure_version": secure_version,
        "version": _cstr(desc[16:48]),
        "project_name": _cstr(desc[48:80]),
        "build_time": _cstr(desc[80:96]),
        "build_date": _cstr(desc[96:112]),
        "idf_version": _cstr(desc[112:144]),
        "elf_sha256": desc[144:176].hex(),
    }


def parse_image(data: bytes, *, name: str | None = None) -> dict[str, Any]:
    """Parse one ESP image and return its metadata as a JSON-ready dict."""
    if len(data) < HEADER_LEN:
        raise ImageError("shorter than the 24-byte image header")
    if data[0] != IMAGE_MAGIC:
        raise ImageError(f"bad magic 0x{data[0]:02x}, expected 0x{IMAGE_MAGIC:02x}")

    warnings: list[str] = []
    segment_count = data[1]
    spi_mode, spi_speed_size = data[2], data[3]
    (entry_addr,) = struct.unpack_from("<I", data, 4)
    wp_pin = data[8]
    spi_pin_drv = list(data[9:12])
    (chip_id,) = struct.unpack_from("<H", data, 12)
    min_chip_rev = data[14]
    min_rev_full, max_rev_full = struct.unpack_from("<HH", data, 15)
    hash_appended = data[23]

    if segment_count == 0:
        warnings.append("header declares zero segments")
    if hash_appended not in (0, 1):
        warnings.append(
            f"hash_appended is 0x{hash_appended:02x}, expected 0 or 1"
        )

    offset = HEADER_LEN
    segments: list[dict[str, Any]] = []
    checksum = CHECKSUM_SEED
    for index in range(segment_count):
        if offset + 8 > len(data):
            raise ImageError(f"segment {index} header runs past end of file")
        load_addr, length = struct.unpack_from("<II", data, offset)
        offset += 8
        end = offset + length
        if end > len(data):
            raise ImageError(f"segment {index} payload runs past end of file")
        if load_addr + length > UINT32_SPACE:
            raise ImageError(
                f"segment {index} load range 0x{load_addr:08x}+{length} "
                "wraps the 32-bit address space"
            )
        payload = data[offset:end]
        segments.append(
            {
                "index": index,
                "load_addr": _hex(load_addr, 8),
                "load_end": _hex(load_addr + length, 8),
                "length": length,
                "file_offset": _hex(offset, 8),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        checksum = _xor_bytes(payload, checksum)
        offset = end

    # esptool aligns to the next 16-byte block *before* writing the checksum,
    # so the checksum byte is always the last byte of a 16-byte block.
    padding_start = offset
    while offset % 16 != 15:
        offset += 1
    if offset >= len(data):
        raise ImageError("missing checksum byte")
    padding = data[padding_start:offset]
    if any(padding):
        warnings.append(f"{len(padding)} checksum padding byte(s) are not zero")
    stored_checksum = data[offset]
    offset += 1

    sha256_ok: bool | None = None
    stored_sha256 = ""
    if hash_appended:
        if offset + 32 > len(data):
            raise ImageError("header announces a SHA-256 but the image is truncated")
        stored_sha256 = data[offset:offset + 32].hex()
        sha256_ok = hashlib.sha256(data[:offset]).digest() == data[offset:offset + 32]
        offset += 32

    image: dict[str, Any] = {
        "name": name or "",
        "file_size": len(data),
        "file_sha256": hashlib.sha256(data).hexdigest(),
        "header": {
            "magic": f"0x{IMAGE_MAGIC:02x}",
            "segment_count": segment_count,
            "spi_mode": SPI_MODES.get(spi_mode, f"unknown 0x{spi_mode:x}"),
            "spi_speed": SPI_SPEEDS.get(
                spi_speed_size & 0x0F, f"unknown 0x{spi_speed_size & 0x0F:x}"
            ),
            "spi_size": SPI_SIZES.get(
                spi_speed_size >> 4, f"unknown 0x{spi_speed_size >> 4:x}"
            ),
            "entry_addr": _hex(entry_addr, 8),
            "wp_pin": wp_pin,
            "spi_pin_drv": spi_pin_drv,
            "chip_id": _hex(chip_id, 4),
            "chip": CHIP_NAMES.get(chip_id, f"unknown 0x{chip_id:04x}"),
            "min_chip_rev": min_chip_rev,
            "min_chip_rev_full": min_rev_full,
            "max_chip_rev_full": max_rev_full,
            "hash_appended": bool(hash_appended),
            "hash_appended_raw": hash_appended,
        },
        "segments": segments,
        "checksum": {
            "stored": _hex(stored_checksum, 2),
            "computed": _hex(checksum, 2),
            "ok": stored_checksum == checksum,
            "padding_bytes": len(padding),
        },
        "sha256_appended": {
            "present": bool(hash_appended),
            "stored": stored_sha256,
            "ok": sha256_ok,
        },
        "trailing_bytes": len(data) - offset,
        "warnings": warnings,
    }

    if segments:
        first = data[HEADER_LEN + 8:HEADER_LEN + 8 + segments[0]["length"]]
        app_desc = _parse_app_desc(first)
        if app_desc is not None:
            image["app_description"] = app_desc
    return image


def parse_file(path: Path) -> dict[str, Any]:
    image = parse_image(path.read_bytes(), name=path.name)
    image["source"] = str(path)
    return image


def _warn_overlaps(entries: list[dict[str, Any]], warnings: list[str]) -> None:
    placed = sorted(
        (e for e in entries if e["size"]),
        key=lambda e: int(e["offset"], 16),
    )
    for previous, current in zip(placed, placed[1:]):
        previous_end = int(previous["offset"], 16) + previous["size"]
        if previous_end > int(current["offset"], 16):
            warnings.append(
                f"partitions {previous['label']} and {current['label']} overlap"
            )


def parse_partition_table(
    data: bytes, *, name: str | None = None
) -> dict[str, Any]:
    """Parse an ESP-IDF partition table and return metadata as a JSON-ready dict."""
    base: dict[str, Any] = {
        "name": name or "",
        "file_size": len(data),
        "file_sha256": hashlib.sha256(data).hexdigest(),
    }
    if not data:
        return {
            **base,
            "status": "empty",
            "entries": [],
            "terminator": None,
            "md5": {
                "present": False,
                "stored": "",
                "computed": "",
                "ok": None,
                "covered_bytes": 0,
            },
            "unused_bytes": 0,
            "warnings": ["partition table is empty"],
        }
    if len(data) < PARTITION_ENTRY_LEN:
        raise PartitionTableError(
            "shorter than one 32-byte partition-table entry"
        )

    warnings: list[str] = []
    entries: list[dict[str, Any]] = []
    md5: dict[str, Any] = {
        "present": False,
        "stored": "",
        "computed": "",
        "ok": None,
        "covered_bytes": 0,
    }
    terminator = "end-of-input"
    offset = 0
    while offset + PARTITION_ENTRY_LEN <= len(data):
        (magic,) = struct.unpack_from("<H", data, offset)
        if magic == PARTITION_MAGIC:
            ptype, subtype, address, size, label, flags = struct.unpack_from(
                "<BBII16sI", data, offset + 2
            )
            if address + size > UINT32_SPACE:
                raise PartitionTableError(
                    f"entry at 0x{offset:04x} wraps the 32-bit address space"
                )
            entries.append(
                {
                    "index": len(entries),
                    "table_offset": _hex(offset, 4),
                    "type_id": ptype,
                    "type": PARTITION_TYPE_NAMES.get(
                        ptype, f"unknown 0x{ptype:02x}"
                    ),
                    "subtype_id": subtype,
                    "subtype": _partition_subtype_name(ptype, subtype),
                    "offset": _hex(address, 8),
                    "size": size,
                    "end": _hex(address + size, 8),
                    "label": _cstr(label),
                    "flags": _hex(flags, 8),
                }
            )
            offset += PARTITION_ENTRY_LEN
            continue
        if magic == PARTITION_MD5_MAGIC:
            stored = data[offset + 16:offset + PARTITION_ENTRY_LEN]
            computed = hashlib.md5(data[:offset]).digest()
            md5 = {
                "present": True,
                "stored": stored.hex(),
                "computed": computed.hex(),
                "ok": stored == computed,
                "covered_bytes": offset,
            }
            terminator = "md5"
            offset += PARTITION_ENTRY_LEN
            break
        if magic == PARTITION_END_MAGIC:
            terminator = "end-of-table"
            break
        raise PartitionTableError(
            f"bad entry magic 0x{magic:04x} at table offset 0x{offset:04x}"
        )
    else:
        if len(data) % PARTITION_ENTRY_LEN:
            warnings.append(
                f"{len(data) % PARTITION_ENTRY_LEN} trailing byte(s) do not "
                "form a complete entry"
            )

    unused = data[offset:]
    if unused and any(byte != 0xFF for byte in unused):
        warnings.append("unused partition-table space is not all 0xFF")
    if len(data) > PARTITION_TABLE_MAX_LEN:
        warnings.append(
            f"table is {len(data)} bytes, larger than the 0xC00-byte window "
            "below the first partition at 0x9000"
        )
    _warn_overlaps(entries, warnings)
    if not entries:
        warnings.append("no partitions defined")

    return {
        **base,
        "status": "ok",
        "entries": entries,
        "terminator": terminator,
        "md5": md5,
        "unused_bytes": len(unused),
        "warnings": warnings,
    }


def _partition_subtype_name(ptype: int, subtype: int) -> str:
    if ptype == 0x00:
        table = PARTITION_APP_SUBTYPES
    elif ptype == 0x01:
        table = PARTITION_DATA_SUBTYPES
    else:
        return f"unknown 0x{subtype:02x}"
    return table.get(subtype, f"unknown 0x{subtype:02x}")


def parse_partition_file(path: Path) -> dict[str, Any]:
    table = parse_partition_table(path.read_bytes(), name=path.name)
    table["source"] = str(path)
    return table


def _hash_status(image: dict[str, Any]) -> str:
    appended = image["sha256_appended"]
    if not appended["present"]:
        return "absent"
    return "ok" if appended["ok"] else "MISMATCH"


def _summary(image: dict[str, Any]) -> str:
    header = image["header"]
    lines = [
        f"{image['name']} ({image['file_size']:,} B, sha256 {image['file_sha256'][:16]}…)",
        f"  chip={header['chip']} segments={header['segment_count']} "
        f"entry={header['entry_addr']} spi={header['spi_mode']}/"
        f"{header['spi_speed']}/{header['spi_size']}",
        f"  checksum={'ok' if image['checksum']['ok'] else 'MISMATCH'} "
        f"sha256={_hash_status(image)}",
    ]
    for segment in image["segments"]:
        lines.append(
            f"  seg{segment['index']}: {segment['load_addr']} "
            f"{segment['length']:,} B"
        )
    desc = image.get("app_description")
    if desc:
        lines.append(
            f"  app: {desc['project_name']} {desc['version']} "
            f"({desc['build_date']} {desc['build_time']}, IDF {desc['idf_version']})"
        )
    for warning in image["warnings"]:
        lines.append(f"  warning: {warning}")
    return "\n".join(lines)


def _partition_summary(table: dict[str, Any]) -> str:
    lines = [
        f"{table['name']} ({table['file_size']:,} B, "
        f"sha256 {table['file_sha256'][:16]}…, {table['status']})",
    ]
    for entry in table["entries"]:
        lines.append(
            f"  {entry['label'] or '<unnamed>'}: {entry['type']}/"
            f"{entry['subtype']} at {entry['offset']} "
            f"{entry['size']:,} B (end {entry['end']}, flags {entry['flags']})"
        )
    md5 = table["md5"]
    if md5["present"]:
        lines.append(
            f"  md5={'ok' if md5['ok'] else 'MISMATCH'} "
            f"over {md5['covered_bytes']} B, terminator {table['terminator']}"
        )
    else:
        lines.append(f"  md5=absent, terminator {table['terminator']}")
    for warning in table["warnings"]:
        lines.append(f"  warning: {warning}")
    return "\n".join(lines)


def _inventory(images: Iterable[dict[str, Any]]) -> dict[str, Any]:
    items = list(images)
    return {
        "schema": "e64-esp-image-inventory/1",
        "tool": "tools/esp_image.py",
        "images": items,
    }


def _partition_inventory(tables: Iterable[dict[str, Any]]) -> dict[str, Any]:
    items = list(tables)
    return {
        "schema": "e64-esp-partition-table-inventory/1",
        "tool": "tools/esp_image.py",
        "tables": items,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Parse ESP32 firmware images or partition tables into metadata "
            "(no payload output)."
        )
    )
    parser.add_argument("images", nargs="+", type=Path, help="ESP image files")
    parser.add_argument(
        "--partitions",
        action="store_true",
        help="treat the inputs as ESP-IDF partition tables",
    )
    parser.add_argument("--json", action="store_true", help="print JSON instead of a summary")
    parser.add_argument(
        "--inventory",
        type=Path,
        metavar="OUT",
        help="write a single inventory JSON for all inputs",
    )
    args = parser.parse_args(argv)

    parsed: list[dict[str, Any]] = []
    errors = (OSError, ImageError, PartitionTableError)
    for path in args.images:
        try:
            if args.partitions:
                parsed.append(parse_partition_file(path))
            else:
                parsed.append(parse_file(path))
        except errors as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            return 1

    if args.partitions:
        inventory = _partition_inventory(parsed)
        summary_fn = _partition_summary
    else:
        inventory = _inventory(parsed)
        summary_fn = _summary

    if args.inventory:
        args.inventory.parent.mkdir(parents=True, exist_ok=True)
        args.inventory.write_text(
            json.dumps(inventory, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.inventory} ({len(parsed)} inputs)")
        return 0

    if args.json:
        payload = parsed[0] if len(parsed) == 1 else inventory
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    for entry in parsed:
        print(summary_fn(entry))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
