"""Tests for tools/esp_image.py against synthetic ESP images and tables.

The real vendor images stay in the ignored local extraction, so the parser is
exercised with hand-built images and partition tables that follow the ESP-IDF
layout.

Run with::

    python3 -m unittest discover -s tools/tests -q
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import esp_image  # noqa: E402

APP_DESC_MAGIC = 0xABCD5432


def make_app_desc(
    version: str = "V01_16_RC1",
    project: str = "Ng2EspApp",
    build_time: str = "13:57:45",
    build_date: str = "Jun  5 2026",
    idf_version: str = "v5.0.0",
) -> bytes:
    def field(value: str, size: int) -> bytes:
        raw = value.encode()
        assert len(raw) < size
        return raw + b"\x00" * (size - len(raw))

    desc = struct.pack("<III", APP_DESC_MAGIC, 0, 0) + struct.pack("<I", 0)
    desc += field(version, 32)
    desc += field(project, 32)
    desc += field(build_time, 16)
    desc += field(build_date, 16)
    desc += field(idf_version, 32)
    desc += b"\x11" * 32  # app_elf_sha256
    desc += b"\x00" * 80  # reserv2[20]
    assert len(desc) == 256
    return desc


def build_image(segments, entry=0x40081520, chip_id=0x0000, checksum=None,
                append_hash=True, tamper_hash=False, min_chip_rev=0,
                hash_byte=None, spi_speed_size=0x20, pad_byte=b"\x00") -> bytes:
    header = struct.pack(
        "<BBBBI", 0xE9, len(segments), 2, spi_speed_size, entry
    )
    header += bytes([0xEE]) + bytes([0, 0, 0])  # wp_pin, spi_pin_drv
    header += struct.pack("<H", chip_id)
    header += bytes([min_chip_rev])  # min_chip_rev
    header += struct.pack("<HH", 0, 0xFFFF)  # revision window
    header += b"\x00\x00\x00\x00"  # reserved
    header += bytes([hash_byte if hash_byte is not None else int(append_hash)])
    assert len(header) == 24

    body = b""
    running = esp_image.CHECKSUM_SEED
    for load_addr, payload in segments:
        body += struct.pack("<II", load_addr, len(payload)) + payload
        for byte in payload:
            running ^= byte

    image = header + body
    while len(image) % 16 != 15:
        image += pad_byte
    image += bytes([running if checksum is None else checksum])
    if append_hash:
        digest = hashlib.sha256(image).digest()
        if tamper_hash:
            digest = bytes([digest[0] ^ 0xFF]) + digest[1:]
        image += digest
    return image


def make_partition_entry(ptype, subtype, offset, size, label, flags=0) -> bytes:
    entry = struct.pack(
        "<HBBII16sI",
        0x50AA,
        ptype,
        subtype,
        offset,
        size,
        label.encode("ascii")[:16].ljust(16, b"\x00"),
        flags,
    )
    assert len(entry) == esp_image.PARTITION_ENTRY_LEN
    return entry


def make_md5_entry(covered: bytes) -> bytes:
    return (
        struct.pack("<H", esp_image.PARTITION_MD5_MAGIC)
        + b"\xff" * 14
        + hashlib.md5(covered).digest()
    )


# The layout parsed from the three vendor partition tables (identical in
# 1.14-2, 1.16-24 and NG2 1.36-2), rebuilt here so the parser is pinned to
# structure only.
VENDOR_PARTITIONS = [
    (0x01, 0x02, 0x9000, 0x4000, "nvs", 0),
    (0x01, 0x01, 0xF000, 0x1000, "phy_init", 0),
    (0x00, 0x00, 0x10000, 0x200000, "factory", 0),
    (0x01, 0x81, 0x210000, 0x100000, "spiflash", 0),
]


def make_partition_table(entries, *, with_md5=True, pad_to=0xC00,
                         pad_byte=b"\xff") -> bytes:
    body = b"".join(entries)
    if with_md5:
        body += make_md5_entry(body)
    if pad_to is not None:
        body = body.ljust(pad_to, pad_byte)
    return body


def make_vendor_table(**kwargs) -> bytes:
    return make_partition_table(
        [make_partition_entry(*entry) for entry in VENDOR_PARTITIONS], **kwargs
    )


class ParseHeaderTests(unittest.TestCase):
    def test_header_fields(self) -> None:
        image = build_image([(0x3F400020, make_app_desc())], entry=0x40081520)
        parsed = esp_image.parse_image(image, name="app.bin")

        header = parsed["header"]
        self.assertEqual(header["magic"], "0xe9")
        self.assertEqual(header["segment_count"], 1)
        self.assertEqual(header["chip"], "ESP32")
        self.assertEqual(header["entry_addr"], "0x40081520")
        self.assertEqual(header["spi_mode"], "DIO")
        self.assertEqual(header["spi_speed"], "40 MHz")
        self.assertEqual(header["spi_size"], "4 MB")
        self.assertTrue(header["hash_appended"])
        self.assertEqual(parsed["file_size"], len(image))
        self.assertEqual(parsed["file_sha256"], hashlib.sha256(image).hexdigest())

    def test_unknown_chip_is_reported_not_rejected(self) -> None:
        parsed = esp_image.parse_image(build_image([(0x1000, b"ab")], chip_id=0x9999))
        self.assertEqual(parsed["header"]["chip"], "unknown 0x9999")

    def test_min_chip_rev_byte_at_offset_14(self) -> None:
        parsed = esp_image.parse_image(build_image([(0x1000, b"ab")], min_chip_rev=3))
        self.assertEqual(parsed["header"]["min_chip_rev"], 3)
        self.assertEqual(parsed["header"]["min_chip_rev_full"], 0)
        self.assertEqual(parsed["header"]["max_chip_rev_full"], 0xFFFF)

    def test_hash_appended_raw_value_is_kept(self) -> None:
        parsed = esp_image.parse_image(
            build_image([(0x1000, b"ab")], append_hash=False, hash_byte=0)
        )
        self.assertEqual(parsed["header"]["hash_appended_raw"], 0)
        self.assertFalse(parsed["header"]["hash_appended"])
        self.assertEqual(parsed["warnings"], [])

    def test_out_of_range_hash_flag_warns(self) -> None:
        parsed = esp_image.parse_image(
            build_image([(0x1000, b"ab")], append_hash=True, hash_byte=7)
        )
        self.assertTrue(parsed["header"]["hash_appended"])
        self.assertEqual(parsed["header"]["hash_appended_raw"], 7)
        self.assertTrue(
            any("hash_appended" in warning for warning in parsed["warnings"])
        )

    def test_unknown_spi_values_keep_the_raw_value(self) -> None:
        parsed = esp_image.parse_image(
            build_image([(0x1000, b"ab")], spi_speed_size=0x8B)
        )
        self.assertEqual(parsed["header"]["spi_speed"], "unknown 0xb")
        self.assertEqual(parsed["header"]["spi_size"], "unknown 0x8")

    def test_zero_segment_image_warns(self) -> None:
        parsed = esp_image.parse_image(build_image([], append_hash=False))
        self.assertEqual(parsed["header"]["segment_count"], 0)
        self.assertEqual(parsed["segments"], [])
        self.assertTrue(any("zero segments" in w for w in parsed["warnings"]))


class IntegrityTests(unittest.TestCase):
    def test_checksum_and_hash_verify(self) -> None:
        parsed = esp_image.parse_image(build_image([(0x1000, b"abcd")]))
        self.assertTrue(parsed["checksum"]["ok"])
        self.assertTrue(parsed["sha256_appended"]["ok"])
        self.assertEqual(parsed["trailing_bytes"], 0)

    def test_wrong_checksum_is_reported(self) -> None:
        parsed = esp_image.parse_image(build_image([(0x1000, b"abcd")], checksum=0x00))
        self.assertFalse(parsed["checksum"]["ok"])

    def test_tampered_hash_is_reported(self) -> None:
        parsed = esp_image.parse_image(build_image([(0x1000, b"abcd")], tamper_hash=True))
        self.assertFalse(parsed["sha256_appended"]["ok"])

    def test_no_hash(self) -> None:
        parsed = esp_image.parse_image(build_image([(0x1000, b"abcd")], append_hash=False))
        self.assertFalse(parsed["sha256_appended"]["present"])
        self.assertIsNone(parsed["sha256_appended"]["ok"])

    def test_checksum_is_last_byte_of_16_byte_block(self) -> None:
        # 24-byte header + 8-byte segment header + 16-byte payload = 48 bytes,
        # already 16-byte aligned, so esptool pads 15 bytes before the checksum.
        image = build_image([(0x1000, b"x" * 16)], append_hash=False)
        parsed = esp_image.parse_image(image)
        self.assertEqual(parsed["checksum"]["padding_bytes"], 15)
        self.assertEqual(len(image), 64)
        self.assertEqual(image[63], int(parsed["checksum"]["stored"], 16))
        self.assertTrue(parsed["checksum"]["ok"])

    def test_non_zero_padding_warns_but_still_parses(self) -> None:
        image = build_image(
            [(0x1000, b"abcd")], append_hash=False, pad_byte=b"\x01"
        )
        parsed = esp_image.parse_image(image)
        self.assertTrue(parsed["checksum"]["ok"])
        self.assertTrue(any("padding" in w for w in parsed["warnings"]))

    def test_sha256_covers_checksum_byte(self) -> None:
        image = build_image([(0x1000, b"abcd")])
        parsed = esp_image.parse_image(image)
        digest_offset = len(image) - 32
        self.assertEqual(
            hashlib.sha256(image[:digest_offset]).hexdigest(),
            parsed["sha256_appended"]["stored"],
        )
        self.assertEqual(parsed["trailing_bytes"], 0)


class AppDescriptionTests(unittest.TestCase):
    def test_app_description_is_parsed(self) -> None:
        desc = make_app_desc()
        parsed = esp_image.parse_image(build_image([(0x3F400020, desc + b"\x00" * 64)]))
        app = parsed["app_description"]
        self.assertEqual(app["version"], "V01_16_RC1")
        self.assertEqual(app["project_name"], "Ng2EspApp")
        self.assertEqual(app["build_time"], "13:57:45")
        self.assertEqual(app["build_date"], "Jun  5 2026")
        self.assertEqual(app["idf_version"], "v5.0.0")
        self.assertEqual(app["magic"], "0xabcd5432")
        self.assertEqual(app["elf_sha256"], "11" * 32)

    def test_app_description_field_offsets(self) -> None:
        # Pin the packed esp_app_desc_t layout independently of the helper above.
        desc = bytearray(256)
        struct.pack_into("<II", desc, 0, APP_DESC_MAGIC, 9)
        desc[16:20] = b"V1\0\0"
        desc[48:52] = b"PRJ\0"
        desc[80:84] = b"TIME"
        desc[96:100] = b"DATE"
        desc[112:117] = b"IDF5\0"
        desc[144:176] = b"\xab" * 32
        desc[176:256] = b"\xcd" * 80

        parsed = esp_image.parse_image(build_image([(0x3F400020, bytes(desc))]))
        app = parsed["app_description"]
        self.assertEqual(app["secure_version"], 9)
        self.assertEqual(app["version"], "V1")
        self.assertEqual(app["project_name"], "PRJ")
        self.assertEqual(app["build_time"], "TIME")
        self.assertEqual(app["build_date"], "DATE")
        self.assertEqual(app["idf_version"], "IDF5")
        self.assertEqual(app["elf_sha256"], "ab" * 32)

    def test_short_first_segment_has_no_app_description(self) -> None:
        # The magic cannot be present because the segment is shorter than 256 B.
        parsed = esp_image.parse_image(build_image([(0x3F400020, b"\x32\x54\xcd\xab")]))
        self.assertNotIn("app_description", parsed)

    def test_bootloader_has_no_app_description(self) -> None:
        parsed = esp_image.parse_image(build_image([(0x3FFF0030, b"\x00" * 512)]))
        self.assertNotIn("app_description", parsed)


class SegmentTests(unittest.TestCase):
    def test_segments_are_listed_in_order(self) -> None:
        segments = [(0x3F400020, b"a" * 16), (0x400D0020, b"b" * 32)]
        parsed = esp_image.parse_image(build_image(segments))
        self.assertEqual([s["load_addr"] for s in parsed["segments"]],
                         ["0x3f400020", "0x400d0020"])
        self.assertEqual([s["length"] for s in parsed["segments"]], [16, 32])
        self.assertEqual(parsed["segments"][1]["sha256"],
                         hashlib.sha256(b"b" * 32).hexdigest())

    def test_first_segment_starts_after_header(self) -> None:
        parsed = esp_image.parse_image(build_image([(0x1000, b"x" * 8)]))
        self.assertEqual(parsed["segments"][0]["file_offset"], "0x00000020")

    def test_load_end_is_reported(self) -> None:
        parsed = esp_image.parse_image(build_image([(0x3FFB0000, b"x" * 0x40)]))
        self.assertEqual(parsed["segments"][0]["load_end"], "0x3ffb0040")


class ErrorTests(unittest.TestCase):
    def test_bad_magic(self) -> None:
        with self.assertRaises(esp_image.ImageError):
            esp_image.parse_image(b"\x00" + b"\x00" * 63)

    def test_short_header(self) -> None:
        with self.assertRaises(esp_image.ImageError):
            esp_image.parse_image(b"\xe9\x01")

    def test_truncated_segment(self) -> None:
        image = build_image([(0x1000, b"abcd")])
        with self.assertRaises(esp_image.ImageError):
            esp_image.parse_image(image[:30])

    def test_segment_load_range_cannot_wrap_32_bits(self) -> None:
        with self.assertRaises(esp_image.ImageError) as caught:
            esp_image.parse_image(build_image([(0xFFFFFFF0, b"x" * 32)]))
        self.assertIn("32-bit", str(caught.exception))

    def test_missing_checksum_byte(self) -> None:
        image = build_image([(0x1000, b"abcd")], append_hash=False)
        with self.assertRaises(esp_image.ImageError):
            esp_image.parse_image(image[:-1])

    def test_truncated_appended_sha256(self) -> None:
        image = build_image([(0x1000, b"abcd")])
        with self.assertRaises(esp_image.ImageError) as caught:
            esp_image.parse_image(image[:-1])
        self.assertIn("truncated", str(caught.exception))


class SummaryTests(unittest.TestCase):
    def test_summary_reports_hash_mismatch(self) -> None:
        parsed = esp_image.parse_image(
            build_image([(0x1000, b"abcd")], tamper_hash=True)
        )
        summary = esp_image._summary(parsed)
        self.assertIn("sha256=MISMATCH", summary)
        self.assertNotIn("sha256=n/a", summary)

    def test_summary_reports_absent_hash(self) -> None:
        parsed = esp_image.parse_image(
            build_image([(0x1000, b"abcd")], append_hash=False)
        )
        self.assertIn("sha256=absent", esp_image._summary(parsed))

    def test_summary_lists_app_description(self) -> None:
        parsed = esp_image.parse_image(
            build_image([(0x3F400020, make_app_desc())]), name="app.bin"
        )
        summary = esp_image._summary(parsed)
        self.assertIn("Ng2EspApp V01_16_RC1", summary)


class InventoryTests(unittest.TestCase):
    def test_inventory_shape(self) -> None:
        first = esp_image.parse_image(build_image([(0x1000, b"ab")]), name="a.bin")
        second = esp_image.parse_image(build_image([(0x2000, b"cd")]), name="b.bin")
        inventory = esp_image._inventory([first, second])
        self.assertEqual(inventory["schema"], "e64-esp-image-inventory/1")
        self.assertEqual([i["name"] for i in inventory["images"]], ["a.bin", "b.bin"])


class PartitionParseTests(unittest.TestCase):
    def test_vendor_layout_parses(self) -> None:
        parsed = esp_image.parse_partition_table(make_vendor_table(), name="t.bin")
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["file_size"], 0xC00)
        self.assertEqual(parsed["terminator"], "md5")
        self.assertEqual(parsed["unused_bytes"], 0xC00 - 0xA0)
        self.assertEqual(parsed["warnings"], [])

        entries = parsed["entries"]
        self.assertEqual([e["label"] for e in entries],
                         ["nvs", "phy_init", "factory", "spiflash"])
        self.assertEqual([e["index"] for e in entries], [0, 1, 2, 3])
        self.assertEqual([e["table_offset"] for e in entries],
                         ["0x0000", "0x0020", "0x0040", "0x0060"])

        factory = entries[2]
        self.assertEqual(factory["type"], "app")
        self.assertEqual(factory["type_id"], 0x00)
        self.assertEqual(factory["subtype"], "factory")
        self.assertEqual(factory["offset"], "0x00010000")
        self.assertEqual(factory["size"], 0x200000)
        self.assertEqual(factory["end"], "0x00210000")
        self.assertEqual(factory["flags"], "0x00000000")

    def test_flags_are_preserved(self) -> None:
        table = make_partition_table(
            [make_partition_entry(0x00, 0x00, 0x10000, 0x1000, "app0", 0xDEADBEEF)],
            pad_to=None,
        )
        parsed = esp_image.parse_partition_table(table)
        self.assertEqual(parsed["entries"][0]["flags"], "0xdeadbeef")

    def test_md5_covers_only_the_entries(self) -> None:
        table = make_vendor_table()
        parsed = esp_image.parse_partition_table(table)
        self.assertTrue(parsed["md5"]["present"])
        self.assertTrue(parsed["md5"]["ok"])
        self.assertEqual(parsed["md5"]["covered_bytes"], 4 * 32)
        self.assertEqual(parsed["md5"]["computed"], parsed["md5"]["stored"])
        # The digest must not be taken over the whole padded file.
        self.assertNotEqual(parsed["md5"]["computed"], hashlib.md5(table).hexdigest())

    def test_md5_mismatch_is_reported(self) -> None:
        table = bytearray(make_vendor_table())
        table[0x91] ^= 0xFF  # first byte of the stored digest at 0x90..0x9F
        parsed = esp_image.parse_partition_table(bytes(table))
        self.assertTrue(parsed["md5"]["present"])
        self.assertFalse(parsed["md5"]["ok"])

    def test_end_of_table_terminator_without_md5(self) -> None:
        body = make_partition_entry(0x00, 0x00, 0x10000, 0x1000, "factory")
        table = body + b"\xff" * 32
        parsed = esp_image.parse_partition_table(table)
        self.assertEqual(parsed["terminator"], "end-of-table")
        self.assertFalse(parsed["md5"]["present"])
        self.assertIsNone(parsed["md5"]["ok"])
        self.assertEqual(len(parsed["entries"]), 1)

    def test_table_without_terminator_reads_to_end(self) -> None:
        table = make_partition_entry(0x01, 0x02, 0x9000, 0x4000, "nvs")
        parsed = esp_image.parse_partition_table(table)
        self.assertEqual(parsed["terminator"], "end-of-input")
        self.assertEqual(parsed["unused_bytes"], 0)

    def test_empty_table_is_reported_as_empty(self) -> None:
        parsed = esp_image.parse_partition_table(b"", name="partitions.bin")
        self.assertEqual(parsed["status"], "empty")
        self.assertEqual(parsed["entries"], [])
        self.assertEqual(parsed["file_size"], 0)
        self.assertEqual(
            parsed["file_sha256"],
            hashlib.sha256(b"").hexdigest(),
        )
        self.assertIsNone(parsed["terminator"])

    def test_bad_magic_raises(self) -> None:
        entry = make_partition_entry(0x01, 0x02, 0x9000, 0x4000, "nvs")
        broken = b"\x00\x00" + entry[2:]
        with self.assertRaises(esp_image.PartitionTableError) as caught:
            esp_image.parse_partition_table(broken)
        self.assertIn("0x0000", str(caught.exception))

    def test_short_input_raises(self) -> None:
        with self.assertRaises(esp_image.PartitionTableError):
            esp_image.parse_partition_table(b"\xaa\x50\x01\x02")

    def test_partial_trailing_entry_warns(self) -> None:
        table = make_partition_entry(0x01, 0x02, 0x9000, 0x4000, "nvs") + b"\xff" * 8
        parsed = esp_image.parse_partition_table(table)
        self.assertTrue(any("trailing byte" in w for w in parsed["warnings"]))

    def test_non_ff_unused_space_warns(self) -> None:
        table = make_vendor_table(pad_to=0xC00, pad_byte=b"\x00")
        parsed = esp_image.parse_partition_table(table)
        self.assertTrue(any("0xFF" in w for w in parsed["warnings"]))

    def test_oversized_table_warns(self) -> None:
        table = make_vendor_table(pad_to=0x1000)
        parsed = esp_image.parse_partition_table(table)
        self.assertTrue(any("0xC00" in w for w in parsed["warnings"]))

    def test_overlapping_partitions_warn(self) -> None:
        table = make_partition_table(
            [
                make_partition_entry(0x00, 0x00, 0x10000, 0x200000, "factory"),
                make_partition_entry(0x01, 0x02, 0x100000, 0x4000, "nvs"),
            ],
            pad_to=None,
        )
        parsed = esp_image.parse_partition_table(table)
        self.assertTrue(any("overlap" in w for w in parsed["warnings"]))

    def test_entry_address_wrap_raises(self) -> None:
        table = make_partition_entry(0x01, 0x02, 0xFFFFFF00, 0x200, "nvs")
        with self.assertRaises(esp_image.PartitionTableError):
            esp_image.parse_partition_table(table)

    def test_full_length_label_without_nul(self) -> None:
        table = make_partition_table(
            [make_partition_entry(0x01, 0x02, 0x9000, 0x4000, "0123456789abcdef")],
            pad_to=None,
        )
        parsed = esp_image.parse_partition_table(table)
        self.assertEqual(parsed["entries"][0]["label"], "0123456789abcdef")


class PartitionSubtypeTests(unittest.TestCase):
    def _subtype(self, ptype: int, subtype: int) -> str:
        table = make_partition_table(
            [make_partition_entry(ptype, subtype, 0x10000, 0x1000, "x")],
            with_md5=False,
            pad_to=None,
        )
        return esp_image.parse_partition_table(table)["entries"][0]["subtype"]

    def test_app_subtypes(self) -> None:
        self.assertEqual(self._subtype(0x00, 0x00), "factory")
        self.assertEqual(self._subtype(0x00, 0x10), "ota_0")
        self.assertEqual(self._subtype(0x00, 0x1F), "ota_15")
        self.assertEqual(self._subtype(0x00, 0x20), "test")
        self.assertEqual(self._subtype(0x00, 0x30), "unknown 0x30")

    def test_data_subtypes(self) -> None:
        self.assertEqual(self._subtype(0x01, 0x01), "phy")
        self.assertEqual(self._subtype(0x01, 0x02), "nvs")
        self.assertEqual(self._subtype(0x01, 0x03), "coredump")
        self.assertEqual(self._subtype(0x01, 0x04), "nvs_keys")
        self.assertEqual(self._subtype(0x01, 0x81), "fat")
        self.assertEqual(self._subtype(0x01, 0x82), "spiffs")
        self.assertEqual(self._subtype(0x01, 0x83), "littlefs")
        self.assertEqual(self._subtype(0x01, 0x7F), "unknown 0x7f")

    def test_unknown_type(self) -> None:
        table = make_partition_table(
            [make_partition_entry(0x02, 0x02, 0x10000, 0x1000, "x")],
            with_md5=False,
            pad_to=None,
        )
        entry = esp_image.parse_partition_table(table)["entries"][0]
        self.assertEqual(entry["type"], "unknown 0x02")
        self.assertEqual(entry["subtype"], "unknown 0x02")


class PartitionSummaryAndCliTests(unittest.TestCase):
    def test_summary_lists_entries_and_md5(self) -> None:
        parsed = esp_image.parse_partition_table(
            make_vendor_table(), name="partition-table.bin"
        )
        summary = esp_image._partition_summary(parsed)
        self.assertIn("partition-table.bin", summary)
        self.assertIn("factory: app/factory at 0x00010000", summary)
        self.assertIn("md5=ok over 128 B", summary)

    def test_summary_reports_md5_mismatch(self) -> None:
        table = bytearray(make_vendor_table())
        table[0x91] ^= 0xFF
        parsed = esp_image.parse_partition_table(bytes(table))
        self.assertIn("md5=MISMATCH", esp_image._partition_summary(parsed))

    def test_partition_inventory_shape(self) -> None:
        first = esp_image.parse_partition_table(make_vendor_table(), name="a.bin")
        second = esp_image.parse_partition_table(b"", name="b.bin")
        inventory = esp_image._partition_inventory([first, second])
        self.assertEqual(
            inventory["schema"], "e64-esp-partition-table-inventory/1"
        )
        self.assertEqual([t["name"] for t in inventory["tables"]], ["a.bin", "b.bin"])

    def test_cli_writes_partition_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "partition-table.bin"
            source.write_bytes(make_vendor_table())
            out = Path(tmp) / "partitions.json"
            with tempfile.TemporaryFile(mode="w+") as sink:
                stdout, sys.stdout = sys.stdout, sink
                try:
                    self.assertEqual(
                        esp_image.main(
                            ["--partitions", "--inventory", str(out), str(source)]
                        ),
                        0,
                    )
                finally:
                    sys.stdout = stdout
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["schema"], "e64-esp-partition-table-inventory/1"
            )
            table = payload["tables"][0]
            self.assertEqual(table["name"], "partition-table.bin")
            self.assertTrue(table["md5"]["ok"])
            self.assertEqual(len(table["entries"]), 4)
            self.assertNotIn("file_bytes", table)

    def test_cli_partition_json_for_single_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "partition-table.bin"
            source.write_bytes(make_vendor_table())
            with tempfile.TemporaryFile(mode="w+") as sink:
                stdout, sys.stdout = sys.stdout, sink
                try:
                    self.assertEqual(
                        esp_image.main(["--partitions", "--json", str(source)]), 0
                    )
                finally:
                    sys.stdout = stdout
                sink.seek(0)
                payload = json.loads(sink.read())
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["entries"][0]["label"], "nvs")

    def test_cli_reports_bad_partition_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "broken.bin"
            source.write_bytes(b"\x00\x00" + b"\x00" * 30)
            with tempfile.TemporaryFile(mode="w+") as sink:
                stderr, sys.stderr = sys.stderr, sink
                try:
                    self.assertEqual(esp_image.main(["--partitions", str(source)]), 1)
                finally:
                    sys.stderr = stderr


if __name__ == "__main__":
    unittest.main()
