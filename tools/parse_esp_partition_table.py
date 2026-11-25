"""Parse an ESP-IDF partition-table binary without flashing or executing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


ENTRY_SIZE = 32
MAGIC = 0x50AA


def parse(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    result: dict[str, object] = {
        "path": str(path),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "entries": [],
        "status": "empty" if not raw else "ok",
    }
    entries: list[dict[str, object]] = []
    for offset in range(0, len(raw) - ENTRY_SIZE + 1, ENTRY_SIZE):
        magic, ptype, subtype, address, size, label, flags = struct.unpack_from(
            "<HBBLL16sL", raw, offset
        )
        if magic == 0xFFFF:
            break
        if magic != MAGIC:
            result["status"] = "invalid-entry"
            result["invalidOffset"] = offset
            break
        entries.append(
            {
                "tableOffset": offset,
                "type": ptype,
                "subtype": subtype,
                "address": f"0x{address:08x}",
                "size": size,
                "label": label.split(b"\0", 1)[0].decode("ascii", errors="replace"),
                "flags": f"0x{flags:08x}",
            }
        )
    result["entries"] = entries
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    print(json.dumps(parse(args.path), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
