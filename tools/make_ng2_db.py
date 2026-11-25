#!/usr/bin/env python3
"""Synthesise a /db seed for the NG2 HMI from the SQL strings in libNgxUi.so.

The published image contains only schema *migrations*; the base tables live in
the factory db partition, which is not part of the SWU. This script rebuilds a
permissive schema from every table/column reference in the binary so the HMI can
open its storage, plus the machine config JSON it requires.

Usage: make_ng2_db.py LIB --out DIR
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sqlite3
import subprocess
import sys


def sql_text(lib: str) -> str:
    return "\n".join(subprocess.run(["strings", "-a", lib], capture_output=True, text=True).stdout.splitlines())


def collect(text: str) -> dict[str, set[str]]:
    tables: dict[str, set[str]] = {}

    def add(table: str, column: str) -> None:
        tables.setdefault(table.lower(), set()).add(column)

    for match in re.finditer(r'INSERT\s+(?:OR\s+\w+\s+)?INTO\s+"?([A-Za-z_][A-Za-z0-9_]*)"?\s*\(([^)]*)\)', text, re.S | re.I):
        for column in re.findall(r'"?([A-Za-z_][A-Za-z0-9_]*)"?', match.group(2)):
            add(match.group(1), column)
    for match in re.finditer(r"\b([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\b", text):
        add(match.group(1), match.group(2))
    for match in re.finditer(r'(?:FROM|JOIN|UPDATE)\s+"?([A-Za-z_][A-Za-z0-9_]*)"?', text, re.I):
        tables.setdefault(match.group(1).lower(), set())
    prefixes = ("recipe", "grind", "brew", "event", "alert", "settings", "gbs", "machine", "dose", "cloud", "log")
    return {t: c for t, c in tables.items() if t.startswith(prefixes)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lib")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    pathlib.Path(args.out).mkdir(parents=True, exist_ok=True)
    tables = collect(sql_text(args.lib))
    db_path = f"{args.out}/Ng2Sqlite.db"
    conn = sqlite3.connect(db_path)
    for table, columns in tables.items():
        defs = [f'"{c}" TEXT' for c in sorted(columns) if c]
        defs.append('"_pk" INTEGER PRIMARY KEY AUTOINCREMENT')
        conn.execute(f'CREATE TABLE "{table}" ({", ".join(defs)})')
    conn.executescript('DROP TABLE IF EXISTS "settings"; CREATE TABLE "settings" ("key" TEXT PRIMARY KEY NOT NULL, "value" TEXT);')
    conn.commit()
    conn.close()

    with open(f"{args.out}/Ng2Config.json", "w", encoding="utf-8") as handle:
        json.dump({"id": 0, "grinderType": 0, "grinderSubType": 0}, handle)
    print(f"{len(tables)} tables + Ng2Config.json written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
