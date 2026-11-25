"""Offline checks for the recovered Qt SQLite resource bundle.

These tests are deliberately limited to the embedded factory schema. They do
not require or construct production rows, credentials, or opaque BLOB values.
"""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ELF = ROOT / ".tools/firmware-1.16-24/app-tree/bin/libNgxUi.so"
EXTRACTOR = ROOT / "tools/extract_qt_sqlite_resources.py"


@unittest.skipUnless(ELF.is_file(), "local firmware extraction is unavailable")
class QtSqliteResourceTests(unittest.TestCase):
    def extract_master(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)
        subprocess.run(
            [sys.executable, str(EXTRACTOR), str(ELF), str(output)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        return output / "NgxSqliteMaster.sql"

    def database(self) -> sqlite3.Connection:
        database = sqlite3.connect(":memory:")
        database.executescript(self.extract_master().read_text(encoding="utf-8"))
        self.addCleanup(database.close)
        return database

    def test_master_schema_and_factory_seed_shape(self) -> None:
        database = self.database()
        tables = {
            row[0]
            for row in database.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertEqual(len(tables), 17)
        self.assertTrue(
            {"settings", "recipe_data", "recipe_entries", "gbs_algo_state", "grind_log"}
            <= tables
        )
        self.assertEqual(
            database.execute("SELECT value FROM settings WHERE key='Version'").fetchone(),
            ("30",),
        )
        self.assertEqual(database.execute("SELECT COUNT(*) FROM recipe_data").fetchone(), (6,))
        self.assertEqual(database.execute("SELECT COUNT(*) FROM recipe_entries").fetchone(), (6,))
        self.assertEqual(database.execute("SELECT COUNT(*) FROM gbs_algo_state").fetchone(), (0,))
        self.assertEqual(database.execute("SELECT COUNT(*) FROM grind_log").fetchone(), (0,))

    def test_no_explicit_indexes_or_triggers_and_only_declared_blob_columns(self) -> None:
        database = self.database()
        explicit_indexes = database.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
        ).fetchall()
        triggers = database.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
        self.assertEqual(explicit_indexes, [])
        self.assertEqual(triggers, [])

        blob_columns = set()
        for table in ("recipe_entries", "grind_log", "gbs_algo_state"):
            for _, column, column_type, *_ in database.execute(f"PRAGMA table_info({table})"):
                if column_type.upper() == "BLOB":
                    blob_columns.add(f"{table}.{column}")
        self.assertEqual(
            blob_columns,
            {
                "recipe_entries.recipe_gbs_data",
                "grind_log.grind_debug_data",
                "gbs_algo_state.data",
            },
        )
