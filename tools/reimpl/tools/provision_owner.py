#!/usr/bin/env python3
"""Provision the fixture owner password and reset transient state.

Mirrors the vendor target's ``reset_cmd`` from /tmp/equiv/targets/vendor.json:
the equivalence scenarios log in as Owner with password ``e64-equivalence``,
which the pristine vendor database does not contain (it is injected as
``Role.Owner.LoginData``).  Run this before a scenario run.

    python3 tools/provision_owner.py --state-dir /tmp/e64ctl \\
        --password e64-equivalence
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from e64ctl.rest import pwhash  # noqa: E402

SALT = "e64fixture"
ROUNDS = 5000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", default="/tmp/e64ctl")
    parser.add_argument("--password", default="e64-equivalence")
    parser.add_argument("--reset", action="store_true",
                        help="delete the database and transient files first")
    args = parser.parse_args()

    db_dir = os.path.join(args.state_dir, "db")
    os.makedirs(db_dir, exist_ok=True)
    if args.reset:
        for name in ("HsgSqlite.db", "HsgSqlite.db-wal", "HsgSqlite.db-shm"):
            try:
                os.unlink(os.path.join(db_dir, name))
            except FileNotFoundError:
                pass
        tmp_dir = os.path.join(args.state_dir, "tmp")
        if os.path.isdir(tmp_dir):
            for name in os.listdir(tmp_dir):
                if name.startswith("tok_"):
                    os.unlink(os.path.join(tmp_dir, name))

    # The service creates the schema on start; create the settings table here
    # so provisioning works before the first run as well.
    connection = sqlite3.connect(os.path.join(db_dir, "HsgSqlite.db"))
    connection.execute(
        'CREATE TABLE IF NOT EXISTS "settings" ("key" TEXT NOT NULL PRIMARY KEY,'
        ' "value" TEXT)')
    encoded = f"1${ROUNDS}${SALT}${pwhash(args.password, SALT, ROUNDS)}"
    connection.execute(
        "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
        ("Role.Owner.LoginData", encoded))
    connection.commit()
    connection.close()
    print(f"provisioned Role.Owner.LoginData in {db_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
