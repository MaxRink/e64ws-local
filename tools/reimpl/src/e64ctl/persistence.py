"""Persistence: the SQLite database and JSON files the vendor writes.

Schema sources: docs/SQLITE_SCHEMA.md (decoded from the Qt resource bundle)
and docs/REST_API.md.  The tables reproduced here are the ones this service
actually writes or exports:

* ``settings(key, value)``                  - ConfigManager key/value store
* ``grind_log``                             - one row per finished grind
* ``brew_events``                           - AddBrewEvent / cloud events
* ``event_types`` / ``event_log``           - service events
* ``alert_types`` / ``alert_log``           - alerts
* ``recipe_data`` / ``recipe_entries`` / ``portafilters`` - minimal shape

The REST ``download_machine_logs`` query in the vendor joins ``grind_log`` with
``recipe_data``; here the join columns are materialised on ``grind_log`` so the
CSV header and row order match.  That is a documented simplification, not a
schema claim.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import struct
import time
import zlib
from typing import Any, Iterable, Optional

GRIND_CSV_COLUMNS = [
    "grind_id", "grind_uuid", "grind_date_time", "recipe_index",
    "recipe_cpr_id", "recipe_data_id", "grind_ddd", "grind_duration",
    "grind_duration_noload", "grind_weight", "grind_successfull",
    "grind_trigger_id", "grind_trigger", "recipe_gbs_enabled",
    "grind_debug_data", "recipe_uuid", "recipe_mode_id", "recipe_mode",
    "recipe_amount", "recipe_type_id", "recipe_type", "recipe_icon_id",
    "recipe_icon", "recipe_coarseness", "recipe_brew_time",
    "recipe_brew_weight",
]

SERVICE_CSV_COLUMNS = [
    "event_id", "event_type_id", "event_type", "event_date_time",
    "event_details",
]

_SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS "settings" (
    "key"   TEXT NOT NULL PRIMARY KEY,
    "value" TEXT
);

CREATE TABLE IF NOT EXISTS "grind_log" (
    "grind_id"            INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "grind_uuid"          TEXT    NOT NULL,
    "grind_date_time"     TEXT    NOT NULL,
    "recipe_index"        INTEGER NOT NULL DEFAULT 0,
    "recipe_cpr_id"       TEXT,
    "recipe_data_id"      INTEGER,
    "grind_ddd"           INTEGER,
    "grind_duration"      INTEGER,
    "grind_duration_noload" INTEGER,
    "grind_weight"        INTEGER,
    "grind_successfull"   INTEGER NOT NULL DEFAULT 0,
    "grind_trigger_id"    INTEGER,
    "grind_trigger"       TEXT,
    "recipe_gbs_enabled"  INTEGER,
    "grind_debug_data"    BLOB,
    "recipe_uuid"         TEXT,
    "recipe_mode_id"      INTEGER,
    "recipe_mode"         TEXT,
    "recipe_amount"       INTEGER,
    "recipe_type_id"      INTEGER,
    "recipe_type"         TEXT,
    "recipe_icon_id"      INTEGER,
    "recipe_icon"         TEXT,
    "recipe_coarseness"   INTEGER,
    "recipe_brew_time"    INTEGER,
    "recipe_brew_weight"  INTEGER
);

CREATE TABLE IF NOT EXISTS "brew_events" (
    "brew_id"           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "brew_uuid"         TEXT    NOT NULL,
    "brew_device_id"    TEXT    NOT NULL,
    "brew_group"        TEXT    NOT NULL,
    "brew_dose_index"   INTEGER NOT NULL,
    "brew_dose_type_id" INTEGER NOT NULL,
    "brew_stop_target"  INTEGER NOT NULL,
    "brew_validity"     INTEGER NOT NULL,
    "brew_duration"     INTEGER NOT NULL,
    "brew_volume"       INTEGER NOT NULL,
    "brew_mass"         INTEGER NOT NULL,
    "grind_id"          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS "event_types" (
    "event_type_id"   INTEGER NOT NULL PRIMARY KEY,
    "event_type_name" VARCHAR(20) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS "event_log" (
    "event_id"        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "event_type_id"   INTEGER NOT NULL,
    "event_date_time" TEXT NOT NULL,
    "event_details"   TEXT
);

CREATE TABLE IF NOT EXISTS "alert_types" (
    "alert_type_id"   INTEGER NOT NULL PRIMARY KEY,
    "alert_type_name" VARCHAR(20) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS "alert_log" (
    "alert_id"        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "alert_type_id"   INTEGER NOT NULL,
    "alert_date_time" TEXT NOT NULL,
    "alert_details"   TEXT,
    "alert_active"    INTEGER
);

CREATE TABLE IF NOT EXISTS "recipe_data" (
    "recipe_data_id"   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "recipe_uuid"      TEXT,
    "recipe_mode_id"   INTEGER,
    "recipe_amount"    INTEGER,
    "recipe_type_id"   INTEGER,
    "recipe_icon_id"   INTEGER,
    "recipe_coarseness" INTEGER,
    "recipe_brew_time" INTEGER,
    "recipe_brew_weight" INTEGER
);

CREATE TABLE IF NOT EXISTS "recipe_entries" (
    "recipe_index"    INTEGER NOT NULL PRIMARY KEY,
    "recipe_data_id"  INTEGER,
    "recipe_active"   INTEGER,
    "recipe_cpr_id"   TEXT,
    "recipe_gbs_data" BLOB
);

CREATE TABLE IF NOT EXISTS "portafilters" (
    "portafilter_id"  INTEGER NOT NULL PRIMARY KEY,
    "weight"          INTEGER,
    "weight_tolerance" INTEGER,
    "recipe_index"    INTEGER
);

CREATE TABLE IF NOT EXISTS "gbs_algo_state" (
    "brew_device" TEXT,
    "data" TEXT,
    "group_head" TEXT,
    "recipe_index" TEXT,
    "_pk" INTEGER PRIMARY KEY AUTOINCREMENT
);

-- Remaining tables from the recovered vendor master schema (SQLITE_SCHEMA.md
-- and sqlite_master of the pristine V01.16-24 database).  They are empty in
-- the fixture, but their presence is part of the persistent surface.
CREATE TABLE IF NOT EXISTS "brew_dose_types" (
    "brew_dose_type_id" INTEGER NOT NULL,
    "brew_dose_type_name" TEXT NOT NULL UNIQUE,
    PRIMARY KEY("brew_dose_type_id")
);
CREATE TABLE IF NOT EXISTS "grind_trigger_modes" (
    "grind_trigger_id" INTEGER NOT NULL,
    "grind_trigger_name" TEXT NOT NULL UNIQUE,
    PRIMARY KEY("grind_trigger_id")
);
CREATE TABLE IF NOT EXISTS "recipe_icons" (
    "recipe_icon_id" INTEGER NOT NULL,
    "recipe_icon_name" VARCHAR(20) NOT NULL UNIQUE,
    PRIMARY KEY("recipe_icon_id")
);
CREATE TABLE IF NOT EXISTS "recipe_modes" (
    "recipe_mode_id" INTEGER NOT NULL,
    "recipe_mode_name" VARCHAR(20) NOT NULL UNIQUE,
    "description" VARCHAR(30),
    PRIMARY KEY("recipe_mode_id")
);
CREATE TABLE IF NOT EXISTS "recipe_types" (
    "recipe_type_id" INTEGER NOT NULL,
    "recipe_type_name" TEXT NOT NULL UNIQUE,
    PRIMARY KEY("recipe_type_id")
);
CREATE TABLE IF NOT EXISTS "cloudsettingsmenu" ("_pk" INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE TABLE IF NOT EXISTS "event" ("_pk" INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE TABLE IF NOT EXISTS "gbs" ("_pk" INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE TABLE IF NOT EXISTS "grindcontroller" ("_pk" INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE TABLE IF NOT EXISTS "recipe" ("_pk" INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE TABLE IF NOT EXISTS "recipechangesucceeded" ("_pk" INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE TABLE IF NOT EXISTS "recipes" ("sync" TEXT, "_pk" INTEGER PRIMARY KEY AUTOINCREMENT);
"""

_EVENT_SEED = [
    (1, "POWER_ON"), (2, "POWER_OFF"), (3, "GRIND_START"), (4, "GRIND_END"),
    (5, "CALIBRATION"), (6, "TARA"), (7, "FACTORY_RESET"), (8, "UPDATE"),
    (9, "WIFI"), (10, "ERROR"),
]


def _csv_field(value: Any) -> str:
    """One field as the sqlite3 shell's CSV mode renders it."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    elif isinstance(value, bool):
        text = "1" if value else "0"
    elif isinstance(value, float):
        text = f"{value:.15g}"
    else:
        text = str(value)
    if (any(ch in text for ch in ('"', ",", "\n", "\r"))
            or text[:1] == " " or text[-1:] == " "):
        return '"' + text.replace('"', '""') + '"'
    return text


def _infozip_archive(entries: list[tuple[str, bytes]], now: float) -> bytes:
    """Byte layout produced by Info-ZIP 3.0 ``zip -j`` (appended twice).

    The vendor writes each CSV with a separate ``zip -j`` call.  Empty files
    are stored; non-empty ones are deflated at level 6, which matches zlib's
    raw deflate stream byte-for-byte.  Each member carries the UT (mtime/atime)
    and ux (uid/gid) extra fields that Info-ZIP adds on Linux.
    """
    tm = time.localtime(now)
    dos_time = (tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec // 2)
    dos_date = ((max(tm.tm_year, 1980) - 1980) << 9) | (tm.tm_mon << 5) | tm.tm_mday
    mtime = int(now)
    uid = os.getuid() if hasattr(os, "getuid") else 0
    gid = os.getgid() if hasattr(os, "getgid") else 0
    # UT: flags=3, mtime, atime.  ux: version=1, uid, gid.
    local_extra = (struct.pack("<HHBII", 0x5455, 9, 3, mtime, mtime)
                   + struct.pack("<HHBBIBI", 0x7875, 11, 1, 4, uid, 4, gid))
    central_extra = (struct.pack("<HHBI", 0x5455, 5, 3, mtime)
                     + struct.pack("<HHBBIBI", 0x7875, 11, 1, 4, uid, 4, gid))

    local_parts: list[bytes] = []
    central_parts: list[bytes] = []
    offset = 0
    for name, data in entries:
        raw_name = name.encode("ascii")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        if data:
            compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
            compressed = compressor.compress(data) + compressor.flush()
            method = 8
            if len(compressed) >= len(data):
                compressed, method = data, 0
        else:
            compressed, method = b"", 0
        version = 20 if method == 8 else 10
        text = bool(data) and all(
            byte in (9, 10, 13) or 32 <= byte < 127 or byte >= 128
            for byte in data)
        local = struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, version, 0, method, dos_time,
            dos_date, crc, len(compressed), len(data), len(raw_name),
            len(local_extra)) + raw_name + local_extra
        central = struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 0x031E, version, 0, method,
            dos_time, dos_date, crc, len(compressed), len(data),
            len(raw_name), len(central_extra), 0, 0, 1 if text else 0,
            0o100644 << 16, offset) + raw_name + central_extra
        local_parts.append(local + compressed)
        central_parts.append(central)
        offset += len(local) + len(compressed)
    directory = b"".join(central_parts)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries),
                      len(entries), len(directory), offset, 0)
    return b"".join(local_parts) + directory + end


class Persistence:
    """Filesystem root + SQLite handle used by the handlers and REST routes."""

    def __init__(self, root: str, clock=time.time) -> None:
        self.root = os.path.abspath(root)
        self.clock = clock
        os.makedirs(os.path.join(self.root, "db"), exist_ok=True)
        os.makedirs(os.path.join(self.root, "tmp"), exist_ok=True)
        self.db_path = os.path.join(self.root, "db", "HsgSqlite.db")
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self._seed()

    # -- paths ------------------------------------------------------------
    def path(self, virtual: str) -> str:
        """Map a vendor absolute path (``/db/x``, ``/tmp/y``) under root."""
        return os.path.join(self.root, virtual.lstrip("/"))

    def write_json(self, virtual: str, payload: Any) -> str:
        target = self.path(virtual)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return target

    def read_json(self, virtual: str, default: Any = None) -> Any:
        try:
            with open(self.path(virtual), "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (FileNotFoundError, ValueError):
            return default

    def read_text(self, virtual: str, default: Optional[str] = None) -> Optional[str]:
        try:
            with open(self.path(virtual), "r", encoding="utf-8") as handle:
                return handle.read()
        except OSError:
            return default

    # -- settings ---------------------------------------------------------
    def _seed(self) -> None:
        with self.conn:
            for event_type_id, name in _EVENT_SEED:
                self.conn.execute(
                    "INSERT OR IGNORE INTO event_types(event_type_id,"
                    " event_type_name) VALUES(?,?)", (event_type_id, name))
            for key, value in _defaults().items():
                self.conn.execute(
                    "INSERT OR IGNORE INTO settings(key, value) VALUES(?,?)",
                    (key, value))

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.conn.execute(
            "SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: Any) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)",
                (key, str(value)))

    # -- state snapshots --------------------------------------------------
    def save_config(self, state: Any) -> None:
        values = dict(state.config_settings)
        # The state field is authoritative for the driver-state value.  The
        # vendor database stores micrograms, not the WSS "0.536960g" form.
        values["Grinding.OvershootWeight"] = (
            f"{state.grind.overshoot_weight_gr:.6f}g")
        for key, value in values.items():
            self.set_setting(key, _db_value(
                key, json.dumps(value) if isinstance(value, (dict, list))
                else value))

    def save_driver_config(self, state: Any) -> None:
        self.write_json("/db/driverConfig.json", state.driver_config_json())

    def save_wifi_config(self, state: Any) -> None:
        payload = {
            "apIp": "192.168.4.1",
            "apPassword": "virtual-grinder",
            "apSsid": "HemroHsg-" + state.machine.serial_number,
            "mode": _wifi_mode_name(state.esp.mode),
            "staDhcp": state.sta.dhcp,
            "staPassword": state.sta.password,
            "staSsid": state.sta.ssid,
            "staStaticDns": state.sta.dns,
            "staStaticGateway": state.sta.gateway,
            "staStaticIp": state.sta.ip,
            "staStaticNetmask": state.sta.netmask,
        }
        self.write_json("/db/wifiConfig.json", payload)

    def save_logs(self, state: Any) -> None:
        self.write_json("/db/logMessages.json",
                        [entry.as_json() for entry in state.logs])

    def clear_logs(self) -> None:
        try:
            os.unlink(self.path("/db/logMessages.json"))
        except FileNotFoundError:
            pass

    def save_state_view(self, state: Any) -> None:
        """Snapshot used by tools/guest_shim.py (the host stands in for sysfs)."""
        self.write_json("/state.json", {
            "backlight_brightness": state.backlight_brightness,
            "backlight_power": state.backlight_power,
            "backlight_bl_power": state.backlight_bl_power,
            "nozzle_light": state.nozzle_light,
            "language": state.language,
            "grind_state": state.grind.state,
            "dd_value": state.agsa.dd_value,
            "esp_sdio_state": state.esp.sdio_status,
            "fans": [{"duty": fan.duty, "rpm": fan.tacho_rpm}
                     for fan in state.fans],
        })

    def write_static_config(self, state: Any) -> None:
        """Stable /db JSON files the vendor keeps (sorted, deterministic)."""
        # HsgConfig.json mirrors the driver configuration; the vendor writes
        # it pretty-printed (59 key lines, including "id").
        with open(self.path("/db/HsgConfig.json"), "w",
                  encoding="utf-8") as handle:
            json.dump(state.driver_config_json(), handle, indent=4)
            handle.write("\n")
        counters = self.path("/db/machineCounters.json")
        if not os.path.exists(counters):
            # Pretty layout matters: scenario 02 removes the powerOnCycles
            # line with grep and compares the remaining trailing comma.
            with open(counters, "w", encoding="utf-8") as handle:
                handle.write(
                    '{\n'
                    '  "discUsageTime100ms": 0,\n'
                    '  "motorRunsCount": 0,\n'
                    '  "motorTime100ms": 0,\n'
                    '  "powerOnCycles": 1\n'
                    '}\n')
        if not os.path.exists(self.path("/db/wifiConfig.json")):
            self.save_wifi_config(state)

    # -- grind log --------------------------------------------------------
    def add_grind(self, state: Any) -> int:
        grind = state.grind
        row = {
            # The live vendor database stores the 36-character UUID text as a
            # BLOB in this otherwise TEXT-declared column.
            "grind_uuid": str(__import__("uuid").uuid4()).encode("ascii"),
            "grind_date_time": state.hmi_time(),
            "recipe_index": 0,
            "recipe_cpr_id": "",
            "recipe_data_id": 0,
            "grind_ddd": int(state.agsa.dd_value),
            "grind_duration": int(grind.motor_run_time_ms),
            "grind_duration_noload": int(grind.motor_run_time_ms),
            "grind_weight": int(round(grind.result_weight_gr * 1000)),
            "grind_successfull": 0 if grind.failure else 1,
            "grind_trigger_id": 1,
            "grind_trigger": grind.mode or "manual",
            "recipe_gbs_enabled": 1 if state.config_settings.get("gbsEnabled") else 0,
            "grind_debug_data": None,
            "recipe_uuid": "",
            "recipe_mode_id": 0,
            "recipe_mode": "",
            "recipe_amount": 0,
            "recipe_type_id": 0,
            "recipe_type": "",
            "recipe_icon_id": 0,
            "recipe_icon": "",
            "recipe_coarseness": int(state.agsa.dd_value),
            "recipe_brew_time": 0,
            "recipe_brew_weight": 0,
        }
        columns = ",".join(row)
        placeholders = ",".join("?" for _ in row)
        with self.conn:
            cursor = self.conn.execute(
                f"INSERT INTO grind_log({columns}) VALUES({placeholders})",
                tuple(row.values()))
        return int(cursor.lastrowid)

    def add_brew_event(self, event: dict[str, Any]) -> int:
        row = (event.get("grindUuid", ""), event.get("machineName", ""),
               event.get("groupHead", ""), int(event.get("doseIndex", 0)),
               int(event.get("recipeType", 3)), 0,
               1 if event.get("validity") else 0,
               int(event.get("brewTimeMs", 0)), 0,
               int(event.get("brewWeightMg", 0)), 0)
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO brew_events(brew_uuid, brew_device_id, brew_group,"
                " brew_dose_index, brew_dose_type_id, brew_stop_target,"
                " brew_validity, brew_duration, brew_volume, brew_mass, grind_id)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)", row)
        return int(cursor.lastrowid)

    def add_event(self, event_type_id: int, details: str = "") -> int:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.clock()))
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO event_log(event_type_id, event_date_time,"
                " event_details) VALUES(?,?,?)", (event_type_id, stamp, details))
        return int(cursor.lastrowid)

    # -- exports ----------------------------------------------------------
    def grind_rows(self, limit: int = 5000) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            f"SELECT {', '.join(GRIND_CSV_COLUMNS)} FROM grind_log"
            " ORDER BY grind_id DESC LIMIT ?", (limit,)))

    def service_rows(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT e.event_id AS event_id, e.event_type_id AS event_type_id,"
            " t.event_type_name AS event_type,"
            " e.event_date_time AS event_date_time,"
            " e.event_details AS event_details"
            " FROM event_log e LEFT JOIN event_types t"
            " ON t.event_type_id = e.event_type_id"
            " ORDER BY e.event_id DESC"))

    def export_csv(self, rows: Iterable[sqlite3.Row],
                   columns: list[str]) -> str:
        """``sqlite3 -header -csv`` output, including its empty-result quirk.

        The vendor runs ``sqlite3 -header -csv <db> "<query>" > file``.  The
        header is written with the first row, so an empty result set leaves a
        zero-byte file - not a header-only CSV.  The pristine database has no
        grind rows and no event rows, so both vendor CSVs are empty.  (The
        service query also names ``event_log.event_id``, which the shipped
        schema spells ``_pk``; it fails either way.)
        """
        rows = list(rows)
        if not rows:
            return ""
        lines = [",".join(_csv_field(name) for name in columns)]
        for row in rows:
            lines.append(",".join(_csv_field(row[column]) for column in columns))
        return "\r\n".join(lines) + "\r\n"

    def build_log_zip(self, serial: str = "000000") -> tuple[str, bytes]:
        now = self.clock()
        stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(now))
        base = f"HemroHsgMachineLogs_SN{serial}_{stamp}"
        grind_name = f"HemroHsgGrindLogs_SN{serial}_{stamp}.csv"
        service_name = f"HemroHsgServiceLogs_SN{serial}_{stamp}.csv"
        grind_csv = self.export_csv(self.grind_rows(), GRIND_CSV_COLUMNS)
        service_csv = self.export_csv(self.service_rows(), SERVICE_CSV_COLUMNS)
        data = _infozip_archive(
            [(grind_name, grind_csv.encode("utf-8")),
             (service_name, service_csv.encode("utf-8"))], now)
        target = self.path(f"/tmp/{base}.zip")
        with open(target, "wb") as handle:
            handle.write(data)
        # The vendor export leaves the two CSVs next to the ZIP in /tmp.
        for name, text in ((grind_name, grind_csv),
                           (service_name, service_csv)):
            path = self.path(f"/tmp/{name}")
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
            os.utime(path, (now, now))
        os.utime(target, (now, now))
        return target, data

    def checkpoint_database(self) -> bytes:
        self.conn.execute("PRAGMA wal_checkpoint(FULL)")
        with open(self.db_path, "rb") as handle:
            return handle.read()

    def close(self) -> None:
        self.conn.close()


def _wifi_mode_name(mode: int) -> str:
    return {0: "Off", 1: "Station", 2: "Access Point",
            3: "Access Point/Station"}.get(int(mode), "Off")


def _db_value(key: str, value: Any) -> Any:
    """Convert a WSS/config-manager value to the vendor database form.

    Only conversions backed by a live observation are applied:
    ``Grinding.OvershootWeight`` is stored in micrograms and
    ``Standby.ActivationTimeSec`` in whole seconds.  Booleans are persisted as
    lower-case ``true``/``false``.
    """
    if key == "Grinding.OvershootWeight" and isinstance(value, str):
        if value.endswith("g"):
            try:
                return str(int(round(float(value[:-1]) * 1_000_000)))
            except ValueError:
                pass
    if key == "Standby.ActivationTimeSec" and isinstance(value, str):
        if value.endswith("s"):
            try:
                return str(int(round(float(value[:-1]))))
            except ValueError:
                pass
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _defaults() -> dict[str, str]:
    # Exact vendor pristine ``settings`` rows (the fixture owner hash is added
    # by the reset adapter, matching the vendor owner.sql step).
    from .defaults import PRISTINE_SETTINGS
    return dict(PRISTINE_SETTINGS)
