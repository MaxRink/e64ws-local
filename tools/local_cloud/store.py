"""SQLite persistence and the append-only audit trail for the local cloud.

Why SQLite
----------

The design (``docs/LOCAL_CLOUD_DESIGN.md`` §4) targets PostgreSQL.  This
skeleton deliberately does not: the point of the exercise is a service that
runs on an owner's laptop with the standard library, so the state lives in one
SQLite file whose schema mirrors the design's tables.  Every column name below
is either the design's own or is marked in a comment as an implementation
addition (``cert_pem`` for D03, ``approved`` for the D01 visibility rule,
``identity`` for D05 idempotency).

Why the audit table has triggers
--------------------------------

The design says "Audit is append-only in the DB and mirrored to a file the API
cannot rewrite" (§8).  An append-only promise enforced only by "the code never
issues UPDATE" is not testable.  Triggers that abort on UPDATE and DELETE make
it a property of the database, and ``tests`` prove it by trying.

Why redaction lives here
------------------------

``DEVICE_SETTINGS`` bodies carry ``productionWifiSsid`` and
``productionWifiPassword`` in plaintext when the device sends them.  Redaction
therefore happens *before* the row is written, at the only place that writes
rows, so no caller can bypass it by forgetting to call a helper.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import uuid
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

#: Design §2.3/§8: the two keys that must never reach storage or a log.
WIFI_SECRET_KEYS = frozenset({"productionWifiSsid", "productionWifiPassword"})

#: Keys that look like secrets.  The design only names the Wi-Fi pair; this
#: pattern is an addition, documented in the design's implementation-status
#: section, because a settings blob may also carry tokens.
SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)",
    re.IGNORECASE,
)

REDACTED = "<redacted>"

#: Recorded event-type literals (design §2.3).  Used only for classification:
#: the key that carries the discriminator is unknown, so a match anywhere in the
#: body is the only evidence-based way to name the type.
EVENT_TYPE_LITERALS = (
    "LOCAL_BREW_EVENT",
    "ERROR_CLEAR",
    "GRIND_COMPLETE",
    "SERVICE_EVENT",
    "DEVICE_SETTINGS",
)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    version     INTEGER NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS device (
    id                TEXT PRIMARY KEY,
    serial            TEXT,
    board_name        TEXT,
    board_rev         TEXT,
    model             TEXT,
    firmware_version  TEXT,
    cloud_device_id   TEXT,
    cert_fingerprint  TEXT,
    m2m_enabled       INTEGER NOT NULL DEFAULT 0,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_credential (
    cert_fingerprint  TEXT PRIMARY KEY,
    device_id         TEXT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    cert_pem          TEXT,
    issued_at         TEXT NOT NULL,
    not_after         TEXT,
    revoked_at        TEXT
);
CREATE INDEX IF NOT EXISTS device_credential_device ON device_credential(device_id);

CREATE TABLE IF NOT EXISTS brew_event (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id         TEXT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    event_uuid        TEXT NOT NULL,
    grind_event_uuid  TEXT,
    duration_ms       INTEGER NOT NULL,
    mass_mg           INTEGER,
    volume_ml         INTEGER,
    source            TEXT NOT NULL DEFAULT 'scale',
    dose_type         TEXT,
    validity          INTEGER,
    stop_target       REAL,
    cloud_date        TEXT NOT NULL,
    approved          INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    UNIQUE(device_id, event_uuid)
);
CREATE INDEX IF NOT EXISTS brew_event_lookup ON brew_event(device_id, cloud_date);

CREATE TABLE IF NOT EXISTS device_event (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,
    identity     TEXT NOT NULL,
    payload      TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    UNIQUE(device_id, identity)
);

CREATE TABLE IF NOT EXISTS device_status (
    device_id     TEXT PRIMARY KEY REFERENCES device(id) ON DELETE CASCADE,
    interval_s    INTEGER,
    online        INTEGER NOT NULL DEFAULT 1,
    last_poll_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recipe (
    id         TEXT PRIMARY KEY,
    name       TEXT,
    model      TEXT,
    payload    TEXT NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recipe_slot (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     TEXT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    slot_id       TEXT NOT NULL,
    store_id      TEXT,
    recipe_id     TEXT,
    payload       TEXT,
    published_at  TEXT NOT NULL,
    UNIQUE(device_id, slot_id)
);

CREATE TABLE IF NOT EXISTS recipe_preset_revision (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    payload      TEXT NOT NULL,
    received_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS onboarding (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    payload      TEXT NOT NULL,
    received_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firmware_artifact (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    filename     TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    bytes        INTEGER,
    version      TEXT NOT NULL,
    model        TEXT,
    source_url   TEXT,
    admitted     INTEGER NOT NULL DEFAULT 0,
    admitted_by  TEXT,
    created_at   TEXT NOT NULL,
    UNIQUE(filename, version)
);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    detail      TEXT NOT NULL,
    source_ip   TEXT
);

CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit is append-only');
END;
"""


def utc_now() -> str:
    """Canonical UTC timestamp used for every stored instant."""

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_utc(moment: datetime) -> str:
    """Normalise to the canonical shape so string comparison is safe."""

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise_iso(value: str) -> str:
    """Parse an ISO-8601 string and return the canonical UTC shape.

    The D01 cursor filter is a string comparison, so every stored ``cloudDate``
    has to be in one shape.  Raises :class:`ValueError` for anything that cannot
    be parsed rather than storing a value the filter would mis-order.
    """

    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    return iso_utc(datetime.fromisoformat(text))


def redact(value: Any) -> Any:
    """Return ``value`` with secret-looking keys replaced.

    Recursive over dicts, lists and tuples.  The two design-named Wi-Fi keys
    are always replaced; anything matching :data:`SECRET_KEY_PATTERN` is
    replaced as well, which is a documented addition.
    """

    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            text = str(key)
            if text in WIFI_SECRET_KEYS or SECRET_KEY_PATTERN.search(text):
                cleaned[key] = REDACTED
            else:
                cleaned[key] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value


def detect_event_type(body: dict[str, Any]) -> str:
    """Name the event type from the recorded literals present in the body.

    The discriminator key is not pinned (design §2.1 D05), so this searches
    values rather than assuming a key.  ``unclassified`` is the honest answer
    when no literal appears; it is not a guess at a missing type.
    """

    found: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str) and value in EVENT_TYPE_LITERALS:
            found.append(value)

    walk(body)
    return found[0] if found else "unclassified"


def event_identity(body: dict[str, Any], raw: bytes) -> str:
    """Stable identity for ``device-event/fire`` idempotency.

    Design §5 D05: "idempotent insert keyed on the event identity available in
    the body".  ``eventUuid`` is the only recorded identity field, so it is used
    when present (top level or under the observed ``payload`` wrapper); when it
    is absent the body digest keeps a replay from duplicating the row without
    inventing a key name.
    """

    for container in (body, body.get("payload") if isinstance(body.get("payload"), dict) else None):
        if isinstance(container, dict):
            candidate = container.get("eventUuid")
            if isinstance(candidate, str) and candidate:
                return candidate
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    """One audit row, also mirrored to the JSONL file."""

    at: str
    actor: str
    action: str
    subject: str
    detail: dict[str, Any]
    source_ip: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "actor": self.actor,
            "action": self.action,
            "subject": self.subject,
            "detail": self.detail,
            "source_ip": self.source_ip,
        }


class Store:
    """One SQLite file plus an optional mirrored audit log.

    A connection is opened per call: the HTTP server is threaded, and an
    ``sqlite3.Connection`` is not thread-safe.  WAL mode keeps concurrent reads
    cheap while the writer serialises.
    """

    def __init__(self, path: str | Path, *, audit_file: str | Path | None = None) -> None:
        self.path = Path(path)
        self.audit_file = Path(audit_file) if audit_file is not None else None
        self._audit_lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.audit_file is not None:
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        self.initialise()

    # -- plumbing ---------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialise(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(_SCHEMA)
            row = connection.execute("SELECT version FROM schema_meta LIMIT 1").fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO schema_meta(version, created_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, utc_now()),
                )

    def close(self) -> None:
        """Nothing is held open between calls; kept for symmetry."""

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        """One connection for callers that need ad-hoc SQL (tests, export)."""

        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def health(self) -> bool:
        try:
            with closing(self._connect()) as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True

    # -- devices and credentials -----------------------------------------

    def ensure_device(self, device_id: str, **fields: Any) -> str:
        """Create the device row if it does not exist; return its id."""

        now = utc_now()
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT id FROM device WHERE id = ?", (device_id,)).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO device(id, serial, board_name, board_rev, model,
                                       firmware_version, cloud_device_id,
                                       cert_fingerprint, m2m_enabled,
                                       first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device_id,
                        fields.get("serial"),
                        fields.get("board_name"),
                        fields.get("board_rev"),
                        fields.get("model"),
                        fields.get("firmware_version"),
                        fields.get("cloud_device_id"),
                        fields.get("cert_fingerprint"),
                        1 if fields.get("m2m_enabled") else 0,
                        now,
                        now,
                    ),
                )
        return device_id

    def enrol_credential(
        self,
        device_id: str,
        cert_fingerprint: str,
        *,
        cert_pem: str | None = None,
        not_after: str | None = None,
    ) -> None:
        """Bind a client certificate fingerprint to a device (design §7)."""

        self.ensure_device(device_id)
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO device_credential(cert_fingerprint, device_id, cert_pem,
                                             issued_at, not_after, revoked_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                ON CONFLICT(cert_fingerprint) DO UPDATE SET
                    device_id = excluded.device_id,
                    cert_pem = COALESCE(excluded.cert_pem, device_credential.cert_pem),
                    not_after = COALESCE(excluded.not_after, device_credential.not_after),
                    revoked_at = NULL
                """,
                (cert_fingerprint, device_id, cert_pem, utc_now(), not_after),
            )
            connection.execute(
                "UPDATE device SET cert_fingerprint = ? WHERE id = ?",
                (cert_fingerprint, device_id),
            )

    def device_by_fingerprint(self, fingerprint: str) -> sqlite3.Row | None:
        with closing(self._connect()) as connection:
            return connection.execute(
                """
                SELECT d.*, c.cert_fingerprint AS presented_fingerprint
                FROM device_credential c
                JOIN device d ON d.id = c.device_id
                WHERE c.cert_fingerprint = ? AND c.revoked_at IS NULL
                """,
                (fingerprint,),
            ).fetchone()

    def device(self, device_id: str) -> sqlite3.Row | None:
        with closing(self._connect()) as connection:
            return connection.execute("SELECT * FROM device WHERE id = ?", (device_id,)).fetchone()

    def certificates_for(self, device_id: str) -> list[sqlite3.Row]:
        with closing(self._connect()) as connection:
            return connection.execute(
                """
                SELECT * FROM device_credential
                WHERE device_id = ? AND revoked_at IS NULL AND cert_pem IS NOT NULL
                ORDER BY issued_at DESC
                """,
                (device_id,),
            ).fetchall()

    def touch_device(self, device_id: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute("UPDATE device SET last_seen = ? WHERE id = ?", (utc_now(), device_id))

    # -- brew events (D01) -------------------------------------------------

    def add_brew_event(
        self,
        *,
        device_id: str,
        duration_ms: int,
        event_uuid: str | None = None,
        grind_event_uuid: str | None = None,
        mass_mg: int | None = None,
        volume_ml: int | None = None,
        source: str = "scale",
        dose_type: str | None = None,
        validity: bool | None = None,
        stop_target: float | None = None,
        cloud_date: str | None = None,
        approved: bool = True,
    ) -> dict[str, Any]:
        """Insert one brew event and return the row as a plain dict."""

        self.ensure_device(device_id)
        uuid_value = event_uuid or str(uuid.uuid4())
        if validity is None:
            validity = source == "scale"
        if dose_type is None and source == "scale":
            dose_type = "MassType"
        moment = normalise_iso(cloud_date) if cloud_date else utc_now()
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO brew_event(device_id, event_uuid, grind_event_uuid,
                                       duration_ms, mass_mg, volume_ml, source,
                                       dose_type, validity, stop_target, cloud_date,
                                       approved, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, event_uuid) DO NOTHING
                """,
                (
                    device_id,
                    uuid_value,
                    grind_event_uuid,
                    int(duration_ms),
                    mass_mg,
                    volume_ml,
                    source,
                    dose_type,
                    None if validity is None else (1 if validity else 0),
                    stop_target,
                    moment,
                    1 if approved else 0,
                    utc_now(),
                ),
            )
            row = connection.execute(
                "SELECT * FROM brew_event WHERE device_id = ? AND event_uuid = ?",
                (device_id, uuid_value),
            ).fetchone()
        return dict(row) if row is not None else {}

    def visible_brew_events(
        self, device_id: str, *, since: datetime, limit: int = 500
    ) -> list[sqlite3.Row]:
        """Events the local cloud may hand out on D01.

        Three filters, all from the design's D01 rule: the event must come from
        an owner-approved source, its ``cloudDate`` must be at or after the
        device cursor, and - because the firmware's own consumer ignores shorter
        events (API_REFERENCE.md §4.6) - its duration must be strictly greater
        than 10 000 ms.
        """

        cursor = iso_utc(since)
        with closing(self._connect()) as connection:
            return connection.execute(
                """
                SELECT * FROM brew_event
                WHERE device_id = ?
                  AND approved = 1
                  AND cloud_date >= ?
                  AND duration_ms > 10000
                ORDER BY cloud_date ASC, id ASC
                LIMIT ?
                """,
                (device_id, cursor, limit),
            ).fetchall()

    # -- device events and status (D05, D06) ------------------------------

    def record_device_event(self, device_id: str, body: dict[str, Any], raw: bytes) -> tuple[bool, int, str]:
        """Insert one event idempotently; return ``(inserted, id, type)``."""

        event_type = detect_event_type(body)
        identity = event_identity(body, raw)
        cleaned = redact(body)
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT INTO device_event(device_id, type, identity, payload, received_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_id, identity) DO NOTHING
                """,
                (device_id, event_type, identity, json.dumps(cleaned, sort_keys=True), utc_now()),
            )
            row = connection.execute(
                "SELECT id FROM device_event WHERE device_id = ? AND identity = ?",
                (device_id, identity),
            ).fetchone()
        return (cursor.rowcount == 1, int(row["id"]) if row is not None else 0, event_type)

    def record_status(self, device_id: str, interval_s: int | None) -> None:
        self.ensure_device(device_id)
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO device_status(device_id, interval_s, online, last_poll_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    interval_s = COALESCE(excluded.interval_s, device_status.interval_s),
                    online = 1,
                    last_poll_at = excluded.last_poll_at
                """,
                (device_id, interval_s, utc_now()),
            )

    def status_for(self, device_id: str) -> sqlite3.Row | None:
        with closing(self._connect()) as connection:
            return connection.execute(
                "SELECT * FROM device_status WHERE device_id = ?", (device_id,)
            ).fetchone()

    # -- recipes (D04, D08) ----------------------------------------------

    def publish_recipe_slot(
        self,
        *,
        device_id: str,
        slot_id: str,
        recipe_id: str | None = None,
        store_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.ensure_device(device_id)
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO recipe_slot(device_id, slot_id, store_id, recipe_id, payload, published_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, slot_id) DO UPDATE SET
                    store_id = excluded.store_id,
                    recipe_id = excluded.recipe_id,
                    payload = excluded.payload,
                    published_at = excluded.published_at
                """,
                (
                    device_id,
                    slot_id,
                    store_id,
                    recipe_id,
                    json.dumps(redact(payload or {}), sort_keys=True),
                    utc_now(),
                ),
            )
            row = connection.execute(
                "SELECT * FROM recipe_slot WHERE device_id = ? AND slot_id = ?",
                (device_id, slot_id),
            ).fetchone()
        return dict(row) if row is not None else {}

    def recipe_slots(self, device_id: str) -> list[sqlite3.Row]:
        with closing(self._connect()) as connection:
            return connection.execute(
                "SELECT * FROM recipe_slot WHERE device_id = ? ORDER BY slot_id", (device_id,)
            ).fetchall()

    def record_recipe_preset(self, device_id: str, body: dict[str, Any]) -> int:
        self.ensure_device(device_id)
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "INSERT INTO recipe_preset_revision(device_id, payload, received_at) VALUES (?, ?, ?)",
                (device_id, json.dumps(redact(body), sort_keys=True), utc_now()),
            )
        return int(cursor.lastrowid or 0)

    def recipe_preset_revisions(self, device_id: str) -> list[sqlite3.Row]:
        with closing(self._connect()) as connection:
            return connection.execute(
                "SELECT * FROM recipe_preset_revision WHERE device_id = ? ORDER BY id",
                (device_id,),
            ).fetchall()

    # -- onboarding and firmware (D09, D07) ------------------------------

    def record_onboarding(self, device_id: str, body: dict[str, Any]) -> int:
        self.ensure_device(device_id)
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "INSERT INTO onboarding(device_id, payload, received_at) VALUES (?, ?, ?)",
                (device_id, json.dumps(redact(body), sort_keys=True), utc_now()),
            )
        return int(cursor.lastrowid or 0)

    def onboarding_records(self, device_id: str) -> list[sqlite3.Row]:
        with closing(self._connect()) as connection:
            return connection.execute(
                "SELECT * FROM onboarding WHERE device_id = ? ORDER BY id", (device_id,)
            ).fetchall()

    def add_firmware_artifact(
        self,
        *,
        filename: str,
        sha256: str,
        version: str,
        model: str | None = None,
        byte_count: int | None = None,
        source_url: str | None = None,
        admitted: bool = False,
        admitted_by: str | None = None,
    ) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO firmware_artifact(filename, sha256, bytes, version, model,
                                              source_url, admitted, admitted_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(filename, version) DO UPDATE SET
                    sha256 = excluded.sha256,
                    admitted = excluded.admitted,
                    admitted_by = excluded.admitted_by
                """,
                (
                    filename,
                    sha256,
                    byte_count,
                    version,
                    model,
                    source_url,
                    1 if admitted else 0,
                    admitted_by,
                    utc_now(),
                ),
            )
            row = connection.execute(
                "SELECT * FROM firmware_artifact WHERE filename = ? AND version = ?",
                (filename, version),
            ).fetchone()
        return dict(row) if row is not None else {}

    def admitted_artifact_above(self, current_version: str | None) -> sqlite3.Row | None:
        """The highest admitted artifact whose version differs from the device's.

        "Offers the highest admitted version" (design §3, firmware artifact
        distribution).  Version comparison is a plain string compare: no version
        scheme is recorded, and pretending to understand ``V01.16-24`` ordering
        would be an invention.  The skeleton therefore offers any admitted
        artifact whose version text differs from ``current_version`` and lets
        the owner admit one at a time.
        """

        with closing(self._connect()) as connection:
            if current_version:
                return connection.execute(
                    """
                    SELECT * FROM firmware_artifact
                    WHERE admitted = 1 AND version <> ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (current_version,),
                ).fetchone()
            return connection.execute(
                "SELECT * FROM firmware_artifact WHERE admitted = 1 ORDER BY id DESC LIMIT 1"
            ).fetchone()

    # -- audit ------------------------------------------------------------

    def audit(
        self,
        *,
        actor: str,
        action: str,
        subject: str,
        detail: dict[str, Any] | None = None,
        source_ip: str | None = None,
    ) -> AuditEntry:
        """Append one audit row and mirror it to the JSONL file if configured."""

        entry = AuditEntry(
            at=utc_now(),
            actor=actor,
            action=action,
            subject=subject,
            detail=redact(detail or {}),
            source_ip=source_ip,
        )
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT INTO audit(at, actor, action, subject, detail, source_ip) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    entry.at,
                    entry.actor,
                    entry.action,
                    entry.subject,
                    json.dumps(entry.detail, sort_keys=True),
                    entry.source_ip,
                ),
            )
        if self.audit_file is not None:
            line = json.dumps(entry.as_dict(), sort_keys=True) + "\n"
            with self._audit_lock:
                with self.audit_file.open("a", encoding="utf-8") as handle:
                    handle.write(line)
        return entry

    def audit_rows(self, limit: int = 50) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [dict(row) for row in rows]

    # -- export -----------------------------------------------------------

    _EXPORT_TABLES = (
        "device",
        "device_credential",
        "brew_event",
        "device_event",
        "device_status",
        "recipe",
        "recipe_slot",
        "recipe_preset_revision",
        "onboarding",
        "firmware_artifact",
        "audit",
    )

    def export(self) -> dict[str, Any]:
        """Versioned logical export (design §4, ``local-cloud-export/1``)."""

        tables: dict[str, list[dict[str, Any]]] = {}
        with closing(self._connect()) as connection:
            for table in self._EXPORT_TABLES:
                rows = connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                tables[table] = [dict(row) for row in rows]
        return {
            "schema": "local-cloud-export/1",
            "generated_at": utc_now(),
            "tables": tables,
        }
