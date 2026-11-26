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

Why the audit table has triggers, and what the JSONL mirror is not
---------------------------------------------------------------

The design says "Audit is append-only in the DB and mirrored to a file the API
cannot rewrite" (§8).  Only the first half of that is true, and the second half
was never true:

* the **table** is append-only as a property of the database: triggers abort
  UPDATE and DELETE, and the tests prove it by trying both;
* the **JSONL mirror** is written by this process with ``open(path, "a")``.  The
  same process can therefore open the same path for writing and rewrite it, and
  nothing signs it, ships it off-host or compares it against the table.  It is
  append-only *by convention* - one ``write()`` of one complete line under a
  lock, then ``flush()`` and ``os.fsync()`` so a crash cannot lose a line that
  the caller was told was written.  It is not tamper-evident, and the
  documentation now says so (§8, "Audit").
* there is no retention: the file grows for as long as the stack runs.  Rotating
  it from inside the API is the one change that would *create* a way to drop
  rows, so it is left to the supervisor that owns the volume rather than done
  here as a half-measure (README.md, "What this directory does not do").

Why redaction lives here
------------------------

``DEVICE_SETTINGS`` bodies carry ``productionWifiSsid`` and
``productionWifiPassword`` in plaintext when the device sends them.  Redaction
therefore happens *before* the row is written, at the only place that writes
rows, so a caller cannot forget to call a helper.

That is not the same thing as "cannot be bypassed", which this module used to
claim.  :func:`redact` matches key *names*, so what it catches depends entirely
on the secret sitting under a recognised name in a shape it knows how to walk.

What it now walks, because a settings blob arrives in all of these shapes:

* nested dicts, lists and tuples;
* a string that decodes to a JSON object or array, including one that has been
  JSON-encoded twice (``json.dumps(json.dumps(...))``);
* a form-urlencoded string (``a=1&productionWifiPassword=x``);
* an XML fragment, by element and by attribute name.

What it still does **not** catch, stated here so nobody reads this as a
guarantee:

* a secret under a name the vocabulary does not reach.  ``key`` only matches as
  a whole word or as the tail of a snake/kebab name, so ``someKey``,
  ``wifiKeyBlob`` and ``primaryKey`` are *not* redacted while ``key``,
  ``api_key`` and ``some-key`` are.  ``credential``, ``password``,
  ``passphrase``, ``psk``, ``pwd``, ``secret`` and ``token`` are substring
  matches, so ``wifiCredentialBlob`` *is* redacted;
* a secret with no name at all - a bare token in a free-text field;
* an encoding not listed above: base64, percent-encoded-then-base64, protobuf,
  a config file's own syntax, or JSON embedded in XML;
* a key written with mixed-script homoglyphs (Cyrillic ``pаssword``), where the
  letters are distinct code points.  Accented Latin (``pässword``) *is* folded;
  non-Latin lookalikes are not.

Redaction is defence in depth.  The database file mode (0600) and the fact that
device bodies are bounded are the controls that do not depend on naming.

Why payloads are bounded here
-----------------------------

Every table below is writable by an unauthenticated device route, and SQLite has
no per-table quota.  A D05 body may be 1 MiB (design §8) and can be repeated, so
the stored form is capped and the append-only per-device tables keep a fixed
number of rows.  Both are implementation additions with no design backing; they
exist so one device cannot decide how large the owner's database gets.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import unicodedata
import uuid
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import parse_qsl, quote

#: Design §2.3/§8: the two keys that must never reach storage or a log.
WIFI_SECRET_KEYS = frozenset({"productionWifiSsid", "productionWifiPassword"})

#: Keys that look like secrets.  The design only names the Wi-Fi pair; this
#: pattern is an addition, documented in the design's implementation-status
#: section, because a settings blob may also carry tokens.  ``passphrase``,
#: ``psk`` and ``pwd`` are here because a Wi-Fi credential sent as
#: ``Passphrase``, ``wifiPsk`` or ``pwd`` was stored in plaintext.
SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|passphrase|secret|token|api[_-]?key|credential"
    r"|private[_-]?key|pwd|psk)",
    re.IGNORECASE,
)

#: A bare ``key`` is a secret name too, but matching it as a substring would
#: redact ``keys`` (an audit field this service writes itself), ``monkey`` and
#: every other innocent name, and matching it after any camelCase boundary would
#: redact ``someKey`` and ``primaryKey`` as well.  It therefore matches only as a
#: whole word or as the tail of a snake/kebab-cased name.  A camelCase secret
#: still matches when its prefix names it - ``apiKey`` and ``privateKey`` are
#: covered by :data:`SECRET_KEY_PATTERN`.
BARE_KEY_PATTERN = re.compile(r"(?:^|[_.-])[kK][eE][yY]$")

REDACTED = "<redacted>"

#: Largest serialised payload stored for one device-supplied body.  A request
#: may be far larger (256 KiB, or 1 MiB on ``device-event/fire``); the stored
#: copy is what has to stay bounded, because nothing else limits how often a
#: device writes it.
MAX_STORED_PAYLOAD = 16 * 1024

#: Characters of an over-cap payload kept as a forensic preview.
PAYLOAD_PREVIEW_CHARS = 1024

#: Rows kept per device in the device-writable tables (``device_event``,
#: ``recipe_preset_revision``, ``onboarding``).  The ``audit`` table is
#: deliberately *not* trimmed: it is the evidence trail, and the module docstring
#: records that it has no retention and that dropping rows is not this process's
#: business.
MAX_ROWS_PER_DEVICE = 200

#: Longest audit subject kept.  A request path is attacker-chosen and
#: ``http.server`` allows a 65 536-byte request line, so an unbounded subject
#: let one unauthenticated request write about 130 KB of audit (the subject and
#: the copy under ``detail.route``).
MAX_AUDIT_SUBJECT = 512

#: Longest audit *method* kept.  The method token comes straight off the request
#: line and ``http.server`` allows 65 536 bytes there, so an unauthenticated
#: request could write a 60 KB audit row through ``detail.method`` alone - the
#: same amplification the subject cap was meant to end.
MAX_AUDIT_METHOD = 32

#: Bound on the ``keys`` list the D08/D09 handlers record: a device chooses those
#: key names in the body it sends, so they are attacker-controlled text too.
MAX_AUDIT_KEYS = 16
MAX_AUDIT_KEY_LEN = 64

#: Bound on the whole serialised ``detail`` column, as a backstop behind the
#: per-field caps above: any field added later that forgets its own bound still
#: cannot write an unbounded row.
MAX_AUDIT_DETAIL = 2048

#: Fields kept when a detail is truncated past ``MAX_AUDIT_DETAIL``.  Losing
#: ``status`` would defeat the point of the row, so the small scalars survive.
_AUDIT_DETAIL_MUST_KEEP = ("status", "reason", "code", "d_id", "method")

#: How far :func:`redact` will follow one nested encoding before giving up.
MAX_REDACTION_DEPTH = 4

#: Strings longer than this are not re-parsed as a form or an XML fragment: the
#: scan is linear but pointless on a body-sized blob, and the payload cap above
#: already bounds what reaches it.
MAX_TEXT_SCAN = 8 * 1024

#: Default and maximum page size for ``/admin/v1/audit``.  SQLite reads
#: ``LIMIT -1`` as "no limit", so a negative request returned the whole table.
DEFAULT_AUDIT_LIMIT = 50
MAX_AUDIT_LIMIT = 500

#: Mode and umask forced on every file this module creates.
PRIVATE_UMASK = 0o077
PRIVATE_FILE_MODE = 0o600

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


def _fold(text: str) -> str:
    """Casefold and strip diacritics, so ``pässword`` reads as ``password``.

    Non-Latin homoglyphs are a different code point and are *not* folded; that
    residual is documented in the module docstring rather than papered over.
    """

    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(character for character in decomposed if not unicodedata.combining(character)).casefold()


def is_secret_key(key: Any) -> bool:
    """Whether a dict key names a secret this module always redacts."""

    text = str(key)
    if text in WIFI_SECRET_KEYS:
        return True
    candidates = (text, _fold(text))
    return any(
        SECRET_KEY_PATTERN.search(candidate) is not None
        or BARE_KEY_PATTERN.search(candidate) is not None
        for candidate in candidates
    )


#: ``<name>value</name>`` - the element form of an XML fragment in a string.
XML_ELEMENT = re.compile(r"<(?P<name>[A-Za-z_][\w.:-]*)>(?P<value>[^<>]*)</(?P=name)>")

#: ``name="value"`` - the attribute form.  It deliberately does not match a JSON
#: pair (``"name": "value"``), whose name is followed by a quote, not ``=``.
XML_ATTRIBUTE = re.compile(r'(?P<name>[A-Za-z_][\w.:-]*)\s*=\s*"(?P<value>[^"<>]*)"')


def _embedded_json(value: str, depth: int) -> Any | None:
    """The object, array or nested string a string encodes as JSON.

    A nested *string* is returned so the caller can follow a double encoding
    (``json.dumps(json.dumps(...))``): the outer decode yields a string, and
    only the next decode reaches the object.  The leading-character check keeps
    a plain sentence or a serial number away from the parser.
    """

    text = value.strip()
    if not text or text[0] not in '{["':
        return None
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if isinstance(parsed, (dict, list)):
        return parsed
    if isinstance(parsed, str) and depth < MAX_REDACTION_DEPTH and parsed != value:
        return parsed
    return None


def _form_redaction(value: str, depth: int) -> str | None:
    """Redact a form-urlencoded string, or ``None`` when nothing changed."""

    if "=" not in value or len(value) > MAX_TEXT_SCAN:
        return None
    if "<" in value:
        # Not a form: an XML fragment also contains '=', and parsing it as
        # ``a=b&c=d`` percent-encodes the tags into an unreadable blob.  The XML
        # pass handles it, and runs first for exactly this reason.
        return None
    try:
        pairs = parse_qsl(value, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        return None
    if not pairs:
        return None
    changed = False
    rebuilt: list[str] = []
    for name, item in pairs:
        if is_secret_key(name):
            rebuilt.append(f"{quote(name, safe='')}={REDACTED}")
            changed = True
            continue
        nested = redact(item, depth + 1)
        if nested != item:
            changed = True
        rebuilt.append(f"{quote(name, safe='')}={nested}")
    return "&".join(rebuilt) if changed else None


def _xml_redaction(value: str, depth: int) -> str | None:
    """Redact secret-named elements and attributes in an XML fragment.

    Applied as a targeted substitution rather than a parse: an XML parser on
    device input brings its own problems (external entities, expansion), and the
    goal here is to stop a value being stored, not to understand the document.
    """

    if "<" not in value or len(value) > MAX_TEXT_SCAN:
        return None

    def replace(match: "re.Match[str]") -> str:
        if not is_secret_key(match.group("name")):
            return match.group(0)
        return match.group(0).replace(match.group("value"), REDACTED)

    rewritten = XML_ELEMENT.sub(replace, value)
    rewritten = XML_ATTRIBUTE.sub(replace, rewritten)
    return rewritten if rewritten != value else None


def redact(value: Any, depth: int = 0) -> Any:
    """Return ``value`` with secret-looking keys replaced, recursively.

    Walks dicts, lists and tuples, and also walks a *string* that encodes one of
    the shapes listed in the module docstring: JSON (including a double
    encoding), a form-urlencoded body, or an XML fragment.  A string is only
    rewritten when redaction actually changed something, so innocent text keeps
    its exact formatting.

    This catches a secret stored under a recognised name in a recognised shape.
    It does not catch a secret with no name at all, and it does not decode an
    arbitrary transport.  See the module docstring for the full residual.
    """

    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if is_secret_key(key):
                cleaned[key] = REDACTED
            else:
                cleaned[key] = redact(item, depth)
        return cleaned
    if isinstance(value, list):
        return [redact(item, depth) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item, depth) for item in value)
    if isinstance(value, str) and depth < MAX_REDACTION_DEPTH:
        embedded = _embedded_json(value, depth)
        if embedded is not None:
            cleaned = redact(embedded, depth + 1)
            if cleaned != embedded:
                return json.dumps(cleaned)
        for transform in (_xml_redaction, _form_redaction):
            rewritten = transform(value, depth)
            if rewritten is not None:
                return rewritten
    return value


def bounded_payload(value: Any) -> str:
    """Serialise a device body for storage, redacted and capped at the column.

    Redaction runs first; this only decides how much of the result is kept.  An
    over-cap body is replaced by a truncation record carrying the original size,
    a digest and a short preview, so the row still says "a large body arrived"
    without storing it.  The record is itself JSON, so every reader of these
    columns can keep calling :func:`json.loads`.
    """

    text = json.dumps(redact(value), sort_keys=True)
    if len(text) <= MAX_STORED_PAYLOAD:
        return text
    return json.dumps(
        {
            "_truncated": True,
            "_original_bytes": len(text),
            "_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "_preview": text[:PAYLOAD_PREVIEW_CHARS],
        },
        sort_keys=True,
    )


def bounded_detail(detail: dict[str, Any]) -> dict[str, Any]:
    """Return ``detail`` if it serialises within ``MAX_AUDIT_DETAIL``, else a stub.

    The per-field caps in the handlers are the real fix; this is the backstop
    for a field that is added later without one.  The small scalars that make
    the row meaningful - status, reason, code, d_id, method - are kept, so a
    truncated row still says what happened.
    """

    text = json.dumps(detail, sort_keys=True)
    if len(text) <= MAX_AUDIT_DETAIL:
        return detail
    kept = {key: detail[key] for key in _AUDIT_DETAIL_MUST_KEEP if key in detail}
    return {**kept, "_truncated": True, "_original_bytes": len(text)}


def clamp_audit_limit(limit: Any) -> int:
    """Clamp an audit page size to ``[1, MAX_AUDIT_LIMIT]``.

    A negative value is not "the whole table": SQLite reads ``LIMIT -1`` as no
    limit, so the clamp is the only thing standing between ``?limit=-1`` and a
    full scan of the audit trail.  Anything that is not an integer falls back to
    :data:`DEFAULT_AUDIT_LIMIT`.
    """

    try:
        value = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_AUDIT_LIMIT
    return max(1, min(value, MAX_AUDIT_LIMIT))


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
        # These files hold device events and the audit trail, and the process
        # umask decides their mode.  The usual container default (022) makes
        # them world-readable, which is how the database, its WAL and
        # shared-memory siblings and the audit mirror were all created 0644.
        # Narrow the umask once, before the first connect, so they are private
        # from creation rather than from the first chmod.
        os.umask(PRIVATE_UMASK)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.audit_file is not None:
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        self.initialise()
        self._restrict_modes()

    def _restrict_modes(self) -> None:
        """chmod every file this store owns to 0600.

        ``umask`` only governs files created after it is set, so a database that
        already exists keeps whatever mode it had - and so do WAL/SHM files left
        by an older run.  This is the half that repairs those.
        """

        targets = [self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")]
        if self.audit_file is not None:
            targets.append(self.audit_file)
        for target in targets:
            try:
                os.chmod(target, PRIVATE_FILE_MODE)
            except FileNotFoundError:
                continue

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

    @staticmethod
    def _trim(connection: sqlite3.Connection, table: str, device_id: str, keep: int) -> None:
        """Keep only the newest ``keep`` rows this device owns in ``table``.

        ``table`` is always one of this module's own constants, never a caller
        string, so the name interpolated below cannot carry injected SQL; the
        device id is still bound as a parameter.
        """

        connection.execute(
            f"""
            DELETE FROM {table}
            WHERE device_id = ?
              AND id NOT IN (
                  SELECT id FROM {table} WHERE device_id = ? ORDER BY id DESC LIMIT ?
              )
            """,
            (device_id, device_id, keep),
        )

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
        stored = bounded_payload(body)
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT INTO device_event(device_id, type, identity, payload, received_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_id, identity) DO NOTHING
                """,
                (device_id, event_type, identity, stored, utc_now()),
            )
            self._trim(connection, "device_event", device_id, MAX_ROWS_PER_DEVICE)
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
                    bounded_payload(payload or {}),
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
                (device_id, bounded_payload(body), utc_now()),
            )
            self._trim(connection, "recipe_preset_revision", device_id, MAX_ROWS_PER_DEVICE)
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
                (device_id, bounded_payload(body), utc_now()),
            )
            self._trim(connection, "onboarding", device_id, MAX_ROWS_PER_DEVICE)
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
            subject=str(subject)[:MAX_AUDIT_SUBJECT],
            detail=bounded_detail(redact(detail or {})),
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
                    # One write() per record and O_APPEND, so concurrent writers
                    # cannot interleave halves of two lines.  flush() empties the
                    # Python buffer; os.fsync() is what actually survives a
                    # power cut or a container SIGKILL, and without it the
                    # "mirrored" file could be missing the last rows while the
                    # SQLite row (already committed) has them.
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
        return entry

    def audit_rows(self, limit: int = DEFAULT_AUDIT_LIMIT) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (clamp_audit_limit(limit),)
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
