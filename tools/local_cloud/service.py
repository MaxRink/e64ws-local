"""Runnable local-cloud skeleton for the ten recorded device-service routes.

Why this exists
---------------

``docs/LOCAL_CLOUD_DESIGN.md`` describes an owner-hosted replacement for the
vendor cloud but contains no server ("This repository contains no server
implementation", §11).  This module is the smallest thing that changes that
sentence without inventing protocol: it serves exactly the paths the design
records, in the shape the design records, and refuses every field the design
marks ``unknown — needs capture`` with a ``501`` that names the D-id and a
stable reason token.

Nothing here claims the firmware will accept a reply.  The point is a service an
owner can point a client at, log against, and grow one captured fact at a time.

What is deliberately not here
-----------------------------

* No vendor account, token, key or JWT semantics (design §8).
* No rate limiting (design §8 asks for it; Caddy cannot express it and this
  skeleton has no per-certificate limiter yet - documented, not pretended).
* No PostgreSQL, object store, admin UI or push (design §3 components beyond the
  one process this file is).
* No guessed wire formats.  A route whose reply shape is unrecorded answers 501,
  because a plausible-looking body would be parsed by the firmware into a wrong
  decision - a wrong clock, a wrong certificate, a wrong diet of brew events.

Identity
--------

The device is identified by the fingerprint of the client certificate it
presents, never by a body field (design §3 and D09).  Two identity sources are
supported, and only one of them is trusted at a time:

``--tls-cert/--tls-key`` + ``--client-ca``
    Direct mutual TLS.  The fingerprint is read from the handshake.  Without
    ``--require-client-cert`` the handshake is optional, so the admin routes
    stay reachable on loopback; a device route without a certificate is still
    refused.

``--trust-proxy-identity``
    The process sits behind the edge proxy, which terminates TLS and forwards
    ``X-Client-Cert-Fingerprint``.  Only valid when the listener is reachable
    from the proxy alone; the flag is off by default for that reason.

``--allow-anonymous``
    Development only.  Every request is attributed to one seeded device.  It
    exists so the skeleton can be exercised without certificates, and it is
    logged as unverified identity.

Usage
-----

    python3 -m tools.local_cloud.service --db /tmp/local-cloud.sqlite3 \\
        --port 8080 --audit-file /tmp/local-cloud-audit.jsonl

    python3 -m tools.local_cloud.service --print-contract > contract.json

    python3 -m tools.local_cloud.service --db /tmp/lc.sqlite3 --port 8443 \\
        --tls-cert certs/server.crt --tls-key certs/server.key \\
        --client-ca certs/ca.crt --admin-token "$LOCAL_CLOUD_ADMIN_TOKEN"
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import socket
import ssl
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlsplit

if __package__ in (None, ""):  # direct execution: python3 tools/local_cloud/service.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tools.local_cloud import contract, store as store_module
else:
    from . import contract, store as store_module

DESIGN_POINTER = contract.DESIGN_POINTER

#: Design §8: global body cap 256 KiB, ``device-event/fire`` 1 MiB.
MAX_BODY = 256 * 1024
FIRE_PATH = "/api/device-service/device-event/fire"
MAX_FIRE_BODY = 1024 * 1024

#: Header that carries the unverified-field list of a device reply.
UNVERIFIED_HEADER = "X-Local-Cloud-Unverified"

#: Header the edge proxy may set when ``--trust-proxy-identity`` is on.
CLIENT_CERT_HEADER = "X-Client-Cert-Fingerprint"

#: The only duration the firmware's own consumer accepts (design §5, D01).
MIN_VISIBLE_DURATION_MS = 10_000

DEFAULT_ARTIFACT_BASE_URL = "http://127.0.0.1:8080/firmware"


class HttpError(Exception):
    """A refusal that already knows its status and machine-readable code."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        reason: str | None = None,
        d_id: str | None = None,
        fields: tuple[str, ...] = (),
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.reason = reason
        self.d_id = d_id
        self.fields = fields

    def payload(self) -> dict[str, Any]:
        return contract.error_payload(
            self.code,
            self.message,
            reason=self.reason,
            d_id=self.d_id,
            fields=self.fields,
            status=self.status,
        )


class UnknownFieldRefusal(HttpError):
    """A 501 for one field the design does not record."""

    def __init__(self, field: str) -> None:
        gap = contract.unknown(field)
        d_id = contract.d_id_for_field(field)
        super().__init__(
            501,
            "unsupported",
            f"{gap.field}: {contract.UNKNOWN_MARKER} - {gap.detail} See {d_id} in {DESIGN_POINTER}.",
            reason=gap.reason,
            d_id=d_id,
            fields=(field,),
        )


@dataclass
class Response:
    """What a route returns: status, body and the gaps it still carries."""

    status: int
    payload: Any
    content_type: str = "application/json"
    unverified: tuple[str, ...] = ()

    def body(self) -> bytes:
        if isinstance(self.payload, (bytes, bytearray)):
            return bytes(self.payload)
        if isinstance(self.payload, str) and self.content_type != "application/json":
            # PEM for D03; JSON strings would otherwise gain quotes.
            return self.payload.encode()
        if self.payload is None:
            return b""
        return json.dumps(self.payload, separators=(",", ":"), sort_keys=True).encode()


@dataclass
class Settings:
    """Everything the routes need that is not state."""

    artifact_base_url: str = DEFAULT_ARTIFACT_BASE_URL
    admin_token: str | None = None
    allow_anonymous: bool = False
    dev_device_id: str = "local-dev-device"
    max_brew_events: int = 500
    firmware_path: str = "/firmware"

    def artifact_url(self, filename: str) -> str:
        return f"{self.artifact_base_url.rstrip('/')}{self.firmware_path}/{filename}"


@dataclass
class App:
    """Store + settings + the audit sink, shared by every request thread."""

    store: store_module.Store
    settings: Settings = field(default_factory=Settings)

    def audit(self, **kwargs: Any) -> None:
        self.store.audit(**kwargs)


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------


def fingerprint_of_der(der: bytes) -> str:
    """OpenSSL-style SHA-256 fingerprint: uppercase hex, colon separated."""

    return ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())


def fingerprint_of_pem(pem: str) -> str:
    """Fingerprint of a PEM certificate without any third-party library."""

    return fingerprint_of_der(ssl.PEM_cert_to_DER_cert(pem))


def normalise_fingerprint(value: str) -> str:
    """Accept ``aa:bb`` or ``AABB`` and return the canonical colon form."""

    cleaned = "".join(character for character in value if character not in ": ").upper()
    if len(cleaned) != 64 or any(character not in "0123456789ABCDEF" for character in cleaned):
        raise ValueError("not a SHA-256 certificate fingerprint")
    return ":".join(cleaned[index : index + 2] for index in range(0, 64, 2))


@dataclass(frozen=True)
class Identity:
    """Who the service thinks is calling, and how it knows."""

    device_id: str
    fingerprint: str | None
    source: str  # "client-cert" | "proxy-header" | "anonymous"

    @property
    def actor(self) -> str:
        return f"device:{self.device_id}"


# ---------------------------------------------------------------------------
# device-service routes (D01-D10)
# ---------------------------------------------------------------------------


def _require_object(raw: bytes, d_id: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HttpError(
            400,
            "invalid_payload",
            f"body is not JSON: {error}",
            reason="body-not-json",
            d_id=d_id,
        ) from error
    if not isinstance(value, dict):
        raise HttpError(
            400,
            "invalid_payload",
            "body must be a JSON object",
            reason="body-not-object",
            d_id=d_id,
        )
    return value


def _parse_iso(value: Any, d_id: str, field_name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise HttpError(
            400,
            "invalid_payload",
            f"{field_name} must be an ISO-8601 string (observed request shape, {d_id})",
            reason="cursor-missing",
            d_id=d_id,
        )
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as error:
        raise HttpError(
            400,
            "invalid_payload",
            f"{field_name} is not ISO-8601: {value!r}",
            reason="cursor-unparseable",
            d_id=d_id,
        ) from error
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def brew_event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """Serialise one ``brew_event`` row as the recorded element payload.

    Field names and the forced values are the ones the design records
    (API_REFERENCE.md §4.4/§4.6): ``brewer`` is the plain source string,
    ``groupNumber`` is ``"0"``, and a scale source forces ``doseType`` to
    ``MassType`` with ``validity`` true.  Optional fields are omitted rather
    than defaulted, because a default would be a made-up value.
    """

    payload: dict[str, Any] = {
        "eventUuid": row["event_uuid"],
        "deviceId": row["device_id"],
        "brewer": row["source"],
        "groupNumber": "0",
        "duration": int(row["duration_ms"]),
        "cloudDate": row["cloud_date"],
    }
    if row.get("dose_type"):
        payload["doseType"] = row["dose_type"]
    if row.get("validity") is not None:
        payload["validity"] = bool(row["validity"])
    if row.get("mass_mg") is not None:
        payload["mass"] = int(row["mass_mg"])
    if row.get("volume_ml") is not None:
        payload["volume"] = int(row["volume_ml"])
    if row.get("grind_event_uuid"):
        payload["grindEventUuid"] = row["grind_event_uuid"]
    if row.get("stop_target") is not None:
        payload["stopTarget"] = float(row["stop_target"])
    return payload


def d01_brew_event_find(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    body = _require_object(raw, "D01")
    payload = body.get("payload")
    if not isinstance(payload, dict):
        raise HttpError(
            400,
            "invalid_payload",
            "observed request shape is {\"payload\": {...}} (D01)",
            reason="payload-wrapper-missing",
            d_id="D01",
        )
    date_range = payload.get("deviceDateRange")
    cursor_value = date_range.get("from") if isinstance(date_range, dict) else None
    cursor = _parse_iso(cursor_value, "D01", "payload.deviceDateRange.from")
    rows = app.store.visible_brew_events(
        identity.device_id, since=cursor, limit=app.settings.max_brew_events
    )
    return Response(
        200,
        [{"payload": brew_event_payload(dict(row))} for row in rows],
        unverified=("D01.response.wrapper-extra-keys", "D01.element.cloudDate.format"),
    )


def d02_brewer_binding_find(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    # The design's local behaviour: an empty array until bindings exist, and
    # bindings are created by an owner action (there is no admin route for them
    # yet).  The query keys were never captured, so the query string is ignored
    # rather than bound to invented parameter names.
    return Response(200, [], unverified=("D02.query.keys",))


def d03_device_cert_download(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    certificates = app.store.certificates_for(identity.device_id)
    if not certificates:
        # Serving a guessed "nothing to install" reply is exactly the kind of
        # invention that can brick provisioning, so the gap is refused instead.
        raise UnknownFieldRefusal("D03.no-update.response")
    return Response(
        200,
        certificates[0]["cert_pem"],
        content_type="application/x-pem-file",
        unverified=("D03.request.method",),
    )


def d04_cloud_recipe_slot_find(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    slots = app.store.recipe_slots(identity.device_id)
    if slots:
        # A published-recipe element was never captured; only the empty array is
        # prescribed by the design.
        raise UnknownFieldRefusal("D04.response.element-schema")
    return Response(200, [])


def d05_device_event_fire(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    body = _require_object(raw, "D05")
    inserted, row_id, event_type = app.store.record_device_event(identity.device_id, body, raw)
    app.audit(
        actor=identity.actor,
        action="device-event",
        subject=event_type,
        detail={
            "route": "D05",
            "device_event_id": row_id,
            "inserted": inserted,
            "type_detected": event_type,
        },
    )
    return Response(200, {}, unverified=("D05.response.body", "D05.request.discriminator-key"))


def d06_device_event_status(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    # requestType 3 has no recovered method, so the heartbeat is read from a
    # query string or a body and a malformed body never costs the device its
    # heartbeat.
    interval: int | None = None
    parameters: dict[str, Any] = {key: values[-1] for key, values in query.items() if values}
    if raw:
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, dict):
            parameters.update(parsed)
    raw_interval = parameters.get("interval")
    try:
        if raw_interval is not None:
            interval = int(str(raw_interval).strip())
    except ValueError:
        interval = None
    app.store.record_status(identity.device_id, interval)
    return Response(200, {}, unverified=("D06.response.shape", "D06.request.method"))


def d07_firmware_check_update(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    current = (query.get("currentVer") or [""])[-1] or None
    artifact = app.store.admitted_artifact_above(current)
    if artifact is None:
        raise UnknownFieldRefusal("D07.no-update.response")
    return Response(
        200,
        {
            "versionText": artifact["version"],
            "downloadUrl": app.settings.artifact_url(artifact["filename"]),
            "notes": f"served from the local manifest; sha256={artifact['sha256']}",
        },
        unverified=("D07.download.auth",),
    )


def d08_recipe_preset_update(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    body = _require_object(raw, "D08")
    revision = app.store.record_recipe_preset(identity.device_id, body)
    app.audit(
        actor=identity.actor,
        action="recipe-preset-stored",
        subject=f"device:{identity.device_id}",
        detail={"route": "D08", "revision": revision, "keys": sorted(body)},
    )
    # Stored, but the reply the firmware's recipeChangeSucceeded(qulonglong)
    # needs is unrecorded, so no body is offered.
    raise UnknownFieldRefusal("D08.reply.value")


def d09_system_onboarding(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    body = _require_object(raw, "D09")
    record = app.store.record_onboarding(identity.device_id, body)
    app.audit(
        actor=identity.actor,
        action="onboarding-stored",
        subject=f"device:{identity.device_id}",
        detail={"route": "D09", "onboarding_id": record, "keys": sorted(body)},
    )
    return Response(200, {}, unverified=("D09.request.keys",))


def d10_system_time(app: App, identity: Identity, query: Mapping[str, list[str]], raw: bytes) -> Response:
    # The device's only cloud clock.  Epoch seconds, an ISO string and a bare
    # number are all consistent with the evidence, and the choice sets the
    # grinder's TLS validity window, so it is refused rather than guessed.
    raise UnknownFieldRefusal("D10.response.format")


DEVICE_HANDLERS: dict[str, Callable[[App, Identity, Mapping[str, list[str]], bytes], Response]] = {
    "D01": d01_brew_event_find,
    "D02": d02_brewer_binding_find,
    "D03": d03_device_cert_download,
    "D04": d04_cloud_recipe_slot_find,
    "D05": d05_device_event_fire,
    "D06": d06_device_event_status,
    "D07": d07_firmware_check_update,
    "D08": d08_recipe_preset_update,
    "D09": d09_system_onboarding,
    "D10": d10_system_time,
}


# ---------------------------------------------------------------------------
# admin routes (loopback only, owner token)
# ---------------------------------------------------------------------------


def _require_admin(app: App, headers: Mapping[str, str]) -> str:
    token = app.settings.admin_token
    if not token:
        raise HttpError(
            403,
            "forbidden",
            "admin API disabled: no LOCAL_CLOUD_ADMIN_TOKEN configured",
            reason="admin-not-configured",
        )
    presented = ""
    authorization = headers.get("Authorization") or ""
    if authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    if not presented or not hmac.compare_digest(presented, token):
        raise HttpError(401, "unauthorized", "admin token missing or wrong", reason="admin-token-invalid")
    return "owner:admin"


def admin_create_device(app: App, body: dict[str, Any]) -> Response:
    device_id = str(body.get("deviceId") or "").strip()
    if not device_id:
        raise HttpError(400, "invalid_payload", "deviceId is required", reason="device-id-missing")
    app.store.ensure_device(
        device_id,
        serial=body.get("serial"),
        model=body.get("model"),
        firmware_version=body.get("firmwareVersion"),
        cloud_device_id=body.get("cloudDeviceId"),
    )
    fingerprint = body.get("certFingerprint")
    if isinstance(fingerprint, str) and fingerprint.strip():
        try:
            normalised = normalise_fingerprint(fingerprint)
        except ValueError as error:
            raise HttpError(
                400,
                "invalid_payload",
                f"certFingerprint is not a SHA-256 fingerprint: {error}",
                reason="fingerprint-invalid",
            ) from error
        app.store.enrol_credential(
            device_id,
            normalised,
            cert_pem=body.get("certPem"),
            not_after=body.get("notAfter"),
        )
    else:
        normalised = None
    return Response(200, {"deviceId": device_id, "certFingerprint": normalised})


def admin_add_brew_event(app: App, body: dict[str, Any]) -> Response:
    device_id = str(body.get("deviceId") or "").strip()
    if not device_id:
        raise HttpError(400, "invalid_payload", "deviceId is required", reason="device-id-missing")
    duration = body.get("durationMs")
    if not isinstance(duration, int) or isinstance(duration, bool):
        raise HttpError(
            400,
            "invalid_payload",
            "durationMs must be an integer number of milliseconds",
            reason="duration-required",
        )
    try:
        row = app.store.add_brew_event(
            device_id=device_id,
            duration_ms=duration,
            event_uuid=body.get("eventUuid"),
            grind_event_uuid=body.get("grindEventUuid"),
            mass_mg=body.get("massMg"),
            volume_ml=body.get("volumeMl"),
            source=str(body.get("source") or "scale"),
            dose_type=body.get("doseType"),
            validity=body.get("validity"),
            stop_target=body.get("stopTarget"),
            cloud_date=body.get("cloudDate"),
            approved=True,
        )
    except ValueError as error:
        raise HttpError(
            400,
            "invalid_payload",
            f"cloudDate is not ISO-8601: {error}",
            reason="cloud-date-unparseable",
        ) from error
    return Response(200, {"brewEvent": row, "d01Payload": brew_event_payload(row)})


def admin_publish_recipe_slot(app: App, body: dict[str, Any]) -> Response:
    device_id = str(body.get("deviceId") or "").strip()
    slot_id = str(body.get("slotId") or "").strip()
    if not device_id or not slot_id:
        raise HttpError(
            400, "invalid_payload", "deviceId and slotId are required", reason="slot-fields-missing"
        )
    row = app.store.publish_recipe_slot(
        device_id=device_id,
        slot_id=slot_id,
        recipe_id=body.get("recipeId"),
        store_id=body.get("storeId"),
        payload=body.get("payload") if isinstance(body.get("payload"), dict) else None,
    )
    return Response(200, {"recipeSlot": row})


def admin_add_firmware(app: App, body: dict[str, Any]) -> Response:
    filename = str(body.get("filename") or "").strip()
    version = str(body.get("version") or "").strip()
    sha256 = str(body.get("sha256") or "").strip()
    if not filename or not version or len(sha256) != 64:
        raise HttpError(
            400,
            "invalid_payload",
            "filename, version and a 64-hex sha256 are required",
            reason="artifact-fields-invalid",
        )
    row = app.store.add_firmware_artifact(
        filename=filename,
        sha256=sha256.lower(),
        version=version,
        model=body.get("model"),
        byte_count=body.get("bytes"),
        source_url=body.get("sourceUrl"),
        admitted=bool(body.get("admitted")),
        admitted_by="owner:admin" if body.get("admitted") else None,
    )
    return Response(200, {"firmwareArtifact": row})


ADMIN_POST_ROUTES: dict[str, Callable[[App, dict[str, Any]], Response]] = {
    "/admin/v1/devices": admin_create_device,
    "/admin/v1/brew-events": admin_add_brew_event,
    "/admin/v1/recipe-slots": admin_publish_recipe_slot,
    "/admin/v1/firmware": admin_add_firmware,
}


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------


class LocalCloudHandler(BaseHTTPRequestHandler):
    """Thin HTTP layer: parse, resolve identity, call a route, audit, reply."""

    server_version = "local-cloud/0.1"
    sys_version = ""

    # -- helpers ----------------------------------------------------------

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib name
        """Silence the default stderr access log; the audit table is the log."""

    def _source_ip(self) -> str | None:
        return self.client_address[0] if self.client_address else None

    def _read_body(self, limit: int) -> bytes:
        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header) if length_header else 0
        except ValueError:
            length = 0
        if length > limit:
            self.close_connection = True
            raise HttpError(
                413,
                "invalid_payload",
                f"body exceeds {limit} bytes (design §8 body cap)",
                reason="body-too-large",
            )
        return self.rfile.read(length) if length else b""

    def _certificate_fingerprint(self) -> tuple[str | None, str]:
        """Fingerprint and its source: the handshake, the proxy header, or none."""

        try:
            der = self.connection.getpeercert(binary_form=True)  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            der = None
        if der:
            return fingerprint_of_der(der), "client-cert"
        if self.server.trust_proxy_identity:  # type: ignore[attr-defined]
            forwarded = self.headers.get(CLIENT_CERT_HEADER)
            if forwarded:
                try:
                    return normalise_fingerprint(forwarded), "proxy-header"
                except ValueError:
                    return None, "proxy-header"
        return None, "none"

    def _identity(self) -> Identity:
        fingerprint, source = self._certificate_fingerprint()
        if fingerprint:
            row = self.app.store.device_by_fingerprint(fingerprint)
            if row is None:
                raise HttpError(
                    401,
                    "unauthorized",
                    "client certificate is not enrolled; enrol the device through "
                    "the admin API before it connects (design §7)",
                    reason="unknown-client-certificate",
                )
            return Identity(device_id=row["id"], fingerprint=fingerprint, source=source)
        if self.server.allow_anonymous:  # type: ignore[attr-defined]
            device_id = self.server.dev_device_id  # type: ignore[attr-defined]
            self.app.store.ensure_device(device_id, model="dev", m2m_enabled=True)
            return Identity(device_id=device_id, fingerprint=None, source="anonymous")
        raise HttpError(
            401,
            "unauthorized",
            "no client certificate presented and anonymous access is off",
            reason="client-certificate-required",
        )

    def _send(self, response: Response) -> None:
        body = response.body()
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if response.unverified:
            self.send_header(UNVERIFIED_HEADER, ",".join(response.unverified))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_error(self, error: HttpError, *, with_body: bool = True) -> None:
        payload = error.payload()
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(error.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if error.fields:
            self.send_header(UNVERIFIED_HEADER, ",".join(error.fields))
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    # -- request lifecycle ------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        self._handle("POST")

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib name
        error = HttpError(405, "unsupported", "HEAD is not served", reason="method-not-supported")
        self.app.audit(
            actor="anonymous",
            action="request",
            subject=urlsplit(self.path).path or "/",
            detail={
                "method": "HEAD",
                "route": urlsplit(self.path).path or "/",
                "status": error.status,
                "reason": error.reason,
            },
            source_ip=self._source_ip(),
        )
        self._send_error(error, with_body=False)

    def do_PUT(self) -> None:  # noqa: N802 - stdlib name
        self._handle("PUT")

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib name
        self._handle("DELETE")

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib name
        self._handle("PATCH")

    def _handle(self, method: str) -> None:
        """Resolve, act, audit, then reply.

        The audit row is written *before* the response is flushed.  Reversing
        that order lets a fast client observe a stored request whose audit row
        does not exist yet, which would make "every device request is audited"
        untestable - and a lie under load.
        """

        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        query = parse_qs(parts.query, keep_blank_values=True)
        detail: dict[str, Any] = {"method": method, "route": path}
        actor = "anonymous"
        response: Response | None = None
        error: HttpError | None = None
        try:
            if path == "/healthz":
                self._send(self._health())
                return
            if path.startswith("/admin/"):
                detail["surface"] = "admin"
                response, actor = self._admin(method, path)
            else:
                spec = contract.ROUTE_BY_PATH.get(path)
                if spec is None:
                    raise HttpError(
                        404,
                        "not_found",
                        f"{path} is not one of the recorded device-service routes",
                        reason="route-not-recorded",
                    )
                detail["d_id"] = spec.d_id
                if method not in spec.methods:
                    raise HttpError(
                        405,
                        "unsupported",
                        f"{spec.d_id} accepts {', '.join(spec.methods)}; requestType 3 "
                        "routes accept both when the method is unrecorded, this one does not",
                        reason="method-not-supported",
                        d_id=spec.d_id,
                    )
                identity = self._identity()
                actor = identity.actor
                detail["identity_source"] = identity.source
                if identity.fingerprint:
                    detail["certificate_fingerprint"] = identity.fingerprint
                limit = MAX_FIRE_BODY if path == FIRE_PATH else MAX_BODY
                raw = self._read_body(limit)
                detail["bytes_in"] = len(raw)
                response = DEVICE_HANDLERS[spec.d_id](self.app, identity, query, raw)
                if response.unverified:
                    detail["unverified_fields"] = list(response.unverified)
                self.app.store.touch_device(identity.device_id)
        except HttpError as caught:
            error = caught
            detail["reason"] = caught.reason
            detail["code"] = caught.code
            if caught.d_id:
                detail["d_id"] = caught.d_id
        except Exception as caught:  # pragma: no cover - defensive
            error = HttpError(
                500,
                "internal",
                f"unhandled {type(caught).__name__}; see the service log",
                reason="unhandled-exception",
            )
            detail["reason"] = "unhandled-exception"
            detail["exception"] = type(caught).__name__

        detail["status"] = response.status if response is not None else error.status  # type: ignore[union-attr]
        self.app.audit(
            actor=actor,
            action="request",
            subject=path,
            detail=detail,
            source_ip=self._source_ip(),
        )
        if response is not None:
            self._send(response)
        else:
            assert error is not None
            self._send_error(error)

    def _health(self) -> Response:
        healthy = self.app.store.health()
        return Response(
            200 if healthy else 503,
            {
                "status": "ok" if healthy else "degraded",
                "schema_version": store_module.SCHEMA_VERSION,
                "database": "ok" if healthy else "error",
            },
        )

    def _admin(self, method: str, path: str) -> tuple[Response, str]:
        # The audit row for the request (including a token refusal) is written
        # by the caller.  Before/after diffs are not implemented; the recorded
        # keys and the status are what exists.
        actor = _require_admin(self.app, self.headers)
        if method == "GET":
            if path == "/admin/v1/audit":
                query = parse_qs(urlsplit(self.path).query)
                try:
                    limit = int((query.get("limit") or ["50"])[-1] or 50)
                except ValueError:
                    limit = 50
                return Response(200, {"entries": self.app.store.audit_rows(limit=limit)}), actor
            if path == "/admin/v1/export":
                return Response(200, self.app.store.export()), actor
            raise HttpError(
                404, "not_found", f"{path} is not an admin route", reason="route-not-recorded"
            )
        if method != "POST":
            raise HttpError(
                405, "unsupported", "admin routes accept GET and POST", reason="method-not-supported"
            )
        handler = ADMIN_POST_ROUTES.get(path)
        if handler is None:
            raise HttpError(
                404, "not_found", f"{path} is not an admin route", reason="route-not-recorded"
            )
        raw = self._read_body(MAX_BODY)
        body = _require_object(raw, "admin")
        return handler(self.app, body), actor



class LocalCloudServer:
    """Threaded HTTP(S) server around :class:`App`.

    ``port=0`` binds an ephemeral port, which is what the tests use so two runs
    can never collide.
    """

    def __init__(
        self,
        *,
        db_path: str | Path,
        audit_file: str | Path | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        tls_cert: str | Path | None = None,
        tls_key: str | Path | None = None,
        client_ca: str | Path | None = None,
        require_client_cert: bool = False,
        trust_proxy_identity: bool = False,
        allow_anonymous: bool = False,
        admin_token: str | None = None,
        artifact_base_url: str = DEFAULT_ARTIFACT_BASE_URL,
        dev_device_id: str = "local-dev-device",
        store: store_module.Store | None = None,
    ) -> None:
        self.store = store or store_module.Store(db_path, audit_file=audit_file)
        self.app = App(self.store, Settings(
            artifact_base_url=artifact_base_url,
            admin_token=admin_token,
            allow_anonymous=allow_anonymous,
            dev_device_id=dev_device_id,
        ))
        self._http = ThreadingHTTPServer((host, port), LocalCloudHandler)
        self._http.daemon_threads = True
        self._http.app = self.app  # type: ignore[attr-defined]
        self._http.allow_anonymous = allow_anonymous  # type: ignore[attr-defined]
        self._http.dev_device_id = dev_device_id  # type: ignore[attr-defined]
        self._http.trust_proxy_identity = trust_proxy_identity  # type: ignore[attr-defined]
        self._context: ssl.SSLContext | None = None
        if tls_cert and tls_key:
            self._context = tls_server_context(
                tls_cert,
                tls_key,
                client_ca=client_ca,
                require_client_cert=require_client_cert,
            )
            self._http.socket = self._context.wrap_socket(self._http.socket, server_side=True)
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return int(self._http.server_address[1])

    @property
    def scheme(self) -> str:
        return "https" if self._context is not None else "http"

    def start(self) -> "LocalCloudServer":
        # A short poll interval keeps shutdown fast: the tests start and stop
        # one server per case.
        self._thread = threading.Thread(
            target=self._http.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self._thread.start()
        return self

    def close(self) -> None:
        self._http.shutdown()
        self._http.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "LocalCloudServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.close()


def tls_server_context(
    cert: str | Path,
    key: str | Path,
    *,
    client_ca: str | Path | None = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    """Server context for direct mutual TLS.

    ``CERT_REQUIRED`` refuses an anonymous handshake outright, which would also
    refuse the admin token on the same listener; the default is therefore
    ``CERT_OPTIONAL`` when a client CA is configured, and the device routes
    still refuse a request that arrives without a certificate.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    if client_ca:
        context.load_verify_locations(cafile=str(client_ca))
        context.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
    return context


def free_port() -> int:
    """An unused localhost port (test helper)."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean from the environment so compose needs no flag plumbing."""

    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Local-cloud skeleton: the ten recorded device-service routes.  "
            "Every option can also be set from the environment (LOCAL_CLOUD_*), "
            "which is how deploy/local-cloud/.env drives the container."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--db", default=_env("LOCAL_CLOUD_DB"), help="SQLite file (created if missing)")
    parser.add_argument(
        "--audit-file",
        default=_env("LOCAL_CLOUD_AUDIT_FILE"),
        help="append-only JSONL mirror of the audit table",
    )
    parser.add_argument("--host", default=_env("LOCAL_CLOUD_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(_env("LOCAL_CLOUD_PORT", "8080") or 8080))
    parser.add_argument("--tls-cert", default=_env("LOCAL_CLOUD_TLS_CERT"))
    parser.add_argument("--tls-key", default=_env("LOCAL_CLOUD_TLS_KEY"))
    parser.add_argument(
        "--client-ca",
        default=_env("LOCAL_CLOUD_CLIENT_CA"),
        help="CA bundle used to verify device client certificates",
    )
    parser.add_argument(
        "--require-client-cert",
        action="store_true",
        default=_env_bool("LOCAL_CLOUD_REQUIRE_CLIENT_CERT"),
        help="refuse anonymous handshakes (then admin routes need a client certificate too)",
    )
    parser.add_argument(
        "--trust-proxy-identity",
        action="store_true",
        default=_env_bool("LOCAL_CLOUD_TRUST_PROXY_IDENTITY"),
        help="take the fingerprint from the edge proxy header instead of the handshake",
    )
    parser.add_argument(
        "--allow-anonymous",
        action="store_true",
        default=_env_bool("LOCAL_CLOUD_ALLOW_ANONYMOUS"),
        help="development only: attribute every request to one seeded device",
    )
    parser.add_argument("--dev-device-id", default=_env("LOCAL_CLOUD_DEV_DEVICE_ID", "local-dev-device"))
    parser.add_argument(
        "--admin-token",
        default=_env("LOCAL_CLOUD_ADMIN_TOKEN"),
        help="owner token for /admin/v1/* (default: $LOCAL_CLOUD_ADMIN_TOKEN)",
    )
    parser.add_argument(
        "--artifact-base-url",
        default=_env("LOCAL_CLOUD_ARTIFACT_BASE_URL", DEFAULT_ARTIFACT_BASE_URL),
    )
    parser.add_argument(
        "--print-contract",
        action="store_true",
        help="print the D01-D10 evidence registry as JSON and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.print_contract:
        print(json.dumps(contract.contract_document(), indent=2, ensure_ascii=False))
        return 0
    if not args.db:
        parser.error("--db is required unless --print-contract is used")
    server = LocalCloudServer(
        db_path=args.db,
        audit_file=args.audit_file,
        host=args.host,
        port=args.port,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        client_ca=args.client_ca,
        require_client_cert=args.require_client_cert,
        trust_proxy_identity=args.trust_proxy_identity,
        allow_anonymous=args.allow_anonymous,
        admin_token=args.admin_token,
        artifact_base_url=args.artifact_base_url,
        dev_device_id=args.dev_device_id,
    ).start()
    print(f"local-cloud: {server.scheme}://{args.host}:{server.port}/api/device-service/", flush=True)
    print(f"database:    {args.db}", flush=True)
    print(f"audit:       {args.audit_file or '(database only)'}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
