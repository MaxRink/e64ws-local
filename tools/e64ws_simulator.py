"""Deterministic, owner-local E64 WS and OpenScale development simulator.

The simulator is deliberately a mock, not a claim about undocumented device
behavior.  Its wire envelopes follow the recovered V01.16-24 shapes and its
limits are explicit test policy.  It never contacts Mahlkönig services or a
physical grinder.

Run it from the repository root after installing ``tools/requirements.txt``::

    python tools/e64ws_simulator.py

The default E64 endpoint is plain ``ws://127.0.0.1:9997`` because this is a
development fixture.  Pass ``--tls-cert`` and ``--tls-key`` to exercise WSS.
The separate scale endpoint speaks the local OpenScale ``/snapshot`` stream.
The HTTP port serves a tiny control UI, deterministic scenario controls, and
a fixture REST session API. The REST password is ``sim-password`` and is
accepted only by this loopback test server. It also exposes an explicitly
synthetic APK-provisioning fixture at ``/api/v2/network``; that surface is
not recovered firmware REST behavior and never contacts a real network.

Nothing here has to be configured.  A handful of fixture defaults that the CLI
does not expose—the REST password, the serial number, the grinder type and the
fake credential rows—also read an optional ``E64_SIM_*`` variable (see
``SETTINGS_ENV_FALLBACKS`` and docs/HOTPATCH_SURFACE.md).  Unset means the
value documented here; an explicit argument always wins.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import csv
import hmac
import io
import json
import os
import re
import mimetypes
import ssl
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, ClassVar, Mapping
from urllib.parse import parse_qs, urlsplit

try:
    from .e64local_actions import (
        ACTION_CATALOG,
        ACTION_META_ROUTES,
        ActionEngine,
        ActionError,
        BOUNDARY_RE,
        CREDENTIAL_RE,
    )
    from .unlock_tiers import detect as detect_unlock_tier
    from .unlock_tiers import facts_from_capabilities
except ImportError:  # direct ``python tools/e64ws_simulator.py`` or top-level import
    from e64local_actions import (  # type: ignore[no-redef]
        ACTION_CATALOG,
        ACTION_META_ROUTES,
        ActionEngine,
        ActionError,
        BOUNDARY_RE,
        CREDENTIAL_RE,
    )
    from unlock_tiers import detect as detect_unlock_tier  # type: ignore[no-redef]
    from unlock_tiers import facts_from_capabilities  # type: ignore[no-redef]


ACTION_SUFFIXES = frozenset(
    {
        "Stop",
        "StartGrindManual",
        "StartGrindGbw",
        "StartGrindGbt",
        "StartCalibration",
        "StartTara",
        "SaveLog",
        "ResetLog",
        "SetFanTemperatureCtrlEnabled",
        "CalibrateFan1",
        "CalibrateFan2",
        "ToggleBacklightPower",
        "SetBacklightBrightness",
        "SetFan1Duty",
        "SetFan2Duty",
        "SetAgsaTargetDdValue",
        "StopAgsa",
        "CalibrateDdSensor",
        "ResetDriverConfig",
        "SetLanguage",
        "StartEnduranceTest",
        "StopEnduranceTest",
        "SetSetupWizardState",
        "AddBrewEvent",
        "EspFlashApp",
        "EspEraseFlash",
        "EspReset",
        "NozzleLightRunStandby",
        "NozzleLightStop",
        "RcTopLeftClick",
        "RcTopLeftLong",
        "RcTopLeftPress",
        "RcTopLeftRelease",
        "RcBottomLeftClick",
        "RcRotaryClick",
        "RcRotaryLong",
        "RcRotaryDouble",
        "RcRotary",
        "GbsCreateReport",
    }
)


# This schema is intentionally separate from the recovered firmware REST
# placeholders below. It models only deterministic local test data for an APK
# provisioning client; these are not real WLANs or device credentials.
SYNTHETIC_APK_NETWORK_SCHEMA = "synthetic-apk-provisioning-v1"
SYNTHETIC_FIRMWARE_PLACEHOLDER_SCHEMA = "synthetic-firmware-rest-placeholder-v1"
SYNTHETIC_OFFICIAL_E64_ONBOARDING_SCHEMA = "synthetic-official-e64-onboarding-v1"
SYNTHETIC_APK_PASSWORD = "synthetic-only-password"
SYNTHETIC_OFFICIAL_ONBOARDING_TOKEN = "fixture-official-onboarding-token"
SYNTHETIC_APK_NETWORKS: tuple[dict[str, Any], ...] = (
    {
        "ssid": "E64-SIM-SETUP",
        "bssid": "02:64:00:00:00:01",
        "rssi": -42,
        "channel": 6,
        "security": "WPA2-PSK",
    },
    {
        "ssid": "E64-SIM-LAB",
        "bssid": "02:64:00:00:00:02",
        "rssi": -58,
        "channel": 11,
        "security": "WPA2-PSK",
    },
    {
        "ssid": "E64-SIM-OPEN",
        "bssid": "02:64:00:00:00:03",
        "rssi": -72,
        "channel": 1,
        "security": "OPEN",
    },
)


# ---------------------------------------------------------------------------
# Optional fixture overrides (``E64_SIM_*``)
#
# The values below are the documented fixture defaults and stay authoritative:
# every variable here is opt-in, unset *or empty* keeps the constant, and a
# value passed to the constructor (which is what every CLI flag does) wins over
# the environment.  Nothing is read at import time, so importing this module
# cannot fail and cannot freeze a value from the launching shell.
# ---------------------------------------------------------------------------

#: Prefix for every fixture fallback in this module.
E64_SIM_ENV_PREFIX = "E64_SIM_"

#: ``$E64_SIM_REST_PASSWORD`` — the REST fixture password (``SimulatedAuth``).
DEFAULT_REST_PASSWORD = "sim-password"
#: ``$E64_SIM_SERIAL`` — ``SimulatedLocalApi.serial`` and ``config.grinderSn``.
DEFAULT_SERIAL = "SIM0000000001"
#: ``$E64_SIM_GRINDER_TYPE`` — ``grinder_type`` in ``/machine`` and ``/config``.
DEFAULT_GRINDER_TYPE = 5
#: ``$E64_SIM_WIFI_SSID`` — the fake production SSID in settings and config.
DEFAULT_WIFI_SSID = "factory-net"
#: ``$E64_SIM_WIFI_STA_PASSWORD`` — the fake ``Wifi.StaPassword`` settings row.
DEFAULT_WIFI_STA_PASSWORD = "sim-wifi-secret"
#: ``$E64_SIM_WIFI_PRODUCTION_PASSWORD`` — the fake config credential.
DEFAULT_WIFI_PRODUCTION_PASSWORD = "factory-secret"
#: ``$E64_SIM_ROLE_LOGIN_DATA`` — the fake ``Role.*.LoginData`` settings rows.
DEFAULT_ROLE_LOGIN_DATA = "should-not-appear"

#: Settings rows whose fixture value is a fake credential, with the optional
#: fallback that replaces it: (exact row names, env suffix, default).
SETTINGS_ENV_FALLBACKS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("Wifi.StaPassword",), "WIFI_STA_PASSWORD", DEFAULT_WIFI_STA_PASSWORD),
    (("productionWifiSsid",), "WIFI_SSID", DEFAULT_WIFI_SSID),
    (
        ("Role.Owner.LoginData", "Role.Technician.LoginData", "Role.Barista.LoginData"),
        "ROLE_LOGIN_DATA",
        DEFAULT_ROLE_LOGIN_DATA,
    ),
)

#: ``config`` rows with the same treatment: (key, env suffix, default).
#: ``grinderSn`` and ``grinderType`` are not listed: they follow ``serial`` and
#: ``grinder_type`` so the two documents can never disagree.
CONFIG_ENV_FALLBACKS: tuple[tuple[str, str, str], ...] = (
    ("productionWifiSsid", "WIFI_SSID", DEFAULT_WIFI_SSID),
    ("productionWifiPassword", "WIFI_PRODUCTION_PASSWORD", DEFAULT_WIFI_PRODUCTION_PASSWORD),
)


def _env_fallback(suffix: str) -> str | None:
    """Return ``$E64_SIM_<suffix>``, or ``None`` when unset or empty.

    Read at call time on purpose: the fallback must describe the environment of
    the process that instantiates the fixture, not of the import.
    """
    value = os.environ.get(E64_SIM_ENV_PREFIX + suffix)
    return value if value not in (None, "") else None


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number")
    return float(value)


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    return value


# download_machine_logs CSV columns, exact SQL aliases (API_REFERENCE.md 1.4.13).
GRIND_LOG_COLUMNS = (
    "grind_id", "grind_uuid", "grind_date_time", "recipe_index", "recipe_cpr_id",
    "recipe_data_id", "grind_ddd", "grind_duration", "grind_duration_noload",
    "grind_weight", "grind_successfull", "grind_trigger_id", "grind_trigger",
    "recipe_gbs_enabled", "grind_debug_data", "recipe_uuid", "recipe_mode_id",
    "recipe_mode", "recipe_amount", "recipe_type_id", "recipe_type", "recipe_icon_id",
    "recipe_icon", "recipe_coarseness", "recipe_brew_time", "recipe_brew_weight",
)
SERVICE_LOG_COLUMNS = ("event_id", "event_type_id", "event_type", "event_date_time", "event_details")
# Synthetic recipe table; integer encodings follow the vendor seed (10^-3 g, ms, 0.1 um).
DEFAULT_RECIPES = (
    {"recipe_index": 1, "recipe_cpr_id": 1, "recipe_data_id": 1, "recipe_active": 1,
     "recipe_uuid": "00000000-0000-4000-8000-000000000001", "recipe_mode_id": 2,
     "recipe_mode": "GbW", "recipe_amount": 18000, "recipe_type_id": 1,
     "recipe_type": "Espresso, double", "recipe_icon_id": 1, "recipe_icon": "cup",
     "recipe_coarseness": 500, "recipe_brew_time": 27000, "recipe_brew_weight": 36000},
)
GRIND_FAMILY = frozenset({"Grind", "GbwPostGrind", "ManualStartGrind", "GbtStartGrind"})

# Commands registered with dev=1 (API_REFERENCE.md 2.3-2.5). On a shipped image
# the dispatcher refuses them by closing the socket without a reply frame.
DEV_GATED_TYPES = frozenset({
    "RequestLogMessages", "RequestAdcConfig", "RequestConfigManagerSettings",
    "UpdateDriverConfig", "UpdateCpuConfig", "CustomSignal1", "CustomSignal2",
})
DEV_UNGATED_ACTIONS = frozenset({"ResetDriverConfig", "EspReset"})


def dev_gated(message: Any) -> bool:
    if not isinstance(message, Mapping):
        return False
    if message.get("type") in DEV_GATED_TYPES:
        return True
    data = message.get("data")
    return message.get("type") == "GrinderAction" and not (
        isinstance(data, Mapping) and data.get("actionType") in DEV_UNGATED_ACTIONS
    )


@dataclass
class SimulatedScale:
    """Minimal OpenScale stream with explicit sequence and source time."""

    grams: float = 0.0
    milliseconds: float = 0.0
    sequence: int = 0
    connected: bool = True

    def set_sample(self, grams: Any, milliseconds: Any | None = None) -> None:
        self.grams = _number(grams, "grams")
        if milliseconds is not None:
            self.milliseconds = _number(milliseconds, "ms")
        self.sequence += 1

    def tare(self) -> None:
        self.grams = 0.0
        self.sequence += 1

    def frame(self) -> dict[str, Any]:
        return {
            "grams": self.grams,
            "ms": self.milliseconds,
            "sequence": self.sequence,
            "connected": self.connected,
        }


# FW-01: the firmware interpolates userRole into its LoginData SELECT, so a
# role of `x" UNION SELECT "<1$rounds$salt$hash>" -- ` supplies the verifier.
FW01_ROLE = re.compile(r'^x" UNION SELECT "(1\$\d{1,5}\$[^"$]{1,64}\$[A-Za-z0-9+/]{1,64})" -- $')


def vendor_hash(password: str, salt: str, rounds: int) -> str:
    """Firmware verifier: sha256(hash || password || salt || hash), base64 without padding."""
    digest = salt.encode()
    for _ in range(rounds):
        digest = hashlib.sha256(digest + password.encode() + salt.encode() + digest).digest()
    return base64.b64encode(digest).decode().replace("=", "")


def _verifier_matches(encoded: str, password: str) -> bool:
    _version, rounds, salt, expected = encoded.split("$", 3)
    if not 1 <= int(rounds) <= 10000:
        return False
    return hmac.compare_digest(vendor_hash(password, salt, int(rounds)), expected)


@dataclass
class SimulatedAuth:
    """Deterministic local REST session fixture.

    This is intentionally not a password cracker or a production auth model.
    It supplies one documented fixture password and a bearer value that the
    local WSS fixture can accept so client session tests do not need hardware.
    """

    wss_token: str
    password: str = DEFAULT_REST_PASSWORD
    fw01_login: bool = False
    session_ttl_seconds: float = 900.0
    generation: int = 0
    active: bool = False
    role: str | None = None
    cookie: str | None = None
    expires_at: float = 0.0
    sessions: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Opt-in only: an explicit ``password`` wins, and with nothing set the
        # value is exactly ``DEFAULT_REST_PASSWORD``.
        if self.password == DEFAULT_REST_PASSWORD:
            self.password = _env_fallback("REST_PASSWORD") or DEFAULT_REST_PASSWORD

    def login(self, role: Any, password: Any) -> dict[str, Any]:
        injected = FW01_ROLE.match(role) if self.fw01_login and isinstance(role, str) else None
        if injected:
            if not isinstance(password, str) or not _verifier_matches(injected.group(1), password):
                raise ValueError("invalid simulator credentials")
            role = "Owner"
        else:
            if not isinstance(role, str) or role not in {"Owner", "User", "Admin", "Technician"}:
                raise ValueError("simulator role must be Owner, User, Admin, or Technician")
            if password != self.password:
                raise ValueError("invalid simulator credentials")
        self.generation += 1
        self.active = True
        self.role = role
        self.cookie = f"sim-session-{self.generation:04d}"
        self.expires_at = time.monotonic() + self.session_ttl_seconds
        self.sessions[self.cookie] = self.expires_at
        return {
            "success": True,
            "role": role,
            "session": self.cookie,
            "expiresInSeconds": self.session_ttl_seconds,
            "simulator": True,
        }

    def _not_expired(self) -> bool:
        now = time.monotonic()
        self.sessions = {
            cookie: expiry
            for cookie, expiry in self.sessions.items()
            if expiry > now
        }
        self.active = bool(self.sessions)
        return self.active

    def accepts(self, headers: Mapping[str, str]) -> bool:
        if not self._not_expired():
            return False
        # HTTP header names are case-insensitive; Dart's HttpClient sends them lower-case.
        headers = {str(key).lower(): value for key, value in headers.items()}
        authorization = headers.get("authorization", "")
        if authorization == f"Bearer {self.wss_token}":
            return True
        cookie_header = headers.get("cookie", "")
        return any(
            f"PHPSESSID={cookie}" in cookie_header for cookie in self.sessions
        )

    def update(self) -> dict[str, Any]:
        if not self._not_expired():
            raise ValueError("simulator session is not active")
        self.expires_at = time.monotonic() + self.session_ttl_seconds
        for cookie in self.sessions:
            self.sessions[cookie] = self.expires_at
        return {
            "success": True,
            "role": self.role,
            "expiresInSeconds": self.session_ttl_seconds,
            "simulator": True,
        }

    def logout(self, headers: Mapping[str, str] | None = None) -> None:
        cookie_header = {str(key).lower(): value for key, value in (headers or {}).items()}.get("cookie", "")
        matching = [
            cookie
            for cookie in self.sessions
            if f"PHPSESSID={cookie}" in cookie_header
        ]
        if matching:
            for cookie in matching:
                self.sessions.pop(cookie, None)
        else:
            self.sessions.clear()
        self.active = bool(self.sessions)
        if not self.active:
            self.role = None
            self.cookie = None
            self.expires_at = 0.0


@dataclass
class SimulatedApkProvisioning:
    """Synthetic APK network-provisioning fixture, not recovered device REST.

    The ``synthetic-apk-provisioning-v1`` schema is a stable local contract for
    app and UI development.  Every response carries that schema marker and
    ``synthetic: true``.  The SSIDs/BSSIDs are reserved-looking fake values,
    and ``synthetic-only-password`` is accepted only by this fixture. Password
    input is never stored, logged, or returned. No scan, association, or other
    network operation is performed.
    """

    scan_generation: int = 0
    connected_ssid: str | None = None
    connected_bssid: str | None = None
    last_operation: str = "initial"
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    @staticmethod
    def _networks() -> list[dict[str, Any]]:
        return [dict(network) for network in SYNTHETIC_APK_NETWORKS]

    @staticmethod
    def _envelope(operation: str, **data: Any) -> dict[str, Any]:
        return {
            "schema": SYNTHETIC_APK_NETWORK_SCHEMA,
            "synthetic": True,
            "source": "simulator-apk-provisioning",
            "operation": operation,
            **data,
        }

    def status(self) -> dict[str, Any]:
        with self.lock:
            return self._envelope(
                "status",
                mode="STA" if self.connected_ssid else "AP",
                connected=self.connected_ssid is not None,
                ssid=self.connected_ssid,
                bssid=self.connected_bssid,
                scanGeneration=self.scan_generation,
                lastOperation=self.last_operation,
            )

    def list_networks(self) -> dict[str, Any]:
        with self.lock:
            return self._envelope(
                "list",
                networks=self._networks(),
                scanGeneration=self.scan_generation,
            )

    def force_scan(self) -> dict[str, Any]:
        with self.lock:
            self.scan_generation += 1
            self.last_operation = "forcescan"
            return self._envelope(
                "forcescan",
                networks=self._networks(),
                scanGeneration=self.scan_generation,
            )

    def connect(self, body: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            ssid = body.get("ssid")
            network = next(
                (candidate for candidate in SYNTHETIC_APK_NETWORKS if candidate["ssid"] == ssid),
                None,
            )
            if network is None:
                raise ValueError("ssid must be one of the synthetic E64-SIM networks")
            password = body.get("password")
            if network["security"] == "OPEN":
                if password not in (None, ""):
                    raise ValueError("the synthetic open network does not accept a password")
            elif password != SYNTHETIC_APK_PASSWORD:
                raise ValueError(
                    "synthetic fixture requires synthetic-only-password; no real credential is accepted"
                )
            self.connected_ssid = str(network["ssid"])
            self.connected_bssid = str(network["bssid"])
            self.last_operation = "connect"
            # Deliberately do not retain or echo body["password"].
            return self._envelope(
                "connect",
                connected=True,
                ssid=self.connected_ssid,
                bssid=self.connected_bssid,
            )

    def reset(self) -> None:
        with self.lock:
            self.scan_generation = 0
            self.connected_ssid = None
            self.connected_bssid = None
            self.last_operation = "initial"


@dataclass
class SimulatedOfficialE64Onboarding:
    """Candidate response fixture for the stock APK's local onboarding path.

    Static AOT evidence identifies the local route, a six-slot
    ``RequestOnboardingData`` serializer, the AP address candidates, and the
    following cloud device-query step. It does *not* recover the complete
    response schema. This class therefore exposes an explicitly synthetic,
    opt-in candidate fixture instead of silently upgrading the conservative
    firmware placeholder into a false compatibility claim.

    Only key names and booleans about request presence are retained. Request
    values—including Wi-Fi passwords and access tokens—are never stored,
    logged, or returned. The token/URLs below are fixed test values and are
    not device credentials.
    """

    request_count: int = 0
    scan_count: int = 0
    last_request_keys: tuple[str, ...] = ()
    last_request_presence: dict[str, bool] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    @staticmethod
    def _presence(body: Mapping[str, Any]) -> dict[str, bool]:
        nested = body.get("data") if isinstance(body.get("data"), Mapping) else body
        return {
            "token": "token" in body or "token" in nested,
            "restUrl": "restUrl" in body or "restUrl" in nested,
            "status": "status" in body or "status" in nested,
            "subType": "subType" in body or "subType" in nested,
            "socketUrl": "socketUrl" in body or "socketUrl" in nested,
            "wifiConfig": "wifiConfig" in body or "wifiConfig" in nested,
        }

    def status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "schema": SYNTHETIC_OFFICIAL_E64_ONBOARDING_SCHEMA,
                "synthetic": True,
                "source": "simulator-official-app-candidate",
                "requestCount": self.request_count,
                "scanCount": self.scan_count,
                "lastRequestKeys": list(self.last_request_keys),
                "lastRequestPresence": dict(self.last_request_presence),
                "wireCompatibility": "candidate-only",
            }

    def request_onboarding(self, body: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            self.request_count += 1
            self.last_request_keys = tuple(sorted(str(key) for key in body))
            self.last_request_presence = self._presence(body)
            return {
                "schema": SYNTHETIC_OFFICIAL_E64_ONBOARDING_SCHEMA,
                "synthetic": True,
                "source": "simulator-official-app-candidate",
                "route": "/rest_api/request_onboarding",
                "success": True,
                "accepted": True,
                "wireCompatibility": "candidate-only",
                "requestShape": {
                    "keys": list(self.last_request_keys),
                    "fieldPresence": dict(self.last_request_presence),
                    "valuesRedacted": True,
                },
                # This is the named-field candidate recovered from AOT. The
                # sixth serialized key and the response envelope remain open.
                "appModelCandidate": {
                    "token": SYNTHETIC_OFFICIAL_ONBOARDING_TOKEN,
                    "restUrl": "https://192.168.4.1/",
                    "status": "connected",
                    "subType": "E64_WS",
                    "socketUrl": "wss://192.168.4.1:9997/?token=" + SYNTHETIC_OFFICIAL_ONBOARDING_TOKEN,
                    "unknownField": None,
                },
                "deviceResponse": {
                    "type": "RequestOnboardingResult",
                    "data": {
                        "success": True,
                        "serial": "E64WS-SIM-0001",
                        "firmware": "V01.16-24-mock",
                        "simulator": True,
                    },
                },
            }

    def scan_wifi(self) -> dict[str, Any]:
        with self.lock:
            self.scan_count += 1
            return {
                "schema": SYNTHETIC_OFFICIAL_E64_ONBOARDING_SCHEMA,
                "synthetic": True,
                "source": "simulator-official-app-candidate",
                "route": "/rest_api/scan_wifi",
                "success": True,
                "accepted": True,
                "wireCompatibility": "candidate-only",
                "data": [
                    {
                        "ssid": network["ssid"],
                        "bssid": network["bssid"],
                        "rssi": network["rssi"],
                        "channel": network["channel"],
                        "isWep": False,
                        "encryptionMode": network["security"],
                        "companyName": "synthetic",
                    }
                    for network in SYNTHETIC_APK_NETWORKS
                ],
            }

    def reset(self) -> None:
        with self.lock:
            self.request_count = 0
            self.scan_count = 0
            self.last_request_keys = ()
            self.last_request_presence = {}


@dataclass
class SimulatedLocalApi:
    """Deterministic local owner API v1 fixture.

    The token is a fixed test value; it is not a device credential. The data is
    synthetic and mirrors the shape of the PHP module on a dev-mode device,
    including the redaction predicate, limit clamping and file allowlist.
    """

    token: str = "sim-local-api-token"
    ws_tokens: set[str] = field(default_factory=set)
    serial: str = DEFAULT_SERIAL
    variant: str = "Hsg"
    grinder_type: int = DEFAULT_GRINDER_TYPE
    grinder_sub_type: int = 0
    settings: dict[str, str] = field(default_factory=lambda: {
        "System.Language": "en_US",
        "Standby.ActivationTimeSec": "600",
        "Role.Owner.LoginData": DEFAULT_ROLE_LOGIN_DATA,
        "Role.Technician.LoginData": DEFAULT_ROLE_LOGIN_DATA,
        "Role.Barista.LoginData": DEFAULT_ROLE_LOGIN_DATA,
        "Wifi.StaPassword": DEFAULT_WIFI_STA_PASSWORD,
        "M2m.CoffeeMachinesConfig": "should-not-appear",
        "productionWifiSsid": DEFAULT_WIFI_SSID,
        "Cloud.ConnectionEnabled": "true",
        "Grinding.OvershootWeight": "536960",
    })
    portafilters: list[dict[str, Any]] = field(default_factory=lambda: [
        {"portafilter_id": 1, "weight": 0, "weight_tolerance": 5, "recipe_index": 1},
    ])
    alert_log: list[dict[str, Any]] = field(default_factory=lambda: [
        {"alert_id": 1, "alert_type_id": 1, "alert_type": "WaterEmpty", "alert_date_time": "2026-01-01 00:00:00", "alert_details": "Tank empty", "alert_active": 0},
    ])
    config: dict[str, Any] = field(default_factory=lambda: {
        "configVersion": 1,
        "grinderType": DEFAULT_GRINDER_TYPE,
        "grinderSn": DEFAULT_SERIAL,
        "productionWifiSsid": DEFAULT_WIFI_SSID,
        "productionWifiPassword": DEFAULT_WIFI_PRODUCTION_PASSWORD,
        "cloudBaseUrl": "https://example.com",
        "targetWeightGr": 18.0,
        "grindTimeSec": 30.0,
    })

    #: Mirrors the route list in ``ondevice/rest_api_dev.php``.
    ROUTES: ClassVar[tuple[str, ...]] = (
        "alert_log", "capabilities", "config", "file", "grind_log", "machine",
        "portafilters", "recipes", "service_log", "settings", "ws_token",
    )
    #: Mirrors ``$E64LOCAL_GRINDER_TYPE_NAMES`` in ``ondevice/rest_api_dev.php``.
    GRINDER_TYPE_NAMES: ClassVar[dict[int, str]] = {
        0: "E64 WS", 1: "E65T GbS", 2: "E65W GbS", 3: "E80T GbS",
        4: "E80W GbS", 5: "E64 WS", 6: "E64 TS",
    }
    API_VERSION: ClassVar[str] = "1"
    SCHEMA: ClassVar[str] = "e64local-api-v1"
    MAX_REQUEST_BYTES: ClassVar[int] = 16384
    MAX_OFFSET: ClassVar[int] = 1000000
    MAX_ROWS: ClassVar[int] = 5000
    DEFAULT_ROWS: ClassVar[dict[str, int]] = {
        "grind_log": 20, "service_log": 500, "alert_log": 500,
    }

    #: Mirrors ``$E64LOCAL_REDACT_KEY_SUFFIXES`` in ``ondevice/rest_api_dev.php``.
    REDACT_KEY_SUFFIXES: ClassVar[tuple[str, ...]] = (
        "password", "passwd", "secret", "token", "logindata", "apikey", "api_key", "credential",
    )
    #: Mirrors ``$E64LOCAL_REDACT_KEY_EXACT`` in ``ondevice/rest_api_dev.php``.
    REDACT_KEY_EXACT: ClassVar[frozenset[str]] = frozenset({
        "m2m.coffeemachinesconfig", "productionwifissid", "cloudbaseurl", "mobileapppairingurl",
        "grindersn", "serialnumber", "machineserial", "machineserialnumber", "serial",
    })
    #: Mirrors ``_redactText()`` in ``ondevice/rest_api_dev.php``.
    REDACT_TEXT_PATTERNS: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(
            r'(\bpassword\b|\bpasswd\b|\bpwd\b|\bpsk\b|\bpass\b|\bsecret\b|\btoken\b'
            r'|\bbearer\b|\bsession\b|\bssid\b)\s*(?::|=|\s)\s*["\']?[^\s"\'&\n]{4,}["\']?',
            re.IGNORECASE,
        ),
        re.compile(r'\bSN[\s:#=_-]*[A-Za-z0-9-]{4,}'),
        re.compile(r'\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b', re.IGNORECASE),
        re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b'),
    )
    #: Synthetic /log content, including identifiers the API must redact.
    LOG_FILE_CONTENT: ClassVar[str] = (
        "boot ok password=sim-log-secret ip 192.168.77.23 "
        "mac 02:00:5e:10:00:01 SN 000000123456\n"
    )
    #: Mirrors the exact-file allowlist in ``ondevice/rest_api_dev.php``.
    FILE_ALLOWLIST: ClassVar[tuple[str, ...]] = ("/etc/issue", "/tmp/FirmwareUpdateState.json")
    #: Mirrors ``$E64LOCAL_FILE_ALLOWED_DIRS``.
    FILE_ALLOWED_DIRS: ClassVar[tuple[str, ...]] = ("/log",)
    #: Paths the fixture treats as symlinks; the real module rejects them.
    FILE_SYMLINKS: ClassVar[frozenset[str]] = frozenset({"/log/link"})
    #: Paths the fixture treats as hard links; the real module rejects them.
    FILE_HARDLINKS: ClassVar[frozenset[str]] = frozenset({"/log/hardlink"})
    MAX_FILE_BYTES: ClassVar[int] = 1048576

    #: The fixture's ``/etc/issue`` first line on a dev image: token 0 is
    #: ``development`` and the line has exactly 14 tokens, so the vendor
    #: 14-token gate is open.  Kept as a literal so a test can point at it.
    ISSUE_LINE: ClassVar[str] = (
        "development image, VERSION: HEM-HSG.140-git-g273ab65 "
        "(built through jenkins@36a955b69793 on Tue, 23 Jun 2026 11:02:11 +0000)"
    )
    #: The same line as the shipped image writes it: 14 tokens, token 0
    #: ``custom``, so ``isDevVersion()`` is false.
    STOCK_ISSUE_LINE: ClassVar[str] = (
        "custom image, VERSION: HEM-HSG.140-git-g273ab65 "
        "(built through jenkins@36a955b69793 on Tue, 23 Jun 2026 11:02:11 +0000)"
    )

    #: Deterministic clock for token expiry and rate-limit tests.
    clock: Callable[[], float] = time.time
    #: Action engine (in-memory mirror of the PHP gate and protocol).
    actions: ActionEngine = field(init=False, repr=False)
    #: Open the action gate.  Off by default, like a shipped image; the
    #: end-to-end suites pass --enable-actions so the real protocol can run.
    actions_enabled: bool = False
    #: Open the destructive gate.  Requires actions_enabled.
    destructive_enabled: bool = False
    #: Mirror of ``--dev-gate open|locked``.  A locked fixture is a shipped
    #: image: the module answers HTTP 403 at its dev gate before any route, so
    #: ``/etc/issue`` is the stock line and the synthetic unlock tier is
    #: ``stock``.  This is a fixture switch, not a claim about a device.
    dev_gate_open: bool = True
    #: Synthetic root-only facts, used only for the synthetic unlock tier.
    #: ``None`` means "not observed", which is the honest default: this fixture
    #: owns no SSH channel and cannot read a real ``/etc/issue``.
    synthetic_root_channel: bool | None = None
    #: Synthetic sudoers fact for the synthetic unlock tier.
    synthetic_sudoers: bool | None = None
    #: Synthetic "an action_* route answered with the owner token" fact for the
    #: synthetic unlock tier.  ``None`` means this fixture has not served one.
    synthetic_action_answered: bool | None = None

    #: Mirrors $E64LOCAL_ACTION_META_ROUTES in ondevice/rest_api_dev.php.
    ACTION_ROUTES: ClassVar[tuple[str, ...]] = ACTION_META_ROUTES

    def __post_init__(self) -> None:
        self._apply_env_fallbacks()
        self.actions = ActionEngine(self.settings, self.portafilters, clock=self.clock)
        self.actions.enabled = self.actions_enabled
        self.actions.destructive_enabled = self.destructive_enabled and self.actions_enabled

    def _apply_env_fallbacks(self) -> None:
        """Overlay the optional ``E64_SIM_*`` values on unchanged fixture defaults.

        Runs before the action engine is built, so a written settings row is the
        row every later read sees.  A field that an explicit constructor
        argument already changed is left alone, and with nothing set in the
        environment every branch is a no-op.
        """
        if self.serial == DEFAULT_SERIAL:
            self.serial = _env_fallback("SERIAL") or DEFAULT_SERIAL
        if self.grinder_type == DEFAULT_GRINDER_TYPE:
            raw_type = _env_fallback("GRINDER_TYPE")
            if raw_type is not None:
                try:
                    self.grinder_type = int(raw_type, 10)
                except ValueError:
                    raise ValueError(
                        f"${E64_SIM_ENV_PREFIX}GRINDER_TYPE must be an integer, got {raw_type!r}"
                    ) from None
        for keys, suffix, default in SETTINGS_ENV_FALLBACKS:
            value = _env_fallback(suffix)
            if value is None:
                continue
            for key in keys:
                if self.settings.get(key) == default:
                    self.settings[key] = value
        for key, suffix, default in CONFIG_ENV_FALLBACKS:
            value = _env_fallback(suffix)
            if value is not None and self.config.get(key) == default:
                self.config[key] = value
        # The two documents describe one machine, so they are updated together.
        if self.config.get("grinderSn") == DEFAULT_SERIAL:
            self.config["grinderSn"] = self.serial
        if self.config.get("grinderType") == DEFAULT_GRINDER_TYPE:
            self.config["grinderType"] = self.grinder_type

    def accepts(self, headers: Mapping[str, str], body: Mapping[str, Any] | None) -> bool:
        headers = {str(key).lower(): value for key, value in headers.items()}
        header_token = headers.get("x-e64-local-token", "")
        body_token = ""
        if isinstance(body, Mapping):
            body_token = str(body.get("token", ""))
        provided = str(header_token or body_token)
        return hmac.compare_digest(provided, self.token)

    def mint_ws_token(self) -> str:
        token = uuid.uuid4().hex
        self.ws_tokens.add(token)
        return token

    @classmethod
    def is_sensitive_key(cls, key: Any) -> bool:
        if not isinstance(key, str) or not key:
            return False
        lower = key.lower()
        if lower in cls.REDACT_KEY_EXACT:
            return True
        return any(lower.endswith(suffix) for suffix in cls.REDACT_KEY_SUFFIXES)

    @classmethod
    def redact_settings(cls, settings: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
        kept: dict[str, str] = {}
        redacted: list[str] = []
        for key, value in settings.items():
            if cls.is_sensitive_key(key):
                redacted.append(key)
            else:
                kept[key] = value
        return kept, redacted

    @classmethod
    def _redact_config_value(cls, value: Any, prefix: str, redacted: list[str]) -> Any:
        if not isinstance(value, Mapping):
            return value
        result: dict[str, Any] = {}
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if cls.is_sensitive_key(key):
                redacted.append(path)
                result[key] = "<redacted>"
                continue
            result[key] = cls._redact_config_value(child, path, redacted)
        return result

    @classmethod
    def redact_config(cls, config: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
        redacted: list[str] = []
        return cls._redact_config_value(config, "", redacted), redacted

    @classmethod
    def redact_text(cls, text: Any) -> Any:
        if not isinstance(text, str) or not text:
            return text
        for pattern in cls.REDACT_TEXT_PATTERNS:
            text = pattern.sub("<redacted>", text)
        return text

    @classmethod
    def redact_rows(cls, rows: list[dict[str, Any]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
        cleaned: list[dict[str, Any]] = []
        for row in rows:
            copy = dict(row)
            for field_name in fields:
                if field_name in copy:
                    copy[field_name] = cls.redact_text(copy[field_name])
            cleaned.append(copy)
        return cleaned

    @staticmethod
    def limit_from_body(body: Any, default: int, maximum: int) -> int:
        if not isinstance(body, Mapping):
            return default
        try:
            limit = int(body.get("limit", default))
        except (TypeError, ValueError):
            limit = default
        if limit <= 0:
            limit = default
        if limit > maximum:
            limit = maximum
        return limit

    @classmethod
    def offset_from_body(cls, body: Any) -> int:
        if not isinstance(body, Mapping):
            return 0
        try:
            offset = int(body.get("offset", 0))
        except (TypeError, ValueError):
            offset = 0
        return max(0, min(offset, cls.MAX_OFFSET))

    @staticmethod
    def _normalize_time(value: Any, is_until: bool) -> str | None:
        if value is None or value == "":
            return None
        if isinstance(value, bool):
            raise ValueError("time filter must not be a boolean")
        if isinstance(value, int) or (isinstance(value, str) and value.isdigit() and len(value) <= 10):
            epoch = int(value)
            if epoch < 0 or epoch > 4102444800:
                raise ValueError("time filter is outside the supported range")
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
        if not isinstance(value, str):
            raise ValueError("time filter must be a string or Unix seconds")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?", value):
            raise ValueError(
                "time filter must be YYYY-MM-DD, YYYY-MM-DD HH:MM:SS or Unix seconds"
            )
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(value, fmt)
                return parsed.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        try:
            parsed_date = datetime.strptime(value, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError(
                "time filter must be YYYY-MM-DD, YYYY-MM-DD HH:MM:SS or Unix seconds"
            ) from exc
        parsed_date = parsed_date.replace(
            hour=23, minute=59, second=59
        ) if is_until else parsed_date
        return parsed_date.strftime("%Y-%m-%d %H:%M:%S")

    @classmethod
    def parse_time_filters(cls, body: Any) -> tuple[str | None, str | None]:
        if not isinstance(body, Mapping):
            return None, None
        since = cls._normalize_time(body.get("since"), False)
        until = cls._normalize_time(body.get("until"), True)
        if since is not None and until is not None and since > until:
            raise ValueError("since must not be after until")
        return since, until

    @classmethod
    def page_rows(
        cls,
        rows: list[dict[str, Any]],
        date_key: str,
        limit: int,
        offset: int,
        since: str | None,
        until: str | None,
    ) -> tuple[list[dict[str, Any]], bool]:
        filtered = [
            row for row in rows
            if (since is None or str(row.get(date_key, "")) >= since)
            and (until is None or str(row.get(date_key, "")) <= until)
        ]
        page = filtered[offset:offset + limit]
        return page, len(page) == limit

    @classmethod
    def stringify_rows(cls, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Mirror sqlite3 -csv output: every DB-backed value is a string."""
        return [
            {
                key: (
                    "" if value is None
                    else "1" if value is True
                    else "0" if value is False
                    else str(value)
                )
                for key, value in row.items()
            }
            for row in rows
        ]

    def capabilities(self) -> dict[str, Any]:
        document = self._capabilities_document()
        # Additive and clearly synthetic: no field of the real module's
        # document changes shape, and a client that does not know this key
        # ignores it.  See docs/UNLOCK_TIERS.md.
        document["syntheticUnlockTier"] = self.synthetic_unlock_tier(document)
        return document

    def _capabilities_document(self) -> dict[str, Any]:
        actions = self.actions.capabilities()
        routes = list(self.ROUTES)
        if actions["enabled"]:
            routes.extend(self.ACTION_ROUTES)
        return {
            "schema": self.SCHEMA,
            "route": "capabilities",
            "apiVersion": self.API_VERSION,
            "routes": routes,
            "actions": actions,
            "features": {
                "pagination": True,
                "timeFilters": True,
                "logRowTypes": "strings",
                "recipeExport": "json",
                "csvExport": False,
                "singleRecipe": False,
                "machineIdentity": "serial-sha256",
                "wssToken": True,
                "actions": bool(actions["enabled"]),
                "destructiveActions": bool(actions["destructiveEnabled"]),
            },
            "limits": {
                "maxRows": self.MAX_ROWS,
                "defaultRows": dict(self.DEFAULT_ROWS),
                "maxOffset": self.MAX_OFFSET,
                "maxFileBytes": self.MAX_FILE_BYTES,
                "maxRequestBytes": self.MAX_REQUEST_BYTES,
            },
            "serverTime": int(time.time()),
            "devMode": True,
        }

    def issue_text(self) -> str:
        """The fixture's ``/etc/issue`` first line, after the module's redaction."""
        line = self.ISSUE_LINE if self.dev_gate_open else self.STOCK_ISSUE_LINE
        return self.redact_text(line)

    def synthetic_unlock_facts(self, document: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """The facts this fixture can honestly offer about its own unlock tier.

        The API half comes from the capabilities document itself, through the
        same mapping a client uses.  The root half comes from the fixture's own
        switches, and ``None`` stays ``None``: "this fixture owns no SSH
        channel" is not the same observation as "a channel refused".
        """
        if not self.dev_gate_open:
            # A locked fixture never serves this document: the dev gate answers
            # 403 first.  Reporting the 403 is the honest fact set.
            facts: dict[str, Any] = {
                "api": {"reached": True, "status": 403, "error_code": 403}
            }
        else:
            facts = facts_from_capabilities(
                document if document is not None else self._capabilities_document(),
                status=200,
            )
            if self.synthetic_sudoers is not None:
                facts["api"]["sudoers"] = self.synthetic_sudoers
            elif self.actions_enabled:
                # ``e64root api deploy --enable-actions`` writes the policy file
                # and the runner's sudoers rule in one step (LOCAL_API.md §12.2),
                # so an opened fixture gate implies the rule is there.
                facts["api"]["sudoers"] = True
            if self.synthetic_action_answered is not None:
                facts["api"]["action_answered"] = self.synthetic_action_answered
        facts["root"] = {"channel": self.synthetic_root_channel, "issue": self.issue_text()}
        return facts

    def synthetic_unlock_tier(self, document: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """``{tier, evidence, reasons}`` for this fixture, from tools/unlock_tiers.py."""
        return detect_unlock_tier(self.synthetic_unlock_facts(document))

    def machine(self, grinder: "SimulatedGrinder") -> dict[str, Any]:
        model = self.GRINDER_TYPE_NAMES.get(self.grinder_type, "unknown")
        return {
            "schema": self.SCHEMA,
            "route": "machine",
            "variant": self.variant,
            "model": model,
            "grinderType": self.grinder_type,
            "grinderTypeName": model,
            "grinderSubType": self.grinder_sub_type,
            "firmware": grinder.firmware_build,
            "devMode": grinder.dev_mode,
            "serialPresent": bool(self.serial),
            "serialSha256": hashlib.sha256(self.serial.encode()).hexdigest() if self.serial else None,
            "serialNote": "the raw serial number is never returned by this API",
        }

    def read_file(self, path: Any) -> tuple[str, str] | None:
        """Return (encoding, content) for an allowlisted path, else None."""
        if not isinstance(path, str) or path == "" or "\x00" in path:
            return None
        if path in self.FILE_SYMLINKS or path in self.FILE_HARDLINKS:
            return None
        if path in self.FILE_ALLOWLIST:
            if path == "/etc/issue":
                return ("text", self.issue_text())
            return ("text", '{"state":"Idle"}')
        components = path.split("/")
        if components[0] != "" or len(components) < 3:
            return None
        if components[1] not in {allowed.strip("/") for allowed in self.FILE_ALLOWED_DIRS}:
            return None
        if any(part in ("", ".", "..") for part in components[2:]):
            return None
        return ("text", self.redact_text(self.LOG_FILE_CONTENT))


@dataclass
class SimulatedGrinder:
    """Thread-safe state machine for the recovered E64 command surface."""

    firmware_build: str = "V01.16-24-mock"
    model: str = "Mahlkönig E64 WS (simulator)"
    dd_value_dum: int = 5000
    target_dd_dum: int = 5000
    grind_state: str = "Idle"
    motor_runtime_ms: int = 0
    grind_target_weight_gr: float = 18.0
    fan1_duty: int = 0
    fan2_duty: int = 0
    fan_temperature_ctrl_enabled: bool = True
    language: str = "en"
    dev_mode: bool = True
    backlight_brightness: int = 100
    backlight_on: bool = True
    firmware_update_state: str = "Idle"
    grind_time_sec: float = 0.0
    setup_wizard_state: str = "Completed"
    agsa_status: str = "Ready"
    events: list[dict[str, Any]] = field(default_factory=list)
    last_brew_event: dict[str, Any] | None = None
    replay: list[tuple[float, dict[str, Any]]] = field(default_factory=list, repr=False)
    recipes: list[dict[str, Any]] = field(default_factory=lambda: [dict(r) for r in DEFAULT_RECIPES])
    grind_log: list[dict[str, Any]] = field(default_factory=list)
    service_log: list[dict[str, Any]] = field(default_factory=list)
    grind_started_at: float = 0.0
    replay_position_s: float = 0.0
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def load_replay(self, path: str) -> None:
        """Load a tools/grind_capture.py JSONL trace; states replay by position."""
        samples = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                if not isinstance(record.get("state"), dict) or not isinstance(record.get("t"), (int, float)):
                    raise ValueError("replay lines need numeric t and object state")
                samples.append((float(record["t"]), record["state"]))
        if not samples:
            raise ValueError("replay trace is empty")
        with self.lock:
            self.replay = sorted(samples, key=lambda sample: sample[0])
            self.replay_position_s = self.replay[0][0]

    def seek_replay(self, seconds: Any) -> None:
        position = _number(seconds, "t")
        with self.lock:
            if not self.replay:
                raise ValueError("no replay trace loaded")
            self._move_replay(position)

    def _move_replay(self, position: float) -> None:
        """Move the replay position; a Grind -> Idle crossing appends a grind-log row."""
        before = self.snapshot()
        self.replay_position_s = position
        after = self.snapshot()
        if before.get("grindState") in GRIND_FAMILY and after.get("grindState") not in GRIND_FAMILY:
            last = max((state for at, state in self.replay if at <= position and state.get("grindState") in GRIND_FAMILY),
                       key=lambda state: state.get("motorRunTimeMs") or 0, default=before)
            self.log_grind(after.get("ddValueDum", 0), last.get("motorRunTimeMs") or 0,
                           after.get("grindResultWeightGr") or after.get("grindTargetWeightGr") or 0)

    def log_grind(self, ddd: Any, duration_ms: Any, weight_gr: Any) -> None:
        recipe = self.recipes[0]
        self.grind_log.append({
            "grind_id": len(self.grind_log) + 1, "grind_uuid": str(uuid.uuid4()),
            "grind_date_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "grind_ddd": int(ddd), "grind_duration": int(duration_ms), "grind_duration_noload": 0,
            "grind_weight": int(round(float(weight_gr) * 1000)), "grind_successfull": 1,
            "grind_trigger_id": 3, "grind_trigger": "Wss", "recipe_gbs_enabled": 0, "grind_debug_data": "",
            **recipe,
        })
        self._record("grind_logged", grindId=len(self.grind_log))

    def log_service(self, event_type: str, details: str) -> None:
        """Append a ServiceLogs row; synthetic types, vendor column names."""
        with self.lock:
            self.service_log.append({
                "event_id": len(self.service_log) + 1, "event_type_id": sum(map(ord, event_type)) % 100,
                "event_type": event_type, "event_date_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "event_details": details,
            })

    def seed_service_log(self) -> None:
        """Synthetic rows, including fake identifiers a consumer must redact."""
        self.log_service("PowerOn", "Firmware V01.16-24-mock started")
        self.log_service("WifiConnected", "Connected to SSID SimHomeNet ip 192.168.77.23 mac 02:00:5e:10:00:01 password=sim-wifi-secret")
        self.log_service("SerialNumberRead", "Device SN 000000123456 session 0123456789abcdef0123456789abcdef")

    def machine_logs_zip(self) -> tuple[str, bytes]:
        """A DEFLATE ZIP with the GrindLogs and ServiceLogs CSVs of download_machine_logs."""
        stamp = time.strftime("%Y%m%d_%H%M%S")
        def table(columns: tuple[str, ...], rows: list[dict[str, Any]]) -> str:
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
            writer.writeheader()
            writer.writerows({key: row.get(key, "") for key in columns} for row in rows)
            return buffer.getvalue()
        archive = io.BytesIO()
        with self.lock, zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            package.writestr(f"HemroE64WSGrindLogs_SN000000_{stamp}.csv", table(GRIND_LOG_COLUMNS, self.grind_log[-5000:]))
            package.writestr(f"HemroE64WSServiceLogs_SN000000_{stamp}.csv", table(SERVICE_LOG_COLUMNS, self.service_log))
        self._record("machine_logs_downloaded")
        return f"HemroE64WSMachineLogs_SN000000_{stamp}.zip", archive.getvalue()

    def reset(self) -> None:
        with self.lock:
            self.dd_value_dum = 5000
            self.target_dd_dum = 5000
            self.grind_state = "Idle"
            self.motor_runtime_ms = 0
            self.grind_target_weight_gr = 18.0
            self.fan1_duty = 0
            self.fan2_duty = 0
            self.agsa_status = "Ready"
            self.events.clear()
            self.last_brew_event = None
            self.grind_log.clear()
            self.service_log.clear()
            self.seed_service_log()
            if self.replay:
                self.replay_position_s = self.replay[0][0]

    def advance(self, milliseconds: Any) -> None:
        elapsed = _integer(milliseconds, "ms")
        if elapsed < 0 or elapsed > 3_600_000:
            raise ValueError("ms must be between 0 and 3600000")
        with self.lock:
            if self.replay:
                self._move_replay(self.replay_position_s + elapsed / 1000)
            if self.grind_state == "Grind":
                self.motor_runtime_ms += elapsed

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            if self.replay:
                current = self.replay[0][1]
                for at, state in self.replay:
                    if at > self.replay_position_s:
                        break
                    current = state
                return dict(current)
            return {
                "sessionId": "sim-session-1",
                "configId": "sim-config-1",
                "grindState": self.grind_state,
                "grindFailure": False,
                "grindCurrentWeightGr": 0.0,
                "grindResultWeightGr": self.grind_target_weight_gr
                if self.grind_state == "Finished"
                else 0.0,
                "grindStartWeightGr": 0.0,
                "grindFinalWeightGr": self.grind_target_weight_gr
                if self.grind_state == "Finished"
                else 0.0,
                "grindTargetWeightGr": self.grind_target_weight_gr,
                "motorRunTimeMs": self.motor_runtime_ms,
                "overshootWeightGr": 0.0,
                "cpuTempFailed": False,
                "cpuTempDegC": 39.0,
                "hasNtc1": True,
                "ntc1Failed": False,
                "ntc1TempDegC": 31.0,
                "ntc2Failed": False,
                "ntc2TempDegC": 30.0,
                "overheatNtc1": False,
                "overheatNtc2": False,
                "hmiTime": "2026-01-01T00:00:00Z",
                "hmiProdDate": "2025-01-01",
                "fanTemperatureCtrlEnabled": self.fan_temperature_ctrl_enabled,
                "fan1Duty": self.fan1_duty,
                "fan2Duty": self.fan2_duty,
                "fan1TachoRpm": 0,
                "fan2TachoRpm": 0,
                "fan1Failed": False,
                "fan2Failed": False,
                "ddValueDum": self.dd_value_dum,
                "agsaHallSensorCounts": self.dd_value_dum,
                "ddSensorAngle": self.dd_value_dum / 10.0,
                "ddSensorFailed": False,
                "agsaStatus": self.agsa_status,
                "shiftCompensationFailed": False,
                "espUartFailed": False,
                "espSdioState": "Alive",
                "espFuseFailed": False,
                "espAlive": True,
                "espVersionNo": "V01.11-1",
                "espUpdateRequired": False,
                "language": self.language,
                "setupWizardState": self.setup_wizard_state,
                "simulator": True,
            }

    def config(self) -> dict[str, Any]:
        with self.lock:
            return {
                "firmwareBuild": self.firmware_build,
                "model": self.model,
                "ddMinDum": 0,
                "ddMaxDum": 10000,
                "ddUnit": "dum",
                "supportsGbs": True,
                "supportsAddBrewEvent": True,
                "simulator": True,
            }

    def _record(self, event: str, **data: Any) -> None:
        self.events.append({"event": event, **data})
        del self.events[:-100]

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(message, Mapping):
            return {"type": "UnknownType", "data": {"success": False}}
        command_type = message.get("type")
        msg_id = message.get("msgId")
        if command_type == "RequestDriverState":
            return {"type": "RequestDriverStateResult", "refId": msg_id, "data": self.snapshot()}
        if command_type == "RequestDriverConfig":
            return {"type": "RequestDriverConfigResult", "refId": msg_id, "data": self.config()}
        if command_type == "RequestNachineInfo":
            return {
                "type": "RequestNachineInfoResult",
                "refId": msg_id,
                # A development image reports grinderType "Unknown" (DEV_MODE_AND_LOCAL_CONTROL.md).
                "data": {"grinderType": "Unknown" if self.dev_mode else "E64 WS",
                         "model": self.model, "firmware": self.firmware_build, "simulator": True},
            }
        if command_type == "RequestLogMessages":
            with self.lock:
                return {
                    "type": "RequestLogMessagesResult",
                    "refId": msg_id,
                    "data": {"skippedLogMessages": 0, "logMessages": list(self.events)},
                }
        if command_type == "RequestConfigManagerSettings":
            return {
                "type": "RequestConfigManagerSettingsResult",
                "refId": msg_id,
                "data": {"simulator": True},
            }
        if command_type != "GrinderAction":
            return {"type": "UnknownType", "refId": msg_id, "data": {"success": False}}

        data = message.get("data")
        if not isinstance(data, Mapping):
            return {"type": "UnknownType", "refId": msg_id, "data": {"success": False}}
        suffix = data.get("actionType")
        if suffix not in ACTION_SUFFIXES:
            return {"type": "UnknownType", "refId": msg_id, "data": {"success": False}}
        if suffix == "GbsCreateReport":
            with self.lock:
                return {
                    "type": "GbsCreateReport",
                    "data": {
                        "firmwareBuild": self.firmware_build,
                        "algorithm": "GbS1",
                        "ddValueDum": self.dd_value_dum,
                        "sampleCount": 0,
                        "simulator": True,
                    },
                }

        try:
            self._apply_action(suffix, data)
        except ValueError as exc:
            return {
                "type": "GrinderActionResult",
                "refId": msg_id,
                "data": {"success": False, "error": str(exc)},
            }
        return {"type": "GrinderActionResult", "refId": msg_id, "data": {"success": True}}

    def _apply_action(self, suffix: str, data: Mapping[str, Any]) -> None:
        with self.lock:
            if suffix == "Stop":
                if self.grind_state == "Grind":
                    elapsed = self.motor_runtime_ms or int((time.monotonic() - self.grind_started_at) * 1000)
                    self.log_grind(self.dd_value_dum, elapsed, self.grind_target_weight_gr)
                self.grind_state = "Idle"
                self.agsa_status = "Ready"
            elif suffix in {"StartGrindManual", "StartGrindGbw", "StartGrindGbt"}:
                self.grind_state = "Grind"
                self.grind_started_at = time.monotonic()
                self.motor_runtime_ms = 0
                if suffix == "StartGrindGbw" and "targetWeightGr" in data:
                    self.grind_target_weight_gr = _number(data["targetWeightGr"], "targetWeightGr")
                if suffix == "StartGrindGbt" and "grindTimeSec" in data:
                    seconds = _number(data["grindTimeSec"], "grindTimeSec")
                    if seconds < 0 or seconds > 600:
                        raise ValueError("grindTimeSec must be between 0 and 600")
                self._record("grind_started", action=suffix)
            elif suffix == "SetAgsaTargetDdValue":
                target = _integer(data.get("targetDdValue"), "targetDdValue")
                if not 0 <= target <= 10000:
                    raise ValueError("simulator targetDdValue must be between 0 and 10000")
                self.target_dd_dum = target
                self.dd_value_dum = target
                self.agsa_status = "Ready"
                self._record("dd_changed", value=target)
            elif suffix in {"SetFan1Duty", "SetFan2Duty"}:
                duty = _integer(data.get("dutyPercent"), "dutyPercent")
                if not 0 <= duty <= 100:
                    raise ValueError("dutyPercent must be between 0 and 100")
                if suffix == "SetFan1Duty":
                    self.fan1_duty = duty
                else:
                    self.fan2_duty = duty
            elif suffix == "SetFanTemperatureCtrlEnabled":
                if not isinstance(data.get("enabled"), bool):
                    raise ValueError("enabled must be boolean")
                self.fan_temperature_ctrl_enabled = data["enabled"]
            elif suffix == "SetLanguage":
                language = data.get("language")
                if not isinstance(language, str) or not language:
                    raise ValueError("language must be non-empty text")
                self.language = language
            elif suffix == "SetSetupWizardState":
                state = data.get("state")
                if not isinstance(state, str) or state not in {"NotRun", "Disabled", "Completed"}:
                    raise ValueError("invalid setup wizard state")
                self.setup_wizard_state = state
            elif suffix == "AddBrewEvent":
                required = ("grindUuid", "machineName", "groupHead", "doseIndex", "validity", "brewTimeMs", "brewWeightMg")
                missing = [key for key in required if key not in data]
                if missing:
                    raise ValueError("missing AddBrewEvent fields: " + ",".join(missing))
                self.last_brew_event = {key: data[key] for key in required}
                self._record("brew_event", **dict(data))
            elif suffix == "ResetDriverConfig":
                self.fan1_duty = 0
                self.fan2_duty = 0
                self.fan_temperature_ctrl_enabled = True
            elif suffix in {"StartCalibration", "StartTara", "CalibrateDdSensor"}:
                self.agsa_status = "Calibrating"
                self._record("maintenance", action=suffix)
            elif suffix == "SetBacklightBrightness":
                brightness = _integer(data.get("brightness"), "brightness")
                if not 0 <= brightness <= 100:
                    raise ValueError("brightness must be between 0 and 100")
                self.backlight_brightness = brightness
                self._record("backlight", brightness=brightness)
            elif suffix == "StopAgsa":
                self.agsa_status = "Ready"
            else:
                self._record("action", action=suffix)

    def state_document(
        self,
        scale: SimulatedScale,
        apk_provisioning: SimulatedApkProvisioning | None = None,
        official_onboarding: SimulatedOfficialE64Onboarding | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            result = {
                "grinder": self.snapshot(),
                "config": self.config(),
                "scale": scale.frame(),
                "events": list(self.events),
                "lastBrewEvent": self.last_brew_event,
            }
            if apk_provisioning is not None:
                result["apkProvisioning"] = apk_provisioning.status()
            if official_onboarding is not None:
                result["officialAppOnboarding"] = official_onboarding.status()
            return result


class _HttpHandler(BaseHTTPRequestHandler):
    server_version = "E64Simulator/1"

    @property
    def simulator(
        self,
    ) -> tuple[
        SimulatedGrinder,
        SimulatedScale,
        SimulatedAuth,
        SimulatedApkProvisioning,
        SimulatedOfficialE64Onboarding | None,
        SimulatedLocalApi,
    ]:
        return self.server.simulator  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(
        self,
        status: int,
        value: Any,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for name, header_value in (headers or {}).items():
            self.send_header(name, header_value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _path(self) -> str:
        return urlsplit(self.path).path

    def _require_session(self, auth: SimulatedAuth) -> bool:
        if auth.accepts({str(key): str(value) for key, value in self.headers.items()}):
            return True
        self._json(401, {"error": "simulator REST session required"})
        return False

    def _local_error(
        self,
        status: int,
        code: int,
        message: str,
        data: dict[str, Any] | None = None,
        retry_after: int | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "error": message, "success": False, "errorCode": code, "simulator": True,
        }
        if data is not None:
            payload["data"] = data
        if retry_after is not None:
            payload["retryAfter"] = retry_after
        self._json(status, payload)

    def _local_ok(self, data: dict[str, Any]) -> None:
        self._json(200, {"data": data, "success": True, "errorCode": 0, "simulator": True})

    def _body(self) -> dict[str, Any]:
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            # Dart's HttpClient (the Decaid plugin host) streams bodies chunked.
            raw = b""
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                if len(raw) + size > 1_048_576:
                    raise ValueError("request body too large")
                raw += self.rfile.read(size)
                self.rfile.readline()
            raw = raw or b"{}"
        else:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
        self._raw_body_size = len(raw)  # type: ignore[attr-defined]
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        grinder, scale, auth, apk_provisioning, official_onboarding, local_api = self.simulator
        path = self._path().rstrip("/") or "/"
        if path == "/" or path == "/index.html":
            asset = Path(__file__).with_name("e64ws_simulator_ui.html")
            body = asset.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(str(asset))[0] or "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/sim/state":
            self._json(200, grinder.state_document(scale, apk_provisioning, official_onboarding))
            return
        if path == "/sim/events":
            self._json(200, {"events": grinder.events})
            return
        if path == "/rest_api/ping":
            self._json(200, {"success": True, "simulator": True})
            return
        if path == "/rest_api/check_session":
            if self._require_session(auth):
                self._json(200, {"success": True, "role": auth.role, "simulator": True})
            return
        if path == "/rest_api/update_session":
            if self._require_session(auth):
                try:
                    self._json(200, auth.update())
                except ValueError as exc:
                    self._json(401, {"error": str(exc)})
            return
        if path == "/rest_api/get_machine_info":
            if self._require_session(auth):
                self._json(200, {"model": grinder.model, "firmware": grinder.firmware_build, "simulator": True})
            return
        if path == "/rest_api/get_fw_update_state":
            if self._require_session(auth):
                self._json(200, {"state": "Idle", "simulator": True})
            return
        if path == "/rest_api/get_wifi_info":
            if self._require_session(auth):
                self._json(200, {"connected": True, "ssid": "simulator-lan", "simulator": True})
            return
        # Explicitly synthetic APK provisioning surface. This is intentionally
        # unauthenticated and local so app onboarding tests do not depend on
        # cloud sessions. It must not be read as recovered firmware behavior.
        if path == "/api/v2/network":
            self._json(200, apk_provisioning.status())
            return
        if path == "/api/v2/network/list":
            self._json(200, apk_provisioning.list_networks())
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        grinder, scale, auth, apk_provisioning, official_onboarding, local_api = self.simulator
        path = self._path().rstrip("/") or "/"
        try:
            body = self._body()
            # Explicitly synthetic APK provisioning fixture. The fixture uses
            # only E64-SIM-* networks and never persists/returns credentials.
            if path == "/api/v2/network/forcescan":
                self._json(200, apk_provisioning.force_scan())
                return
            if path == "/api/v2/network/connect":
                try:
                    self._json(200, apk_provisioning.connect(body))
                except ValueError as exc:
                    self._json(422, {
                        "schema": SYNTHETIC_APK_NETWORK_SCHEMA,
                        "synthetic": True,
                        "source": "simulator-apk-provisioning",
                        "operation": "connect",
                        "connected": False,
                        "error": str(exc),
                    })
                return
            if path == "/rest_api/login":
                result = auth.login(body.get("userRole"), body.get("password"))
                grinder.log_service("LogIn", f"Role {result['role']} logged in")
                self._json(
                    200,
                    result,
                    {
                        "Authorization": f"Bearer {auth.wss_token}",
                        "Set-Cookie": f"PHPSESSID={auth.cookie}; Path=/; HttpOnly",
                    },
                )
                return
            if path == "/rest_api/logout":
                if not self._require_session(auth):
                    return
                auth.logout({str(key): str(value) for key, value in self.headers.items()})
                self._json(
                    200,
                    {"success": True, "simulator": True},
                    {"Set-Cookie": "PHPSESSID=deleted; Path=/; Max-Age=0"},
                )
                return
            if path == "/rest_api/download_machine_logs":
                if not self._require_session(auth):
                    return
                name, payload = grinder.machine_logs_zip()
                self.send_response(200)
                self.send_header("Content-Description", "File Transfer")
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path in {
                "/rest_api/check_session",
                "/rest_api/update_session",
                "/rest_api/get_machine_info",
                "/rest_api/get_fw_update_state",
                "/rest_api/get_wifi_info",
            }:
                if not self._require_session(auth):
                    return
                if path == "/rest_api/update_session":
                    self._json(200, auth.update())
                elif path == "/rest_api/check_session":
                    self._json(200, {"success": True, "role": auth.role, "simulator": True})
                elif path == "/rest_api/get_machine_info":
                    self._json(200, {"model": grinder.model, "firmware": grinder.firmware_build, "simulator": True})
                elif path == "/rest_api/get_fw_update_state":
                    self._json(200, {"state": "Idle", "simulator": True})
                else:
                    self._json(200, {"connected": True, "ssid": "simulator-lan", "simulator": True})
                return
            if path in {
                "/rest_api/request_onboarding",
                "/rest_api/reboot",
                "/rest_api/scan_wifi",
            }:
                if not self._require_session(auth):
                    return
                if path == "/rest_api/request_onboarding":
                    if official_onboarding is not None:
                        self._json(200, official_onboarding.request_onboarding(body))
                    else:
                        self._json(200, {
                            "success": True,
                            "simulator": True,
                            "route": path,
                            "schema": SYNTHETIC_FIRMWARE_PLACEHOLDER_SCHEMA,
                            "synthetic": True,
                            "source": "recovered-firmware-rest-placeholder",
                            "forwardedType": "RequestOnboarding",
                            "accepted": True,
                            "dataKeys": sorted(body),
                            "deviceResponse": None,
                        })
                elif path == "/rest_api/scan_wifi":
                    if official_onboarding is not None:
                        self._json(200, official_onboarding.scan_wifi())
                    else:
                        self._json(200, {
                            "success": True,
                            "simulator": True,
                            "route": path,
                            "schema": SYNTHETIC_FIRMWARE_PLACEHOLDER_SCHEMA,
                            "synthetic": True,
                            "source": "recovered-firmware-rest-placeholder",
                            "operation": "scan_wifi",
                            "accepted": True,
                            "deviceResponse": None,
                            "networkFixture": "/api/v2/network/list",
                        })
                else:
                    self._json(200, {"success": True, "simulator": True, "route": path})
                return
            # Local API v1 routes (owner token required)
            if path in {
                f"/rest_api/{route}"
                for route in SimulatedLocalApi.ROUTES + SimulatedLocalApi.ACTION_ROUTES
            }:
                if not grinder.dev_mode:
                    self._local_error(403, 403, "dev mode required")
                    return
                if not self._require_session(auth):
                    return
                if getattr(self, "_raw_body_size", 0) > local_api.MAX_REQUEST_BYTES:
                    self._local_error(
                        413, 413,
                        f"request body too large (max {local_api.MAX_REQUEST_BYTES} bytes)",
                    )
                    return
                # Check local API token
                if not local_api.accepts({str(key).lower(): str(value) for key, value in self.headers.items()}, body):
                    self._local_error(401, 401, "owner token required")
                    return
                route = path.split("/")[-1]

                if route in local_api.ACTION_ROUTES:
                    try:
                        if route == "action_prepare":
                            data = local_api.actions.prepare(grinder, body)
                        elif route == "action_execute":
                            data = local_api.actions.execute(grinder, body)
                        elif route == "action_status":
                            data = local_api.actions.status(body)
                        elif route == "action_cancel":
                            data = local_api.actions.cancel(grinder, body)
                        else:
                            limit = local_api.limit_from_body(
                                body, 50, 1000
                            )
                            offset = local_api.offset_from_body(body)
                            since, until = local_api.parse_time_filters(body)
                            since_epoch = (
                                int(time.mktime(time.strptime(since, "%Y-%m-%d %H:%M:%S")))
                                if since is not None else None
                            )
                            until_epoch = (
                                int(time.mktime(time.strptime(until, "%Y-%m-%d %H:%M:%S")))
                                if until is not None else None
                            )
                            data = local_api.actions.audit_page(limit, offset, since_epoch, until_epoch)
                            data["since"] = since
                            data["until"] = until
                    except ActionError as exc:
                        self._local_error(
                            exc.code, exc.code, exc.message,
                            data=exc.data, retry_after=exc.retry_after,
                        )
                        return
                    except ValueError as exc:
                        self._local_error(400, 400, str(exc))
                        return
                    self._local_ok(data)
                    return

                def log_page(
                    rows: list[dict[str, Any]],
                    date_key: str,
                    field_name: str,
                ) -> None:
                    limit = local_api.limit_from_body(
                        body, local_api.DEFAULT_ROWS[route], local_api.MAX_ROWS
                    )
                    offset = local_api.offset_from_body(body)
                    try:
                        since, until = local_api.parse_time_filters(body)
                    except ValueError as exc:
                        self._local_error(400, 400, str(exc))
                        return
                    page, has_more = local_api.page_rows(
                        rows, date_key, limit, offset, since, until
                    )
                    page = local_api.redact_rows(
                        local_api.stringify_rows(page), (field_name,)
                    )
                    self._local_ok({
                        "schema": local_api.SCHEMA,
                        "route": route,
                        "rows": page,
                        "count": len(page),
                        "limit": limit,
                        "offset": offset,
                        "since": since,
                        "until": until,
                        "hasMore": has_more,
                    })

                if route == "grind_log":
                    log_page(list(reversed(grinder.grind_log)), "grind_date_time", "grind_debug_data")
                elif route == "service_log":
                    log_page(list(reversed(grinder.service_log)), "event_date_time", "event_details")
                elif route == "alert_log":
                    log_page(list(reversed(local_api.alert_log)), "alert_date_time", "alert_details")
                elif route == "portafilters":
                    rows = local_api.stringify_rows(list(local_api.portafilters))
                    self._local_ok({
                        "schema": local_api.SCHEMA,
                        "route": "portafilters",
                        "rows": rows,
                        "count": len(rows),
                    })
                elif route == "recipes":
                    rows = []
                    for entry in grinder.recipes:
                        rows.append({
                            "recipe_index": entry.get("recipe_index", 1),
                            "recipe_data_id": entry.get("recipe_data_id", 1),
                            "recipe_active": entry.get("recipe_active", 1),
                            "recipe_cpr_id": entry.get("recipe_cpr_id", 1),
                            "recipe_uuid": entry.get("recipe_uuid", ""),
                            "recipe_mode_id": entry.get("recipe_mode_id", 2),
                            "recipe_mode": entry.get("recipe_mode", "GbW"),
                            "recipe_amount": entry.get("recipe_amount", 18000),
                            "recipe_type_id": entry.get("recipe_type_id", 1),
                            "recipe_type": entry.get("recipe_type", "Espresso, double"),
                            "recipe_icon_id": entry.get("recipe_icon_id", 1),
                            "recipe_icon": entry.get("recipe_icon", "cup"),
                            "recipe_coarseness": entry.get("recipe_coarseness", 500),
                            "recipe_brew_time": entry.get("recipe_brew_time", 27000),
                            "recipe_brew_weight": entry.get("recipe_brew_weight", 36000),
                        })
                    rows = local_api.stringify_rows(rows)
                    self._local_ok({
                        "schema": local_api.SCHEMA,
                        "route": "recipes",
                        "rows": rows,
                        "count": len(rows),
                    })
                elif route == "settings":
                    settings, redacted = local_api.redact_settings(local_api.settings)
                    self._local_ok({
                        "schema": local_api.SCHEMA,
                        "route": "settings",
                        "settings": settings,
                        "redacted": redacted,
                        "count": len(settings),
                    })
                elif route == "config":
                    config, redacted = local_api.redact_config(local_api.config)
                    config["_e64local_schema"] = local_api.SCHEMA
                    config["_e64local_route"] = "config"
                    self._local_ok({
                        "schema": local_api.SCHEMA,
                        "route": "config",
                        "config": config,
                        "redacted": redacted,
                    })
                elif route == "file":
                    file_path = body.get("path", "") if isinstance(body, Mapping) else ""
                    file_data = local_api.read_file(file_path)
                    if file_data is None:
                        self._local_error(400, 400, "file not in allowlist")
                        return
                    encoding, content = file_data
                    self._local_ok({
                        "schema": local_api.SCHEMA,
                        "route": "file",
                        "path": file_path,
                        "encoding": encoding,
                        "content": content,
                    })
                elif route == "capabilities":
                    self._local_ok(local_api.capabilities())
                elif route == "machine":
                    self._local_ok(local_api.machine(grinder))
                elif route == "ws_token":
                    ws_token = local_api.mint_ws_token()
                    self._local_ok({
                        "schema": local_api.SCHEMA,
                        "route": "ws_token",
                        "token": ws_token,
                        "expires": int(time.time()) + 300,
                        "warning": "this token authorises WSS commands; it is not a read-only data credential",
                    })
                return
            # Action identifiers are not HTTP paths.  Authenticate first so the
            # response cannot be used as an unauthenticated oracle.
            if path.startswith("/rest_api/action_"):
                if not grinder.dev_mode:
                    self._local_error(403, 403, "dev mode required")
                    return
                if not self._require_session(auth):
                    return
                if getattr(self, "_raw_body_size", 0) > local_api.MAX_REQUEST_BYTES:
                    self._local_error(
                        413, 413,
                        f"request body too large (max {local_api.MAX_REQUEST_BYTES} bytes)",
                    )
                    return
                if not local_api.accepts({str(key).lower(): str(value) for key, value in self.headers.items()}, body):
                    self._local_error(401, 401, "owner token required")
                    return
                name = path.split("/")[-1]
                if BOUNDARY_RE.match(name):
                    self._local_error(
                        403, 403,
                        "ESP, WiFi, firmware, fuse and bootloader operations are outside this API by construction",
                    )
                elif CREDENTIAL_RE.match(name):
                    self._local_error(
                        403, 403,
                        "credential-bearing operations are outside this API by owner decision",
                    )
                else:
                    self._local_error(
                        404, 404,
                        "action identifiers are not HTTP paths; use action_prepare",
                    )
                return
            if path == "/sim/reset":
                grinder.reset()
                scale.__dict__.update(SimulatedScale().__dict__)
                apk_provisioning.reset()
            elif path == "/sim/advance":
                grinder.advance(body.get("ms", 100))
                scale.milliseconds += _number(body.get("ms", 100), "ms")
            elif path == "/sim/replay/seek":
                grinder.seek_replay(body.get("t"))
            elif path == "/sim/scale":
                scale.set_sample(body.get("grams"), body.get("ms"))
            elif path == "/sim/scale/tare":
                scale.tare()
            elif path == "/sim/scale/connect":
                scale.connected = bool(body.get("connected", True))
            elif path == "/sim/action":
                suffix = body.get("suffix")
                data = body.get("data", {})
                if not isinstance(suffix, str) or not isinstance(data, dict):
                    raise ValueError("action requires string suffix and object data")
                response = grinder.handle(
                    {"type": "GrinderAction", "msgId": 1, "data": {"actionType": suffix, **data}}
                )
                if response.get("data", {}).get("success") is False:
                    self._json(422, response)
                    return
            elif path == "/sim/shot/start":
                scale.milliseconds = 0.0
                scale.sequence += 1
                grinder._record("shot_started")
            elif path == "/sim/shot/sample":
                scale.set_sample(body.get("grams"), body.get("ms"))
            elif path == "/sim/shot/stop":
                grinder._record("shot_stopped", finalScale=scale.frame())
            else:
                self._json(404, {"error": "not found"})
                return
            if official_onboarding is not None:
                official_onboarding.reset()
            self._json(200, grinder.state_document(scale, apk_provisioning, official_onboarding))
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})


def _http_server(
    host: str,
    port: int,
    grinder: SimulatedGrinder,
    scale: SimulatedScale,
    auth: SimulatedAuth,
    apk_provisioning: SimulatedApkProvisioning | None = None,
    official_onboarding: SimulatedOfficialE64Onboarding | None = None,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    actions_enabled: bool = False,
    destructive_enabled: bool = False,
    api_token: str | None = None,
) -> ThreadingHTTPServer:
    if bool(tls_cert) != bool(tls_key):
        raise SystemExit(
            "--http-tls-cert and --http-tls-key must be supplied together"
        )
    server = ThreadingHTTPServer((host, port), _HttpHandler)
    if tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.simulator = (  # type: ignore[attr-defined]
        grinder,
        scale,
        auth,
        apk_provisioning or SimulatedApkProvisioning(),
        official_onboarding,
        SimulatedLocalApi(
            token=api_token or "sim-local-api-token",
            actions_enabled=actions_enabled,
            destructive_enabled=destructive_enabled,
            # The fixture's dev gate and the local API's own gate are the same
            # device state: with --dev-gate locked the module answers 403, so
            # the synthetic unlock tier must be stock, not dev.
            dev_gate_open=grinder.dev_mode,
        ),
    )
    thread = threading.Thread(target=server.serve_forever, name="e64-sim-http", daemon=True)
    thread.start()
    return server


async def _e64_handler(websocket: Any, path: str, grinder: SimulatedGrinder, token: str) -> None:
    query = parse_qs(urlsplit(path or getattr(websocket, "path", "")).query)
    if query.get("token", [None])[0] != token:
        await websocket.close(code=1008, reason="invalid simulator token")
        return
    async for raw in websocket:
        try:
            message = json.loads(raw)
            if not grinder.dev_mode and dev_gated(message):
                # Locked image: handleMessage returns 0 and the socket is closed silently.
                await websocket.close()
                return
            response = grinder.handle(message)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            response = {"type": "UnknownType", "data": {"success": False, "error": str(exc)}}
        await websocket.send(json.dumps(response, separators=(",", ":")))


async def _scale_handler(websocket: Any, path: str, scale: SimulatedScale) -> None:
    if urlsplit(path or getattr(websocket, "path", "")).path != "/snapshot":
        await websocket.close(code=1008, reason="use /snapshot")
        return

    async def sender() -> None:
        while True:
            await websocket.send(json.dumps(scale.frame(), separators=(",", ":")))
            await asyncio.sleep(0.1)

    async def receiver() -> None:
        async for raw in websocket:
            try:
                command = json.loads(raw)
                if command == "tare" or (isinstance(command, Mapping) and command.get("command") == "tare"):
                    scale.tare()
                elif isinstance(command, Mapping) and command.get("command") == "sample":
                    scale.set_sample(command.get("grams"), command.get("ms"))
            except (ValueError, TypeError, json.JSONDecodeError):
                continue

    send_task = asyncio.create_task(sender())
    try:
        await receiver()
    finally:
        send_task.cancel()
        await asyncio.gather(send_task, return_exceptions=True)


async def _run_servers(
    args: argparse.Namespace,
    grinder: SimulatedGrinder,
    scale: SimulatedScale,
) -> None:
    try:
        from websockets.legacy.server import serve
    except ImportError:  # pragma: no cover - compatibility fallback
        from websockets.server import serve  # type: ignore[no-redef]

    ssl_context: ssl.SSLContext | None = None
    if bool(args.tls_cert) != bool(args.tls_key):
        raise SystemExit("--tls-cert and --tls-key must be supplied together")
    if args.tls_cert:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(args.tls_cert, args.tls_key)
    scheme = "wss" if ssl_context else "ws"

    async def e64(websocket: Any, path: str) -> None:
        await _e64_handler(websocket, path, grinder, args.token)

    async def scale_ws(websocket: Any, path: str) -> None:
        await _scale_handler(websocket, path, scale)

    async with serve(e64, args.host, args.port, ssl=ssl_context, ping_interval=10), serve(
        scale_ws, args.host, args.scale_port, ssl=ssl_context, ping_interval=10
    ):
        print(f"E64 simulator: {scheme}://{args.host}:{args.port}/?token=<test-token>")
        print(f"OpenScale simulator: {scheme}://{args.host}:{args.scale_port}/snapshot")
        print(f"Control UI: http://{args.host}:{args.http_port}/")
        print(f"REST simulator: http://{args.host}:{args.http_port}/rest_api")
        print("Simulator token is test-only and is not a device credential.")
        await asyncio.Future()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9997)
    parser.add_argument("--scale-port", type=int, default=8765)
    parser.add_argument("--http-port", type=int, default=8787)
    parser.add_argument("--token", default="mock-e64-token-0001")
    parser.add_argument("--session-ttl", type=float, default=900.0)
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--http-tls-cert")
    parser.add_argument("--http-tls-key")
    parser.add_argument(
        "--fw01-login",
        action="store_true",
        help="emulate the FW-01 SELECT-only login construction on /rest_api/login",
    )
    parser.add_argument("--replay", help="replay a tools/grind_capture.py JSONL state trace")
    parser.add_argument("--recipes", help="JSON array of grind-log recipe rows (DEFAULT_RECIPES keys)")
    parser.add_argument(
        "--dev-gate",
        choices=("open", "locked"),
        default="open",
        help="locked emulates a shipped image: dev=1 WSS commands close the socket",
    )
    parser.add_argument(
        "--official-app-fixture",
        action="store_true",
        help="opt in to the synthetic candidate response for APK local onboarding",
    )
    parser.add_argument(
        "--api-token",
        help="owner token the local API expects (default sim-local-api-token); "
        "pass a 64-hex value so a client with a real OwnerToken can send its own",
    )
    parser.add_argument(
        "--enable-actions",
        action="store_true",
        help="open the fixture action gate so the five meta routes can run "
        "(a real image ships with it closed)",
    )
    parser.add_argument(
        "--enable-destructive-actions",
        action="store_true",
        help="also open the destructive gate; requires --enable-actions",
    )
    args = parser.parse_args(argv)
    grinder = SimulatedGrinder(dev_mode=args.dev_gate == "open")
    grinder.seed_service_log()
    if args.replay:
        grinder.load_replay(args.replay)
    if args.recipes:
        grinder.recipes = json.loads(Path(args.recipes).read_text(encoding="utf-8"))
    scale = SimulatedScale()
    auth = SimulatedAuth(args.token, session_ttl_seconds=args.session_ttl, fw01_login=args.fw01_login)
    apk_provisioning = SimulatedApkProvisioning()
    official_onboarding = SimulatedOfficialE64Onboarding() if args.official_app_fixture else None
    http = _http_server(
        args.host,
        args.http_port,
        grinder,
        scale,
        auth,
        apk_provisioning,
        official_onboarding,
        args.http_tls_cert,
        args.http_tls_key,
        actions_enabled=args.enable_actions,
        destructive_enabled=args.enable_destructive_actions,
        api_token=args.api_token,
    )
    try:
        asyncio.run(_run_servers(args, grinder, scale))
    except KeyboardInterrupt:
        return 0
    finally:
        http.shutdown()
        http.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
