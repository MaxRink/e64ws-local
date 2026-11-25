"""Gated local-API action engine for the offline simulator.

This module mirrors the behaviour of the action layer in
``ondevice/rest_api_dev.php`` and ``ondevice/e64local_action_run.php``:

* the same action catalog (implemented and unavailable entries),
* the same canonical-parameter form and HMAC confirm token,
* the same gate, destructive gate, rate limit, idempotency and precondition
  rules,
* the same audit record shape.

It is deterministic and in-memory.  The PHP layer is authoritative; this module
exists so the documented contract has an always-available offline parity fixture
and so the simulator can answer action routes without a device.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Any, Callable, Mapping

ACTION_META_ROUTES: tuple[str, ...] = (
    "action_audit",
    "action_cancel",
    "action_execute",
    "action_prepare",
    "action_status",
)

#: Absolute bounds; the policy may narrow them, never widen them.
ABSOLUTE_BOUNDS: dict[str, dict[str, float]] = {
    "targetWeightGr": {"min": 0.1, "max": 50.0},
    "grindTimeSec": {"min": 0.5, "max": 60.0},
    "manualGrindMs": {"min": 100, "max": 5000},
    "purgeMs": {"min": 100, "max": 10000},
    "agsaStepDd": {"min": 1, "max": 300},
    "fanDuty": {"min": 0, "max": 100},
    "brightness": {"min": 0, "max": 100},
    "brewTimeMs": {"min": 0, "max": 120000},
    "brewWeightMg": {"min": 0, "max": 200000},
    "recipeAmountMg": {"min": 100, "max": 100000},
    "recipeCoarseness": {"min": 0, "max": 10000},
    "standbySec": {"min": 0, "max": 86400},
    "settingsEntries": {"min": 1, "max": 8},
}

DEFAULT_RATES: dict[str, dict[str, int]] = {
    "grind_start": {"perMinute": 6, "perHour": 30},
    "grind_stop": {"perMinute": 60, "perHour": 600},
    "agsa": {"perMinute": 10, "perHour": 120},
    "fan": {"perMinute": 10, "perHour": 120},
    "display": {"perMinute": 30, "perHour": 300},
    "settings_write": {"perMinute": 30, "perHour": 300},
    "recipe_write": {"perMinute": 30, "perHour": 300},
    "brew": {"perMinute": 30, "perHour": 300},
    "calibration": {"perMinute": 2, "perHour": 2},
    "destructive": {"perMinute": 1, "perHour": 1},
    "execute": {"perMinute": 60, "perHour": 600},
    "default": {"perMinute": 30, "perHour": 300},
}

LANGUAGES = ("de", "en", "en_US", "es", "fr", "it", "nl", "pl", "pt", "tr")

SETTING_SPECS: dict[str, dict[str, Any]] = {
    "System.WelcomeName": {"type": "text", "max": 64},
    "System.Name": {"type": "text", "max": 64},
    "System.UseAmPm": {"type": "bool"},
    "System.Brightness.Backlight": {"type": "int", "min": 0, "max": 100},
    "System.Gbw3PointCalibrationEnabled": {"type": "bool"},
    "Temperature.Unit": {"type": "enum", "values": ["C", "F"]},
    "Temperature.ShowOnMainScreen": {"type": "bool"},
    "Grinding.OvershootWeight": {"type": "int", "min": 0, "max": 2000000},
    "Grinding.PurgeValueMs": {"type": "int", "min": 100, "max": 10000},
    "Grinding.Portafilter.DetectionEnabled": {"type": "bool"},
    "Grinding.PortafilterSwitch.Disabled": {"type": "bool"},
    "Grinding.LoadCell.Disabled": {"type": "bool"},
    "Grinding.BreakFunctionEnabled": {"type": "bool"},
    "Gbw.CalibrationCustomWeight": {"type": "int", "min": 0, "max": 5000000},
    "Gbw.CalibrationCustomWeightEnable": {"type": "bool"},
    "Gbw.CalibrationReminderInterval": {"type": "int", "min": 0, "max": 3650},
    "Gbs.Algo.PreventAgsaBrewtimeRange_ms": {"type": "int", "min": 0, "max": 600000},
}

ACTION_CATALOG: dict[str, dict[str, Any]] = {
    "action_grind_start_gbw": {
        "risk": "actuator", "status": "implemented", "surface": "wss",
        "command": "StartGrindGbw", "bucket": "grind_start", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 16)",
        "preconditions": ["update", "state", "wizard", "calibration", "portafilter"],
    },
    "action_grind_start_gbt": {
        "risk": "actuator", "status": "implemented", "surface": "wss",
        "command": "StartGrindGbt", "bucket": "grind_start", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 17)",
        "preconditions": ["update", "state", "wizard", "portafilter"],
    },
    "action_grind_start_manual": {
        "risk": "actuator", "status": "implemented", "surface": "wss",
        "command": "StartGrindManual", "bucket": "grind_start", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (rows 14-15)",
        "preconditions": ["update", "state", "wizard", "portafilter"],
    },
    "action_grind_stop": {
        "risk": "actuator", "status": "implemented", "surface": "wss",
        "command": "Stop", "bucket": "grind_stop", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 14)",
        "preconditions": ["update"],
    },
    "action_grind_purge": {
        "risk": "actuator", "status": "implemented", "surface": "wss",
        "command": "StartGrindGbt", "bucket": "grind_start", "destructive": False,
        "evidence": "docs/GRINDER_FEATURE_MAP.md#3-grinding (Purge)",
        "preconditions": ["update", "state", "wizard", "portafilter"],
    },
    "action_agsa_move": {
        "risk": "actuator", "status": "implemented", "surface": "wss",
        "command": "SetAgsaTargetDdValue", "bucket": "agsa", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 35)",
        "preconditions": ["update", "state", "wizard"],
    },
    "action_agsa_stop": {
        "risk": "actuator", "status": "implemented", "surface": "wss",
        "command": "StopAgsa", "bucket": "agsa", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 36)",
        "preconditions": ["update"],
    },
    "action_agsa_configure": {
        "risk": "state-changing", "status": "implemented", "surface": "sqlite",
        "sqlKind": "settings_set_bulk", "bucket": "settings_write", "destructive": False,
        "evidence": "docs/SQLITE_SCHEMA.md#complete-persistent-key-inventory (Agsa.*)",
        "preconditions": ["update"],
    },
    "action_fan_set": {
        "risk": "actuator", "status": "implemented", "surface": "wss",
        "command": "SetFan1Duty", "bucket": "fan", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (rows 22-24)",
        "preconditions": ["update"],
    },
    "action_display_backlight": {
        "risk": "state-changing", "status": "implemented", "surface": "wss",
        "command": "SetBacklightBrightness", "bucket": "display", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (rows 27-28)",
        "preconditions": ["update"],
    },
    "action_led_set": {
        "risk": "state-changing", "status": "implemented", "surface": "sqlite",
        "sqlKind": "settings_set_bulk", "bucket": "settings_write", "destructive": False,
        "evidence": "docs/SQLITE_SCHEMA.md#settings-and-configuration (Standby.LedColorRgb)",
        "preconditions": ["update"],
    },
    "action_language_set": {
        "risk": "state-changing", "status": "implemented", "surface": "wss",
        "command": "SetLanguage", "bucket": "settings_write", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 40)",
        "preconditions": ["update"],
    },
    "action_standby_configure": {
        "risk": "state-changing", "status": "implemented", "surface": "sqlite",
        "sqlKind": "settings_set_bulk", "bucket": "settings_write", "destructive": False,
        "evidence": "docs/SQLITE_SCHEMA.md#complete-persistent-key-inventory (Standby.*)",
        "preconditions": ["update"],
    },
    "action_settings_set": {
        "risk": "state-changing", "status": "implemented", "surface": "sqlite",
        "sqlKind": "settings_set_bulk", "bucket": "settings_write", "destructive": False,
        "evidence": "docs/SQLITE_SCHEMA.md#settings-and-configuration",
        "preconditions": ["update"],
    },
    "action_recipe_activate": {
        "risk": "state-changing", "status": "implemented", "surface": "sqlite",
        "sqlKind": "recipe_activate", "bucket": "recipe_write", "destructive": False,
        "evidence": "docs/SQLITE_SCHEMA.md (recipe_entries.recipe_active)",
        "preconditions": ["update"],
    },
    "action_recipe_create": {
        "risk": "state-changing", "status": "implemented", "surface": "sqlite",
        "sqlKind": "recipe_create", "bucket": "recipe_write", "destructive": False,
        "evidence": "docs/SQLITE_SCHEMA.md (recipe_data/recipe_entries)",
        "preconditions": ["update"],
    },
    "action_recipe_update": {
        "risk": "state-changing", "status": "implemented", "surface": "sqlite",
        "sqlKind": "recipe_update", "bucket": "recipe_write", "destructive": False,
        "evidence": "docs/SQLITE_SCHEMA.md (recipe_data columns)",
        "preconditions": ["update"],
    },
    "action_recipe_delete": {
        "risk": "destructive", "status": "implemented", "surface": "sqlite",
        "sqlKind": "recipe_delete", "bucket": "destructive", "destructive": True,
        "evidence": "docs/GRINDER_FEATURE_MAP.md#5-recipes-and-presets",
        "preconditions": ["update"],
    },
    "action_calibration_loadcell": {
        "risk": "destructive", "status": "implemented", "surface": "wss",
        "command": "StartCalibration", "bucket": "calibration", "destructive": True,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 18)",
        "preconditions": ["update", "state", "wizard", "role-limitation"],
    },
    "action_calibration_tare": {
        "risk": "destructive", "status": "implemented", "surface": "wss",
        "command": "StartTara", "bucket": "calibration", "destructive": True,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 19)",
        "preconditions": ["update", "state", "wizard", "role-limitation"],
    },
    "action_calibration_dd": {
        "risk": "destructive", "status": "implemented", "surface": "wss",
        "command": "CalibrateDdSensor", "bucket": "calibration", "destructive": True,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 37)",
        "preconditions": ["update", "state", "wizard", "role-limitation"],
    },
    "action_logs_clear": {
        "risk": "destructive", "status": "implemented", "surface": "wss",
        "command": "ResetLog", "bucket": "destructive", "destructive": True,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 21)",
        "preconditions": ["update"],
    },
    "action_statistics_reset": {
        "risk": "destructive", "status": "implemented", "surface": "sqlite",
        "sqlKind": "statistics_reset", "bucket": "destructive", "destructive": True,
        "evidence": "docs/SQLITE_SCHEMA.md (Statistics.Reset.*)",
        "preconditions": ["update"],
    },
    "action_driver_reset": {
        "risk": "destructive", "status": "implemented", "surface": "wss",
        "command": "ResetDriverConfig", "bucket": "destructive", "destructive": True,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 34)",
        "preconditions": ["update"],
    },
    "action_brew_event_add": {
        "risk": "state-changing", "status": "implemented", "surface": "wss",
        "command": "AddBrewEvent", "bucket": "brew", "destructive": False,
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 38)",
        "preconditions": ["update"],
    },
    "action_fan_calibrate": {
        "risk": "actuator", "status": "unavailable", "code": 422,
        "reason": "CalibrateFan1/2 has no completion signal or duration bound",
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (rows 25-26)",
    },
    "action_endurance_start": {
        "risk": "actuator", "status": "unavailable", "code": 422,
        "reason": "StartEnduranceTest is an unbounded loop with no host-side watchdog",
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 50)",
    },
    "action_endurance_stop": {
        "risk": "actuator", "status": "unavailable", "code": 422,
        "reason": "no endurance run can be started through this API",
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 51)",
    },
    "action_rc_input": {
        "risk": "actuator", "status": "unavailable", "code": 422,
        "reason": "Rc* press/release pairs cannot be bounded or undone",
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (rows 41-49)",
    },
    "action_gbs_report": {
        "risk": "state-changing", "status": "unavailable", "code": 422,
        "reason": "GbsCreateReport replies with a non-standard envelope",
        "evidence": "docs/API_REFERENCE.md#25-grinderaction-suffixes-39 (row 39)",
    },
    "action_recipe_clone": {
        "risk": "state-changing", "status": "unavailable", "code": 422,
        "reason": "no vendor surface; deferred compound read+create",
        "evidence": "docs/GRINDER_FEATURE_MAP.md#5-recipes-and-presets",
    },
    "action_recipe_import": {
        "risk": "state-changing", "status": "unavailable", "code": 422,
        "reason": "no vendor route; bulk import has no validated payload contract",
        "evidence": "docs/GRINDER_FEATURE_MAP.md#5-recipes-and-presets",
    },
    "action_factory_reset": {
        "risk": "destructive", "status": "unavailable", "code": 422,
        "reason": "no REST/WSS factory-reset surface; only the physical emergency script exists",
        "evidence": "docs/SQLITE_SCHEMA.md#corruption-reset-retention-and-export",
    },
}

BOUNDARY_RE = re.compile(
    r"^action_(esp|wifi|firmware|fuse|otp|bootloader|pairing|onboarding|cloud)_"
)

#: Credential writes are excluded by owner decision.  The names are absent from
#: the catalog and refused explicitly, never reported as an unavailable action.
CREDENTIAL_RE = re.compile(r"^action_(role|password|credential|login)_")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class ActionError(Exception):
    """A refusal that maps to the local API error envelope."""

    def __init__(
        self,
        code: int,
        message: str,
        retry_after: int | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after
        self.data = data


def canonical(value: Any) -> str:
    """Language-neutral canonical form; must match _actionCanonical() in PHP."""
    if isinstance(value, Mapping):
        parts = []
        for key in sorted(value.keys(), key=lambda item: str(item)):
            text = str(key)
            parts.append(
                "k" + str(len(text.encode("utf-8"))) + ":" + text + "=" + canonical(value[key])
            )
        return "a" + str(len(parts)) + "{" + ",".join(parts) + "}"
    if isinstance(value, bool):
        return "b:" + ("1" if value else "0")
    if isinstance(value, int):
        return "i:" + str(value)
    if isinstance(value, float):
        return "d:{:.6f}".format(value)
    text = str(value)
    return "s:" + str(len(text.encode("utf-8"))) + ":" + text


def params_hash(params: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical(params).encode("utf-8")).hexdigest()


def confirm_token(
    secret: str, action_id: str, route: str, param_hash: str, expires: int, request_id: str
) -> str:
    message = "|".join([action_id, route, param_hash, str(expires), request_id])
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def _int_param(params: Mapping[str, Any], key: str, low: int, high: int, required: bool) -> int | None:
    if key not in params:
        if required:
            raise ActionError(422, key + " is required")
        return None
    value = params[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ActionError(422, key + " must be a JSON integer")
    if value < low or value > high:
        raise ActionError(422, f"{key} must be between {low} and {high}")
    return value


def _number_param(params: Mapping[str, Any], key: str, low: float, high: float, required: bool) -> float | None:
    if key not in params:
        if required:
            raise ActionError(422, key + " is required")
        return None
    value = params[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ActionError(422, key + " must be a JSON number")
    if value != value or value in (float("inf"), float("-inf")):
        raise ActionError(422, key + " must be finite")
    if value < low or value > high:
        raise ActionError(422, f"{key} must be between {low} and {high}")
    return float(value)


def _bool_param(params: Mapping[str, Any], key: str, required: bool) -> bool | None:
    if key not in params:
        if required:
            raise ActionError(422, key + " is required")
        return None
    if not isinstance(params[key], bool):
        raise ActionError(422, key + " must be a JSON boolean")
    return params[key]


def _enum_param(params: Mapping[str, Any], key: str, values: tuple[str, ...], required: bool) -> str | None:
    if key not in params:
        if required:
            raise ActionError(422, key + " is required")
        return None
    value = params[key]
    if not isinstance(value, str) or value not in values:
        raise ActionError(422, key + " must be one of " + ", ".join(values))
    return value


def _only_keys(params: Any, allowed: tuple[str, ...]) -> Mapping[str, Any]:
    if params is None:
        return {}
    if not isinstance(params, Mapping):
        raise ActionError(422, "params must be a JSON object")
    for key in params:
        if not isinstance(key, str) or key not in allowed:
            raise ActionError(422, "unknown parameter " + str(key))
    return params


def _setting_value(key: str, value: Any) -> Any:
    spec = SETTING_SPECS.get(key)
    if spec is None:
        raise ActionError(422, "setting key is not allowlisted: " + key)
    kind = spec["type"]
    if kind == "bool":
        if not isinstance(value, bool):
            raise ActionError(422, key + " expects a JSON boolean")
        return value
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ActionError(422, key + " expects a JSON integer")
        if value < spec["min"] or value > spec["max"]:
            raise ActionError(422, f"{key} is outside {spec['min']}..{spec['max']}")
        return value
    if kind == "enum":
        if not isinstance(value, str) or value not in spec["values"]:
            raise ActionError(422, key + " has an unsupported value")
        return value
    if not isinstance(value, str) or len(value) > spec["max"]:
        raise ActionError(422, key + " is too long")
    if not re.fullmatch(r"[\w .\-]*", value, re.UNICODE):
        raise ActionError(422, key + " contains unsupported characters")
    return value


def _entries(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [{"key": key, "value": values[key]} for key in sorted(values)]


class ActionEngine:
    """In-memory mirror of the PHP gate, protocol and catalog."""

    def __init__(
        self,
        settings: dict[str, str],
        portafilters: list[dict[str, Any]],
        clock: Callable[[], float] = time.time,
        secret: str = "0123456789abcdef" * 4,
        monotonic: Callable[[], float] = time.monotonic,
        boot_id: str = "00000000-0000-4000-8000-000000000000",
    ) -> None:
        self.settings = settings
        self.portafilters = portafilters
        self.clock = clock
        self.secret = secret
        #: Monotonic seconds, the domain of the rate-limit events.  Separate
        #: from ``clock`` (wall clock), which only formats timestamps.
        self.monotonic = monotonic
        #: The boot this engine models; a record from another boot is refused.
        self.boot_id = boot_id
        self.enabled = False
        self.destructive_enabled = False
        self.records: dict[str, dict[str, Any]] = {}
        self.audit: list[dict[str, Any]] = []
        self.rate: dict[str, list[int]] = {}
        self.bounds = {name: dict(value) for name, value in ABSOLUTE_BOUNDS.items()}
        self.rates = {name: dict(value) for name, value in DEFAULT_RATES.items()}

    def monotonic_now(self) -> int:
        """Monotonic milliseconds; the rate-limit timestamp domain."""
        return int(float(self.monotonic()) * 1000)

    # -- gate -----------------------------------------------------------------

    def gate_reason(self) -> str | None:
        if not self.enabled:
            return "actions are not enabled (policy file missing)"
        return None

    def require_gate(self) -> None:
        if not self.enabled:
            raise ActionError(403, "actions are not enabled (policy file missing)")

    def capabilities(self) -> dict[str, Any]:
        implemented = [
            route
            for route, entry in ACTION_CATALOG.items()
            if entry["status"] == "implemented"
            and (self.destructive_enabled or not entry.get("destructive"))
        ]
        catalog = []
        for route, entry in ACTION_CATALOG.items():
            item = {
                "route": route,
                "status": entry["status"],
                "risk": entry["risk"],
                "destructive": bool(entry.get("destructive")),
                "surface": entry.get("surface"),
                "summary": entry.get("summary"),
                "evidence": entry["evidence"],
            }
            if entry["status"] == "unavailable":
                item["reason"] = entry["reason"]
            elif entry.get("destructive") and not self.destructive_enabled:
                # A route the gate would refuse is not dispatchable, so it must
                # not be advertised as one.
                item["blocked"] = "destructive actions are disabled"
            catalog.append(item)
        document: dict[str, Any] = {
            "schema": "e64local-api-v1",
            "enabled": self.enabled,
            "destructiveEnabled": self.enabled and self.destructive_enabled,
            "reason": self.gate_reason(),
            "actionRoutes": implemented if self.enabled else [],
            "catalog": catalog,
            "note": "action identifiers are passed in action_prepare, not posted as paths",
        }
        if self.enabled:
            document["policy"] = {
                "version": 1,
                "bounds": self.effective_bounds(),
                "rateLimits": self.effective_rates(),
                "tokenTtlSec": {"actuator": 60, "stateChanging": 600, "destructive": 60},
                "audit": {"file": "/db/e64local/audit.jsonl", "maxBytes": 1048576, "keep": 3},
            }
        return document

    # -- audit and rate -------------------------------------------------------

    def _client(self) -> dict[str, Any]:
        return {"addr": "127.0.0.1", "uaSha256": None}

    def _audit(
        self,
        phase: str,
        route: str,
        action_id: str | None,
        request_id: str | None,
        param_hash: str | None,
        result: str | None,
        error_code: int,
        retry_after: int | None = None,
        duration_ms: int | None = None,
    ) -> None:
        now = int(self.clock())
        self.audit.append({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "tsEpoch": now,
            "phase": phase,
            "route": route,
            "actionId": action_id,
            "requestId": request_id,
            "paramsHash": param_hash,
            "result": result,
            "errorCode": error_code,
            "retryAfter": retry_after,
            "durationMs": duration_ms,
            "client": self._client(),
        })

    def _rate_limit(self, bucket: str) -> None:
        limits = self.effective_rates().get(bucket, self.effective_rates()["default"])
        now = self.monotonic_now()
        events = self.rate.get(bucket, [])
        if any(not isinstance(event, int) or event > now for event in events):
            # A stored event in the future cannot be produced by a monotonic
            # source; fail closed instead of pruning it away.
            raise ActionError(500, "rate-limit state is unusable")
        events = [event for event in events if event > now - 3_600_000]
        minute = [event for event in events if event > now - 60_000]
        if limits["perMinute"] <= 0 or limits["perHour"] <= 0:
            raise ActionError(429, "rate limit exceeded", 3600)
        if len(minute) >= limits["perMinute"]:
            raise ActionError(429, "rate limit exceeded", max(1, (60_000 - (now - min(minute))) // 1000))
        if len(events) >= limits["perHour"]:
            raise ActionError(429, "rate limit exceeded", max(1, (3_600_000 - (now - min(events))) // 1000))
        events.append(now)
        self.rate[bucket] = events

    # -- params ---------------------------------------------------------------

    def effective_bounds(self) -> dict[str, dict[str, float]]:
        """Return the bounds after the code-side clamp; never wider than absolute.

        The policy (here: ``self.bounds``) may narrow a range.  Both ends are
        clamped back into the absolute range so a policy that puts its minimum
        above the absolute maximum cannot invert the range and widen it.
        """
        effective: dict[str, dict[str, float]] = {}
        for name, absolute in ABSOLUTE_BOUNDS.items():
            configured = self.bounds.get(name, absolute)
            low = min(max(float(configured["min"]), absolute["min"]), absolute["max"])
            high = min(max(float(configured["max"]), absolute["min"]), absolute["max"])
            if high <= low:
                # A policy that clamps to a point is not a usable range; fall
                # back to the absolute range (the wider one), never a policy one.
                low, high = absolute["min"], absolute["max"]
            effective[name] = {"min": low, "max": high}
        return effective

    def effective_rates(self) -> dict[str, dict[str, int]]:
        """Return the rate limits after the clamp; a policy can only tighten."""
        effective: dict[str, dict[str, int]] = {}
        for name, default in DEFAULT_RATES.items():
            configured = self.rates.get(name, default)
            effective[name] = {
                "perMinute": min(default["perMinute"], max(0, int(configured["perMinute"]))),
                "perHour": min(default["perHour"], max(0, int(configured["perHour"]))),
            }
        return effective

    def _bound(self, name: str) -> dict[str, float]:
        return self.effective_bounds()[name]

    def normalize(self, route: str, raw: Any, grinder: Any) -> dict[str, Any]:
        params = _only_keys(raw, tuple()) if raw is None else raw

        if route == "action_grind_start_gbw":
            params = _only_keys(params, ("targetWeightGr",))
            bound = self._bound("targetWeightGr")
            value = _number_param(params, "targetWeightGr", bound["min"], bound["max"], True)
            return {"targetWeightGr": value}

        if route == "action_grind_start_gbt":
            params = _only_keys(params, ("grindTimeSec",))
            bound = self._bound("grindTimeSec")
            value = _number_param(params, "grindTimeSec", bound["min"], bound["max"], True)
            return {"grindTimeSec": value}

        if route == "action_grind_start_manual":
            params = _only_keys(params, ("durationMs",))
            bound = self._bound("manualGrindMs")
            value = _int_param(params, "durationMs", int(bound["min"]), int(bound["max"]), False)
            return {"durationMs": 1500 if value is None else value}

        if route in (
            "action_grind_stop", "action_agsa_stop", "action_calibration_loadcell",
            "action_calibration_tare", "action_calibration_dd", "action_logs_clear",
            "action_statistics_reset", "action_driver_reset",
        ):
            _only_keys(params, tuple())
            return {}

        if route == "action_grind_purge":
            params = _only_keys(params, ("durationMs",))
            bound = self._bound("purgeMs")
            value = _int_param(params, "durationMs", int(bound["min"]), int(bound["max"]), False)
            if value is None:
                configured = self.settings.get("Grinding.PurgeValueMs", "200")
                value = int(configured) if str(configured).isdigit() else 200
                value = max(int(bound["min"]), min(int(bound["max"]), value))
            return {"durationMs": value}

        if route == "action_agsa_move":
            params = _only_keys(params, ("targetDdValue",))
            value = _int_param(params, "targetDdValue", 0, 10000, True)
            return {"targetDdValue": value}

        if route == "action_agsa_configure":
            params = _only_keys(
                params,
                ("enabled", "startWithRecipeDd", "showRecipeDd", "blockageWarningThreshold"),
            )
            values: dict[str, Any] = {}
            values["Agsa.AgsaUponRecipeChange"] = _bool_param(params, "enabled", True)
            if "startWithRecipeDd" in params:
                values["Agsa.AgsaStartWithRecipeDd"] = _bool_param(params, "startWithRecipeDd", True)
            if "showRecipeDd" in params:
                values["Agsa.ShowRecipeDdEnabled"] = _bool_param(params, "showRecipeDd", True)
            if "blockageWarningThreshold" in params:
                values["Agsa.BlockageWarningThreshold"] = _int_param(
                    params, "blockageWarningThreshold", 0, 10000, True
                )
            return {"entries": _entries(values)}

        if route == "action_fan_set":
            params = _only_keys(params, ("fan", "dutyPercent", "temperatureCtrlEnabled"))
            fan = _int_param(params, "fan", 1, 2, True)
            bound = self._bound("fanDuty")
            duty = _int_param(params, "dutyPercent", int(bound["min"]), int(bound["max"]), True)
            normalized: dict[str, Any] = {"fan": fan, "dutyPercent": duty}
            if "temperatureCtrlEnabled" in params:
                normalized["temperatureCtrlEnabled"] = _bool_param(params, "temperatureCtrlEnabled", True)
            return normalized

        if route == "action_display_backlight":
            params = _only_keys(params, ("brightness", "power"))
            if "brightness" not in params and "power" not in params:
                raise ActionError(422, "brightness or power is required")
            bound = self._bound("brightness")
            normalized = {}
            brightness = _int_param(params, "brightness", int(bound["min"]), int(bound["max"]), False)
            power = _enum_param(params, "power", ("toggle",), False)
            if brightness is not None:
                normalized["brightness"] = brightness
            if power is not None:
                normalized["power"] = power
            return normalized

        if route == "action_led_set":
            params = _only_keys(
                params, ("enabled", "colorRgb", "permanentLighting", "colorFading", "permanentColorRgb")
            )
            if not params:
                raise ActionError(422, "at least one LED field is required")
            mapping = {
                "enabled": ("Standby.LedEnabled", "bool"),
                "colorRgb": ("Standby.LedColorRgb", "color"),
                "permanentLighting": ("System.PermanentLedLightingEnabled", "bool"),
                "colorFading": ("System.PermanentLedColorFadingEnabled", "bool"),
                "permanentColorRgb": ("System.PermanentLedColorRgb", "color"),
            }
            values = {}
            for param, (key, kind) in mapping.items():
                if param not in params:
                    continue
                value = params[param]
                if kind == "bool":
                    if not isinstance(value, bool):
                        raise ActionError(422, key + " expects a JSON boolean")
                    values[key] = value
                else:
                    if not isinstance(value, str) or not re.fullmatch(r"#[0-9A-Fa-f]{6}", value):
                        raise ActionError(422, key + " expects #RRGGBB")
                    values[key] = value.upper()
            return {"entries": _entries(values)}

        if route == "action_language_set":
            params = _only_keys(params, ("language",))
            return {"language": _enum_param(params, "language", LANGUAGES, True)}

        if route == "action_standby_configure":
            params = _only_keys(
                params,
                ("activationTimeSec", "ledEnabled", "shiftTimesEnabled", "shiftTimeBegin", "shiftTimeEnd"),
            )
            if not params:
                raise ActionError(422, "at least one standby field is required")
            values = {}
            if "activationTimeSec" in params:
                bound = self._bound("standbySec")
                values["Standby.ActivationTimeSec"] = _int_param(
                    params, "activationTimeSec", int(bound["min"]), int(bound["max"]), True
                )
            if "ledEnabled" in params:
                values["Standby.LedEnabled"] = _bool_param(params, "ledEnabled", True)
            shift = _bool_param(params, "shiftTimesEnabled", False)
            if shift is not None:
                values["Standby.ShiftTimesEnabled"] = shift
            for param, key in (
                ("shiftTimeBegin", "Standby.ShiftTimeBegin"),
                ("shiftTimeEnd", "Standby.ShiftTimeEnd"),
            ):
                if param not in params:
                    continue
                value = params[param]
                if not isinstance(value, str) or not re.fullmatch(r"([01][0-9]|2[0-3]):[0-5][0-9]", value):
                    raise ActionError(422, key + " expects HH:MM")
                values[key] = value
            if shift is True:
                begin = params.get("shiftTimeBegin", self.settings.get("Standby.ShiftTimeBegin"))
                end = params.get("shiftTimeEnd", self.settings.get("Standby.ShiftTimeEnd"))
                if not begin or not end:
                    raise ActionError(422, "enabling shift times requires shiftTimeBegin and shiftTimeEnd")
            return {"entries": _entries(values)}

        if route == "action_settings_set":
            params = _only_keys(params, ("settings",))
            settings = params.get("settings")
            if not isinstance(settings, Mapping):
                raise ActionError(422, "settings must be a JSON object")
            bound = self._bound("settingsEntries")
            if len(settings) < bound["min"] or len(settings) > bound["max"]:
                raise ActionError(422, "settings must contain between 1 and 8 entries")
            values = {}
            for key, value in settings.items():
                if not isinstance(key, str) or key not in SETTING_SPECS:
                    raise ActionError(422, "setting key is not allowlisted: " + str(key))
                values[key] = _setting_value(key, value)
            return {"entries": _entries(values)}

        if route == "action_recipe_activate":
            params = _only_keys(params, ("recipeIndex",))
            return {"recipeIndex": _int_param(params, "recipeIndex", 1, 1000, True)}

        if route == "action_recipe_create":
            params = _only_keys(
                params,
                ("recipeIndex", "modeId", "amountMg", "typeId", "iconId", "coarseness", "brewTimeMs", "brewWeightMg"),
            )
            amount_bound = self._bound("recipeAmountMg")
            coarse_bound = self._bound("recipeCoarseness")
            time_bound = self._bound("brewTimeMs")
            weight_bound = self._bound("brewWeightMg")
            return {
                "recipeIndex": _int_param(params, "recipeIndex", 1, 1000, True),
                "modeId": _int_param(params, "modeId", 1, 1000, True),
                "amountMg": _int_param(params, "amountMg", int(amount_bound["min"]), int(amount_bound["max"]), True),
                "typeId": _int_param(params, "typeId", 1, 1000, True),
                "iconId": _int_param(params, "iconId", 1, 1000, True),
                "coarseness": _int_param(params, "coarseness", int(coarse_bound["min"]), int(coarse_bound["max"]), True),
                "brewTimeMs": _int_param(params, "brewTimeMs", int(time_bound["min"]), int(time_bound["max"]), True),
                "brewWeightMg": _int_param(params, "brewWeightMg", int(weight_bound["min"]), int(weight_bound["max"]), True),
                "uuid": str(uuid.uuid4()),
            }

        if route == "action_recipe_update":
            params = _only_keys(
                params,
                ("recipeIndex", "modeId", "amountMg", "typeId", "iconId", "coarseness", "brewTimeMs", "brewWeightMg"),
            )
            index = _int_param(params, "recipeIndex", 1, 1000, True)
            fields = ("modeId", "amountMg", "typeId", "iconId", "coarseness", "brewTimeMs", "brewWeightMg")
            if not any(field in params for field in fields):
                raise ActionError(422, "at least one recipe field is required")
            recipe = self._recipe(grinder, index)
            amount_bound = self._bound("recipeAmountMg")
            coarse_bound = self._bound("recipeCoarseness")
            time_bound = self._bound("brewTimeMs")
            weight_bound = self._bound("brewWeightMg")
            limits = {
                "modeId": (1, 1000),
                "amountMg": (int(amount_bound["min"]), int(amount_bound["max"])),
                "typeId": (1, 1000),
                "iconId": (1, 1000),
                "coarseness": (int(coarse_bound["min"]), int(coarse_bound["max"])),
                "brewTimeMs": (int(time_bound["min"]), int(time_bound["max"])),
                "brewWeightMg": (int(weight_bound["min"]), int(weight_bound["max"])),
            }
            normalized = {"recipeIndex": index}
            for field in fields:
                if field in params:
                    normalized[field] = _int_param(params, field, limits[field][0], limits[field][1], True)
                else:
                    normalized[field] = {
                        "modeId": recipe.get("recipe_mode_id", 2),
                        "amountMg": recipe.get("recipe_amount", 18000),
                        "typeId": recipe.get("recipe_type_id", 1),
                        "iconId": recipe.get("recipe_icon_id", 1),
                        "coarseness": recipe.get("recipe_coarseness", 500),
                        "brewTimeMs": recipe.get("recipe_brew_time", 27000),
                        "brewWeightMg": recipe.get("recipe_brew_weight", 36000),
                    }[field]
            return normalized

        if route == "action_recipe_delete":
            params = _only_keys(params, ("recipeIndex",))
            return {"recipeIndex": _int_param(params, "recipeIndex", 1, 1000, True)}

        if route == "action_brew_event_add":
            params = _only_keys(
                params,
                ("grindUuid", "doseIndex", "validity", "brewTimeMs", "brewWeightMg", "machineName", "groupHead"),
            )
            grind_uuid = params.get("grindUuid")
            if not isinstance(grind_uuid, str) or not UUID_RE.match(grind_uuid):
                raise ActionError(422, "grindUuid must be a lowercase UUID")
            time_bound = self._bound("brewTimeMs")
            weight_bound = self._bound("brewWeightMg")
            normalized = {
                "grindUuid": grind_uuid,
                "doseIndex": _int_param(params, "doseIndex", 0, 1000, False) or 0,
                "validity": _bool_param(params, "validity", True),
                "brewTimeMs": _int_param(params, "brewTimeMs", int(time_bound["min"]), int(time_bound["max"]), True),
                "brewWeightMg": _int_param(params, "brewWeightMg", int(weight_bound["min"]), int(weight_bound["max"]), True),
            }
            for key in ("machineName", "groupHead"):
                if key in params:
                    value = params[key]
                    if not isinstance(value, str) or not value or len(value) > 64 or not re.fullmatch(r"[\w .\-]+", value, re.UNICODE):
                        raise ActionError(422, key + " must be 1..64 safe characters")
                    normalized[key] = value
            return normalized

        raise ActionError(404, "unknown action")

    # -- data lookups ---------------------------------------------------------

    @staticmethod
    def _recipes(grinder: Any) -> list[dict[str, Any]]:
        return grinder.recipes

    def _recipe(self, grinder: Any, index: int) -> dict[str, Any]:
        for recipe in self._recipes(grinder):
            if int(recipe.get("recipe_index", 0)) == index:
                return recipe
        raise ActionError(404, "recipe slot does not exist")

    # -- preconditions --------------------------------------------------------

    def preconditions(self, grinder: Any, route: str, params: Mapping[str, Any]) -> list[str]:
        entry = ACTION_CATALOG[route]
        checks = entry.get("preconditions", [])
        warnings: list[str] = []

        if "role-limitation" in checks:
            warnings.append(
                "the module cannot verify the vendor session role; calibration is documented as "
                "Owner/Technician only and this API cannot enforce it"
            )
        if "update" in checks:
            update_state = getattr(grinder, "firmware_update_state", "Idle")
            if str(update_state).lower() != "idle":
                raise ActionError(409, f"firmware update in progress ({update_state})")

        state = None
        if "state" in checks:
            state = grinder.snapshot()
            grind_state = state.get("grindState", "")
            starts = route in (
                "action_grind_start_gbw", "action_grind_start_gbt",
                "action_grind_start_manual", "action_grind_purge",
            )
            if starts and grind_state != "Idle":
                raise ActionError(409, f"the grinder is not idle (grindState={grind_state})")
            if starts and state.get("grindFailure"):
                raise ActionError(409, "the last grind reported a failure")
            if state.get("overheatNtc1") or state.get("overheatNtc2"):
                raise ActionError(409, "a temperature sensor reports overheat")
            if state.get("espAlive") is False:
                raise ActionError(409, "the ESP co-processor is not reported alive")
            sdio = str(state.get("espSdioState", ""))
            if any(word in sdio.lower() for word in ("fail", "error", "down", "dead")):
                raise ActionError(409, f"the ESP SDIO link reports a failure ({sdio})")
            if state.get("ddSensorFailed") is True:
                raise ActionError(409, "the disc-distance sensor reports a failure")
            if route == "action_agsa_move":
                current = state.get("ddValueDum")
                if not isinstance(current, (int, float)):
                    raise ActionError(503, "the driver did not report ddValueDum")
                step = int(self._bound("agsaStepDd")["max"])
                if abs(int(params["targetDdValue"]) - int(current)) > step:
                    raise ActionError(
                        409,
                        f"AGSA moves are limited to {step} dd units from the current value "
                        f"(current={int(current)}, requested={int(params['targetDdValue'])})",
                    )
                warnings.append(
                    "no vendor-reported dd minimum/maximum was recovered, so this API allows only "
                    "incremental moves from the live value"
                )
        if "wizard" in checks and state is not None and state.get("setupWizardState") == "NotRun":
            raise ActionError(409, "the setup wizard has not run")
        if "calibration" in checks:
            last = self.settings.get("Gbw.LastGbwCalibrationDate")
            if last is not None and str(last).strip() == "":
                raise ActionError(409, "no load-cell calibration date is recorded")
            if last is None:
                warnings.append(
                    "Gbw.LastGbwCalibrationDate is not present on this firmware; the calibration "
                    "precondition could not be evaluated"
                )
        if "portafilter" in checks:
            if not self.portafilters:
                raise ActionError(409, "no portafilter is configured")

        if route in ("action_recipe_create", "action_recipe_activate", "action_recipe_delete"):
            index = int(params["recipeIndex"])
            found = any(int(recipe.get("recipe_index", 0)) == index for recipe in self._recipes(grinder))
            if route == "action_recipe_create" and found:
                raise ActionError(409, f"recipe slot {index} is already in use")
            if route != "action_recipe_create" and not found:
                raise ActionError(404, f"recipe slot {index} does not exist")
            if route == "action_recipe_delete":
                recipe = self._recipe(grinder, index)
                if int(recipe.get("recipe_active", 0)) == 1:
                    raise ActionError(409, "the active recipe cannot be deleted")
                if len(self._recipes(grinder)) <= 1:
                    raise ActionError(409, "the last recipe cannot be deleted")
        if route == "action_brew_event_add" and getattr(grinder, "grind_log", None) is not None:
            uuids = {str(row.get("grind_uuid", "")) for row in grinder.grind_log}
            if params["grindUuid"] not in uuids:
                raise ActionError(404, "no grind with that UUID exists")

        for record in self.records.values():
            if record.get("state") == "executing" and record.get("route") == route:
                raise ActionError(409, "an incompatible action is already executing")
        return warnings

    # -- execution ------------------------------------------------------------

    def _apply_sql(self, grinder: Any, route: str, params: Mapping[str, Any]) -> dict[str, Any]:
        kind = ACTION_CATALOG[route].get("sqlKind")
        if kind == "settings_set_bulk":
            for entry in params["entries"]:
                value = entry["value"]
                self.settings[entry["key"]] = (
                    "true" if value is True else "false" if value is False else str(value)
                )
            return {"kind": kind, "keys": [entry["key"] for entry in params["entries"]]}
        if kind == "statistics_reset":
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(self.clock())))
            self.settings["Statistics.Reset.TimeStamp"] = stamp
            self.settings["Statistics.Reset.Today.TimeStamp"] = stamp
            return {"kind": kind, "timestamp": stamp}
        if kind == "recipe_activate":
            index = int(params["recipeIndex"])
            for recipe in self._recipes(grinder):
                recipe["recipe_active"] = 1 if int(recipe.get("recipe_index", 0)) == index else 0
            return {"kind": kind, "recipeIndex": index}
        if kind == "recipe_delete":
            index = int(params["recipeIndex"])
            self._recipes(grinder)[:] = [
                recipe for recipe in self._recipes(grinder)
                if int(recipe.get("recipe_index", 0)) != index
            ]
            return {"kind": kind, "recipeIndex": index}
        if kind == "recipe_create":
            index = int(params["recipeIndex"])
            data_id = max(
                [int(recipe.get("recipe_data_id", 0)) for recipe in self._recipes(grinder)] or [0]
            ) + 1
            self._recipes(grinder).append({
                "recipe_index": index,
                "recipe_data_id": data_id,
                "recipe_active": 0,
                "recipe_cpr_id": 0,
                "recipe_uuid": params["uuid"],
                "recipe_mode_id": params["modeId"],
                "recipe_mode": {1: "Time", 2: "GbW"}.get(params["modeId"], "GbW"),
                "recipe_amount": params["amountMg"],
                "recipe_type_id": params["typeId"],
                "recipe_type": "Espresso, double",
                "recipe_icon_id": params["iconId"],
                "recipe_icon": "cup",
                "recipe_coarseness": params["coarseness"],
                "recipe_brew_time": params["brewTimeMs"],
                "recipe_brew_weight": params["brewWeightMg"],
            })
            self._recipes(grinder).sort(key=lambda recipe: int(recipe.get("recipe_index", 0)))
            return {"kind": kind, "recipeIndex": index, "recipeDataId": data_id}
        if kind == "recipe_update":
            index = int(params["recipeIndex"])
            recipe = self._recipe(grinder, index)
            recipe.update({
                "recipe_mode_id": params["modeId"],
                "recipe_amount": params["amountMg"],
                "recipe_type_id": params["typeId"],
                "recipe_icon_id": params["iconId"],
                "recipe_coarseness": params["coarseness"],
                "recipe_brew_time": params["brewTimeMs"],
                "recipe_brew_weight": params["brewWeightMg"],
            })
            return {"kind": kind, "recipeIndex": index}
        raise ActionError(500, "unhandled sql kind")

    def _apply_wss(self, grinder: Any, route: str, params: Mapping[str, Any]) -> dict[str, Any]:
        if route == "action_display_backlight" and "brightness" not in params:
            command = "ToggleBacklightPower"
        else:
            command = ACTION_CATALOG[route]["command"]
        if command == "StartGrindGbw":
            grinder.grind_target_weight_gr = params["targetWeightGr"]
            grinder.grind_state = "Grind"
            grinder.motor_runtime_ms = 0
        elif command == "StartGrindGbt":
            seconds = params.get("grindTimeSec")
            if seconds is None:
                # action_grind_purge normalizes to durationMs; GbT takes seconds.
                seconds = params["durationMs"] / 1000.0
            grinder.grind_state = "Grind"
            grinder.motor_runtime_ms = 0
            grinder.grind_time_sec = seconds
        elif command == "StartGrindManual":
            grinder.grind_state = "Grind"
            grinder.motor_runtime_ms = 0
        elif command == "Stop":
            if grinder.grind_state == "Grind":
                grinder.log_grind(
                    grinder.dd_value_dum,
                    grinder.motor_runtime_ms or 1000,
                    grinder.grind_target_weight_gr,
                )
            grinder.grind_state = "Idle"
            grinder.agsa_status = "Ready"
        elif command == "SetAgsaTargetDdValue":
            grinder.dd_value_dum = params["targetDdValue"]
            grinder.target_dd_dum = params["targetDdValue"]
            grinder.agsa_status = "Ready"
        elif command == "StopAgsa":
            grinder.agsa_status = "Ready"
        elif command == "SetFan1Duty":
            grinder.fan1_duty = params["dutyPercent"]
        elif command == "SetFan2Duty":
            grinder.fan2_duty = params["dutyPercent"]
        elif command == "SetFanTemperatureCtrlEnabled":
            grinder.fan_temperature_ctrl_enabled = params["enabled"]
        elif command == "SetBacklightBrightness":
            grinder.backlight_brightness = params["brightness"]
        elif command == "ToggleBacklightPower":
            grinder.backlight_on = not getattr(grinder, "backlight_on", True)
            if not grinder.backlight_on:
                grinder.backlight_brightness = 0
        elif command == "SetLanguage":
            grinder.language = params["language"]
        elif command in ("StartCalibration", "StartTara", "CalibrateDdSensor"):
            grinder.agsa_status = "Calibrating"
        elif command == "ResetLog":
            grinder.grind_log.clear()
            grinder.service_log.clear()
        elif command == "ResetDriverConfig":
            grinder.fan1_duty = 0
            grinder.fan2_duty = 0
            grinder.fan_temperature_ctrl_enabled = True
            grinder.backlight_brightness = 100
        elif command == "AddBrewEvent":
            grinder.last_brew_event = dict(params)
        else:
            raise ActionError(403, "command is not in the runner allowlist")
        return {"command": command}

    def execute_steps(self, grinder: Any, route: str, params: Mapping[str, Any]) -> dict[str, Any]:
        results = []
        if route == "action_display_backlight":
            # Mirrors _actionSteps() in PHP: brightness and power are separate
            # steps, and a power-only request never touches the brightness.
            if "brightness" in params:
                results.append(self._apply_wss(grinder, "action_display_backlight", params))
            if "power" in params:
                results.append(self._apply_wss(grinder, "action_display_backlight", {"power": "toggle"}))
        elif ACTION_CATALOG[route]["surface"] == "wss":
            result = self._apply_wss(grinder, route, params)
            if route == "action_grind_start_manual":
                # The runner sends Stop after the bounded duration; the fixture
                # applies the stop immediately and records it.
                grinder.grind_state = "Idle"
                result["stopSent"] = True
            results.append(result)
            if route == "action_fan_set" and "temperatureCtrlEnabled" in params:
                grinder.fan_temperature_ctrl_enabled = params["temperatureCtrlEnabled"]
                results.append({"command": "SetFanTemperatureCtrlEnabled"})
        else:
            results.append(self._apply_sql(grinder, route, params))
        merged: dict[str, Any] = {"steps": results}
        if len(results) == 1:
            merged.update(results[0])
        return merged

    # -- protocol -------------------------------------------------------------

    def prepare(self, grinder: Any, body: Mapping[str, Any]) -> dict[str, Any]:
        self.require_gate()
        request_id = body.get("requestId")
        if not isinstance(request_id, str) or not REQUEST_ID_RE.match(request_id):
            self._audit("refuse", "action_prepare", None, None, None, "bad_request_id", 400)
            raise ActionError(400, "requestId is required (8..64 characters: A-Z a-z 0-9 . _ -)")
        route = body.get("route")
        if not isinstance(route, str) or not route:
            self._audit("refuse", "action_prepare", None, request_id, None, "missing_route", 400)
            raise ActionError(400, "route is required")

        entry = ACTION_CATALOG.get(route)
        if entry is None:
            if BOUNDARY_RE.match(route):
                self._audit("refuse", route, None, request_id, None, "esp_boundary", 403)
                raise ActionError(
                    403,
                    "ESP, WiFi, firmware, fuse and bootloader operations are outside this API by construction",
                )
            if CREDENTIAL_RE.match(route):
                self._audit("refuse", route, None, request_id, None, "credential_excluded", 403)
                raise ActionError(
                    403, "credential-bearing operations are outside this API by owner decision"
                )
            self._audit("refuse", route, None, request_id, None, "unknown_action", 404)
            raise ActionError(404, "unknown action")
        if entry["status"] != "implemented":
            code = int(entry.get("code", 422))
            self._audit("refuse", route, None, request_id, None, "unavailable", code)
            raise ActionError(code, "action unavailable: " + entry["reason"])
        if entry.get("destructive") and not self.destructive_enabled:
            self._audit("refuse", route, None, request_id, None, "destructive_gate_off", 403)
            raise ActionError(403, "destructive actions are disabled")

        try:
            params = self.normalize(route, body.get("params", {}), grinder)
        except ActionError as exc:
            self._audit("refuse", route, None, request_id, None, "invalid_params", exc.code)
            raise
        param_hash = params_hash(params)

        for record in self.records.values():
            if record["requestId"] != request_id:
                continue
            if record["route"] != route or record["paramsHash"] != param_hash:
                self._audit("refuse", route, record["actionId"], request_id, param_hash, "idempotency_conflict", 409)
                raise ActionError(409, "requestId was already used with different parameters")
            if record.get("bootId") != self.boot_id:
                # The stored token cannot execute in this boot, so a retry
                # prepares a new action instead of returning the dead one.
                record["state"] = "expired"
                continue
            token = confirm_token(
                self.secret, record["actionId"], route, param_hash, int(record["expires"]), request_id
            )
            return {
                "schema": "e64local-api-v1",
                "route": "action_prepare",
                "actionId": record["actionId"],
                "actionRoute": route,
                "confirmToken": token,
                "expires": int(record["expires"]),
                "expiresAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(record["expires"]))),
                "state": record["state"],
                "warnings": record.get("warnings", []),
                "auditId": record.get("auditId"),
                "idempotent": True,
            }

        self._rate_limit(entry["bucket"])
        warnings = self.preconditions(grinder, route, params)
        ttl = 60 if entry.get("destructive") or entry["risk"] == "actuator" else 600
        action_id = str(uuid.uuid4())
        audit_id = str(uuid.uuid4())
        expires = int(self.clock()) + ttl
        token = confirm_token(self.secret, action_id, route, param_hash, expires, request_id)
        self.records[action_id] = {
            "schema": "e64local-action-record-v1",
            "actionId": action_id,
            "auditId": audit_id,
            "route": route,
            "risk": entry["risk"],
            "destructive": bool(entry.get("destructive")),
            "paramsHash": param_hash,
            "params": params,
            "requestId": request_id,
            "state": "prepared",
            "expires": expires,
            "bootId": self.boot_id,
            "preparedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(self.clock()))),
            "preparedAtEpoch": int(self.clock()),
            "warnings": warnings,
            "client": self._client(),
        }
        self._audit("prepare", route, action_id, request_id, param_hash, "prepared", 0)
        return {
            "schema": "e64local-api-v1",
            "route": "action_prepare",
            "actionId": action_id,
            "actionRoute": route,
            "confirmToken": token,
            "expires": expires,
            "expiresAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires)),
            "state": "prepared",
            "warnings": warnings,
            "auditId": audit_id,
        }

    def execute(self, grinder: Any, body: Mapping[str, Any]) -> dict[str, Any]:
        self.require_gate()
        action_id = body.get("actionId")
        token = body.get("confirmToken")
        request_id = body.get("requestId")
        if not isinstance(action_id, str) or not UUID_RE.match(action_id):
            self._audit("refuse", "action_execute", None, None, None, "bad_action_id", 400)
            raise ActionError(400, "actionId is required")
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            self._audit("refuse", "action_execute", action_id, None, None, "bad_confirm_token", 400)
            raise ActionError(400, "confirmToken is required")
        if request_id is not None and (
            not isinstance(request_id, str) or not REQUEST_ID_RE.match(request_id)
        ):
            self._audit("refuse", "action_execute", action_id, None, None, "bad_request_id", 400)
            raise ActionError(400, "requestId is malformed")

        record = self.records.get(action_id)
        if record is None:
            self._audit("refuse", "action_execute", action_id, request_id, None, "unknown_action_id", 404)
            raise ActionError(404, "unknown actionId")
        route = record["route"]
        param_hash = record["paramsHash"]

        if request_id is not None and request_id != record["requestId"]:
            self._audit("refuse", route, action_id, request_id, param_hash, "idempotency_conflict", 409)
            raise ActionError(409, "requestId does not match the prepared action")
        if record["state"] != "prepared":
            self._audit("refuse", route, action_id, record["requestId"], param_hash, "state_" + record["state"], 409)
            raise ActionError(409, "action is not in a state that allows execute")
        if not isinstance(record.get("bootId"), str) or record["bootId"] != self.boot_id:
            # A token prepared before a reboot cannot be executed afterwards:
            # the wall clock may have moved either way, so expiry is not a
            # reliable bound across a reboot.
            record["state"] = "expired"
            self._audit("refuse", route, action_id, record["requestId"], param_hash, "boot_changed", 409)
            raise ActionError(409, "the device has rebooted since this action was prepared")
        if int(self.clock()) > int(record["expires"]):
            record["state"] = "expired"
            self._audit("refuse", route, action_id, record["requestId"], param_hash, "expired", 409)
            raise ActionError(409, "the confirm token has expired")

        expected = confirm_token(
            self.secret, action_id, route, param_hash, int(record["expires"]), record["requestId"]
        )
        if not hmac.compare_digest(expected, token):
            self._audit("refuse", route, action_id, record["requestId"], param_hash, "token_mismatch", 403)
            raise ActionError(403, "confirm token does not match this action")
        if params_hash(record["params"]) != param_hash:
            self._audit("refuse", route, action_id, record["requestId"], param_hash, "record_integrity", 500)
            raise ActionError(500, "the prepared action record failed its integrity check")

        entry = ACTION_CATALOG.get(route)
        if entry is None or entry["status"] != "implemented":
            self._audit("refuse", route, action_id, record["requestId"], param_hash, "unavailable", 403)
            raise ActionError(403, "the action is no longer available")
        if entry.get("destructive") and not self.destructive_enabled:
            self._audit("refuse", route, action_id, record["requestId"], param_hash, "destructive_gate_off", 403)
            raise ActionError(403, "destructive actions are disabled")

        self._rate_limit("execute")
        self.preconditions(grinder, route, record["params"])

        record["state"] = "executing"
        record["startedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(self.clock())))
        record["startedAtEpoch"] = int(self.clock())
        self._audit("execute", route, action_id, record["requestId"], param_hash, "executing", 0)

        started = self.clock()
        try:
            result = self.execute_steps(grinder, route, record["params"])
            state = "completed"
            error_code = 0
            error = None
        except ActionError as exc:
            result = {}
            state = "failed"
            error_code = exc.code
            error = exc.message

        duration_ms = int((self.clock() - started) * 1000)
        record["state"] = state
        record["errorCode"] = error_code
        record["error"] = error
        record["result"] = result
        record["durationMs"] = duration_ms
        record["finishedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(self.clock())))
        record["finishedAtEpoch"] = int(self.clock())
        if record.get("cancelRequested") and state == "completed":
            record["state"] = "cancelled"
        self._audit("result", route, action_id, record["requestId"], param_hash, state, error_code, None, duration_ms)

        data = {
            "schema": "e64local-api-v1",
            "route": "action_execute",
            "actionId": action_id,
            "actionRoute": route,
            "state": record["state"],
            "auditId": record["auditId"],
            "result": result,
            "durationMs": duration_ms,
        }
        if error_code != 0:
            raise ActionError(error_code, error or "the action failed", data=data)
        return data

    def status(self, body: Mapping[str, Any]) -> dict[str, Any]:
        self.require_gate()
        action_id = body.get("actionId")
        if not isinstance(action_id, str) or not UUID_RE.match(action_id):
            raise ActionError(400, "actionId is required")
        record = self.records.get(action_id)
        if record is None:
            raise ActionError(404, "unknown actionId")
        return {
            "schema": "e64local-api-v1",
            "route": "action_status",
            "actionId": record["actionId"],
            "actionRoute": record["route"],
            "state": record["state"],
            "preparedAt": record.get("preparedAt"),
            "expiresAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(record["expires"]))),
            "startedAt": record.get("startedAt"),
            "finishedAt": record.get("finishedAt"),
            "durationMs": record.get("durationMs"),
            "errorCode": record.get("errorCode", 0),
            "error": record.get("error"),
            "result": record.get("result", {}),
            "cancelRequested": bool(record.get("cancelRequested")),
            "auditId": record.get("auditId"),
        }

    def cancel(self, grinder: Any, body: Mapping[str, Any]) -> dict[str, Any]:
        self.require_gate()
        action_id = body.get("actionId")
        if not isinstance(action_id, str) or not UUID_RE.match(action_id):
            raise ActionError(400, "actionId is required")
        record = self.records.get(action_id)
        if record is None:
            raise ActionError(404, "unknown actionId")

        state = record["state"]
        if state == "prepared":
            record["state"] = "cancelled"
            record["finishedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(self.clock())))
            self._audit("cancel", record["route"], action_id, record["requestId"], record["paramsHash"], "cancelled_before_execute", 0)
            return {
                "schema": "e64local-api-v1",
                "route": "action_cancel",
                "actionId": action_id,
                "actionRoute": record["route"],
                "state": "cancelled",
                "cancelled": True,
                "stopSent": False,
            }
        if state == "executing":
            stop_sent = False
            if record["route"] in (
                "action_grind_start_gbw", "action_grind_start_gbt",
                "action_grind_start_manual", "action_grind_purge",
            ):
                grinder.grind_state = "Idle"
                stop_sent = True
            elif record["route"] == "action_agsa_move":
                grinder.agsa_status = "Ready"
                stop_sent = True
            record["cancelRequested"] = True
            self._audit("cancel", record["route"], action_id, record["requestId"], record["paramsHash"], "cancel_requested", 0)
            return {
                "schema": "e64local-api-v1",
                "route": "action_cancel",
                "actionId": action_id,
                "actionRoute": record["route"],
                "state": "cancelling",
                "cancelled": False,
                "stopSent": stop_sent,
            }
        return {
            "schema": "e64local-api-v1",
            "route": "action_cancel",
            "actionId": action_id,
            "actionRoute": record["route"],
            "state": state,
            "cancelled": state == "cancelled",
            "stopSent": False,
            "note": "the action is already in a terminal state",
        }

    def audit_page(
        self,
        limit: int,
        offset: int,
        since_epoch: int | None = None,
        until_epoch: int | None = None,
    ) -> dict[str, Any]:
        self.require_gate()
        rows = [
            row for row in self.audit
            if (since_epoch is None or int(row["tsEpoch"]) >= since_epoch)
            and (until_epoch is None or int(row["tsEpoch"]) <= until_epoch)
        ]
        rows = list(reversed(rows))
        total = len(rows)
        page = rows[offset:offset + limit]
        return {
            "schema": "e64local-api-v1",
            "route": "action_audit",
            "rows": page,
            "count": len(page),
            "total": total,
            "limit": limit,
            "offset": offset,
            "hasMore": (offset + len(page)) < total,
        }
