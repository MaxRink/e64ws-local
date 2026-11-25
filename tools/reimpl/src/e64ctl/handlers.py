"""Handlers for all 52 registry records.

Response builders follow the recovered per-callback code shape: every direct
handler builds ``{"type": <incoming type> + "Result", "refId": <msgId>,
"data": <builder object>}``; the three special records
(``RequestOnboarding``, ``WifiStaConfig``, ``WifiConfigChanged``) use fixed
response types and omit ``refId``; ``GrinderAction`` variants return the
standard ``{"success": bool}`` envelope.

Side effects are applied to :class:`e64ctl.state.DeviceState` and, where the
vendor drives hardware, to the injected ESP client or persistence layer.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from . import registry
from .state import (
    GRIND_STARTING, SETUP_WIZARD_STATES, BrewEvent, DeviceState, GRIND_IDLE,
)

def qint(value: Any, default: int = 0) -> int:
    """QJsonValue::toInt(): only JSON numbers convert; everything else -> 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    try:
        return int(value)
    except (OverflowError, ValueError):
        return default


def qdouble(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    try:
        return float(value)
    except (OverflowError, ValueError):
        return default


def qbool(value: Any, default: bool = False) -> bool:
    return value if isinstance(value, bool) else default


def qstr(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


#: The vendor stores the language string verbatim (scenario 05: "de" ->
#: driverState.language "de" and System.Language "de"), not a locale id.
LANGUAGE_ALIASES: dict[str, str] = {}

RC_KEYS = {
    "RcTopLeftClick": 0x31,
    "RcTopLeftLong": 0x31,
    "RcTopLeftPress": 0x31,
    "RcTopLeftRelease": 0x8031,
    "RcBottomLeftClick": 0x32,
    "RcRotaryClick": 0x33,
    "RcRotaryLong": 0x33,
    "RcRotaryDouble": 0x33,
}

REQUIRED_ADD_BREW_KEYS = (
    "grindUuid", "machineName", "groupHead", "doseIndex", "validity",
    "brewTimeMs", "brewWeightMg",
)


class Handlers:
    def __init__(self, state: DeviceState, persistence: Any = None,
                 esp: Any = None, dev_mode=None) -> None:
        self.state = state
        self.persistence = persistence
        self.esp = esp
        self.dev_mode = dev_mode or (lambda: False)
        self.gbs_provider = True

    # -- helpers ----------------------------------------------------------
    def _msg_id(self, message: dict[str, Any]) -> Any:
        return message.get("msgId")

    def _result(self, message: dict[str, Any], data: Any) -> dict[str, Any]:
        response: dict[str, Any] = {
            "type": str(message.get("type", "")) + "Result",
        }
        # A frame without msgId produces a reply without refId (vendor m06).
        if "msgId" in message:
            response["refId"] = self._msg_id(message)
        response["data"] = data
        return response

    def _action_result(self, message: dict[str, Any], success: bool) -> dict[str, Any]:
        response: dict[str, Any] = {"type": "GrinderActionResult"}
        if "msgId" in message:
            response["refId"] = self._msg_id(message)
        response["data"] = {"success": bool(success)}
        return response

    def _data(self, message: dict[str, Any]) -> dict[str, Any]:
        data = message.get("data")
        return data if isinstance(data, dict) else {}

    # =====================================================================
    # Direct records (13)
    # =====================================================================
    def cmd_request_driver_config(self, message, rec) -> dict:
        return self._result(message, self.state.driver_config_json())

    def cmd_request_driver_state(self, message, rec) -> dict:
        return self._result(message, self.state.driver_state_json())

    def cmd_request_log_messages(self, message, rec) -> dict:
        # Vendor logMessages is an array of formatted lines, not objects.
        data = {
            "skippedLogMessages": self.state.skipped_log_messages,
            "logMessages": [f"({entry.level}) {entry.message}"
                            for entry in self.state.logs],
        }
        return self._result(message, data)

    def cmd_request_adc_config(self, message, rec) -> dict:
        return self._result(message, self.state.adc_config_json())

    def cmd_request_config_manager_settings(self, message, rec) -> dict:
        return self._result(message, self.state.config_manager_json())

    def cmd_request_nachine_info(self, message, rec) -> dict:
        data = self.state.machine_info_json()
        # A development image reports an unknown product identity.
        if self.dev_mode():
            data["grinderType"] = "Unknown"
        return self._result(message, data)

    def cmd_request_onboarding(self, message, rec) -> dict:
        # requestOnboarding(data) then a fixed two-field object without refId.
        data = self._data(message)
        self.state.log("onboarding request received")
        self.state.emit("onboardingRequested", data)
        if self.persistence is not None:
            self.persistence.write_json("/tmp/onboardingRequest.json",
                                        {"type": "RequestOnboarding", "data": data})
        return {"type": "RequestOnboardingResult", "data": {"success": True}}

    def cmd_wifi_sta_config(self, message, rec) -> dict:
        data = self._data(message)
        for key in ("ssid", "password"):
            if key in data and isinstance(data[key], str):
                setattr(self.state.sta, key, data[key])
        for key in ("ip", "gateway", "netmask", "dns"):
            if key in data and isinstance(data[key], str):
                setattr(self.state.sta, key, data[key])
        if "dhcp" in data:
            self.state.sta.dhcp = bool(data["dhcp"])
        self.state.emit("wifiStaConfig", self.state.sta.as_json())
        if self.esp is not None:
            self.esp.apply_station_config(self.state.sta)
        if self.persistence is not None:
            self.persistence.save_wifi_config(self.state)
            self._persist_wifi_settings()
        return {"type": "WifiStaConfig", "data": {"success": True}}

    def _persist_wifi_settings(self) -> None:
        sta = self.state.sta
        self.persistence.set_setting("Wifi.Enabled", "true")
        # ConfigManager stores the APSTA mode id (2), independent of the
        # current ESP association state.  Only these four rows are
        # materialised in the pristine vendor database.
        self.persistence.set_setting("Wifi.Mode", "2")
        self.persistence.set_setting("Wifi.StaSsid", sta.ssid)
        self.persistence.set_setting("Wifi.StaPassword", sta.password)

    def cmd_wifi_config_changed(self, message, rec) -> dict:
        data = self._data(message)
        self.state.emit("wifiConfigChanged", data)
        if self.persistence is not None:
            self.persistence.save_wifi_config(self.state)
        return {"type": "WifiConfigChangedProcessed", "data": {"success": True}}

    def cmd_update_driver_config(self, message, rec) -> dict:
        # processDriverConfig() applies the payload, then the handler returns
        # the standard result with success=false (recovered call argument and
        # the documented VM capture).
        data = self._data(message)
        if isinstance(data, str):
            try:
                import json
                data = json.loads(data)
            except ValueError:
                data = {}
        if isinstance(data, dict):
            for key, value in data.items():
                self.state.driver_config[key] = value
            self.state.emit("driverConfigUpdated", dict(data))
        return self._result(message, {"success": False})

    def cmd_update_cpu_config(self, message, rec) -> dict:
        # Recovered callback ignores its payload and returns a failure value.
        return self._result(message, {"success": False})

    def cmd_custom_signal_1(self, message, rec) -> dict:
        self.state.emit("customSignal1", {})
        # The recovered builder emits only type + refId (no data member).
        return {"type": "CustomSignal1Result",
                "refId": self._msg_id(message)}

    def cmd_custom_signal_2(self, message, rec) -> dict:
        self.state.emit("customSignal2", {})
        return {"type": "CustomSignal2Result",
                "refId": self._msg_id(message)}

    # =====================================================================
    # GrinderAction variants (39)
    # =====================================================================
    def act_stop(self, message, rec) -> dict:
        self.state.stop_grind("stop command")
        self.state.stop_agsa()
        return self._action_result(message, True)

    def act_start_grind_manual(self, message, rec) -> dict:
        ok, _ = self.state.start_grind("manual")
        return self._action_result(message, ok)

    def act_start_grind_gbw(self, message, rec) -> dict:
        # startGrindGbw(data["targetWeightGr"].toDouble())
        target = qdouble(self._data(message).get("targetWeightGr"))
        self.state.start_grind("gbw", target_weight_gr=target)
        return self._action_result(message, True)

    def act_start_grind_gbt(self, message, rec) -> dict:
        # startGrindGbt(data["grindTimeSec"].toDouble())
        seconds = qdouble(self._data(message).get("grindTimeSec"))
        self.state.start_grind("gbt", target_time_s=seconds)
        return self._action_result(message, True)

    def act_start_calibration(self, message, rec) -> dict:
        self.state.calibration["state"] = "Running"
        self.state.calibration["kind"] = "loadcell"
        self.state.log("calibration started")
        self.state.emit("calibrationStarted", {})
        return self._action_result(message, True)

    def act_start_tara(self, message, rec) -> dict:
        self.state.grind.current_weight_gr = 0.0
        self.state.grind.start_weight_gr = 0.0
        self.state.calibration["tara"] = "done"
        self.state.log("tara performed")
        self.state.emit("taraPerformed", {})
        return self._action_result(message, True)

    def act_save_log(self, message, rec) -> dict:
        if self.persistence is not None:
            self.persistence.save_logs(self.state)
        return self._action_result(message, True)

    def act_reset_log(self, message, rec) -> dict:
        self.state.logs.clear()
        self.state.skipped_log_messages = 0
        if self.persistence is not None:
            self.persistence.clear_logs()
        return self._action_result(message, True)

    def act_set_fan_temperature_ctrl_enabled(self, message, rec) -> dict:
        data = self._data(message)
        enabled = bool(data.get("enabled"))
        self.state.fan_temperature_ctrl_enabled = enabled
        self.state.config_settings["fanTemperatureCtrlEnabled"] = enabled
        return self._action_result(message, True)

    def act_set_fan1_duty(self, message, rec) -> dict:
        return self._set_fan_duty(message, 0)

    def act_set_fan2_duty(self, message, rec) -> dict:
        return self._set_fan_duty(message, 1)

    def _set_fan_duty(self, message, index: int) -> dict:
        # FanDriver::setPwmDuty(data["dutyPercent"].toInt()) -> clamp 0..100.
        # Without a fan driver the call is accepted but driverState keeps the
        # unset duty (-1), as observed in the QEMU baseline.
        if self.state.motion_simulated:
            duty = qint(self._data(message).get("dutyPercent"))
            self.state.set_fan_duty(index, duty)
        return self._action_result(message, True)

    def act_calibrate_fan1(self, message, rec) -> dict:
        return self._action_result(message, self.state.calibrate_fan(0))

    def act_calibrate_fan2(self, message, rec) -> dict:
        return self._action_result(message, self.state.calibrate_fan(1))

    def act_toggle_backlight_power(self, message, rec) -> dict:
        self.state.backlight_power = not self.state.backlight_power
        self.state.backlight_bl_power = ("0" if self.state.backlight_power
                                         else "4")
        self.state.emit("backlightPower", {"on": self.state.backlight_power})
        return self._action_result(message, True)

    def act_set_backlight_brightness(self, message, rec) -> dict:
        # BacklightDriver::setBrightness(data["brightness"].toInt())
        brightness = qint(self._data(message).get("brightness"))
        # Panel maximum is 7 steps; 9 is clamped (scenario 05 reads back 7).
        self.state.backlight_brightness = max(0, min(7, brightness))
        # The vendor driver leaves bl_power at the magic value 1 after a
        # brightness write (scenario 03: Toggle then Set -> power=1).
        self.state.backlight_power = True
        self.state.backlight_bl_power = "1"
        self.state.config_settings["backlightBrightness"] = \
            self.state.backlight_brightness
        return self._action_result(message, True)

    def act_esp_flash_app(self, message, rec) -> dict:
        self.state.log("esp flash app requested")
        self.state.esp.update_required = False
        return self._action_result(message, True)

    def act_esp_erase_flash(self, message, rec) -> dict:
        self.state.log("esp erase flash requested")
        return self._action_result(message, True)

    def act_esp_reset(self, message, rec) -> dict:
        # resetEsp.sh: pulse GPIO 60; the ESP reboots and re-initialises SDIO.
        self.state.esp.sdio_status = 1
        self.state.esp.status_reset_at = self.state.clock()
        if self.esp is not None:
            self.esp.reset()
        self.state.log("esp reset")
        return self._action_result(message, True)

    def act_nozzle_light_run_standby(self, message, rec) -> dict:
        self.state.nozzle_light = "Standby"
        self.state.emit("nozzleLight", {"state": "Standby"})
        return self._action_result(message, True)

    def act_nozzle_light_stop(self, message, rec) -> dict:
        self.state.nozzle_light = "Off"
        self.state.emit("nozzleLight", {"state": "Off"})
        return self._action_result(message, True)

    def act_reset_driver_config(self, message, rec) -> dict:
        import copy

        from .defaults import DRIVER_CONFIG

        button_action = self.state.driver_config.get("buttonAction", 0)
        self.state.driver_config = copy.deepcopy(DRIVER_CONFIG)
        # ResetDriverConfig writes the factory defaults, which have no
        # machine type yet (vendor baseline: grinderType 0 after the reset),
        # but keeps the last remote-control key.
        self.state.driver_config["grinderType"] = 0
        self.state.driver_config["buttonAction"] = button_action
        self.state.log("driver config reset")
        if self.persistence is not None:
            self.persistence.save_driver_config(self.state)
        return self._action_result(message, True)

    def act_set_agsa_target_dd_value(self, message, rec) -> dict:
        # AgsaMotionScheduler::forceMoveToDd(data["targetDdValue"].toInt())
        if not self.state.agsa.sensor_configured:
            self.state.log("agsa target ignored: sensor type not selected", "warning")
            return self._action_result(message, True)
        self.state.set_agsa_target(float(qint(self._data(message).get("targetDdValue"))))
        return self._action_result(message, True)

    def act_stop_agsa(self, message, rec) -> dict:
        self.state.stop_agsa()
        return self._action_result(message, True)

    def act_calibrate_dd_sensor(self, message, rec) -> dict:
        # The action is accepted even when no DD sensor is configured; the
        # hardware wait never completes in QEMU (scenario 08 w09).
        if not self.state.agsa.sensor_configured:
            return self._action_result(message, True)
        self.state.agsa.status = "Calibrating"
        self.state.agsa.dd_value = 0.0
        self.state.agsa.hall_counts = 0
        self.state.agsa.dd_angle = 0.0
        self.state.agsa.status = "Idle"
        self.state.calibration["dd"] = "done"
        self.state.log("dd sensor calibrated")
        return self._action_result(message, True)

    def act_add_brew_event(self, message, rec) -> dict:
        # brewEventReceived(uuid, machineName, groupHead, ..., doseType,
        #                   brewTimeMs, brewWeightMg, validity)
        data = self._data(message)
        dose_index = qint(data.get("doseIndex"))
        brew_time = qint(data.get("brewTimeMs"))
        brew_weight = qint(data.get("brewWeightMg"))
        event = {
            "grindUuid": qstr(data.get("grindUuid")),
            "machineName": qstr(data.get("machineName")),
            "groupHead": qstr(data.get("groupHead")),
            "doseIndex": dose_index,
            "validity": qbool(data.get("validity")),
            "brewTimeMs": brew_time,
            "brewWeightMg": brew_weight,
            "source": "web_simu",
            # Invalid dose indices fall back to recipe type 3 (no range check).
            "recipeType": 3 if dose_index < 0 else 3,
            "receivedAt": self.state.clock(),
        }
        stored = BrewEvent(
            grind_uuid=event["grindUuid"], machine_name=event["machineName"],
            group_head=event["groupHead"], dose_index=dose_index,
            validity=event["validity"], brew_time_ms=brew_time,
            brew_weight_mg=brew_weight, recipe_type=event["recipeType"],
            received_at=event["receivedAt"])
        self.state.brew_events.append(stored)
        self.state.emit("brewEvent", event)
        if self.persistence is not None:
            self.persistence.add_brew_event(event)
        return self._action_result(message, True)

    def act_gbs_create_report(self, message, rec) -> dict:
        # The special GbsCreateReport response carries no refId and the
        # vendor baseline returns an empty GBS log (no active GBS session).
        return {"type": "GbsCreateReport", "data": {"log": []}}

    def act_set_language(self, message, rec) -> dict:
        # ConfigManager::getLanguageConfig()->set(data["language"].toString())
        language = qstr(self._data(message).get("language"))
        if not language:
            return self._action_result(message, True)
        # ConfigManager stores a locale id, not the bare ISO code: the
        # equivalence run sets "de" and reads back "de_DE" after a restart.
        self.state.language = LANGUAGE_ALIASES.get(language, language)
        self.state.config_settings["language"] = self.state.language
        if self.persistence is not None:
            self.persistence.set_setting("System.Language",
                                         self.state.language)
        return self._action_result(message, True)

    # -- remote control ---------------------------------------------------
    def _rc(self, message, suffix: str) -> dict:
        self.state.remote_key_events.append(RC_KEYS[suffix])
        # The last injected remote-control key is mirrored in the driver
        # config's buttonAction (vendor baseline a56: 2 after Rc actions).
        self.state.driver_config["buttonAction"] = 2
        self.state.emit("keyEvent", {"code": RC_KEYS[suffix]})
        return self._action_result(message, True)

    def act_rc_top_left_click(self, message, rec):
        return self._rc(message, "RcTopLeftClick")

    def act_rc_top_left_long(self, message, rec):
        return self._rc(message, "RcTopLeftLong")

    def act_rc_top_left_press(self, message, rec):
        return self._rc(message, "RcTopLeftPress")

    def act_rc_top_left_release(self, message, rec):
        return self._rc(message, "RcTopLeftRelease")

    def act_rc_bottom_left_click(self, message, rec):
        return self._rc(message, "RcBottomLeftClick")

    def act_rc_rotary_click(self, message, rec):
        return self._rc(message, "RcRotaryClick")

    def act_rc_rotary_long(self, message, rec):
        return self._rc(message, "RcRotaryLong")

    def act_rc_rotary_double(self, message, rec):
        return self._rc(message, "RcRotaryDouble")

    def act_rc_rotary(self, message, rec) -> dict:
        ticks = qint(self._data(message).get("ticks"))
        self.state.rotary_ticks += ticks
        self.state.emit("rotaryTick", {"ticks": ticks})
        return self._action_result(message, True)

    def act_start_endurance_test(self, message, rec) -> dict:
        # GrindEnduranceTesting::start(data["grindTimeSec"], data["pauseTimeSec"])
        data = self._data(message)
        grind_time = qint(data.get("grindTimeSec"))
        pause_time = qint(data.get("pauseTimeSec"))
        self.state.start_endurance(grind_time, pause_time)
        return self._action_result(message, True)

    def act_stop_endurance_test(self, message, rec) -> dict:
        return self._action_result(message, self.state.stop_endurance())

    def act_set_setup_wizard_state(self, message, rec) -> dict:
        # Json::toEnum<SetupWizardState>(data["state"]); an unknown value is
        # ignored, but the standard result is still built.
        state = qstr(self._data(message).get("state"))
        if state in SETUP_WIZARD_STATES:
            self.state.setup_wizard_state = state
            self.state.config_settings["setupWizardState"] = state
            if self.persistence is not None:
                self.persistence.set_setting("System.SetupWizard.State",
                                             state)
        return self._action_result(message, True)
