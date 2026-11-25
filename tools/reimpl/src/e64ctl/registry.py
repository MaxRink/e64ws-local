"""The 52-record WSS command registry (vendor: JsonConnector ctor @ ELF 0x003fb298).

Every record is a 0x1c-byte ``CommandDef`` in the vendor image:

    +0x00  type        QString (data pointer in the dump)
    +0x04  actionType  QString (null for direct records)
    +0x08  log         bool
    +0x09  devOnly     bool
    +0x0a  tokenReq    bool
    +0x0c  callback    code pointer

The table below is transcribed from docs/API_REGISTRY.md, which was extracted
from the constructor.  Callback addresses are kept for traceability; the
Python handler name is what the dispatcher actually calls.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class CommandDef:
    type: str
    action: Optional[str]
    log: bool
    dev: bool
    token: bool
    callback: str
    elf: str
    handler: str

    @property
    def wire(self) -> str:
        return "GrinderAction" if self.action else self.type


# (type, action, log, dev, token, callback symbol suffix, ELF address, handler)
_RECORDS = [
    # --- 13 direct records -------------------------------------------------
    ("RequestDriverConfig", None, True, False, True,
     "cmdRequestDriverConfig", "0x003f12b8", "cmd_request_driver_config"),
    ("RequestDriverState", None, False, False, True,
     "cmdRequestDriverState", "0x003f1910", "cmd_request_driver_state"),
    ("RequestLogMessages", None, False, True, True,
     "cmdRequestLogMessages", "0x003f1f5c", "cmd_request_log_messages"),
    ("RequestAdcConfig", None, True, True, True,
     "cmdRequestAdcConfig", "0x003f25b8", "cmd_request_adc_config"),
    ("RequestConfigManagerSettings", None, False, True, True,
     "cmdRequestConfigManagerSettings", "0x003f4124",
     "cmd_request_config_manager_settings"),
    ("RequestNachineInfo", None, False, False, True,
     "cmdRequestMachineInfo", "0x003f4778", "cmd_request_nachine_info"),
    ("RequestOnboarding", None, True, False, False,
     "cmdRequestOnboarding", "0x003f2c08", "cmd_request_onboarding"),
    ("WifiStaConfig", None, True, False, True,
     "cmdWifiStaConfig", "0x003f31ec", "cmd_wifi_sta_config"),
    ("WifiConfigChanged", None, True, False, True,
     "cmdWifiConfigChanged", "0x003f37d0", "cmd_wifi_config_changed"),
    ("UpdateDriverConfig", None, True, True, True,
     "UpdateDriverConfig", "0x003f988c", "cmd_update_driver_config"),
    ("UpdateCpuConfig", None, True, True, True,
     "cmdUpdateCpuConfig", "0x003f7c20", "cmd_update_cpu_config"),
    ("CustomSignal1", None, True, True, True,
     "cmdCustomSignal1", "0x003f4dd0", "cmd_custom_signal_1"),
    ("CustomSignal2", None, True, True, True,
     "cmdCustomSignal2", "0x003f5440", "cmd_custom_signal_2"),

    # --- 39 GrinderAction variants ----------------------------------------
    ("GrinderAction", "Stop", True, True, True,
     "cmdGrinderActionStop", "0x003f6098", "act_stop"),
    ("GrinderAction", "StartGrindManual", True, True, True,
     "StartGrindManual", "0x003f6190", "act_start_grind_manual"),
    ("GrinderAction", "StartGrindGbw", True, True, True,
     "StartGrindGbw", "0x003f7d00", "act_start_grind_gbw"),
    ("GrinderAction", "StartGrindGbt", True, True, True,
     "StartGrindGbt", "0x003f7f4c", "act_start_grind_gbt"),
    ("GrinderAction", "StartCalibration", True, True, True,
     "StartCalibration", "0x003f6288", "act_start_calibration"),
    ("GrinderAction", "StartTara", True, True, True,
     "StartTara", "0x003f6380", "act_start_tara"),
    ("GrinderAction", "SaveLog", True, True, True,
     "cmdGrinderActionSaveLog", "0x003f6478", "act_save_log"),
    ("GrinderAction", "ResetLog", True, True, True,
     "ResetLog", "0x003f6570", "act_reset_log"),
    ("GrinderAction", "SetFanTemperatureCtrlEnabled", True, True, True,
     "SetFanTemperatureCtrlEnabled", "0x003f819c",
     "act_set_fan_temperature_ctrl_enabled"),
    ("GrinderAction", "SetFan1Duty", True, True, True,
     "SetFan1Duty", "0x003f8538", "act_set_fan1_duty"),
    ("GrinderAction", "SetFan2Duty", True, True, True,
     "SetFan2Duty", "0x003f8798", "act_set_fan2_duty"),
    ("GrinderAction", "CalibrateFan1", True, True, True,
     "CalibrateFan1", "0x003f6668", "act_calibrate_fan1"),
    ("GrinderAction", "CalibrateFan2", True, True, True,
     "CalibrateFan2", "0x003f6760", "act_calibrate_fan2"),
    ("GrinderAction", "ToggleBacklightPower", True, True, True,
     "ToggleBacklightPower", "0x003f6858", "act_toggle_backlight_power"),
    ("GrinderAction", "SetBacklightBrightness", True, True, True,
     "SetBacklightBrightness", "0x003f89f8", "act_set_backlight_brightness"),
    ("GrinderAction", "EspFlashApp", True, True, True,
     "EspFlashApp", "0x003f6988", "act_esp_flash_app"),
    ("GrinderAction", "EspEraseFlash", True, True, True,
     "EspEraseFlash", "0x003f6a94", "act_esp_erase_flash"),
    ("GrinderAction", "EspReset", False, False, True,
     "EspReset", "0x003f6c10", "act_esp_reset"),
    ("GrinderAction", "NozzleLightRunStandby", True, True, True,
     "NozzleLightRunStandby", "0x003f6d18", "act_nozzle_light_run_standby"),
    ("GrinderAction", "NozzleLightStop", True, True, True,
     "NozzleLightStop", "0x003f6e20", "act_nozzle_light_stop"),
    ("GrinderAction", "ResetDriverConfig", False, False, True,
     "ResetDriverConfig", "0x003f6f28", "act_reset_driver_config"),
    ("GrinderAction", "SetAgsaTargetDdValue", True, True, True,
     "SetAgsaTargetDdValue", "0x003f8c58", "act_set_agsa_target_dd_value"),
    ("GrinderAction", "StopAgsa", True, True, True,
     "StopAgsa", "0x003f7020", "act_stop_agsa"),
    ("GrinderAction", "CalibrateDdSensor", True, True, True,
     "CalibrateDdSensor", "0x003f7130", "act_calibrate_dd_sensor"),
    ("GrinderAction", "AddBrewEvent", True, True, True,
     "AddBrewEvent", "0x003f9cac", "act_add_brew_event"),
    ("GrinderAction", "GbsCreateReport", True, True, True,
     "cmdGrinderActionGbsCreateReport", "0x003f3d30",
     "act_gbs_create_report"),
    ("GrinderAction", "SetLanguage", True, True, True,
     "SetLanguage", "0x003f8eb0", "act_set_language"),
    ("GrinderAction", "RcTopLeftClick", True, True, True,
     "RcTopLeftClick", "0x003f7270", "act_rc_top_left_click"),
    ("GrinderAction", "RcTopLeftLong", True, True, True,
     "RcTopLeftLong", "0x003f7384", "act_rc_top_left_long"),
    ("GrinderAction", "RcTopLeftPress", True, True, True,
     "RcTopLeftPress", "0x003f7498", "act_rc_top_left_press"),
    ("GrinderAction", "RcTopLeftRelease", True, True, True,
     "RcTopLeftRelease", "0x003f75ac", "act_rc_top_left_release"),
    ("GrinderAction", "RcBottomLeftClick", True, True, True,
     "RcBottomLeftClick", "0x003f76c0", "act_rc_bottom_left_click"),
    ("GrinderAction", "RcRotaryClick", True, True, True,
     "RcRotaryClick", "0x003f77d4", "act_rc_rotary_click"),
    ("GrinderAction", "RcRotaryLong", True, True, True,
     "RcRotaryLong", "0x003f78e8", "act_rc_rotary_long"),
    ("GrinderAction", "RcRotaryDouble", True, True, True,
     "RcRotaryDouble", "0x003f79fc", "act_rc_rotary_double"),
    ("GrinderAction", "RcRotary", True, True, True,
     "RcRotary", "0x003f9198", "act_rc_rotary"),
    ("GrinderAction", "StartEnduranceTest", True, True, True,
     "StartEnduranceTest", "0x003f94ec", "act_start_endurance_test"),
    ("GrinderAction", "StopEnduranceTest", True, True, True,
     "StopEnduranceTest", "0x003f7b10", "act_stop_endurance_test"),
    ("GrinderAction", "SetSetupWizardState", True, True, True,
     "SetSetupWizardState", "0x003faba0", "act_set_setup_wizard_state"),
]

COMMANDS: list[CommandDef] = [CommandDef(*r) for r in _RECORDS]

#: Direct wire types (13).
DIRECT = [c for c in COMMANDS if c.action is None]
#: Action suffixes (39).
ACTIONS = [c for c in COMMANDS if c.action is not None]

_BY_TYPE: dict[str, list[CommandDef]] = {}
for _c in COMMANDS:
    _BY_TYPE.setdefault(_c.type, []).append(_c)

_BY_ACTION = {c.action: c for c in ACTIONS}


def ensure_complete() -> None:
    assert len(COMMANDS) == 52, len(COMMANDS)
    assert len(DIRECT) == 13, len(DIRECT)
    assert len(ACTIONS) == 39, len(ACTIONS)
    assert sum(1 for c in COMMANDS if c.token) == 51
    assert sum(1 for c in COMMANDS if c.dev) == 44
    # 44 dev records total: 37 action records (all but ResetDriverConfig and
    # EspReset) plus 7 direct records.
    assert sum(1 for c in COMMANDS if c.dev and not c.action) == 7
    assert sum(1 for c in COMMANDS if c.dev and c.action) == 37


def records_for_type(wire_type: str) -> list[CommandDef]:
    """Records whose top-level ``type`` matches (registry order preserved)."""
    return _BY_TYPE.get(wire_type, [])


def action_record(suffix: str) -> Optional[CommandDef]:
    return _BY_ACTION.get(suffix)


def lookup(wire_type: str, action: object) -> Optional[CommandDef]:
    """Resolve exactly like ``handleMessage``: first type match wins.

    Direct records are selected when the record has no action type; action
    records require ``data.actionType`` to compare equal.
    """
    for rec in _BY_TYPE.get(wire_type, []):
        if rec.action is None:
            return rec
        if isinstance(action, str) and rec.action == action:
            return rec
    return None


def live_commands(dev_mode: bool) -> list[CommandDef]:
    """The dispatchable subset for a given ``/etc/issue`` dev state."""
    return [c for c in COMMANDS if dev_mode or not c.dev]


ensure_complete()
