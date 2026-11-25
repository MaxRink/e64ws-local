"""Sanitized live HSG profile observed on 2026-11-18.

The values are the vendor ``settings`` rows read from the downloaded
``HsgSqlite.db``, not the WSS/config-manager presentation.  Network
credentials, the serial number and the MAC address are intentionally not
retained.  Use this profile to exercise the simulator with a used-device
snapshot; the pristine/factory profile remains the default.

Evidence:
``docs/evidence/live-2026-11-18/database.json`` and
``docs/LIVE_VALIDATION_2026-11-18.md``.
"""
from __future__ import annotations

from typing import Any

from .assumptions import LIVE_LOAD_CELL
from .state import DeviceState

#: Exact key set and vendor-DB representation observed on the live unit.
#: ``Wifi.StaSsid`` and ``Wifi.StaPassword`` are redacted to empty strings.
LIVE_DB_SETTINGS: dict[str, str] = {
    "Agsa.AgsaUponRecipeChange": "true",
    "Agsa.ShowRecipeDdEnabled": "true",
    "Cloud.ConnectionEnabled": "true",
    "Cloud.State.LastSyncedGrindEvent": "47",
    "Cloud.State.LastSyncedServiceEvent": "6",
    "Cloud.State.NeedPortafilterPush": "false",
    "Cloud.State.NeedRecipePush": "false",
    "Cloud.TermsAcknowledged": "true",
    "GbS.State.PendingBrewInfo": "",
    "Gbs.State.EffectiveGrindSizePrediction":
        '{"grindSizeUm":86.27375105880708,"version":1}',
    "Gbw.Sensitivity": "Medium",
    "Grinding.OvershootWeight": "536960",       # micrograms (vendor DB units)
    "Grinding.Portafilter.DetectionEnabled": "true",
    "Grinding.SelectedRecipeIndex": "-1",
    "Role.Owner.LoginData": "",
    "Standby.ActivationTimeSec": "600",         # seconds (vendor DB units)
    "System.Language": "en_US",
    "System.PermanentLedLightingEnabled": "false",
    "System.SetupWizard.State": "Completed",
    "Version": "31",
    "Wifi.Enabled": "true",
    "Wifi.Mode": "2",                           # persisted APSTA mode id
    "Wifi.StaDhcp": "true",
    "Wifi.StaPassword": "",                     # redacted; value not retained
    "Wifi.StaSsid": "",                         # redacted; value not retained
    "timezoneId": "Europe/Berlin",
    "timezoneIdWasEntered": "true",
}

REDACTED_SETTING_KEYS: frozenset[str] = frozenset({
    "Wifi.StaSsid",
    "Wifi.StaPassword",
})

#: Derived values used by the simulator and tests.
LIVE_DERIVED: dict[str, Any] = {
    "overshootWeightGr": 536960 / 1_000_000,    # 0.53696 g
    "standbyActivationSec": 600,
    "activeRecipeIndex": 2,
    "grindLogRows": 8,
    "grindSuccessRows": 3,
    "serviceLogRows": 3,
    # Latest read.  The first session on 2026-11-18 saw 854, the later
    # session saw 817, and the 2026-11-19 grind capture saw 819.
    "ddValueDum": 819,
    "ntc1TempDegC": 34.3,
    "cpuTempDegC": -88.5,
    "fan1TachoRpm": 0,
    "idleWeightGr": -0.52,
    "gbwAdcToWeightC0": LIVE_LOAD_CELL["c0"],
    "gbwAdcToWeightC1": LIVE_LOAD_CELL["c1"],
}


def apply_live_hsg_profile(state: DeviceState) -> None:
    """Apply the non-network live settings to a simulator state.

    The live profile is a used device, not a factory baseline.  It sets the
    setup wizard to ``Completed`` and the observed overshoot/standby/cloud
    values.  WiFi credentials are not applied because they were redacted.
    """
    state.language = "en_US"
    state.setup_wizard_state = "Completed"
    state.machine.grinder_type = 5
    state.machine.production_date = "2026-06-23"
    state.config_id = 7
    state.grind.overshoot_weight_gr = LIVE_DERIVED["overshootWeightGr"]
    state.grind.current_weight_gr = LIVE_DERIVED["idleWeightGr"]
    # Live RequestDriverState: calibrated, NTC1 valid at 34.3 C despite
    # hasNtc1=false, NTC2 absent, both fan tachos zero, CPU temp about -88.5 C.
    state.agsa.dd_value = LIVE_DERIVED["ddValueDum"]
    state.agsa.status = "Normal"
    state.agsa.sensor_failed = False
    state.agsa.sensor_configured = True
    state.thermal.has_ntc1 = False
    state.thermal.ntc1_failed = False
    state.thermal.ntc1_temp_degc = LIVE_DERIVED["ntc1TempDegC"]
    state.thermal.ntc2_failed = True
    state.thermal.ntc2_temp_degc = -999
    state.thermal.cpu_temp_failed = False
    state.thermal.cpu_temp_degc = LIVE_DERIVED["cpuTempDegC"]
    for fan in state.fans:
        fan.duty = -1
        fan.tacho_rpm = 0
        fan.failed = False
    if state.fans:
        state.fans[0].tacho_rpm = LIVE_DERIVED["fan1TachoRpm"]
    # Live RequestDriverConfig: this unit's load-cell coefficients differ from
    # the documented fixture, so they are per-device calibration values.
    state.driver_config.update({
        "id": 7,
        "gbwAdcToWeightC0": LIVE_LOAD_CELL["c0"],
        "gbwAdcToWeightC1": LIVE_LOAD_CELL["c1"],
        "buttonAction": 2,
        "productionLineTestCompleted": True,
    })
    state.config_settings.update({
        "language": "en_US",
        "setupWizardState": "Completed",
        "timeZone": "Europe/Berlin",
        "cloudEnabled": True,
        "gbsEnabled": True,
        "Agsa.AgsaUponRecipeChange": True,
        "Agsa.ShowRecipeDdEnabled": True,
        "Cloud.ConnectionEnabled": True,
        "Cloud.TermsAcknowledged": True,
        "Gbw.Sensitivity": "Medium",
        "Standby.ActivationTimeSec": "600.0s",
        "timezoneId": "Europe/Berlin",
        "timezoneIdWasEntered": True,
    })


def seed_live_settings(persistence: Any) -> int:
    """Write the observed vendor settings rows into a simulator database.

    Redacted network values are written as empty strings so the key set stays
    faithful without retaining the live SSID or password.  Returns the number
    of rows written.
    """
    for key, value in LIVE_DB_SETTINGS.items():
        persistence.set_setting(key, value)
    return len(LIVE_DB_SETTINGS)


__all__ = [
    "LIVE_DB_SETTINGS",
    "LIVE_DERIVED",
    "REDACTED_SETTING_KEYS",
    "apply_live_hsg_profile",
    "seed_live_settings",
]
