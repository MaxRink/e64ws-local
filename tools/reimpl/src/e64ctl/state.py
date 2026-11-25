"""Device state model: driver, grind FSM, AGSA/DD, fans, ESP, WiFi, config.

Field names and types follow the recovered ``createDataDriverState`` field list
(docs/WEBSOCKET_API.md and docs/bible/protocols.md).  Values that the vendor
only exposes through opaque C++ objects (driver config, ADC config) are modelled
as JSON objects whose contents are documented as approximations.

Everything time-driven (grind progress, AGSA travel, heartbeats, endurance) is
advanced by :meth:`DeviceState.tick`, which takes an explicit timestamp, so
scenarios are deterministic.
"""
from __future__ import annotations

import copy
import itertools
import math
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .defaults import ADC_CONFIG, CONFIG_MANAGER, DRIVER_CONFIG

# ---------------------------------------------------------------------------
# Enumerations recovered from the image (or documented as approximated)
# ---------------------------------------------------------------------------

#: ``DriverTypes::SdioState`` enum order (libNgxUi.so 0x45ea88).
SDIO_STATE = {0: "Uninitialized", 1: "Init", 2: "Running", 3: "Failed", 4: "Restart"}

#: ``Ctrl_Status`` values used by the ESP protobuf responses.
CTRL_STATUS = {
    0: "Connected",
    1: "Not_Connected",
    2: "No_AP_Found",
    3: "Connection_Fail",
    4: "Invalid_Argument",
    5: "Out_Of_Range",
}

#: Grind states.  Only ``Idle`` was observed on a live image (DECLOUD.md); the
#: remaining labels follow the semantic state machine in
#: INTERNAL_STATE_MACHINES.md section 2 and are marked approximated.
GRIND_IDLE = "Idle"
GRIND_STARTING = "Starting"
GRIND_RUNNING = "Grinding"
GRIND_STOPPING = "Stopping"
GRIND_DONE = "Done"
GRIND_FAILURE = "Failure"

#: ``SetSetupWizardState`` accepts exactly these three strings.
SETUP_WIZARD_STATES = ("NotRun", "Disabled", "Completed")

#: Backlight brightness is a raw integer; the driver exposes 0..100 %.
MAX_DUTY = 100


def now_default() -> float:
    return time.time()


def _trace_weight(trace: list[tuple[float, float]], elapsed: float) -> float:
    """Interpolate a captured weight trace at elapsed seconds."""
    if elapsed <= trace[0][0]:
        return trace[0][1]
    for (t0, w0), (t1, w1) in zip(trace, trace[1:]):
        if elapsed <= t1:
            if t1 <= t0:
                return w1
            return w0 + (w1 - w0) * ((elapsed - t0) / (t1 - t0))
    return trace[-1][1]


@dataclass
class MachineInfo:
    grinder_type: int = 0
    grinder_type_name: str = "E64 WS"
    serial_number: str = "000000"
    article_number: str = "HEM-HSG-HMI-S01"
    production_date: str = "2026-07-01"
    firmware_version: str = "01.16-24"
    hardware_version: str = "01.00"
    hostname: str = "HEM-HSG-000000"

    def as_json(self) -> dict[str, Any]:
        return {
            "grinderType": self.grinder_type,
            "grinderTypeName": self.grinder_type_name,
            "serialNumber": self.serial_number,
            "articleNumber": self.article_number,
            "productionDate": self.production_date,
            "firmwareVersion": self.firmware_version,
            "hardwareVersion": self.hardware_version,
        }


@dataclass
class GrindRuntime:
    state: str = GRIND_IDLE
    failure: bool = False
    failure_reason: str = "None"
    mode: str = ""                 # manual | gbw | gbt
    session_id: int = 0
    current_weight_gr: float = 0.0
    result_weight_gr: float = 0.0
    start_weight_gr: float = 0.0
    final_weight_gr: float = 0.0
    target_weight_gr: float = 0.0
    target_time_s: float = 0.0
    motor_run_time_ms: float = 0.0
    overshoot_weight_gr: float = 0.6   # vendor config default (capture)
    started_at: Optional[float] = None
    stopped_at: Optional[float] = None
    # simulation rates (vendor: load-cell + motor drive, not a protocol field)
    weight_rate_gr_s: float = 2.6
    start_delay_s: float = 0.15
    #: Optional captured (elapsed_s, grams) trace.  When non-empty it replaces
    #: the linear rate in _advance_grind, so a real grind can be replayed.
    weight_trace: list[tuple[float, float]] = field(default_factory=list)


@dataclass
class AgsaState:
    status: str = "Disc calibration missing"
    dd_value: float = 0.0          # ddValueDum
    target_dd: float = 0.0
    hall_counts: int = 0
    dd_angle: float = 0.0
    sensor_failed: bool = True
    sensor_configured: bool = False
    shift_compensation_failed: bool = False
    direction_inverted: bool = False
    lower_limit: float = 0.0
    upper_limit: float = 15.0
    speed_dd_per_s: float = 2.0   # controller field 0xe8 analogue
    moving_since: Optional[float] = None
    timeout_ms: float = 0.0
    overcurrent: bool = False
    blockage_counter: int = 0
    max_blockage_counter: int = 5


@dataclass
class FanState:
    temperature_ctrl_enabled: bool = True
    duty: int = -1          # -1 = never set (vendor capture)
    tacho_rpm: int = 0
    failed: bool = False
    calibrating: bool = False
    power_enabled: bool = False


@dataclass
class ThermalState:
    # Sentinels from the vendor capture: -999 with the failed flag set when the
    # board has no sensor populated (VM/fixture state).
    cpu_temp_failed: bool = True
    cpu_temp_degc: float = -999
    has_ntc1: bool = False
    ntc1_failed: bool = True
    ntc1_temp_degc: float = -999
    ntc2_failed: bool = True
    ntc2_temp_degc: float = -999
    overheat_ntc1: bool = False
    overheat_ntc2: bool = False


@dataclass
class EspState:
    sdio_status: int = 2          # Running
    sdio_error: int = 0
    fuse_failed: bool = False
    alive: bool = True
    uart_failed: bool = False
    version_no: str = "01.11"
    version_date: str = "16.12.2025"
    update_required: bool = False
    last_heartbeat: float = 0.0
    missed_heartbeats: int = 0
    wifi_rssi: int = -45
    ap_connected: bool = False
    mode: int = 0                 # Ctrl_WifiMode: 0 NONE, 1 STA, 2 AP, 3 APSTA


@dataclass
class WifiStaConfig:
    ssid: str = ""
    password: str = ""
    dhcp: bool = True
    ip: str = ""
    gateway: str = ""
    netmask: str = ""
    dns: str = ""

    def as_json(self) -> dict[str, Any]:
        return {
            "ssid": self.ssid,
            "password": self.password,
            "dhcp": self.dhcp,
            "ip": self.ip,
            "gateway": self.gateway,
            "netmask": self.netmask,
            "dns": self.dns,
        }


@dataclass
class SoftApConfig:
    ssid: str = "E64WS-000000"
    password: str = ""
    channel: int = 6
    security: int = 0
    max_conn: int = 4
    ssid_hidden: bool = False
    bandwidth: int = 1


@dataclass
class EnduranceTest:
    running: bool = False
    cycle: int = 0
    state: str = "Idle"
    start_time: str = ""
    duration: int = 0
    grind_time_s: int = 0
    pause_time_s: int = 0
    started_at: Optional[float] = None

    def duration_string(self) -> str:
        seconds = max(0, int(self.duration))
        return f"{seconds // 3600:02d}h:{(seconds % 3600) // 60:02d}m:{seconds % 60:02d}s"


@dataclass
class LogEntry:
    time: str
    level: str
    message: str

    def as_json(self) -> dict[str, Any]:
        return {"time": self.time, "level": self.level, "message": self.message}


@dataclass
class BrewEvent:
    grind_uuid: str
    machine_name: str
    group_head: str
    dose_index: int
    validity: bool
    brew_time_ms: int
    brew_weight_mg: int
    source: str = "web_simu"
    recipe_type: int = 3
    received_at: float = 0.0

    def as_json(self) -> dict[str, Any]:
        return {
            "grindUuid": self.grind_uuid,
            "machineName": self.machine_name,
            "groupHead": self.group_head,
            "doseIndex": self.dose_index,
            "validity": self.validity,
            "brewTimeMs": self.brew_time_ms,
            "brewWeightMg": self.brew_weight_mg,
            "source": self.source,
            "recipeType": self.recipe_type,
        }


@dataclass
class DeviceState:
    """Complete mutable device state, independent of transport."""

    clock: Callable[[], float] = now_default
    machine: MachineInfo = field(default_factory=MachineInfo)
    grind: GrindRuntime = field(default_factory=GrindRuntime)
    agsa: AgsaState = field(default_factory=AgsaState)
    fans: list[FanState] = field(default_factory=lambda: [FanState(), FanState()])
    thermal: ThermalState = field(default_factory=ThermalState)
    esp: EspState = field(default_factory=EspState)
    sta: WifiStaConfig = field(default_factory=WifiStaConfig)
    softap: SoftApConfig = field(default_factory=SoftApConfig)
    scan_results: list[dict[str, Any]] = field(default_factory=list)
    endurance: EnduranceTest = field(default_factory=EnduranceTest)
    language: str = "en_US"
    setup_wizard_state: str = "NotRun"
    backlight_power: bool = True
    #: Raw sysfs bl_power value: 0=on, 4=off, 1 after a brightness write
    #: (observed vendor sequence ToggleBacklightPower + SetBacklightBrightness).
    backlight_bl_power: str = "0"
    #: Raw backlight step written to /sys/class/backlight/backlight/brightness.
    #: The equivalence scenarios use 5/7/9 and the factory default is 7, so the
    #: protocol value is the raw step (0..10), not a percentage.
    backlight_brightness: int = 7
    nozzle_light: str = "Off"
    fan_temperature_ctrl_enabled: bool = True
    logs: list[LogEntry] = field(default_factory=list)
    skipped_log_messages: int = 0
    brew_events: list[BrewEvent] = field(default_factory=list)
    driver_config: dict[str, Any] = field(default_factory=dict)
    adc_config: dict[str, Any] = field(default_factory=dict)
    config_settings: dict[str, Any] = field(default_factory=dict)
    remote_key_events: list[int] = field(default_factory=list)
    rotary_ticks: int = 0
    last_dd_target: float = 0.0
    calibration: dict[str, Any] = field(default_factory=dict)
    listener: Optional[Callable[[str, dict[str, Any]], None]] = None
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    config_id: int = 1
    #: Set by the service when a persisted Role.Owner.LoginData row exists.
    owner_login_data: str = ""
    #: When false, no load-cell/motor source is present (the QEMU baseline):
    #: grind commands are accepted but the state machine stays Idle.
    motion_simulated: bool = True

    def __post_init__(self) -> None:
        self.esp.last_heartbeat = self.clock()
        if not self.driver_config:
            self.driver_config = copy.deepcopy(DRIVER_CONFIG)
        if not self.adc_config:
            self.adc_config = copy.deepcopy(ADC_CONFIG)
        self.config_settings.setdefault("language", self.language)
        self.config_settings.setdefault("units", "metric")
        self.config_settings.setdefault("timeZone", "Europe/Berlin")
        self.config_settings.setdefault("setupWizardState", self.setup_wizard_state)
        self.config_settings.setdefault("backlightBrightness",
                                        self.backlight_brightness)
        self.config_settings.setdefault("fanTemperatureCtrlEnabled", True)
        self.config_settings.setdefault("gbsEnabled", True)
        self.config_settings.setdefault("cloudEnabled", False)
        # Ambient boot-time log ring buffer.  RequestLogMessages is reduced to
        # level/category digests; these three categories are what the vendor
        # HMI has already logged before a client connects.
        if not self.logs:
            for category in ("AdcVoltageInDriver", "EspUartDriver",
                             "WebSocketConnector"):
                self.log(f"{category}::ready", "C")

    # -- helpers ----------------------------------------------------------
    def log(self, message: str, level: str = "info") -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.clock()))
        self.logs.append(LogEntry(stamp, level, message))
        if len(self.logs) > 1000:
            del self.logs[: len(self.logs) - 1000]

    def emit(self, event: str, payload: dict[str, Any]) -> None:
        if self.listener is not None:
            self.listener(event, payload)

    def hmi_time(self) -> str:
        # Vendor capture: "30.10.2026 22:46:26" (DD.MM.YYYY HH:MM:SS).
        return time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(self.clock()))

    def grind_failure_string(self) -> str:
        return self.grind.failure_reason if self.grind.failure else "None"

    # -- grind ------------------------------------------------------------
    def start_grind(self, mode: str, target_weight_gr: float = 0.0,
                    target_time_s: float = 0.0) -> tuple[bool, str]:
        if self.grind.state in (GRIND_STARTING, GRIND_RUNNING, GRIND_STOPPING):
            return False, "grind already active"
        if not self.esp.alive:
            return False, "esp not alive"
        if self.thermal.overheat_ntc1 or self.thermal.overheat_ntc2:
            self.grind.failure = True
            self.grind.failure_reason = "Overheat"
            return False, "overheat"
        if not self.motion_simulated:
            # The vendor accepts the action (success:true) but has no ADC
            # sample stream.  A weighted/timed start reports AdcTimeout with
            # the raw ADC constant as the weight and stays Idle; a manual
            # start enters "ManualStartGrind" until Stop.
            self.grind.mode = ""
            self.grind.target_time_s = float(target_time_s)
            self.grind.result_weight_gr = 0.0
            self.grind.final_weight_gr = 0.0
            self.grind.motor_run_time_ms = 0.0
            self.grind.started_at = None
            self.grind.stopped_at = None
            if mode == "gbw":
                self.grind.target_weight_gr = float(target_weight_gr)
            if mode == "manual":
                self.grind.state = "ManualStartGrind"
                self.grind.failure = False
                self.grind.failure_reason = "None"
                self.grind.current_weight_gr = 0.0
            else:
                self.grind.state = GRIND_IDLE
                self.grind.failure = True
                self.grind.failure_reason = "AdcTimeout"
                self.grind.current_weight_gr = 2974.49
            self.log(f"grind accepted without load-cell source mode={mode}")
            return True, ""
        self.grind.mode = mode
        self.grind.state = GRIND_STARTING
        self.grind.failure = False
        self.grind.failure_reason = "None"
        self.grind.session_id += 1
        self.grind.target_weight_gr = float(target_weight_gr)
        self.grind.target_time_s = float(target_time_s)
        self.grind.start_weight_gr = self.grind.current_weight_gr
        self.grind.result_weight_gr = 0.0
        self.grind.final_weight_gr = 0.0
        self.grind.motor_run_time_ms = 0.0
        self.grind.overshoot_weight_gr = 0.0
        self.grind.started_at = self.clock()
        self.grind.stopped_at = None
        self.emit("grindStarted", {"mode": mode,
                                   "targetWeightGr": self.grind.target_weight_gr,
                                   "targetTimeSec": self.grind.target_time_s})
        self.log(f"grind started mode={mode}")
        return True, ""

    def stop_grind(self, reason: str = "requested") -> bool:
        if not self.motion_simulated:
            if self.grind.state == "ManualStartGrind":
                self.grind.state = GRIND_IDLE
                return True
            return False
        if self.grind.state not in (GRIND_STARTING, GRIND_RUNNING):
            return False
        self._finish_grind(reason)
        return True

    def _finish_grind(self, reason: str) -> None:
        self.grind.state = GRIND_STOPPING
        self.grind.stopped_at = self.clock()
        if self.grind.started_at is not None:
            self.grind.motor_run_time_ms = (
                self.grind.stopped_at - self.grind.started_at) * 1000.0
        ground = max(0.0, self.grind.current_weight_gr - self.grind.start_weight_gr)
        self.grind.result_weight_gr = round(ground, 2)
        self.grind.final_weight_gr = round(self.grind.current_weight_gr, 2)
        if self.grind.target_weight_gr > 0:
            self.grind.overshoot_weight_gr = round(
                max(0.0, ground - self.grind.target_weight_gr), 2)
        self.grind.state = GRIND_DONE
        self.grind.mode = ""
        self.emit("grindFinished", {
            "reason": reason,
            "resultWeightGr": self.grind.result_weight_gr,
            "motorRunTimeMs": self.grind.motor_run_time_ms,
            "failure": self.grind.failure,
        })
        self.log(f"grind finished reason={reason} weight={self.grind.result_weight_gr}gr")
        # Return to Idle on the next tick, like the controller's settle phase.
        self._settle_until = self.clock() + 0.2

    def _advance_grind(self, now: float) -> None:
        if not self.motion_simulated:
            return
        g = self.grind
        if getattr(self, "_settle_until", 0) and now >= self._settle_until \
                and g.state == GRIND_DONE:
            g.state = GRIND_IDLE
        if g.state == GRIND_STARTING:
            if now - (g.started_at or now) >= g.start_delay_s:
                g.state = GRIND_RUNNING
        if g.state != GRIND_RUNNING or g.started_at is None:
            return
        elapsed = now - g.started_at - g.start_delay_s
        if g.weight_trace:
            g.current_weight_gr = round(_trace_weight(g.weight_trace, max(0.0, elapsed)), 2)
        else:
            g.current_weight_gr = round(
                g.start_weight_gr + max(0.0, elapsed) * g.weight_rate_gr_s, 2)
        g.motor_run_time_ms = max(0.0, now - g.started_at) * 1000.0
        if g.mode == "gbw" and g.current_weight_gr - g.start_weight_gr >= g.target_weight_gr:
            self._finish_grind("target weight")
        elif g.mode == "gbt" and elapsed >= g.target_time_s:
            self._finish_grind("target time")
        elif g.motor_run_time_ms >= float(
                self.driver_config.get("motorMaxRunTimeMs", 60000)):
            g.failure = True
            self._finish_grind("max motor run time")

    # -- AGSA -------------------------------------------------------------
    def set_agsa_target(self, target_dd: float) -> tuple[bool, str]:
        if not self.agsa.sensor_configured:
            self.agsa.status = "Fault"
            return False, "sensor type not selected"
        if self.agsa.sensor_failed:
            self.agsa.status = "Fault"
            return False, "dd sensor failed"
        self.agsa.target_dd = float(target_dd)
        self.last_dd_target = float(target_dd)
        self.agsa.status = "Moving"
        self.agsa.moving_since = self.clock()
        distance = abs(self.agsa.target_dd - self.agsa.dd_value)
        scaled_speed = self.agsa.speed_dd_per_s * 10.0
        if scaled_speed <= 0:
            self.agsa.timeout_ms = 10000.0
        else:
            self.agsa.timeout_ms = 10000.0 + round(
                abs(distance / scaled_speed) * 1000.0 * 1.5)
        self.emit("agsaTarget", {"targetDdValue": self.agsa.target_dd})
        return True, ""

    def stop_agsa(self) -> bool:
        if self.agsa.status != "Moving":
            return False
        self.agsa.status = "Idle"
        self.agsa.moving_since = None
        return True

    def _advance_agsa(self, now: float) -> None:
        a = self.agsa
        if a.status != "Moving" or a.moving_since is None:
            return
        elapsed = now - a.moving_since
        if elapsed * 1000.0 > a.timeout_ms:
            a.status = "Fault"
            a.moving_since = None
            self.log("agsa timeout", "warning")
            return
        delta = a.target_dd - a.dd_value
        step = a.speed_dd_per_s * (now - getattr(self, "_agsa_last", now))
        self._agsa_last = now
        if abs(delta) <= abs(step):
            a.dd_value = round(a.target_dd, 3)
            a.status = "Idle"
            a.moving_since = None
            self.emit("agsaTargetReached", {"ddValue": a.dd_value})
        else:
            a.dd_value = round(a.dd_value + math.copysign(abs(step), delta), 3)
        a.hall_counts = int(a.dd_value * 40)
        a.dd_angle = round(a.dd_value * 1.8, 2)

    # -- fans -------------------------------------------------------------
    def set_fan_duty(self, index: int, duty: int) -> bool:
        fan = self.fans[index]
        clamped = max(0, min(MAX_DUTY, int(duty)))
        fan.duty = clamped
        fan.power_enabled = clamped > 0
        fan.tacho_rpm = 0 if clamped == 0 else int(clamped * 42)
        return True

    def calibrate_fan(self, index: int) -> bool:
        fan = self.fans[index]
        if fan.failed:
            return False
        fan.calibrating = True
        fan.calibrating = False
        return True

    # -- endurance --------------------------------------------------------
    def start_endurance(self, grind_time_s: int, pause_time_s: int) -> bool:
        if self.endurance.running:
            return False
        self.endurance = EnduranceTest(
            running=True, cycle=0, state="Running",
            start_time=self.hmi_time(), duration=0,
            grind_time_s=int(grind_time_s), pause_time_s=int(pause_time_s),
            started_at=self.clock())
        self.log("endurance test started")
        return True

    def stop_endurance(self) -> bool:
        if not self.endurance.running:
            return False
        self.endurance.running = False
        self.endurance.state = "Stopped"
        self.log("endurance test stopped")
        return True

    # -- ESP --------------------------------------------------------------
    def esp_heartbeat(self, hb_num: int = 0) -> None:
        self.esp.last_heartbeat = self.clock()
        self.esp.alive = True
        self.esp.missed_heartbeats = 0

    def _advance_esp(self, now: float) -> None:
        # Three missed heartbeat cycles mark the link dead (ESP_PROTOCOL.md).
        if not self.esp.alive:
            return
        if now - self.esp.last_heartbeat > 3 * 1.0:
            self.esp.alive = False
            self.esp.uart_failed = True
            self.esp.sdio_status = 3
            self.log("esp heartbeat lost", "warning")

    # -- periodic ---------------------------------------------------------
    def tick(self, now: Optional[float] = None) -> None:
        now = self.clock() if now is None else now
        self._advance_grind(now)
        if not hasattr(self, "_agsa_last"):
            self._agsa_last = now
        self._advance_agsa(now)
        self._advance_esp(now)
        if self.endurance.running and self.endurance.started_at is not None:
            self.endurance.duration = int(now - self.endurance.started_at)
            cycle_s = max(1, self.endurance.grind_time_s + self.endurance.pause_time_s)
            self.endurance.cycle = int(self.endurance.duration // cycle_s)

    # -- serialisation ----------------------------------------------------
    def driver_state_json(self) -> dict[str, Any]:
        fans = self.fans
        return {
            "sessionId": self.session_id,
            "configId": self.config_id,
            "grinderType": self.machine.grinder_type_name,
            "grindState": self.grind.state,
            "grindFailure": self.grind_failure_string(),
            "grindCurrentWeightGr": self.grind.current_weight_gr,
            "grindResultWeightGr": self.grind.result_weight_gr,
            "grindStartWeightGr": self.grind.start_weight_gr,
            "grindFinalWeightGr": self.grind.final_weight_gr,
            "grindTargetWeightGr": self.grind.target_weight_gr,
            "motorRunTimeMs": round(self.grind.motor_run_time_ms, 1),
            "overshootWeightGr": self.grind.overshoot_weight_gr,
            "cpuTempFailed": self.thermal.cpu_temp_failed,
            "cpuTempDegC": self.thermal.cpu_temp_degc,
            "hasNtc1": self.thermal.has_ntc1,
            "ntc1Failed": self.thermal.ntc1_failed,
            "ntc1TempDegC": self.thermal.ntc1_temp_degc,
            "ntc2Failed": self.thermal.ntc2_failed,
            "ntc2TempDegC": self.thermal.ntc2_temp_degc,
            "overheatNtc1": self.thermal.overheat_ntc1,
            "overheatNtc2": self.thermal.overheat_ntc2,
            "hmiTime": self.hmi_time(),
            "hmiProdDate": self.machine.production_date,
            "fanTemperatureCtrlEnabled": self.fan_temperature_ctrl_enabled,
            "fan1Duty": fans[0].duty,
            "fan2Duty": fans[1].duty,
            "fan1TachoRpm": fans[0].tacho_rpm,
            "fan2TachoRpm": fans[1].tacho_rpm,
            "fan1Failed": fans[0].failed,
            "fan2Failed": fans[1].failed,
            "ddValueDum": self.agsa.dd_value,
            "agsaHallSensorCounts": self.agsa.hall_counts,
            "ddSensorAngle": self.agsa.dd_angle,
            "ddSensorFailed": self.agsa.sensor_failed,
            "agsaStatus": self.agsa.status,
            "shiftCompensationFailed": self.agsa.shift_compensation_failed,
            "espUartFailed": self.esp.uart_failed,
            "espSdioState": self.esp.sdio_status,
            "espFuseFailed": self.esp.fuse_failed,
            "espAlive": self.esp.alive,
            "espVersionNo": self.esp.version_no,
            "espUpdateRequired": self.esp.update_required,
            "enduranceTestCycle": self.endurance.cycle,
            "enduranceTestState": self.endurance.state,
            "enduranceTestStartTime": self.endurance.start_time,
            "enduranceTestDuration": self.endurance.duration_string(),
            "language": self.language,
            "setupWizardState": self.setup_wizard_state,
        }

    def machine_info_json(self) -> dict[str, Any]:
        # createDataMachineInfo() builds exactly two members: sessionId (the
        # JsonConnector UUID) and grinderType (MachineConfig::grinderTypeString,
        # which reads "Unknown" on a development image).
        return {
            "sessionId": self.session_id,
            "grinderType": self.machine.grinder_type_name,
        }

    def adc_config_json(self) -> dict[str, Any]:
        return copy.deepcopy(self.adc_config)

    def driver_config_json(self) -> dict[str, Any]:
        data = copy.deepcopy(self.driver_config)
        data["id"] = data.get("id", 2)
        return data

    def config_manager_json(self) -> dict[str, Any]:
        data = copy.deepcopy(CONFIG_MANAGER)
        data["System.Language"] = self.language
        data["System.SetupWizard.State"] = self.setup_wizard_state
        data["Role.Owner.LoginData"] = self.owner_login_data
        data["System.Name"] = f"HemroHsg-{self.machine.serial_number}"
        data["Wifi.Enabled"] = bool(self.sta.ssid)
        data["Wifi.Mode"] = ("Accesspoint" if self.esp.mode in (2, 3)
                             else "Station" if self.esp.mode == 1
                             else "Accesspoint")
        data["Wifi.StaSsid"] = self.sta.ssid
        data["Wifi.StaPassword"] = self.sta.password
        data["Wifi.StaDhcp"] = self.sta.dhcp
        data["Wifi.StaIp"] = self.sta.ip
        data["Wifi.StaGateway"] = self.sta.gateway
        data["Wifi.StaNetmask"] = self.sta.netmask
        data["Wifi.StaDns"] = self.sta.dns
        # Settings supplied by a profile (for example the sanitized
        # 2026-11-18 live profile) override the pristine defaults.
        for key, value in self.config_settings.items():
            if key in data:
                data[key] = value
        # The WSS config-manager presentation is in grams, while the vendor
        # database stores micrograms.  Keep the state value authoritative.
        data["Grinding.OvershootWeight"] = f"{self.grind.overshoot_weight_gr:.6f}g"
        return data
