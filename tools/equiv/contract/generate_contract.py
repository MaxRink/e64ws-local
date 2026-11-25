#!/usr/bin/env python3
"""Generate contract/hmi_contract.json.

Source of record ids/flags: docs/API_REGISTRY.md (52 WSS records),
docs/bible/protocols.md (HTTP/ESP/JSON/sysfs), docs/REST_API.md.
`observed` means the row was exercised in the virtual grinder during this work
and the reply shape in `observable` was read from the transcript.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DIRECT = [
    # name, dev, token, reply, refId, confidence, observed_shape
    ("RequestDriverConfig", 0, 1, "RequestDriverConfigResult", True, "observed",
     "data: 59 driver-config keys (configVersion, gbwAdcToWeightC0, grinderType, ...)"),
    ("RequestDriverState", 0, 1, "RequestDriverStateResult", True, "observed",
     "data: 48 runtime keys (grindState, espSdioState, hmiTime, sessionId, ...)"),
    ("RequestLogMessages", 1, 1, "RequestLogMessagesResult", True, "observed",
     "data: {skippedLogMessages, logMessages[]} ring buffer"),
    ("RequestAdcConfig", 1, 1, "RequestAdcConfigResult", True, "observed",
     "data: 14 ADC timing/oversampling keys"),
    ("RequestConfigManagerSettings", 1, 1, "RequestConfigManagerSettingsResult", True, "observed",
     "data: dotted config-manager keys (Agsa.*, Cloud.*, Gbw.*, Gbs.*)"),
    ("RequestNachineInfo", 0, 1, "RequestNachineInfoResult", True, "observed",
     "data: {grinderType, sessionId}; note firmware spelling 'Nachine'"),
    ("RequestOnboarding", 0, 0, "RequestOnboardingResult", False, "observed",
     "data: {success}; no refId in the recovered builder"),
    ("WifiStaConfig", 0, 1, "WifiStaConfig", False, "observed",
     "data: {success}; type is not suffixed with Result"),
    ("WifiConfigChanged", 0, 1, "WifiConfigChangedProcessed", False, "observed",
     "data: {success}; distinct from WifiStaConfig"),
    ("UpdateDriverConfig", 1, 1, "UpdateDriverConfigResult", True, "unknown",
     "driver-config write; payload object or JSON string"),
    ("UpdateCpuConfig", 1, 1, "UpdateCpuConfigResult", True, "inferred",
     "recovered callback ignores payload and returns failure-valued result"),
    ("CustomSignal1", 1, 1, "CustomSignal1Result", True, "observed",
     "empty data object; payload ignored"),
    ("CustomSignal2", 1, 1, "CustomSignal2Result", True, "observed",
     "empty data object; payload ignored"),
]

ACTIONS = [
    # suffix, dev, payload, special reply
    ("Stop", 1, None, None),
    ("StartGrindManual", 1, None, None),
    ("StartGrindGbw", 1, "targetWeightGr:number", None),
    ("StartGrindGbt", 1, "grindTimeSec:number", None),
    ("StartCalibration", 1, None, None),
    ("StartTara", 1, None, None),
    ("SaveLog", 1, None, None),
    ("ResetLog", 1, None, None),
    ("SetFanTemperatureCtrlEnabled", 1, "enabled:bool", None),
    ("SetFan1Duty", 1, "dutyPercent:number", None),
    ("SetFan2Duty", 1, "dutyPercent:number", None),
    ("CalibrateFan1", 1, None, None),
    ("CalibrateFan2", 1, None, None),
    ("ToggleBacklightPower", 1, None, None),
    ("SetBacklightBrightness", 1, "brightness:number", None),
    ("EspFlashApp", 1, None, None),
    ("EspEraseFlash", 1, None, None),
    ("EspReset", 0, None, None),
    ("NozzleLightRunStandby", 1, None, None),
    ("NozzleLightStop", 1, None, None),
    ("ResetDriverConfig", 0, None, None),
    ("SetAgsaTargetDdValue", 1, "targetDdValue:number", None),
    ("StopAgsa", 1, None, None),
    ("CalibrateDdSensor", 1, None, None),
    ("AddBrewEvent", 1,
     "grindUuid,machineName,groupHead,doseIndex,validity,brewTimeMs,brewWeightMg", None),
    ("GbsCreateReport", 1, None, "GbsCreateReport {log:[...]} (no refId)"),
    ("SetLanguage", 1, "language:string", None),
    ("RcTopLeftClick", 1, None, None),
    ("RcTopLeftLong", 1, None, None),
    ("RcTopLeftPress", 1, None, None),
    ("RcTopLeftRelease", 1, None, None),
    ("RcBottomLeftClick", 1, None, None),
    ("RcRotaryClick", 1, None, None),
    ("RcRotaryLong", 1, None, None),
    ("RcRotaryDouble", 1, None, None),
    ("RcRotary", 1, "ticks:number", None),
    ("StartEnduranceTest", 1, "grindTimeSec,pauseTimeSec", None),
    ("StopEnduranceTest", 1, None, None),
    ("SetSetupWizardState", 1, "state: NotRun|Disabled|Completed", None),
]


def wss_entries() -> list[dict]:
    rows = []
    for index, (name, dev, token, reply, refid, conf, observed) in enumerate(DIRECT, 1):
        rows.append({
            "id": f"WSS-D{index:02d}",
            "surface": "wss",
            "direction": "C->D",
            "name": name,
            "action": None,
            "dev_only": bool(dev),
            "token_required": bool(token),
            "shape": "{\"type\":\"%s\",\"msgId\":<int>}" % name,
            "observable": f"{reply}; refId={{{'msgId' if refid else 'absent'}}}; {observed}",
            "confidence": conf,
            "scenario": "02_readonly" if not dev else "03_dev_cmds",
        })
    for index, (suffix, dev, payload, special) in enumerate(ACTIONS, 1):
        observable = special or "GrinderActionResult; refId=msgId; data.success:bool"
        if suffix in ("EspFlashApp", "EspEraseFlash", "EspReset", "CalibrateDdSensor",
                      "StartCalibration", "StartTara"):
            observable += "; hardware path stubbed in QEMU (see REPORT limits)"
        rows.append({
            "id": f"WSS-A{index:02d}",
            "surface": "wss",
            "direction": "C->D",
            "name": "GrinderAction",
            "action": suffix,
            "dev_only": bool(dev),
            "token_required": True,
            "shape": "{\"type\":\"GrinderAction\",\"msgId\":<int>,\"data\":{\"actionType\":\"%s\"%s}}" % (
                suffix, (", " + payload) if payload else ""),
            "observable": observable,
            "confidence": "observed",
            "scenario": None if suffix in ("EspFlashApp", "EspEraseFlash") else "03_dev_actions",
            **({"coverage_note": "Drives esptool over /dev/ttySTM5 (stubbed in QEMU); no signed ESP image fixture is available and the path can block for the flash timeout."}
               if suffix in ("EspFlashApp", "EspEraseFlash") else {}),
        })
    return rows


REST = [
    ("REST-01", "ping", "ANY /rest_api/ping", "pong\\n (valid session) | expired\\n", "observed", "01_http"),
    ("REST-02", "login", "POST /rest_api/login {userRole,password}", "200 {success,errorCode} + Authorization: Bearer <64hex>; 400 on wrong password", "observed", "01_http"),
    ("REST-03", "logout", "POST /rest_api/logout", "{success:true}; clears application session", "observed", "01_http"),
    ("REST-04", "check_session", "ANY /rest_api/check_session", "session_valid\\n | session_invalid\\n", "observed", "01_http"),
    ("REST-05", "update_session", "POST /rest_api/update_session", "{console:\"\",success:true}", "observed", "01_http"),
    ("REST-06", "get_machine_info", "ANY /rest_api/get_machine_info", "{grinderType,grinderTypeName,error} before auth gate", "observed", "01_http"),
    ("REST-07", "get_wifi_info", "POST /rest_api/get_wifi_info", "{hostname,mode,apIp,apMacAddress,staIp,staMacAddress}", "observed", "01_http"),
    ("REST-08", "scan_wifi", "POST /rest_api/scan_wifi", "{data:[{ssid,bssid,rssi,channel,encryptionMode}]} from EspWifiConfig -u", "observed", "01_http"),
    ("REST-09", "request_onboarding", "POST /rest_api/request_onboarding", "writes /tmp/onboardingRequest.json, invokes NgxWsClient", "observed", None),
    ("REST-10", "reboot", "POST /rest_api/reboot", "sudo reboot; connection drops, boot_id changes", "observed", None),
    ("REST-11", "get_fw_update_state", "POST /rest_api/get_fw_update_state", "raw /tmp/FirmwareUpdateState.json", "observed", "01_http"),
    ("REST-12", "download_database", "POST /rest_api/download_database", "SQLite attachment (byte length + sha256)", "observed", "01_http"),
    ("REST-13", "download_machine_logs", "POST /rest_api/download_machine_logs", "ZIP with 2 CSVs", "observed", "01_http"),
    ("REST-14", "upload_swu", "POST /upload_swu.php (multipart swuFile + Chunk-*)", "prepare|install|failed JSON; /storage/update.swu state", "observed", None),
    ("REST-15", "upload_esp", "POST /upload_esp.php (multipart espFile ZIP)", "unzip to /tmp/esp.zip, flashEspZip.sh /dev/ttySTM5", "observed", None),
    ("REST-16", "upload_splash", "POST /upload_splash_screen.php (<=480x360)", "writes /config/custom-splash-screen", "observed", None),
    ("REST-17", "wifi_save", "POST /wifi.php saveConfig", "writes /tmp/wifiStaConfig.json + /db/wifiConfig.json", "observed", None),
]

ESP_PAIRS = [
    (101, "GetMACAddress", "mode:u32", "mac:bytes, resp:i32"),
    (102, "SetMacAddress", "mac,mode", "resp:i32"),
    (103, "GetWifiMode", "-", "mode:i32, resp:i32"),
    (104, "SetWifiMode", "mode", "resp:i32"),
    (105, "GetAPScanList", "-", "count, ScanResult[]"),
    (106, "GetAPConfig", "-", "ssid,bssid,rssi,chnl,sec_prot,resp"),
    (107, "ConnectAP", "ssid,pwd,bssid,is_wpa3_supported,listen_interval", "resp,mac"),
    (108, "DisconnectAP", "-", "resp"),
    (109, "GetSoftAPConfig", "-", "7 fields + resp"),
    (110, "SetSoftAPVendorSpecificIE", "enable,type,idx,vendor_ie_data", "resp"),
    (111, "StartSoftAP", "ssid,pwd,chnl,sec_prot,max_conn,ssid_hidden,bw", "resp,mac"),
    (112, "GetSoftAPConnectedSTAList", "-", "num, stations[]"),
    (113, "StopSoftAP", "-", "resp"),
    (114, "SetPowerSaveMode", "mode", "resp"),
    (115, "GetPowerSaveMode", "-", "mode, resp"),
    (116, "OTABegin", "-", "resp"),
    (117, "OTAWrite", "ota_data", "resp"),
    (118, "OTAEnd", "-", "resp"),
    (119, "SetWifiMaxTxPower", "wifi_max_tx_power", "resp"),
    (120, "GetWifiCurrTxPower", "-", "wifi_curr_tx_power, resp"),
    (121, "ConfigHeartbeat", "enable,duration", "resp"),
]


REST_NOT_COVERED = {
    "REST-09": "Requires /tmp/onboardingRequest.json + NgxWsClient; the same handler is covered through WSS RequestOnboarding (02_readonly).",
    "REST-10": "The REST route only shells out to `sudo reboot`; reboot behaviour is covered through the guest agent in 05_persistence.",
    "REST-14": "Destructive: `prepare` runs `rm -rf /storage/*` and requires a vendor-signed SWU. Not safe against the shared snapshot; covered by static review only.",
    "REST-15": "Invokes flashEspZip.sh /dev/ttySTM5 (stubbed in QEMU); no signed fixture is available.",
    "REST-16": "Writes /config/custom-splash-screen and restarts the splash process; needs a 480x360 fixture, no behavioural value for the HMI core.",
    "REST-17": "Writes /tmp/wifiStaConfig.json then delegates to the same WifiStaConfig handler covered in 03_dev_actions.",
}


def rest_entries() -> list[dict]:
    rows = []
    for rid, name, shape, observable, conf, scenario in REST:
        entry = {
            "id": rid, "surface": "rest", "direction": "C->D",
            "name": name, "action": None, "shape": shape,
            "observable": observable, "confidence": conf, "scenario": scenario,
        }
        if rid in REST_NOT_COVERED:
            entry["coverage_note"] = REST_NOT_COVERED[rid]
        rows.append(entry)
    return rows


def esp_entries() -> list[dict]:
    rows = []
    for mid, name, req, resp in ESP_PAIRS:
        rows.append({
            "id": f"ESP-{mid}", "surface": "esp.ctrl", "direction": "D->X",
            "name": f"Req_{name}", "action": None,
            "shape": f"14-byte TLV (ctrlResp) + protobuf CtrlMsg(msg_id={mid})",
            "observable": f"Resp_{name} (msg_id={mid + 100}): {resp}",
            "confidence": "observed", "scenario": "06_esp",
        })
    for eid, name, fields in ((301, "ESPInit", "init_data:bytes"),
                              (302, "Heartbeat", "hb_num:i32"),
                              (303, "StationDisconnectFromAP", "resp:i32"),
                              (304, "StationDisconnectFromESPSoftAP", "resp:i32,mac:bytes")):
        rows.append({
            "id": f"ESP-{eid}", "surface": "esp.ctrl", "direction": "X->D",
            "name": name, "action": None,
            "shape": "14-byte TLV (ctrlEvnt) + protobuf CtrlMsg",
            "observable": fields + "; HMI reaction visible in RequestDriverState",
            "confidence": "observed", "scenario": "06_esp",
        })
    return rows


def esp_json_entries() -> list[dict]:
    rows = [
        ("ESPU-01", "C->D", "{\"ping\":true}", "-", "HMI heartbeat every ~500 ms; ESP must answer within its timeout", "06_esp"),
        ("ESPU-02", "D->C", "{\"pong\":true}", "reply to ping", "emulator fixture; reply schema observed", "06_esp"),
        ("ESPU-03", "C->D", "{\"type\":\"RequestVersion\"}", "-", "HMI asks for ESP version after boot", "06_esp"),
        ("ESPU-04", "D->C", "{\"versionNo\":\"01.11\",\"versionDate\":\"16.12.2025\"}", "reply", "mirrored into driverState.espVersionNo", "06_esp"),
        ("ESPU-05", "C->D", "{\"type\":\"RequestSdioStatus\"}", "-", "state poll", "06_esp"),
        ("ESPU-06", "D->C", "{\"sdioStatus\":1,...}", "reply", "mirrored into driverState.espSdioState", "06_esp"),
        ("ESPU-07", "C->D", "{\"type\":\"StartFunction\",\"function\":2,...}", "LED animation request", "7 LED fields; emitted on UI light changes", "03_dev_actions"),
        ("ESPU-08", "D->C", "{\"requestConfig\":true}", "-", "ESP asks HMI to push config", "06_esp"),
    ]
    return [{
        "id": rid, "surface": "esp.json", "direction": direction,
        "name": name, "action": None, "shape": shape,
        "observable": observable, "confidence": "observed", "scenario": scenario,
    } for rid, direction, name, shape, observable, scenario in rows]


def io_entries() -> list[dict]:
    rows = [
        ("IO-01", "/sys/class/input/input1/device/gpio_value", "front-panel keys: write index, read 0/1", "write + read-back", "observed"),
        ("IO-02", "/sys/class/leds/{AGSA_*,FAN1_EN,FAN2_EN,USB_EN}/brightness", "LED/relay outputs", "value after action", "observed"),
        ("IO-03", "/sys/class/backlight/backlight/{brightness,bl_power}", "display backlight", "value after ToggleBacklightPower/SetBacklightBrightness", "observed"),
        ("IO-04", "/sys/class/gpio/{export,gpio59,gpio60}/{direction,value}", "ESP boot/reset lines", "value after EspReset", "observed"),
        ("IO-05", "/dev/watchdog", "keepalive byte stream", "file size growth; 'V' on stop", "observed"),
        ("IO-06", "/sys/bus/iio/devices/iio:device3..6/*", "ADC buffer/scan config", "sysfs values", "observed"),
        ("IO-07", "/sys/bus/platform/.../stm32-one-pulse, stm32-timers", "motor pulse/PWM/counter", "prepare,pulse_length,count,enable", "observed"),
        ("IO-08", "/sys/bus/nvmem/devices/stm32-romem0/nvmem", "CPU temperature OTP", "128-byte image", "observed"),
        ("IO-09", "/dev/mem (MPC157 registers)", "device-memory IO", "mmap read/write (shim to memfd)", "observed"),
    ]
    return [{
        "id": rid, "surface": "sysfs", "direction": "D->HW",
        "name": path, "action": None, "shape": shape,
        "observable": observable, "confidence": conf, "scenario": "02_readonly",
    } for rid, path, shape, observable, conf in rows] + [
        {
            "id": "FS-01", "surface": "files", "direction": "D->FS",
            "name": "/db (HsgSqlite.db, HsgConfig.json, machineCounters.json, wifiConfig.json, webui.crt|key)",
            "action": None, "shape": "file set + sha256 + SQLite rows",
            "observable": "grind_log/event_log/settings rows, counters, config JSON",
            "confidence": "observed", "scenario": "05_persistence",
        },
        {
            "id": "FS-02", "surface": "files", "direction": "D->FS",
            "name": "/tmp (tok_*, onboardingRequest.json, wifiStaConfig.json, FirmwareUpdateState.json, esp.zip)",
            "action": None, "shape": "file presence + content",
            "observable": "transient state written by handlers",
            "confidence": "observed", "scenario": "01_http",
        },
        {
            "id": "FS-03", "surface": "files", "direction": "D->FS",
            "name": "/storage (chunk.dat, update.swu)",
            "action": None, "shape": "file set + size",
            "observable": "upload accumulation",
            "confidence": "observed", "scenario": None,
            "coverage_note": "Only written by upload_swu.php prepare, which is destructive (rm -rf /storage/*).",
        },
        {
            "id": "PWR-01", "surface": "power", "direction": "C->D",
            "name": "reboot / poweroff via REST, WSS, guest init",
            "action": None, "shape": "POST /rest_api/reboot, GrinderAction Stop+reboot, S90app restart",
            "observable": "boot_id change, time to WSS ready, post-boot state",
            "confidence": "observed", "scenario": "05_persistence",
        },
        {
            "id": "LOG-01", "surface": "log", "direction": "D->out",
            "name": "serial console (/dev/console)",
            "action": None, "shape": "kernel + vendor init + HMI stdout",
            "observable": "boot markers, driver errors, crash traces",
            "confidence": "observed", "scenario": None,
        },
    ]


def main() -> None:
    entries = wss_entries() + rest_entries() + esp_entries() + esp_json_entries() + io_entries()
    contract = {
        "version": 1,
        "target": "HEM-HSG-HMI-S01 V01.16-24 (Mahlkoenig E64 WS)",
        "confidence_tags": {
            "observed": "read or exercised directly in the vendor artifact/VM during this work",
            "inferred": "mechanically derived from observed facts plus a named mechanism",
            "unknown": "not established; needs the reconstruction or a physical device",
        },
        "entries": entries,
    }
    out = ROOT / "contract" / "hmi_contract.json"
    out.write_text(json.dumps(contract, indent=2) + "\n")
    surfaces = {}
    for row in entries:
        surfaces.setdefault(row["surface"], 0)
        surfaces[row["surface"]] += 1
    print(f"{len(entries)} contract entries -> {out}")
    print(json.dumps(surfaces, indent=2))


if __name__ == "__main__":
    main()
