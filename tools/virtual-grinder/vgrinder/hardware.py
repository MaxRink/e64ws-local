"""Explicit synthetic hardware model for the virtual grinder.

The vendor HMI does not consume every surface in the VM (for example the DD
analogue path and fan tacho). This module still models them, so the state is
observable and testable through `/api/state` and `vg hardware`, and so a future
driver emulation has a defined contract.

All values are synthetic. Nothing here is a hardware measurement.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class HardwareModel:
    # Load cell / ADC. C0/C1 are the vendor's gbwAdcToWeight coefficients:
    # weight_g = C0 + C1 * raw. The fixture inverts this.
    loadcell_weight_g: float = 0.0
    loadcell_tare_g: float = 0.0
    loadcell_raw: int = 32538
    loadcell_c0: float = 2974.494926
    loadcell_c1: float = -0.091416034
    loadcell_scale: float = 0.001
    adc_buffer_enabled: bool = True
    adc_sample_hz: int = 1000
    adc_channels: int = 13

    # Disc distance / AGSA
    ddd_sensor_type: str = "analog"
    ddd_voltage_v: float = 2.048
    ddd_valid: bool = True
    dd_um: int = 1200
    dd_calibration_valid: bool = True
    agsa_encoder_counts: int = 0
    agsa_dd_um: int = 1200
    agsa_current_ma: int = 120
    agsa_overcurrent: bool = False
    agsa_blocked: bool = False

    # Thermal
    ntc1_c: float = 24.5
    ntc2_c: float = 24.0
    cpu_c: float = 41.0

    # Fans
    fan1_rpm: int = 0
    fan2_rpm: int = 0
    fan_duty: int = 0
    fan_calibrated: bool = True

    # Inputs / outputs
    buttons: str = "00000000"
    leds: dict[str, int] = field(default_factory=dict)
    backlight: int = 7
    gpio59: int = 1
    gpio60: int = 0
    watchdog_writes: int = 0

    # Update / identity
    esp_version: str = "01.11"
    rootfs_version: str = "01.16-24"
    edpk_present: bool = True

    def set_weight(self, grams: float) -> None:
        self.loadcell_weight_g = round(float(grams), 2)
        if abs(self.loadcell_c1) < 1e-12:
            raw = 1000
        else:
            raw = (self.loadcell_weight_g - self.loadcell_c0) / self.loadcell_c1
            raw = int(round(raw))
        self.loadcell_raw = max(0, min(65535, raw))

    def set_agsa(self, dd_um: int, current_ma: int = 120) -> None:
        self.agsa_dd_um = int(dd_um)
        self.agsa_encoder_counts = int(dd_um * 4)
        self.agsa_current_ma = int(current_ma)
        self.agsa_overcurrent = current_ma > 2000
        self.agsa_blocked = self.agsa_overcurrent

    def snapshot(self) -> dict:
        return asdict(self)
