# Virtual grinder — Mahlkönig E64 WS (HEM-HSG-HMI-S01 V01.16-24)

A development environment that runs the **vendor userspace** of the E64 WS in
QEMU and virtualizes the hardware around it, so a developer can drive inputs
and observe outputs without a physical machine.

Everything here lives under `/tmp/virtual-grinder/`. The research repository is
only read (firmware at `.tools/firmware-1.16-24/`, kernel helpers at
`.tools/qemu/kernel/`); no repository file is modified.

---

## Quick start

```sh
cd /tmp/virtual-grinder

./vg build          # kernel, initrd, DTB, rootfs/app/db images (~1 min)
./vg up             # boot the VM and start the control daemon
./vg status         # VM, HTTP/HTTPS, WSS, Qt VNC, guest agent, ESP
./vg screen         # capture the HMI over VNC -> work/screens/*.png
./vg logs -f        # serial console (kernel + vendor init + HMI)
./vg down           # stop everything
```

To build the whole tree directly from the vendor SWU instead of the repository
extraction:

```sh
tools/virtual-grinder/from_swu.sh   /tmp/all-firmware/downloads/HEM-HSG-HMI-S01-V01.16-24.swu /tmp/vg-swu
VG_ROOT=/tmp/vg-swu/vm E64_FW_DIR=/tmp/vg-swu/fw tools/virtual-grinder/vg up
```

The macOS front end is [tools/vm-app](../vm-app/README.md); the input and
calibration audit is [docs/VM_INPUT_AND_CALIBRATION.md](../../docs/VM_INPUT_AND_CALIBRATION.md).

First boot to the HMI screen takes roughly **60–80 seconds** (the vendor app
initializes its services and QML). `vg up` returns as soon as the guest getty
is up; use `vg status`/`vg screen` until the HMI paints.

Ports (host, loopback only):

| Purpose | URL / port |
|---|---|
| Web UI (HTTP, redirects to HTTPS) | `http://127.0.0.1:28082/` |
| Web UI (HTTPS) | `https://127.0.0.1:28443/login.php` |
| HMI WebSocket (WSS) | `wss://127.0.0.1:29997/` |
| HMI display (Qt VNC platform plugin) | `vnc://127.0.0.1:25900` |
| SSH forward (guest has no sshd by default) | `127.0.0.1:22222` |
| Control daemon (HTTP dashboard + JSON) | `http://127.0.0.1:28765/` |
| OpenScale fixture (`/snapshot`) | `ws://127.0.0.1:28090/snapshot` |

All ports are overridable with `VG_HTTP_PORT`, `VG_HTTPS_PORT`, `VG_WSS_PORT`,
`VG_QT_VNC_PORT`, `VG_CONTROL_PORT`, `VG_SCALE_PORT`, `VG_SSH_PORT`.
The defaults deliberately avoid `18082/18443/15900/12222`, which other tooling
in this workspace uses concurrently. QEMU is launched through a symlink named
`work/bin/vg-qemu` so a `pkill -f qemu-system-arm` from another session does not
kill this VM.

---

## Control surface

A single `vg` command talks to a small daemon (`vgrinder.daemon`) that owns
QEMU, the virtual ESP32, the guest agent channel and the synthetic scale.

```sh
./vg status [--json]            # health of every observable surface
./vg state                      # full state (VM, guest, ESP, scale, grinder)
./vg hardware                   # synthetic hardware model (load cell, DD/AGSA, NTC, fan)
./vg issue custom|development   # toggle REST-capable vs WSS-dev /etc/issue
./vg probe                      # probe HTTP/HTTPS/WSS/VNC/agent
./vg logs [-f] [-n N]           # serial console log

# Inputs
./vg key top                    # top|bottom|rotary|ddd|hopper|agsa (or --index N)
./vg key top --hold 800         # hold time in ms
./vg key top --value 1          # press and leave held; --value 0 releases
./vg rotate 3                   # rotary clicks (negative = other direction)
./vg weight 18.5                # grams: guest state + OpenScale fixture
./vg weight --base 18.0         # empty-basket tare (basket detection)
./vg weight --rate 2.0          # grams/second while grinding
./vg weight --start             # start the ramp at the base weight
./vg weight --stop              # stop and freeze the weight

# The VM build enables development mode (14-token /etc/issue starting with
# `development`), so the Rc* WSS actions are dispatchable. Without it the
# socket closes on every dev-only action and input looks dead.
./vg wss --json-message '{"type":"GrinderAction","msgId":1,"data":{"actionType":"RcRotaryClick"}}'
./vg wifi scan                  # virtual ESP scan list
./vg wifi join vg-lab --password secret
./vg wifi off
./vg vnc click 70 180           # RFB pointer event (emulation-only touch path)
./vg vnc key 0xff0d             # RFB key event (X11 keysym)
./vg esp event 302 --data 08 01 # async ESP event (id + protobuf body hex)
./vg esp raw 010800...          # raw frame to /dev/esps0

# Outputs
./vg screen [FILE]              # PNG of the Qt VNC framebuffer
./vg web get /login.php         # vendor HTTP(S) page
./vg wss RequestDriverState     # WSS query (mints a guest token automatically)
./vg wss --json-message '{"type":"GrinderAction","msgId":1,"data":{"actionType":"Stop"}}'
./vg grind start --mode manual  # GrinderAction convenience wrapper
./vg grind stop

# Guest / power
./vg shell 'ps w; cat /tmp/vg/agent.log'
./vg power reset|off|reboot|shutdown
```

The daemon also serves a small browser dashboard at
`http://127.0.0.1:28765/` with buttons for the common inputs and a live state
dump. `run/state.json` is rewritten every second; `work/serial.log` is the
full serial console.

The macOS app in [tools/vm-app](../vm-app/README.md) is the graphical front end:
rotated 480×320 display, the two round panel buttons, a draggable rotary knob,
the full five-level input matrix, load-cell simulation, machine schematic,
state and logs. Build/run instructions and the known gaps are in
[docs/VM_INPUT_AND_CALIBRATION.md](../../docs/VM_INPUT_AND_CALIBRATION.md).

`vg wss` mints a 64-hex token by writing `/tmp/tok_<token>` in the guest, which
is the file the vendor `WebSocketConnector` validates (the PHP login flow uses
the same shape). This is a development fixture; it never touches a real
machine.

---

## Architecture

```
 host /tmp/virtual-grinder
 ┌──────────────────────────────────────────────────────────────────────┐
 │  vg CLI ── unix socket ──► daemon                                   │
 │                              ├── QEMU (work/bin/vg-qemu)             │
 │                              ├── ESP control server  ◄─ virtio-serial│
 │                              ├── ESP JSON server     ◄─ virtio-serial│
 │                              ├── guest agent channel ◄─ virtio-serial│
 │                              └── OpenScale fixture (ws://:28090)     │
 └──────────────────────────────────────────────────────────────────────┘
                    │ QMP, serial, hostfwd
 ┌──────────────────▼───────────────────────────────────────────────────┐
 │ guest (vendor rootfs, Debian armmp kernel)                           │
 │  /sbin/init → S00vgagent → vg-agent                                  │
 │    ├─ tmpfs overlays: /sys/class/{input,leds,backlight,gpio}          │
 │    │                  /sys/bus/{iio,platform,nvmem}                  │
 │    ├─ uinput: vg-rotary → /dev/input/event0 (EV_REL + EV_KEY)        │
 │    ├─ pty relay: /dev/ttySTM1 ↔ /dev/vport0p2 (JSON)                 │
 │    ├─ /dev/esps0 → /dev/vport0p1 (TLV + protobuf)                    │
 │    └─ control: /dev/vport0p3 (sequenced JSON lines)                  │
 │  S50esp: symlinks only (no mknod/modprobe)                           │
 │  S90app: LD_PRELOAD=/db/libvgsim.so, QT_QPA_PLATFORM=vnc             │
 │  NgxUiApp → 320x480 Qt VNC on :5900 (host 25900)                     │
 │           → lighttpd/PHP :80/:443 (host 28082/28443)                 │
 │           → WSS :9997 (host 29997)                                   │
 └──────────────────────────────────────────────────────────────────────┘
```

The kernel is Debian's `6.1.0-50-armmp` (the vendor BSP kernel has no
`mach-virt` support). The userspace is 100% vendor. The DTB is QEMU's `virt`
DTB plus an `/hde` node (`bname`, `brev`, `sernr`, `proddate`, `edpk`), because
the vendor bootloader normally injects that node at runtime.

---

## Virtual devices: interface, evidence, implementation

Confidence tags follow the repository convention: **observed** = read directly
from the vendor artifact; **inferred** = derived from surrounding evidence;
**unknown** = not established. The evidence paths are in
`docs/research/stm32-peripheral-dependencies.md` and
`docs/research/esp32-emulation-evidence.md`.

| Device / input | Linux interface the vendor opens | Evidence | Implemented here | Confidence |
|---|---|---|---|---|
| HMI display | Qt QPA `vnc` plugin; no `/dev/fb0`, no DRM/EGL | `libqvnc.so` shipped; `QVncServer created on port 5900` at runtime; QML `Window{320x480}` | `QT_QPA_PLATFORM=vnc:size=320x480:port=5900`, host forward 25900; Python RFB capture | **observed** (renders; screenshot) |
| Front-panel keys | `/sys/class/input/input1/device/gpio_value` (vendor-patched gpio-keys: write index, read 0/1) | `KeyStateDriver`; `emergencyFactoryReset.sh` uses `echo $idx > file; cat file` | Agent writes `/tmp/vg/keys`; `libvgsim.so` interposes open/read/write on that path and serves the state | **observed** device semantics; UI reaction on the calibration modal **unknown** |
| Rotary encoder | `/dev/input/event0`, blocking `read(fd,&ev,16)`, requires `type == 2` (EV_REL) | `RotaryDevice::readEvent` at `NgxUiApp:0x250bc`; negates `value` | uinput `vg-rotary` with `REL_DIAL`/`REL_X`; `/dev/input/event0` symlinked to it; `EV_KEY` codes 2–8 also emitted | **observed** writes/evdev; UI reaction **unknown** |
| Touchscreen | none in userland | no touch driver/path in the image | RFB pointer injection (`vg vnc click`) as emulation-only fallback | **unknown** (no device); VNC click accepted, UI reaction not observed |
| Load cells / ADC | `/dev/iio:device3..6` (ADC1/ADC2 DMA buffers), sysfs `buffer/*`, `scan_elements/*` | `AdcDmaReader::create`, `AdcVoltageInDriver`, `iio:device3..6` strings | sysfs trees are real files with plausible values; `/dev/iio:device*` are empty regular files. **Samples are not emulated.** | files **observed**; sample stream **stubbed/unknown** |
| ADC scale/offset | `/sys/bus/platform/devices/48003000.adc:adc@100/iio:device4/in_voltage_{scale,offset}` | live HMI log paths | files present (`1.0`, `0`) | **observed** path; values synthetic |
| Motor / AGSA | `/sys/bus/platform/drivers/stm32-one-pulse/...`, `stm32-timers/...`, `/sys/devices/platform/soc/...timer...` | `PwmOutDriver`, `PwmCounterDriver`, `AgsaDriver`; live log paths | inert tmpfs files (`prepare`, `pulse_length`, `count`, `enable`, PWM period/duty) — writes succeed and are observable | **observed** paths/writes; physical motion **not emulated** |
| AGSA / fan / USB LEDs | `/sys/class/leds/{AGSA_*,FAN1_EN,FAN2_EN,USB_EN}/brightness` | `SystemIo::FanDriver`, AGSA driver | fake LED class with `brightness`/`max_brightness`; `vg state` reports values | **observed** writes (e.g. `AGSA_DRV_MODE1=1`) |
| Backlight | `/sys/class/backlight/backlight/{brightness,max_brightness,bl_power}` | `SystemIo::BacklightDriver` | fake files; observed value `7` after boot | **observed** |
| Watchdog | `/dev/watchdog` (open + 1-byte keepalive, `"V"` on stop) | `WatchdogController` | regular file; writes observable via size | **observed** writes |
| GPIO 59/60 (ESP boot/reset) | `/sys/class/gpio/{export,gpio59,gpio60}/{direction,value}` | `S50esp`, `resetEsp.sh` | fake gpio class; observed `gpio59=1` | **observed** |
| STM32 `/dev/mem` | `/dev/mem` + `mmap` of MPC157 registers | `DeviceMemoryIo::readRegister` | `libvgsim.so` redirects to a sparse memfd and falls back to anonymous memory | **observed** (driver proceeds with zeros) |
| BSEC / CPU temp | `/sys/bus/nvmem/devices/stm32-romem0/nvmem` (dd skip=23) | `CpuTempDriver` | 128-byte fake OTP file | **observed** path; values synthetic |
| ESP control (`EspWifiConfig`) | `/dev/esps0` major 221:0, 14-byte TLV + protobuf-C `CtrlMsg` | `compose_tlv`/`parse_tlv`, `transport_pserial_open` | `/dev/esps0` → virtio-serial p1; Python server implements 101–121, events 301–304, byte-exact vectors | **observed** framing/IDs; handler payloads **inferred** |
| ESP app UART (HMI) | `/dev/ttySTM1` 576000 8N1, newline JSON (`ping`/`pong`, `versionNo`, `sdioStatus`) | `EspUartDriver::create("/dev/ttySTM1",576000,...)`; keys at `processUartData` | guest pty relayed to virtio-serial p2; JSON server replies `pong`, `versionNo=01.11`, `sdioStatus=1` | **observed** channel/keys; reply schema **inferred + verified at runtime** (`espVersionNo=01.11`, `espSdioState=1`) |
| ESP flash | `/dev/ttySTM5` (esptool, 115200/2 Mbaud) | `EspFlashDriver::setFlashParameters` | `/dev/null`; flashing **stubbed** | **observed** path; emulation intentionally omitted |
| WiFi | no Linux WiFi stack (`hostapd`/`wpa_supplicant`/`iw` absent); ESP softAP/STA via `EspWifiConfig` | `docs/ESP_ROOT_ACCESS.md`, `S50esp`, image inventory | ESP protocol state + `ethsta0`/`ethap0` dummy setup attempt; no real RF | state **observed**; real connectivity **not emulated** |
| Scale (internal / Sync) | internal load cell via ADC; external Sync is cloud/M2M, no local protocol | `docs/SCALE_INTEGRATION.md`, `docs/OPENSCALE_INTEGRATION.md` | `vg weight` updates guest state and a synthetic OpenScale `ws://:28090/snapshot`; **not consumed by the vendor HMI** | synthetic fixture; vendor path **unknown/stubbed** |
| Power / reboot | QMP; guest `/sbin/reboot`, `poweroff` | `S90app`, `ngstop`, app strings | QMP `system_reset`/`system_powerdown`; agent `reboot`/`poweroff` | **observed** |
| Web UI | lighttpd + PHP 8.4 on :80/:443, `/db/webui.crt\|key` | verified 301/200 + login title | vendor stack runs unchanged; ports forwarded | **observed** |
| WSS | TLS WebSocket server on :9997, `/db/webui.crt\|key`, `?token=` | `WebSocketConnector`; `docs/WEBSOCKET_API.md` | vendor server; `vg wss` client + token minting | **observed** `RequestDriverState`; action dispatch closes the connection (see limits) |

### What the guest agent (`vg-agent`) does

`S00vgagent` starts `/usr/sbin/vg-agent` as root before the vendor init scripts.
It:

1. Mounts tmpfs over the sysfs subtrees the HMI reads/writes, then seeds the
   exact paths the vendor drivers poll (LEDs, backlight, gpio, IIO, timers,
   nvmem). Writes are real file writes, so every hardware output becomes an
   observable value.
2. Creates a uinput device `vg-rotary` (EV_REL + EV_KEY codes 2–8), then points
   `/dev/input/event0` at it. QEMU's own `gpio-keys` power button occupies
   event0, so the symlink is required.
3. Creates a guest pty and relays it to `/dev/vport0p2`; `S50esp` symlinks
   `/dev/ttySTM1` to that pty. QSerialPort needs a real tty (termios), which a
   virtio-console port is not.
4. Creates `/dev/watchdog` and empty `/dev/iio:device3..6` nodes.
5. Serves the line protocol on `/dev/vport0p3` (`#<seq> <cmd>`), with sequence
   numbers so concurrent state polling cannot steal a reply.

---

## Emulation-only patches (disclosed)

These are applied only to the disposable image copies in `work/images/`.
They are documented as emulation aids, not as device behavior:

1. **`/db/libvgsim.so` (LD_PRELOAD)**
   - `/dev/mem` → sparse memfd; failed `mmap` → anonymous zero page.
   - `gpio_value` open/read/write semantics backed by `/tmp/vg/keys`.
   - `SystemIo::At24c16Driver::readEncryptedDevicePK()` returns an empty
     `QByteArray` (the real EDPK is provisioned per machine and cannot be
     synthesized).
   - Installs a crash handler that records PC/LR/maps to `/tmp/vg/crash.log`
     (diagnostics; it replaces the vendor handler).
2. **`NgxUiApp` at `0x1853c`** (`recoverEcPrivateKey`): `*out = NULL; return`.
   With an empty EDPK the original routine does `memcpy(dst, NULL, 68)` and
   crashes. The patch skips key recovery; the HMI continues with an
   unprovisioned identity.
3. **`libNgxUi.so` at `0x1d8b80`**
   (`EspUartDriver::processInitialCommunicationCheck`): `bx lr`. A virtual
   grinder has no ESP application firmware to update; skipping the check keeps
   the HMI out of the "Chip #2 Update aborted" screen. The ESP JSON channel
   still reports `versionNo=01.11`, `sdioStatus=1` and the HMI reports
   `espUpdateRequired=false`.
4. **`/etc/init.d/S90app` and `/bin/ngstart`**: export
   `LD_PRELOAD=/db/libvgsim.so` and `QT_QPA_PLATFORM=vnc:size=320x480:port=5900`
   (configurable via `/db/vg.conf`).
5. **`/etc/init.d/S50esp`**: replace `mknod /dev/esps0 c 221 0` + `modprobe
   esp32_sdio` with symlinks to the virtio-serial ports.
6. **DTB `/hde` node**: `bname="HEM-HSG-HMI-P01"`, `brev="210"`,
   `sernr="0123456789AB"`, `proddate`, `edpk` placeholder.

No vendor binary on disk in the repository is modified; the source images are
copied first. The `--force` build re-applies all patches.

---

## What works (verified in this environment)

- QEMU boots the vendor rootfs, init scripts, lighttpd/PHP, SWUpdate and the
  HMI. Serial log: `initramfs: switching root`, `Starting lighttpd`,
  `S90app: starting NgxUiApp with QT_QPA_PLATFORM=vnc:size=320x480:port=5900`.
- HMI paints and is captured over VNC: `320x480`, main UI with the
  **"Disc calibration missing"** alert (expected for a fresh DB; see limits).
- Web UI: `GET http://127.0.0.1:28082/` → 301; `GET
  https://127.0.0.1:28443/login.php` → 200, title `Login Hemro E64`.
- WSS: `RequestDriverState` returns the full driver state with a minted token.
  Verified fields: `espAlive=true`, `espVersionNo="01.11"`,
  `espUpdateRequired=false`, `espUartFailed=false`, `espSdioState=1`,
  `agsaStatus="Disc calibration missing"`, `grindState="Idle"`.
- ESP: the HMI's UART state reaches `EspState::Ok`; it requests and accepts
  `versionNo=01.11`; the SDIO server answers `EspWifiConfig` requests (byte
  vectors in `vg/proto.py` and `tests/test_proto.py`).
- Inputs: `vg key top --value 1` sets guest key state `10000000`; `vg rotate N`
  writes EV_REL events (16-byte records) to uinput; `vg weight 18.5` updates
  guest and scale state; `vg wifi join` updates ESP state; `vg vnc click/key`
  sends RFB input.
- Outputs: `vg screen` PNG; `vg state`/`run/state.json`; `vg logs`; fake sysfs
  values (`AGSA_DRV_MODE1=1`, `backlight=7`, growing `watchdog_bytes`);
  `vg probe`; `vg web get`.
- Power: `vg power reset` (QMP), `vg power off`, guest `reboot`.

Evidence files are in `docs/evidence/`: `status.json`, `state.json`,
`wss-driver-state.json`, `wifi-scan.txt`, `web-login.txt`, `probe.json`,
`serial-tail.txt`, `hmi-main.png`, `selftest.txt`.

The VM runs the kernel directly and has no U-Boot, so it cannot select an A/B
slot; see the "Boundaries" note below for what that means for the update and
rollback rehearsals.

## What is stubbed or unverified

| Area | Status | Consequence |
|---|---|---|
| ADC / IIO sample stream | **stubbed** — sysfs files only | The HMI shows `cpuTempDegC=-999`, `ddSensorFailed=true`; grind-by-weight cannot close the loop. A CUSE/IIO emulator or a small kernel module is required for real samples. |
| Motor / AGSA / PWM / fan tach | **inert files** | Writes are observable, but no physical motion or tacho feedback. `fan1Duty=-1`, `agsaHallSensorCounts=0`. |
| WSS action dispatch | **not accepted** in this image | `GrinderAction` / `Rc*` requests close the connection (registry/development-version/token policy). Read-only `RequestDriverState` works. Physical inputs are the documented path. |
| Front-panel input → UI reaction | **device-level observed, UI unknown** | Key state and evdev events are delivered, but the "Disc calibration missing" modal did not visibly change in tests. Calibration data, not the input path, is the likely gate. |
| Touchscreen | **absent** | No touch driver/path in the vendor userland; RFB pointer/key injection is emulation-only and its UI effect is unverified. |
| ESP firmware flashing | **stubbed** | `/dev/ttySTM5` is `/dev/null`; `EspFlashApp`/`EspEraseFlash` actions cannot flash. |
| WiFi RF / netdev | **synthetic** | ESP state changes are host-side; no real AP association or DHCP. `ethsta0`/`ethap0` setup is best-effort. |
| Sync Scale / cloud | **synthetic fixture** | OpenScale `ws://127.0.0.1:28090/snapshot` is a developer fixture; the vendor HMI does not consume it (the vendor path is cloud/M2M). |
| HMI calibration alert | **data state** | Fresh `HsgSqlite.db` has no disc calibration; the HMI blocks on the alert. Seed a calibrated DB or acknowledge it to reach the grind screen. |
| EDPK / device identity | **patched** | Per-machine key is not synthesizable; the HMI runs with an unprovisioned identity. TLS/WSS uses `/db/webui.crt\|key`. |

## File layout

```
/tmp/virtual-grinder/
├── vg                         # CLI entry point
├── README.md
├── vgrinder/
│   ├── cli.py                 # argparse commands
│   ├── daemon.py              # control daemon (unix socket + HTTP dashboard)
│   ├── vm.py                  # QEMU lifecycle, QMP, serial
│   ├── build.py               # image/initrd/DTB builder + patches
│   ├── channels.py            # virtio-serial line channels (sequenced)
│   ├── proto.py               # ESP TLV + protobuf-C
│   ├── esp.py                 # virtual ESP32 control server
│   ├── espjson.py             # /dev/ttySTM1 JSON server
│   ├── ws.py                  # WebSocket client + OpenScale fixture
│   ├── vnc.py                 # RFB capture/input + PNG writer
│   ├── http_probe.py          # HTTP(S)/REST probes
│   └── paths.py               # layout, ports, environment
├── guest/
│   ├── vg-agent.c             # guest device agent (static armhf)
│   ├── vg-sim.c               # LD_PRELOAD shim (mem/gpio/EDPK/crash)
│   ├── build.sh               # docker arm32v7 builds
│   └── build/{vg-agent,libvgsim.so}
├── tests/
│   ├── test_proto.py          # protocol vectors
│   └── test_boot_scr.py       # slot/ustate harness checks
├── docs/evidence/             # captured status, logs, screenshots
├── work/images/               # generated kernel/initrd/dtb/rootfs/app/db
├── work/screens/              # VNC captures
├── work/serial.log            # serial console
└── run/                       # sockets, pid, state.json
```

## Rebuilding after a change

Guest C changes:

```sh
./guest/build.sh
rm -f work/images/rootfs.ext2 work/images/db.ext4
./vg build
./vg down && ./vg up
```

Host Python changes only need `./vg down && ./vg up` (the daemon imports the
package). Full rebuild: `./vg build --force` (copies the vendor images again;
~1 minute). Vendor inputs are read from
`/Users/A92615428/git/GitHub/MaxRink/mahlkoenig-e64ws-local-research/.tools/`;
override with `VG_REPO`/`E64_FW_DIR`/`E64_QEMU_DIR`.

## Troubleshooting

- **`vg: daemon exited`** — read `work/daemon.out` and `work/qemu.log`. A port
  collision is the usual cause; override `VG_*_PORT`.
- **Qt VNC capture times out** — the Qt VNC plugin accepts one client at a
  time; close other VNC viewers and retry. The HMI takes 60–80 s to start.
- **`firmwareUpdateRequired` / update screen** — the app image must contain the
  patched `libNgxUi.so` (`0x1d8b80: bx lr`). Re-run `./vg build` after removing
  `work/images/app.ext4`.
- **`no reply from agent`** — the guest agent may be blocked in a long shell
  command. Avoid reading `/dev/console` (`tail -f`) in `vg shell`; use
  `vg logs -f` on the host instead.
- **HMI alert** — expected on a fresh DB. The discard calibration value lives
  in `HsgSqlite.db`/`HsgConfig.json`; seed a calibrated database to reach the
  grind screen.

## Recovery rehearsals

`rehearse_vm_recovery.sh` runs the R2/R4/R8 recovery procedures from
[`docs/evidence/recovery/`](../../docs/evidence/recovery/README.md) against a
built VM and writes their transcripts. It owns the VM lifecycle:

```sh
VG_ROOT=/tmp/vg-recovery sh tools/virtual-grinder/rehearse_vm_recovery.sh /tmp/out
```

It expects the kernel to be `-kernel`-booted, so the U-Boot half of each
procedure is recorded as "not exercised" and the Linux half (`fw_setenv`,
`fw_printenv`, the real `S30verifyupdate`) runs for real. The procedure-level
checks that need no VM are in `tests/rehearse_recovery.sh`, registered in the
`boot-script` suite.

## Boundaries

This is a development and analysis environment. It does not reproduce the
STM32MP1 boot chain, SPL, secure boot, eFuses, real motor control or RF. It
never contacts Mahlkönig services. The emulation-only patches are clearly
marked and only apply to disposable copies under `work/`.
