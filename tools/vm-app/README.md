# Virtual Grinder for macOS

A native SwiftUI control surface for the virtual E64 WS. It shows the vendor HMI
**rotated to the real 480×320 landscape orientation**, puts the two round panel
buttons on the left and the rotary knob on the right, and exposes the full
daemon state and serial log.

## Build

```sh
cd tools/vm-app
./build_app.sh          # → dist/VirtualGrinder.app
open dist/VirtualGrinder.app
```

The build uses the command-line Swift toolchain; Xcode is not required. The app
is ad-hoc signed and not sandboxed, so it can talk to the local daemon.

## Run against the VM

```sh
# terminal 1 — start the vendor userspace
tools/virtual-grinder/vg up

# terminal 2 — control URL of the daemon (default 28765)
VG_CONTROL_URL=http://127.0.0.1:28765 open dist/VirtualGrinder.app
```

If the daemon uses a non-default port, set `VG_CONTROL_URL` accordingly. The
app talks only to `127.0.0.1`.

## What it shows

| Pane | Content |
|---|---|
| HMI | live framebuffer, rotated 90° clockwise to 480×320; click maps back to the 320×480 VNC coordinates. Two round buttons sit on the left and a draggable rotary knob on the right, matching the real panel. |
| Left panel | Top and Bottom round buttons (tap; long-press for the long event) |
| Right panel | Rotary knob — drag clockwise/counter-clockwise for `REL_DIAL` ticks (continuous, one tick per 12 pt), click, long-press, double-click; plus ±1/±10 buttons and a last-input readout |
| Controls | full input-event matrix, load-cell simulation, Wi-Fi, ESP event, grind, power, WSS, VNC key |
| Machine | labelled schematic of the grinder with live weight, basket tare, rate and grind state |
| Internal state | complete `/api/state` JSON (VM, guest agent, ESP, scale, grinder) |
| Logs | serial console (last 120 lines) |

## Dismissing the first-boot alerts

The vendor HMI starts with two blocking alerts (`Disc calibration missing`,
then `Security data missing`). Press **Dismiss alerts**; it sends the panel
sequence three times and leaves the main screen. Input does not reach the main
UI until those alerts are acknowledged.

## Input model

Every panel input has five levels: **Tap**, **Press**, **Release**, **Long**
(900 ms) and **Double**. Top/Bottom/Rotary use the vendor WSS `Rc*` actions when
the VM is in development mode; DDD/Hopper/AGSA use the GPIO key line. The app
shows the raw HMI, so the two first-boot vendor alerts must be acknowledged
before the main screen accepts input.

## Load cell

The daemon and app expose:

- base/tare weight (basket detection),
- grind rate in g/s,
- start/stop ramp, automatic with `grind start`,
- live weight fed to `/tmp/vg/weight` and the OpenScale fixture.

The app displays the live value in the Machine schematic. What the vendor HMI
itself displays still depends on the ADC buffer emulation; the audit and gaps
are in [docs/VM_INPUT_AND_CALIBRATION.md](../../docs/VM_INPUT_AND_CALIBRATION.md).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `VG_CONTROL_URL` | `http://127.0.0.1:28765` | daemon control endpoint |
| `VG_APP_TAB` | `0` | start tab: 0 Controls, 1 Machine, 2 State, 3 Logs |
| `VG_APP_AUTOSNAP` | unset | write a PNG of the window after 6 s (for docs/tests) |

Screenshots: `docs/assets/vm-app-controls.png`, `vm-app-machine.png`,
`vm-app-weight.png`, `vm-app-logs.png`.

## Limits

This is a development fixture, not the vendor HMI and not a hardware model.
The schematic is illustrative; the vendor screen is the authority for UI
behaviour. The panel buttons are wired to the same daemon commands as `vg`, so
they exercise the same input path.
