# e64ctl — clean-room control service for the Mahlkönig E64 WS

A host-runnable reimplementation of the **vendor control logic** of the
HEM-HSG-HMI-S01 HMI (`libNgxUi.so` in firmware V01.16-24), not of its Qt UI.
It exposes the same three machine-facing surfaces:

| Surface | Vendor | This service |
|---|---|---|
| WebSocket command channel | `wss://<host>:9997` (Qt `QWebSocketServer`) | `ws://` or `wss://` :9997, same envelopes and gates |
| REST/HTTP | lighttpd + PHP 8.4 `rest_api.php` | stdlib HTTP server, same 13 routes |
| ESP32 control | `/dev/esps0` TLV+protobuf, `/dev/ttySTM1` JSON | same protocols over a pty/unix socket, built-in ESP simulator |

State lives in a SQLite database and JSON files with the vendor's names and
formats where they matter for behaviour.

## Quick start

```sh
cd /tmp/reimpl

# 1. run the service (dev gate open, ESP simulated in-process)
PYTHONPATH=src python3 -m e64ctl \
    --state-dir /tmp/e64ctl --dev-mode \
    --wss-port 9997 --http-port 8080

# 2. mint a WebSocket token the way the PHP login does
curl -s -i -X POST http://127.0.0.1:8080/rest_api/login \
     -d '{"userRole":"Owner","password":""}' | grep -i authorization

# 3. talk to it (any WebSocket client)
python3 - <<'PY'
from tests.wsclient import WsClient
tok = "..."                      # from the Authorization header
c = WsClient(port=9997, token=tok).connect()
print(c.request({"type": "RequestDriverState", "msgId": 1}))
print(c.request({"type": "GrinderAction", "msgId": 2,
                 "data": {"actionType": "EspReset"}}))
PY
```

Useful flags:

```
--dev-mode / --no-dev-mode   force the /etc/issue gate (default: probe it)
--issue-file PATH            file used by the gate probe
--tls --certfile --keyfile   serve wss:// (self-signed cert is generated)
--esp-device PATH|unix:PATH  real /dev/esps0 (default: in-process simulator)
--esp-json-device PATH       real /dev/ttySTM1
--no-esp-sim                 do not start the simulator
--state-dir DIR              database + JSON files (default /tmp/e64ctl)
--print-registry             dump the 52 command records as JSON
```

## Tests

```sh
cd /tmp/reimpl
python3 -m unittest discover -s tests -p "test_*.py"     # 124 tests
```

| File | Covers |
|---|---|
| `tests/test_registry_dispatch.py` | 52 records, gates, envelopes, token/dev policy |
| `tests/test_esp.py` | TLV framing, byte-exact published vectors, all 21 request/response pairs, events, limits, JSON UART |
| `tests/test_rest.py` | 13 routes, auth matrix, error strings, downloads |
| `tests/test_state.py` | grind FSM, AGSA travel/timeout, fan clamp, endurance, ESP liveness |
| `tests/test_e2e_wss.py` | handshake, token reuse, close-on-reject, Qt JSON wire format |
| `tests/test_tokens_json_persistence.py` | token files, Qt JSON formatting, DB rows, CSV/ZIP export |
| `tests/test_capture_parity.py` | field set/types/key order match the recorded vendor reply in `tests/data/wss-driver-state.json` |
| `tests/test_live_profile.py` | sanitized 2026-11-18 live settings, used-device state, DB representation, redactions |
| `tests/test_weight_trace.py` | captured weight-trace replay, interpolation and finish result |

## Assumptions and sensor simulator

`src/e64ctl/assumptions.py` is the evidence-linked HSG profile ledger. It
encodes the one-NTC profile, the locked DD store, the fan calibration/RPM
split, the missing touch path and the explicitly low-confidence A1330 PWM
angle hypothesis. Print it with:

```sh
PYTHONPATH=src python3 -m e64ctl.assumptions
```

Tests: `tests/test_assumptions.py` (10 tests). See
[docs/RE_ASSUMPTIONS.md](../../docs/RE_ASSUMPTIONS.md).

### Sanitized live profile (2026-11-18)

`src/e64ctl/live_profile.py` holds the 27 `settings` rows and the read-only
sensor values from a used E64 WS. It is evidence, not a factory default:

```python
from e64ctl.live_profile import apply_live_hsg_profile, seed_live_settings
apply_live_hsg_profile(state)      # Completed wizard, 0.53696 g overshoot,
                                   # ddValueDum=854, NTC/fan/C0 values, etc.
seed_live_settings(persistence)    # the exact vendor DB key set
```

The profile includes the live `RequestDriverState` values (`ddValueDum=854`,
`ntc1TempDegC=34.32`, NTC2 absent, fan tachos 0, CPU temp `-88.59`, idle weight
offset `-0.52 g`) and the per-device load-cell
`C0=2393.920401128173` / `C1=-0.07834534628643058`.
`Wifi.StaSsid` and `Wifi.StaPassword` are deliberately empty; the live values
were redacted.

`save_config()` now converts back to the vendor database form
(`Grinding.OvershootWeight` in µg, `Standby.ActivationTimeSec` in whole seconds,
booleans as `true`/`false`), and `add_grind()` stores the 36-character
`grind_uuid` as the BLOB storage class seen in the live database.
`RequestConfigManagerSettings` reports overshoot from the state field and
overlays profile settings. The pristine profile still reports `0.600000g`.

Start the service with the live profile and a captured grind trace:

```sh
PYTHONPATH=src python3 -m e64ctl --state-dir /tmp/e64-live \
    --live-profile --weight-trace captures/grind-20261118-01.jsonl
```

The first capture sample also seeds the read-only device fields it contains
(`ddValueDum`, NTC1/NTC2, fan tacho/duty, overshoot, `configId`, setup state),
so the simulator follows the current machine instead of a stale profile.
`tools/capture_trace.py CAPTURE.jsonl` prints a short trace summary. See
[LIVE_VALIDATION_2026-11-18.md](../../docs/LIVE_VALIDATION_2026-11-18.md).

## Scenario runner (differential harness)

The service speaks the `/tmp/equiv` scenario format through
`tools/scenario.py`, and `tools/guest_shim.py` answers the guest-shell steps
(sysfs, `/db` files, `sqlite3`, `EspWifiConfig -u`) from the state directory.

```sh
# terminal 1
python3 tools/provision_owner.py --state-dir /tmp/e64-run1 --reset
PYTHONPATH=src python3 -m e64ctl --state-dir /tmp/e64-run1 --dev-mode \
    --wss-port 19997 --http-port 18080

# terminal 2 — run any /tmp/equiv scenario
PYTHONPATH=src python3 tools/scenario.py \
    --scenario /tmp/equiv/scenarios/02_readonly.json \
    --out runs/reimpl/02_readonly.jsonl \
    --wss ws://127.0.0.1:19997 --http http://127.0.0.1:18080 \
    --state-dir /tmp/e64-run1
```

Recorded transcripts for the vendor scenarios are in `runs/reimpl/`
(`01`–`05`, `07`; `06` needs ESP fault injection that is covered in-process by
`tests/test_esp.py`).

To run the real harness against this service, copy
`integration/reimpl_target.json` to `/tmp/equiv/targets/reimpl.json` and start
the service on ports 39998/38080 first.

## Reuse from the repository

| Repository piece | Use here |
|---|---|
| `tools/esp_stub.py` | validated TLV framing reference; `src/e64ctl/esp.py` re-implements it with the full protobuf table and byte-exactness tests |
| `tools/esp_json_stub.py` | JSON UART message set (`ping`/`pong`, `RequestVersion`, `RequestSdioStatus`); re-implemented in `esp_bridge.py` including `StartFunction` |
| `tools/vendor_pwhash.py` | password verifier algorithm; same loop in `rest.py` (`pwhash`) |
| `tools/virtual-grinder` | ports, `/etc/issue` profiles and the guest command surface used to shape `guest_shim.py` |
| `docs/API_REGISTRY.md` | the 52-row table transcribed into `registry.py` |
| `docs/ESP_PROTOBUF_SCHEMA.md` | protobuf field numbers/types in `esp.py` |
| `docs/bible/protocols.md`, `docs/REST_API.md` | REST route semantics in `rest.py` |
| `docs/SQLITE_SCHEMA.md` | table/column names in `persistence.py` |

Everything else (dispatcher, state machine, persistence, transports, tests) is
new code written from the decompilation and the documents; no vendor binary is
executed at runtime.

## Layout

```
src/e64ctl/
  registry.py   52 CommandDef records (type, action, log, dev, token, callback)
  dispatch.py   handleMessage / handleFoundMessage / validateTokenWithDef
  handlers.py   the 52 callbacks and their side effects
  state.py      driver state, grind FSM, AGSA, fans, ESP, WiFi, config
  jsonfmt.py    Qt QJsonDocument::toJson() compatible serialiser
  tokens.py     /tmp/tok_<token> files and in-memory expiry
  wss.py        WebSocket server (:9997) and close-on-reject behaviour
  rest.py       13 REST routes with PHP session semantics
  esp.py        TLV + protobuf codec, HMI client, ESP simulator
  esp_bridge.py protobuf + JSON UART bridge
  persistence.py SQLite schema, JSON files, CSV/ZIP export
  main.py       CLI and service wiring
tools/
  scenario.py        /tmp/equiv scenario runner (JSONL transcripts)
  guest_shim.py      guest-shell emulation for scenario steps
  target_adapter.py  argv adapter for the harness 'direct' target
  provision_owner.py fixture owner password (matches vendor reset_cmd)
  elfread.py         analysis helper (read strings by vaddr)
integration/reimpl_target.json
runs/reimpl/*.jsonl
```
