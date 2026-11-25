# E64 Local — iOS app

A **cloud-free, LAN-only** iOS app for the owner of an E64 WS / NG2 grinder.
No account, no telemetry, no analytics, no vendor cloud, and no host other than
the device the owner enters.

The app reads the [Local Owner HTTP API](../docs/LOCAL_API.md) —
[`docs/openapi/local-api.yaml`](../docs/openapi/local-api.yaml) — and can install
it on a development-image grinder with one click.

> Owner-authorized use only. The app talks to one grinder on your own network.

## What it does

| Screen | Routes |
|---|---|
| **Setup** | `GET /login.php` (probe), `POST /rest_api/capabilities` (verify), one-click install |
| **Dashboard** | `capabilities`, `machine` (model, firmware, hashed serial) |
| **Logs** | `grind_log`, `service_log`, `alert_log` with `limit`/`offset`/`since`/`until` |
| **Data** | `recipes`, `portafilters`, `settings`, `config`, `file` (allowlist only) |
| **About & Security** | owner-token model, dev-image requirement, no-cloud statement |

The app has no control **screen**. `GrinderCore` does carry an action-layer
client (see [Action layer](#action-layer-gated-control-surface) below), but no
view uses it yet, so nothing in the running app can start a grind, calibrate or
change a setting. `ws_token` is deliberately absent from both clients because it
mints a credential that authorises WSS commands.

Setup installs the module's root-owned **action runner** as well, but it writes
no `/db/e64local/actions.json` policy. The module fails every action route closed
while that policy is absent: on a grinder set up by this app the runner is inert,
`capabilities` reports `features.actions: false`, and every action call is
refused 403 before any parameter is parsed. Enabling actions is an explicit owner
decision made with `e64root`, not here.

## Layout

```
apps/ios/
├── GrinderCore/                  Swift package (Foundation + Apple frameworks only)
│   ├── Sources/GrinderCore/
│   │   ├── HTTP/                 Endpoint, form encoding, TLS pinning, transport, isolation
│   │   ├── Models/               Response shapes, action catalog, log query, file allowlist
│   │   ├── Auth/                 Owner token + Keychain store, vendor session
│   │   ├── Client/               LocalAPI (read-only) + ActionClient (gated action routes)
│   │   ├── Setup/                FW-01 port: planner, runner, device prober
│   │   ├── State/                Device configuration, bundled digests
│   │   └── Resources/            rest_api_dev.php + e64local_action_run.php
│   │                             (byte-identical to ondevice/)
│   ├── Sources/GrinderCoreChecksKit/  The checks, written once
│   ├── Sources/GrinderCoreChecks/     Portable harness (no XCTest)
│   └── Tests/GrinderCoreTests/        XCTest wrapper over the same checks
├── GrinderApp/                   SwiftUI sources (AppModel, views, Info.plist)
├── GrinderAppTests/              App-bundle tests (module digest, ATS shape)
├── project.yml                   XcodeGen manifest
└── scripts/verify-app-sources.sh
```

## Auth (exact)

Every local API request carries **both** factors:

1. **Vendor session** — `POST /login.php` with `login=1`, `userRole=Owner` and the
   Owner password; the `PHPSESSID` cookie is kept and sent as `Cookie`. Cookies
   are handled explicitly: nothing goes into a shared cookie store.
2. **Owner token** — sent as `X-E64-Local-Token`. The token is generated on the
   phone (`SecRandomCopyBytes`, 32 bytes as 64 hex characters), stored in the
   **Keychain** (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, not synced), and
   never logged. `OwnerToken`'s `description`/`debugDescription` are redacted, so
   even an accidental interpolation cannot print it.

The app never falls back to the JSON `token` body key while it has a token, so
the secret is not duplicated in a request body.

## Self-signed TLS

The device certificate is self-signed, and ATS does not validate it silently.

- The default policy is normal system validation.
- On the Setup screen the certificate is shown (subject and SHA-256) and the
  owner can opt in **for that device only**. Opting in records the leaf
  fingerprint and pins it: `URLSessionTransport` accepts the connection only when
  that exact certificate is presented, and cancels on anything else.
- `Info.plist` contains `NSAppTransportSecurity → NSAllowsLocalNetworking` only.
  There is no `NSAllowsArbitraryLoads` and no per-domain exception.

The target must be on the local network. A numeric address must be
private/link-local/loopback, and a host name must resolve only to such
addresses; anything that resolves to the public internet is refused before a
request is sent (`NetworkIsolation`).

## One-click setup (FW-01, no ESP writes)

`GrinderCore/Setup` is a port of
[`tools/e64root/transports.py`](../../tools/e64root/transports.py) and
`e64root api deploy`:

1. `POST /login.php` with `userRole = "x';<command>;#"` — the same quote-closing
   injection e64root uses, percent-encoded so the form cannot break apart.
2. The module and the action runner are base64-encoded and appended in
   **~40 000-character chunks** with
   `printf '%s' '<chunk>' >> /tmp/e64local.b64` (the runner goes to
   `/tmp/e64local-runner.b64`).
3. One root script decodes them and installs:
   - `/db/e64local` (0711)
   - `/db/e64local/token` (0600, `www-data:www-data`), 64 hex characters
   - `/usr/local/www/dev/rest_api_dev.php` (0644)
   - `/usr/local/bin/e64local-action-run` (0755, `root:root`, `php -l` checked)
   - then deletes both staging files
   - and deliberately **does not** write `/db/e64local/actions.json`, so no
     action route becomes reachable
4. **Verification:** the app signs in to the vendor UI, then calls
   `POST /rest_api/capabilities` with **both** factors. Setup succeeds only on a
   valid `e64local-api-v1` response for every route the app uses; the device is
   not saved until that handshake passes.

The exact commands are shown on a confirmation screen and must be acknowledged
before the install button is enabled. The owner token appears there as a
placeholder: it is generated on the phone, and a screenshot, a screen recording
or the app switcher's snapshot must not capture the second factor.

**Not touched:** ESP, firmware, NVS, bootloader, eFuses. No flash, no upload, no
`ttySTM5`. A check asserts the install and revert scripts never mention them.

Both files are bundled as resources and their SHA-256s are pinned in
`BundledModule.expectedSHA256` and `BundledActionRunner.expectedSHA256`; the app
refuses to install a file whose digest does not match. Checks compare each
bundled copy with `ondevice/rest_api_dev.php` and
`ondevice/e64local_action_run.php`.

## Action layer (gated control surface)

`GrinderCore/Client/ActionClient.swift` is the client for the five meta routes in
[`docs/LOCAL_API.md` §12](../../docs/LOCAL_API.md): `action_prepare`,
`action_execute`, `action_status`, `action_cancel`, `action_audit`. An action
identifier such as `action_grind_start_gbw` is a **value of the `route` field**,
never a path, and no request here touches the ESP, firmware, NVS or bootloader.

What the client enforces, each pinned by a check:

| Rule | Behaviour |
|---|---|
| Confirm token | Returned by `prepare`, kept in the actor's memory, sent once by `execute`, then dropped. `PreparedAction` has **no token field**, `ConfirmToken` is internal with a redacted description, so a view, a log line or an error message cannot render one. A check asserts the token appears in exactly one request body — the execute — and in no description, error or user message |
| Both factors | An action request without the owner token and the vendor session is refused before anything is sent (401-shaped and 403-shaped) |
| Fail closed without a catalog | `prepare` refuses with `catalogUnavailable` until `capabilities.data.actions` has been read: without it the app cannot tell a dispatchable route from one the gate would refuse |
| Destructive gate | Checked at `prepare` against the device's own `actionRoutes`/`blocked`, and **again at `execute`**, because the module re-reads its policy on every request |
| Reboot binding | A 409 that mentions a reboot or a missing boot id becomes `.rebooted` and spends the token: it can never execute. A record without a boot id is the same failure (`_actionBootMatchesRecord`) |
| Replay/expiry | Any other 409 is `.conflict`, terminal, and the token is dropped |
| Rate limit | 429 reads `retryAfter` from the **top level** of the body (not `data`) into `.rateLimited(retryAfterSeconds:)`, and `retryAfterSeconds()` counts the wait down. The token is kept: the module refuses before it claims the record |
| Unavailable | 422 prefixed `action unavailable:` is `.unavailable`; other 422s are `.invalidParameters`. Neither is retried |
| 503 | `.runnerUnavailable`, retriable, token kept: the module refuses before claiming the record |
| Started and failed | A failed execute carries the record in `data`; that surfaces as `.executionFailed(outcome:code:message:)`, which is the difference between "refused before actuation" and "ran and failed" |
| Auditing | `action_audit` is read through `ActionAuditPage`. Rows hold the canonical `paramsHash` and never a parameter value — a check reads the row's stored property names and fails if a `params` field ever appears |

`capabilities.data.actions` (the catalog, the effective bounds and the TTLs) is
decoded by `ActionCatalog` in `Models/ActionModels.swift`; that document is the
one read shape the read-only client did not model. `action_status` and
`action_audit` are read-only routes and are modelled alongside it.

**Not proven:** this client has never run against a grinder, and no Swift code
here has run against the PHP module either. Every check replays canned responses
whose shapes and messages are copied from `ondevice/rest_api_dev.php`, so the
checks prove the client matches the module's source, not that the module behaves
that way on hardware. The one live peer is
[`GrinderCoreE2E`](#end-to-end-suite-live-simulator), which runs this client
against `tools/e64ws_simulator.py` over a real `URLSession` with the fixture's
gate open: the full prepare → execute → status → audit protocol, a
cancel-before-execute and the destructive refusal are no longer canned bytes. It
is still the fixture, not a grinder, so actuation itself remains unproven.

The module's own action routes are exercised offline by other suites — not by
this package: `tools/e64root/tests/test_local_api.py` runs
`ondevice/rest_api_dev.php` through
`tools/e64root/tests/fixtures/local_api/harness.php` (including the 429 with
`retryAfter`), and `tools/e64root/tests/test_local_actions.py` mirrors the gate,
the destructive gate and the reboot binding in `tools/e64local_actions.py`. What
would settle the real thing is the on-device runbook,
[`docs/ACTION_LAYER_BENCH.md`](../../docs/ACTION_LAYER_BENCH.md); steps 9 to 11 of
it (reboot binding, rate limiting, destructive gate) are exactly the paths the
Swift client has only seen as canned bytes.

**No SwiftUI.** The action layer has no screen. A SwiftUI view cannot be
compiled on this host (no iOS SDK, and `SwiftUI`'s macros ship only inside
Xcode), so the app target is deliberately unchanged: `AppModel` and
`Screens/*.swift` are exactly as they were, and nothing yet constructs an
`ActionClient`.

## End-to-end suite (live simulator)

`Sources/GrinderCoreE2E` is the only target here that needs a peer. It drives the
**real** `LocalAPI` and `ActionClient` over a real `URLSession` against
[`tools/e64ws_simulator.py`](../../tools/e64ws_simulator.py), so it proves the
HTTP half the offline checks stub out: envelopes, headers, the `PHPSESSID`
cookie, status codes, JSON shapes, the redaction pass and the action gate.

```sh
cd apps/ios/GrinderCore
swift run GrinderCoreE2E
```

The fixture has to be running first, **with its action gate open**, and with an
owner token it will accept. It serves the eleven read routes and the five
`action_*` meta routes, with the REST password `sim-password`:

```sh
TOKEN=$(openssl rand -hex 32)
# .venv/bin/python, because the simulator imports websockets
.venv/bin/python tools/e64ws_simulator.py --http-port 8787 --enable-actions \
  --api-token "$TOKEN"
```

`--api-token` is the token the local API expects. It must be the 64-hex shape a
device writes, because the app's `OwnerToken` accepts nothing else — and the
point of this suite is that the client sends the token it holds, not a
stand-in. `--token` is a different flag: it sets the **WSS** fixture token that
the login response hands back as `Authorization: Bearer …`.

`--enable-actions` is what a shipped image does **not** do: without it the
fixture mirrors a grinder with no action policy and every meta route answers 403.
The suite reads `capabilities.data.actions` and asserts whichever state it is
given (241 checks with the gate open, 191 with it shut), so a plain
`swift run GrinderCoreE2E` against a gate-less fixture still passes — it just
proves the refusal instead of the protocol. `--enable-destructive-actions` is
deliberately **not** passed: the second gate staying shut is what the destructive
refusal is about, and the suite fails loudly if a peer opens it.

| Variable | Meaning |
|---|---|
| `E64_E2E_BASE_URL` | `http://host:port` of the fixture, no trailing slash. **Unset or empty → the suite skips**: it prints `E2E SKIP (no E64_E2E_BASE_URL)` and runs nothing, exit 0 |
| `E64_E2E_TOKEN` | The owner token to send. Required when the base URL is set, must equal `--api-token`, and must be 64 hex characters |
| `E64_E2E_VERBOSE` | `1`/`true`/`yes` prints one line per check on stderr. stdout stays the summary line |

One summary line, always: `E2E PASS <n>` with the number of checks performed, or
`E2E FAIL <detail>` on stderr with exit 1. The failure detail is scrubbed of the
token and of every session id before it is written.

```sh
# with the fixture from the block above already running, and the same $TOKEN
E64_E2E_BASE_URL=http://127.0.0.1:8787 E64_E2E_TOKEN="$TOKEN" \
  swift run GrinderCoreE2E
# E2E PASS 241
```

What it covers, all of it over the wire:

- **Session** — a wrong password is refused, the Owner login returns the
  `PHPSESSID` the clients parse with `CookieHeader`, `check_session` and
  `update_session` accept the cookie alone, a request without it is 401, logout
  really ends the session, and the reads work again after signing back in.
- **Read routes** — `capabilities`, `machine`, `grind_log`, `service_log`,
  `alert_log`, `portafilters`, `recipes`, `settings`, `config`, `file`: route
  lists and limits, `limit`/`offset`/`since` normalisation and clamping, strings
  where the database has integers, the redaction predicate for settings, config,
  log text and `/log` files, the file allowlist refusing a path client-side (no
  request), and the serial arriving only as its SHA-256.
- **Both factors** — every data and action request carried
  `X-E64-Local-Token` and the cookie. A read with only the session, and one with
  only the token, are each refused 401 by the fixture; the token refusal is the
  module's envelope and surfaces as `LocalAPIError(401, "owner token required")`,
  while the fixture's *session* refusal is a bare `{"error": …}` with no
  `errorCode`, so the client reports a decode failure rather than a typed 401. That
  is a real difference between the fixture and `ondevice/rest_api_dev.php`, and the
  suite asserts both halves instead of papering over it.
- **Action layer, gate open** — `capabilities.data.actions` reports
  `enabled: true`, `destructiveEnabled: false`, no closed-gate reason and the
  policy it publishes (version, per-risk confirm-token TTLs, audit file and cap,
  effective bounds, rate buckets); the catalog still lists all 33 entries with
  the seven destructive ones `blocked`, and 18 routes are dispatchable. Then the
  real protocol on a non-destructive actuator (`action_grind_stop`):
  `prepare` → `execute` → `status` → `audit` — the confirm token is held only by
  the client, spent once, and never handed back in `PreparedAction`; the outcome
  reports `completed` with the device's `Stop` command; the stored record has
  prepared/started/finished timestamps; the audit trail holds prepare, execute
  and result rows with the canonical `paramsHash` (never the parameters), the
  requestId and the client address, and pages two-at-a-time. Then
  **cancel before execute** on a second prepared action: `cancel` answers
  `cancelled` with `stopSent: false`, the token is dropped so `execute` is
  refused locally, `status` shows `cancelled` with no start, and the audit row
  says `cancelled_before_execute`. Finally the **destructive gate**: with
  `destructiveEnabled: false`, `prepare` of `action_logs_clear` is refused before
  a byte is sent with the catalog's own `blocked` text, and the fixture refuses
  the same route on the wire with `403` and that message — the *second* gate's,
  not the first's.
- **Action layer, gate shut** (a fixture started without `--enable-actions`, the
  state a shipped image and a grinder set up by this app are in) — all five meta
  routes refused 403: `prepare`/`execute` by the client before sending,
  `status`/`cancel`/`audit` by the device and classified by the client's typed
  `ActionError` mapping, plus the catalog's `actionRoutes` being empty and its
  reason naming the missing policy file.
- **Token hygiene** — the token appears in exactly one place (the
  `X-E64-Local-Token` header), never in a body or a URL, and never in an error
  the suite rendered; `OwnerToken` and `VendorSession` descriptions are
  redacted, and the shipped `LogRedaction` plus the suite's own scrubber remove
  it from a secret-shaped line.

**Not proven by this suite:**

- **No device.** The peer is the fixture. Nothing here has run against a grinder,
  and no Swift code here has run against the PHP module
  (`ondevice/rest_api_dev.php`) either — the fixture is an in-memory mirror of
  it. TLS, the self-signed certificate pin and `NSAllowsLocalNetworking` are
  untouched: the fixture is plain `http://127.0.0.1`, which is why this target
  carries its own transport instead of `URLSessionTransport` (that one requires
  `https` and pins the device certificate — a property this suite deliberately
  cannot weaken).
- **No SwiftUI render.** No view is constructed, no screen is shown. The app
  target is not involved at all, and `swift build` here cannot compile SwiftUI.
- **A cancel while an action is running.** The fixture's `execute` applies its
  steps synchronously, so nothing is ever still `executing` when a second request
  arrives. The interrupt path (`cancel` → `cancelling`, `stopSent: true`) and the
  `cancelRequested` flag are covered only by the offline checks' canned bytes.
- **Rate limiting, the reboot binding, and 429/503/504.** Also still
  canned-bytes-only: the fixture's clock and boot id do not move during a run, and
  its runner never refuses, so those five `ActionError` cases cannot be provoked
  through this peer.
- **The destructive path with the second gate open.** Deliberately: the suite
  asserts the *refusal*, and `--enable-destructive-actions` is not part of the
  harness. Nothing here has ever executed `action_logs_clear` or any calibration
  action.
- **Real actuation.** A completed `action_grind_stop` proves the protocol, not
  that a grinder stops: the fixture records the command instead of moving a
  motor. The bench runbook,
  [`docs/ACTION_LAYER_BENCH.md`](../../docs/ACTION_LAYER_BENCH.md), is what would
  settle that.

`tools/e2e/run_apps_e2e.py` starts the fixture on free loopback ports, exports
both variables and runs this suite (and the Android one) through the same
contract.

## Building

### GrinderCore (works without Xcode)

```sh
cd apps/ios/GrinderCore
swift run GrinderCoreChecks      # portable: runs every check, exit 0 on success
```

The harness prints one `ok`/`FAIL` line per case and a final count (136 at the
time of writing). Both the count and the *set* of case names are asserted:
`Checks+Generated.swift` pins `generatedCaseCount`, so adding a case without
regenerating the XCTest list fails the run.

With Xcode installed, the same cases also run as XCTest — one method per case:

```sh
cd apps/ios/GrinderCore
swift test
```

`Tests/GrinderCoreTests/GeneratedCases.swift` is generated by
`GrinderCore/scripts/generate-xctest-cases.py`, one XCTest method per case. It
records the case count **and** every case name; `testNothingIsStale` and the
portable `generated:` check both fail if either drifts, so the generated file
cannot silently go stale even on a host without XCTest. The case bodies live in
`Sources/GrinderCoreChecksKit`, so both harnesses cover exactly the same cases.

**On this machine, `swift test` builds the XCTest target and exits 0, but runs
0 tests:** the Command Line Tools install has no XCTest module or runtime (no
Xcode), so the XCTest target is filtered out before execution. That is why the
portable harness exists — `swift run GrinderCoreChecks` executes the identical
case bodies here and proves the code, while the XCTest target is proven to
compile. On a host with Xcode, `swift test` runs the same cases.

### The iOS app (requires Xcode)

The app target cannot be built on a Command Line Tools-only host: there is no
iOS SDK. On a Mac with Xcode:

```sh
brew install xcodegen
cd apps/ios
xcodegen generate
open E64Local.xcodeproj         # build the GrinderApp scheme for an iPhone
```

Set `DEVELOPMENT_TEAM` in `project.yml` (or in Xcode's signing settings) to run
on a physical device.

What *is* verified on a host without Xcode:

```sh
cd apps/ios
sh scripts/verify-app-sources.sh
```

This parses every SwiftUI source (`GrinderApp.swift`, `AppModel.swift`,
`Screens/*.swift`) and fully type-checks `AppModel.swift` — the app's non-view
logic — against GrinderCore and the macOS SDK. The views' *types* are checked by
Xcode: SwiftUI's `@State`/`@EnvironmentObject` are macros implemented by
`SwiftUIMacros`, which ships only inside Xcode.

## Privacy

- Only `https://<host>[:port]/login.php` and `/rest_api/*` on the entered device
  are contacted.
- No redirects are followed; no caches, cookies or credentials are persisted by
  URLSession.
- The device address is stored in the app container; the owner token in the
  Keychain; nothing else.
- Forgetting a device deletes both, and can optionally remove the module and
  token from the grinder.
