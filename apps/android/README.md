# E64 Local — Android owner app

A cloud-free, LAN-only Android app for the owner of an E64 WS / NG2 grinder.
No account, no telemetry, no crash reporting, no analytics and no vendor
cloud: the app contacts exactly one host, the device address the owner enters.

```
apps/android/
├── app/src/main/java/de/mahlkoenig/e64local/
│   ├── core/      JSON, response envelope, log queries, auth header, redaction
│   ├── device/    endpoint + LAN guard, cookie jar, TLS pinning, HTTP client,
│   │              API repository, gated action client
│   ├── setup/     FW-01 injection, chunking, installer script, setup coordinator
│   ├── crypto/    Android Keystore AES-GCM
│   ├── storage/   per-device token, owner password and certificate pin
│   └── ui/        Compose screens (setup wizard, dashboard, logs, data, actions, about)
└── app/src/main/assets/                 copies of ondevice/rest_api_dev.php
                                         and ondevice/e64local_action_run.php
```

## Build and test

```bash
cd apps/android
./gradlew :app:assembleDebug :app:testDebugUnitTest
```

- `minSdk 26`, `targetSdk 36`, `compileSdk 37.2`.
- `compileSdk 37.2` is required by the Compose 1.13.0 / Lifecycle 2.11
  artifacts resolved by Compose BOM 2026.11.01: their AAR metadata asks for
  Android 37.1 or later. AGP names a minor release with `compileSdkMinor`, and
  the platform package is `platforms;android-37.2`. Compiling against a newer
  platform and opting in to new runtime behaviour are separate steps, so
  `targetSdk` stays at 36.
- Kotlin DSL, Jetpack Compose, no third-party networking library
  (`HttpURLConnection` and a small cookie jar), no analytics or crash SDK.
- The JVM tests never need an emulator. `org.json` is supplied to the test
  runtime because the `android.jar` stub is empty.

The build fails if either bundled PHP file does not match its `ondevice/` copy
byte for byte (`verifyBundledModule` task); the same digests are asserted again
by `BundledModuleDigestTest`.

### The build cache is scoped to the checkout

`settings.gradle.kts` puts the local build cache in `.gradle/build-cache` rather
than in the Gradle user home, so a `:app:mergeDebugResources` entry written under
another checkout is never restored here. AGP 9.5.3 stores that entry's resource
directories as absolute paths while the cache key ignores them, so the entry
describes the checkout that wrote it rather than the one reading it.

If a merge ever publishes only the app's own resources and AAPT then reports
"not found" for symbols `androidx.core` declares itself - for instance
`drawable/notification_action_background.xml` and the `compat_*` dimens and
styles it references - that is this cache and not a missing AppCompat
dependency. Repairing a tree that restored a bad entry means making the merge run
again: `./gradlew --rerun-tasks`, which also overwrites the entry with a good one,
or deleting `.gradle/build-cache` **and** `app/build` and rebuilding. `clean`
alone does not help - the merge is restored from the cache again - and
`--no-build-cache` only helps together with a clean, leaving the bad entry in
place for the next cached build.

An AGP upgrade may make the scoping unnecessary. To decide, count how many lines
across the cached entries name this checkout - it greps lines, not entries, so
two entries that still record the path print `4`. Run it after a
`./gradlew clean :app:assembleDebug`, in a tree whose `.gradle/build-cache` is
populated: an empty cache prints `0` and proves nothing, and so does a wrong
`$PWD` or a moved `merger.xml`. The count has to reach `0` on a populated cache
before the cache can move back to the Gradle user home:

```bash
for e in .gradle/build-cache/[0-9a-f]*; do
  gunzip -c "$e" 2>/dev/null | tar -xO ./tree-incrementalFolder/merger.xml 2>/dev/null
done | grep -c "$PWD/app/src/main/res"
```

## Auth model

1. Vendor session: `POST /login.php` with `login=1`, `userRole=Owner` and the
   owner password (an empty password is sent verbatim). The `PHPSESSID` cookie
   is kept in a small per-device jar and never sent to another host.
2. Owner token: sent as `X-E64-Local-Token`. It is generated on the phone
   (32 random bytes, 64 hex characters), stored encrypted with an AES-GCM key
   that never leaves the Android Keystore, and never written to a log.

The device certificate is self-signed. The app shows its SHA-256 fingerprint and
requires an explicit opt-in before storing a pin. Only the pinned certificate is
accepted afterwards; verification is narrowed, never silently disabled.

## One-click setup (FW-01, no ESP writes)

The setup wizard probes `GET /login.php` (model, firmware, dev mode), then shows
the exact installer script and every command that will be sent. On confirmation
it:

1. Uploads the module and the action runner as base64 chunks of 40 000
   characters: `printf '%s' '<chunk>' >> /tmp/e64local.b64`, then
   `base64 -d /tmp/e64local.b64 > /tmp/e64local-module.php` (or
   `/tmp/e64local-action-run.php`).
2. Uploads and runs the installer through the login form
   (`userRole = x';<command>;#`), which creates `/usr/local/www/dev` (module
   0644), `/usr/local/bin/e64local-action-run` (runner 0755, `root:root`),
   `/db/e64local` (0711) and `/db/e64local/token` (0600, `www-data:www-data`),
   then verifies both digests, both modes and the token mode on the device.
3. Calls `POST /rest_api/capabilities` with the new token. The token is stored
   only if that response is a valid `e64local-api-v1` document.

The runner is installed so the module's gated action layer can work, but the
app writes no `/db/e64local/actions.json`. Actions stay disabled (`403`) until
an owner deploys a policy with `e64root api deploy --enable-actions`; the app
can then use the five action routes (see below) but cannot open the gate itself.

The app refuses any command whose shell skeleton names a path outside
`/tmp`, `/usr/local/www/dev`, `/usr/local/bin/e64local-action-run`,
`/db/e64local`, `/log`, `/etc/issue` or `/dev/null`, or that mentions ESP
flash/NVS, the bootloader, eFuse or a firmware image. It never writes
`/dev/esps*`, ESP NVS, the bootloader or the eFuse, and never uploads firmware.

## Action layer (gated, closed by default)

`device/ActionApiClient.kt` implements the five meta routes of
`ondevice/rest_api_dev.php`: `action_prepare`, `action_execute`,
`action_status`, `action_cancel` and `action_audit`. Action identifiers such as
`action_grind_start_gbw` are **values** of the `route` field, never HTTP paths.

- **Confirm token, memory only.** `action_prepare` returns a single-use HMAC.
  `PreparedAction` has no token field: the client keeps the token in a private
  map keyed by `actionId`, and `execute` reads it from there. It is not part of
  `ActionsUi`, not written to storage, not in any `toString` and not logged.
  Discarding the confirm dialog, a handled cancel, or any execute the device
  answered (success or refusal) removes it; only a transport failure keeps it,
  because then nothing reached the device and no token was spent.
- **Destructive gate.** `capabilities.data.actions.destructiveEnabled` comes
  from the device. `ActionPolicy.gate(route)` blocks a destructive route with
  `403` while that flag is `false`, `prepare` refuses before any request is
  sent, and the screen shows the device's reason with a disabled button. There
  is no override in the app; the module re-checks the same flag on execute.
- **Readable errors.** `ActionErrors.describe` turns the device's `errorCode`
  into an instruction: a reboot between prepare and execute (`409`, "the device
  has rebooted") says the token is dead and to prepare again, an expired token
  says the same, `429` prints the `retryAfter` seconds the module sends next to
  the envelope, `422` distinguishes "unavailable" from bad parameters, `403`
  distinguishes the closed gate from the closed destructive gate, and `503`
  says nothing was actuated.
- **Read routes.** `ws_token` is exposed as `LocalApiRepository.wsToken()`; its
  value is a credential, so `WsToken.toString()` prints a placeholder only. The
  read layer therefore covers every route in the module's route list.
- **Not in scope.** The app never deploys a policy, never writes job or record
  files, never contacts the WSS socket, and never names the ESP, WiFi,
  firmware, fuse or bootloader namespaces.

## Screens

- **Setup wizard** — address, password, probe, certificate opt-in, one-click
  install with an explicit command preview.
- **Dashboard** — `capabilities`, `machine`, model, firmware, hashed serial and
  connection state.
- **Logs** — `grind_log`, `service_log`, `alert_log` with limit/offset paging and
  `since`/`until` filters.
- **Data** — `recipes`, `portafilters`, `settings`, `config` and `file`, limited
  to the device's read allowlist.
- **Actions** — the gate and the full catalog as the device reports it, a params
  field, a confirm dialog with route, params and risk class, a status view with
  refresh and cancel, and the audit trail (newest first). A route the gate would
  refuse stays visible with its reason and cannot be submitted.
- **About/Security** — the owner-token model, the action layer, the dev-mode
  requirement and the no-cloud design.

## Tests

`./gradlew :app:testDebugUnitTest` runs **162 JVM tests**, all offline and
without an emulator: the 155 that existed before the live suite (114 from before
the action layer, 41 from it), the 3 that came with the exchange log in
`BridgeOrderingUnitTest`, and the 4 new ones - three offline closed-gate checks
and the live end-to-end entry point, which skips itself when no simulator address
is given.

`app/src/test` covers JSON parsing, envelope and error-code handling (including
`retryAfter`), cookie handling, the auth header, pagination and time filters,
setup command generation, base64 chunking, the no-ESP guard, token redaction
(owner token, session cookie, password and the action confirm token), token
storage, TLS pinning, login-page parsing, a source scan that asserts no
non-device host appears, and the bundled-module digest.

`device/ActionApiClientTest.kt` (25 tests) drives the client through the
documented responses: prepare/execute/status/cancel/audit success paths, a
`401`, a closed-gate `403`, a destructive `403`, the reboot `409`, an expired
`409`, `429` with `retryAfter`, an unavailable `422`, cancel before execute,
cancel during execute, cancel of a terminal action, and the guarantee that the
confirm token appears in exactly one place (the execute body) and is redacted
everywhere else. `device/ActionGateTest.kt` (14 tests) pins the catalog parsing,
the destructive gate, the request-id pattern and the params parser, and asserts
that a blocked prepare never posts anything. The client test also re-checks that
every action route it posts appears in `docs/openapi/local-api.yaml`, the same
way `LocalApiRepositoryTest` does for the read routes.

Those tests use a fake transport. The suite below is the part that runs the real
one.

## Live end-to-end suite

`app/src/test/java/de/mahlkoenig/e64local/e2e/` drives the app's own networking
and action code against `tools/e64ws_simulator.py` over a real socket:

| File | What it is |
|---|---|
| `E2ESuite.kt` | the single JUnit entry point: environment, skip line, one summary line |
| `E2EReport.kt` | the check counter, `E2E PASS <n>` / `E2E FAIL <detail>`, the wire log |
| `LoopbackTlsBridge.kt` | terminates TLS on loopback in front of the plain-http simulator; key pair generated per JVM by the JDK's `keytool` |
| `SimulatorClient.kt` | the production `DeviceHttpClient` + `LocalApiRepository` pointed at that bridge |
| `LiveDeviceChecks.kt` | auth path, capabilities, all eleven read routes, transport invariants |
| `ActionLifecycleChecks.kt` | the gated action layer, end to end |
| `ClosedGateUnitTest.kt` | the offline counterpart: the app while the gate is still closed |

Nothing is mocked. `DeviceHttpClient` is the production client (`HttpURLConnection`,
the app's cookie jar, the app's pinned `PinnedTrustManager`), `LocalApiRepository`
and `ActionApiClient` are the production classes, and every byte the checks
assert on came from the simulator. The bridge exists for one reason: the runner
states the simulator address as plain `http`, while the app's client is TLS-only
with a pinned certificate. The terminator sits on loopback, presents a
certificate the suite generated and pinned, and forwards the request byte for
byte - so the app still performs a real TLS handshake and a real pin check,
against the real simulator, on the same wire the checks read back.

### Commands

```bash
# 1. a simulator with the action gate open (from the repository root).
#    `websockets` is needed; this checkout has it in .venv (tools/requirements.txt).
python3 tools/e64ws_simulator.py --http-port 18787 --port 19997 --scale-port 18765 --enable-actions

# 2. the live suite (from apps/android)
ANDROID_HOME=$HOME/Library/Android/sdk \
E64_E2E_BASE_URL=http://127.0.0.1:18787 \
E64_E2E_TOKEN=sim-local-api-token \
./gradlew :app:testDebugUnitTest --tests 'de.mahlkoenig.e64local.e2e.*'
```

The tail of a passing run is one summary line (a `note:` line can precede it; it
reports a finding and is prefixed so it cannot be read as the summary):

```
E2ESuite > live simulator end to end STANDARD_OUT
    note: HttpURLConnection drops the body of a 401, so the app reports
          'empty response from device' for a real token refusal; the device's
          own reason is only visible on the wire
    E2E PASS 63
BUILD SUCCESSFUL
```

Environment variables:

| Variable | Required | Meaning |
|---|---|---|
| `E64_E2E_BASE_URL` | yes | the simulator's plain-http address, no trailing slash, e.g. `http://127.0.0.1:18787`. Unset: the suite prints `E2E SKIP (no E64_E2E_BASE_URL)` and runs nothing. Only loopback addresses are accepted. |
| `E64_E2E_TOKEN` | yes once the address is set | the local-API owner token. The simulator's field default is `sim-local-api-token`; its `--token` flag is the unrelated WSS test token. |
| `E64_E2E_PASSWORD` | no | the owner password, default `sim-password`. |
| `ANDROID_HOME` | yes for Gradle | the Android SDK. |

`--enable-actions` is not optional for the suite: a shipped image (and a
simulator without the flag) reports `actions.enabled: false`, and the action
block then fails with a message naming the flag instead of pretending to have
proven anything.

The result contract, unchanged by how many checks run:

- no `E64_E2E_BASE_URL` -> `E2E SKIP (no E64_E2E_BASE_URL)` on stdout, exit 0;
- all checks passed -> exactly one `E2E PASS <n>` line on stdout, exit 0;
- any check failed -> `E2E FAIL <detail>` on stderr, exit 1.

`app/build.gradle.kts` forwards the test JVM's standard streams (Gradle would
otherwise swallow the summary line), declares the three environment variables as
task inputs so a changed address or credential re-runs the suite, and disables
the up-to-date check for `testDebugUnitTest`: a cached result would print no
summary line at all, and the simulator the suite talks to is not a declared
input. The e2e task therefore always runs; the plain unit suite is re-run too,
which costs a couple of seconds.

### What the suite proves

- **Auth path.** The app posts its vendor form login (`login=1`,
  `userRole=Owner`, `password`) to `/login.php` with the owner token deliberately
  absent, and fails closed when no session cookie comes back. It then stores the
  session cookie from the simulator's fixture session endpoint through its own
  client, holds it in its own jar, and sends it on every later route; a wrong
  password stores nothing.
- **Capabilities.** `e64local-api-v1`, api version `1`, all eleven read routes,
  pagination/time filters, the documented limits, `serverTime`, the action gate
  (`actions.enabled`, `destructiveEnabled`, `reason`, `actionRoutes`), the whole
  catalog including `unavailable` entries with their reasons and destructive
  entries with `blocked`, and the policy bounds/rate limits/token TTLs when the
  gate is open.
- **All eleven read routes** the app models: `machine` (with the serial only as a
  SHA-256), `grind_log` (default page, limit/offset, normalized `since`/`until`),
  `service_log` (seeded rows, module redaction), `alert_log`, `recipes`,
  `portafilters`, `settings` (sensitive keys withheld and listed),
  `config` (flattened, credentials redacted), `file` (`/etc/issue`,
  `/log/messages`, and a refusal for an off-allowlist path without a request),
  `ws_token` (a credential that prints only a placeholder).
- **Transport invariants.** Every routed request carried the owner token header
  and the `PHPSESSID` cookie; the token never appears in a body; a wrong token is
  refused with `401`; a lost session fails closed without a token-only route
  request; every answer is the simulator's own envelope.
- **The action lifecycle** with the gate open: prepare → execute → status →
  audit for `action_grind_stop` (no parameters, and the widest rate-limit bucket,
  so a parallel suite sharing the simulator cannot starve it), the confirm token
  minted once and spent by exactly one request body, the client forgetting it as
  soon as the device answered, a replay of the spent token refused by the device
  with `409`, cancel before execute (device state `cancelled`, no stop sent,
  idempotent on the second cancel), the destructive gate refusing
  `action_recipe_delete` locally *and* on the device with
  `destructiveEnabled: false`, and `429` with a `retryAfter` once the `agsa`
  bucket is exhausted.
- **Confirm-token hygiene.** The token is extracted from the device's raw
  prepare answer, then asserted absent from `PreparedAction`, `ActionResult`,
  `ActionStatus`, the audit page and every failure message; absent from captured
  `System.out`/`System.err` for the whole flow; present in exactly two places on
  the wire (prepare answer, execute body); and the classes that hold it
  (`ActionApiClient`, `LocalApiRepository`, `DeviceHttpClient`, `Auth`,
  `AppViewModel`) are source-scanned to contain no logging call at all.

### Proving the suite can fail

Point it at a closed port; the build exits 1 and the summary line says why:

```bash
ANDROID_HOME=$HOME/Library/Android/sdk \
E64_E2E_BASE_URL=http://127.0.0.1:18788 \
E64_E2E_TOKEN=sim-local-api-token \
./gradlew :app:testDebugUnitTest --tests 'de.mahlkoenig.e64local.e2e.*'
```

```
E2ESuite > live simulator end to end STANDARD_ERROR
    E2E FAIL target: the simulator at http://127.0.0.1:18788 answers through the app's pinned TLS client: HTTP 502: {"success":false,"errorCode":502,"error":"e2e bridge cannot reach Connection refused (connect failed)"}

E2ESuite > live simulator end to end FAILED
BUILD FAILED
```

The failure comes out of the app's real stack (a refused TCP connection under the
pinned TLS client), not out of a stub.

### What the live suite does not prove

- **The PHP module itself.** `ondevice/rest_api_dev.php` and
  `ondevice/e64local_action_run.php` were never executed: the simulator mirrors
  their wire shapes. No real grinder, no firmware, no actuation.
- **The vendor form login succeeding.** The simulator serves no `/login.php`, so
  the suite proves the app's *refusal* path for it (no session, no cookie, no
  token leak) and establishes the vendor session through the simulator's
  documented fixture endpoint instead. A real dispatcher answering the HTML login
  page is untested.
- **The reboot `409` at the device level.** The simulator has no reboot or
  boot-id control, so a prepared record cannot be made to belong to another boot.
  The app's reading of that answer is pinned offline in `ClosedGateUnitTest`;
  `ActionApiClientTest` covers the transport shape with a fake client.
- **A `401` body in the app's own words.** `HttpURLConnection` withholds the body
  of a `401`, so the app reports `empty response from device` even though the
  device explained itself (the suite asserts both sides and records a note).
  This is a property of the production stack, left unchanged here.
- **The Compose screens beyond one run.** The instrumented test below covers
  one screen on one AVD at one API level (35, arm64) and one locale, by hand;
  it is not a CI gate.
- **A real certificate.** The pinned certificate is one the suite generated with
  `keytool`; the vendor's self-signed certificate was not available.

## Instrumented UI test

`app/src/androidTest/java/de/mahlkoenig/e64local/ActionsE2E.kt` runs the same
flow through the real Compose UI on an emulator: it writes the device settings
the setup wizard would write (pin, token, password, active endpoint), opens the
Actions tab, asserts the gate and the destructive policy, taps
`action_language_set`, types its parameters, prepares, confirms, waits for the
terminal state of *this run's* action on its own status card, refreshes that
card's status, loads the audit page, discards a second confirmation (the app's
local cancel: the token is dropped and nothing runs), and asserts that the
destructive route is shown with its refusal and a disabled prepare button. It
then drains this process's logcat and fails on any 64-hex value.

**It runs, and it is green.** `OK (1 test)` on an arm64 API 35 AVD, twice in a
row against the same simulator instance; the same command pointed at a port with
nothing behind it fails at the gate assertion after 30 s. The run needs the
test-only TLS terminator in front of the simulator - the app is TLS-only and pins
the leaf certificate, and the simulator serves no `/login.php` - so
[`E2E_EMULATOR.md`](E2E_EMULATOR.md) is the recipe, its "Two runs per simulator"
section says what the second run established, and this paragraph only says what
the test covers. It is not part of CI (`.github/workflows/apps.yml` runs the JVM
suite only), and it is skipped - not failed - unless the instrumentation
arguments name a simulator:

```bash
python3 tools/e64ws_simulator.py --http-port 18787 --port 19997 --scale-port 18765 \
    --enable-actions --api-token sim-local-api-token \
    --http-tls-cert .tools/e2e.crt --http-tls-key .tools/e2e.key
python3 apps/android/e2e/device_terminator.py --listen-port 18788 \
    --cert .tools/e2e.crt --key .tools/e2e.key --upstream-port 18787 \
    --accept-token "$(openssl rand -hex 32)"          # -> e2eToken
openssl x509 -in .tools/e2e.crt -noout -fingerprint -sha256     # -> e2eCertSha256

adb -s emulator-5554 shell am instrument -w \
    -e class de.mahlkoenig.e64local.ActionsE2E \
    -e e2ePort 18788 -e e2eToken <the 64-hex token from the terminator> \
    -e e2ePassword sim-password -e e2eCertSha256 <the fingerprint from above> \
    de.mahlkoenig.e64local.test/androidx.test.runner.AndroidJUnitRunner
```

`10.0.2.2` (the emulator's alias for the host loopback) is the default host, and
the simulator must serve its REST API over TLS for the app's TLS-only client.
`am instrument -w` exits `0` even when the test fails: read the summary line
(`OK (1 test)` / `FAILURES!!!`), not the exit status.
