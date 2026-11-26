# The instrumented action test on an emulator

`app/src/androidTest/java/de/mahlkoenig/e64local/ActionsE2E.kt` drives the action
layer through the real Compose UI on a device. `e2e/device_terminator.py` is the
test-only shim in between, and it exists so that run can happen against
`tools/e64ws_simulator.py` without changing a line under `app/src/main`. This
file says what the shim does, why it is needed, and what the run did and did not
establish.

## What the terminator does

One file, loopback only, in front of the simulator. It terminates TLS with a
host-generated certificate pair (`.tools/e2e.crt` / `.tools/e2e.key`, both
git-ignored) and adds exactly two device-side behaviours:

| Behaviour | Why the app needs it |
|---|---|
| `POST /login.php` answers by delegating to the simulator's `POST /rest_api/login` and relays that answer's `PHPSESSID` as the session cookie | the app's whole auth model starts with the vendor form login |
| `X-E64-Local-Token` is accepted as the run's 64-hex token and mapped to the fixture's literal token on the upstream leg | the app only ever stores a 64-hex token; the fixture only knows `sim-local-api-token` |

Every other request is forwarded verbatim (`GET /login.php` included, because the
setup wizard probes it), with `content-type`, `set-cookie`, `location`,
`content-disposition` and `authorization` relayed back unchanged. It fails
closed: if the simulator does not answer `200` with a `PHPSESSID`, the app is
given the simulator's own error and stores no session; a token that is not the
one passed as `--accept-token` is refused with `401` before anything is
forwarded, which is what the module on a real device does with an unknown token.

## Why it exists

1. **Pinning is not disabled.** The production client is TLS-only and pins the
   device's leaf certificate (`device/PinnedTrustManager.kt`), so the test cannot
   be pointed at a plain-`http` fixture and the app is not given a client that
   skips verification. The terminator presents the certificate whose SHA-256 the
   test pins in the token store, so the app performs a real handshake and a real
   pin check; any other certificate is still rejected, by the app.
2. **The simulator has no `/login.php`.** It models the module, not the vendor
   dispatcher: `POST /login.php` there is a `404`. The app's own login code
   therefore cannot obtain a session from the simulator alone, and the JVM suite
   relies on that absence - it pins the app's refusal path rather than a login
   that succeeds. The terminator answers the form by delegating to the fixture's
   documented session route, so the app runs its real login path and stores the
   simulator's real cookie.
3. **The two token shapes differ.** The app stores a 64-hex token it generates on
   the phone (`setup/OwnerToken.isValid`, enforced by `storage/TokenStore.save`)
   and sends it as `X-E64-Local-Token`; the simulator accepts only the literal
   `sim-local-api-token`. The terminator takes the single 64-hex value it is
   given, so the app still holds a real 64-hex token and the storage invariant is
   still load-bearing in the run - it is the terminator's job to make one
   accepted value, not to make any value accepted.

Nothing under `app/src/main` knows the terminator exists, and no verification
step is skipped: the pin check, the token store, the cookie jar and the action
client are all the production classes.

## Running it

```bash
# 0. one-time, from the repository root: the certificate the test will pin.
mkdir -p .tools
openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
    -keyout .tools/e2e.key -out .tools/e2e.crt -subj "/CN=e64-e2e-terminator"
openssl x509 -in .tools/e2e.crt -noout -fingerprint -sha256    # -> e2eCertSha256

# 1. the simulator: REST over TLS, action gate open, destructive gate still shut.
python3 tools/e64ws_simulator.py --http-port 18787 --port 19997 --scale-port 18765 \
    --enable-actions --api-token sim-local-api-token \
    --http-tls-cert .tools/e2e.crt --http-tls-key .tools/e2e.key

# 2. the terminator in front of it; --accept-token is the run's 64-hex token.
python3 apps/android/e2e/device_terminator.py --listen-port 18788 \
    --cert .tools/e2e.crt --key .tools/e2e.key \
    --upstream-port 18787 --fixture-token sim-local-api-token \
    --accept-token "$(openssl rand -hex 32)"

# 3. an emulator; the verified run used an arm64 API 35 AVD.
emulator -avd e64ws-actions -no-window -no-audio -gpu swiftshader_indirect \
    -no-snapshot -no-boot-anim -port 5554

# 4. build, install on that one device, run.
cd apps/android
ANDROID_HOME=$HOME/Library/Android/sdk ./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb -s emulator-5554 install -r -t app/build/outputs/apk/debug/app-debug.apk
adb -s emulator-5554 install -r -t app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s emulator-5554 shell am instrument -w \
    -e class de.mahlkoenig.e64local.ActionsE2E \
    -e e2ePort 18788 -e e2eToken <the 64-hex token from step 2> \
    -e e2ePassword sim-password -e e2eCertSha256 <the fingerprint from step 0> \
    de.mahlkoenig.e64local.test/androidx.test.runner.AndroidJUnitRunner
```

`10.0.2.2` is the emulator's alias for the host's loopback, which is why both
servers bind `127.0.0.1`. `adb -s <serial>` is used instead of
`:app:connectedDebugAndroidTest` because the connected task runs the APK on every
attached device; with one device either form works. The test is skipped, not
failed, when `e2ePort` or `e2eCertSha256` is missing, so a plain
`connectedDebugAndroidTest` stays green on a machine with no fixture.
`am instrument -w` exits `0` even when the test fails, so read the summary line
(`OK (1 test)` / `FAILURES!!!`), not the exit status.

## What the run proved

The recorded runs are **two consecutive runs against one** simulator instance,
started once as in "Running it" above. The second run's audit page already
carried the first run's rows - the condition under which this test used to fail,
see "Two runs per simulator" below - so that condition is part of the result.

- The production stack reached a TLS endpoint from the emulator: handshake,
  pin check against the pinned leaf, vendor login, own cookie jar, all requests
  through the app's `DeviceHttpClient`.
- The Actions tab rendered what the device reported: gate open, the destructive
  policy shown as blocked with its reason, and **Prepare action** disabled for
  `action_recipe_delete` - that refusal never reached the wire (the terminator saw
  exactly two `action_prepare` calls, the executed one and the later discarded
  one, and none for the destructive route).
- The full lifecycle through the UI: prepare -> confirm dialog -> execute ->
  terminal `completed` -> status refresh -> audit page, on `action_language_set`.
  The refresh is a real round trip in both runs: the terminator saw two
  `action_status` calls per run, the execute path's own read and the click.
- The discard path: a second prepare, then **Discard** produced `Not submitted`
  and no `action_execute` was sent.
- No 64-hex value appeared in this process's logcat during the flow (the test's
  own assertion, `logcat -d --pid=<pid>`).
- The test is load-bearing: the same command pointed at a port with nothing
  behind it fails at the gate assertion after 30 s instead of passing.

## What the run did not prove

- **The PHP module.** `ondevice/rest_api_dev.php` and
  `ondevice/e64local_action_run.php` were not executed; the simulator mirrors
  their wire shapes. No grinder, no firmware, no actuation.
- **The real dispatcher's login page.** The `/login.php` the app talked to is the
  terminator's, so the vendor page's markup, its `PHPSESSID` and its failure modes
  are still only covered by `LoginPageFingerprintTest`.
- **The token against a real device.** The 64-hex token was accepted by the
  terminator, which then presented the fixture's literal one. The app's storage
  and header behaviour is verified; a grinder's own token store is not.
- **A real certificate, and a real refusal.** The pinned leaf is one generated on
  the host. Nothing here exercises the vendor's self-signed certificate, a
  rotated certificate, or the app's owner-facing pin prompt.
- **The rest of the app.** One screen (the Actions tab only), one AVD, one API level
  (35, arm64), one locale; no other read route, no setup wizard run, no reboot
  `409`.
- **CI.** `.github/workflows/apps.yml` deliberately runs only
  `:app:testDebugUnitTest`; this run is local and reproducible by hand, not gated.

## Two runs per simulator

The test is idempotent: two consecutive runs against the same simulator instance,
started once, both pass. That is a regression the test itself had to fix - until
then it passed only on a simulator that had no action history:

```
# pre-fix, same APK and arguments, one simulator instance:
#   run 1, fresh instance (audit total 0)   -> OK (1 test), 19.599 s
#   run 2, same instance (audit populated)  -> FAILURES!!!, Tests run: 1, Failures: 1
java.lang.AssertionError: Action performScrollTo() failed.
Reason: Expected exactly '1' node but could not find any node that satisfies:
        (Text + InputText + EditableText contains 'Result' (ignoreCase: false))
    at de.mahlkoenig.e64local.ActionsE2E.actionLayerOnADevice(ActionsE2E.kt:124)
```

The cause was in the test, not in the app: `waitForText("completed", ...)` was a
substring match over the whole tree, and `loadActions()` also loads the audit
page, so on a simulator that already had action rows the wait was satisfied by an
old audit row (`action_language_set  0 ms  completed`) before this run's status
existed. The tree at that moment showed this run's status card still saying
`Nothing here yet.`, with `Refresh status` and `Cancel action` both `[Disabled]`:
the click landed while `busy` was still true, the button was disabled, the click
was dropped - the terminator saw one `action_status` instead of two - and the
`actions_result` label was asserted against a card that was never filled.

The wait and the assertions are now scoped to this run's action id and to its own
status card, and the refresh is clicked only once that card's button is enabled
(`ActionsE2E.statusCard`, `ActionsE2E.waitForStatus`); nothing sleeps. The same
two runs afterwards, one simulator instance, same APK:

```
# post-fix, one simulator instance started once:
#   run 1 -> OK (1 test), 12.811 s   two action_status on the wire
#   run 2 -> OK (1 test), 11.854 s   two action_status on the wire
# negative control, same APK, -e e2ePort 18789 (nothing behind it):
#   -> FAILURES!!!, Tests run: 1, Failures: 1
androidx.compose.ui.test.ComposeTimeoutException: Condition still not satisfied after 30000 ms
    at de.mahlkoenig.e64local.ActionsE2E.waitForText(ActionsE2E.kt:262)
    at de.mahlkoenig.e64local.ActionsE2E.actionLayerOnADevice(ActionsE2E.kt:108)
```

So restarting `tools/e64ws_simulator.py` between runs is no longer required, and
a second run's failure is a real failure rather than fixture history.

One weakness is left on purpose: `loadActions()` still fills the audit card, so
the audit step's wait for `Rows on the device` is already satisfied on a re-run
and does not prove a freshly loaded page. The status assertions are the ones that
are scoped to this run.
