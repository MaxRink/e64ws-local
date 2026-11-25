package de.mahlkoenig.e64local

import android.os.Process
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import de.mahlkoenig.e64local.device.ActionApiClient
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The action layer on a device: the same flow the JVM suite proves against the
 * simulator, driven through the real Compose UI.
 *
 * ## Status: UNRUN
 *
 * No emulator was available when this was written, so this file has never been
 * executed. It is kept in the repository so the flow is not lost, and it is
 * documented as unproven in `apps/android/README.md`. The JVM suite
 * (`app/src/test/java/de/mahlkoenig/e64local/e2e`) is the part that is actually
 * verified; nothing here weakens it.
 *
 * ## Running it
 *
 * The simulator serves the REST API over TLS with `--http-tls-cert/--http-tls-key`
 * (the app's production client is TLS-only and pins the certificate), so the run
 * needs that fingerprint:
 *
 * ```
 * python3 tools/e64ws_simulator.py --http-port 18787 --port 19997 --scale-port 18765 \
 *     --enable-actions --http-tls-cert .tools/e2e.crt --http-tls-key .tools/e2e.key
 *
 * openssl x509 -in .tools/e2e.crt -noout -fingerprint -sha256
 *
 * ANDROID_HOME=$HOME/Library/Android/sdk ./gradlew :app:connectedDebugAndroidTest \
 *     -Pandroid.testInstrumentationRunnerArguments.class=de.mahlkoenig.e64local.ActionsE2E \
 *     -Pandroid.testInstrumentationRunnerArguments.e2ePort=18787 \
 *     -Pandroid.testInstrumentationRunnerArguments.e2eCertSha256=<hex from above>
 * ```
 *
 * `10.0.2.2` is the emulator's alias for the host loopback, which is where the
 * simulator has to run. Without the arguments the test is skipped instead of
 * failing, so a plain `connectedDebugAndroidTest` stays green.
 */
@RunWith(AndroidJUnit4::class)
class ActionsE2E {

    @get:Rule
    val compose = createEmptyComposeRule()

    private val arguments = InstrumentationRegistry.getArguments()
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun text(id: Int): String = context.getString(id)

    @Test
    fun actionLayerOnADevice() {
        val port = arguments.getString("e2ePort")
        assumeTrue("pass -e e2ePort=<http-port> to run this test", port != null)
        val host = arguments.getString("e2eHost") ?: "10.0.2.2"
        val token = arguments.getString("e2eToken") ?: "sim-local-api-token"
        val password = arguments.getString("e2ePassword") ?: "sim-password"
        val certificate = arguments.getString("e2eCertSha256")
        assumeTrue(
            "pass -e e2eCertSha256=<sha256 of the simulator certificate> to run this test",
            certificate != null,
        )

        // The owner's stored settings, written the way the setup wizard writes them:
        // pin first, then the token and the owner password, then the active device.
        val app = App.from(context)
        val endpointId = "$host:$port"
        app.tokenStore.pinCertificate(endpointId, certificate!!)
        app.tokenStore.save(endpointId, token, password)
        app.tokenStore.setActiveEndpoint(endpointId)

        ActivityScenario.launch(MainActivity::class.java).use {
            compose.onNodeWithText(text(R.string.tab_actions)).performClick()

            // The gate and the destructive policy, straight from the device.
            waitForText(text(R.string.actions_enabled), "the device never reported an open action gate")
            compose.onNodeWithText(text(R.string.actions_destructive)).performScrollTo()
            compose.onNodeWithText(text(R.string.actions_blocked)).assertExists()
            compose.onNodeWithText(text(R.string.actions_destructive_off)).assertExists()

            // A non-destructive route: prepare, confirm, execute, status, audit.
            selectRoute("action_language_set")
            setParams("{\"language\":\"en\"}")
            compose.onNodeWithText(text(R.string.actions_prepare)).performClick()
            compose.waitUntil(20_000) {
                compose.onAllNodesWithText(text(R.string.actions_confirm_title)).fetchSemanticsNodes().isNotEmpty()
            }
            // The dialog names route, risk and expiry; it has no token field, because
            // the confirm token never leaves ActionApiClient.
            compose.onNodeWithText("action_language_set").assertExists()
            compose.onNodeWithText("state-changing").assertExists()
            compose.onNodeWithText(text(R.string.actions_expires)).assertExists()
            compose.onNodeWithText(text(R.string.actions_confirm_run)).performClick()

            waitForText("completed", "the action never reached a terminal state")
            compose.onNodeWithText(text(R.string.actions_status_refresh)).performScrollTo().performClick()
            waitForText("completed", "the status refresh lost the terminal state")
            compose.onNodeWithText(text(R.string.actions_result)).performScrollTo().assertExists()
            compose.onNodeWithText(text(R.string.actions_audit_load)).performScrollTo().performClick()
            waitForText(text(R.string.actions_audit_total), "the audit page never loaded")

            // A prepared action that is never executed: the dialog's discard is the
            // app's local cancel - the token is dropped and nothing is actuated.
            selectRoute("action_language_set")
            setParams("{\"language\":\"en\"}")
            compose.onNodeWithText(text(R.string.actions_prepare)).performClick()
            compose.waitUntil(20_000) {
                compose.onAllNodesWithText(text(R.string.actions_confirm_title)).fetchSemanticsNodes().isNotEmpty()
            }
            compose.onNodeWithText(text(R.string.actions_confirm_cancel)).performClick()
            waitForText(
                "Not submitted",
                "discarding the confirmation produced no notice",
            )

            // A destructive route: visible with the device's reason, and the prepare
            // button is disabled. There is no override in the app.
            selectRoute("action_recipe_delete")
            waitForText(
                ActionApiClient.DESTRUCTIVE_GATE_CLOSED.substring(0, 40),
                "the destructive route was offered without the app's refusal",
            )
            compose.onNodeWithText(text(R.string.actions_prepare)).assertIsNotEnabled()
        }

        // Nothing this app writes may carry a 64-hex secret. The confirm token is
        // minted during this run, so a token-shaped value in this process's log is a
        // failure, not a coincidence.
        val log = drainLogcat()
        assertFalse(
            "a 64-hex value reached logcat while the action layer ran:\n$log",
            Regex("[0-9a-f]{64}").containsMatchIn(log),
        )
    }

    private fun selectRoute(route: String) {
        compose.onAllNodesWithText(route).onFirst().performScrollTo().performClick()
        compose.waitUntil(20_000) {
            compose.onAllNodesWithText(text(R.string.actions_prepare)).fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun setParams(json: String) {
        compose.onNode(hasSetTextAction()).performScrollTo().performTextClearance()
        compose.onNode(hasSetTextAction()).performTextInput(json)
    }

    private fun waitForText(value: String, message: String) {
        compose.waitUntil(30_000) {
            compose.onAllNodesWithText(value, substring = true).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onAllNodesWithText(value, substring = true).onFirst().assertExists(message)
    }

    /** This process's logcat only, so another app's hashes cannot fail the assertion. */
    private fun drainLogcat(): String = runCatching {
        val descriptor = InstrumentationRegistry.getInstrumentation()
            .uiAutomation
            .executeShellCommand("logcat -d --pid=${Process.myPid()}")
        descriptor.use {
            java.io.FileInputStream(it.fileDescriptor).bufferedReader().use { reader -> reader.readText() }
        }
    }.getOrElse { "" }
}
