package de.mahlkoenig.e64local

import android.os.Process
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.filter
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onChildren
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onParent
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
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
 * ## Status: RUN, green on an emulator
 *
 * `1/1 completed, 0 skipped, 0 failed` on an arm64 API 35 AVD against
 * `tools/e64ws_simulator.py`, twice in a row against the same simulator
 * instance: the waits and the status assertions are scoped to this run's action
 * id and its status card, so the audit rows a previous run left behind cannot
 * stand in for this run's status. The JVM suite
 * (`app/src/test/java/de/mahlkoenig/e64local/e2e`) stays the faster gate; this
 * proves the same action layer through the real Compose UI.
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
            compose.onNodeWithText(text(R.string.actions_prepare)).performScrollTo().performClick()
            compose.waitUntil(20_000) {
                compose.onAllNodesWithText(text(R.string.actions_confirm_title)).fetchSemanticsNodes().isNotEmpty()
            }
            // The dialog names route, parameters, risk and expiry; it has no token
            // field, because the confirm token never leaves ActionApiClient. Each
            // lookup is scoped to the dialog: the route string is also the catalog
            // card and the prepare title, and the risk class is on every catalog
            // card, so an unscoped match finds several nodes.
            compose.onNode(inDialog(hasText("action_language_set"))).assertExists()
            compose.onNode(inDialog(hasText("state-changing"))).assertExists()
            compose.onNode(inDialog(hasText(text(R.string.actions_expires)))).assertExists()
            // The parameters the owner typed are the parameters the dialog shows.
            compose.onNode(inDialog(hasText("{\"language\":\"en\"}"))).assertExists()
            compose.onNodeWithText(text(R.string.actions_confirm_run)).performClick()

            // The terminal state of *this run's* action, read off its own status
            // card. `loadActions()` loads the audit page as well, so on a simulator
            // that already has rows an unscoped text wait returns on an earlier
            // run's audit row before this run's status exists - and the refresh
            // click below then lands on a disabled button and is dropped.
            val actionId = waitForActionId()
            waitForStatus(actionId, "completed", "the action never reached a terminal state")

            // The status card's own button, and only once it is live: a click on a
            // disabled button is dropped without an error, and the refresh it was
            // meant to send never reaches the device.
            statusCard(actionId).onChildren()
                .filter(hasText(text(R.string.actions_status_refresh)))
                .onFirst()
                .assertIsEnabled()
                .performScrollTo()
                .performClick()
            waitForStatus(actionId, "completed", "the status refresh lost the terminal state")
            statusCard(actionId).onChildren()
                .filter(hasText(text(R.string.actions_result)))
                .onFirst()
                .assertExists("the status card of $actionId shows no result for this run's action")
                .performScrollTo()
            compose.onNodeWithText(text(R.string.actions_audit_load)).performScrollTo().performClick()
            waitForText(text(R.string.actions_audit_total), "the audit page never loaded")

            // A prepared action that is never executed: the dialog's discard is the
            // app's local cancel - the token is dropped and nothing is actuated.
            selectRoute("action_language_set")
            setParams("{\"language\":\"en\"}")
            compose.onNodeWithText(text(R.string.actions_prepare)).performScrollTo().performClick()
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
            compose.onNodeWithText(text(R.string.actions_prepare)).performScrollTo().assertIsNotEnabled()
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

    /** Scopes a matcher to the confirmation dialog, not the screen behind it. */
    private fun inDialog(matcher: SemanticsMatcher): SemanticsMatcher =
        matcher and hasAnyAncestor(isDialog())

    /**
     * The status card: the card holding this run's "Action id" row, or - once the
     * id is known - the one row that carries it.
     *
     * The audit card sits in the same scroll column and its rows carry the same
     * words ("completed", the route), so an assertion that is not scoped to this
     * card can be satisfied by an earlier run against the same simulator.
     */
    private fun statusCard(actionId: String? = null): SemanticsNodeInteraction =
        compose.onNodeWithText(actionId ?: text(R.string.actions_action_id)).onParent()

    /** This run's action id: the value of the status card's Action id row. */
    private fun waitForActionId(): String {
        var found: String? = null
        compose.waitUntil(30_000) {
            found = runCatching {
                statusCard().fetchSemanticsNode().children
                    .flatMap { it.texts() }
                    .firstOrNull { ACTION_ID.matches(it) }
            }.getOrNull()
            found != null
        }
        return checkNotNull(found)
    }

    /**
     * Waits until [actionId]'s status card reports [state] and its own buttons are
     * live again (`busy` is over), then asserts the state on that card.
     */
    private fun waitForStatus(actionId: String, state: String, message: String) {
        compose.waitUntil(30_000) {
            runCatching {
                val card = statusCard(actionId).fetchSemanticsNode()
                val reported = card.children.any { it.texts().contains(state) }
                val live = card.children.any { child ->
                    child.texts().contains(text(R.string.actions_status_refresh)) &&
                        !child.config.contains(SemanticsProperties.Disabled)
                }
                reported && live
            }.getOrDefault(false)
        }
        statusCard(actionId).onChildren().filter(hasText(state)).onFirst().assertExists(message)
    }

    private fun SemanticsNode.texts(): List<String> =
        config.getOrNull(SemanticsProperties.Text)?.map { it.text } ?: emptyList()

    private fun selectRoute(route: String) {
        compose.onAllNodesWithText(route).onFirst().performScrollTo().performClick()
        compose.waitUntil(20_000) {
            compose.onAllNodesWithText(text(R.string.actions_prepare)).fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun setParams(json: String) {
        // SetText replaces the whole value in one step. InsertTextAtCursor needs a
        // live IME session, which a headless emulator does not always provide; the
        // value used to stay empty without an error.
        compose.onNode(hasSetTextAction()).performScrollTo().performTextReplacement(json)
        // Prove the parameters actually landed: an empty field is a valid object
        // for the app, so a silent no-op would prepare the wrong request and the
        // confirm dialog would still appear.
        compose.onNode(hasSetTextAction()).assert(hasText(json))
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

    private companion object {
        /** The id shape this fixture issues (`uuid4`); the app stores it verbatim. */
        val ACTION_ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    }
}
