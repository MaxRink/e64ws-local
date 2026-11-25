package de.mahlkoenig.e64local.e2e

import de.mahlkoenig.e64local.core.ApiResult
import de.mahlkoenig.e64local.core.Json
import de.mahlkoenig.e64local.device.ActionApiClient
import de.mahlkoenig.e64local.device.ActionErrors
import de.mahlkoenig.e64local.device.ActionPolicy
import de.mahlkoenig.e64local.device.ActionSubmit
import de.mahlkoenig.e64local.device.CookieJar
import de.mahlkoenig.e64local.device.DeviceHttpClient
import de.mahlkoenig.e64local.device.GrinderEndpoint
import de.mahlkoenig.e64local.device.LocalApiRepository
import de.mahlkoenig.e64local.device.PinnedTrustManager
import de.mahlkoenig.e64local.device.TransportException
import de.mahlkoenig.e64local.device.TransportResponse
import de.mahlkoenig.e64local.device.gate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The offline half of the action-gate contract: what the app does while the
 * device reports the gate closed.
 *
 * No socket is opened and no server is started. The device's own document is
 * quoted (`ondevice/rest_api_dev.php` answers `actions.enabled: false` with no
 * policy file, and `destructiveEnabled: false` even when actions are on), the
 * transport is the app's [DeviceHttpClient] with only its `postJson` replaced,
 * and every assertion is about the app: it must refuse locally, explain the
 * device's reason, and send nothing.
 *
 * The device side of the same contract (that the simulator really answers 403)
 * is covered by the simulator's own Python tests, so it is not repeated here.
 */
class ClosedGateUnitTest {

    /** Records what the repository would have posted; answers nothing on its own. */
    private class RecordingClient : DeviceHttpClient(
        GrinderEndpoint(HOST),
        CookieJar(),
        PinnedTrustManager("00"),
    ) {
        val posts = mutableListOf<String>()

        override fun postForm(path: String, fields: Map<String, String>): TransportResponse {
            cookieJar.storeFromSetCookie(listOf("PHPSESSID=session"), HOST)
            return TransportResponse(200, "{\"success\":true}", "application/json", listOf("PHPSESSID=session"), null)
        }

        override fun postJson(path: String, json: String, extraHeaders: Map<String, String>): TransportResponse {
            posts += path
            throw TransportException("the test never answers $path")
        }
    }

    private val client = RecordingClient()
    private val repository = LocalApiRepository(
        GrinderEndpoint(HOST),
        client,
        client.cookieJar,
        tokenProvider = { "token" },
        passwordProvider = { "password" },
    )

    @Test
    fun `a closed gate blocks every route locally and posts nothing`() {
        val gateClosed = policy(gateEnabled = false, destructiveEnabled = false)
        val actions = ActionApiClient(repository)
        actions.updatePolicy(gateClosed)

        val submit = actions.check("action_language_set")
        assertTrue("the gate allowed a route: $submit", submit is ActionSubmit.Blocked)
        assertEquals(403, (submit as ActionSubmit.Blocked).errorCode)
        assertEquals("actions are not enabled (policy file missing)", submit.reason)

        val prepared = actions.prepare("action_language_set")
        assertTrue("prepare was not refused: $prepared", prepared is ApiResult.Failure)
        assertEquals(403, (prepared as ApiResult.Failure).errorCode)
        assertEquals("the app posted a request through a closed gate", emptyList<String>(), client.posts)
        assertEquals("a confirmation survived a refused prepare", emptyList<String>(), actions.pendingActionIds)
    }

    @Test
    fun `the destructive gate refuses a destructive route while destructiveEnabled is false`() {
        val gateOpen = policy(gateEnabled = true, destructiveEnabled = false)
        val actions = ActionApiClient(repository)
        actions.updatePolicy(gateOpen)

        val submit = gateOpen.gate("action_language_set")
        assertEquals("a non-destructive route must stay dispatchable: $submit", ActionSubmit.Allowed, submit)

        val blocked = gateOpen.gate("action_recipe_delete")
        assertTrue("the destructive route was allowed: $blocked", blocked is ActionSubmit.Blocked)
        assertEquals(403, (blocked as ActionSubmit.Blocked).errorCode)
        assertEquals(ActionApiClient.DESTRUCTIVE_GATE_CLOSED, blocked.reason)

        val prepared = actions.prepare("action_recipe_delete")
        assertTrue("prepare accepted a destructive route: $prepared", prepared is ApiResult.Failure)
        assertEquals("the app posted a request for a blocked route", emptyList<String>(), client.posts)
    }

    @Test
    fun `the closed gate and the destroyed token are explained in words an owner can act on`() {
        val closed = ApiResult.Failure(403, "actions are not enabled (policy file missing)", httpStatus = 403)
        assertTrue(
            "describe() does not name the policy file: ${ActionErrors.describe(closed)}",
            ActionErrors.describe(closed).contains("/db/e64local/actions.json"),
        )
        val destructive = ApiResult.Failure(403, "destructive actions are disabled", httpStatus = 403)
        assertTrue(
            "describe() does not name the flag: ${ActionErrors.describe(destructive)}",
            ActionErrors.describe(destructive).contains("--enable-destructive-actions"),
        )
        // The device path for this one cannot be provoked on the simulator (it has no
        // reboot control), so the app's reading of the 409 is pinned offline.
        val rebooted = ApiResult.Failure(
            409,
            "the device has rebooted since this action was prepared",
            httpStatus = 409,
        )
        assertTrue("the 409 is not read as a reboot conflict", ActionErrors.isRebootConflict(rebooted))
        assertTrue(
            "describe() gives no instruction: ${ActionErrors.describe(rebooted)}",
            ActionErrors.describe(rebooted).contains("Prepare the action again"),
        )
        assertTrue(
            "an expired token is not distinguished",
            ActionErrors.isExpiredToken(ApiResult.Failure(409, "the confirm token has expired", httpStatus = 409)),
        )
    }

    /** A capabilities `data.actions` document, exactly as the module writes it. */
    private fun policy(gateEnabled: Boolean, destructiveEnabled: Boolean): ActionPolicy {
        val catalog = listOf(
            catalogEntry("action_language_set", destructive = false, blocked = null),
            catalogEntry(
                "action_recipe_delete",
                destructive = true,
                blocked = if (destructiveEnabled) null else "destructive actions are disabled",
            ),
            "{\"route\":\"action_fan_calibrate\",\"status\":\"unavailable\",\"risk\":\"actuator\"," +
                "\"destructive\":false,\"reason\":\"CalibrateFan1/2 has no completion signal\"}",
        )
        val document = "{" +
            "\"schema\":\"e64local-api-v1\"," +
            "\"enabled\":$gateEnabled," +
            "\"destructiveEnabled\":${gateEnabled && destructiveEnabled}," +
            (if (gateEnabled) "\"reason\":null," else "\"reason\":\"actions are not enabled (policy file missing)\",") +
            "\"actionRoutes\":[" +
            (if (gateEnabled) "\"action_language_set\"" else "") +
            "]," +
            "\"catalog\":[${catalog.joinToString(",")}]," +
            "\"note\":\"action identifiers are passed in action_prepare, not posted as paths\"" +
            "}"
        return ActionPolicy.from(Json.parseObject(document))
    }

    private fun catalogEntry(route: String, destructive: Boolean, blocked: String?): String =
        "{\"route\":\"$route\",\"status\":\"implemented\",\"risk\":\"state-changing\"," +
            "\"destructive\":$destructive" +
            (if (blocked == null) "" else ",\"blocked\":\"$blocked\"") +
            "}"

    companion object {
        private const val HOST = "127.0.0.1"
    }
}
