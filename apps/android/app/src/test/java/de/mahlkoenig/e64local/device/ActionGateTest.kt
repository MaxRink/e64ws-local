package de.mahlkoenig.e64local.device

import de.mahlkoenig.e64local.core.ApiResult
import de.mahlkoenig.e64local.core.Json
import de.mahlkoenig.e64local.core.JsonValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The local half of the action gate.
 *
 * The device is the authority: it re-reads `/db/e64local/actions.json` on every
 * call and refuses a destructive route while the second gate is closed. These
 * tests pin the app's behaviour so it cannot offer a route the device would
 * refuse, and so a destructive action cannot be submitted on the app's own
 * initiative.
 */
class ActionGateTest {

    private val transport = FixedClient()

    private class FixedClient : DeviceHttpClient(
        GrinderEndpoint("192.168.1.100"),
        CookieJar(),
        PinnedTrustManager("00"),
    ) {
        val posts = mutableListOf<Pair<String, String>>()

        override fun postForm(path: String, fields: Map<String, String>): TransportResponse {
            cookieJar.storeFromSetCookie(listOf("PHPSESSID=sess"), "192.168.1.100")
            return TransportResponse(200, "", "text/html", listOf("PHPSESSID=sess"), null)
        }

        override fun postJson(path: String, json: String, extraHeaders: Map<String, String>): TransportResponse {
            posts += path to json
            error("the gate must refuse before a request is sent")
        }
    }

    private fun repository() = LocalApiRepository(
        GrinderEndpoint("192.168.1.100"),
        transport,
        transport.cookieJar,
        tokenProvider = { "a".repeat(64) },
        passwordProvider = { "" },
    )

    private fun client(policy: ActionPolicy?) = ActionApiClient(repository(), policy)

    private fun entry(
        route: String,
        status: String = "implemented",
        risk: String = "actuator",
        destructive: Boolean = false,
        blocked: String? = null,
        reason: String? = null,
    ) = ActionCatalogEntry(
        route = route,
        status = status,
        risk = risk,
        destructive = destructive,
        surface = "wss",
        summary = "summary of $route",
        evidence = "docs/API_REFERENCE.md#25",
        blocked = blocked,
        reason = reason,
    )

    private fun policy(
        enabled: Boolean = true,
        destructiveEnabled: Boolean = false,
        catalog: List<ActionCatalogEntry> = listOf(entry("action_grind_start_gbw")),
        routes: List<String> = catalog.filter { it.isDispatchable }.map { it.route },
        reason: String? = null,
    ) = ActionPolicy(
        schema = "e64local-api-v1",
        enabled = enabled,
        destructiveEnabled = destructiveEnabled,
        reason = reason,
        actionRoutes = routes,
        catalog = catalog,
        note = null,
    )

    @Test
    fun `capabilities carry the gate, the catalog and the destructive flag`() {
        val data = Json.parseObject(
            """{"schema":"e64local-api-v1","apiVersion":"1","routes":["capabilities","action_prepare"],
                "features":{"actions":true,"destructiveActions":false},"limits":{},
                "actions":{"schema":"e64local-api-v1","enabled":true,"destructiveEnabled":false,
                    "reason":null,"actionRoutes":["action_grind_start_gbw"],
                    "catalog":[
                        {"route":"action_grind_start_gbw","status":"implemented","risk":"actuator",
                         "destructive":false,"surface":"wss","summary":"Start a grind",
                         "evidence":"docs/API_REFERENCE.md#25"},
                        {"route":"action_logs_clear","status":"implemented","risk":"destructive",
                         "destructive":true,"surface":"wss","summary":"Clear the logs",
                         "evidence":"docs/API_REFERENCE.md#25",
                         "blocked":"destructive actions are disabled"}
                    ]}}""",
        )
        val capabilities = Capabilities.from(data)

        assertTrue(capabilities.isLocalApiV1)
        assertTrue(capabilities.actionsEnabled)
        assertFalse(capabilities.destructiveEnabled)
        val actions = capabilities.actions!!
        assertEquals(listOf("action_grind_start_gbw"), actions.actionRoutes)
        assertEquals(2, actions.catalog.size)
        assertEquals("actuator", actions.entry("action_grind_start_gbw")?.risk)
        assertTrue(actions.entry("action_grind_start_gbw")!!.isDispatchable)
        // The catalog stays readable for a route the gate would refuse.
        assertTrue(actions.entry("action_logs_clear")!!.destructive)
        assertFalse(actions.entry("action_logs_clear")!!.isDispatchable)
        assertEquals("destructive actions are disabled", actions.entry("action_logs_clear")?.blocked)
    }

    @Test
    fun `a capabilities document without the action layer has no destructive flag`() {
        val capabilities = Capabilities.from(
            Json.parseObject("""{"schema":"e64local-api-v1","apiVersion":"1"}"""),
        )
        assertNull(capabilities.actions)
        assertFalse(capabilities.destructiveEnabled)
    }

    @Test
    fun `no action can be offered before capabilities were read`() {
        val blocked = client(null).check("action_grind_start_gbw") as ActionSubmit.Blocked
        assertEquals(503, blocked.errorCode)
        assertTrue(blocked.reason.contains("capabilities"))
    }

    @Test
    fun `a closed gate reports the device's own reason`() {
        val gate = client(policy(enabled = false, reason = "actions are not enabled (policy file missing)"))
        val blocked = gate.check("action_grind_start_gbw") as ActionSubmit.Blocked

        assertEquals(403, blocked.errorCode)
        assertEquals("actions are not enabled (policy file missing)", blocked.reason)
    }

    @Test
    fun `an unknown route is a 404 block`() {
        val blocked = client(policy()).check("action_esp_flash") as ActionSubmit.Blocked
        assertEquals(404, blocked.errorCode)
        assertTrue(blocked.reason.contains("not in this device's action catalog"))
    }

    @Test
    fun `an unavailable route is a 422 block that quotes the device`() {
        val gate = client(
            policy(
                catalog = listOf(
                    entry(
                        "action_recipe_import",
                        status = "unavailable",
                        reason = "no vendor route",
                    ),
                ),
            ),
        )
        val blocked = gate.check("action_recipe_import") as ActionSubmit.Blocked

        assertEquals(422, blocked.errorCode)
        assertTrue(blocked.reason.contains("no vendor route"))
    }

    @Test
    fun `a destructive route is blocked while the device reports the gate closed`() {
        val gate = client(
            policy(
                destructiveEnabled = false,
                catalog = listOf(
                    entry("action_logs_clear", risk = "destructive", destructive = true, blocked = null),
                ),
                // Even if the device listed it, the local gate must not open.
                routes = listOf("action_logs_clear"),
            ),
        )

        val blocked = gate.check("action_logs_clear") as ActionSubmit.Blocked
        assertEquals(403, blocked.errorCode)
        assertTrue(blocked.reason.contains("destructiveEnabled: false"))
        assertTrue(blocked.reason.contains("--enable-destructive-actions"))

        val result = gate.prepare("action_logs_clear")
        assertEquals(403, (result as ApiResult.Failure).errorCode)
        assertTrue("a blocked destructive action must not reach the device", transport.posts.isEmpty())
    }

    @Test
    fun `a destructive route is offered once the device reports the gate open`() {
        val gate = client(
            policy(
                destructiveEnabled = true,
                catalog = listOf(
                    entry("action_logs_clear", risk = "destructive", destructive = true, blocked = null),
                ),
            ),
        )
        assertEquals(ActionSubmit.Allowed, gate.check("action_logs_clear"))
    }

    @Test
    fun `a route the device does not list as dispatchable is blocked`() {
        val gate = client(
            policy(
                catalog = listOf(entry("action_grind_start_gbw")),
                routes = emptyList(),
            ),
        )
        val blocked = gate.check("action_grind_start_gbw") as ActionSubmit.Blocked

        assertEquals(403, blocked.errorCode)
        assertTrue(blocked.reason.contains("does not list"))
    }

    @Test
    fun `a blocked prepare never posts anything`() {
        val gate = client(policy(enabled = false))
        assertTrue(gate.prepare("action_grind_start_gbw") is ApiResult.Failure)
        assertTrue(gate.prepare("action_esp_flash") is ApiResult.Failure)
        assertTrue(transport.posts.isEmpty())
        assertTrue(gate.pendingActionIds.isEmpty())
    }

    @Test
    fun `params are a JSON object and an empty field means no parameters`() {
        assertEquals(emptyMap<String, JsonValue>(), ActionParams.parse("   ").getOrThrow().entries)
        assertEquals(emptyMap<String, JsonValue>(), ActionParams.parse("{}").getOrThrow().entries)
        val parsed = ActionParams.parse("""{"targetWeightGr":18,"doseIndex":2}""").getOrThrow()
        assertEquals(18L, parsed.long("targetWeightGr"))
        assertEquals(2L, parsed.long("doseIndex"))
        assertEquals(
            """{"targetWeightGr":18}""",
            ActionParams.render(ActionParams.parse("""{"targetWeightGr":18}""").getOrThrow()),
        )
        assertEquals(ActionParams.EMPTY, ActionParams.render(Json.obj()))
    }

    @Test
    fun `params refuse an array and broken JSON`() {
        val array = ActionParams.parse("[1,2,3]").exceptionOrNull()
        assertTrue(array is IllegalArgumentException)
        assertTrue(array!!.message!!.contains("JSON object"))

        val broken = ActionParams.parse("""{"targetWeightGr":}""").exceptionOrNull()
        assertTrue(broken is IllegalArgumentException)
        assertTrue(broken!!.message!!.contains("not valid JSON"))
    }

    @Test
    fun `request ids follow the device pattern`() {
        assertTrue(ActionRequestId.isValid("app-req-0001"))
        assertTrue(ActionRequestId.isValid("A1234567"))
        assertTrue(ActionRequestId.isValid(ActionRequestId.random()))
        assertEquals(36, ActionRequestId.random().length)

        assertFalse(ActionRequestId.isValid(null))
        assertFalse(ActionRequestId.isValid(""))
        assertFalse(ActionRequestId.isValid("short"))
        assertFalse(ActionRequestId.isValid(".hidden-id"))
        assertFalse(ActionRequestId.isValid("has space"))
        assertFalse(ActionRequestId.isValid("x".repeat(65)))
    }

    @Test
    fun `the catalog can be listed without opening the gate`() {
        val gate = client(
            policy(
                enabled = false,
                reason = "actions are not enabled (policy file missing)",
                catalog = listOf(
                    entry("action_grind_start_gbw"),
                    entry("action_endurance_start", status = "unavailable", reason = "unbounded loop"),
                ),
                routes = emptyList(),
            ),
        )
        val actions = gate.policy()!!

        assertFalse(actions.enabled)
        assertEquals(2, actions.catalog.size)
        assertEquals("unbounded loop", actions.catalog[1].reason)
        assertFalse(actions.catalog[1].isImplemented)
    }
}
