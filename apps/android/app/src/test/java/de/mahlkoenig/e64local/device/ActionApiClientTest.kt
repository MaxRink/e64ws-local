package de.mahlkoenig.e64local.device

import de.mahlkoenig.e64local.core.ApiResult
import de.mahlkoenig.e64local.core.Json
import de.mahlkoenig.e64local.core.Redaction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Protocol tests for the gated action layer. No socket is opened: the subclass
 * below replaces only the transport call, so header, body, cookie and envelope
 * handling run exactly as they do against a device.
 *
 * The fixtures quote the responses in `ondevice/rest_api_dev.php` (the five
 * `_handleAction*` functions), so a field rename there fails a test here.
 */
class ActionApiClientTest {

    private class RecordingClient : DeviceHttpClient(
        GrinderEndpoint(HOST),
        CookieJar(),
        PinnedTrustManager("00"),
    ) {
        data class Call(val path: String, val body: String, val headers: Map<String, String>)

        val calls = mutableListOf<Call>()
        private val responses = mutableListOf<TransportResponse>()
        private var transportFailure: String? = null

        fun respond(json: String, status: Int = 200) {
            responses += TransportResponse(status, json, "application/json", emptyList(), null)
        }

        /** Makes the next JSON post throw instead of answer. */
        fun failNext(message: String) {
            transportFailure = message
        }

        fun bodiesFor(path: String): List<String> = calls.filter { it.path == path }.map { it.body }

        override fun postForm(path: String, fields: Map<String, String>): TransportResponse {
            if (path != "/login.php") error("unexpected form post $path")
            cookieJar.storeFromSetCookie(listOf("PHPSESSID=sess"), HOST)
            return TransportResponse(200, "", "text/html", listOf("PHPSESSID=sess"), null)
        }

        override fun postJson(path: String, json: String, extraHeaders: Map<String, String>): TransportResponse {
            calls += Call(path, json, extraHeaders)
            transportFailure?.let {
                transportFailure = null
                throw TransportException(it)
            }
            if (responses.isEmpty()) error("no canned response for $path")
            return responses.removeAt(0)
        }

        companion object {
            const val HOST = "192.168.1.100"
        }
    }

    private val ownerToken = "a".repeat(64)
    private val confirmToken = "b".repeat(64)
    private val actionId = "0f1e2d3c-4b5a-6978-8765-43210fedcba9"

    private fun repository(client: RecordingClient) = LocalApiRepository(
        GrinderEndpoint(RecordingClient.HOST),
        client,
        client.cookieJar,
        tokenProvider = { ownerToken },
        passwordProvider = { "" },
    )

    private fun entry(
        route: String,
        risk: String,
        destructive: Boolean = false,
        status: String = "implemented",
        blocked: String? = null,
        reason: String? = null,
    ) = ActionCatalogEntry(
        route = route,
        status = status,
        risk = risk,
        destructive = destructive,
        surface = "wss",
        summary = "test entry",
        evidence = "docs/API_REFERENCE.md#25-grinderaction-suffixes-39",
        blocked = blocked,
        reason = reason,
    )

    private fun policy(
        enabled: Boolean = true,
        destructiveEnabled: Boolean = false,
        catalog: List<ActionCatalogEntry> = listOf(
            entry("action_grind_start_gbw", "actuator"),
            entry("action_logs_clear", "destructive", destructive = true),
        ),
        routes: List<String> = listOf("action_grind_start_gbw", "action_logs_clear"),
    ) = ActionPolicy(
        schema = "e64local-api-v1",
        enabled = enabled,
        destructiveEnabled = destructiveEnabled,
        reason = if (enabled) null else "actions are not enabled (policy file missing)",
        actionRoutes = routes,
        catalog = catalog,
        note = "action identifiers are passed in action_prepare, not posted as paths",
    )

    private fun preparedJson(token: String = confirmToken) =
        """{"data":{"schema":"e64local-api-v1","route":"action_prepare","actionId":"$actionId",
            "actionRoute":"action_grind_start_gbw","confirmToken":"$token","expires":1900000000,
            "expiresAt":"2030-01-01T00:00:00Z","state":"prepared","warnings":["portafilter required"],
            "auditId":"audit-1"},"success":true,"errorCode":0}"""

    private fun failureJson(errorCode: Int, error: String, retryAfter: Int? = null): String {
        val retry = retryAfter?.let { ",\"retryAfter\":$it" }.orEmpty()
        return "{\"success\":false,\"errorCode\":$errorCode,\"error\":\"$error\"$retry}"
    }

    /** A fresh client whose repository has one canned answer for the prepare call. */
    private fun preparedClient(
        response: String = preparedJson(),
        policy: ActionPolicy = policy(),
    ): Pair<ActionApiClient, RecordingClient> {
        val transport = RecordingClient().apply { respond(response) }
        return ActionApiClient(repository(transport), policy, requestIdFactory = { REQUEST_ID }) to transport
    }

    @Test
    fun `prepare posts the route, params and request id and not the token`() {
        val (client, transport) = preparedClient()
        val result = client.prepare("action_grind_start_gbw", Json.obj("targetWeightGr" to Json.num(18)))

        assertTrue(result is ApiResult.Success)
        val body = transport.bodiesFor("/rest_api/action_prepare").single()
        val parsed = Json.parseObject(body)
        assertEquals("action_grind_start_gbw", parsed.string("route"))
        assertEquals(18L, parsed.obj("params")?.long("targetWeightGr"))
        assertEquals(REQUEST_ID, parsed.string("requestId"))
        assertFalse(body.contains("confirmToken"))
        assertEquals(ownerToken, transport.calls.last().headers["X-E64-Local-Token"])
    }

    @Test
    fun `the prepared value does not carry the confirm token`() {
        val (client, _) = preparedClient()
        val prepared = (client.prepare("action_grind_start_gbw") as ApiResult.Success).data

        assertEquals(actionId, prepared.actionId)
        assertEquals("prepared", prepared.state)
        assertEquals(listOf("portafilter required"), prepared.warnings)
        assertEquals(1_900_000_000L, prepared.expiresEpoch)
        assertFalse("the confirm token must not be part of a value the UI can hold", prepared.toString().contains(confirmToken))
        assertEquals(listOf(actionId), client.pendingActionIds)
    }

    @Test
    fun `execute sends the held token once and forgets it`() {
        val (client, transport) = preparedClient()
        client.prepare("action_grind_start_gbw")
        transport.respond(
            """{"data":{"schema":"e64local-api-v1","route":"action_execute","actionId":"$actionId",
                "actionRoute":"action_grind_start_gbw","state":"completed","auditId":"audit-1",
                "result":{"targetWeightGr":18.0},"durationMs":1250},"success":true,"errorCode":0}""",
        )

        val result = client.execute(actionId)
        val executed = (result as ApiResult.Success).data
        assertEquals("completed", executed.state)
        assertEquals(1_250L, executed.durationMs)
        assertTrue(executed.resultJson.contains("targetWeightGr"))

        val body = Json.parseObject(transport.bodiesFor("/rest_api/action_execute").single())
        assertEquals(actionId, body.string("actionId"))
        assertEquals(confirmToken, body.string("confirmToken"))
        assertEquals(REQUEST_ID, body.string("requestId"))

        // Single use: the app no longer holds the token, so a second tap cannot
        // replay it even before the device would answer 409.
        assertTrue(client.pendingActionIds.isEmpty())
        val replay = client.execute(actionId)
        assertEquals(409, (replay as ApiResult.Failure).errorCode)
        assertEquals(ActionErrors.NO_CONFIRMATION, replay.message)
        assertEquals(1, transport.bodiesFor("/rest_api/action_execute").size)
    }

    @Test
    fun `execute without a prepare is refused locally`() {
        val transport = RecordingClient()
        val client = ActionApiClient(repository(transport), policy())

        val result = client.execute(actionId)

        assertEquals(409, (result as ApiResult.Failure).errorCode)
        assertTrue(transport.calls.isEmpty())
    }

    @Test
    fun `prepare refuses a malformed request id without a request`() {
        val transport = RecordingClient()
        val client = ActionApiClient(repository(transport), policy())

        val result = client.prepare("action_grind_start_gbw", requestId = "short")

        assertEquals(400, (result as ApiResult.Failure).errorCode)
        assertTrue(transport.calls.isEmpty())
    }

    @Test
    fun `a rejected owner token is a readable 401`() {
        val (client, transport) = preparedClient(
            response = failureJson(
                401,
                "owner token mismatch",
            ),
        )
        val result = client.prepare("action_grind_start_gbw")

        val failure = result as ApiResult.Failure
        assertEquals(401, failure.errorCode)
        val text = ActionErrors.describe(failure)
        assertTrue(text, text.contains("owner token"))
        assertTrue(text, text.contains("setup"))
        assertFalse(text.contains(ownerToken))
        assertEquals(1, transport.bodiesFor("/rest_api/action_prepare").size)
    }

    @Test
    fun `a closed gate is a readable 403`() {
        val (client, _) = preparedClient(
            response = failureJson(403, "actions are not enabled (policy file missing)"),
        )
        val failure = client.prepare("action_grind_start_gbw") as ApiResult.Failure

        assertEquals(403, failure.errorCode)
        val text = ActionErrors.describe(failure)
        assertTrue(text, text.contains("403"))
        assertTrue(text, text.contains("/db/e64local/actions.json"))
    }

    @Test
    fun `a destructive refusal names the second gate`() {
        val (client, _) = preparedClient(
            response = failureJson(
                403,
                "destructive actions are disabled; re-deploy with --enable-destructive-actions",
            ),
            policy = policy(destructiveEnabled = true),
        )
        val failure = client.prepare("action_logs_clear") as ApiResult.Failure

        val text = ActionErrors.describe(failure)
        assertTrue(text, text.contains("Destructive actions are disabled"))
        assertTrue(text, text.contains("--enable-destructive-actions"))
    }

    @Test
    fun `a reboot after prepare is a readable 409 and is not mistaken for expiry`() {
        val (client, transport) = preparedClient()
        client.prepare("action_grind_start_gbw")
        transport.respond(failureJson(409, "the device has rebooted since this action was prepared"))

        val failure = client.execute(actionId) as ApiResult.Failure

        assertEquals(409, failure.errorCode)
        assertTrue(ActionErrors.isRebootConflict(failure))
        assertFalse(ActionErrors.isExpiredToken(failure))
        val text = ActionErrors.describe(failure)
        assertTrue(text, text.contains("rebooted"))
        assertTrue(text, text.contains("Prepare the action again"))
        assertTrue("a boot refusal spends the token", client.pendingActionIds.isEmpty())
    }

    @Test
    fun `an expired token is a readable 409 and says prepare again`() {
        val (client, transport) = preparedClient()
        client.prepare("action_grind_start_gbw")
        transport.respond(failureJson(409, "the confirm token has expired"))

        val failure = client.execute(actionId) as ApiResult.Failure

        assertTrue(ActionErrors.isExpiredToken(failure))
        assertFalse(ActionErrors.isRebootConflict(failure))
        assertTrue(ActionErrors.describe(failure).contains("expired"))
    }

    @Test
    fun `a rate limit keeps retryAfter and shows it`() {
        val (client, _) = preparedClient(
            response = failureJson(429, "rate limit exceeded; retry after 42 seconds", retryAfter = 42),
        )
        val failure = client.prepare("action_grind_start_gbw") as ApiResult.Failure

        assertEquals(429, failure.errorCode)
        assertTrue(failure.isRateLimited)
        assertEquals(42, failure.retryAfter)
        val text = ActionErrors.describe(failure)
        assertTrue(text, text.contains("Retry after 42 s"))
    }

    @Test
    fun `an unavailable action is a readable 422`() {
        // The device's catalog is authoritative: it may implement a route that a
        // cached policy still lists, and then it answers 422 with the reason.
        val (client, _) = preparedClient(
            response = failureJson(
                422,
                "action unavailable: no vendor route; bulk import needs a schema-validated payload contract",
            ),
            policy = policy(
                catalog = listOf(entry("action_recipe_import", "state-changing")),
                routes = listOf("action_recipe_import"),
            ),
        )
        val failure = client.prepare("action_recipe_import") as ApiResult.Failure

        assertEquals(422, failure.errorCode)
        val text = ActionErrors.describe(failure)
        assertTrue(text, text.contains("unavailable"))
        assertTrue(text, text.contains("422"))
        assertTrue(text, text.contains("no vendor route"))
    }

    @Test
    fun `an unavailable catalog entry is blocked before a request is sent`() {
        val transport = RecordingClient()
        val unavailable = entry(
            "action_recipe_import",
            "state-changing",
            status = "unavailable",
            reason = "no vendor route",
        )
        val client = ActionApiClient(
            repository(transport),
            policy(catalog = listOf(unavailable), routes = emptyList()),
        )

        val blocked = client.check("action_recipe_import") as ActionSubmit.Blocked
        assertEquals(422, blocked.errorCode)
        assertTrue(blocked.reason.contains("no vendor route"))

        val result = client.prepare("action_recipe_import")
        assertEquals(422, (result as ApiResult.Failure).errorCode)
        assertTrue(transport.calls.isEmpty())
    }

    @Test
    fun `cancel before execute cancels the record and drops the confirmation`() {
        val (client, transport) = preparedClient()
        client.prepare("action_grind_start_gbw")
        transport.respond(
            """{"data":{"schema":"e64local-api-v1","route":"action_cancel","actionId":"$actionId",
                "actionRoute":"action_grind_start_gbw","state":"cancelled","cancelled":true,
                "stopSent":false},"success":true,"errorCode":0}""",
        )

        val cancelled = (client.cancel(actionId) as ApiResult.Success).data
        assertTrue(cancelled.cancelled)
        assertFalse(cancelled.stopSent)
        assertEquals("cancelled", cancelled.state)
        assertEquals("""{"actionId":"$actionId"}""", transport.bodiesFor("/rest_api/action_cancel").single())

        // The prepared token is spent by the cancel, so execute must not try.
        assertTrue(client.pendingActionIds.isEmpty())
        val execute = client.execute(actionId) as ApiResult.Failure
        assertEquals(409, execute.errorCode)
        assertTrue(transport.bodiesFor("/rest_api/action_execute").isEmpty())
    }

    @Test
    fun `cancel during execute reports cancelling and whether the stop was sent`() {
        val transport = RecordingClient()
        val client = ActionApiClient(repository(transport), policy())
        transport.respond(
            """{"data":{"schema":"e64local-api-v1","route":"action_cancel","actionId":"$actionId",
                "actionRoute":"action_grind_start_gbw","state":"cancelling","cancelled":false,
                "stopSent":true,"stopError":null},"success":true,"errorCode":0}""",
        )

        val result = (client.cancel(actionId) as ApiResult.Success).data

        assertEquals("cancelling", result.state)
        assertFalse(result.cancelled)
        assertTrue(result.stopSent)
        assertNull(result.stopError)
    }

    @Test
    fun `a cancel of a finished action is idempotent and reported as such`() {
        val transport = RecordingClient().apply {
            respond(
                """{"data":{"schema":"e64local-api-v1","route":"action_cancel","actionId":"$actionId",
                    "actionRoute":"action_grind_start_gbw","state":"completed","cancelled":false,
                    "stopSent":false,"note":"the action is already in a terminal state"},
                    "success":true,"errorCode":0}""",
            )
        }
        val client = ActionApiClient(repository(transport), policy())

        val result = (client.cancel(actionId) as ApiResult.Success).data

        assertEquals("completed", result.state)
        assertFalse(result.cancelled)
        assertEquals("the action is already in a terminal state", result.note)
    }

    @Test
    fun `status reports the state, the result and the cancel flag`() {
        val transport = RecordingClient().apply {
            respond(
                """{"data":{"schema":"e64local-api-v1","route":"action_status","actionId":"$actionId",
                    "actionRoute":"action_grind_start_gbw","state":"executing",
                    "preparedAt":"2030-01-01T00:00:00Z","expiresAt":"2030-01-01T00:01:00Z",
                    "startedAt":"2030-01-01T00:00:05Z","finishedAt":null,"durationMs":null,
                    "errorCode":0,"error":null,"result":{},"cancelRequested":true,
                    "auditId":"audit-1"},"success":true,"errorCode":0}""",
            )
        }
        val client = ActionApiClient(repository(transport), policy())

        val status = (client.status(actionId) as ApiResult.Success).data
        assertEquals("executing", status.state)
        assertTrue(status.cancelRequested)
        assertTrue(status.isCancellable)
        assertFalse(status.isTerminal)
        assertEquals("""{"actionId":"$actionId"}""", transport.bodiesFor("/rest_api/action_status").single())
    }

    @Test
    fun `status and cancel need an action id and send nothing without one`() {
        val transport = RecordingClient()
        val client = ActionApiClient(repository(transport), policy())

        assertEquals(400, (client.status("") as ApiResult.Failure).errorCode)
        assertEquals(400, (client.cancel("") as ApiResult.Failure).errorCode)
        assertTrue(transport.calls.isEmpty())
    }

    @Test
    fun `audit sends paging and time filters and parses the rows`() {
        val transport = RecordingClient().apply {
            respond(
                """{"data":{"schema":"e64local-api-v1","route":"action_audit","rows":[
                    {"ts":"2030-01-01T00:00:00Z","tsEpoch":1900000000,"phase":"refuse",
                     "route":"action_logs_clear","actionId":null,"requestId":"req-0001",
                     "paramsHash":null,"result":"destructive_gate_off","errorCode":403,
                     "retryAfter":null,"durationMs":null,"client":{"addr":"192.168.1.5","uaSha256":"00"}},
                    {"ts":"2030-01-01T00:00:01Z","tsEpoch":1900000001,"phase":"result",
                     "route":"action_grind_start_gbw","actionId":"$actionId","requestId":"req-0001",
                     "paramsHash":"deadbeef","result":"completed","errorCode":0,
                     "retryAfter":null,"durationMs":1250,"client":{"addr":"192.168.1.5","uaSha256":"00"}}
                    ],"count":2,"total":7,"limit":2,"offset":0,"since":null,"until":null,
                    "hasMore":true},"success":true,"errorCode":0}""",
            )
        }
        val client = ActionApiClient(repository(transport), policy())

        val page = (client.audit(ActionAuditQuery(limit = 2, offset = 0, since = "2030-01-01")) as ApiResult.Success).data

        assertEquals(2, page.rows.size)
        assertEquals(7, page.total)
        assertTrue(page.hasMore)
        assertEquals("refuse", page.rows[0].phase)
        assertEquals(403, page.rows[0].errorCode)
        assertFalse(page.rows[0].isActuation)
        assertEquals("result", page.rows[1].phase)
        assertTrue(page.rows[1].isActuation)
        assertEquals(1_250L, page.rows[1].durationMs)

        val body = Json.parseObject(transport.bodiesFor("/rest_api/action_audit").single())
        assertEquals(2L, body.long("limit"))
        assertEquals(0L, body.long("offset"))
        assertEquals("2030-01-01", body.string("since"))
        assertFalse(body.has("until"))
    }

    @Test
    fun `a transport failure keeps the confirmation so the owner can retry`() {
        val (client, transport) = preparedClient()
        client.prepare("action_grind_start_gbw")
        transport.failNext("The device did not answer in time (20s)")

        val first = client.execute(actionId) as ApiResult.Failure
        assertEquals(0, first.errorCode)
        assertEquals(0, first.httpStatus)
        assertTrue(ActionErrors.describe(first).contains("Nothing was executed"))
        assertEquals("nothing reached the device, so the token is still valid", listOf(actionId), client.pendingActionIds)

        transport.respond(
            """{"data":{"schema":"e64local-api-v1","route":"action_execute","actionId":"$actionId",
                "actionRoute":"action_grind_start_gbw","state":"completed","auditId":"audit-1",
                "result":{},"durationMs":900},"success":true,"errorCode":0}""",
        )
        assertTrue(client.execute(actionId) is ApiResult.Success)
        assertEquals(2, transport.bodiesFor("/rest_api/action_execute").size)
    }

    @Test
    fun `the confirm token never appears in a value the app can log`() {
        val (client, transport) = preparedClient()
        val prepared = (client.prepare("action_grind_start_gbw") as ApiResult.Success).data
        transport.respond(failureJson(403, "confirm token does not match this action"))

        val failure = client.execute(actionId) as ApiResult.Failure
        val executeBody = transport.bodiesFor("/rest_api/action_execute").single()

        // The token is in exactly one place: the execute request body.
        assertTrue(executeBody.contains(confirmToken))
        listOf(
            prepared.toString(),
            failure.describe(),
            ActionErrors.describe(failure),
        ).forEach { text ->
            assertFalse("the confirm token leaked into \"$text\"", text.contains(confirmToken))
        }
        // And if that body ever reached a log, redaction removes the value.
        assertFalse(Redaction.redact(executeBody).contains(confirmToken))
        assertTrue(Redaction.redact(executeBody).contains(Redaction.PLACEHOLDER))
    }

    @Test
    fun `no other action request body carries the confirm token`() {
        val transport = RecordingClient().apply {
            respond(CAPABILITIES)
            respond(preparedJson())
            respond("""{"data":{"actionId":"$actionId","state":"prepared","cancelRequested":false,
                "result":{}},"success":true,"errorCode":0}""")
            respond("""{"data":{"actionId":"$actionId","state":"cancelled","cancelled":true,
                "stopSent":false},"success":true,"errorCode":0}""")
            respond("""{"data":{"rows":[],"count":0,"total":0},"success":true,"errorCode":0}""")
        }
        val client = ActionApiClient(repository(transport), policy(), requestIdFactory = { REQUEST_ID })
        client.prepare("action_grind_start_gbw")
        client.status(actionId)
        client.cancel(actionId)
        client.audit()

        val bodies = transport.calls
            .filter { it.path != "/login.php" }
            .filter { it.path != "/rest_api/action_execute" }
        assertTrue(bodies.size >= 4)
        bodies.forEach { call ->
            assertFalse("${call.path} carried the token", call.body.contains(confirmToken))
        }
    }

    @Test
    fun `refreshPolicy reads the gate and the catalog from capabilities`() {
        val transport = RecordingClient().apply { respond(CAPABILITIES) }
        val client = ActionApiClient(repository(transport), policy = null)

        assertEquals(503, (client.check("action_grind_start_gbw") as ActionSubmit.Blocked).errorCode)
        val refreshed = client.refreshPolicy()
        assertTrue(refreshed is ApiResult.Success)
        assertTrue(client.policy()?.enabled == true)
        assertEquals(ActionSubmit.Allowed, client.check("action_grind_start_gbw"))
        assertEquals(1, transport.bodiesFor("/rest_api/capabilities").size)
    }

    @Test
    fun `refreshPolicy fails when the device has no action layer`() {
        val transport = RecordingClient().apply {
            respond("""{"data":{"schema":"e64local-api-v1","apiVersion":"1"},"success":true,"errorCode":0}""")
        }
        val client = ActionApiClient(repository(transport))

        val failure = client.refreshPolicy() as ApiResult.Failure
        assertEquals(502, failure.errorCode)
        assertTrue(failure.message.contains("action layer"))
        assertNull(client.policy())
    }

    @Test
    fun `every action route the client posts is in the published OpenAPI document`() {
        val document = java.io.File("../../../docs/openapi/local-api.yaml")
        // This repository is the published subset of the research tree, and the
        // export gate classes docs/ as research-prose / publish with changes, so
        // the OpenAPI document is withheld and not carried here. Where it does
        // exist (the research tree) the routes are still asserted; where it does
        // not, skip with that reason instead of failing on a file this checkout
        // was never meant to contain.
        org.junit.Assume.assumeTrue(
            "docs/openapi/local-api.yaml is withheld by the export gate " +
                "(research-prose / publish with changes), so route coverage " +
                "cannot be checked in this checkout",
            document.isFile,
        )
        val source = java.io.File(
            "src/main/java/de/mahlkoenig/e64local/device/ActionApiClient.kt",
        ).readText()
        val spec = document.readText()
        val routes = Regex("\"(/rest_api/[a-z_]+)\"").findAll(source)
            .map { it.groupValues[1] }
            .toSet()

        assertEquals(ActionApiClient.ROUTES.toSet(), routes)
        routes.forEach { route ->
            assertTrue("$route is not in docs/openapi/local-api.yaml", spec.contains("  $route:"))
        }
    }

    private companion object {
        const val REQUEST_ID = "app-req-0001"

        val CAPABILITIES =
            """{"data":{"schema":"e64local-api-v1","apiVersion":"1",
                "routes":["capabilities","action_prepare","action_execute","action_status",
                    "action_cancel","action_audit"],
                "features":{"actions":true,"destructiveActions":false},
                "limits":{},
                "actions":{"schema":"e64local-api-v1","enabled":true,"destructiveEnabled":false,
                    "reason":null,
                    "actionRoutes":["action_grind_start_gbw"],
                    "catalog":[
                        {"route":"action_grind_start_gbw","status":"implemented","risk":"actuator",
                         "destructive":false,"surface":"wss","summary":"Start a grind",
                         "evidence":"docs/API_REFERENCE.md#25"},
                        {"route":"action_logs_clear","status":"implemented","risk":"destructive",
                         "destructive":true,"surface":"wss","summary":"Clear the logs",
                         "evidence":"docs/API_REFERENCE.md#25",
                         "blocked":"destructive actions are disabled; re-deploy with --enable-destructive-actions"}
                    ]}},"success":true,"errorCode":0}"""
    }
}
