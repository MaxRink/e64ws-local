package de.mahlkoenig.e64local.device

import java.io.IOException
import de.mahlkoenig.e64local.core.ApiResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The JVM tests never open a socket. This subclass replaces only the transport
 * call, so header, body and cookie behaviour of the repository is exercised
 * exactly as in the app.
 */
class LocalApiRepositoryTest {

    private class RecordingClient(
        private val responses: MutableList<TransportResponse> = mutableListOf(),
        private val error: IOException? = null,
        private val loginSucceeds: Boolean = true,
        private val requireSession: Boolean = false,
    ) : DeviceHttpClient(
        GrinderEndpoint(HOST),
        CookieJar(),
        PinnedTrustManager("00"),
    ) {
        val calls = mutableListOf<Pair<String, String>>()
        val forms = mutableListOf<Map<String, String>>()

        fun respond(json: String, status: Int = 200) {
            responses += TransportResponse(status, json, "application/json", emptyList(), null)
        }

        fun respondHtml(html: String, status: Int = 200) {
            responses += TransportResponse(status, html, "text/html", emptyList(), null)
        }

        override fun postForm(path: String, fields: Map<String, String>): TransportResponse {
            if (path != "/login.php") error("unexpected form post $path")
            forms += fields
            if (!loginSucceeds) {
                return TransportResponse(200, "<html>wrong password</html>", "text/html", emptyList(), null)
            }
            cookieJar.storeFromSetCookie(listOf("PHPSESSID=sess"), HOST)
            return TransportResponse(200, "", "text/html", listOf("PHPSESSID=sess"), null)
        }

        override fun postJson(path: String, json: String, extraHeaders: Map<String, String>): TransportResponse {
            calls += path to json
            if (requireSession && cookieJar.headerFor(HOST, path) == null) {
                // What the vendor dispatcher does without a PHP session.
                return TransportResponse(200, "<html>login</html>", "text/html", emptyList(), null)
            }
            error?.let { throw TransportException(it.message ?: "error", it) }
            if (responses.isEmpty()) error("no canned response")
            return responses.removeAt(0)
        }

        companion object {
            const val HOST = "192.168.1.100"
        }
    }

    private val token = "a".repeat(64)

    private fun repository(
        client: RecordingClient,
        token: String? = "a".repeat(64),
        observed: MutableList<JsonRequest> = mutableListOf(),
        password: () -> String? = { "" },
    ) = LocalApiRepository(
        GrinderEndpoint(RecordingClient.HOST),
        client,
        client.cookieJar,
        { token },
        passwordProvider = password,
    ) { observed += it }

    @Test
    fun `owner token is sent as the X-E64-Local-Token header, not in the body`() {
        val client = RecordingClient().apply {
            respond("""{"data":{"apiVersion":"1","routes":[],"features":{},"limits":{}},"success":true,"errorCode":0}""")
        }
        val observed = mutableListOf<JsonRequest>()
        repository(client, observed = observed).capabilities()

        assertEquals("/rest_api/capabilities", client.calls.single().first)
        val headers = observed.single().headers
        assertEquals(token, headers["X-E64-Local-Token"])
        assertFalse(observed.single().body.contains(token))
        assertFalse(observed.single().body.contains("token"))
    }

    @Test
    fun `missing token fails before any request is sent`() {
        val client = RecordingClient()
        val result = repository(client, token = null).capabilities()
        assertTrue(result is de.mahlkoenig.e64local.core.ApiResult.Failure)
        assertEquals(401, (result as de.mahlkoenig.e64local.core.ApiResult.Failure).errorCode)
        assertTrue(client.calls.isEmpty())
    }

    @Test
    fun `log pagination parameters are sent as documented`() {
        val client = RecordingClient().apply {
            respond(
                """{"data":{"route":"grind_log","rows":[],"count":0,"limit":100,"offset":100,
                    "since":"2026-01-01 00:00:00","until":null,"hasMore":false},
                    "success":true,"errorCode":0}""",
            )
        }
        val page = repository(client).grindLog(
            de.mahlkoenig.e64local.core.LogQuery(
                limit = 100,
                offset = 100,
                since = "2026-01-01",
                until = null,
            ),
        )
        assertTrue(page is de.mahlkoenig.e64local.core.ApiResult.Success)
        val body = client.calls.single().second
        assertTrue(body.contains("\"limit\":100"))
        assertTrue(body.contains("\"offset\":100"))
        assertTrue(body.contains("\"since\":\"2026-01-01\""))
        assertFalse(body.contains("until"))
    }

    @Test
    fun `each log route posts to its own path`() {
        val patterns = listOf(
            "grind_log" to { r: LocalApiRepository -> r.grindLog(de.mahlkoenig.e64local.core.LogQuery()) },
            "service_log" to { r: LocalApiRepository -> r.serviceLog(de.mahlkoenig.e64local.core.LogQuery()) },
            "alert_log" to { r: LocalApiRepository -> r.alertLog(de.mahlkoenig.e64local.core.LogQuery()) },
        )
        val ok = """{"data":{"route":"x","rows":[],"count":0,"limit":20,"offset":0,"hasMore":false},"success":true,"errorCode":0}"""
        for ((route, call) in patterns) {
            val client = RecordingClient().apply { respond(ok) }
            call(repository(client))
            assertEquals("/rest_api/$route", client.calls.single().first)
        }
    }

    @Test
    fun `handled failure exposes its errorCode`() {
        val client = RecordingClient().apply {
            respond("""{"error":"dev mode required","success":false,"errorCode":403}""", 403)
        }
        val result = repository(client).machine()
        assertEquals(403, (result as de.mahlkoenig.e64local.core.ApiResult.Failure).errorCode)
    }

    @Test
    fun `transport error becomes a failure rather than an exception`() {
        val client = RecordingClient(error = IOException("host unreachable"))
        val result = repository(client).capabilities()
        assertTrue(result is de.mahlkoenig.e64local.core.ApiResult.Failure)
    }

    @Test
    fun `file route refuses paths outside the allowlist without a request`() {
        val client = RecordingClient()
        val repository = repository(client)
        assertTrue(repository.file("/db/e64local/token") is de.mahlkoenig.e64local.core.ApiResult.Failure)
        assertTrue(repository.file("/etc/passwd") is de.mahlkoenig.e64local.core.ApiResult.Failure)
        assertTrue(repository.file("/log/../db/x") is de.mahlkoenig.e64local.core.ApiResult.Failure)
        assertTrue(client.calls.isEmpty())
    }

    @Test
    fun `file route sends an allowlisted path`() {
        val client = RecordingClient().apply {
            respond("""{"data":{"route":"file","path":"/etc/issue","encoding":"text","content":"dev"},
                "success":true,"errorCode":0}""")
        }
        val result = repository(client).file("/etc/issue")
        assertTrue(result is de.mahlkoenig.e64local.core.ApiResult.Success)
        assertEquals("""{"path":"/etc/issue"}""", client.calls.single().second)
    }

    @Test
    fun `machine identity parses the hashed serial`() {
        val client = RecordingClient().apply {
            respond(
                """{"data":{"schema":"e64local-api-v1","route":"machine","variant":"Hsg",
                    "model":"E64 WS","grinderType":5,"grinderTypeName":"E64 WS","grinderSubType":0,
                    "firmware":"development image","devMode":true,"serialPresent":true,
                    "serialSha256":"${"0".repeat(64)}","serialNote":"hashed"},
                    "success":true,"errorCode":0}""",
            )
        }
        val result = repository(client).machine()
        val machine = (result as de.mahlkoenig.e64local.core.ApiResult.Success).data
        assertEquals("E64 WS", machine.model)
        assertEquals("Hsg", machine.variant)
        assertTrue(machine.devMode)
        assertEquals("0".repeat(64), machine.serialSha256)
    }

    @Test
    fun `config flattening keeps dotted paths`() {
        val out = LinkedHashMap<String, String>()
        LocalApiRepository.flattenConfig(
            de.mahlkoenig.e64local.core.Json.parseObject("""{"a":{"b":"c"},"n":1,"k":true}"""),
            "",
            out,
        )
        assertEquals("c", out["a.b"])
        assertEquals("1", out["n"])
        assertEquals("true", out["k"])
    }

    @Test
    fun `allowlist mirrors the device module`() {
        assertTrue(AllowedPaths.isAllowed("/etc/issue"))
        assertTrue(AllowedPaths.isAllowed("/tmp/FirmwareUpdateState.json"))
        assertTrue(AllowedPaths.isAllowed("/log/messages"))
        assertFalse(AllowedPaths.isAllowed("/logfoo/x"))
        assertFalse(AllowedPaths.isAllowed("/proc/self/environ"))
        assertFalse(AllowedPaths.isAllowed("/sys/class/gpio"))
        assertFalse(AllowedPaths.isAllowed("relative/path"))
        assertFalse(AllowedPaths.isAllowed("/etc/issue\u0000"))
    }

    @Test
    fun `ws_token is the last read route and is parsed`() {
        val client = RecordingClient().apply {
            respond(
                """{"data":{"schema":"e64local-api-v1","route":"ws_token",
                    "token":"${"c".repeat(64)}","expires":1900000000,
                    "warning":"this token authorises WSS commands; it is not a read-only data credential"},
                    "success":true,"errorCode":0}""",
            )
        }
        val result = repository(client).wsToken()

        val minted = (result as de.mahlkoenig.e64local.core.ApiResult.Success).data
        assertEquals("c".repeat(64), minted.token)
        assertEquals(1_900_000_000L, minted.expires)
        assertEquals("/rest_api/ws_token", client.calls.single().first)
    }

    @Test
    fun `a minted ws token never prints its value`() {
        val minted = WsToken("d".repeat(64), 1_900_000_000L, "warning")
        assertFalse(minted.toString().contains("d".repeat(64)))
        assertTrue(minted.toString().contains(de.mahlkoenig.e64local.core.Redaction.PLACEHOLDER))
    }

    @Test
    fun `cookie jar is consulted for the session state`() {
        val jar = CookieJar()
        val client = RecordingClient()
        val repository = LocalApiRepository(GrinderEndpoint("h"), client, jar, tokenProvider = { null })
        assertFalse(repository.hasSession)
        jar.storeFromSetCookie(listOf("PHPSESSID=x"), "h")
        assertTrue(repository.hasSession)
    }

    @Test
    fun `a token-only request is refused before any route is called`() {
        val client = RecordingClient(requireSession = true)
        val result = repository(client, password = { null }).capabilities()

        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).errorCode)
        assertTrue(client.calls.isEmpty())
        assertTrue(client.forms.isEmpty())
    }

    @Test
    fun `a route call logs in once with the stored password and keeps the session`() {
        val client = RecordingClient(requireSession = true).apply { respond(CAPABILITIES) }
        val repository = repository(client, password = { "owner-pw" })

        assertTrue(repository.capabilities() is ApiResult.Success)
        assertEquals(1, client.forms.size)
        assertEquals("1", client.forms.single()["login"])
        assertEquals("Owner", client.forms.single()["userRole"])
        assertEquals("owner-pw", client.forms.single()["password"])
        assertTrue(repository.hasSession)

        // The next read reuses the cookie instead of logging in again.
        client.respond(CAPABILITIES)
        assertTrue(repository.capabilities() is ApiResult.Success)
        assertEquals(1, client.forms.size)
    }

    @Test
    fun `a rejected login fails the read without sending it`() {
        val client = RecordingClient(requireSession = true, loginSucceeds = false)
        val result = repository(client, password = { "wrong" }).capabilities()

        assertTrue(result is ApiResult.Failure)
        assertTrue("a route must not be called without a session", client.calls.isEmpty())
    }

    @Test
    fun `an expired session clears the jar so the next read can log in again`() {
        val client = RecordingClient(requireSession = true).apply { respondHtml("<html>login</html>") }
        val repository = repository(client, password = { "owner-pw" })

        assertTrue(repository.capabilities() is ApiResult.Failure)
        assertFalse(repository.hasSession)
    }

    @Test
    fun `every route the repository calls is in the published OpenAPI document`() {
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
            "src/main/java/de/mahlkoenig/e64local/device/LocalApiRepository.kt",
        ).readText()
        val spec = document.readText()
        val routes = Regex("\"(/rest_api/[a-z_]+)\"").findAll(source)
            .map { it.groupValues[1] }
            .toSet()

        assertTrue("no routes found in the client", routes.isNotEmpty())
        routes.forEach { route ->
            assertTrue("$route is not in docs/openapi/local-api.yaml", spec.contains("  $route:"))
        }
    }

    private companion object {
        const val CAPABILITIES =
            """{"data":{"schema":"e64local-api-v1","apiVersion":"1","routes":[],""" +
                """"features":{},"limits":{}},"success":true,"errorCode":0}"""
    }
}
