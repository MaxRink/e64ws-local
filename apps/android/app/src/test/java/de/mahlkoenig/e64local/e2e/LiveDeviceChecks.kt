package de.mahlkoenig.e64local.e2e

import de.mahlkoenig.e64local.core.ApiResult
import de.mahlkoenig.e64local.core.Json
import de.mahlkoenig.e64local.core.LogQuery
import de.mahlkoenig.e64local.core.Redaction
import de.mahlkoenig.e64local.device.CookieJar
import de.mahlkoenig.e64local.device.DeviceHttpClient
import de.mahlkoenig.e64local.device.PinnedTrustManager
import java.security.MessageDigest

/**
 * Everything the app can prove against the simulator exactly as the runner
 * starts it: the auth path, the capabilities handshake, all eleven read routes
 * the app models, and the transport invariants behind them.
 *
 * Every request goes through [SimulatorClient], i.e. through the production
 * `DeviceHttpClient` and `LocalApiRepository`.
 */
internal class LiveDeviceChecks(
    private val report: E2EReport,
    private val device: SimulatorClient,
    private val token: String,
    private val password: String,
) {

    fun run() {
        reachability()
        loginRoute()
        fixtureSession()
        capabilities()
        readRoutes()
        transportInvariants()
    }

    // -- reachability ---------------------------------------------------------

    private fun reachability() {
        report.verify("target: the simulator at ${device.base.raw} answers through the app's pinned TLS client") {
            val answer = device.client.get("/rest_api/ping")
            require(answer.status == 200) { "HTTP ${answer.status}: ${answer.body.take(160)}" }
            require(answer.body.contains("\"simulator\":true")) { "the ping said ${answer.body.take(160)}" }
            // Reading the wire log straight after the call is sound, and no
            // waiting is needed: the bridge records an exchange before it answers
            // it, so an answer the app holds is already in the log. The other
            // checks below rely on the same invariant; BridgeOrderingUnitTest
            // pins it.
            require(device.exchanges.any { it.path == "/rest_api/ping" }) {
                "the request did not cross the loopback bridge"
            }
        }
    }

    // -- auth -----------------------------------------------------------------

    private fun loginRoute() {
        device.clearWire()
        val attempt = device.repository.login(password)

        report.verify("login: the app posts the vendor form (login=1, userRole=Owner, password) to /login.php") {
            val posted = device.exchangesTo("/login.php")
            require(posted.size == 1) { "expected exactly one POST /login.php, saw ${posted.size}" }
            val entry = posted.single()
            require(entry.method == "POST") { "the login was sent as ${entry.method}" }
            val contentType = entry.requestHeaders.entries
                .firstOrNull { it.key.equals("Content-Type", ignoreCase = true) }
                ?.value
                .orEmpty()
            require(contentType.contains("application/x-www-form-urlencoded")) {
                "the login form was sent as '$contentType'"
            }
            require(entry.requestBody.contains("login=1")) { "body=${entry.requestBody}" }
            require(entry.requestBody.contains("userRole=Owner")) { "body=${entry.requestBody}" }
            require(entry.requestBody.contains("password=")) { "the form carries no password field" }
            require(entry.requestHeaders.keys.none { it.equals("X-E64-Local-Token", ignoreCase = true) }) {
                "the vendor login must not carry the owner token"
            }
        }

        report.verify("login: the simulator serves no /login.php, so the vendor login fails closed") {
            val entry = device.exchangesTo("/login.php").single()
            // The simulator parses every POST body as JSON before it dispatches, so
            // the vendor form lands on its generic body error: an answer, but never
            // a session. A real dispatcher answers the HTML login page instead.
            require(entry.status in setOf(400, 404)) {
                "the simulator answered HTTP ${entry.status} for /login.php: ${entry.responseBody.take(160)}"
            }
            require(!entry.responseBody.contains("PHPSESSID")) { "the login answer carried a session cookie" }
            val failure = attempt as? ApiResult.Failure
                ?: throw E2EFailure("login() reported success although no session cookie was ever set")
            require(failure.message.contains("session cookie")) { "the failure says: ${failure.message}" }
            require(!device.repository.hasSession) { "the app believes it holds a vendor session" }
            require(device.cookieJar.isEmpty()) { "the jar holds ${device.cookieJar.names()}" }
        }

        report.verify("login: the refusal carries neither the password nor the owner token") {
            val failure = attempt as ApiResult.Failure
            val text = failure.message + " " + failure.describe()
            require(!text.contains(password)) { "the login failure echoes the password" }
            require(!text.contains(token)) { "the login failure echoes the owner token" }
        }
    }

    /**
     * The simulator's fixture session endpoint (`POST /rest_api/login`, JSON
     * `{userRole, password}`) is what stands in for the vendor dispatcher's
     * form login. It is reached through the app's own client, and the session
     * cookie it sets is the same jar every later route call uses.
     */
    private fun fixtureSession() {
        val body = Json.write(
            Json.obj(
                "userRole" to Json.str("Owner"),
                "password" to Json.str(password),
            ),
        )
        report.verify("session: the fixture session API answers through the app's own HTTP client and fills its jar") {
            val answer = device.client.postJson("/rest_api/login", body)
            require(answer.status == 200) { "the session endpoint answered HTTP ${answer.status}: ${answer.body.take(200)}" }
            require(answer.body.contains("\"success\":true")) { "the endpoint said ${answer.body.take(200)}" }
            require(answer.setCookieHeaders.any { it.startsWith("PHPSESSID=") }) {
                "no PHPSESSID was set: ${answer.setCookieHeaders}"
            }
            require(device.cookieJar.names().any { it.equals("PHPSESSID", ignoreCase = true) }) {
                "the app's cookie jar holds ${device.cookieJar.names()}"
            }
            require(device.repository.hasSession) { "the repository does not see the session it just stored" }
        }

        report.verify("session: the session request itself carries no owner token") {
            val entry = device.exchangesTo("/rest_api/login").last()
            require(entry.requestHeaders.keys.none { it.equals("X-E64-Local-Token", ignoreCase = true) }) {
                "the session request carried the owner token"
            }
        }

        report.verify("session: a wrong owner password is refused and stores no cookie") {
            val jar = CookieJar()
            val client = DeviceHttpClient(device.endpoint, jar, PinnedTrustManager(device.pin))
            val answer = client.postJson(
                "/rest_api/login",
                Json.write(Json.obj("userRole" to Json.str("Owner"), "password" to Json.str("not-the-password"))),
            )
            require(answer.status in setOf(400, 401, 422)) { "a wrong password answered HTTP ${answer.status}" }
            require(jar.isEmpty()) { "a refused login stored ${jar.names()}" }
        }
    }

    // -- capabilities ---------------------------------------------------------

    private fun capabilities() {
        val capabilities = report.verify("capabilities: the device answers a valid e64local-api-v1 document") {
            when (val result = device.repository.capabilities()) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("capabilities failed: ${result.describe()}")
            }
        }

        report.verify("capabilities: schema and api version match the published contract") {
            require(capabilities.isLocalApiV1) {
                "schema=${capabilities.schema} apiVersion=${capabilities.apiVersion}"
            }
        }

        report.verify("capabilities: every read route the app models is advertised") {
            val modelled = listOf(
                "capabilities", "machine", "grind_log", "service_log", "alert_log",
                "recipes", "portafilters", "settings", "config", "file", "ws_token",
            )
            val missing = modelled.filterNot { capabilities.routes.contains(it) }
            require(missing.isEmpty()) { "the device does not list $missing" }
            require(capabilities.supports("grind_log")) { "supports() disagrees with routes" }
        }

        report.verify("capabilities: pagination, time filters and the documented limits are reported") {
            require(capabilities.pagination) { "pagination is not advertised" }
            require(capabilities.timeFilters) { "time filters are not advertised" }
            require(capabilities.maxRows == LogQuery.MAX_ROWS) { "maxRows=${capabilities.maxRows}" }
            require(capabilities.maxOffset == LogQuery.MAX_OFFSET) { "maxOffset=${capabilities.maxOffset}" }
            require(capabilities.defaultRows["grind_log"] == 20) { "defaultRows=${capabilities.defaultRows}" }
            require(capabilities.maxFileBytes == 1_048_576) { "maxFileBytes=${capabilities.maxFileBytes}" }
            require((capabilities.serverTime ?: 0L) > 0L) { "serverTime is missing" }
        }

        val actions = report.verify("capabilities: the action layer is reported with its gate, reason and catalog") {
            val policy = capabilities.actions ?: throw E2EFailure("the document carries no actions object")
            require(capabilities.actionsEnabled == policy.enabled) {
                "features.actions=${capabilities.actionsEnabled} but actions.enabled=${policy.enabled}"
            }
            require(capabilities.destructiveEnabled == policy.destructiveEnabled) {
                "features.destructiveActions=${capabilities.destructiveEnabled} but " +
                    "actions.destructiveEnabled=${policy.destructiveEnabled}"
            }
            if (policy.enabled) {
                require(policy.reason == null) { "reason=${policy.reason}" }
                require(policy.actionRoutes.isNotEmpty()) { "the gate is open but no route is dispatchable" }
                require(capabilities.routes.contains("action_prepare")) {
                    "the gate is open but capabilities does not list the meta routes"
                }
            } else {
                require(!policy.reason.isNullOrEmpty()) { "a closed gate must explain itself" }
                require(policy.actionRoutes.isEmpty()) { "actionRoutes=${policy.actionRoutes}" }
            }
            policy
        }

        report.verify("capabilities: the whole action catalog is reported whatever the gate says") {
            require(actions.catalog.size >= 20) { "the catalog holds ${actions.catalog.size} entries" }
            require(actions.catalog.any { it.isImplemented }) { "no implemented entry" }
            require(actions.catalog.any { !it.isImplemented && !it.reason.isNullOrEmpty() }) {
                "no unavailable entry carries a reason"
            }
            val destructive = actions.catalog.filter { it.destructive && it.isImplemented }
            require(destructive.isNotEmpty()) { "the catalog names no destructive action" }
            if (!actions.destructiveEnabled) {
                require(destructive.all { it.blocked == "destructive actions are disabled" }) {
                    "a destructive entry does not carry the device's block reason"
                }
                require(destructive.none { it.isDispatchable }) {
                    "a destructive entry is advertised as dispatchable while the gate is closed"
                }
            }
            require(actions.entry("action_agsa_stop")?.isImplemented == true) {
                "action_agsa_stop is missing from the catalog"
            }
        }

        if (actions.enabled) {
            report.verify("capabilities: an open gate ships the policy bounds, rate limits and token TTLs") {
                val body = device.exchangesTo("/rest_api/capabilities")
                    .lastOrNull { it.status == 200 }
                    ?.responseBody
                    ?: throw E2EFailure("no capabilities answer was recorded")
                val policy = Json.parseObject(body).obj("data")?.obj("actions")?.obj("policy")
                    ?: throw E2EFailure("the enabled policy carries no policy object")
                require(policy.obj("bounds") != null) { "the policy carries no bounds" }
                require(policy.obj("rateLimits") != null) { "the policy carries no rate limits" }
                require(policy.obj("tokenTtlSec") != null) { "the policy carries no token TTLs" }
            }
        }
    }

    // -- read routes ----------------------------------------------------------

    private fun readRoutes() {
        val machine = report.verify("read route machine: the identity document parses into the app's model") {
            ok(device.repository.machine())
        }
        report.verify("read route machine: model, firmware and dev mode come from the device") {
            require(machine.model.isNotEmpty() && machine.model != "unknown") { "model=${machine.model}" }
            require(machine.firmware.startsWith("V01.16")) { "firmware=${machine.firmware}" }
            require(machine.devMode) { "the simulator reports dev mode off" }
            require(machine.grinderTypeName.isNotEmpty()) { "grinderTypeName is empty" }
        }
        report.verify("read route machine: the serial is only ever reported as a SHA-256") {
            require(machine.serialPresent) { "the device says no serial is present" }
            val expected = MessageDigest.getInstance("SHA-256")
                .digest("SIM0000000001".toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            require(machine.serialSha256 == expected) { "serialSha256=${machine.serialSha256}" }
            require(machine.serialNote.isNotEmpty()) { "the serial note is empty" }
            require(device.exchanges.none { it.responseBody.contains("SIM0000000001") }) {
                "a device response carries the raw serial number"
            }
        }

        report.verify("read route grind_log: the default page parses with the module's paging values") {
            val page = ok(device.repository.grindLog(LogQuery()))
            require(page.route == "grind_log") { "route=${page.route}" }
            require(page.limit == 20) { "limit=${page.limit}" }
            require(page.offset == 0) { "offset=${page.offset}" }
            require(page.count == page.rows.size) { "count=${page.count} rows=${page.rows.size}" }
        }
        report.verify("read route grind_log: limit and offset reach the device") {
            val page = ok(device.repository.grindLog(LogQuery(limit = 1, offset = 5)))
            require(page.limit == 1) { "limit=${page.limit}" }
            require(page.offset == 5) { "offset=${page.offset}" }
        }
        report.verify("read route grind_log: the since/until filter is normalized by the device and echoed") {
            val page = ok(device.repository.grindLog(LogQuery(since = "2026-01-01", until = "2026-01-31")))
            require(page.since == "2026-01-01 00:00:00") { "since=${page.since}" }
            require(page.until == "2026-01-31 23:59:59") { "until=${page.until}" }
        }

        report.verify("read route service_log: seeded rows arrive with the module's redaction applied") {
            // The default page (500 rows) is used on purpose: the simulator appends a
            // row per successful session login, so a long-lived simulator holds more
            // rows than a fresh one and the seeded row can be deep in the page.
            val page = ok(device.repository.serviceLog(LogQuery()))
            require(page.rows.isNotEmpty()) { "no service rows" }
            require(page.count == page.rows.size) { "count=${page.count}" }
            val details = page.rows.joinToString(" ") { it.columns["event_details"].orEmpty() }
            require(!details.contains("000000123456")) { "the raw serial survived in the service log" }
            require(details.contains("<redacted>")) { "no redaction marker in the service log: ${details.take(200)}" }
        }

        report.verify("read route alert_log: the seeded alert parses") {
            val page = ok(device.repository.alertLog(LogQuery()))
            require(page.route == "alert_log") { "route=${page.route}" }
            val row = page.rows.firstOrNull() ?: throw E2EFailure("no alert rows")
            require(row.columns["alert_type"] == "WaterEmpty") { "alert_type=${row.columns["alert_type"]}" }
        }

        report.verify("read route recipes: the recipe rows parse") {
            val rows = ok(device.repository.recipes())
            require(rows.isNotEmpty()) { "no recipes" }
            require(rows.first().columns.containsKey("recipe_mode")) {
                "columns=${rows.first().columns.keys}"
            }
        }

        report.verify("read route portafilters: the portafilter row parses") {
            val rows = ok(device.repository.portafilters())
            require(rows.isNotEmpty()) { "no portafilters" }
            require(rows.first().columns["portafilter_id"] == "1") {
                "portafilter_id=${rows.first().columns["portafilter_id"]}"
            }
        }

        report.verify("read route settings: sensitive keys are withheld and listed as redacted") {
            val page = ok(device.repository.settings())
            require(page.values.isNotEmpty()) { "no settings" }
            require(page.values.keys.none { it.contains("LoginData", ignoreCase = true) }) {
                "a login blob was returned"
            }
            require(page.values.values.none { it == "should-not-appear" || it == "sim-wifi-secret" }) {
                "a fixture credential survived the module's redaction"
            }
            require(page.redacted.contains("Role.Owner.LoginData")) { "redacted=${page.redacted}" }
            require(page.redacted.contains("Wifi.StaPassword")) { "redacted=${page.redacted}" }
        }

        report.verify("read route config: the tree is flattened and credentials are redacted") {
            val page = ok(device.repository.config())
            require(page.values["_e64local_schema"] == "e64local-api-v1") {
                "schema=${page.values["_e64local_schema"]}"
            }
            require(page.values["grinderSn"] == "<redacted>") { "grinderSn=${page.values["grinderSn"]}" }
            require(page.values["productionWifiPassword"] == "<redacted>") {
                "productionWifiPassword=${page.values["productionWifiPassword"]}"
            }
            require(page.values.values.none { it.contains("factory-secret") }) {
                "a fixture credential survived the module's redaction"
            }
            require(page.values["targetWeightGr"] == "18.0") { "targetWeightGr=${page.values["targetWeightGr"]}" }
        }

        report.verify("read route file: an allowlisted path is read") {
            val issue = ok(device.repository.file("/etc/issue"))
            require(issue.path == "/etc/issue") { "path=${issue.path}" }
            require(!issue.isBinary) { "encoding=${issue.encoding}" }
            require(issue.content.contains("development image")) { "content=${issue.content.take(120)}" }
        }
        report.verify("read route file: a log file is redacted before it reaches the app") {
            val content = ok(device.repository.file("/log/messages")).content
            require(content.isNotEmpty()) { "the log file is empty" }
            require(!content.contains("sim-log-secret")) { "the log password survived: $content" }
            require(content.contains("<redacted>")) { "no redaction marker in the log file" }
        }
        report.verify("read route file: a path outside the allowlist is refused without a request") {
            val before = device.exchanges.size
            val failure = device.repository.file("/etc/passwd") as? ApiResult.Failure
                ?: throw E2EFailure("the app asked the device for a path outside the allowlist")
            require(failure.errorCode == 400) { "errorCode=${failure.errorCode}" }
            require(device.exchanges.size == before) { "a request was sent for /etc/passwd" }
        }

        val wsToken = report.verify("read route ws_token: the device mints a token the app parses") {
            ok(device.repository.wsToken())
        }
        report.verify("read route ws_token: the value is a credential and the model prints only a placeholder") {
            require(wsToken.token.matches(Regex("[0-9a-f]{32,64}"))) {
                "token=${Redaction.tokenHint(wsToken.token)}"
            }
            require(wsToken.token != token) { "the minted ws token equals the owner token" }
            require(wsToken.expires > 0L) { "expires=${wsToken.expires}" }
            require(wsToken.warning.isNotEmpty()) { "the device sent no warning" }
            require(!wsToken.toString().contains(wsToken.token)) { "WsToken.toString() prints the token" }
            require(wsToken.toString().contains(Redaction.PLACEHOLDER)) { "WsToken.toString() ${wsToken}" }
            require(device.requests.none { it.body.contains(wsToken.token) }) {
                "the minted ws token was sent back to the device"
            }
        }
    }

    // -- transport ------------------------------------------------------------

    private fun transportInvariants() {
        report.verify("transport: every route request carried the owner token header") {
            val routed = device.requests.filter { it.path.startsWith("/rest_api/") && it.path != "/rest_api/login" }
            require(routed.isNotEmpty()) { "no route request was recorded" }
            val wrong = routed.filter { it.headers["X-E64-Local-Token"] != token }
            require(wrong.isEmpty()) { "${wrong.size} route request(s) were sent without the owner token" }
        }

        report.verify("transport: every route request carried the vendor session cookie") {
            val routed = device.exchanges.filter {
                it.path.startsWith("/rest_api/") && it.path != "/rest_api/login"
            }
            require(routed.isNotEmpty()) { "no route request crossed the bridge" }
            val missing = routed.filter { entry ->
                val cookie = entry.requestHeaders.entries
                    .firstOrNull { it.key.equals("Cookie", ignoreCase = true) }
                    ?.value
                    .orEmpty()
                !cookie.contains("PHPSESSID=")
            }
            require(missing.isEmpty()) { "${missing.size} route request(s) were sent without a session: ${missing.map { it.path }}" }
        }

        report.verify("transport: the owner token never appears in a request body") {
            val leaks = device.exchanges.filter { it.requestBody.contains(token) }
            require(leaks.isEmpty()) { "the owner token was written into a body: ${leaks.map { it.path }}" }
        }

        report.verify("transport: every answer is the simulator's own, the bridge invents nothing") {
            val answers = device.exchanges.filter {
                it.path.startsWith("/rest_api/") && it.path != "/rest_api/login"
            }
            require(answers.isNotEmpty()) { "no answers were recorded" }
            val foreign = answers.filter { !it.responseBody.contains("\"simulator\":true") }
            require(foreign.isEmpty()) { "${foreign.map { it.path }} did not come from the simulator" }
        }

        report.verify("auth: a wrong owner token is refused with 401 and no data") {
            val rogue = device.repositoryWithToken("0".repeat(64))
            val failure = rogue.capabilities() as? ApiResult.Failure
                ?: throw E2EFailure("the device accepted a made-up owner token")
            val answer = device.lastExchangeTo("/rest_api/capabilities")
            require(answer?.status == 401) { "the device answered HTTP ${answer?.status}" }
            require(answer.responseBody.contains("owner token required")) {
                "the device's body is ${answer.responseBody.take(160)}"
            }
            require(failure.errorCode == 401) {
                "the app reported errorCode=${failure.errorCode}: ${failure.message}"
            }
            require(failure.isTokenProblem) { "the app does not classify the answer as a token problem" }
            // The app's client is HttpURLConnection, which withholds the body of a
            // 401, so the app can only report that the answer was empty. That is a
            // property of the production stack, recorded here rather than papered
            // over: the device did explain itself, the app cannot read it.
            require(
                failure.message == "empty response from device" || failure.message.contains("owner token"),
            ) { "the app's text for a 401 is: ${failure.message}" }
            if (failure.message == "empty response from device") {
                report.note(
                    "HttpURLConnection drops the body of a 401, so the app reports 'empty response " +
                        "from device' for a real token refusal; the device's own reason is only visible " +
                        "on the wire",
                )
            }
        }

        report.verify("auth: a lost session fails closed and never posts a route with only the token") {
            device.cookieJar.clear()
            device.clearRequests()
            val failure = device.repository.machine() as? ApiResult.Failure
                ?: throw E2EFailure("a route answered without a vendor session")
            require(failure.message.contains("session cookie")) { "message=${failure.message}" }
            require(device.requests.none { it.path.startsWith("/rest_api/machine") }) {
                "a route request was sent although no session could be established"
            }
            // The fixture session is re-established through the app's client so the
            // checks that follow still have one.
            val restored = device.client.postJson(
                "/rest_api/login",
                Json.write(Json.obj("userRole" to Json.str("Owner"), "password" to Json.str(password))),
            )
            require(restored.status == 200) { "could not re-establish the session: HTTP ${restored.status}" }
            require(device.repository.machine() is ApiResult.Success) { "the session was not restored" }
        }

        report.verify("transport: read answers are versioned envelopes, not error pages") {
            val envelope = device.exchangesTo("/rest_api/capabilities").lastOrNull { it.status == 200 }
                ?.responseBody
                ?: throw E2EFailure("no successful capabilities answer was recorded")
            require(envelope.contains("\"schema\":\"e64local-api-v1\"")) {
                "the capabilities envelope is ${envelope.take(160)}"
            }
            require(device.exchanges.none { it.responseBody.trimStart().startsWith("<") }) {
                "the device answered with HTML"
            }
        }
    }

    private fun <T> ok(result: ApiResult<T>): T = when (result) {
        is ApiResult.Success -> result.data
        is ApiResult.Failure -> throw E2EFailure("the device refused the route: ${result.describe()}")
    }
}
