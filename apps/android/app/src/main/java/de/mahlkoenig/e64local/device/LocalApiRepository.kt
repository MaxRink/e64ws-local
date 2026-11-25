package de.mahlkoenig.e64local.device

import de.mahlkoenig.e64local.core.ApiResult
import de.mahlkoenig.e64local.core.AuthHeader
import de.mahlkoenig.e64local.core.Envelope
import de.mahlkoenig.e64local.core.Json
import de.mahlkoenig.e64local.core.JsonParseException
import de.mahlkoenig.e64local.core.JsonValue
import de.mahlkoenig.e64local.core.LogPage
import de.mahlkoenig.e64local.core.LogQuery
import de.mahlkoenig.e64local.core.Redaction
import de.mahlkoenig.e64local.core.StringRow
import de.mahlkoenig.e64local.core.toRows

/** Machine identity from `machine`. The raw serial is never returned by the device. */
data class MachineInfo(
    val model: String,
    val variant: String,
    val firmware: String,
    val grinderTypeName: String,
    val devMode: Boolean,
    val serialPresent: Boolean,
    val serialSha256: String?,
    val serialNote: String,
) {
    companion object {
        fun from(data: JsonValue.Obj) = MachineInfo(
            model = data.string("model") ?: "unknown",
            variant = data.string("variant") ?: "unknown",
            firmware = data.string("firmware").orEmpty(),
            grinderTypeName = data.string("grinderTypeName") ?: "unknown",
            devMode = data.bool("devMode") ?: false,
            serialPresent = data.bool("serialPresent") ?: false,
            serialSha256 = data.string("serialSha256"),
            serialNote = data.string("serialNote").orEmpty(),
        )
    }
}

/** The `capabilities` handshake. */
data class Capabilities(
    val schema: String,
    val apiVersion: String,
    val routes: List<String>,
    val actionsEnabled: Boolean,
    val pagination: Boolean,
    val timeFilters: Boolean,
    val maxRows: Int,
    val defaultRows: Map<String, Int>,
    val maxOffset: Int,
    val maxFileBytes: Int,
    val serverTime: Long?,
    /**
     * `data.actions`: the action gate, its catalog and its policy. Reported even
     * when the gate is closed, so the UI can explain why a route is not
     * dispatchable instead of hiding it. `null` when the module predates the
     * action layer or the document did not carry the object.
     */
    val actions: ActionPolicy? = null,
) {
    fun supports(route: String): Boolean = routes.contains(route)

    /**
     * Last check before a destructive action may be offered: the device has to
     * say so itself. A client-side flag would be a lie the UI tells itself.
     */
    val destructiveEnabled: Boolean get() = actions?.destructiveEnabled == true

    /**
     * True only for the reviewed module. A 200 `success: true` envelope is not
     * enough on its own: any local PHP page could answer with an empty object,
     * so the schema and the API version must both match the published contract.
     */
    val isLocalApiV1: Boolean
        get() = schema == Envelope.SCHEMA && apiVersion == API_VERSION

    companion object {
        const val API_VERSION = "1"

        fun from(data: JsonValue.Obj): Capabilities {
            val features = data.obj("features")
            val limits = data.obj("limits")
            val defaults = limits?.obj("defaultRows")?.entries.orEmpty()
                .mapNotNull { (key, value) -> (value as? JsonValue.Num)?.toLongOrNull()?.let { key to it.toInt() } }
                .toMap()
            return Capabilities(
                schema = data.string("schema").orEmpty(),
                apiVersion = data.string("apiVersion").orEmpty(),
                routes = data.array("routes")?.items?.mapNotNull { (it as? JsonValue.Str)?.value }.orEmpty(),
                actionsEnabled = features?.bool("actions") ?: false,
                pagination = features?.bool("pagination") ?: false,
                timeFilters = features?.bool("timeFilters") ?: false,
                maxRows = limits?.long("maxRows")?.toInt() ?: LogQuery.MAX_ROWS,
                defaultRows = defaults,
                maxOffset = limits?.long("maxOffset")?.toInt() ?: LogQuery.MAX_OFFSET,
                maxFileBytes = limits?.long("maxFileBytes")?.toInt() ?: 1_048_576,
                serverTime = data.long("serverTime"),
                actions = data.obj("actions")?.let { ActionPolicy.from(it) },
            )
        }
    }
}

/** Key/value pages (`settings`, `config`, `file`) and simple row pages. */
data class KeyValuePage(val values: Map<String, String>, val redacted: List<String>)

data class FileContent(val path: String, val encoding: String, val content: String) {
    val isBinary: Boolean get() = encoding.equals("base64", ignoreCase = true)
}

/**
 * One minted WSS token. It authorises actuator commands on the device's own
 * command socket, so it is treated as a credential: [toString] never contains
 * it and the app does not display or store it.
 */
class WsToken(val token: String, val expires: Long, val warning: String) {
    override fun toString(): String = "WsToken(expires=$expires, token=${Redaction.PLACEHOLDER})"

    companion object {
        fun from(data: JsonValue.Obj) = WsToken(
            token = data.string("token").orEmpty(),
            expires = data.long("expires") ?: 0L,
            warning = data.string("warning").orEmpty(),
        )
    }
}

/**
 * One outbound request as the repository issues it. Exposed so tests can
 * assert the auth header and body without a device or a network.
 */
data class JsonRequest(val path: String, val body: String, val headers: Map<String, String>)

/**
 * Typed client for the Local Owner API.
 *
 * Every call needs both credentials: the vendor `PHPSESSID` cookie (held by
 * [cookieJar]) and the owner token (sent as `X-E64-Local-Token`). Responses
 * are parsed into values, never into a log line.
 */
class LocalApiRepository(
    val endpoint: GrinderEndpoint,
    private val client: DeviceHttpClient,
    private val cookieJar: CookieJar,
    private val tokenProvider: () -> String?,
    /**
     * Owner password used for the vendor login. When the jar holds no
     * `PHPSESSID` the repository logs in before the first route call: the
     * module is only reachable through an authenticated vendor session, so a
     * token alone is not enough. A provider that returns `null` means no
     * password is available and the call fails closed instead of sending a
     * token-only request (the setup probe logs in explicitly instead).
     */
    private val passwordProvider: () -> String? = { null },
    /** Optional observer for the exact request that was sent (tests only). */
    private val onRequest: (JsonRequest) -> Unit = {},
) {
    val hasSession: Boolean get() = cookieJar.names().any { it.equals("PHPSESSID", ignoreCase = true) }

    /**
     * Vendor login. Form fields are exactly `login`, `userRole` and `password`;
     * an empty password is sent verbatim for devices that allow it.
     */
    fun login(password: String): ApiResult<Unit> {
        val response = try {
            client.postForm(
                "/login.php",
                mapOf(
                    "login" to "1",
                    "userRole" to "Owner",
                    "password" to password,
                ),
            )
        } catch (exc: TransportException) {
            return ApiResult.Failure(errorCode = 0, message = exc.message ?: "login failed", httpStatus = 0)
        }
        if (!hasSession) {
            return ApiResult.Failure(
                errorCode = response.status,
                message = "the device did not return a session cookie; check the owner password",
                httpStatus = response.status,
            )
        }
        return ApiResult.Success(Unit)
    }

    fun capabilities(): ApiResult<Capabilities> = dataCall("/rest_api/capabilities") { Capabilities.from(it) }

    fun machine(): ApiResult<MachineInfo> = dataCall("/rest_api/machine") { MachineInfo.from(it) }

    fun grindLog(query: LogQuery): ApiResult<LogPage> =
        dataCall("/rest_api/grind_log", query.toBody()) { LogPage.from(it) }

    fun serviceLog(query: LogQuery): ApiResult<LogPage> =
        dataCall("/rest_api/service_log", query.toBody()) { LogPage.from(it) }

    fun alertLog(query: LogQuery): ApiResult<LogPage> =
        dataCall("/rest_api/alert_log", query.toBody()) { LogPage.from(it) }

    fun recipes(): ApiResult<List<StringRow>> = rowsCall("/rest_api/recipes")

    fun portafilters(): ApiResult<List<StringRow>> = rowsCall("/rest_api/portafilters")

    fun settings(): ApiResult<KeyValuePage> = dataCall("/rest_api/settings") { data ->
        val values = LinkedHashMap<String, String>()
        data.obj("settings")?.entries?.forEach { (key, value) ->
            values[key] = (value as? JsonValue.Str)?.value ?: Json.write(value)
        }
        KeyValuePage(values, stringList(data, "redacted"))
    }

    fun config(): ApiResult<KeyValuePage> = dataCall("/rest_api/config") { data ->
        val values = LinkedHashMap<String, String>()
        flattenConfig(data.obj("config"), "", values)
        KeyValuePage(values, stringList(data, "redacted"))
    }

    fun file(path: String): ApiResult<FileContent> {
        if (!AllowedPaths.isCallerSelectable(path)) {
            return ApiResult.Failure(400, "path is not in the device's read allowlist")
        }
        return dataCall("/rest_api/file", Json.obj("path" to Json.str(path))) { data ->
            FileContent(
                path = data.string("path") ?: path,
                encoding = data.string("encoding") ?: "text",
                content = data.string("content").orEmpty(),
            )
        }
    }

    /** Mints a WSS command token. Returned without logging it; see [WsToken]. */
    fun wsToken(): ApiResult<WsToken> = dataCall("/rest_api/ws_token") { WsToken.from(it) }

    /**
     * Posts one route with the owner token and returns its `data` object.
     *
     * The action layer lives in its own client ([ActionApiClient]) because it
     * adds state that must not be shared with a read route: a single-use confirm
     * token and the destructive gate. Both still travel through this method, so
     * session handling, the token header and the HTML-session-recovery path are
     * exactly the same code as for every read route.
     */
    internal fun postRoute(path: String, body: JsonValue = Json.obj()): ApiResult<JsonValue.Obj> =
        call(path, body) { it }

    private fun rowsCall(path: String): ApiResult<List<StringRow>> =
        dataCall(path) { it.toRows() }

    private fun dataCall(path: String, body: JsonValue = Json.obj()): ApiResult<JsonValue.Obj> =
        call(path, body) { it }

    private fun <T> dataCall(path: String, body: JsonValue = Json.obj(), map: (JsonValue.Obj) -> T): ApiResult<T> =
        dataCall(path, body).mapData(map)

    private fun <T> ApiResult<JsonValue.Obj>.mapData(map: (JsonValue.Obj) -> T): ApiResult<T> =
        when (this) {
            is ApiResult.Success -> ApiResult.Success(map(data))
            is ApiResult.Failure -> this
        }

    /** Posts [body] with the owner token header and parses the envelope. */
    private fun <T> call(path: String, body: JsonValue = Json.obj(), map: (JsonValue.Obj) -> T): ApiResult<T> {
        val token = tokenProvider()
        if (token.isNullOrEmpty()) {
            return ApiResult.Failure(401, "no owner token is stored for this device")
        }
        if (!hasSession) {
            // The vendor dispatcher authenticates the PHP session before it
            // calls the module, so a token alone cannot reach a route. Log in
            // on first use when a password is available. A failed login is
            // returned as-is: no route request is attempted without a session.
            val password = passwordProvider() ?: return ApiResult.Failure(
                401,
                "no vendor session: the owner password is not stored for this device",
            )
            val session = login(password)
            if (session is ApiResult.Failure) return session
        }
        val response = try {
            client.postJson(path, Json.write(body), AuthHeader.headers(token))
        } catch (exc: TransportException) {
            return ApiResult.Failure(errorCode = 0, message = exc.message ?: "request failed", httpStatus = 0)
        }
        onRequest(JsonRequest(path, Json.write(body), AuthHeader.headers(token)))
        val envelope = Envelope.parse(response.body, response.status)
        if (envelope is ApiResult.Failure && response.body.trimStart().startsWith("<")) {
            // The vendor dispatcher answers with the login page when the PHP
            // session expired. Drop the stale cookie so the next call logs in
            // again instead of repeating the failure for the lifetime of the app.
            cookieJar.clear()
        }
        return when (envelope) {
            is ApiResult.Failure -> envelope
            is ApiResult.Success -> when (val data = Envelope.dataOf(envelope.data)) {
                is ApiResult.Failure -> data
                is ApiResult.Success -> ApiResult.Success(map(data.data))
            }
        }
    }

    companion object {
        fun stringList(data: JsonValue.Obj, key: String): List<String> =
            data.array(key)?.items?.mapNotNull { (it as? JsonValue.Str)?.value }.orEmpty()

        /** Flattens nested config JSON into dotted keys; arrays are joined with a comma. */
        fun flattenConfig(value: JsonValue?, prefix: String, out: MutableMap<String, String>) {
            when (value) {
                is JsonValue.Obj -> for ((key, child) in value.entries) {
                    flattenConfig(child, if (prefix.isEmpty()) key else "$prefix.$key", out)
                }

                is JsonValue.Arr -> out[prefix] = value.items.joinToString(", ") { Json.write(it) }
                is JsonValue.Str -> out[prefix] = value.value
                is JsonValue.Num -> out[prefix] = value.literal
                is JsonValue.Bool -> out[prefix] = value.value.toString()
                JsonValue.Null -> out[prefix] = ""
                null -> Unit
            }
        }

        fun parseOrNull(text: String): JsonValue? = try {
            Json.parse(text)
        } catch (exc: JsonParseException) {
            null
        }
    }
}

/**
 * The device's read allowlist, mirrored on the client so the UI can only offer
 * paths the module actually serves. Exact entries plus regular files below
 * allowed directories.
 */
object AllowedPaths {
    val exact: List<String> = listOf(
        "/etc/issue",
        "/tmp/FirmwareUpdateState.json",
    )

    val directories: List<String> = listOf("/log")

    val suggestions: List<String> = exact + listOf("/log/messages")

    fun isAllowed(path: String): Boolean {
        if (!path.startsWith("/") || path.contains('\u0000')) return false
        if (path in exact) return true
        return directories.any { dir -> path.startsWith("$dir/") && !path.contains("/../") && path.length > dir.length + 1 }
    }

    /** Paths the app may offer as free-text input (directories are prefix-matched). */
    fun isCallerSelectable(path: String): Boolean = isAllowed(path)
}
