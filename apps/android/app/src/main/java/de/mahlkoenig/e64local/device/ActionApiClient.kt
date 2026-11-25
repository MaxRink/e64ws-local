package de.mahlkoenig.e64local.device

import de.mahlkoenig.e64local.core.ApiResult
import de.mahlkoenig.e64local.core.Json
import de.mahlkoenig.e64local.core.JsonParseException
import de.mahlkoenig.e64local.core.JsonValue
import java.util.UUID

/**
 * One entry of `capabilities.data.actions.catalog`.
 *
 * The device reports the whole catalog even when the gate is closed, so the app
 * can show an unavailable action with the device's own reason instead of
 * pretending the route does not exist.
 */
data class ActionCatalogEntry(
    val route: String,
    /** `implemented` or `unavailable`. */
    val status: String,
    /** `actuator`, `state-changing` or `destructive`; shown in the confirm dialog. */
    val risk: String,
    val destructive: Boolean,
    val surface: String?,
    val summary: String?,
    val evidence: String?,
    /** Set by the device when the gate would refuse this route right now. */
    val blocked: String?,
    /** Set for an `unavailable` entry: why this release cannot dispatch it. */
    val reason: String?,
) {
    val isImplemented: Boolean get() = status == "implemented"

    /** True when the device would accept a prepare for this route. */
    val isDispatchable: Boolean get() = isImplemented && blocked == null

    companion object {
        fun from(data: JsonValue.Obj) = ActionCatalogEntry(
            route = data.string("route").orEmpty(),
            status = data.string("status").orEmpty(),
            risk = data.string("risk") ?: "unknown",
            destructive = data.bool("destructive") ?: false,
            surface = data.string("surface"),
            summary = data.string("summary"),
            evidence = data.string("evidence"),
            blocked = data.string("blocked"),
            reason = data.string("reason"),
        )
    }
}

/**
 * `capabilities.data.actions`: the gate, the policy and the catalog.
 *
 * Nothing here is cached on the device side: the module re-reads
 * `/db/e64local/actions.json` on every call, so a policy change takes effect on
 * the next request. The app therefore treats this document as a snapshot and
 * refreshes it before offering an action.
 */
data class ActionPolicy(
    val schema: String,
    val enabled: Boolean,
    val destructiveEnabled: Boolean,
    val reason: String?,
    val actionRoutes: List<String>,
    val catalog: List<ActionCatalogEntry>,
    val note: String?,
) {
    fun entry(route: String): ActionCatalogEntry? = catalog.firstOrNull { it.route == route }

    companion object {
        fun from(data: JsonValue.Obj) = ActionPolicy(
            schema = data.string("schema").orEmpty(),
            enabled = data.bool("enabled") ?: false,
            destructiveEnabled = data.bool("destructiveEnabled") ?: false,
            reason = data.string("reason"),
            actionRoutes = data.array("actionRoutes")?.items
                ?.mapNotNull { (it as? JsonValue.Str)?.value }.orEmpty(),
            catalog = data.array("catalog")?.items.orEmpty()
                .mapNotNull { (it as? JsonValue.Obj)?.let(ActionCatalogEntry::from) },
            note = data.string("note"),
        )
    }
}

/**
 * The device's answer to `action_prepare`, minus the confirm token.
 *
 * The token is deliberately not a field: it is an HMAC that authorises exactly
 * one actuation, so it lives in [ActionApiClient]'s memory and is looked up by
 * action id when the owner confirms. Nothing serialises it, nothing logs it and
 * no UI state holds it.
 */
data class PreparedAction(
    val actionId: String,
    val actionRoute: String,
    val expiresEpoch: Long,
    val expiresAt: String,
    val state: String,
    val warnings: List<String>,
    val auditId: String?,
    val idempotent: Boolean,
) {
    companion object {
        fun from(data: JsonValue.Obj) = PreparedAction(
            actionId = data.string("actionId").orEmpty(),
            actionRoute = data.string("actionRoute").orEmpty(),
            expiresEpoch = data.long("expires") ?: 0L,
            expiresAt = data.string("expiresAt").orEmpty(),
            state = data.string("state").orEmpty(),
            warnings = data.array("warnings")?.items
                ?.mapNotNull { (it as? JsonValue.Str)?.value }.orEmpty(),
            auditId = data.string("auditId"),
            idempotent = data.bool("idempotent") ?: false,
        )
    }
}

/** `action_status`: the persisted state and result of one action. */
data class ActionStatus(
    val actionId: String,
    val actionRoute: String,
    val state: String,
    val preparedAt: String,
    val expiresAt: String,
    val startedAt: String?,
    val finishedAt: String?,
    val durationMs: Long?,
    val errorCode: Int,
    val error: String?,
    /** The runner's result object, pretty-printed; empty when there is none. */
    val resultJson: String,
    val cancelRequested: Boolean,
    val auditId: String?,
) {
    val isTerminal: Boolean
        get() = state in setOf("completed", "failed", "cancelled", "expired", "timed_out")

    /** A cancel is only offered while the device could still act on it. */
    val isCancellable: Boolean get() = state in setOf("prepared", "executing")

    companion object {
        fun from(data: JsonValue.Obj) = ActionStatus(
            actionId = data.string("actionId").orEmpty(),
            actionRoute = data.string("actionRoute").orEmpty(),
            state = data.string("state").orEmpty(),
            preparedAt = data.string("preparedAt").orEmpty(),
            expiresAt = data.string("expiresAt").orEmpty(),
            startedAt = data.string("startedAt"),
            finishedAt = data.string("finishedAt"),
            durationMs = data.long("durationMs"),
            errorCode = data.long("errorCode")?.toInt() ?: 0,
            error = data.string("error"),
            resultJson = data.obj("result")?.let { Json.write(it) }.orEmpty(),
            cancelRequested = data.bool("cancelRequested") ?: false,
            auditId = data.string("auditId"),
        )
    }
}

/** `action_cancel`: idempotent, and honest about which case applied. */
data class ActionCancelResult(
    val actionId: String,
    val actionRoute: String,
    val state: String,
    val cancelled: Boolean,
    val stopSent: Boolean,
    val stopError: String?,
    val note: String?,
) {
    companion object {
        fun from(data: JsonValue.Obj) = ActionCancelResult(
            actionId = data.string("actionId").orEmpty(),
            actionRoute = data.string("actionRoute").orEmpty(),
            state = data.string("state").orEmpty(),
            cancelled = data.bool("cancelled") ?: false,
            stopSent = data.bool("stopSent") ?: false,
            stopError = data.string("stopError"),
            note = data.string("note"),
        )
    }
}

/** `action_execute`: the terminal outcome of the action that just ran. */
data class ActionResult(
    val actionId: String,
    val actionRoute: String,
    val state: String,
    val auditId: String?,
    val resultJson: String,
    val durationMs: Long?,
) {
    companion object {
        fun from(data: JsonValue.Obj) = ActionResult(
            actionId = data.string("actionId").orEmpty(),
            actionRoute = data.string("actionRoute").orEmpty(),
            state = data.string("state").orEmpty(),
            auditId = data.string("auditId"),
            resultJson = data.obj("result")?.let { Json.write(it) }.orEmpty(),
            durationMs = data.long("durationMs"),
        )
    }
}

/** One line of the device's audit log (`audit.jsonl`, newest first). */
data class ActionAuditRow(
    val ts: String,
    val tsEpoch: Long,
    val phase: String,
    val route: String,
    val actionId: String?,
    val requestId: String?,
    val paramsHash: String?,
    val result: String?,
    val errorCode: Int,
    val retryAfter: Int?,
    val durationMs: Long?,
    val clientAddr: String?,
) {
    /** True for the rows that mean something happened to the machine. */
    val isActuation: Boolean get() = phase in setOf("execute", "result", "timeout", "cancel")

    companion object {
        fun from(data: JsonValue.Obj) = ActionAuditRow(
            ts = data.string("ts").orEmpty(),
            tsEpoch = data.long("tsEpoch") ?: 0L,
            phase = data.string("phase").orEmpty(),
            route = data.string("route").orEmpty(),
            actionId = data.string("actionId"),
            requestId = data.string("requestId"),
            paramsHash = data.string("paramsHash"),
            result = data.string("result"),
            errorCode = data.long("errorCode")?.toInt() ?: 0,
            retryAfter = data.long("retryAfter")?.toInt(),
            durationMs = data.long("durationMs"),
            clientAddr = data.obj("client")?.string("addr"),
        )
    }
}

data class ActionAuditPage(
    val rows: List<ActionAuditRow>,
    val count: Int,
    val total: Int,
    val limit: Int,
    val offset: Int,
    val since: String?,
    val until: String?,
    val hasMore: Boolean,
) {
    companion object {
        fun from(data: JsonValue.Obj) = ActionAuditPage(
            rows = data.array("rows")?.items.orEmpty()
                .mapNotNull { (it as? JsonValue.Obj)?.let(ActionAuditRow::from) },
            count = data.long("count")?.toInt() ?: 0,
            total = data.long("total")?.toInt() ?: 0,
            limit = data.long("limit")?.toInt() ?: 0,
            offset = data.long("offset")?.toInt() ?: 0,
            since = data.string("since"),
            until = data.string("until"),
            hasMore = data.bool("hasMore") ?: false,
        )
    }
}

/** Paging and time filter for `action_audit`; unset fields are not sent. */
data class ActionAuditQuery(
    val limit: Int? = null,
    val offset: Int? = null,
    val since: String? = null,
    val until: String? = null,
) {
    fun toBody(): JsonValue.Obj = Json.obj(
        "limit" to limit?.let { Json.num(it.toLong()) },
        "offset" to offset?.let { Json.num(it.toLong()) },
        "since" to since?.takeIf { it.isNotBlank() }?.let { Json.str(it) },
        "until" to until?.takeIf { it.isNotBlank() }?.let { Json.str(it) },
    )
}

/** The result of the client-side destructive/unavailable check. */
sealed interface ActionSubmit {
    data object Allowed : ActionSubmit

    /** [errorCode] mirrors the code the device would answer with. */
    data class Blocked(val reason: String, val errorCode: Int) : ActionSubmit
}

/**
 * The local gate for one route: a pure decision from the last capabilities
 * snapshot, so the UI can explain a blocked route before any request is made.
 * It never widens what the device allows; it only avoids asking.
 */
fun ActionPolicy.gate(route: String): ActionSubmit {
    if (!enabled) {
        return ActionSubmit.Blocked(
            reason ?: "The action layer is disabled on this device (no policy file).",
            403,
        )
    }
    val entry = entry(route)
        ?: return ActionSubmit.Blocked("$route is not in this device's action catalog.", 404)
    if (!entry.isImplemented) {
        return ActionSubmit.Blocked(
            "$route is unavailable on this device: ${entry.reason ?: "no reason reported"}",
            422,
        )
    }
    if (entry.destructive && !destructiveEnabled) {
        return ActionSubmit.Blocked(ActionApiClient.DESTRUCTIVE_GATE_CLOSED, 403)
    }
    entry.blocked?.let { return ActionSubmit.Blocked(it, 403) }
    if (!actionRoutes.contains(route)) {
        return ActionSubmit.Blocked(
            "The device does not list $route as dispatchable right now.",
            403,
        )
    }
    return ActionSubmit.Allowed
}

/** Request ids the device accepts: 8..64 of `A-Za-z0-9._-`, not starting with a dot. */
object ActionRequestId {
    private val pattern = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")

    fun isValid(value: String?): Boolean = value != null && pattern.matches(value)

    /** A random id in the accepted alphabet; a UUID is 36 characters. */
    fun random(): String = UUID.randomUUID().toString()
}

/**
 * Parsing for the free-text `params` field on the action screen.
 *
 * The device validates every parameter again, and it is the authority on the
 * bounds. This only turns what the owner typed into a JSON object, so a typo
 * fails in the dialog instead of on the machine.
 */
object ActionParams {
    const val EMPTY = "{}"

    fun parse(text: String): Result<JsonValue.Obj> {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return Result.success(Json.obj())
        return try {
            val value = Json.parse(trimmed)
            if (value is JsonValue.Obj) {
                Result.success(value)
            } else {
                Result.failure(IllegalArgumentException("Parameters must be a JSON object, for example {\"targetWeightGr\": 18}"))
            }
        } catch (exc: JsonParseException) {
            Result.failure(IllegalArgumentException("Parameters are not valid JSON: ${exc.message}"))
        }
    }

    fun render(params: JsonValue.Obj): String =
        if (params.entries.isEmpty()) EMPTY else Json.write(params)
}

/**
 * Readable text for the action error codes.
 *
 * The device's prose is good, but a code alone is not an instruction. Every
 * sentence below is derived from the documented meaning of the code in
 * `docs/LOCAL_API.md` §12.7 and from the messages in
 * `ondevice/rest_api_dev.php`; none of it is invented at runtime. The confirm
 * token never appears here because it never leaves [ActionApiClient].
 */
object ActionErrors {
    const val NO_CONFIRMATION =
        "No confirm token is held for this action. Prepare it again before executing."

    /**
     * True for the boot-id refusal: the prepare happened before a reboot, so the
     * record can never execute. The device answers 409 with a message that says
     * so, and marks the record `expired`.
     */
    fun isRebootConflict(failure: ApiResult.Failure): Boolean =
        failure.errorCode == 409 && failure.message.contains("rebooted", ignoreCase = true)

    /** True when the token outlived its TTL; the fix is the same: prepare again. */
    fun isExpiredToken(failure: ApiResult.Failure): Boolean =
        failure.errorCode == 409 && failure.message.contains("expired", ignoreCase = true)

    fun describe(failure: ApiResult.Failure): String = when {
        failure.errorCode == 0 && failure.httpStatus == 0 ->
            "The device did not answer: ${failure.message}. Nothing was executed."

        failure.errorCode == 401 ->
            "The device rejected the owner token (401). ${failure.message}. Run the setup " +
                "wizard again to install a valid token."

        failure.errorCode == 403 && failure.message.contains("destructive", ignoreCase = true) ->
            "Destructive actions are disabled on this device (403). An owner has to deploy the " +
                "policy with --enable-destructive-actions before this route can run."

        failure.errorCode == 403 && failure.message.contains("no longer available", ignoreCase = true) ->
            "The action is no longer available on this device (403): the deployed policy or " +
                "catalog changed after it was prepared."

        failure.errorCode == 403 ->
            "The device refused the action (403): ${failure.message}. The action gate is closed " +
                "unless an owner has deployed /db/e64local/actions.json."

        isRebootConflict(failure) ->
            "The grinder rebooted after this action was prepared (409), so its confirm token is " +
                "no longer valid. Nothing was executed. Prepare the action again."

        isExpiredToken(failure) ->
            "The confirm token expired before it was used (409). Nothing was executed. Prepare " +
                "the action again."

        failure.errorCode == 409 ->
            "The action is not in a state that allows this step (409): ${failure.message}."

        failure.errorCode == 422 && failure.message.contains("unavailable", ignoreCase = true) ->
            "This action is unavailable on this device (422): ${failure.message}. " +
                "Nothing was executed."

        failure.errorCode == 422 ->
            "The device refused the parameters (422): ${failure.message}. Nothing was executed."

        failure.errorCode == 429 -> buildString {
            append("The device rate-limited this action (429).")
            val retry = failure.retryAfter
            if (retry != null) append(" Retry after ").append(retry).append(" s.")
            else append(" ").append(failure.message).append('.')
        }

        failure.errorCode == 404 ->
            "The device does not know this action (404): ${failure.message}."

        failure.errorCode == 503 ->
            "The device could not run the action (503): ${failure.message}. Nothing was actuated."

        failure.errorCode == 504 ->
            "The action hit its hard timeout (504) and the stop primitive was attempted: " +
                "${failure.message}. Check the machine before retrying."

        failure.errorCode == 500 ->
            "The device failed an integrity or bookkeeping check (500): ${failure.message}."

        else -> failure.describe()
    }
}

/**
 * The gated action layer, as the app may use it.
 *
 * Responsibilities split deliberately:
 *  - [LocalApiRepository] owns transport, session and the owner-token header.
 *  - This class owns the two things the device cannot enforce for us: the
 *    single-use confirm token (kept in memory, per action id) and the local
 *    refusal of a destructive route while the device reports
 *    `destructiveEnabled: false`.
 *
 * The device re-validates everything: the token, the boot id, the gate, the
 * rate limit, the bounds and the preconditions. A compromised app cannot widen
 * what the module allows; the local checks only avoid a pointless request.
 */
class ActionApiClient(
    private val repository: LocalApiRepository,
    /**
     * The last `capabilities` document the app read. It is a parameter rather
     * than a hidden fetch so the gate decision is deterministic in a test and
     * the caller decides when the snapshot is refreshed.
     */
    private var policy: ActionPolicy? = null,
    /** Injectable so a test can pin the idempotency key. */
    private val requestIdFactory: () -> String = { ActionRequestId.random() },
) {
    /**
     * Prepare -> execute handoff. Memory only: it is not a field on a UI state
     * object, not written to disk and not part of any toString.
     */
    private class Confirmation(val token: String, val requestId: String)

    private val confirmations = LinkedHashMap<String, Confirmation>()

    /** Confirmation state for the UI; never includes the token. */
    val pendingActionIds: List<String> get() = confirmations.keys.toList()

    fun policy(): ActionPolicy? = policy

    fun updatePolicy(policy: ActionPolicy?) {
        this.policy = policy
    }

    /** Reads the gate and catalog from the device and remembers them. */
    fun refreshPolicy(): ApiResult<ActionPolicy> = when (val result = repository.capabilities()) {
        is ApiResult.Failure -> result
        is ApiResult.Success -> {
            val actions = result.data.actions
                ?: return ApiResult.Failure(
                    502,
                    "the device capabilities document has no action layer (module too old)",
                )
            policy = actions
            ApiResult.Success(actions)
        }
    }

    /**
     * The local gate. A destructive route is blocked unless the device itself
     * reports `destructiveEnabled: true`; there is no override and no cached
     * "was allowed once" flag.
     */
    fun check(route: String): ActionSubmit = policy?.gate(route) ?: ActionSubmit.Blocked(
        "The device's capabilities have not been read yet, so no action can be offered. " +
            "Refresh first.",
        503,
    )

    /**
     * `action_prepare`. Refuses locally when [check] blocks the route, so a
     * destructive action cannot even be submitted while the device reports the
     * second gate closed.
     */
    fun prepare(
        route: String,
        params: JsonValue.Obj = Json.obj(),
        requestId: String = requestIdFactory(),
    ): ApiResult<PreparedAction> {
        when (val gate = check(route)) {
            is ActionSubmit.Blocked -> return ApiResult.Failure(gate.errorCode, gate.reason)
            ActionSubmit.Allowed -> Unit
        }
        if (!ActionRequestId.isValid(requestId)) {
            return ApiResult.Failure(
                400,
                "requestId must be 8..64 of A-Z a-z 0-9 . _ - and must not start with a dot",
            )
        }
        val body = Json.obj(
            "route" to Json.str(route),
            "params" to params,
            "requestId" to Json.str(requestId),
        )
        return when (val result = repository.postRoute("/rest_api/action_prepare", body)) {
            is ApiResult.Failure -> result
            is ApiResult.Success -> {
                val prepared = PreparedAction.from(result.data)
                if (prepared.actionId.isEmpty()) {
                    ApiResult.Failure(502, "the device prepared an action without an actionId")
                } else {
                    // The token is in the device's answer; it is read here and
                    // nowhere else, and stored under the action id it belongs to.
                    // `idempotent: true` means the device handed back the token
                    // of an earlier prepare with the same requestId, which is
                    // still a single token for one action.
                    val token = result.data.string("confirmToken").orEmpty()
                    if (token.isEmpty()) {
                        ApiResult.Failure(502, "the device prepared an action without a confirm token")
                    } else {
                        confirmations[prepared.actionId] = Confirmation(token, requestId)
                        ApiResult.Success(prepared)
                    }
                }
            }
        }
    }

    /**
     * `action_execute`. The token is looked up in memory and forgotten as soon
     * as the device answers: a handled answer means the request reached the
     * module, which spends the token even when it refuses. A transport failure
     * keeps it, because nothing was actuated and the owner may retry.
     */
    fun execute(actionId: String): ApiResult<ActionResult> {
        val confirmation = confirmations[actionId]
            ?: return ApiResult.Failure(409, ActionErrors.NO_CONFIRMATION)
        val body = Json.obj(
            "actionId" to Json.str(actionId),
            "confirmToken" to Json.str(confirmation.token),
            "requestId" to Json.str(confirmation.requestId),
        )
        val result = repository.postRoute("/rest_api/action_execute", body)
        val answered = !(result is ApiResult.Failure && result.errorCode == 0 && result.httpStatus == 0)
        if (answered) confirmations.remove(actionId)
        return when (result) {
            is ApiResult.Failure -> result
            is ApiResult.Success -> ApiResult.Success(ActionResult.from(result.data))
        }
    }

    /** `action_status`: read-only, so it needs no token and drops nothing. */
    fun status(actionId: String): ApiResult<ActionStatus> {
        if (actionId.isBlank()) return ApiResult.Failure(400, "actionId is required")
        return when (val result = repository.postRoute("/rest_api/action_status", idBody(actionId))) {
            is ApiResult.Failure -> result
            is ApiResult.Success -> ApiResult.Success(ActionStatus.from(result.data))
        }
    }

    /**
     * `action_cancel`. Idempotent on the device. A cancel ends this client's
     * confirmation, because a cancelled record can never execute; dropping the
     * token is the local half of that.
     */
    fun cancel(actionId: String): ApiResult<ActionCancelResult> {
        if (actionId.isBlank()) return ApiResult.Failure(400, "actionId is required")
        val result = repository.postRoute("/rest_api/action_cancel", idBody(actionId))
        return when (result) {
            is ApiResult.Failure -> result
            is ApiResult.Success -> {
                confirmations.remove(actionId)
                ApiResult.Success(ActionCancelResult.from(result.data))
            }
        }
    }

    /** `action_audit`: newest first, paged, optionally time-filtered. */
    fun audit(query: ActionAuditQuery = ActionAuditQuery()): ApiResult<ActionAuditPage> =
        when (val result = repository.postRoute("/rest_api/action_audit", query.toBody())) {
            is ApiResult.Failure -> result
            is ApiResult.Success -> ApiResult.Success(ActionAuditPage.from(result.data))
        }

    /** Forget a confirmation without asking the device (dialog dismissed). */
    fun discard(actionId: String) {
        confirmations.remove(actionId)
    }

    /** Forget every confirmation; used when the view model is torn down. */
    fun discardAll() {
        confirmations.clear()
    }

    private fun idBody(actionId: String): JsonValue.Obj = Json.obj("actionId" to Json.str(actionId))

    companion object {
        const val DESTRUCTIVE_GATE_CLOSED =
            "This action is destructive and the device reports destructiveEnabled: false, so it " +
                "cannot be submitted. An owner has to re-deploy the action policy with " +
                "--enable-destructive-actions."

        /** Routes the client posts; kept here so the OpenAPI check can scan them. */
        val ROUTES: List<String> = listOf(
            "/rest_api/action_prepare",
            "/rest_api/action_execute",
            "/rest_api/action_status",
            "/rest_api/action_cancel",
            "/rest_api/action_audit",
        )
    }
}
