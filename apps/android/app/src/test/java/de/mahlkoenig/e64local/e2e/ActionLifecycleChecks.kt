package de.mahlkoenig.e64local.e2e

import de.mahlkoenig.e64local.core.ApiResult
import de.mahlkoenig.e64local.core.Json
import de.mahlkoenig.e64local.core.JsonValue
import de.mahlkoenig.e64local.core.Redaction
import de.mahlkoenig.e64local.device.ActionApiClient
import de.mahlkoenig.e64local.device.ActionAuditQuery
import de.mahlkoenig.e64local.device.ActionErrors
import de.mahlkoenig.e64local.device.ActionRequestId
import de.mahlkoenig.e64local.device.ActionSubmit
import de.mahlkoenig.e64local.device.gate
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * The gated action layer, driven end to end against the live simulator.
 *
 * The simulator is expected to run with `--enable-actions` (the shared harness
 * passes it; a real image ships with the gate closed). Under that policy the
 * gate is open and the destructive gate is still closed, which is exactly the
 * state the app has to handle:
 *
 *  - `capabilities.data.actions.enabled == true`, `destructiveEnabled == false`;
 *  - prepare → execute → status → audit for a non-destructive action;
 *  - cancel before execute, after which the confirm token is worthless;
 *  - a second execute with a spent token is refused by the device with `409`;
 *  - a destructive route is refused by the app *and* by the device;
 *  - a bucket the owner has exhausted answers `429` with `retryAfter`.
 *
 * The confirm token only exists in this state, so this is also the only place
 * where "the token never leaks" can be proven rather than asserted about an
 * empty value. The offline counterpart - the app's behaviour while the gate is
 * still closed - lives in [ClosedGateUnitTest] and needs no server.
 */
internal class ActionLifecycleChecks(
    private val report: E2EReport,
    private val device: SimulatorClient,
    private val token: String,
) {

    fun run() {
        val captured = ByteArrayOutputStream()
        val originalOut = System.out
        val originalErr = System.err
        val sink = PrintStream(captured, true, "UTF-8")
        var confirmToken = ""
        try {
            System.setOut(sink)
            System.setErr(sink)
            confirmToken = lifecycle()
        } finally {
            sink.flush()
            System.setOut(originalOut)
            System.setErr(originalErr)
        }

        val capturedText = captured.toString("UTF-8")
        report.verify("actions: the confirm token never reached stdout or stderr") {
            require(confirmToken.isNotEmpty()) { "no confirm token was minted, so the log claim cannot be made" }
            require(!capturedText.contains(confirmToken)) { "the confirm token was written to stdout/stderr" }
            require(!capturedText.contains(token)) { "the owner token was written to stdout/stderr" }
        }

        report.verify("actions: the classes that hold the confirm token contain no logging call") {
            val root = File("src/main/java/de/mahlkoenig/e64local")
            require(root.isDirectory) { "cannot find the app sources at ${root.absolutePath}" }
            val names = setOf(
                "ActionApiClient.kt", "LocalApiRepository.kt", "DeviceHttpClient.kt",
                "Auth.kt", "AppViewModel.kt",
            )
            val files = root.walkTopDown().filter { it.isFile && it.name in names }.toList()
            require(files.size == names.size) { "found ${files.map { it.name }}" }
            val markers = listOf(
                "println(", "printStackTrace", "System.out", "System.err",
                "android.util.Log", "Log.d(", "Log.i(", "Log.w(", "Log.e(",
            )
            val offenders = files.flatMap { file ->
                val text = file.readText()
                markers.filter { text.contains(it) }.map { "${file.name}: $it" }
            }
            require(offenders.isEmpty()) { "logging found: $offenders" }
        }
    }

    private fun lifecycle(): String {
        val client = ActionApiClient(device.repository)

        report.verify("actions: before the policy is read the app offers no action at all") {
            val blocked = client.check(LIFECYCLE_ROUTE) as? ActionSubmit.Blocked
                ?: throw E2EFailure("check() allowed an action before any capabilities document was read")
            require(blocked.errorCode == 503) { "errorCode=${blocked.errorCode}" }
        }

        val policy = report.verify("actions: refreshPolicy reads the deployed gate from the device") {
            when (val result = client.refreshPolicy()) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("refreshPolicy failed: ${result.describe()}")
            }
        }

        report.verify("actions: the device reports actions enabled and the destructive gate closed") {
            require(policy.enabled) {
                "the device reports actions.enabled=false; start the simulator with --enable-actions"
            }
            require(!policy.destructiveEnabled) {
                "the device reports destructiveEnabled=true; this suite expects --enable-actions " +
                    "without --enable-destructive-actions"
            }
            require(policy.actionRoutes.contains(LIFECYCLE_ROUTE)) {
                "actionRoutes does not list $LIFECYCLE_ROUTE"
            }
            require(policy.gate(LIFECYCLE_ROUTE) == ActionSubmit.Allowed) {
                "the gate blocks $LIFECYCLE_ROUTE: ${(policy.gate(LIFECYCLE_ROUTE) as? ActionSubmit.Blocked)?.reason}"
            }
            require(policy.catalog.count { it.isImplemented } >= 10) {
                "the catalog only names ${policy.catalog.count { it.isImplemented }} implemented actions"
            }
        }

        val destructiveRoute = report.verify("actions: the catalog names an implemented destructive route") {
            policy.catalog.firstOrNull { it.destructive && it.isImplemented }?.route
                ?: throw E2EFailure("the catalog names no implemented destructive action")
        }

        report.verify("actions: the app refuses the destructive route while destructiveEnabled is false") {
            val blocked = policy.gate(destructiveRoute) as? ActionSubmit.Blocked
                ?: throw E2EFailure("the gate allowed $destructiveRoute")
            require(blocked.errorCode == 403) { "errorCode=${blocked.errorCode}" }
            require(blocked.reason == ActionApiClient.DESTRUCTIVE_GATE_CLOSED) { "reason=${blocked.reason}" }
        }

        report.verify("actions: a blocked destructive prepare sends nothing at all") {
            val before = device.exchanges.size
            val failure = client.prepare(destructiveRoute) as? ApiResult.Failure
                ?: throw E2EFailure("prepare accepted a destructive route")
            require(failure.errorCode == 403) { "errorCode=${failure.errorCode}" }
            require(device.exchanges.size == before) { "prepare posted a request for a blocked route" }
            require(client.pendingActionIds.isEmpty()) { "a confirmation was stored for a blocked route" }
        }

        report.verify("actions: the device re-checks the destructive gate and refuses the same route") {
            val failure = postFailure(
                "/rest_api/action_prepare",
                Json.obj(
                    "route" to Json.str(destructiveRoute),
                    "params" to Json.obj(),
                    "requestId" to Json.str(ActionRequestId.random()),
                ),
            )
            require(failure.errorCode == 403) { "errorCode=${failure.errorCode}: ${failure.message}" }
            require(failure.message.contains("destructive")) { "message=${failure.message}" }
            val described = ActionErrors.describe(failure)
            require(described.contains("--enable-destructive-actions")) { "describe()=$described" }
        }

        val prepared = report.verify("actions: prepare returns the action identity and no token") {
            when (val result = client.prepare(LIFECYCLE_ROUTE, LIFECYCLE_PARAMS)) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("prepare failed: ${result.describe()}")
            }
        }

        report.verify("actions: the prepared action is well formed and held in memory only") {
            require(prepared.actionRoute == LIFECYCLE_ROUTE) { "actionRoute=${prepared.actionRoute}" }
            require(
                prepared.actionId.matches(
                    Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
                ),
            ) { "actionId=${prepared.actionId}" }
            require(prepared.state == "prepared") { "state=${prepared.state}" }
            require(prepared.expiresEpoch * 1_000 > System.currentTimeMillis()) { "expires=${prepared.expiresEpoch}" }
            require(prepared.expiresAt.isNotEmpty()) { "expiresAt is empty" }
            require(client.pendingActionIds == listOf(prepared.actionId)) { "pending=${client.pendingActionIds}" }
        }

        val confirmToken = report.verify("actions: the device minted one 64-hex confirm token for this action") {
            val answer = device.lastExchangeTo("/rest_api/action_prepare")
                ?: throw E2EFailure("no prepare answer was recorded")
            val data = Json.parseObject(answer.responseBody).obj("data")
                ?: throw E2EFailure("the prepare envelope carries no data object")
            require(data.string("actionId") == prepared.actionId) { "the recorded answer belongs to another action" }
            val minted = data.string("confirmToken").orEmpty()
            require(minted.matches(Regex("[0-9a-f]{64}"))) { "the device minted '${Redaction.tokenHint(minted)}'" }
            require(!prepared.toString().contains(minted)) { "PreparedAction.toString() prints the token" }
            minted
        }

        report.verify("actions: the prepare request itself carries no token") {
            val answer = device.lastExchangeTo("/rest_api/action_prepare")
                ?: throw E2EFailure("no prepare answer was recorded")
            require(!answer.requestBody.contains(confirmToken)) { "the confirm token was sent with the prepare" }
            require(answer.header("X-E64-Local-Token") == token) { "the prepare went out without the owner token" }
        }

        val prepareRequestId = report.verify("actions: the prepare carried the idempotency key the device compares") {
            val answer = device.lastExchangeTo("/rest_api/action_prepare")
                ?: throw E2EFailure("no prepare answer was recorded")
            val id = Json.parseObject(answer.requestBody).string("requestId").orEmpty()
            require(ActionRequestId.isValid(id)) { "requestId='${id.take(8)}'" }
            id
        }

        val executed = report.verify("actions: execute runs the non-destructive action to a terminal state") {
            when (val result = client.execute(prepared.actionId)) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("execute failed: ${result.describe()}")
            }
        }

        report.verify("actions: the executed action reports the runner's own result") {
            require(executed.actionId == prepared.actionId) { "actionId=${executed.actionId}" }
            require(executed.state == "completed") { "state=${executed.state}" }
            require(executed.resultJson.contains(LIFECYCLE_COMMAND)) { "result=${executed.resultJson}" }
            require(executed.auditId != null) { "the device reported no audit id" }
            require(executed.durationMs != null) { "the device reported no duration" }
            require(!executed.toString().contains(confirmToken)) { "ActionResult.toString() prints the token" }
        }

        report.verify("actions: the confirm token crossed the wire exactly twice, prepare answer and execute body") {
            val carriers = device.exchanges.filter {
                it.requestBody.contains(confirmToken) || it.responseBody.contains(confirmToken)
            }
            require(carriers.size == 2) { "carried by ${carriers.map { "${it.method} ${it.path}" }}" }
            require(carriers.any { it.path == "/rest_api/action_prepare" && it.responseBody.contains(confirmToken) }) {
                "the prepare answer is not one of them"
            }
            require(carriers.any { it.path == "/rest_api/action_execute" && it.requestBody.contains(confirmToken) }) {
                "the execute body is not one of them"
            }
        }

        report.verify("actions: the client forgets the confirmation once the device answered") {
            require(client.pendingActionIds.isEmpty()) { "pending=${client.pendingActionIds}" }
        }

        report.verify("actions: the spent confirm token cannot be replayed, the device answers 409") {
            val failure = postFailure(
                "/rest_api/action_execute",
                Json.obj(
                    "actionId" to Json.str(prepared.actionId),
                    "confirmToken" to Json.str(confirmToken),
                    "requestId" to Json.str(prepareRequestId),
                ),
            )
            require(failure.errorCode == 409) { "errorCode=${failure.errorCode}: ${failure.message}" }
            require(failure.message.contains("state")) { "message=${failure.message}" }
        }

        report.verify("actions: status reads the persisted state of the same action") {
            val status = when (val result = client.status(prepared.actionId)) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("status failed: ${result.describe()}")
            }
            require(status.actionId == prepared.actionId) { "actionId=${status.actionId}" }
            require(status.state == "completed") { "state=${status.state}" }
            require(status.isTerminal) { "the state is not terminal" }
            require(status.errorCode == 0) { "errorCode=${status.errorCode}" }
            require(status.auditId == executed.auditId) { "auditId=${status.auditId}" }
            require(status.resultJson.contains(LIFECYCLE_COMMAND)) { "result=${status.resultJson}" }
            require(!status.isCancellable) { "a completed action is offered for cancel" }
            require(!status.toString().contains(confirmToken)) { "ActionStatus.toString() prints the token" }
        }

        report.verify("actions: the audit trail reports prepare, execute and result for this action, newest first") {
            val page = when (val result = client.audit(ActionAuditQuery(limit = 50))) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("audit failed: ${result.describe()}")
            }
            require(page.rows.isNotEmpty()) { "the audit trail is empty" }
            require(page.total >= page.rows.size) { "total=${page.total} rows=${page.rows.size}" }
            require(page.rows.first().tsEpoch >= page.rows.last().tsEpoch) { "the audit trail is not newest first" }
            val mine = page.rows.filter { it.actionId == prepared.actionId }
            val phases = mine.map { it.phase }
            require(phases.containsAll(listOf("prepare", "execute", "result"))) { "phases=$phases" }
            require(mine.first { it.phase == "result" }.result == "completed") {
                "result row=${mine.first { it.phase == "result" }.result}"
            }
            require(mine.all { !it.paramsHash.isNullOrEmpty() }) { "a row carries no params hash" }
            require(!page.toString().contains(confirmToken)) { "the audit page prints the token" }
        }

        val cancelled = report.verify("actions: an action can be cancelled before it is executed") {
            val second = when (val result = client.prepare(LIFECYCLE_ROUTE, LIFECYCLE_PARAMS)) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("prepare failed: ${result.describe()}")
            }
            val cancel = when (val result = client.cancel(second.actionId)) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("cancel failed: ${result.describe()}")
            }
            require(cancel.actionId == second.actionId) { "actionId=${cancel.actionId}" }
            require(cancel.cancelled) { "the device did not report the cancel" }
            require(cancel.state == "cancelled") { "state=${cancel.state}" }
            require(!cancel.stopSent) { "a stop was sent for an action that never started" }
            second
        }

        report.verify("actions: a cancelled action can never execute and holds no token") {
            require(client.pendingActionIds.none { it == cancelled.actionId }) {
                "the confirm token of a cancelled action is still held"
            }
            val failure = client.execute(cancelled.actionId) as? ApiResult.Failure
                ?: throw E2EFailure("execute accepted a cancelled action")
            require(failure.errorCode == 409) { "errorCode=${failure.errorCode}" }
            require(failure.message == ActionErrors.NO_CONFIRMATION) { "message=${failure.message}" }
            val status = when (val result = client.status(cancelled.actionId)) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("status failed: ${result.describe()}")
            }
            require(status.state == "cancelled") { "state=${status.state}" }
            require(status.isTerminal) { "the cancelled action is not terminal" }
        }

        report.verify("actions: cancelling a terminal action is idempotent and says so") {
            val again = when (val result = client.cancel(cancelled.actionId)) {
                is ApiResult.Success -> result.data
                is ApiResult.Failure -> throw E2EFailure("cancel failed: ${result.describe()}")
            }
            require(again.cancelled) { "the device stopped reporting the cancel" }
            require(again.state == "cancelled") { "state=${again.state}" }
            require(again.note?.contains("terminal") == true) { "note=${again.note}" }
        }

        report.verify("actions: the device rate-limits an exhausted bucket with 429 and a retryAfter") {
            var limited: ApiResult.Failure? = null
            for (attempt in 1..40) {
                val result = client.prepare(RATE_LIMIT_ROUTE)
                if (result is ApiResult.Success) continue
                val failure = result as? ApiResult.Failure
                    ?: throw E2EFailure("prepare answered neither success nor failure")
                if (failure.errorCode == 429) {
                    limited = failure
                    break
                }
                throw E2EFailure("prepare answered ${failure.errorCode}: ${failure.message}")
            }
            val failure = limited
                ?: throw E2EFailure("the device did not rate-limit 40 prepares on $RATE_LIMIT_ROUTE")
            require(failure.isRateLimited) { "errorCode=${failure.errorCode}" }
            val retry = failure.retryAfter ?: throw E2EFailure("the 429 carried no retryAfter")
            require(retry in 1..3_600) { "retryAfter=$retry" }
            val described = ActionErrors.describe(failure)
            require(described.contains("429")) { "describe()=$described" }
            require(described.contains("Retry after $retry s")) { "describe()=$described" }
        }

        return confirmToken
    }

    private fun postFailure(path: String, body: JsonValue.Obj): ApiResult.Failure {
        val result = device.repository.postRoute(path, body)
        return result as? ApiResult.Failure
            ?: throw E2EFailure("$path answered with data although it was expected to refuse")
    }

    companion object {
        /**
         * Non-destructive, implemented, no parameters, and its bucket
         * (`grind_stop`, 60/min) is the widest one available, so a parallel suite
         * sharing the simulator is unlikely to starve the lifecycle steps. The
         * rate-limit check uses a deliberately tight bucket afterwards.
         */
        const val LIFECYCLE_ROUTE = "action_grind_stop"
        const val LIFECYCLE_COMMAND = "Stop"
        val LIFECYCLE_PARAMS: JsonValue.Obj = Json.obj()

        /** `agsa` allows 10 prepares a minute, so the limit is reachable in a test. */
        const val RATE_LIMIT_ROUTE = "action_agsa_stop"
    }
}
