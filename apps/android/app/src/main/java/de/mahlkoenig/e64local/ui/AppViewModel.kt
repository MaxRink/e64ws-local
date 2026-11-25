package de.mahlkoenig.e64local.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import de.mahlkoenig.e64local.App
import de.mahlkoenig.e64local.core.ApiResult
import de.mahlkoenig.e64local.core.LogPage
import de.mahlkoenig.e64local.core.LogQuery
import de.mahlkoenig.e64local.core.StringRow
import de.mahlkoenig.e64local.device.ActionApiClient
import de.mahlkoenig.e64local.device.ActionAuditPage
import de.mahlkoenig.e64local.device.ActionAuditQuery
import de.mahlkoenig.e64local.device.ActionErrors
import de.mahlkoenig.e64local.device.ActionParams
import de.mahlkoenig.e64local.device.ActionPolicy
import de.mahlkoenig.e64local.device.ActionStatus
import de.mahlkoenig.e64local.device.ActionSubmit
import de.mahlkoenig.e64local.device.Capabilities
import de.mahlkoenig.e64local.device.CookieJar
import de.mahlkoenig.e64local.device.DeviceCertificate
import de.mahlkoenig.e64local.device.DeviceHttpClient
import de.mahlkoenig.e64local.device.GrinderEndpoint
import de.mahlkoenig.e64local.device.LanScope
import de.mahlkoenig.e64local.device.LocalApiRepository
import de.mahlkoenig.e64local.device.MachineInfo
import de.mahlkoenig.e64local.device.PinnedTrustManager
import de.mahlkoenig.e64local.device.PreparedAction
import de.mahlkoenig.e64local.device.gate
import de.mahlkoenig.e64local.setup.ProbeReport
import de.mahlkoenig.e64local.setup.ProbeResult
import de.mahlkoenig.e64local.setup.SetupCoordinator
import de.mahlkoenig.e64local.setup.SetupPlan
import de.mahlkoenig.e64local.setup.SetupProgress
import de.mahlkoenig.e64local.setup.SetupResult
import de.mahlkoenig.e64local.setup.SetupStage
import de.mahlkoenig.e64local.storage.TokenStore
import java.util.concurrent.Executors
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class Tab { DASHBOARD, LOGS, DATA, ACTIONS, ABOUT }

sealed interface SetupUi {
    data object Idle : SetupUi
    data class CertificateNeeded(val certificate: DeviceCertificate, val reason: String) : SetupUi
    data class Probed(val report: ProbeReport) : SetupUi
    data class Confirming(val plan: SetupPlan) : SetupUi
    data class Running(val progress: SetupProgress) : SetupUi
    data class Failed(val message: String) : SetupUi
    data class Done(val report: ProbeReport) : SetupUi
}

data class LogsUi(
    val kind: String = "grind_log",
    val page: LogPage? = null,
    val since: String = "",
    val until: String = "",
    val loading: Boolean = false,
    val error: String? = null,
)

data class DataUi(
    val recipes: List<StringRow> = emptyList(),
    val portafilters: List<StringRow> = emptyList(),
    val settings: Map<String, String> = emptyMap(),
    val settingsRedacted: List<String> = emptyList(),
    val config: Map<String, String> = emptyMap(),
    val configRedacted: List<String> = emptyList(),
    val filePath: String = "/etc/issue",
    val fileEncoding: String = "",
    val fileContent: String = "",
    val loading: Boolean = false,
    val error: String? = null,
)

data class DashboardUi(
    val connected: Boolean = false,
    val endpoint: String = "",
    val machine: MachineInfo? = null,
    val capabilities: Capabilities? = null,
    val loading: Boolean = false,
    val error: String? = null,
)

/**
 * State of the action screen.
 *
 * [pending] is the prepared action *without* its confirm token: the token stays
 * inside [ActionApiClient] and is looked up by action id on confirmation. This
 * object is therefore safe to hand to a composable, and it dies with the
 * ViewModel.
 */
data class ActionsUi(
    val policy: ActionPolicy? = null,
    val selectedRoute: String = "",
    val paramsText: String = ActionParams.EMPTY,
    val pending: PreparedAction? = null,
    val pendingRisk: String = "",
    val activeActionId: String? = null,
    val status: ActionStatus? = null,
    val audit: ActionAuditPage? = null,
    val auditLimit: Int = DEFAULT_AUDIT_LIMIT,
    val message: String? = null,
    val error: String? = null,
    val busy: Boolean = false,
) {
    /** True when the catalog is known but the gate would not dispatch the route. */
    fun gate(): ActionSubmit? =
        if (selectedRoute.isEmpty()) null else policy?.gate(selectedRoute)

    companion object {
        const val DEFAULT_AUDIT_LIMIT = 50
    }
}

/**
 * The single state holder. It owns no network thread of its own: blocking work
 * runs on a single background executor and results are pushed into the state
 * flows. Nothing here writes a token or a password to a log.
 */
class AppViewModel(private val app: App) : ViewModel() {

    private val tokenStore: TokenStore get() = app.tokenStore
    private val coordinator: SetupCoordinator get() = app.setupCoordinator

    private val io = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

    private val _tab = MutableStateFlow(Tab.DASHBOARD)
    val tab: StateFlow<Tab> = _tab.asStateFlow()

    private val _setup = MutableStateFlow<SetupUi>(SetupUi.Idle)
    val setup: StateFlow<SetupUi> = _setup.asStateFlow()

    private val _setupOpen = MutableStateFlow(false)
    val setupOpen: StateFlow<Boolean> = _setupOpen.asStateFlow()

    /** Opens the wizard for a new device or to rotate an existing token. */
    fun openSetup() {
        _setupOpen.value = true
        _setup.value = SetupUi.Idle
    }

    fun closeSetup() {
        _setupOpen.value = false
    }

    private val _dashboard = MutableStateFlow(DashboardUi())
    val dashboard: StateFlow<DashboardUi> = _dashboard.asStateFlow()

    private val _logs = MutableStateFlow(LogsUi())
    val logs: StateFlow<LogsUi> = _logs.asStateFlow()

    private val _data = MutableStateFlow(DataUi())
    val data: StateFlow<DataUi> = _data.asStateFlow()

    private val _actions = MutableStateFlow(ActionsUi())
    val actions: StateFlow<ActionsUi> = _actions.asStateFlow()

    val activeEndpointId: String?
        get() = tokenStore.activeEndpoint()

    fun selectTab(tab: Tab) {
        _tab.value = tab
    }

    fun dismissSetupError() {
        _setup.value = SetupUi.Idle
    }

    /** Step 1: probe the device. Pops a certificate decision when untrusted. */
    fun probe(hostInput: String, ownerPassword: String) {
        val endpoint = GrinderEndpoint.parse(hostInput).getOrElse {
            _setup.value = SetupUi.Failed(it.message ?: "invalid device address")
            return
        }
        if (LanScope.scopeOf(endpoint) == LanScope.Scope.Public) {
            // The app is LAN-only. A public address is refused outright: it is
            // far more likely a typo or a forwarded port than the owner's grinder.
            _setup.value = SetupUi.Failed(
                "${endpoint.host} is a public address. This app only talks to a " +
                    "grinder on your local network.",
            )
            return
        }
        _setup.value = SetupUi.Running(SetupProgress(SetupStage.PROBING, "Contacting the device"))
        viewModelScope.launch {
            val result = withContext(io) {
                runCatching { coordinator.probe(endpoint) }
                    .getOrElse { ProbeResult.Failed(it.message ?: "probe failed") }
            }
            _setup.value = when (result) {
                is ProbeResult.Ok -> SetupUi.Probed(result.report)
                is ProbeResult.CertificateDecision -> SetupUi.CertificateNeeded(result.certificate, result.reason)
                is ProbeResult.Failed -> SetupUi.Failed(result.message)
            }
            if (ownerPassword.isNotEmpty() && result is ProbeResult.Ok) {
                tokenStore.updatePassword(endpoint.id, ownerPassword)
            }
        }
    }

    /**
     * The owner explicitly accepted the device certificate shown in the
     * wizard. Pinning happens before any credential is sent.
     */
    fun trustCertificate(hostInput: String, certificate: DeviceCertificate, ownerPassword: String) {
        val endpoint = GrinderEndpoint.parse(hostInput).getOrElse { return }
        tokenStore.pinCertificate(endpoint.id, certificate.sha256)
        // A cached client still holds the previous pin; build a new one so the
        // pin the owner just accepted is the one that is used.
        invalidateTransport()
        probe(hostInput, ownerPassword)
    }

    /** Step 2: build the plan that the owner has to confirm before the root step. */
    fun prepareInstall(hostInput: String, ownerPassword: String) {
        val endpoint = GrinderEndpoint.parse(hostInput).getOrElse {
            _setup.value = SetupUi.Failed(it.message ?: "invalid device address")
            return
        }
        val plan = coordinator.plan(endpoint)
        _setup.value = SetupUi.Confirming(plan)
    }

    /** Step 3: the confirmed root step. */
    fun runInstall(hostInput: String, ownerPassword: String) {
        val endpoint = GrinderEndpoint.parse(hostInput).getOrElse {
            _setup.value = SetupUi.Failed(it.message ?: "invalid device address")
            return
        }
        _setup.value = SetupUi.Running(SetupProgress(SetupStage.UPLOADING_MODULE, "Starting"))
        viewModelScope.launch {
            val result = withContext(io) {
                runCatching { coordinator.install(endpoint, ownerPassword) { progress ->
                    _setup.value = SetupUi.Running(progress)
                } }.getOrElse { SetupResult.Failed(SetupStage.RUNNING_INSTALLER, it.message ?: "install failed") }
            }
            _setup.value = when (result) {
                is SetupResult.Ok -> {
                    // SetupCoordinator stores the token only after verification.
                    // Drop the cached client too: a re-install may have accepted
                    // a new pin, and the cached repository holds the old one.
                    invalidateTransport()
                    refresh()
                    SetupUi.Done(result.report)
                }

                is SetupResult.Failed -> SetupUi.Failed(result.message)
            }
        }
    }

    fun refresh() {
        _dashboard.value = _dashboard.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val endpoint = currentEndpoint()
            if (endpoint == null) {
                _dashboard.value = DashboardUi(connected = false, error = "No device configured. Run setup first.")
                return@launch
            }
            val caps = withContext(io) { withRepository { it.capabilities() } }
            val machine = withContext(io) { withRepository { it.machine() } }
            _dashboard.value = DashboardUi(
                connected = caps is ApiResult.Success,
                endpoint = endpoint.authority,
                machine = (machine as? ApiResult.Success)?.data,
                capabilities = (caps as? ApiResult.Success)?.data,
                loading = false,
                error = when {
                    caps is ApiResult.Failure -> caps.describe()
                    machine is ApiResult.Failure -> machine.describe()
                    else -> null
                },
            )
        }
    }

    fun loadLogs(kind: String, since: String? = null, until: String? = null) {
        val query = LogQuery(since = since?.takeIf { it.isNotBlank() }, until = until?.takeIf { it.isNotBlank() })
        _logs.value = _logs.value.copy(kind = kind, loading = true, error = null, since = since ?: _logs.value.since, until = until ?: _logs.value.until)
        viewModelScope.launch {
            val result = withContext(io) {
                withRepository { repository ->
                    when (kind) {
                        "service_log" -> repository.serviceLog(query)
                        "alert_log" -> repository.alertLog(query)
                        else -> repository.grindLog(query)
                    }
                }
            }
            _logs.value = when (result) {
                is ApiResult.Success -> _logs.value.copy(loading = false, page = result.data, error = null)
                is ApiResult.Failure -> _logs.value.copy(loading = false, error = result.describe())
            }
        }
    }

    fun shiftLogsPage(forward: Boolean) {
        val page = _logs.value.page ?: return
        val kind = _logs.value.kind
        val query = LogQuery(
            limit = page.limit,
            offset = if (forward) page.nextOffset else (page.offset - page.limit).coerceAtLeast(0),
            since = _logs.value.since.takeIf { it.isNotBlank() },
            until = _logs.value.until.takeIf { it.isNotBlank() },
        )
        viewModelScope.launch {
            _logs.value = _logs.value.copy(loading = true)
            val result = withContext(io) {
                withRepository { repository ->
                    when (kind) {
                        "service_log" -> repository.serviceLog(query)
                        "alert_log" -> repository.alertLog(query)
                        else -> repository.grindLog(query)
                    }
                }
            }
            _logs.value = when (result) {
                is ApiResult.Success -> _logs.value.copy(loading = false, page = result.data, error = null)
                is ApiResult.Failure -> _logs.value.copy(loading = false, error = result.describe())
            }
        }
    }

    fun loadData() {
        _data.value = _data.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val recipes = withContext(io) { withRepository { it.recipes() } }
            val portafilters = withContext(io) { withRepository { it.portafilters() } }
            val settings = withContext(io) { withRepository { it.settings() } }
            val config = withContext(io) { withRepository { it.config() } }
            _data.value = DataUi(
                recipes = (recipes as? ApiResult.Success)?.data.orEmpty(),
                portafilters = (portafilters as? ApiResult.Success)?.data.orEmpty(),
                settings = ((settings as? ApiResult.Success)?.data?.values).orEmpty(),
                settingsRedacted = ((settings as? ApiResult.Success)?.data?.redacted).orEmpty(),
                config = ((config as? ApiResult.Success)?.data?.values).orEmpty(),
                configRedacted = ((config as? ApiResult.Success)?.data?.redacted).orEmpty(),
                filePath = _data.value.filePath,
                loading = false,
                error = firstFailure(recipes, portafilters, settings, config),
            )
        }
    }

    fun readFile(path: String) {
        _data.value = _data.value.copy(filePath = path, loading = true, error = null)
        viewModelScope.launch {
            val result = withContext(io) { withRepository { it.file(path) } }
            _data.value = when (result) {
                is ApiResult.Success -> _data.value.copy(
                    loading = false,
                    fileEncoding = result.data.encoding,
                    fileContent = result.data.content,
                    error = null,
                )

                is ApiResult.Failure -> _data.value.copy(loading = false, error = result.describe())
            }
        }
    }

    fun clearError() {
        _data.value = _data.value.copy(error = null)
        _logs.value = _logs.value.copy(error = null)
        _dashboard.value = _dashboard.value.copy(error = null)
    }

    // --- Action layer -------------------------------------------------------
    // The confirm token is never part of ActionsUi: ActionApiClient keeps it in
    // memory and exchanges it by action id, so a state object, a log line or a
    // saved instance state can never carry it.

    /** Reads the gate and catalog, then the newest audit page. */
    fun loadActions() {
        _actions.value = _actions.value.copy(busy = true, error = null)
        viewModelScope.launch {
            val endpoint = currentEndpoint()
            if (endpoint == null) {
                _actions.value = ActionsUi(error = "No device configured. Run setup first.")
                return@launch
            }
            val client = actionClientFor(endpoint)
            val policy = withContext(io) { client.refreshPolicy() }
            if (policy is ApiResult.Failure) {
                _actions.value = _actions.value.copy(
                    busy = false,
                    error = ActionErrors.describe(policy),
                )
                return@launch
            }
            val actions = (policy as ApiResult.Success).data
            val audit = withContext(io) {
                client.audit(ActionAuditQuery(limit = _actions.value.auditLimit))
            }
            _actions.value = _actions.value.copy(
                policy = actions,
                busy = false,
                audit = (audit as? ApiResult.Success)?.data ?: _actions.value.audit,
                error = (audit as? ApiResult.Failure)?.let { ActionErrors.describe(it) },
                // A selected route may no longer be dispatchable after a policy
                // change; the gate is recomputed from the fresh snapshot by the UI.
                message = null,
            )
        }
    }

    fun selectActionRoute(route: String) {
        _actions.value = _actions.value.copy(
            selectedRoute = route,
            paramsText = ActionParams.EMPTY,
            status = null,
            activeActionId = null,
            message = null,
            error = null,
        )
    }

    fun updateActionParams(text: String) {
        _actions.value = _actions.value.copy(paramsText = text, error = null)
    }

    /** Validates the JSON locally, then asks the device to prepare the action. */
    fun prepareAction() {
        val state = _actions.value
        val route = state.selectedRoute
        if (route.isEmpty()) return
        val params = ActionParams.parse(state.paramsText).getOrElse { problem ->
            _actions.value = state.copy(error = problem.message)
            return
        }
        _actions.value = state.copy(busy = true, error = null, message = null)
        viewModelScope.launch {
            val result = withContext(io) { withActionClient { it.prepare(route, params) } }
            _actions.value = when (result) {
                is ApiResult.Success -> _actions.value.copy(
                    busy = false,
                    pending = result.data,
                    pendingRisk = _actions.value.policy?.entry(route)?.risk ?: "unknown",
                    activeActionId = result.data.actionId,
                    status = null,
                )

                is ApiResult.Failure -> _actions.value.copy(
                    busy = false,
                    error = ActionErrors.describe(result),
                )
            }
        }
    }

    /** The owner dismissed the confirm dialog: drop the token, run nothing. */
    fun dismissActionConfirm() {
        val pending = _actions.value.pending ?: return
        onActionClient { it.discard(pending.actionId) }
        _actions.value = _actions.value.copy(
            pending = null,
            activeActionId = null,
            message = "Not submitted. The confirm token was dropped without being used.",
        )
    }

    /** The owner confirmed: run the action, then read the final state back. */
    fun runConfirmedAction() {
        val pending = _actions.value.pending ?: return
        _actions.value = _actions.value.copy(busy = true, pending = null, error = null, message = null)
        viewModelScope.launch {
            val result = withContext(io) { withActionClient { it.execute(pending.actionId) } }
            val status = withContext(io) { withActionClient { it.status(pending.actionId) } }
            val failure = (result as? ApiResult.Failure) ?: (status as? ApiResult.Failure)
            // A transport failure means the request never reached the device, so
            // the client still holds the token: keep the dialog open for a retry.
            val neverArrived = failure != null && failure.errorCode == 0 && failure.httpStatus == 0
            _actions.value = _actions.value.copy(
                busy = false,
                pending = if (neverArrived) pending else null,
                activeActionId = pending.actionId,
                status = (status as? ApiResult.Success)?.data,
                message = (result as? ApiResult.Success)?.let { "The device reports: ${it.data.state}." },
                error = failure?.let { ActionErrors.describe(it) },
            )
        }
    }

    fun refreshActionStatus() {
        val actionId = _actions.value.activeActionId ?: return
        _actions.value = _actions.value.copy(busy = true, error = null)
        viewModelScope.launch {
            val result = withContext(io) { withActionClient { it.status(actionId) } }
            _actions.value = when (result) {
                is ApiResult.Success -> _actions.value.copy(busy = false, status = result.data, error = null)
                is ApiResult.Failure -> _actions.value.copy(busy = false, error = ActionErrors.describe(result))
            }
        }
    }

    /**
     * `action_cancel`. Before execute it ends the record; during execute the
     * device sends the stop primitive and reports `cancelling`. Either way the
     * client drops its confirmation, because a cancelled record never executes.
     */
    fun cancelAction() {
        val actionId = _actions.value.activeActionId ?: return
        _actions.value = _actions.value.copy(busy = true, error = null, message = null)
        viewModelScope.launch {
            val result = withContext(io) { withActionClient { it.cancel(actionId) } }
            val status = withContext(io) { withActionClient { it.status(actionId) } }
            _actions.value = _actions.value.copy(
                busy = false,
                pending = null,
                status = (status as? ApiResult.Success)?.data ?: _actions.value.status,
                message = when (result) {
                    is ApiResult.Success -> when {
                        result.data.cancelled -> "Cancelled before anything ran."
                        result.data.state == "cancelling" ->
                            "Stop sent to the device (stopSent=${result.data.stopSent}). " +
                                "The runner reports the final state."
                        else -> "The action is already ${result.data.state}; nothing to cancel."
                    }

                    is ApiResult.Failure -> null
                },
                error = (result as? ApiResult.Failure)?.let { ActionErrors.describe(it) },
            )
        }
    }

    fun loadActionAudit() {
        _actions.value = _actions.value.copy(busy = true, error = null)
        viewModelScope.launch {
            val result = withContext(io) {
                withActionClient { it.audit(ActionAuditQuery(limit = _actions.value.auditLimit)) }
            }
            _actions.value = when (result) {
                is ApiResult.Success -> _actions.value.copy(busy = false, audit = result.data, error = null)
                is ApiResult.Failure -> _actions.value.copy(busy = false, error = ActionErrors.describe(result))
            }
        }
    }

    fun clearActionNotice() {
        _actions.value = _actions.value.copy(error = null, message = null)
    }

    private fun <T> firstFailure(vararg results: ApiResult<T>): String? =
        results.filterIsInstance<ApiResult.Failure>().firstOrNull()?.describe()

    private fun currentEndpoint(): GrinderEndpoint? =
        tokenStore.activeEndpoint()?.let { GrinderEndpoint.parse(it).getOrNull() }

    /**
     * Runs one authenticated read against the cached repository. The repository
     * logs in with the stored owner password when its cookie jar has no vendor
     * session yet; a Local Owner API route rejects a token-only request.
     */
    private fun <T> withRepository(action: (LocalApiRepository) -> ApiResult<T>): ApiResult<T> {
        val endpoint = currentEndpoint()
            ?: return ApiResult.Failure(0, "No device configured. Run setup first.")
        return action(repositoryFor(endpoint))
    }

    /**
     * Runs one action-layer call against the cached client. Same endpoint and
     * same repository as a read route, so the vendor session, the owner token
     * and the TLS pin are shared; only the in-memory confirm token is extra.
     */
    private fun <T> withActionClient(action: (ActionApiClient) -> ApiResult<T>): ApiResult<T> {
        val endpoint = currentEndpoint()
            ?: return ApiResult.Failure(0, "No device configured. Run setup first.")
        return action(actionClientFor(endpoint))
    }

    /** Runs a side effect on the cached action client (no device call). */
    private fun onActionClient(action: (ActionApiClient) -> Unit) {
        val endpoint = currentEndpoint() ?: return
        action(actionClientFor(endpoint))
    }

    /**
     * One repository (and therefore one cookie jar) per endpoint for the life
     * of this ViewModel. A fresh jar per call would drop the PHPSESSID after
     * the login and every read would answer with the vendor login page.
     */
    @Volatile
    private var cachedRepository: Pair<String, LocalApiRepository>? = null

    private fun repositoryFor(endpoint: GrinderEndpoint): LocalApiRepository {
        cachedRepository?.let { (id, repository) -> if (id == endpoint.id) return repository }
        val jar = CookieJar()
        val client = DeviceHttpClient(
            endpoint,
            jar,
            PinnedTrustManager(tokenStore.pinnedCertificate(endpoint.id)),
        )
        val repository = LocalApiRepository(
            endpoint,
            client,
            jar,
            tokenProvider = { tokenStore.token(endpoint.id) },
            passwordProvider = { tokenStore.ownerPassword(endpoint.id) },
        )
        cachedRepository = endpoint.id to repository
        return repository
    }

    /**
     * One action client per endpoint, for the same reason as the repository: it
     * holds the confirm token between prepare and execute. It is recreated with
     * the repository whenever the pin or the token changes.
     */
    @Volatile
    private var cachedActionClient: Pair<String, ActionApiClient>? = null

    private fun actionClientFor(endpoint: GrinderEndpoint): ActionApiClient {
        cachedActionClient?.let { (id, client) -> if (id == endpoint.id) return client }
        val client = ActionApiClient(repositoryFor(endpoint))
        cachedActionClient = endpoint.id to client
        return client
    }

    /** Drops the cached transport so a new pin or token takes effect. */
    private fun invalidateTransport() {
        cachedActionClient?.second?.discardAll()
        cachedActionClient = null
        cachedRepository = null
    }

    override fun onCleared() {
        // The confirm tokens live only in this object graph; clear them before
        // the dispatcher goes away.
        cachedActionClient?.second?.discardAll()
        cachedActionClient = null
        io.close()
        super.onCleared()
    }
}
