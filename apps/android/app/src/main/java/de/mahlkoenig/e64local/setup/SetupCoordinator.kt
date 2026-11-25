package de.mahlkoenig.e64local.setup

import de.mahlkoenig.e64local.storage.TokenStore
import de.mahlkoenig.e64local.device.CookieJar
import de.mahlkoenig.e64local.device.DeviceCertificate
import de.mahlkoenig.e64local.device.DeviceHttpClient
import de.mahlkoenig.e64local.device.GrinderEndpoint
import de.mahlkoenig.e64local.device.LocalApiRepository
import de.mahlkoenig.e64local.device.LoginPageFingerprint
import de.mahlkoenig.e64local.device.PinnedTrustManager
import de.mahlkoenig.e64local.core.ApiResult
import de.mahlkoenig.e64local.core.Redaction
import java.security.MessageDigest

/** Facts read from the device before anything is installed. */
data class ProbeReport(
    val endpoint: GrinderEndpoint,
    val certificateSha256: String,
    val certificateSubject: String,
    val fingerprint: LoginPageFingerprint,
    val httpStatus: Int,
    val alreadyInstalled: Boolean,
    val tokenPresent: Boolean,
)

sealed interface ProbeResult {
    data class Ok(val report: ProbeReport) : ProbeResult
    /** The certificate is not pinned yet, or changed; the owner must decide. */
    data class CertificateDecision(val certificate: DeviceCertificate, val reason: String) : ProbeResult
    data class Failed(val message: String) : ProbeResult
}

enum class SetupStage { PROBING, UPLOADING_MODULE, RUNNING_INSTALLER, VERIFYING, DONE }

data class SetupProgress(val stage: SetupStage, val detail: String)

sealed interface SetupResult {
    data class Ok(val token: String, val report: ProbeReport) : SetupResult
    data class Failed(val stage: SetupStage, val message: String) : SetupResult
}

/**
 * Orchestrates probe, root install and verification.
 *
 * The order is fixed and each step fails closed:
 * 1. `GET /login.php` — fingerprint model/firmware/dev mode without credentials.
 * 2. `POST /rest_api/capabilities` with the stored token — detect an existing install.
 * 3. Upload the bundled module (base64, 40000-char appends) and run the installer.
 * 4. `POST /rest_api/capabilities` again with the new token; success only if that
 *    response is a valid `e64local-api-v1` document.
 */
class SetupCoordinator(
    private val tokenStore: TokenStore,
    private val moduleProvider: () -> ByteArray,
    private val runnerProvider: () -> ByteArray,
    /** Seam for the TLS fingerprint probe; the app default reads the real certificate. */
    private val certificateProbe: (GrinderEndpoint) -> Result<DeviceCertificate> = { endpoint ->
        DeviceHttpClient.probeCertificate(endpoint)
    },
    /** Seam for the HTTP client; the app default builds a pinned client. */
    private val clientFactory: (GrinderEndpoint, CookieJar, String?) -> DeviceHttpClient = { endpoint, jar, pin ->
        DeviceHttpClient(endpoint, jar, PinnedTrustManager(pin))
    },
) {
    fun moduleSha256(): String = MessageDigest.getInstance("SHA-256")
        .digest(moduleProvider())
        .joinToString("") { "%02x".format(it) }

    fun runnerSha256(): String = MessageDigest.getInstance("SHA-256")
        .digest(runnerProvider())
        .joinToString("") { "%02x".format(it) }

    fun probe(endpoint: GrinderEndpoint): ProbeResult {
        val certificate = certificateProbe(endpoint).getOrElse {
            return ProbeResult.Failed(it.message ?: "cannot reach the device")
        }
        val pinned = tokenStore.pinnedCertificate(endpoint.id)
        if (pinned == null) {
            return ProbeResult.CertificateDecision(
                certificate,
                "The device uses a self-signed certificate. Compare this fingerprint with " +
                    "the one shown by `e64root probe` before you trust it.",
            )
        }
        if (PinnedTrustManager.normalize(pinned) != certificate.sha256) {
            return ProbeResult.CertificateDecision(
                certificate,
                "The certificate changed since you trusted this device. Accept the new " +
                    "fingerprint only if you expect it (for example after a factory reset).",
            )
        }

        val jar = CookieJar()
        val client = makeClient(endpoint, jar)
        return try {
            val page = client.get(Fw01Injection.LOGIN_PATH)
            if (page.status != 200) {
                return ProbeResult.Failed("GET /login.php returned HTTP ${page.status}; this is not the grinder web UI")
            }
            val fingerprint = LoginPageFingerprint.parse(page.body)
            val token = tokenStore.token(endpoint.id)
            var installed = false
            var tokenPresent = false
            if (!token.isNullOrEmpty()) {
                val repository = LocalApiRepository(endpoint, client, jar, tokenProvider = { token })
                // The vendor login is best effort: the password may not be
                // stored, and a stored token is still probed for readiness.
                repository.login(tokenStore.ownerPassword(endpoint.id).orEmpty())
                when (val capabilities = repository.capabilities()) {
                    is ApiResult.Success -> {
                        installed = capabilities.data.isLocalApiV1
                        tokenPresent = true
                    }

                    is ApiResult.Failure -> tokenPresent = capabilities.isTokenProblem
                }
            }
            ProbeResult.Ok(
                ProbeReport(
                    endpoint = endpoint,
                    certificateSha256 = certificate.sha256,
                    certificateSubject = certificate.subject,
                    fingerprint = fingerprint,
                    httpStatus = page.status,
                    alreadyInstalled = installed,
                    tokenPresent = tokenPresent,
                ),
            )
        } catch (exc: Exception) {
            ProbeResult.Failed(Redaction.redact(exc.message ?: exc.javaClass.simpleName))
        }
    }

    /**
     * Runs the root install. Callers must have shown [plan] and received an
     * explicit confirmation before invoking this.
     */
    fun install(
        endpoint: GrinderEndpoint,
        ownerPassword: String,
        onProgress: (SetupProgress) -> Unit,
    ): SetupResult {
        val module = moduleProvider()
        val runner = runnerProvider()
        val moduleSha = moduleSha256()
        val token = OwnerToken.generate()
        val commands = SetupCommands(moduleSha, runnerSha256())

        val jar = CookieJar()
        val client = makeClient(endpoint, jar)

        onProgress(SetupProgress(SetupStage.UPLOADING_MODULE, "Uploading the local API module"))
        val installerScript = commands.script(token)

        // The bytes are base64 chunks that decode straight into the staging
        // files; the installer then copies them into place, writes the token
        // and verifies every digest and mode.
        val moduleCommands = Fw01Injection.uploadCommands(
            String(module, Charsets.UTF_8),
            SetupCommands.MODULE_STAGE,
            execute = false,
        )
        val runnerCommands = Fw01Injection.uploadCommands(
            String(runner, Charsets.UTF_8),
            SetupCommands.RUNNER_STAGE,
            execute = false,
        )
        val installerCommands = Fw01Injection.uploadCommands(installerScript, SetupCommands.INSTALLER_STAGE)

        val total = moduleCommands.size + runnerCommands.size + installerCommands.size
        var sent = 0
        try {
            for (command in moduleCommands) {
                send(client, command)
                sent++
                onProgress(SetupProgress(SetupStage.UPLOADING_MODULE, "Uploading $sent/$total"))
            }
            for (command in runnerCommands) {
                send(client, command)
                sent++
                onProgress(SetupProgress(SetupStage.UPLOADING_MODULE, "Uploading $sent/$total"))
            }
            onProgress(SetupProgress(SetupStage.RUNNING_INSTALLER, "Running the installer as root"))
            for (command in installerCommands) {
                send(client, command)
                sent++
                onProgress(SetupProgress(SetupStage.RUNNING_INSTALLER, "Installing $sent/$total"))
            }
        } catch (exc: Exception) {
            val stage = if (sent <= moduleCommands.size + runnerCommands.size) {
                SetupStage.UPLOADING_MODULE
            } else {
                SetupStage.RUNNING_INSTALLER
            }
            return SetupResult.Failed(stage, Redaction.redact(exc.message ?: "upload failed"))
        }

        onProgress(SetupProgress(SetupStage.VERIFYING, "Verifying the owner token"))
        // login.php only runs the injected command; the module lives in the
        // existing www tree, so a vendor session is enough to verify it. A
        // fresh client is used so a new session cookie is obtained cleanly.
        val verifyJar = CookieJar()
        val verifyClient = makeClient(endpoint, verifyJar)
        val repository = LocalApiRepository(endpoint, verifyClient, verifyJar, tokenProvider = { token })
        val login = repository.login(ownerPassword)
        if (login is ApiResult.Failure) {
            return SetupResult.Failed(SetupStage.VERIFYING, "vendor login failed: ${login.message}")
        }
        val capabilities = repository.capabilities()
        if (capabilities !is ApiResult.Success) {
            val failure = capabilities as ApiResult.Failure
            return SetupResult.Failed(
                SetupStage.VERIFYING,
                "the module did not answer with the new token: ${failure.message}",
            )
        }
        if (!capabilities.data.isLocalApiV1) {
            // A 200 envelope from something that is not the reviewed module is
            // not proof that the install worked. Fail closed and store nothing.
            return SetupResult.Failed(
                SetupStage.VERIFYING,
                "the device answered with an unexpected document " +
                    "(schema '${capabilities.data.schema}', apiVersion '${capabilities.data.apiVersion}')",
            )
        }

        // Only now is the credential stored.
        tokenStore.save(endpoint.id, token, ownerPassword)
        onProgress(SetupProgress(SetupStage.DONE, "Local Owner API v1 is installed"))
        val report = when (val verification = probe(endpoint)) {
            is ProbeResult.Ok -> verification.report
            else -> ProbeReport(
                endpoint = endpoint,
                certificateSha256 = tokenStore.pinnedCertificate(endpoint.id).orEmpty(),
                certificateSubject = "",
                fingerprint = LoginPageFingerprint("", "", "", false, true),
                httpStatus = 200,
                alreadyInstalled = true,
                tokenPresent = true,
            )
        }
        return SetupResult.Ok(token, report)
    }

    /** The exact commands and the installer script, for the confirmation screen. */
    fun plan(endpoint: GrinderEndpoint): SetupPlan {
        val moduleSha = moduleSha256()
        val runnerSha = runnerSha256()
        val commands = SetupCommands(moduleSha, runnerSha)
        val script = commands.script("0".repeat(OwnerToken.LENGTH))
        val moduleBytes = moduleProvider()
        val runnerBytes = runnerProvider()
        return SetupPlan(
            moduleSha256 = moduleSha,
            moduleBytes = moduleBytes.size,
            runnerSha256 = runnerSha,
            runnerBytes = runnerBytes.size,
            installerScript = script,
            moduleUploadCommands = Fw01Injection.uploadCommands(
                String(moduleBytes, Charsets.UTF_8),
                SetupCommands.MODULE_STAGE,
                execute = false,
            ),
            runnerUploadCommands = Fw01Injection.uploadCommands(
                String(runnerBytes, Charsets.UTF_8),
                SetupCommands.RUNNER_STAGE,
                execute = false,
            ),
            installerCommands = Fw01Injection.uploadCommands(script, SetupCommands.INSTALLER_STAGE),
        )
    }

    private fun send(client: DeviceHttpClient, command: String) {
        Fw01Injection.validate(command).getOrThrow()
        val response = client.postForm(Fw01Injection.LOGIN_PATH, Fw01Injection.loginForm(command))
        if (response.status >= 500) {
            throw IllegalStateException("login.php returned HTTP ${response.status} for an upload step")
        }
    }

    private fun makeClient(endpoint: GrinderEndpoint, jar: CookieJar): DeviceHttpClient {
        val pin = tokenStore.pinnedCertificate(endpoint.id)
        return clientFactory(endpoint, jar, pin)
    }

}

data class SetupPlan(
    val moduleSha256: String,
    val moduleBytes: Int,
    val runnerSha256: String,
    val runnerBytes: Int,
    val installerScript: String,
    val moduleUploadCommands: List<String>,
    val runnerUploadCommands: List<String>,
    val installerCommands: List<String>,
) {
    val commandCount: Int
        get() = moduleUploadCommands.size + runnerUploadCommands.size + installerCommands.size
}
