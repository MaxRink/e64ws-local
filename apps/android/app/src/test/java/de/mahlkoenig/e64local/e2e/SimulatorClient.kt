package de.mahlkoenig.e64local.e2e

import de.mahlkoenig.e64local.device.CookieJar
import de.mahlkoenig.e64local.device.DeviceHttpClient
import de.mahlkoenig.e64local.device.GrinderEndpoint
import de.mahlkoenig.e64local.device.JsonRequest
import de.mahlkoenig.e64local.device.LocalApiRepository
import de.mahlkoenig.e64local.device.PinnedTrustManager
import java.util.Collections

/**
 * One simulator, dialled exactly the way the app dials a grinder.
 *
 * Nothing here is a test double: [client] is the production
 * [DeviceHttpClient] (HttpURLConnection, the app's cookie jar, the app's pinned
 * trust manager) and [repository] is the production [LocalApiRepository]. The
 * only additions are a recorder for the requests the repository issued and the
 * wire log of the loopback bridge in front of the simulator.
 *
 * The bridge exists because the runner states the simulator address as plain
 * `http` while the app's production client is TLS-only with a pinned
 * certificate. Putting the terminator on loopback keeps the app's stack
 * unchanged: a real TLS handshake, a real pin check, the real cookie jar and
 * the real envelope handling.
 */
internal class SimulatorClient(
    val base: E2EEnvironment.Target,
    val token: String,
    val password: String,
) : AutoCloseable {
    private val observed = Collections.synchronizedList(mutableListOf<JsonRequest>())

    private val bridge: LoopbackTlsBridge = LoopbackTlsBridge.to(base)

    val cookieJar = CookieJar()

    val endpoint = GrinderEndpoint("127.0.0.1", bridge.port)

    /** The SHA-256 the app would show the owner before accepting the device. */
    val pin: String = bridge.fingerprint

    val client = DeviceHttpClient(endpoint, cookieJar, PinnedTrustManager(pin))

    val repository = LocalApiRepository(
        endpoint,
        client,
        cookieJar,
        tokenProvider = { token },
        passwordProvider = { password },
        onRequest = { request -> observed += request },
    )

    /** Every route request the repository issued, in order. */
    val requests: List<JsonRequest> get() = synchronized(observed) { observed.toList() }

    /** Every byte that crossed the loopback bridge. */
    val exchanges: List<WireLog.Entry> get() = bridge.exchanges.all

    fun exchangesTo(path: String): List<WireLog.Entry> = exchanges.filter { it.path == path }

    fun lastExchangeTo(path: String): WireLog.Entry? = exchanges.lastOrNull { it.path == path }

    fun clearRequests() {
        observed.clear()
    }

    fun clearWire() {
        bridge.exchanges.clear()
    }

    /**
     * A second repository on the same certificate and session but a different
     * owner token, so a `401` can be provoked without disturbing the first one.
     */
    fun repositoryWithToken(otherToken: String, otherPassword: String? = password): LocalApiRepository =
        LocalApiRepository(
            endpoint,
            client,
            cookieJar,
            tokenProvider = { otherToken },
            passwordProvider = { otherPassword },
            onRequest = { request -> observed += request },
        )

    override fun close() {
        bridge.close()
    }
}
