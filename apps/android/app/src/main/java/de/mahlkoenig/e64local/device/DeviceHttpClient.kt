package de.mahlkoenig.e64local.device

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URI
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class TransportResponse(
    val status: Int,
    val body: String,
    val contentType: String?,
    val setCookieHeaders: List<String>,
    val location: String?,
)

class TransportException(message: String, cause: Throwable? = null) : IOException(message, cause)

data class DeviceCertificate(
    val sha256: String,
    val subject: String,
    val issuer: String,
    val notAfter: String,
    val tlsVersion: String,
)

/**
 * The only network code in the app.
 *
 * `HttpURLConnection` is deliberate: no third-party client, no analytics
 * interceptor and no redirect to a host the owner did not enter. Proxy
 * settings are bypassed (as the repository's `e64root` client does) so a
 * corporate proxy can never become an intermediary for a LAN appliance.
 */
open class DeviceHttpClient(
    private val endpoint: GrinderEndpoint,
    val cookieJar: CookieJar,
    private val pinnedTrustManager: PinnedTrustManager,
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 20_000,
) {
    open fun get(path: String): TransportResponse = execute("GET", path, null, emptyMap())

    open fun postForm(path: String, fields: Map<String, String>): TransportResponse {
        val body = fields.entries.joinToString("&") { (key, value) ->
            encode(key) + "=" + encode(value)
        }
        return execute(
            "POST",
            path,
            body,
            mapOf("Content-Type" to "application/x-www-form-urlencoded"),
        )
    }

    open fun postJson(path: String, json: String, extraHeaders: Map<String, String> = emptyMap()): TransportResponse =
        execute("POST", path, json, mapOf("Content-Type" to "application/json") + extraHeaders)

    private fun execute(
        method: String,
        path: String,
        body: String?,
        headers: Map<String, String>,
    ): TransportResponse {
        val url = URI.create(endpoint.url(path)).toURL()
        val connection = url.openConnection(Proxy.NO_PROXY) as HttpsURLConnection
        try {
            connection.sslSocketFactory = sslContext().socketFactory
            // A self-signed certificate is only accepted after the owner pins its
            // SHA-256 fingerprint, so the pin replaces the CA/hostname chain:
            // PinnedTrustManager rejects any certificate that is not the pinned
            // one. Verification is therefore not disabled, it is narrowed.
            connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.instanceFollowRedirects = false
            connection.requestMethod = method
            connection.setRequestProperty("Accept", "application/json, text/html;q=0.9")
            connection.setRequestProperty("User-Agent", "e64local-android/1")
            for ((name, value) in headers) connection.setRequestProperty(name, value)
            cookieJar.headerFor(endpoint.host, path)?.let {
                connection.setRequestProperty("Cookie", it)
            }
            if (body != null) {
                val bytes = body.toByteArray(Charsets.UTF_8)
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(bytes.size)
                connection.outputStream.use { it.write(bytes) }
            }

            val status = connection.responseCode
            val setCookies = connection.headerFields
                .filterKeys { it.equals("Set-Cookie", ignoreCase = true) }
                .values.flatten()
            if (setCookies.isNotEmpty()) cookieJar.storeFromSetCookie(setCookies, endpoint.host)

            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val text = stream?.use { it.readBytes().toString(Charsets.UTF_8) }.orEmpty()
            return TransportResponse(
                status = status,
                body = text,
                contentType = connection.contentType,
                setCookieHeaders = setCookies,
                location = connection.getHeaderField("Location"),
            )
        } catch (exc: java.net.SocketTimeoutException) {
            throw TransportException("The device did not answer in time (${readTimeoutMs / 1000}s)", exc)
        } catch (exc: javax.net.ssl.SSLException) {
            throw TransportException(describeTlsFailure(exc), exc)
        } catch (exc: IOException) {
            throw TransportException("Cannot reach ${endpoint.authority}: ${exc.message ?: exc.javaClass.simpleName}", exc)
        } finally {
            connection.disconnect()
        }
    }

    fun sslContext(): SSLContext = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf<TrustManager>(pinnedTrustManager), java.security.SecureRandom())
    }

    private fun describeTlsFailure(exc: Throwable): String {
        var cause: Throwable? = exc
        while (cause != null) {
            if (cause is CertificateException) return cause.message ?: "certificate rejected"
            cause = cause.cause
        }
        return "TLS handshake failed: ${exc.message ?: "unknown error"}"
    }

    private fun encode(value: String): String =
        java.net.URLEncoder.encode(value, "UTF-8")

    companion object {
        /**
         * Reads the certificate the device presents without trusting it.
         * Used only to show the fingerprint for the explicit opt-in; no
         * credential is sent over this probe connection.
         */
        fun probeCertificate(endpoint: GrinderEndpoint, timeoutMs: Int = 8_000): Result<DeviceCertificate> {
            val context = SSLContext.getInstance("TLS").apply {
                init(null, arrayOf<TrustManager>(AcceptAnyForFingerprint()), java.security.SecureRandom())
            }
            val factory = context.socketFactory as SSLSocketFactory
            val raw = Socket()
            return try {
                raw.connect(InetSocketAddress(endpoint.host, endpoint.port), timeoutMs)
                raw.soTimeout = timeoutMs
                val socket = factory.createSocket(raw, endpoint.host, endpoint.port, true) as SSLSocket
                socket.use {
                    it.startHandshake()
                    val peer = it.session.peerCertificates.firstOrNull() as? X509Certificate
                        ?: return Result.failure(TransportException("the device presented no certificate"))
                    Result.success(
                        DeviceCertificate(
                            sha256 = PinnedTrustManager.fingerprint(peer),
                            subject = peer.subjectDN.name,
                            issuer = peer.issuerDN.name,
                            notAfter = peer.notAfter.toString(),
                            tlsVersion = it.session.protocol ?: "",
                        ),
                    )
                }
            } catch (exc: IOException) {
                Result.failure(TransportException("TLS probe failed: ${exc.message ?: exc.javaClass.simpleName}", exc))
            } catch (exc: java.security.GeneralSecurityException) {
                Result.failure(TransportException("TLS probe failed: ${exc.message}", exc))
            } finally {
                runCatching { raw.close() }
            }
        }

        private class AcceptAnyForFingerprint : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
    }
}
