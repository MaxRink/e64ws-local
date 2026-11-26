package de.mahlkoenig.e64local.e2e

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import de.mahlkoenig.e64local.device.PinnedTrustManager
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/**
 * The certificate the suite's loopback TLS bridge presents.
 *
 * The app's production stack is TLS-only (`HttpsURLConnection` plus a pinned
 * certificate), while the runner hands the suite a plain-http simulator
 * address. Rather than teach the app a cleartext mode, the suite terminates TLS
 * on loopback in front of the simulator and pins the certificate it generated,
 * so every request the app makes is still a real TLS request through the real
 * pin check.
 *
 * The key pair is generated once per test JVM by the JDK's own `keytool`, lives
 * in a temporary directory and is deleted with the JVM. It is never committed.
 */
internal class TlsFixture private constructor(
    private val keyStore: KeyStore,
    private val password: CharArray,
    val certificate: X509Certificate,
) {
    /** Lower-case hex SHA-256 of the certificate, the form [PinnedTrustManager] expects. */
    val fingerprint: String get() = PinnedTrustManager.fingerprint(certificate)

    fun sslContext(): SSLContext {
        val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        managers.init(keyStore, password)
        return SSLContext.getInstance("TLS").apply {
            init(managers.keyManagers, null, SecureRandom())
        }
    }

    companion object {
        private const val ALIAS = "e64-e2e-bridge"
        private val installed: TlsFixture by lazy { generate() }

        fun shared(): TlsFixture = installed

        private fun generate(): TlsFixture {
            val directory = java.nio.file.Files.createTempDirectory("e64-e2e-tls").toFile()
            directory.deleteOnExit()
            val store = File(directory, "bridge.p12").also { it.deleteOnExit() }
            val password = "e64-e2e-bridge".toCharArray()
            val keytool = findKeytool()
            val command = listOf(
                keytool.absolutePath,
                "-genkeypair",
                "-alias", ALIAS,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-sigalg", "SHA256withRSA",
                "-dname", "CN=127.0.0.1,O=e64local e2e fixture",
                "-ext", "SAN=ip:127.0.0.1,dns:localhost",
                "-validity", "2",
                "-storetype", "PKCS12",
                "-keystore", store.absolutePath,
                "-storepass", String(password),
                "-keypass", String(password),
            )
            val process = try {
                ProcessBuilder(command).redirectErrorStream(true).start()
            } catch (failure: IOException) {
                throw E2EFailure("cannot run ${keytool.absolutePath} to build the e2e bridge certificate: ${failure.message}")
            }
            val output = process.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
            val code = process.waitFor()
            if (code != 0) {
                throw E2EFailure("keytool could not create the e2e bridge certificate (exit $code): ${output.take(500)}")
            }
            val keyStore = KeyStore.getInstance("PKCS12").apply {
                FileInputStream(store).use { load(it, password) }
            }
            val certificate = keyStore.getCertificate(ALIAS) as? X509Certificate
                ?: throw E2EFailure("the generated keystore has no certificate")
            return TlsFixture(keyStore, password, certificate)
        }

        private fun findKeytool(): File {
            val home = System.getProperty("java.home")?.let(::File)
            if (home != null) {
                for (name in listOf("keytool", "keytool.exe")) {
                    val candidate = File(File(home, "bin"), name)
                    if (candidate.isFile && candidate.canExecute()) return candidate
                }
            }
            val path = System.getenv("PATH").orEmpty().split(File.pathSeparatorChar)
            for (element in path) {
                for (name in listOf("keytool", "keytool.exe")) {
                    val candidate = File(element, name)
                    if (candidate.isFile && candidate.canExecute()) return candidate
                }
            }
            throw E2EFailure(
                "no keytool found (looked in java.home/bin and PATH); the suite needs it to create " +
                    "the loopback TLS certificate the app's pinned client talks to",
            )
        }
    }
}

/**
 * A loopback HTTPS endpoint that forwards every request, byte for byte, to the
 * simulator address the runner supplied.
 *
 * It is a transport adapter, not a double: it invents no answer, rewrites no
 * body and adds no header. The upstream leg is spoken on a raw socket on
 * purpose. `HttpURLConnection` (which the app itself uses) refuses to expose the
 * body of a `401`, so a bridge built on it would silently turn the device's
 * "owner token required" into an empty answer and hide a real app-side
 * limitation. The raw leg keeps [exchanges] faithful to the device.
 */
internal class LoopbackTlsBridge private constructor(
    private val upstreamScheme: String,
    private val upstreamHost: String,
    private val upstreamPort: Int,
    private val tls: TlsFixture,
    private val server: HttpsServer,
) : AutoCloseable {
    val exchanges = WireLog()

    val port: Int get() = server.address.port

    val fingerprint: String get() = tls.fingerprint

    private fun handle(exchange: HttpExchange) {
        try {
            val requestBody = exchange.requestBody.use { it.readBytes() }.toString(Charsets.UTF_8)
            val requestHeaders = LinkedHashMap<String, String>()
            for ((name, values) in exchange.requestHeaders) {
                requestHeaders[name] = values.joinToString(", ")
            }
            val path = exchange.requestURI.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
            val answer = try {
                RawHttp.forward(
                    scheme = upstreamScheme,
                    host = upstreamHost,
                    port = upstreamPort,
                    method = exchange.requestMethod,
                    path = path,
                    query = exchange.requestURI.rawQuery,
                    requestHeaders = requestHeaders,
                    body = requestBody,
                )
            } catch (failure: IOException) {
                RawHttp.Answer(
                    502,
                    listOf("Content-Type" to "application/json"),
                    "{\"success\":false,\"errorCode\":502,\"error\":\"e2e bridge cannot reach " +
                        "${E2EReport.oneLine(failure.message)}\"}",
                )
            }
            for ((name, value) in answer.headers) {
                if (name.equals("Content-Type", ignoreCase = true) ||
                    name.equals("Location", ignoreCase = true) ||
                    name.equals("Set-Cookie", ignoreCase = true) ||
                    name.equals("Content-Description", ignoreCase = true) ||
                    name.equals("Content-Disposition", ignoreCase = true) ||
                    name.equals("Authorization", ignoreCase = true)
                ) {
                    exchange.responseHeaders.add(name, value)
                }
            }
            // Record before responding, in the same step that builds the
            // answer. Every check of the suite reads this log once its call has
            // returned, so the entry must be in it by the time any client can
            // see the answer. Appending after `respond()` - which is what the
            // `finally` used to do, once the body was already flushed - left the
            // caller racing this handler thread: it could receive a served
            // answer whose entry had not been written yet, and report "the
            // request did not cross the loopback bridge" for a request that did.
            //
            // Fields and their order are unchanged, so every assertion that
            // reads an entry keeps its meaning, and the entry is built from the
            // very [RawHttp.Answer] that is sent next.
            exchanges.add(
                WireLog.Entry(
                    method = exchange.requestMethod,
                    path = path,
                    requestHeaders = requestHeaders,
                    requestBody = requestBody,
                    status = answer.status,
                    responseBody = answer.body,
                ),
            )
            respond(exchange, answer.status, answer.body)
        } finally {
            try {
                exchange.close()
            } catch (_: Throwable) {
                // The client may already have closed the stream; nothing to do.
            }
        }
    }

    private fun respond(exchange: HttpExchange, status: Int, body: String) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty()) {
            exchange.sendResponseHeaders(status, -1)
            return
        }
        exchange.sendResponseHeaders(status, bytes.size.toLong())
        exchange.responseBody.use { it.write(bytes) }
    }

    override fun close() {
        server.stop(0)
    }

    companion object {
        fun to(upstream: E2EEnvironment.Target, tls: TlsFixture = TlsFixture.shared()): LoopbackTlsBridge {
            val server = HttpsServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
            val bridge = LoopbackTlsBridge(upstream.scheme, upstream.host, upstream.port, tls, server)
            server.httpsConfigurator = HttpsConfigurator(tls.sslContext())
            server.createContext("/") { exchange -> bridge.handle(exchange) }
            server.executor = Executors.newCachedThreadPool { runnable ->
                Thread(runnable, "e64-e2e-bridge").apply { isDaemon = true }
            }
            server.start()
            return bridge
        }
    }
}

/** The request headers the bridge forwards; nothing else leaves the loopback leg. */
private val FORWARDED_HEADERS = listOf(
    "Accept",
    "Content-Type",
    "Cookie",
    "User-Agent",
    "X-E64-Local-Token",
)

/**
 * A minimal HTTP/1.0 client for the loopback leg.
 *
 * It reads the status line, the headers and then the body (by `Content-Length`,
 * by chunked framing, or to end of stream), so every status code keeps its body
 * - including `401`, which `HttpURLConnection` does not expose.
 */
private object RawHttp {
    data class Answer(val status: Int, val headers: List<Pair<String, String>>, val body: String)

    fun forward(
        scheme: String,
        host: String,
        port: Int,
        method: String,
        path: String,
        query: String?,
        requestHeaders: Map<String, String>,
        body: String,
    ): Answer {
        val target = if (query.isNullOrEmpty()) path else "$path?$query"
        val socket = Socket()
        try {
            socket.connect(InetSocketAddress(host, port), 5_000)
            socket.soTimeout = 20_000
            val connection: Socket = if (scheme == "https") {
                val factory = LoopbackTrust.context().socketFactory
                (factory.createSocket(socket, host, port, true) as SSLSocket).apply { startHandshake() }
            } else {
                socket
            }
            val bytes = body.toByteArray(Charsets.UTF_8)
            val head = StringBuilder()
                .append(method).append(' ').append(target).append(" HTTP/1.0\r\n")
                .append("Host: ").append(host).append(':').append(port).append("\r\n")
            for (name in FORWARDED_HEADERS) {
                val value = requestHeaders.entries
                    .firstOrNull { it.key.equals(name, ignoreCase = true) }
                    ?.value
                if (value != null) head.append(name).append(": ").append(value).append("\r\n")
            }
            head.append("Content-Length: ").append(bytes.size).append("\r\n")
                .append("Connection: close\r\n\r\n")

            val out = BufferedOutputStream(connection.getOutputStream())
            out.write(head.toString().toByteArray(Charsets.ISO_8859_1))
            if (bytes.isNotEmpty()) out.write(bytes)
            out.flush()

            val input = BufferedInputStream(connection.getInputStream())
            val statusLine = readLine(input)
                ?: throw IOException("the device closed the connection without a status line")
            val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull()
                ?: throw IOException("the device sent a malformed status line: $statusLine")
            val headers = ArrayList<Pair<String, String>>()
            while (true) {
                val line = readLine(input) ?: break
                if (line.isEmpty()) break
                val separator = line.indexOf(':')
                if (separator <= 0) continue
                headers += line.substring(0, separator).trim() to line.substring(separator + 1).trim()
            }
            val chunked = headers.any {
                it.first.equals("Transfer-Encoding", ignoreCase = true) &&
                    it.second.contains("chunked", ignoreCase = true)
            }
            val declared = headers.firstOrNull { it.first.equals("Content-Length", ignoreCase = true) }
                ?.second
                ?.toIntOrNull()
            val payload = when {
                chunked -> readChunked(input)
                declared != null -> readExactly(input, declared)
                else -> input.readBytes()
            }
            return Answer(status, headers, payload.toString(Charsets.UTF_8))
        } finally {
            try {
                socket.close()
            } catch (_: IOException) {
                // Closing a broken socket is not an error worth reporting.
            }
        }
    }

    private fun readLine(input: InputStream): String? {
        val buffer = java.io.ByteArrayOutputStream()
        while (true) {
            val byte = input.read()
            if (byte < 0) {
                if (buffer.size() == 0) return null
                break
            }
            if (byte == '\n'.code) break
            if (byte != '\r'.code) buffer.write(byte)
        }
        return buffer.toString("ISO-8859-1")
    }

    private fun readExactly(input: InputStream, length: Int): ByteArray {
        val bytes = ByteArray(length)
        var read = 0
        while (read < length) {
            val count = input.read(bytes, read, length - read)
            if (count < 0) break
            read += count
        }
        return if (read == length) bytes else bytes.copyOf(read)
    }

    private fun readChunked(input: InputStream): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        while (true) {
            val sizeLine = readLine(input) ?: break
            val size = sizeLine.substringBefore(';').trim().toIntOrNull(16) ?: break
            if (size == 0) break
            out.write(readExactly(input, size))
            readLine(input)
        }
        return out.toByteArray()
    }
}

/** The bridge's own client trust for a loopback upstream. Test-only, loopback-only. */
private object LoopbackTrust {
    private val shared: SSLContext by lazy {
        val manager = object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) = Unit

            override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) = Unit

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<javax.net.ssl.TrustManager>(manager), SecureRandom())
        }
    }

    fun context(): SSLContext = shared
}
