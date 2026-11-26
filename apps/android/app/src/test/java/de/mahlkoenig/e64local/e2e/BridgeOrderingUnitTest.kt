package de.mahlkoenig.e64local.e2e

import com.sun.net.httpserver.HttpServer
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The ordering invariant the live suite rests on: [LoopbackTlsBridge] records an
 * exchange *before* it answers it, so a client that holds an answer always finds
 * its entry in the wire log.
 *
 * [LiveDeviceChecks] and [ActionLifecycleChecks] read that log immediately after
 * each call, which is only sound under that invariant. While the bridge appended
 * its entry from the `finally` of the handler - that is, after `respond()` had
 * already flushed the answer - the caller raced the handler thread and the very
 * first check (`the request did not cross the loopback bridge`) could fail for a
 * request that did cross it. This class pins the invariant, so moving the append
 * back after `respond()` fails here on every run instead of intermittently in a
 * live run.
 *
 * No simulator and no `E64_E2E_BASE_URL` are needed: a two-line JDK HTTP server
 * stands in for the device on the bridge's upstream leg, and the bridge under
 * test is the one the live suite uses.
 *
 * The first test does not sleep, poll or retry; it pins the instant. It reads
 * only the response header block - the part `sendResponseHeaders` flushes - while
 * a body far larger than any socket buffer is still being written to a client
 * that has stopped reading. The handler thread is provably still inside
 * `respond()` there, so the log has to be complete already. With the append back
 * after `respond()` that assertion fails deterministically, which is what makes
 * this a regression test and not a smaller copy of the flake.
 */
class BridgeOrderingUnitTest {

    @Test
    fun `an answer is already recorded when the client holds only its header block`() {
        val body = "x".repeat(BLOCKED_BODY_BYTES)
        withUpstream(body) { upstream ->
            withBridge(upstream.address.port) { bridge, port ->
                sslClient(port).use { socket ->
                    val out = socket.getOutputStream()
                    out.write(request("GET", BLOCKED_PATH, emptyMap(), ""))
                    out.flush()

                    val input = socket.getInputStream()
                    val head = readHeaderBlock(input)
                    assertTrue("the bridge answered no 200: ${head.lines().first()}", head.startsWith("HTTP/1.1 200"))

                    // Not one body byte has been read, so the handler cannot have
                    // returned from respond(): what is left of the body exceeds
                    // the send and receive buffers together.
                    val entries = bridge.exchanges.all
                    assertEquals(
                        "a client that holds an answer must already see its wire-log entry; " +
                            "an entry appended after respond() leaves every check of the suite " +
                            "racing the handler thread",
                        1,
                        entries.size,
                    )
                    val entry = entries.single()
                    assertEquals("GET", entry.method)
                    assertEquals(BLOCKED_PATH, entry.path)
                    assertEquals(200, entry.status)
                    assertEquals(
                        "the entry must describe the whole answer, not a prefix of it",
                        body.length,
                        entry.responseBody.length,
                    )
                    assertTrue("the logged body is not the body the device sent", entry.responseBody == body)

                    // Draining the answer changes nothing: one request, one entry.
                    assertEquals(body, readBody(input, body.length))
                    assertEquals(1, bridge.exchanges.all.size)
                    assertEquals(body, bridge.exchanges.all.single().responseBody)
                }
            }
        }
    }

    @Test
    fun `every served answer is logged complete, field for field, in request order`() {
        val body = "{\"success\":true,\"simulator\":true}"
        withUpstream(body) { upstream ->
            withBridge(upstream.address.port) { bridge, port ->
                val paths = listOf("/rest_api/ping", "/rest_api/capabilities", "/rest_api/machine")
                paths.forEachIndexed { index, path ->
                    val sent = if (index == 1) "{\"probe\":true}" else ""
                    val headers = mapOf("X-E64-Local-Token" to TOKEN, "Content-Type" to "application/json")
                    val method = if (sent.isEmpty()) "GET" else "POST"
                    val answer = sslClient(port).use { socket ->
                        val out = socket.getOutputStream()
                        out.write(request(method, path, headers, sent))
                        out.flush()
                        val input = socket.getInputStream()
                        val head = readHeaderBlock(input)
                        assertTrue("$path answered no 200: ${head.lines().first()}", head.startsWith("HTTP/1.1 200"))
                        readBody(input, body.length)
                    }
                    assertEquals("the bridge answered $path with $body", body, answer)

                    // The log is read immediately after the call returned, exactly
                    // as the live checks do: the answered request must be there.
                    val entries = bridge.exchanges.all
                    assertEquals(
                        "after answering $path the log holds ${entries.map { it.path }}",
                        index + 1,
                        entries.size,
                    )
                    val entry = entries.last()
                    // The entry's six fields, in the order the suite has always
                    // read them: a dropped field or a reshuffle shows up here.
                    assertEquals(method, entry.component1())
                    assertEquals(path, entry.component2())
                    assertEquals(
                        TOKEN,
                        entry.component3().entries
                            .firstOrNull { it.key.equals("X-E64-Local-Token", ignoreCase = true) }
                            ?.value,
                    )
                    assertEquals(sent, entry.component4())
                    assertEquals(200, entry.component5())
                    assertEquals(body, entry.component6())
                    assertEquals(
                        "the wire log dropped a header the bridge received",
                        TOKEN,
                        entry.header("X-E64-Local-Token"),
                    )
                }
                assertEquals(paths, bridge.exchanges.all.map { it.path })
            }
        }
    }

    @Test
    fun `an unreachable device is answered and recorded, not silently swallowed`() {
        val path = "/rest_api/ping"
        withBridge(closedPort()) { bridge, port ->
            sslClient(port).use { socket ->
                val out = socket.getOutputStream()
                out.write(request("GET", path, emptyMap(), ""))
                out.flush()
                val input = socket.getInputStream()
                val head = readHeaderBlock(input)
                assertTrue("the bridge did not answer 502: ${head.lines().first()}", head.startsWith("HTTP/1.1 502"))
                val entry = bridge.exchanges.all.single()
                assertEquals(502, entry.status)
                assertTrue(
                    "the bridge's own refusal is not explained: ${entry.responseBody.take(160)}",
                    entry.responseBody.contains("cannot reach"),
                )
                assertEquals(
                    "the refusal on the wire is not the one in the log",
                    entry.responseBody,
                    readBody(input, entry.responseBody.length),
                )
            }
        }
    }

    // -- fixture --------------------------------------------------------------

    private fun <T> withUpstream(body: String, block: (HttpServer) -> T): T {
        val server = HttpServer.create(InetSocketAddress(loopback, 0), 0)
        try {
            server.createContext("/") { exchange ->
                exchange.requestBody.use { it.readBytes() }
                val bytes = body.toByteArray(Charsets.UTF_8)
                exchange.responseHeaders.add("Content-Type", "application/json")
                exchange.sendResponseHeaders(200, bytes.size.toLong())
                exchange.responseBody.use { it.write(bytes) }
            }
            server.executor = Executors.newCachedThreadPool { runnable ->
                Thread(runnable, "e64-e2e-order-stand-in").apply { isDaemon = true }
            }
            server.start()
            return block(server)
        } finally {
            server.stop(0)
        }
    }

    private fun <T> withBridge(upstreamPort: Int, block: (LoopbackTlsBridge, Int) -> T): T {
        val host = loopback.hostAddress ?: "127.0.0.1"
        val target = E2EEnvironment.Target("http", host, upstreamPort, "http://$host:$upstreamPort")
        val bridge = LoopbackTlsBridge.to(target)
        try {
            return block(bridge, bridge.port)
        } finally {
            bridge.close()
        }
    }

    /** A loopback client that trusts the fixture certificate, as a pin would. */
    private fun sslClient(port: Int): SSLSocket {
        val socket = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAll), SecureRandom())
        }.socketFactory.createSocket() as SSLSocket
        // A small receive window is what keeps the handler inside respond() in
        // the first test: the body cannot drain into buffers that do not exist.
        socket.receiveBufferSize = RECEIVE_BUFFER_BYTES
        socket.connect(InetSocketAddress(loopback, port), 5_000)
        socket.soTimeout = 30_000
        socket.startHandshake()
        return socket
    }

    private fun request(method: String, path: String, headers: Map<String, String>, body: String): ByteArray {
        val head = StringBuilder()
            .append(method).append(' ').append(path).append(" HTTP/1.1\r\n")
            .append("Host: ").append(loopback.hostAddress).append("\r\n")
        for ((name, value) in headers) head.append(name).append(": ").append(value).append("\r\n")
        head.append("Content-Length: ").append(body.toByteArray(Charsets.UTF_8).size).append("\r\n")
            .append("Connection: close\r\n\r\n")
        return (head.toString() + body).toByteArray(Charsets.UTF_8)
    }

    /** Everything up to and including the empty line that ends the header block. */
    private fun readHeaderBlock(input: InputStream): String {
        val buffer = ByteArrayOutputStream()
        var matched = 0
        while (matched < CRLF.size) {
            val byte = input.read()
            if (byte < 0) break
            buffer.write(byte)
            matched = when (byte) {
                CRLF[matched] -> matched + 1
                CRLF[0] -> 1
                else -> 0
            }
        }
        return buffer.toString("ISO-8859-1")
    }

    /** Reads exactly [length] body bytes, failing if the peer closes early. */
    private fun readBody(input: InputStream, length: Int): String {
        val bytes = ByteArray(length)
        var read = 0
        while (read < length) {
            val count = input.read(bytes, read, length - read)
            if (count < 0) break
            read += count
        }
        assertEquals("the answer ended after $read of $length body bytes", length, read)
        return bytes.toString(Charsets.UTF_8)
    }

    /**
     * A port nothing listens on. Bound and released rather than made up, so the
     * bridge's upstream connect is refused instead of reaching another process.
     */
    private fun closedPort(): Int = ServerSocket(0, 1, loopback).use { it.localPort }

    private companion object {
        /** Larger than any socket send/receive buffer pair on a test host. */
        const val BLOCKED_BODY_BYTES = 4 * 1024 * 1024
        const val RECEIVE_BUFFER_BYTES = 4 * 1024
        const val BLOCKED_PATH = "/rest_api/stalled"
        const val TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val CRLF = intArrayOf('\r'.code, '\n'.code, '\r'.code, '\n'.code)
        val loopback: InetAddress = InetAddress.getLoopbackAddress()
        val trustAll: X509TrustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) = Unit

            override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) = Unit

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
    }
}
