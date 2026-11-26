package de.mahlkoenig.e64local.e2e

import java.net.URI
import java.util.Collections

/**
 * One failed check of the live end-to-end suite.
 *
 * It is a plain exception on purpose: the suite reports the failure as the
 * single contract line `E2E FAIL <detail>` on stderr and then fails the JUnit
 * test, so `./gradlew` exits 1. Nothing here carries a credential.
 */
internal class E2EFailure(message: String) : Exception(message)

/**
 * The suite's check counter and its three output shapes.
 *
 * The contract with the runner is narrow:
 *  - no `E64_E2E_BASE_URL`  -> `E2E SKIP (no E64_E2E_BASE_URL)` on stdout, exit 0, nothing run;
 *  - every check passed     -> exactly one `E2E PASS <n>` line on stdout, exit 0;
 *  - a check failed         -> `E2E FAIL <detail>` on stderr, exit 1.
 *
 * Diagnostics that are not the summary line are prefixed `note:` so they can
 * never be mistaken for it.
 */
internal class E2EReport {
    private var performed = 0
    private val notes = mutableListOf<String>()

    /** Records why a block of checks could not run. Never a credential. */
    fun note(text: String) {
        notes += text
    }

    /**
     * Runs one check. [what] names the behaviour, so a failure reads as a
     * sentence about the app rather than as an assertion index.
     */
    fun <T> verify(what: String, block: () -> T): T {
        performed++
        return try {
            block()
        } catch (failure: E2EFailure) {
            throw failure
        } catch (throwable: Throwable) {
            throw E2EFailure("$what: ${oneLine(throwable)}")
        }
    }

    fun verify(what: String, condition: Boolean, detail: () -> String = { "condition is false" }) {
        verify(what) {
            if (!condition) throw E2EFailure("$what: ${oneLine(detail())}")
        }
    }

    fun emitSuccess() {
        notes.forEach { println("note: ${oneLine(it)}") }
        println("E2E PASS $performed")
    }

    fun emitFailure(detail: String) {
        System.err.println("E2E FAIL ${oneLine(detail)}")
        System.err.flush()
    }

    companion object {
        const val SKIP_LINE = "E2E SKIP (no E64_E2E_BASE_URL)"

        /** Collapses a message to one line so the contract output stays parseable. */
        fun oneLine(value: Any?): String {
            val text = when (value) {
                null -> "unknown error"
                is Throwable -> value.message ?: value::class.simpleName ?: value.javaClass.simpleName
                else -> value.toString()
            }
            val single = text.replace(Regex("\\s+"), " ").trim().ifEmpty { "no detail" }
            return if (single.length <= 400) single else single.take(397) + "..."
        }
    }
}

/**
 * The inputs the runner supplies. Only the two documented variables are
 * required; `E64_E2E_PASSWORD` exists so an operator can point the suite at
 * their own simulator without editing code.
 *
 * `E64_E2E_TOKEN` is the local-API owner token. The bundled simulator's field
 * default is `sim-local-api-token`; its `--token` command-line flag is a
 * different credential (the WSS test token) and must not be used here.
 */
internal object E2EEnvironment {
    const val BASE_URL = "E64_E2E_BASE_URL"
    const val TOKEN = "E64_E2E_TOKEN"
    const val PASSWORD = "E64_E2E_PASSWORD"

    const val DEFAULT_PASSWORD = "sim-password"
    const val DEFAULT_API_TOKEN = "sim-local-api-token"

    fun read(name: String): String? = System.getenv(name)?.trim()?.takeIf { it.isNotEmpty() }

    /** One simulator address, as the runner states it. */
    data class Target(val scheme: String, val host: String, val port: Int, val raw: String) {
        val plainHttp: Boolean get() = scheme == "http"
        val authority: String get() = "$host:$port"
    }

    /**
     * Parses `E64_E2E_BASE_URL`. Plain `http` is the documented form: the app's
     * production client speaks TLS only, so the suite terminates TLS itself in
     * front of the given address (see [LoopbackTlsBridge]). An `https` address
     * is accepted as well and is dialled directly.
     */
    fun parseBaseUrl(raw: String): Target {
        val trimmed = raw.trim().trimEnd('/')
        val uri = try {
            URI(trimmed)
        } catch (failure: IllegalArgumentException) {
            throw E2EFailure("$BASE_URL is not a URL: $trimmed (${failure.message})")
        }
        val scheme = uri.scheme?.lowercase()
            ?: throw E2EFailure("$BASE_URL has no scheme: $trimmed")
        if (scheme != "http" && scheme != "https") {
            throw E2EFailure("$BASE_URL must be http or https, not $scheme")
        }
        val host = uri.host?.takeIf { it.isNotEmpty() }
            ?: throw E2EFailure("$BASE_URL has no host: $trimmed")
        val path = uri.rawPath.orEmpty()
        if (path.isNotEmpty() && path != "/") {
            throw E2EFailure("$BASE_URL must not carry a path: $trimmed")
        }
        if (uri.rawQuery != null || uri.rawFragment != null) {
            throw E2EFailure("$BASE_URL must not carry a query or fragment: $trimmed")
        }
        val port = when {
            uri.port != -1 -> uri.port
            scheme == "https" -> 443
            else -> 80
        }
        if (!isLoopback(host)) {
            throw E2EFailure(
                "$BASE_URL must point at this host (127.0.0.1, ::1 or localhost); the suite never " +
                    "opens a connection to any other machine, and $host is not loopback",
            )
        }
        return Target(scheme, host, port, trimmed)
    }

    fun isLoopback(host: String): Boolean {
        val value = host.lowercase().removePrefix("[").removeSuffix("]")
        return value == "127.0.0.1" || value == "::1" || value == "localhost" || value == "0:0:0:0:0:0:0:1"
    }
}

/**
 * A tiny record of what went over the wire, used by the checks that assert
 * transport invariants (the owner token header, the session cookie, where the
 * confirm token may appear).
 *
 * The ordering contract with [LoopbackTlsBridge] is what makes those assertions
 * sound: an entry is added *before* the answer it describes is written back to
 * the client, so a check that reads this log once its call has returned can
 * never miss an exchange that was in fact served. [BridgeOrderingUnitTest]
 * pins that invariant.
 */
internal class WireLog {
    data class Entry(
        val method: String,
        val path: String,
        val requestHeaders: Map<String, String>,
        val requestBody: String,
        val status: Int,
        val responseBody: String,
    ) {
        /**
         * Case-insensitive header lookup. The JDK's HTTP server rewrites header
         * names to `First-letter-capitalised`, so a plain map lookup on the
         * name the app sent would miss.
         */
        fun header(name: String): String? =
            requestHeaders.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
    }

    private val entries = Collections.synchronizedList(mutableListOf<Entry>())

    val all: List<Entry> get() = synchronized(entries) { entries.toList() }

    fun add(entry: Entry) {
        entries += entry
    }

    fun clear() {
        entries.clear()
    }
}
