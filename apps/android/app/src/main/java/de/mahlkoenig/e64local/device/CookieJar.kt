package de.mahlkoenig.e64local.device

/**
 * A deliberately small `PHPSESSID` cookie jar.
 *
 * The vendor dispatcher only needs one cookie. Keeping the implementation in
 * plain Kotlin (instead of `java.net.CookieManager`) makes the cookie handling
 * unit-testable without a device and keeps the jar from ever being sent to a
 * host other than the stored grinder.
 */
class CookieJar {
    data class Cookie(
        val name: String,
        val value: String,
        val domain: String,
        val path: String = "/",
        val secure: Boolean = true,
        val hostOnly: Boolean = true,
    )

    private val cookies = ArrayList<Cookie>()

    val size: Int get() = cookies.size

    fun isEmpty(): Boolean = cookies.isEmpty()

    fun clear() {
        cookies.clear()
    }

    fun names(): List<String> = cookies.map { it.name }

    /** Collects every `Set-Cookie` header of a response for [requestHost]. */
    fun storeFromSetCookie(headers: List<String>, requestHost: String) {
        for (header in headers) {
            parseSetCookie(header, requestHost)?.let { put(it) }
        }
    }

    fun store(cookie: Cookie) {
        put(cookie.normalized())
    }

    private fun put(cookie: Cookie) {
        val existing = cookies.indexOfFirst { it.name == cookie.name && it.domain == cookie.domain && it.path == cookie.path }
        if (existing >= 0) {
            if (cookie.value.isEmpty()) cookies.removeAt(existing) else cookies[existing] = cookie
        } else if (cookie.value.isNotEmpty()) {
            cookies += cookie
        }
    }

    fun cookiesFor(host: String, path: String = "/"): List<Cookie> {
        val normalizedHost = host.lowercase()
        return cookies.filter { cookie ->
            domainMatches(cookie, normalizedHost) &&
                pathMatches(cookie.path, path)
        }
    }

    /** A `Cookie:` header value for [host], or `null` when the jar is empty. */
    fun headerFor(host: String, path: String = "/"): String? {
        val selected = cookiesFor(host, path)
        if (selected.isEmpty()) return null
        return selected.joinToString("; ") { "${it.name}=${it.value}" }
    }

    private fun domainMatches(cookie: Cookie, host: String): Boolean =
        if (cookie.hostOnly || cookie.domain.isEmpty()) {
            host == cookie.domain
        } else {
            host == cookie.domain || host.endsWith("." + cookie.domain)
        }

    private fun pathMatches(cookiePath: String, requestPath: String): Boolean =
        cookiePath.isEmpty() || requestPath == cookiePath ||
            requestPath.startsWith(cookiePath.trimEnd('/') + "/")

    private fun Cookie.normalized(): Cookie = copy(
        domain = domain.lowercase().removePrefix("."),
        path = if (path.isEmpty()) "/" else path,
    )

    companion object {
        /** Parses one `Set-Cookie` header line. Never throws. */
        fun parseSetCookie(header: String, requestHost: String): Cookie? {
            val parts = header.split(';')
            val pair = parts.firstOrNull()?.trim().orEmpty()
            val name = pair.substringBefore('=', "").trim()
            val value = pair.substringAfter('=', "").trim()
            if (name.isEmpty()) return null

            var domain = requestHost.lowercase()
            var path = "/"
            var secure = false
            for (attribute in parts.drop(1)) {
                val trimmed = attribute.trim()
                val key = trimmed.substringBefore('=', "").trim().lowercase()
                val attrValue = trimmed.substringAfter('=', "").trim()
                when (key) {
                    "domain" -> if (attrValue.isNotEmpty()) domain = attrValue.lowercase().removePrefix(".")
                    "path" -> if (attrValue.isNotEmpty()) path = attrValue
                    "secure" -> secure = true
                }
            }
            val hostOnly = parts.drop(1).none { it.trim().substringBefore('=').trim().equals("Domain", ignoreCase = true) }
            return Cookie(name, value, domain, path, secure, hostOnly)
        }
    }
}
