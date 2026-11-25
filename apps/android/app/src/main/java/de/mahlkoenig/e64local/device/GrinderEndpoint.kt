package de.mahlkoenig.e64local.device

/**
 * A validated grinder address. The app never accepts a URL, a path or a query
 * string here: only a host (name or IP literal) and an optional port.
 */
data class GrinderEndpoint(val host: String, val port: Int = 443) {
    val isDefaultPort: Boolean get() = port == 443

    /** `host:port`, with IPv6 literals bracketed. */
    val authority: String
        get() = if (host.contains(':')) "[$host]:$port" else "$host:$port"

    val baseUrl: String
        get() = if (isDefaultPort) "https://$host" else "https://$authority"

    fun url(path: String): String =
        baseUrl + if (path.startsWith("/")) path else "/$path"

    /** Stable identity for stored settings; never a secret. */
    val id: String get() = authority

    companion object {
        val HOST_PATTERN = Regex("^[A-Za-z0-9._:\\-\\[\\]]+$")

        fun parse(raw: String): Result<GrinderEndpoint> {
            val value = raw.trim()
            if (value.isEmpty()) return Result.failure(IllegalArgumentException("Enter the grinder's IP address or host name"))
            if ("://" in value) {
                return Result.failure(IllegalArgumentException("Enter only the host, without https://"))
            }
            if (value.any { it == '/' || it == '?' || it == '#' }) {
                return Result.failure(IllegalArgumentException("Enter only the host, without a path"))
            }
            if (value.any { it.isWhitespace() }) {
                return Result.failure(IllegalArgumentException("The host must not contain spaces"))
            }

            var host: String
            var port = 443
            when {
                value.startsWith("[") -> {
                    val end = value.indexOf(']')
                    if (end < 0) return Result.failure(IllegalArgumentException("Unterminated IPv6 address"))
                    host = value.substring(1, end)
                    val tail = value.substring(end + 1)
                    if (tail.isNotEmpty()) {
                        if (!tail.startsWith(":")) {
                            return Result.failure(IllegalArgumentException("Unexpected text after the IPv6 address"))
                        }
                        val parsed = parsePort(tail.substring(1))
                            ?: return Result.failure(IllegalArgumentException("Invalid port in the address"))
                        port = parsed
                    }
                }

                value.count { it == ':' } == 1 -> {
                    val parts = value.split(':')
                    host = parts[0]
                    port = parsePort(parts[1])
                        ?: return Result.failure(IllegalArgumentException("Invalid port in the address"))
                }

                else -> host = value
            }

            if (host.isEmpty() || !HOST_PATTERN.matches(host)) {
                return Result.failure(IllegalArgumentException("Not a valid host name or IP address"))
            }
            if (port !in 1..65535) {
                return Result.failure(IllegalArgumentException("Port must be between 1 and 65535"))
            }
            return Result.success(GrinderEndpoint(host, port))
        }

        private fun parsePort(text: String): Int? =
            text.toIntOrNull()?.takeIf { it in 1..65535 }
    }
}

/**
 * LAN-scope checks. The grinder is a local appliance, and this app is
 * LAN-only, so an address that is globally routable gets an explicit warning
 * before any credential is sent to it.
 */
object LanScope {
    /** Loopback, RFC1918, link-local, CGNAT and IPv6 unique-local space. */
    fun isPrivateAddress(address: String): Boolean {
        val value = address.substringBefore('%')
        if (value.contains(':')) return isPrivateIpv6(value)
        val octets = value.split('.').mapNotNull { it.toIntOrNull() }
        if (octets.size != 4 || octets.any { it !in 0..255 }) return false
        val (a, b) = octets[0] to octets[1]
        return when {
            a == 10 -> true
            a == 127 -> true
            a == 169 && b == 254 -> true
            a == 172 && b in 16..31 -> true
            a == 192 && b == 168 -> true
            a == 100 && b in 64..127 -> true
            else -> false
        }
    }

    private fun isPrivateIpv6(value: String): Boolean {
        val groups = value.lowercase().split(':')
        val first = groups.firstOrNull()?.let { it.ifEmpty { "0" }.toIntOrNull(16) } ?: 0
        return when {
            value == "::1" -> true
            first and 0xFE00 == 0xFC00 -> true // fc00::/7 unique local
            first and 0xFFC0 == 0xFE80 -> true // fe80::/10 link local
            first == 0 -> true                 // ::/8 (unspecified, loopback, v4-mapped)
            else -> false
        }
    }

    /** True for a host name that only resolves inside a home/lab LAN. */
    fun isPrivateHostName(host: String): Boolean {
        val lower = host.lowercase().trimEnd('.')
        return lower == "localhost" ||
            lower.endsWith(".local") ||
            lower.endsWith(".lan") ||
            lower.endsWith(".home") ||
            lower.endsWith(".internal") ||
            lower.endsWith(".home.arpa")
    }

    fun scopeOf(endpoint: GrinderEndpoint): Scope {
        val host = endpoint.host
        if (isPrivateAddress(host)) return Scope.Private
        if (isPrivateHostName(host)) return Scope.Private
        // A bare IPv4 literal that is not private is public; anything else is an
        // unknown name, which cannot be classified offline.
        return if (host.contains('.') && host.all { it.isDigit() || it == '.' }) Scope.Public else Scope.Unknown
    }

    enum class Scope { Private, Public, Unknown }
}
