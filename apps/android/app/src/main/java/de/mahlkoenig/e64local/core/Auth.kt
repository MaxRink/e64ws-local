package de.mahlkoenig.e64local.core

/**
 * Token handling helpers. The owner token is a device-local secret: it is sent
 * only as the `X-E64-Local-Token` header, never written to a log and never
 * included in an error message.
 */
object AuthHeader {
    const val HEADER = "X-E64-Local-Token"
    const val TOKEN_BODY_KEY = "token"

    fun headers(token: String?): Map<String, String> =
        if (token.isNullOrEmpty()) emptyMap() else mapOf(HEADER to token)

    /** JSON body with the token fallback field; used only when the header cannot be sent. */
    fun bodyWithToken(token: String, body: JsonValue = Json.obj()): String {
        val entries = LinkedHashMap<String, JsonValue>()
        entries[TOKEN_BODY_KEY] = Json.str(token)
        (body as? JsonValue.Obj)?.entries?.forEach { (key, value) ->
            if (key != TOKEN_BODY_KEY) entries[key] = value
        }
        return Json.write(JsonValue.Obj(entries))
    }
}

/**
 * Removes secrets from text before it reaches the UI log or logcat.
 *
 * The app never logs a token, a password or a cookie; this is the last line of
 * defence for text that arrives from the device or from an exception message.
 */
object Redaction {
    const val PLACEHOLDER = "<redacted>"

    private val patterns = listOf(
        // Header-style token values: "X-E64-Local-Token: abc…"
        Regex("(?i)(x-e64-local-token\\s*[:=]\\s*)(\\S+)"),
        // JSON field: "token": "abc…"
        Regex("(?i)(\"token\"\\s*:\\s*\")([^\"]+)(\")"),
        // The action confirm token: `"confirmToken": "<64 hex>"`. It is a
        // single-use HMAC, but it still authorises one actuation, so it is
        // redacted like the owner token.
        Regex("(?i)(\"?confirmToken\"?\\s*[:=]\\s*\"?)([0-9a-f]{16,})"),
        // Cookies: PHPSESSID=abc…
        Regex("(?i)(phpsessid\\s*=\\s*)([^;\\s]+)"),
        // password=… / "password": "…"
        Regex("(?i)(password\\s*[\"']?\\s*[:=]\\s*[\"']?)([^\\s\"'&,;]+)"),
    )

    fun redact(text: String): String {
        var result = text
        for (pattern in patterns) {
            result = pattern.replace(result) { match ->
                if (match.groupValues.size >= 4) {
                    match.groupValues[1] + PLACEHOLDER + match.groupValues[3]
                } else {
                    match.groupValues[1] + PLACEHOLDER
                }
            }
        }
        return result
    }

    /** Short, non-reversible label for a token; safe to show in diagnostics. */
    fun tokenHint(token: String): String =
        if (token.isEmpty()) "none" else "len=${token.length}, fp=${token.take(4)}…"
}
