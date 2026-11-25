package de.mahlkoenig.e64local.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthTest {

    private val token = "f".repeat(64)

    @Test
    fun `auth header uses the documented name`() {
        assertEquals("X-E64-Local-Token", AuthHeader.HEADER)
        assertEquals(mapOf("X-E64-Local-Token" to token), AuthHeader.headers(token))
        assertTrue(AuthHeader.headers(null).isEmpty())
        assertTrue(AuthHeader.headers("").isEmpty())
    }

    @Test
    fun `token body fallback keeps the token and the original fields`() {
        val body = AuthHeader.bodyWithToken(token, Json.obj("limit" to Json.num(5)))
        val parsed = Json.parseObject(body)
        assertEquals(token, parsed.string("token"))
        assertEquals(5L, parsed.long("limit"))
    }

    @Test
    fun `redaction removes token values from header-style text`() {
        val text = "X-E64-Local-Token: $token and more"
        val redacted = Redaction.redact(text)
        assertFalse(redacted.contains(token))
        assertTrue(redacted.contains("<redacted>"))
    }

    @Test
    fun `redaction removes token, session and password values from JSON`() {
        val json = """{"token":"$token","session":"PHPSESSID=abcdef","password":"hunter2"}"""
        val redacted = Redaction.redact(json)
        assertFalse(redacted.contains(token))
        assertFalse(redacted.contains("abcdef"))
        assertFalse(redacted.contains("hunter2"))
        assertTrue(redacted.contains("redacted"))
    }

    @Test
    fun `redaction leaves ordinary text alone`() {
        val text = "grind_log returned 20 rows for E64 WS"
        assertEquals(text, Redaction.redact(text))
    }

    @Test
    fun `token hint never contains the whole token`() {
        val hint = Redaction.tokenHint(token)
        assertFalse(hint.contains(token))
        assertEquals("none", Redaction.tokenHint(""))
    }
}
