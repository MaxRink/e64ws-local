package de.mahlkoenig.e64local.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CookieJarTest {

    @Test
    fun `stores and returns the PHP session cookie`() {
        val jar = CookieJar()
        jar.storeFromSetCookie(
            listOf("PHPSESSID=abc123; path=/; HttpOnly; Secure"),
            "192.168.1.100",
        )
        assertEquals("PHPSESSID=abc123", jar.headerFor("192.168.1.100"))
        assertTrue(jar.names().contains("PHPSESSID"))
    }

    @Test
    fun `cookie is never sent to another host`() {
        val jar = CookieJar()
        jar.storeFromSetCookie(listOf("PHPSESSID=abc123; path=/"), "192.168.1.100")
        assertNull(jar.headerFor("192.168.1.101"))
        assertNull(jar.headerFor("example.com"))
    }

    @Test
    fun `a domain attribute allows subdomain matching only`() {
        val jar = CookieJar()
        jar.storeFromSetCookie(listOf("SID=v; Domain=grinder.local; Path=/"), "grinder.local")
        assertEquals("SID=v", jar.headerFor("grinder.local"))
        assertNull("SID=v", jar.headerFor("evilgrinder.local"))
    }

    @Test
    fun `replaces an existing cookie with the same identity`() {
        val jar = CookieJar()
        jar.storeFromSetCookie(listOf("PHPSESSID=one; path=/"), "h")
        jar.storeFromSetCookie(listOf("PHPSESSID=two; path=/"), "h")
        assertEquals("PHPSESSID=two", jar.headerFor("h"))
        assertEquals(1, jar.size)
    }

    @Test
    fun `path scoping is respected`() {
        val jar = CookieJar()
        jar.storeFromSetCookie(listOf("PHPSESSID=abc; path=/dev"), "h")
        assertNull(jar.headerFor("h", "/rest_api/capabilities"))
        assertEquals("PHPSESSID=abc", jar.headerFor("h", "/dev/x"))
    }

    @Test
    fun `clearing removes every cookie`() {
        val jar = CookieJar()
        jar.storeFromSetCookie(listOf("PHPSESSID=abc"), "h")
        jar.clear()
        assertTrue(jar.isEmpty())
        assertNull(jar.headerFor("h"))
    }

    @Test
    fun `malformed set-cookie headers are ignored`() {
        assertNull(CookieJar.parseSetCookie("=value", "h"))
        assertNull(CookieJar.parseSetCookie("", "h"))
        val jar = CookieJar()
        jar.storeFromSetCookie(listOf("garbage", "PHPSESSID=x"), "h")
        assertEquals("PHPSESSID=x", jar.headerFor("h"))
    }

    @Test
    fun `two cookies are joined in one header`() {
        val jar = CookieJar()
        jar.storeFromSetCookie(listOf("PHPSESSID=a", "other=b"), "h")
        val header = jar.headerFor("h")!!
        assertTrue(header.contains("PHPSESSID=a"))
        assertTrue(header.contains("other=b"))
        assertFalse(header.contains("; ;"))
    }
}
