package de.mahlkoenig.e64local.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GrinderEndpointTest {

    @Test
    fun `accepts an IPv4 address`() {
        val endpoint = GrinderEndpoint.parse("192.168.1.100").getOrThrow()
        assertEquals("192.168.1.100", endpoint.host)
        assertEquals(443, endpoint.port)
        assertEquals("https://192.168.1.100", endpoint.baseUrl)
        assertEquals("https://192.168.1.100/rest_api/machine", endpoint.url("/rest_api/machine"))
    }

    @Test
    fun `accepts a host name and an explicit port`() {
        val endpoint = GrinderEndpoint.parse("grinder.local:8443").getOrThrow()
        assertEquals("grinder.local", endpoint.host)
        assertEquals(8443, endpoint.port)
        assertEquals("https://grinder.local:8443", endpoint.baseUrl)
    }

    @Test
    fun `brackets an IPv6 literal`() {
        val endpoint = GrinderEndpoint.parse("[fe80::1]:443").getOrThrow()
        assertEquals("fe80::1", endpoint.host)
        assertEquals("[fe80::1]:443", endpoint.authority)
    }

    @Test
    fun `refuses a URL, a path or a query`() {
        listOf("https://192.168.1.100", "192.168.1.100/rest_api", "192.168.1.100?x=1", "").forEach {
            assertTrue(it, GrinderEndpoint.parse(it).isFailure)
        }
    }

    @Test
    fun `refuses out-of-range and non-numeric ports`() {
        listOf("h:0", "h:65536", "h:abc").forEach {
            assertTrue(it, GrinderEndpoint.parse(it).isFailure)
        }
    }

    @Test
    fun `refuses whitespace and shell metacharacters`() {
        listOf("192.168.1.1 ; rm -rf /", "a b", "host\tname").forEach {
            assertTrue(it, GrinderEndpoint.parse(it).isFailure)
        }
    }

    @Test
    fun `classifies LAN scope`() {
        listOf("192.168.1.5", "10.0.0.1", "172.16.4.2", "172.31.255.1", "127.0.0.1", "169.254.1.1", "100.64.0.1")
            .forEach { assertTrue(it, LanScope.isPrivateAddress(it)) }
        listOf("8.8.8.8", "172.32.0.1", "1.1.1.1", "100.63.255.255").forEach {
            assertFalse(it, LanScope.isPrivateAddress(it))
        }
        assertTrue(LanScope.isPrivateAddress("fe80::1"))
        assertTrue(LanScope.isPrivateAddress("fd00::1"))
        assertTrue(LanScope.isPrivateAddress("::1"))
        assertFalse(LanScope.isPrivateAddress("2001:4860:4860::8888"))
    }

    @Test
    fun `scope of an endpoint drives the public-address refusal`() {
        assertEquals(LanScope.Scope.Private, LanScope.scopeOf(GrinderEndpoint("192.168.1.100")))
        assertEquals(LanScope.Scope.Private, LanScope.scopeOf(GrinderEndpoint("grinder.local")))
        assertEquals(LanScope.Scope.Public, LanScope.scopeOf(GrinderEndpoint("203.0.113.5")))
        assertEquals(LanScope.Scope.Unknown, LanScope.scopeOf(GrinderEndpoint("grinder.example.org")))
    }

    @Test
    fun `empty host is not a valid endpoint id`() {
        assertNull(GrinderEndpoint.parse("").getOrNull())
    }
}
