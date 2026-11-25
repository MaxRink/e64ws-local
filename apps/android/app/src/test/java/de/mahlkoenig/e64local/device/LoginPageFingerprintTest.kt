package de.mahlkoenig.e64local.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LoginPageFingerprintTest {

    private val page = """
        <html><head><title>Login Hemro E64</title></head><body>
        <div>MODEL</div><div>E64 WS</div>
        <div>S/N</div><div>HMI12345678</div>
        <div>FW VERSION</div><div>V01.16 (development)</div>
        <select><option value="Owner">Owner</option><option value="Developer">Developer</option></select>
        </body></html>
    """.trimIndent()

    @Test
    fun `reads model, firmware and dev mode`() {
        val fingerprint = LoginPageFingerprint.parse(page)
        assertEquals("E64 WS", fingerprint.model)
        assertEquals("V01.16 (development)", fingerprint.firmware)
        assertTrue(fingerprint.devMode)
        assertTrue(fingerprint.known)
    }

    @Test
    fun `the raw serial from the login page is not part of the fingerprint`() {
        val fingerprint = LoginPageFingerprint.parse(page)
        assertFalse(fingerprint.toString().contains("HMI12345678"))
        assertFalse(fingerprint.firmware.contains("HMI12345678"))
    }

    @Test
    fun `a production page has no dev mode`() {
        val prod = page.replace(" (development)", "").replace("""<option value="Developer">Developer</option>""", "")
        val fingerprint = LoginPageFingerprint.parse(prod)
        assertFalse(fingerprint.devMode)
        assertTrue(fingerprint.known)
    }

    @Test
    fun `an unrelated page is not recognised`() {
        val fingerprint = LoginPageFingerprint.parse("<html><title>Router</title></html>")
        assertFalse(fingerprint.known)
        assertEquals("", fingerprint.model)
    }
}
