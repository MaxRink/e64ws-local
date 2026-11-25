package de.mahlkoenig.e64local.device

import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PinnedTrustManagerTest {

    private class FakeCertificate(private val bytes: ByteArray) : X509Certificate() {
        override fun getEncoded(): ByteArray = bytes
        override fun getPublicKey(): java.security.PublicKey? = null
        override fun checkValidity() {}
        override fun checkValidity(p0: java.util.Date?) {}
        override fun getVersion(): Int = 3
        override fun getSerialNumber(): java.math.BigInteger = java.math.BigInteger.ONE
        override fun getIssuerDN(): java.security.Principal? = null
        override fun getSubjectDN(): java.security.Principal? = null
        override fun getNotBefore(): java.util.Date? = null
        override fun getNotAfter(): java.util.Date? = null
        override fun getTBSCertificate(): ByteArray = ByteArray(0)
        override fun getSignature(): ByteArray = ByteArray(0)
        override fun getSigAlgName(): String = "none"
        override fun getSigAlgOID(): String = "none"
        override fun getSigAlgParams(): ByteArray? = null
        override fun getIssuerUniqueID(): BooleanArray? = null
        override fun getSubjectUniqueID(): BooleanArray? = null
        override fun getKeyUsage(): BooleanArray? = null
        override fun getBasicConstraints(): Int = -1
        override fun verify(p0: java.security.PublicKey?) {}
        override fun verify(p0: java.security.PublicKey?, p1: java.security.Provider?) {}
        override fun verify(p0: java.security.PublicKey?, p1: String?) {}
        override fun toString(): String = "fake"
        override fun hasUnsupportedCriticalExtension(): Boolean = false
        override fun getCriticalExtensionOIDs(): MutableSet<String>? = null
        override fun getNonCriticalExtensionOIDs(): MutableSet<String>? = null
        override fun getExtensionValue(p0: String?): ByteArray? = null
    }

    private val certificate = FakeCertificate("e64-device-certificate".toByteArray())
    private val fingerprint = PinnedTrustManager.fingerprint(certificate)

    @Test
    fun `no pin means the owner has not trusted the device yet`() {
        val manager = PinnedTrustManager(null)
        val exc = assertThrows(CertificateException::class.java) {
            manager.checkServerTrusted(arrayOf(certificate), "ECDHE_RSA")
        }
        assertTrue(exc.message!!.contains("not trusted yet"))
    }

    @Test
    fun `a matching pin is accepted`() {
        PinnedTrustManager(fingerprint).checkServerTrusted(arrayOf(certificate), "ECDHE_RSA")
        // Colon-separated and upper-case pins are normalised.
        PinnedTrustManager(fingerprint.uppercase().chunked(2).joinToString(":"))
            .checkServerTrusted(arrayOf(certificate), "ECDHE_RSA")
    }

    @Test
    fun `a different certificate fails closed`() {
        val other = PinnedTrustManager(fingerprint.replaceRange(0, 2, "00"))
        assertThrows(CertificateException::class.java) {
            other.checkServerTrusted(arrayOf(certificate), "ECDHE_RSA")
        }
    }

    @Test
    fun `an empty chain is rejected`() {
        assertThrows(CertificateException::class.java) {
            PinnedTrustManager(fingerprint).checkServerTrusted(emptyArray(), "ECDHE_RSA")
        }
    }

    @Test
    fun `client certificates are never accepted`() {
        assertThrows(CertificateException::class.java) {
            PinnedTrustManager(fingerprint).checkClientTrusted(arrayOf(certificate), "ECDHE_RSA")
        }
    }

    @Test
    fun `display fingerprint is grouped in upper case`() {
        assertEquals("AB:CD", PinnedTrustManager.displayFingerprint("abcd"))
        assertEquals("abc", PinnedTrustManager.normalize("AB:C"))
        assertEquals(64, fingerprint.length)
    }
}
