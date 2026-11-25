package de.mahlkoenig.e64local.device

import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

/**
 * Trust-on-first-use for the grinder's self-signed certificate.
 *
 * Verification is never silently disabled: the owner is shown the SHA-256
 * fingerprint of the certificate the device presents and has to accept it
 * explicitly. Only that exact certificate is then accepted. Pinning replaces
 * the CA check, so a new certificate (for example after a factory reset) fails
 * closed and the owner has to trust the device again.
 */
class PinnedTrustManager(private val expectedSha256: String?) : X509TrustManager {

    override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) {
        throw CertificateException("this app never accepts client certificates")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
        val certificate = chain.firstOrNull()
            ?: throw CertificateException("the device presented no certificate")
        val expected = expectedSha256?.trim()?.lowercase()?.replace(":", "")?.replace(" ", "")
        if (expected.isNullOrEmpty()) {
            throw CertificateException(
                "the device certificate is not trusted yet; open setup and accept its fingerprint",
            )
        }
        val actual = fingerprint(certificate)
        if (!MessageDigest.isEqual(actual.toByteArray(), expected.toByteArray())) {
            throw CertificateException(
                "the device certificate does not match the saved fingerprint " +
                    "(expected ${expected.take(16)}…, got ${actual.take(16)}…)",
            )
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

    companion object {
        /** Lower-case hex SHA-256 of the DER-encoded certificate. */
        fun fingerprint(certificate: X509Certificate): String =
            MessageDigest.getInstance("SHA-256")
                .digest(certificate.encoded)
                .joinToString("") { "%02x".format(it) }

        /** `AA:BB:…` display form for the owner-facing prompt. */
        fun displayFingerprint(hex: String): String =
            hex.chunked(2).joinToString(":").uppercase()

        fun normalize(hex: String): String = hex.trim().lowercase().replace(":", "").replace(" ", "")
    }
}
