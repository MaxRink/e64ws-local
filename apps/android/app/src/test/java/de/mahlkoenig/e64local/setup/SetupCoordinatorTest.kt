package de.mahlkoenig.e64local.setup

import de.mahlkoenig.e64local.crypto.SecretCipher
import de.mahlkoenig.e64local.device.CookieJar
import de.mahlkoenig.e64local.device.DeviceHttpClient
import de.mahlkoenig.e64local.device.TransportException
import de.mahlkoenig.e64local.device.DeviceCertificate
import de.mahlkoenig.e64local.device.GrinderEndpoint
import de.mahlkoenig.e64local.storage.TokenStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Setup behaviour that does not need a device: planning, the certificate
 * decision, token validation and the failure paths. The full install is
 * exercised by [SetupInstallFlowTest] against an in-process fake device.
 */
class SetupCoordinatorTest {

    private class FakeCipher : SecretCipher {
        override fun encrypt(plainText: String): String = "enc:$plainText"
        override fun decrypt(payload: String): String? =
            payload.removePrefix("enc:").takeIf { payload.startsWith("enc:") }
    }

    private fun store() = TokenStore(FakePreferences(), FakeCipher())

    private fun coordinator(
        store: TokenStore = store(),
        certificate: DeviceCertificate = certificate("00"),
    ) = SetupCoordinator(
        tokenStore = store,
        moduleProvider = { MODULE.toByteArray() },
        runnerProvider = { RUNNER.toByteArray() },
        certificateProbe = { Result.success(certificate) },
        clientFactory = { _, _, _ -> error("the network must not be touched by these paths") },
    )

    @Test
    fun `plan shows the exact installer script and commands`() {
        val plan = coordinator().plan(GrinderEndpoint("192.168.1.100"))
        assertEquals(64, plan.moduleSha256.length)
        assertEquals(MODULE.toByteArray().size, plan.moduleBytes)
        assertEquals(64, plan.runnerSha256.length)
        assertEquals(RUNNER.toByteArray().size, plan.runnerBytes)
        assertTrue(plan.installerScript.contains("/db/e64local/token"))
        assertTrue(plan.installerScript.contains("chmod 600"))
        assertTrue(plan.installerScript.contains("/usr/local/bin/e64local-action-run"))
        assertTrue(plan.installerScript.contains("chmod 755"))
        assertTrue(plan.commandCount > 2)
        (plan.moduleUploadCommands + plan.runnerUploadCommands + plan.installerCommands).forEach {
            assertFalse(it, Fw01Injection.isForbidden(it))
        }
    }

    @Test
    fun `an unpinned device is a certificate decision, not a connection`() {
        val result = coordinator().probe(GrinderEndpoint("192.168.1.100"))
        assertTrue(result is ProbeResult.CertificateDecision)
        assertTrue((result as ProbeResult.CertificateDecision).reason.contains("self-signed"))
    }

    @Test
    fun `a changed certificate is a decision again`() {
        val store = store()
        // The stored pin is a 64-hex fingerprint; a different one must not match.
        store.pinCertificate("192.168.1.100", ("aabb" + "0".repeat(60)))
        val presented = "ccdd" + "0".repeat(60)
        val result = coordinator(store, certificate(presented)).probe(GrinderEndpoint("192.168.1.100"))
        assertTrue(result is ProbeResult.CertificateDecision)
        assertEquals(presented, (result as ProbeResult.CertificateDecision).certificate.sha256)
    }

    @Test
    fun `the module digest is the digest of the provided bytes`() {
        val coordinator = coordinator()
        val expected = java.security.MessageDigest.getInstance("SHA-256")
            .digest(MODULE.toByteArray()).joinToString("") { "%02x".format(it) }
        assertEquals(expected, coordinator.moduleSha256())
    }

    @Test
    fun `an unreachable device fails the install at the upload stage and stores nothing`() {
        val store = store()
        val prefs = FakePreferences()
        val isolated = TokenStore(prefs, FakeCipher())
        val coordinator = SetupCoordinator(
            tokenStore = isolated,
            moduleProvider = { MODULE.toByteArray() },
            runnerProvider = { RUNNER.toByteArray() },
            certificateProbe = { Result.success(certificate("00")) },
            clientFactory = { _, jar, _ -> DisconnectedClient(jar) },
        )
        val result = coordinator.install(GrinderEndpoint("192.168.1.100"), "") { }
        assertTrue(result.toString(), result is SetupResult.Failed)
        assertEquals(SetupStage.UPLOADING_MODULE, (result as SetupResult.Failed).stage)
        assertNull(isolated.token("192.168.1.100"))
        assertTrue(prefs.map.keys.none { it.contains("token") })
    }

    /** A client whose every request fails the way a dead device does. */
    private class DisconnectedClient(jar: CookieJar) : de.mahlkoenig.e64local.device.DeviceHttpClient(
        GrinderEndpoint("192.168.1.100"),
        jar,
        de.mahlkoenig.e64local.device.PinnedTrustManager("00"),
    ) {
        override fun get(path: String) = throw de.mahlkoenig.e64local.device.TransportException("unreachable")
        override fun postForm(path: String, fields: Map<String, String>) =
            throw de.mahlkoenig.e64local.device.TransportException("unreachable")
        override fun postJson(path: String, json: String, extraHeaders: Map<String, String>) =
            throw de.mahlkoenig.e64local.device.TransportException("unreachable")
    }

    private fun certificate(sha: String) = DeviceCertificate(
        sha256 = sha,
        subject = "CN=e64",
        issuer = "CN=e64",
        notAfter = "2030-01-01",
        tlsVersion = "TLSv1.2",
    )

    companion object {
        const val MODULE = "<?php\n// local owner api module (test fixture)\n"
        const val RUNNER = "#!/usr/bin/env php\n<?php\n// bounded action runner (test fixture)\n"
    }
}

/**
 * In-memory `SharedPreferences` for the JVM tests. Shared with
 * [SetupInstallFlowTest] so the install flow can inspect what was persisted.
 */
internal class FakePreferences : android.content.SharedPreferences {
    val map = LinkedHashMap<String, Any?>()
    override fun getAll(): MutableMap<String, *> = map.toMutableMap()
    override fun getString(key: String, defValue: String?): String? = map[key] as? String ?: defValue
    override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? = defValues
    override fun getInt(key: String, defValue: Int): Int = map[key] as? Int ?: defValue
    override fun getLong(key: String, defValue: Long): Long = map[key] as? Long ?: defValue
    override fun getFloat(key: String, defValue: Float): Float = map[key] as? Float ?: defValue
    override fun getBoolean(key: String, defValue: Boolean): Boolean = map[key] as? Boolean ?: defValue
    override fun contains(key: String): Boolean = map.containsKey(key)
    override fun edit(): android.content.SharedPreferences.Editor = Editor()
    override fun registerOnSharedPreferenceChangeListener(listener: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(listener: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}

    inner class Editor : android.content.SharedPreferences.Editor {
        private val pending = LinkedHashMap<String, Any?>()
        private val removals = mutableSetOf<String>()
        override fun putString(key: String, value: String?) = apply { pending[key] = value }
        override fun putStringSet(key: String, values: MutableSet<String>?) = apply { pending[key] = values }
        override fun putInt(key: String, value: Int) = apply { pending[key] = value }
        override fun putLong(key: String, value: Long) = apply { pending[key] = value }
        override fun putFloat(key: String, value: Float) = apply { pending[key] = value }
        override fun putBoolean(key: String, value: Boolean) = apply { pending[key] = value }
        override fun remove(key: String) = apply { removals += key }
        override fun clear() = apply { removals += map.keys }
        override fun commit(): Boolean {
            removals.forEach { map.remove(it) }
            pending.forEach { (k, v) -> map[k] = v }
            return true
        }

        override fun apply() {
            commit()
        }
    }
}
