package de.mahlkoenig.e64local.setup

import de.mahlkoenig.e64local.crypto.SecretCipher
import de.mahlkoenig.e64local.device.CookieJar
import de.mahlkoenig.e64local.device.DeviceCertificate
import de.mahlkoenig.e64local.device.DeviceHttpClient
import de.mahlkoenig.e64local.device.GrinderEndpoint
import de.mahlkoenig.e64local.device.PinnedTrustManager
import de.mahlkoenig.e64local.device.TransportResponse
import de.mahlkoenig.e64local.storage.TokenStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The whole install flow against an in-process fake device: the upload
 * commands, the root step, and the verification that decides whether the
 * credential is stored. These are the paths that must fail closed.
 */
class SetupInstallFlowTest {

    private val host = "192.168.1.100"
    private val endpoint = GrinderEndpoint(host)

    private class FakeCipher : SecretCipher {
        // Reversible, but never leaves the plain text as a substring.
        override fun encrypt(plainText: String): String = "enc:" + plainText.reversed()
        override fun decrypt(payload: String): String? =
            payload.removePrefix("enc:").reversed().takeIf { payload.startsWith("enc:") }
    }

    /** A device that answers the vendor login, the injection and capabilities. */
    private class FakeDevice(
        jar: CookieJar,
        private val capabilities: String,
        private val capabilitiesStatus: Int = 200,
        private val loginSucceeds: Boolean = true,
    ) : DeviceHttpClient(GrinderEndpoint(HOST), jar, PinnedTrustManager("00")) {
        val commands = mutableListOf<String>()
        var logins = 0

        override fun get(path: String): TransportResponse =
            TransportResponse(200, LOGIN_PAGE, "text/html", emptyList(), null)

        override fun postForm(path: String, fields: Map<String, String>): TransportResponse {
            if (path != "/login.php" || fields["login"] != "1") error("unexpected form post $path")
            val role = fields["userRole"].orEmpty()
            if (role.startsWith("x';")) {
                commands += role.removePrefix("x';").removeSuffix(";#")
            } else {
                logins++
                if (!loginSucceeds) {
                    return TransportResponse(200, LOGIN_PAGE, "text/html", emptyList(), null)
                }
            }
            cookieJar.storeFromSetCookie(listOf("PHPSESSID=sess"), HOST)
            return TransportResponse(200, "", "text/html", listOf("PHPSESSID=sess"), null)
        }

        override fun postJson(path: String, json: String, extraHeaders: Map<String, String>): TransportResponse {
            if (cookieJar.headerFor(HOST, path) == null) {
                return TransportResponse(200, LOGIN_PAGE, "text/html", emptyList(), null)
            }
            if (path != "/rest_api/capabilities") error("unexpected route $path")
            return TransportResponse(capabilitiesStatus, capabilities, "application/json", emptyList(), null)
        }

        companion object {
            const val HOST = "192.168.1.100"
            const val LOGIN_PAGE = "<html><title>Login Hemro E64 WS</title></html>"
        }
    }

    private fun coordinator(
        store: TokenStore,
        capabilities: String,
        capabilitiesStatus: Int = 200,
        loginSucceeds: Boolean = true,
    ): SetupCoordinator = SetupCoordinator(
        tokenStore = store,
        moduleProvider = { MODULE.toByteArray() },
        runnerProvider = { RUNNER.toByteArray() },
        certificateProbe = { Result.success(certificate) },
        clientFactory = { _, jar, _ ->
            FakeDevice(jar, capabilities, capabilitiesStatus, loginSucceeds)
        },
    )

    private fun cipher(): SecretCipher = FakeCipher()

    @Test
    fun `a successful install stores the token only after capabilities validates`() {
        val prefs = FakePreferences()
        val store = TokenStore(prefs, cipher())
        store.pinCertificate(endpoint.id, certificate.sha256)

        val result = coordinator(store, VALID_CAPABILITIES).install(endpoint, "owner-pw") { }

        val ok = result as SetupResult.Ok
        assertTrue(OwnerToken.isValid(ok.token))
        assertEquals(ok.token, store.token(endpoint.id))
        assertEquals("owner-pw", store.ownerPassword(endpoint.id))
        // Only ciphertext is at rest.
        val persisted = prefs.map.values.filterIsInstance<String>().joinToString("|")
        assertFalse("plain token leaked: $persisted", persisted.contains(ok.token))
        assertFalse("plain password leaked: $persisted", persisted.contains("owner-pw"))
        assertTrue(persisted.contains("enc:"))
    }

    @Test
    fun `the install sends the module upload, the installer and nothing the guard rejects`() {
        val devices = mutableListOf<FakeDevice>()
        val store = TokenStore(FakePreferences(), cipher())
        store.pinCertificate(endpoint.id, certificate.sha256)
        val coordinator = SetupCoordinator(
            tokenStore = store,
            moduleProvider = { MODULE.toByteArray() },
            runnerProvider = { RUNNER.toByteArray() },
            certificateProbe = { Result.success(certificate) },
            clientFactory = { _, jar, _ -> FakeDevice(jar, VALID_CAPABILITIES).also { devices += it } },
        )

        val result = coordinator.install(endpoint, "") { }
        assertTrue(result.toString(), result is SetupResult.Ok)

        val commands = devices.first().commands
        assertTrue("module chunks missing", commands.any { it.startsWith("printf '%s' '") })
        assertTrue("module decode missing", commands.any { it.startsWith("base64 -d /tmp/e64local.b64 > /tmp/e64local-module.php") })
        assertTrue("runner decode missing", commands.any { it.startsWith("base64 -d /tmp/e64local.b64 > /tmp/e64local-action-run.php") })
        assertTrue("installer decode missing", commands.any { it.startsWith("base64 -d /tmp/e64local.b64 > /tmp/e64local-setup.sh") })
        assertTrue("installer run missing", commands.contains("sudo sh /tmp/e64local-setup.sh"))
        // The guard that ships with the app accepts every command that was sent.
        commands.forEach { assertFalse("guard would reject: $it", Fw01Injection.isForbidden(it)) }
    }

    @Test
    fun `a document without the reviewed schema is not reported as installed`() {
        val prefs = FakePreferences()
        val store = TokenStore(prefs, cipher())
        store.pinCertificate(endpoint.id, certificate.sha256)

        val result = coordinator(store, """{"data":{"apiVersion":"1","routes":[]},"success":true,"errorCode":0}""")
            .install(endpoint, "") { }

        assertTrue(result.toString(), result is SetupResult.Failed)
        assertEquals(SetupStage.VERIFYING, (result as SetupResult.Failed).stage)
        assertNull(store.token(endpoint.id))
        assertTrue(prefs.map.keys.none { it.endsWith(".token") })
    }

    @Test
    fun `a rejected token at verification stores nothing`() {
        val prefs = FakePreferences()
        val store = TokenStore(prefs, cipher())
        store.pinCertificate(endpoint.id, certificate.sha256)

        val result = coordinator(
            store,
            """{"success":false,"errorCode":401,"error":"owner token rejected"}""",
            capabilitiesStatus = 400,
        ).install(endpoint, "") { }

        assertTrue(result.toString(), result is SetupResult.Failed)
        assertEquals(SetupStage.VERIFYING, (result as SetupResult.Failed).stage)
        assertNull(store.token(endpoint.id))
        assertTrue(prefs.map.keys.none { it.endsWith(".token") })
    }

    @Test
    fun `a failed vendor login stores nothing`() {
        val prefs = FakePreferences()
        val store = TokenStore(prefs, cipher())
        store.pinCertificate(endpoint.id, certificate.sha256)

        val result = coordinator(store, VALID_CAPABILITIES, loginSucceeds = false)
            .install(endpoint, "wrong-pw") { }

        assertTrue(result.toString(), result is SetupResult.Failed)
        assertEquals(SetupStage.VERIFYING, (result as SetupResult.Failed).stage)
        assertNull(store.token(endpoint.id))
        assertTrue(prefs.map.keys.none { it.endsWith(".token") })
    }

    private val certificate = DeviceCertificate(
        sha256 = "aa".repeat(32),
        subject = "CN=e64",
        issuer = "CN=e64",
        notAfter = "2030-01-01",
        tlsVersion = "TLSv1.2",
    )

    companion object {
        const val MODULE = "<?php\n// local owner api module (test fixture)\n"
        const val RUNNER = "#!/usr/bin/env php\n<?php\n// bounded action runner (test fixture)\n"

        const val VALID_CAPABILITIES =
            """{"data":{"schema":"e64local-api-v1","apiVersion":"1","routes":["capabilities"],""" +
                """"features":{"actions":false,"pagination":true,"timeFilters":true},""" +
                """"limits":{"maxRows":5000,"maxOffset":1000000,"maxFileBytes":1048576},"serverTime":1767225600},""" +
                """"success":true,"errorCode":0}"""
    }
}
