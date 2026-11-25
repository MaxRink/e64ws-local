package de.mahlkoenig.e64local.policy

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Source-level guarantee that the app is cloud-free and LAN-only.
 *
 * This test fails if any source or resource file names a remote host that is
 * not the user's own device. The only URL-shaped strings allowed are the
 * `https://` base of a user-entered endpoint and schema identifiers.
 */
class NoRemoteHostsTest {

    private val appDir = File("src/main").also {
        assertTrue("missing $it", it.isDirectory)
    }

    private val sourceFiles: List<File> by lazy {
        appDir.walkTopDown()
            .filter { it.isFile }
            .filter { it.extension in setOf("kt", "xml", "properties", "pro") }
            .toList()
    }

    /** Domains and SDK endpoints that would indicate a vendor cloud or telemetry. */
    private val forbiddenHosts = listOf(
        "mahlkoenig.com",
        "hemro.com",
        "decaid",
        "firebase",
        "googleapis.com",
        "google-analytics",
        "googletagmanager",
        "crashlytics",
        "sentry.io",
        "bugsnag",
        "amplitude.com",
        "mixpanel",
        "segment.io",
        "appcenter.ms",
        "analytics.google",
        "doubleclick",
        "facebook.com",
        "adjust.com",
        "appsflyer",
        "datadoghq",
        "newrelic",
        "cloudfront",
        "amazonaws.com",
        "azure",
        "api.sync",
        "wss://",
        "ws://",
    )

    @Test
    fun `no source file mentions a cloud, analytics or crash-reporting host`() {
        val violations = mutableListOf<String>()
        for (file in sourceFiles) {
            val text = file.readText()
            forbiddenHosts.forEach { needle ->
                if (text.contains(needle, ignoreCase = true)) violations += "${file.name}: $needle"
            }
        }
        assertEquals("forbidden hosts found: $violations", emptyList<String>(), violations)
    }

    @Test
    fun `every absolute URL in the app points at the user-entered device`() {
        val urlPattern = Regex("""https?://[^\s"'<)]+""")
        val violations = mutableListOf<String>()
        for (file in sourceFiles) {
            urlPattern.findAll(file.readText()).forEach { match ->
                val url = match.value
                val allowed = url == "https://" ||
                    url.startsWith("https://${'$'}{") ||
                    url.startsWith("https://\$") ||
                    url == "http://schemas.android.com/apk/res/android" ||
                    url.startsWith("http://schemas.android.com") ||
                    url.startsWith("http://java.sun.com") ||
                    url.startsWith("http://www.w3.org")
                if (!allowed) violations += "${file.name}: $url"
            }
        }
        assertEquals("unexpected absolute URLs: $violations", emptyList<String>(), violations)
    }

    @Test
    fun `the network security config refuses cleartext`() {
        val config = File(appDir, "res/xml/network_security_config.xml").readText()
        assertTrue(config.contains("cleartextTrafficPermitted=\"false\""))
        assertFalse(config.contains("cleartextTrafficPermitted=\"true\""))
    }

    @Test
    fun `the manifest requests only the INTERNET permission`() {
        val manifest = File(appDir, "AndroidManifest.xml").readText()
        val permissions = Regex("<uses-permission[^>]*android:name=\"([^\"]+)\"").findAll(manifest)
            .map { it.groupValues[1] }
            .toList()
        assertEquals(listOf("android.permission.INTERNET"), permissions)
        assertFalse(manifest.contains("allowBackup=\"true\""))
        assertFalse(manifest.contains("usesCleartextTraffic=\"true\""))
        assertFalse(manifest.contains("android:debuggable=\"true\""))
    }

    /**
     * The structural half of the no-cloud guarantee: reaching a host needs one
     * of these APIs, and only the device client may name them. A hardcoded
     * collector assembled without a literal URL would still have to appear here.
     */
    @Test
    fun `only the device client can open a network connection`() {
        val socketApis = listOf(
            "openConnection(",
            "java.net.Socket(",
            ".createSocket(",
            "InetSocketAddress(",
            "SSLSocketFactory",
            "InetAddress",
            "java.net.URL(",
        )
        val offenders = sourceFiles
            .filter { it.extension == "kt" }
            .filter { file -> file.readText().let { text -> socketApis.any { text.contains(it) } } }
            .map { it.name }
            .toSet()
        assertEquals(
            "network entry points outside the device client: $offenders",
            setOf("DeviceHttpClient.kt"),
            offenders,
        )
    }

    @Test
    fun `neither cloud backup nor device transfer may carry the encrypted token`() {
        val rules = File(appDir, "res/xml/data_extraction_rules.xml").readText()
        assertTrue(rules.contains("<cloud-backup>"))
        assertTrue(rules.contains("<device-transfer>"))
        // Android 12+ device transfer ignores allowBackup="false", so every
        // domain that can hold the token must be excluded explicitly.
        listOf("root", "file", "database", "sharedpref", "external").forEach { domain ->
            assertEquals(
                "$domain must be excluded from both cloud backup and device transfer",
                2,
                Regex("domain=\"$domain\"").findAll(rules).count(),
            )
        }
    }

    @Test
    fun `no token or password literal is committed`() {
        val suspicious = Regex("""(?i)(owner[_-]?token|password)\s*=\s*"[0-9a-fA-F]{16,}"""")
        for (file in sourceFiles) {
            assertFalse(file.name, suspicious.containsMatchIn(file.readText()))
        }
    }
}
