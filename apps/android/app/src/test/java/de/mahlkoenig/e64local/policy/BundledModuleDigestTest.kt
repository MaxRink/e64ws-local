package de.mahlkoenig.e64local.policy

import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The PHP files shipped inside the APK must be byte-identical to the
 * repository copies, so the digests reported in the setup plan and enforced on
 * the device are the digests of the reviewed files.
 */
class BundledModuleDigestTest {

    private val projectDir = File(System.getProperty("user.dir")).let {
        if (File(it, "src/main").isDirectory) it else File(it, "app")
    }

    private fun asset(name: String) = File(projectDir, "src/main/assets/$name")

    /** apps/android/app -> repository root. */
    private fun repositoryCopy(name: String) =
        File(projectDir, "../../../ondevice/$name").canonicalFile

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun assertBundled(name: String, pinnedSha: String) {
        val asset = asset(name)
        val repository = repositoryCopy(name)
        assertTrue("asset missing: ${asset.absolutePath}", asset.isFile)
        assertTrue("repository copy missing: ${repository.absolutePath}", repository.isFile)
        assertEquals(name, sha256(repository.readBytes()), sha256(asset.readBytes()))
        assertEquals("$name drifted; update the asset and this pin together", pinnedSha, sha256(asset.readBytes()))
    }

    @Test
    fun `the bundled module is the reviewed repository module`() {
        assertBundled(
            "rest_api_dev.php",
            "ca0203d6cee4e0ec241fe37e27ca0d17178def082d103feb774d7ddf93ea4c0c",
        )
    }

    @Test
    fun `the bundled action runner is the reviewed repository runner`() {
        assertBundled(
            "e64local_action_run.php",
            "a6f3ec2ac191e0d13094a221551590041c38b90b7624fb102d8874ad283cb35b",
        )
    }

    @Test
    fun `the bundled module still enforces the dev gate and the owner token`() {
        val php = asset("rest_api_dev.php").readText()
        assertTrue(php.contains("isDev()"))
        assertTrue(php.contains("X_E64_LOCAL_TOKEN"))
        assertTrue(php.contains("/db/e64local/token"))
        assertTrue(php.contains("e64local-api-"))
    }

    @Test
    fun `the bundled module keeps actions behind the policy gate`() {
        val php = asset("rest_api_dev.php").readText()
        assertTrue(php.contains("/db/e64local/actions.json"))
        assertTrue(php.contains("E64LOCAL_ACTION_RUNNER"))
        assertTrue(php.contains("/usr/local/bin/e64local-action-run"))
    }

    @Test
    fun `the bundled runner keeps the bounded job schema and no ESP command`() {
        val php = asset("e64local_action_run.php").readText()
        assertTrue(php.contains("e64local-action-job-v1"))
        assertTrue(php.contains("E64RUN_MAX_TIMEOUT_MS"))
        // The allowlist must not grow ESP, firmware or bootloader commands.
        listOf("EspFlashApp", "EspEraseFlash", "espFlash", "fw_setenv", "FirmwareUpdate").forEach { needle ->
            assertFalse("runner allowlist maps $needle", php.contains("\"$needle\" =>"))
        }
    }
}
