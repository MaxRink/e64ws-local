package de.mahlkoenig.e64local.setup

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class Fw01InjectionTest {

    @Test
    fun `quotes the command exactly as the FW-01 transport does`() {
        assertEquals("x';id;#", Fw01Injection.quote("id"))
        assertEquals("x';printf '%s' 'abc' >> /tmp/e64local.b64;#", Fw01Injection.quote("printf '%s' 'abc' >> /tmp/e64local.b64"))
    }

    @Test
    fun `refuses newlines and NUL bytes in a command`() {
        assertTrue(runCatching { Fw01Injection.quote("a\nb") }.isFailure)
        assertTrue(runCatching { Fw01Injection.quote("a\u0000b") }.isFailure)
        assertTrue(runCatching { Fw01Injection.quote("") }.isFailure)
    }

    @Test
    fun `login form carries the four documented fields and never a password`() {
        val form = Fw01Injection.loginForm("id")
        assertEquals(listOf("login", "requestDeveloper", "password", "userRole"), form.keys.toList())
        assertEquals("1", form["login"])
        assertEquals("1", form["requestDeveloper"])
        assertEquals("x", form["password"])
        assertEquals("x';id;#", form["userRole"])
    }

    @Test
    fun `base64 encoder matches the RFC test vectors`() {
        assertEquals("", Base64.encode(ByteArray(0)))
        assertEquals("Zg==", Base64.encode("f".toByteArray()))
        assertEquals("Zm8=", Base64.encode("fo".toByteArray()))
        assertEquals("Zm9v", Base64.encode("foo".toByteArray()))
        assertEquals("Zm9vYg==", Base64.encode("foob".toByteArray()))
        assertEquals("Zm9vYmE=", Base64.encode("fooba".toByteArray()))
        assertEquals("Zm9vYmFy", Base64.encode("foobar".toByteArray()))
        assertEquals(Base64.encode("hello world".toByteArray()), java.util.Base64.getEncoder().encodeToString("hello world".toByteArray()))
    }

    @Test
    fun `upload chunks at 40000 characters with a reset and a decode step`() {
        val script = "#!/bin/sh\necho hello\n".repeat(6000) // ~108 KB, ~144 KB base64
        val commands = Fw01Injection.uploadCommands(script, "/tmp/x.sh")
        val appends = commands.filter { it.startsWith("printf '%s' '") }
        assertTrue("expected several chunks, got ${appends.size}", appends.size > 3)
        appends.forEach { command ->
            val chunk = command.removePrefix("printf '%s' '").removeSuffix("' >> /tmp/e64local.b64")
            assertTrue("chunk too large: ${chunk.length}", chunk.length <= Fw01Injection.WEB_CHUNK)
            assertTrue(chunk.matches(Regex("^[A-Za-z0-9+/=]+$")))
        }
        // Reassembling every chunk gives the original script.
        val joined = appends.joinToString("") {
            it.removePrefix("printf '%s' '").removeSuffix("' >> /tmp/e64local.b64")
        }
        assertEquals(script, String(java.util.Base64.getDecoder().decode(joined)))
        assertEquals("sudo rm -f /tmp/e64local.b64 /tmp/x.sh", commands.first())
        assertTrue(commands.contains("base64 -d /tmp/e64local.b64 > /tmp/x.sh"))
        assertTrue(commands.contains("sudo sh /tmp/x.sh"))
    }

    @Test
    fun `decode-only upload does not delete its own staging file`() {
        val commands = Fw01Injection.uploadCommands("module", "/tmp/module.php", execute = false)
        assertEquals("sudo rm -f /tmp/e64local.b64", commands.first())
        assertFalse(commands.contains("chmod 700 /tmp/module.php"))
        assertFalse(commands.any { it.startsWith("sudo rm -f /tmp/e64local.b64 /tmp/module.php") })
        assertTrue(commands.last().startsWith("base64 -d"))
    }

    @Test
    fun `the forbidden-pattern guard blocks every ESP and firmware surface`() {
        val forbidden = listOf(
            "sudo dd if=/dev/esps0 of=/tmp/x",
            "dd if=/dev/mtd0 of=/tmp/x",
            "echo 1 > /dev/ttySTM5",
            "python3 esptool.py write_flash",
            "flashEspZip.sh /tmp/a.zip",
            "setEspBootmode.sh",
            "fw_setenv bootcmd run mmcboot",
            "echo x > /sys/class/efuse/otp",
            "swupdate -i update.swu",
            "cp /tmp/FirmwareUpdate.swu /db/",
        )
        forbidden.forEach { command ->
            assertTrue("guard missed: $command", Fw01Injection.isForbidden(command))
            assertTrue(Fw01Injection.validate(command).isFailure)
        }
    }

    @Test
    fun `the installer commands pass the forbidden-pattern guard`() {
        val script = SetupCommands(MODULE_SHA, RUNNER_SHA).script(TOKEN)
        val commands = Fw01Injection.uploadCommands(script, SetupCommands.INSTALLER_STAGE)
        assertTrue(commands.isNotEmpty())
        commands.forEach { command ->
            assertFalse("guard rejected an installer command: $command", Fw01Injection.isForbidden(command))
            assertTrue(Fw01Injection.validate(command).isSuccess)
        }
        // The module itself is base64 text; it must contain no shell-breaking quote.
        assertFalse(commands.any { it.contains("';#") && it.startsWith("printf") })
    }

    @Test
    fun `the installer plan never references the ESP or firmware paths`() {
        val script = SetupCommands(MODULE_SHA, RUNNER_SHA).script(TOKEN)
        val commands = Fw01Injection.uploadCommands(script, SetupCommands.INSTALLER_STAGE)
        listOf("/dev/esps", "/dev/mtd", "esptool", "flashEsp", "efuse", ".swu").forEach { needle ->
            assertFalse("plan mentions $needle", commands.any { it.contains(needle, ignoreCase = true) })
        }
    }

    @Test
    fun `owner tokens are 64 lower-case hex characters`() {
        val token = OwnerToken.generate()
        assertEquals(64, token.length)
        assertTrue(token.matches(Regex("^[0-9a-f]{64}$")))
        assertTrue(OwnerToken.isValid(token))
        assertFalse(OwnerToken.isValid(token.uppercase()))
        assertFalse(OwnerToken.isValid("abc"))
        // Two generated tokens are never equal (256 bits of entropy).
        assertTrue(OwnerToken.generate() != OwnerToken.generate())
        // Generation uses the 32 bytes it is given: a fixed SecureRandom yields
        // the same token, a huge JSF2000-like source (all zeros) yields zeros.
        assertEquals("00".repeat(32), OwnerToken.generate(FixedRandom(ByteArray(32) { 0 })))
    }

    @Test
    fun `token digests are stable`() {
        assertEquals(
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            OwnerToken.sha256Hex("foo"),
        )
    }

    @Test
    fun `installer script writes only the module, the runner, the token directory and the token`() {
        val script = SetupCommands(MODULE_SHA, RUNNER_SHA).script(TOKEN)
        assertTrue(script.contains("mkdir -p /usr/local/www/dev"))
        assertTrue(script.contains("chmod 644 /usr/local/www/dev/rest_api_dev.php"))
        assertTrue(script.contains("cp /tmp/e64local-action-run.php /usr/local/bin/e64local-action-run"))
        assertTrue(script.contains("chmod 755 /usr/local/bin/e64local-action-run"))
        assertTrue(script.contains("chown root:root /usr/local/bin/e64local-action-run"))
        assertTrue(script.contains("if [ ! -x /usr/local/bin/e64local-action-run ]"))
        assertTrue(script.contains("mkdir -p /db/e64local"))
        assertTrue(script.contains("chmod 711 /db/e64local"))
        assertTrue(script.contains("printf '%s\\n' '$TOKEN' > /db/e64local/token"))
        assertTrue(script.contains("chmod 600 /db/e64local/token"))
        assertTrue(script.contains("chown www-data:www-data /db/e64local/token"))
        assertTrue(script.contains("if [ \"\$token_mode\" != \"600\" ]"))
        assertTrue(script.contains("if [ \"\$runner_mode\" != \"755\" ]"))
        assertTrue(script.contains("sha256sum /usr/local/www/dev/rest_api_dev.php"))
        assertTrue(script.contains("sha256sum /usr/local/bin/e64local-action-run"))
        assertTrue(script.contains("set -eu"))
        // No policy file is written: installing the runner cannot enable an action.
        assertFalse(script.contains("> /db/e64local/actions.json"))
        // Nothing else is written.
        listOf("/var", "/etc", "/root", "/db/Hsg", "/db/Ng2", "/usr/local/sbin").forEach { unexpected ->
            assertFalse("script writes $unexpected", script.contains("> $unexpected") || script.contains("mkdir -p $unexpected"))
        }
    }

    @Test
    fun `installer refuses a malformed token or digest`() {
        assertEquals(
            true,
            runCatching { SetupCommands(MODULE_SHA, RUNNER_SHA).script("short") }.isFailure,
        )
        assertEquals(
            true,
            runCatching { SetupCommands("nothex", RUNNER_SHA).script(TOKEN) }.isFailure,
        )
        assertEquals(
            true,
            runCatching { SetupCommands(MODULE_SHA, "nothex").script(TOKEN) }.isFailure,
        )
    }

    private class FixedRandom(private val bytes: ByteArray) : SecureRandom() {
        override fun nextBytes(b: ByteArray) {
            bytes.copyInto(b, 0, 0, minOf(b.size, bytes.size))
        }
    }

    companion object {
        const val TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        // Local fixtures; the pinned digests of the real files live in
        // BundledModuleDigestTest.
        val MODULE_SHA = "ab".repeat(32)
        val RUNNER_SHA = "cd".repeat(32)
    }
}
