package de.mahlkoenig.e64local.setup

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * The FW-01 login-form injection, ported from
 * `tools/e64root/transports.py` (`WebTransport.inject`).
 *
 * `login.php` passes `userRole` into a `sudo sqlite3` command, so `';` closes
 * the shell quote and `#` comments out the trailing SQL. This is the *only*
 * way the app changes anything on the device, and it runs the installer in
 * [SetupCommands], which never touches the ESP, the firmware, the bootloader or
 * the eFuse.
 */
object Fw01Injection {
    const val LOGIN_PATH = "/login.php"

    /** Base64 characters appended per request; matches `WEB_CHUNK` in transports.py. */
    const val WEB_CHUNK = 40_000

    const val UPLOAD_B64 = "/tmp/e64local.b64"

    fun quote(command: String): String {
        require(command.isNotEmpty()) { "the injected command must not be empty" }
        require('\u0000' !in command) { "the injected command must not contain a NUL byte" }
        require('\n' !in command && '\r' !in command) { "the injected command must be a single line" }
        return "x';$command;#"
    }

    /** The exact form fields sent for one command. The owner password is never included. */
    fun loginForm(command: String): Map<String, String> = linkedMapOf(
        "login" to "1",
        "requestDeveloper" to "1",
        "password" to "x",
        "userRole" to quote(command),
    )

    fun chunks(script: String, chunkSize: Int = WEB_CHUNK): List<String> {
        require(chunkSize >= 512) { "chunk size is too small" }
        val encoded = Base64.encode(script.toByteArray(Charsets.UTF_8))
        if (encoded.isEmpty()) return emptyList()
        return encoded.chunked(chunkSize)
    }

    /**
     * Reset, one append per chunk, then decode (and, unless [execute] is
     * false, decode, chmod, run and clean up).
     */
    fun uploadCommands(
        script: String,
        target: String,
        chunkSize: Int = WEB_CHUNK,
        execute: Boolean = true,
    ): List<String> = buildList {
        // An executing upload may reuse the shared buffer; a decode-only upload
        // must not delete the staging file it is about to decode into.
        add(if (execute) "sudo rm -f $UPLOAD_B64 $target" else "sudo rm -f $UPLOAD_B64")
        for (chunk in chunks(script, chunkSize)) {
            add("printf '%s' '$chunk' >> $UPLOAD_B64")
        }
        add("base64 -d $UPLOAD_B64 > $target")
        if (execute) {
            add("chmod 700 $target")
            add("sudo sh $target")
            add("rm -f $UPLOAD_B64 $target")
        }
    }

    /**
     * A command is only accepted when its shell skeleton stays on the paths the
     * installer uses. This is the app-side half of the "never touch the ESP"
     * guarantee: a command that names a flash device, firmware image, ESP NVS
     * or bootloader utility is refused before it is sent.
     *
     * Quoted literals are collapsed before the check: a base64 payload chunk is
     * opaque data, not a command, and random base64 reliably contains
     * substrings like "nvs". The *skeleton* is what matters, not the payload.
     */
    fun isForbidden(command: String): Boolean {
        val skeleton = skeletonOf(command)
        return ForbiddenPatterns.any { it.containsMatchIn(skeleton) } ||
            !writeTargetsAllowed(skeleton)
    }

    /** Replaces every single-quoted literal with an empty one. */
    fun skeletonOf(command: String): String = command.replace(Regex("'[^']*'"), "''")

    /** Absolute paths a command may name; anything else is outside the install. */
    private fun writeTargetsAllowed(skeleton: String): Boolean {
        val paths = Regex("""(?:^|[\s>|;&(])(/[A-Za-z0-9._/-]+)""").findAll(skeleton)
            .map { it.groupValues[1] }
            .toList()
        return paths.all { path ->
            AllowedWritePrefixes.any { prefix -> path == prefix || path.startsWith("$prefix/") }
        }
    }

    fun validate(command: String): Result<String> =
        if (isForbidden(command)) {
            Result.failure(IllegalArgumentException("refusing a command that touches the ESP, firmware or an unexpected path"))
        } else {
            Result.success(command)
        }

    /** Every path the installer is permitted to name. */
    val AllowedWritePrefixes: List<String> = listOf(
        "/tmp",
        "/usr/local/www/dev",
        "/usr/local/bin/e64local-action-run",
        "/db/e64local",
        "/log",
        "/etc/issue",
        "/dev/null",
    )

    /** Patterns covering ESP flash, NVS, bootloader, eFuse and firmware surfaces. */
    val ForbiddenPatterns: List<Regex> = listOf(
        Regex("/dev/esps\\d", RegexOption.IGNORE_CASE),
        Regex("/dev/mtd", RegexOption.IGNORE_CASE),
        Regex("/dev/ttySTM", RegexOption.IGNORE_CASE),
        Regex("esptool", RegexOption.IGNORE_CASE),
        Regex("/dev/mmcblk", RegexOption.IGNORE_CASE),
        Regex("flash_erase|nanddump|nandwrite|fw_setenv|u-boot|uboot", RegexOption.IGNORE_CASE),
        Regex("flashEspZip|setEspBootmode|unsetEspBootmode|espFlash|nvs", RegexOption.IGNORE_CASE),
        Regex("efuse|otp", RegexOption.IGNORE_CASE),
        Regex("FirmwareUpdate\\.swu|\\*\\.swu|\\.swu\\b", RegexOption.IGNORE_CASE),
        Regex("fwupd|swupdate|flash-image|sysupgrade", RegexOption.IGNORE_CASE),
    )
}

object Base64 {
    private val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray()

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
            out.append(alphabet[b0 shr 2])
            out.append(alphabet[((b0 and 0x03) shl 4) or (b1 shr 4)])
            out.append(if (i + 1 < bytes.size) alphabet[((b1 and 0x0F) shl 2) or (b2 shr 6)] else '=')
            out.append(if (i + 2 < bytes.size) alphabet[b2 and 0x3F] else '=')
            i += 3
        }
        return out.toString()
    }
}

/** Generates the per-device owner token: 32 random bytes as lower-case hex. */
object OwnerToken {
    const val BYTES = 32
    const val LENGTH = BYTES * 2

    val HEX = Regex("^[0-9a-f]+$")

    fun generate(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(BYTES)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun isValid(token: String): Boolean = token.length == LENGTH && HEX.matches(token)

    fun sha256Hex(token: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(token.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}

/**
 * The idempotent installer script. It mirrors
 * `e64root api deploy` in `tools/e64root/commands.py`, with both files
 * uploaded through the FW-01 chunked path instead of a heredoc (Android cannot
 * post a 170 KB form field in one request reliably).
 *
 * It writes exactly four things: the module, the root-owned action runner, the
 * token directory and the token. It does not read or write any ESP, firmware,
 * database or config path.
 */
class SetupCommands(private val moduleSha256: String, private val runnerSha256: String) {

    val modulePath = MODULE_PATH
    val moduleDir = MODULE_DIR
    val runnerPath = RUNNER_PATH
    val tokenDir = TOKEN_DIR
    val tokenPath = TOKEN_FILE

    fun script(token: String): String {
        require(OwnerToken.isValid(token)) { "the token must be 32 random bytes as 64 hex characters" }
        require(Regex("^[0-9a-f]{64}$").matches(moduleSha256)) { "module digest must be a sha256 hex string" }
        require(Regex("^[0-9a-f]{64}$").matches(runnerSha256)) { "runner digest must be a sha256 hex string" }

        return """
            |#!/bin/sh
            |# e64local android setup (generated on the phone; owner-authorized use only)
            |# Installs the Local Owner API module, the bounded action runner and the
            |# owner token. Never touches the ESP, firmware, bootloader, eFuse or the
            |# machine database. Actions stay disabled until a policy file is deployed.
            |set -eu
            |umask 077
            |mount -o remount,rw / 2>/dev/null || true
            |
            |mkdir -p $moduleDir
            |
            |# Both files were already decoded from the chunked upload.
            |if [ ! -s __MODULE_STAGE__ ]; then
            |  echo "e64local: uploaded module is missing" >&2
            |  exit 1
            |fi
            |cp __MODULE_STAGE__ $modulePath
            |rm -f __MODULE_STAGE__
            |chmod 644 $modulePath
            |chown www-data:www-data $modulePath 2>/dev/null || true
            |
            |# The root-owned runner is inert without /db/e64local/actions.json, so
            |# installing it here does not enable a single action.
            |if [ ! -s __RUNNER_STAGE__ ]; then
            |  echo "e64local: uploaded action runner is missing" >&2
            |  exit 1
            |fi
            |cp __RUNNER_STAGE__ $runnerPath
            |rm -f __RUNNER_STAGE__
            |chmod 755 $runnerPath
            |chown root:root $runnerPath 2>/dev/null || chown root $runnerPath 2>/dev/null || true
            |
            |# 0711: www-data can traverse to the token but cannot list the directory.
            |mkdir -p $tokenDir
            |chmod 711 $tokenDir
            |
            |printf '%s\n' '$token' > $tokenPath
            |chmod 600 $tokenPath
            |chown www-data:www-data $tokenPath 2>/dev/null || chown www-data $tokenPath 2>/dev/null || true
            |
            |# Verify before reporting success.
            |if [ ! -r $modulePath ]; then
            |  echo "e64local: module is not readable" >&2
            |  exit 1
            |fi
            |if [ ! -r $tokenPath ]; then
            |  echo "e64local: token file is not readable" >&2
            |  exit 1
            |fi
            |token_mode=${'$'}(stat -c '%a' $tokenPath 2>/dev/null || echo unknown)
            |if [ "${'$'}token_mode" != "600" ]; then
            |  echo "e64local: token file mode is ${'$'}token_mode, expected 600" >&2
            |  exit 1
            |fi
            |module_hash=${'$'}(sha256sum $modulePath 2>/dev/null | cut -d' ' -f1)
            |if [ "${'$'}module_hash" != "$moduleSha256" ]; then
            |  echo "e64local: module digest ${'$'}module_hash does not match $moduleSha256" >&2
            |  exit 1
            |fi
            |if [ ! -x $runnerPath ]; then
            |  echo "e64local: action runner is not executable" >&2
            |  exit 1
            |fi
            |runner_mode=${'$'}(stat -c '%a' $runnerPath 2>/dev/null || echo unknown)
            |if [ "${'$'}runner_mode" != "755" ]; then
            |  echo "e64local: action runner mode is ${'$'}runner_mode, expected 755" >&2
            |  exit 1
            |fi
            |runner_hash=${'$'}(sha256sum $runnerPath 2>/dev/null | cut -d' ' -f1)
            |if [ "${'$'}runner_hash" != "$runnerSha256" ]; then
            |  echo "e64local: runner digest ${'$'}runner_hash does not match $runnerSha256" >&2
            |  exit 1
            |fi
            |# A syntax check is best effort: images without a PHP CLI keep working,
            |# and the runner cannot run there anyway.
            |if command -v php >/dev/null 2>&1; then
            |  if ! php -l $runnerPath >/dev/null 2>&1; then
            |    echo "e64local: action runner failed php -l" >&2
            |    exit 1
            |  fi
            |fi
            |
            |echo "e64local setup ok"
            |echo "module: $modulePath"
            |echo "runner: $runnerPath (mode 0755, root:root)"
            |echo "token: $tokenPath (mode 0600)"
            |echo "module_sha256: $moduleSha256"
            |echo "runner_sha256: $runnerSha256"
            |echo "actions: disabled (no policy file)"
            |""".trimMargin().replace("__MODULE_STAGE__", MODULE_STAGE)
            .replace("__RUNNER_STAGE__", RUNNER_STAGE)
    }


    companion object {
        const val MODULE_PATH = "/usr/local/www/dev/rest_api_dev.php"
        const val MODULE_DIR = "/usr/local/www/dev"
        const val RUNNER_PATH = "/usr/local/bin/e64local-action-run"
        const val TOKEN_DIR = "/db/e64local"
        const val TOKEN_FILE = "/db/e64local/token"
        const val MODULE_STAGE = "/tmp/e64local-module.php"
        const val RUNNER_STAGE = "/tmp/e64local-action-run.php"
        const val INSTALLER_STAGE = "/tmp/e64local-setup.sh"
    }
}
