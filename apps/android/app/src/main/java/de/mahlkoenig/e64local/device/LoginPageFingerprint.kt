package de.mahlkoenig.e64local.device

/**
 * Reads model, firmware, serial and dev-mode state from the unauthenticated
 * `GET /login.php` page. Mirrors `parse_login_page()` in
 * `tools/e64root/target.py`, without the serial being kept: the setup wizard
 * never displays or stores the raw serial from the login page.
 */
data class LoginPageFingerprint(
    val model: String,
    val firmware: String,
    val title: String,
    val devMode: Boolean,
    val known: Boolean,
) {
    companion object {
        private val TITLE = Regex("<title>\\s*Login\\s+Hemro\\s+([^<]+?)\\s*</title>", RegexOption.IGNORE_CASE)
        private val DEV_OPTION = Regex("<option[^>]+value=[\"']Developer[\"']", RegexOption.IGNORE_CASE)
        private val SUPPORTED_FIRMWARE = listOf("V01.16", "V01.36")

        fun parse(html: String): LoginPageFingerprint {
            val title = TITLE.find(html)?.groupValues?.get(1)?.unescape()?.trim().orEmpty()
            val model = labelValue(html, "MODEL")
            val firmware = labelValue(html, "FW VERSION")
            val devMode = firmware.contains("(development)", ignoreCase = true) ||
                DEV_OPTION.containsMatchIn(html)
            val known = model.isNotEmpty() || firmware.isNotEmpty() ||
                SUPPORTED_FIRMWARE.any { firmware.contains(it) } ||
                title.lowercase().contains("e64") || title.lowercase().contains("e65") ||
                title.lowercase().contains("e80")
            return LoginPageFingerprint(model, firmware, title, devMode, known)
        }

        private fun labelValue(html: String, label: String): String {
            val pattern = Regex(">\\s*${Regex.escape(label)}\\s*</div>\\s*<div[^>]*>\\s*([^<]*?)\\s*</div>", RegexOption.IGNORE_CASE)
            return pattern.find(html)?.groupValues?.get(1)?.unescape()?.trim().orEmpty()
        }

        private fun String.unescape(): String = this
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&nbsp;", " ")
    }
}
