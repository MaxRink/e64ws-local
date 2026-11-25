package de.mahlkoenig.e64local.storage

import android.content.SharedPreferences
import de.mahlkoenig.e64local.crypto.SecretCipher
import de.mahlkoenig.e64local.setup.OwnerToken

/**
 * Per-device settings. Only three things persist, and only one is a secret:
 *
 * - the endpoint (`host:port`, not a secret),
 * - the pinned certificate SHA-256 (a fingerprint, not a secret),
 * - the owner token and owner password, encrypted with the Keystore key.
 *
 * No value is ever written to a log. Keys are scoped by the endpoint id so a
 * second grinder cannot inherit the first one's token or pin.
 */
class TokenStore(
    private val prefs: SharedPreferences,
    private val cipher: SecretCipher,
) {
    fun activeEndpoint(): String? = prefs.getString(KEY_ACTIVE_ENDPOINT, null)

    fun setActiveEndpoint(endpointId: String) {
        prefs.edit().putString(KEY_ACTIVE_ENDPOINT, endpointId).apply()
    }

    fun clearActiveEndpoint() {
        prefs.edit().remove(KEY_ACTIVE_ENDPOINT).apply()
    }

    fun pinnedCertificate(endpointId: String): String? =
        prefs.getString(key(endpointId, KEY_PIN), null)

    fun pinCertificate(endpointId: String, sha256: String) {
        prefs.edit().putString(key(endpointId, KEY_PIN), sha256.lowercase()).apply()
    }

    fun token(endpointId: String): String? = readSecret(key(endpointId, KEY_TOKEN))

    fun ownerPassword(endpointId: String): String? = readSecret(key(endpointId, KEY_PASSWORD))

    fun save(endpointId: String, token: String, ownerPassword: String) {
        require(OwnerToken.isValid(token)) { "refusing to store a malformed owner token" }
        prefs.edit()
            .putString(key(endpointId, KEY_TOKEN), cipher.encrypt(token))
            .putString(key(endpointId, KEY_PASSWORD), cipher.encrypt(ownerPassword))
            .putString(KEY_ACTIVE_ENDPOINT, endpointId)
            .apply()
    }

    fun updatePassword(endpointId: String, ownerPassword: String) {
        prefs.edit()
            .putString(key(endpointId, KEY_PASSWORD), cipher.encrypt(ownerPassword))
            .apply()
    }

    fun clearToken(endpointId: String) {
        prefs.edit()
            .remove(key(endpointId, KEY_TOKEN))
            .remove(key(endpointId, KEY_PASSWORD))
            .apply()
    }

    /**
     * A hint derived from the *decrypted* token at call time. Nothing
     * token-derived is ever written in clear text.
     */
    fun tokenHint(endpointId: String): String? = token(endpointId)?.let { it.take(4) + "…" }

    private fun readSecret(prefKey: String): String? {
        val payload = prefs.getString(prefKey, null) ?: return null
        return cipher.decrypt(payload)
    }

    private fun key(endpointId: String, suffix: String): String = "device.$endpointId.$suffix"

    companion object {
        const val PREFS = "e64local"
        private const val KEY_ACTIVE_ENDPOINT = "activeEndpoint"
        private const val KEY_PIN = "pin"
        private const val KEY_TOKEN = "token"
        private const val KEY_PASSWORD = "ownerPassword"
    }
}
