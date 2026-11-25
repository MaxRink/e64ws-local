package de.mahlkoenig.e64local.storage

import de.mahlkoenig.e64local.crypto.SecretCipher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TokenStoreTest {

    /** Reverses the text; enough to prove the store never writes plain text. */
    private class FakeCipher : SecretCipher {
        override fun encrypt(plainText: String): String = PREFIX + plainText.reversed()
        override fun decrypt(payload: String): String? =
            payload.removePrefix(PREFIX).reversed().takeIf { payload.startsWith(PREFIX) }

        companion object {
            const val PREFIX = "aes-gcm:"
        }
    }

    private class FakePreferences : android.content.SharedPreferences {
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

    private val token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    private val prefs = FakePreferences()
    private val store = TokenStore(prefs, FakeCipher())

    @Test
    fun `token is stored encrypted, never as plain text`() {
        store.save("192.168.1.100", token, "owner-password")
        assertEquals(token, store.token("192.168.1.100"))
        assertEquals("owner-password", store.ownerPassword("192.168.1.100"))
        val persisted = prefs.map.values.filterIsInstance<String>().joinToString("|")
        assertFalse("plain token leaked into preferences", persisted.contains(token))
        assertFalse("plain password leaked into preferences", persisted.contains("owner-password"))
        assertTrue(persisted.contains("aes-gcm:"))
    }

    @Test
    fun `secrets are scoped per device`() {
        store.save("192.168.1.100", token, "")
        assertNull(store.token("192.168.1.101"))
        assertEquals("192.168.1.100", store.activeEndpoint())
    }

    @Test
    fun `malformed tokens are refused`() {
        assertTrue(runCatching { store.save("h", "short", "") }.isFailure)
        assertTrue(runCatching { store.save("h", token.uppercase(), "") }.isFailure)
    }

    @Test
    fun `clearing removes the token and password but keeps the pin`() {
        store.pinCertificate("h", "AABB")
        store.save("h", token, "pw")
        store.clearToken("h")
        assertNull(store.token("h"))
        assertNull(store.ownerPassword("h"))
        assertEquals("aabb", store.pinnedCertificate("h"))
    }

    @Test
    fun `the only token-derived value exposed is a short hint`() {
        store.save("h", token, "")
        assertEquals("0123…", store.tokenHint("h"))
        assertFalse(store.tokenHint("h")!!.contains(token))
        // The hint is derived at call time; nothing token-derived is at rest.
        assertTrue(prefs.map.values.filterIsInstance<String>().none { it.contains("0123") })
    }

    @Test
    fun `an undecryptable value is treated as missing`() {
        prefs.map["device.h.token"] = "not-encrypted"
        assertNull(store.token("h"))
    }
}
