package de.mahlkoenig.e64local.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import de.mahlkoenig.e64local.setup.ModuleProvider
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-GCM encryption with a key that never leaves the Android Keystore.
 *
 * Only ciphertext is written to SharedPreferences. The owner token and the
 * owner password are never stored as plain text, never logged and never
 * exported: the app has no backup and no cloud transport.
 */
class KeystoreCrypto(private val alias: String = DEFAULT_ALIAS) {

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (store.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    fun encrypt(plainText: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val iv = cipher.iv
        val cipherText = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(iv, Base64.NO_WRAP) + ":" + Base64.encodeToString(cipherText, Base64.NO_WRAP)
    }

    fun decrypt(payload: String): String? {
        val parts = payload.split(':')
        if (parts.size != 2) return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                key(),
                GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP)),
            )
            String(cipher.doFinal(Base64.decode(parts[1], Base64.NO_WRAP)), Charsets.UTF_8)
        } catch (exc: Exception) {
            // A rotated key or a wiped Keystore entry: treat as missing, not fatal.
            null
        }
    }

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val DEFAULT_ALIAS = "e64local-owner-secrets"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}

/** Small indirection that keeps [KeystoreCrypto] testable without a device. */
interface SecretCipher {
    fun encrypt(plainText: String): String
    fun decrypt(payload: String): String?
}

class KeystoreCipher(alias: String = KeystoreCrypto.DEFAULT_ALIAS) : SecretCipher {
    private val delegate = KeystoreCrypto(alias)
    override fun encrypt(plainText: String): String = delegate.encrypt(plainText)
    override fun decrypt(payload: String): String? = delegate.decrypt(payload)
}

/** Reads a bundled PHP file from the APK assets. */
class AssetModuleProvider(
    private val context: Context,
    private val assetName: String = "rest_api_dev.php",
) : ModuleProvider {
    override fun read(): ByteArray = context.assets.open(assetName).use { it.readBytes() }
}

/** Injectable time source, so retry hints are testable. */
fun interface Clock {
    fun nowMs(): Long

    companion object {
        val System = Clock { java.lang.System.currentTimeMillis() }
    }
}
