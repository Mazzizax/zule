package com.mazzizax.zule.util

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Per-device flags bucketed under EncryptedSharedPreferences.
 *
 * Today this stores a single boolean — "has the user enrolled a passkey on
 * this device?" — consumed by the post-signin enrollment prompt. The value
 * isn't a secret, but encryption costs almost nothing and removes the
 * temptation to add sensitive values later.
 *
 * Device-scoped: never leaves the device, not backed up, not transferred.
 */
object DeviceFlags {

    private const val PREFS_NAME = "zule_device_flags"
    private const val KEY_PASSKEY_ENROLLED = "passkey_enrolled_v1"

    private fun prefs(context: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun isPasskeyEnrolledOnDevice(context: Context): Boolean =
        prefs(context).getBoolean(KEY_PASSKEY_ENROLLED, false)

    fun markPasskeyEnrolled(context: Context) {
        prefs(context).edit().putBoolean(KEY_PASSKEY_ENROLLED, true).apply()
    }

    fun clearPasskeyEnrolled(context: Context) {
        prefs(context).edit().putBoolean(KEY_PASSKEY_ENROLLED, false).apply()
    }
}
