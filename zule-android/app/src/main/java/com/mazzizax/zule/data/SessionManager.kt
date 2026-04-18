package com.mazzizax.zule.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.github.jan.supabase.auth.Auth
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * 8-min inactivity + 25-min hard session timers. Inactivity resets on
 * every UI touch (fed from SessionTimeoutWrapper's pointerInput). Hard
 * cap is absolute from sign-in.
 */
class SessionManager(
    context: Context,
    private val auth: Auth,
) {
    companion object {
        private const val INACTIVITY_TIMEOUT_MS = 8 * 60 * 1000L  // 8 minutes
        private const val HARD_TIMEOUT_MS = 25 * 60 * 1000L       // 25 minutes
        private const val PREFS_NAME = "zule_session"
    }

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    val encryptedPrefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    private var inactivityJob: Job? = null
    private var hardTimeoutJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.Main)

    private val _sessionExpired = MutableStateFlow(false)
    val sessionExpired: StateFlow<Boolean> = _sessionExpired.asStateFlow()

    fun onUserActivity() {
        if (hardTimeoutJob == null) return
        inactivityJob?.cancel()
        inactivityJob = scope.launch {
            delay(INACTIVITY_TIMEOUT_MS)
            forceLogout()
        }
    }

    fun startSessionTimers() {
        _sessionExpired.value = false

        inactivityJob?.cancel()
        inactivityJob = scope.launch {
            delay(INACTIVITY_TIMEOUT_MS)
            forceLogout()
        }

        hardTimeoutJob?.cancel()
        hardTimeoutJob = scope.launch {
            delay(HARD_TIMEOUT_MS)
            forceLogout()
        }
    }

    fun stopSessionTimers() {
        inactivityJob?.cancel()
        inactivityJob = null
        hardTimeoutJob?.cancel()
        hardTimeoutJob = null
    }

    fun clearSession() {
        stopSessionTimers()
        encryptedPrefs.edit().clear().apply()
        _sessionExpired.value = false
    }

    private fun forceLogout() {
        inactivityJob?.cancel()
        inactivityJob = null
        hardTimeoutJob?.cancel()
        hardTimeoutJob = null
        _sessionExpired.value = true
        scope.launch {
            try {
                auth.signOut()
            } catch (_: Exception) {
                // signOut may fail if already expired — session is still terminated
            }
        }
    }
}
