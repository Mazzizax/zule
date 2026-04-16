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
 * Translation of the session security logic from AuthContext.tsx
 *
 * Web app behavior (exact translation):
 *
 *   resetInactivityTimer():
 *     clearTimeout(inactivityTimerRef)
 *     inactivityTimerRef = setTimeout(forceLogout, INACTIVITY_TIMEOUT)
 *
 *   startSessionTimers():
 *     loginTimeRef = Date.now()
 *     resetInactivityTimer()
 *     hardTimeoutRef = setTimeout(forceLogout, HARD_TIMEOUT)
 *     ACTIVITY_EVENTS.forEach(addEventListener(resetInactivityTimer))
 *
 *   stopSessionTimers():
 *     clearTimeout(inactivityTimerRef)
 *     clearTimeout(hardTimeoutRef)
 *     ACTIVITY_EVENTS.forEach(removeEventListener(resetInactivityTimer))
 *
 * Android translation:
 *   - Each timeout is a separate coroutine Job with a single delay() call
 *   - onUserActivity() cancels and restarts the inactivity Job (same as clearTimeout + setTimeout)
 *   - Hard timeout Job is started once at login and never restarted
 *   - Touch events detected via Modifier.pointerInput in SessionTimeoutWrapper
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

    /**
     * Exact translation of resetInactivityTimer() from AuthContext.tsx:
     *   if (!loginTimeRef.current) return;
     *   clearTimeout(inactivityTimerRef);
     *   inactivityTimerRef = setTimeout(() => forceLogout(...), INACTIVITY_TIMEOUT);
     *
     * Called on every touch event via SessionTimeoutWrapper.
     */
    fun onUserActivity() {
        if (hardTimeoutJob == null) return // no active session — matches if (!loginTimeRef.current) return
        inactivityJob?.cancel()
        inactivityJob = scope.launch {
            delay(INACTIVITY_TIMEOUT_MS)
            forceLogout()
        }
    }

    /**
     * Exact translation of startSessionTimers() from AuthContext.tsx:
     *   loginTimeRef = Date.now()
     *   resetInactivityTimer()
     *   hardTimeoutRef = setTimeout(forceLogout, HARD_TIMEOUT)
     *   ACTIVITY_EVENTS.forEach(addEventListener(resetInactivityTimer))
     */
    fun startSessionTimers() {
        _sessionExpired.value = false

        // Start inactivity timer (resets on every touch)
        inactivityJob?.cancel()
        inactivityJob = scope.launch {
            delay(INACTIVITY_TIMEOUT_MS)
            forceLogout()
        }

        // Start hard timeout (never resets)
        hardTimeoutJob?.cancel()
        hardTimeoutJob = scope.launch {
            delay(HARD_TIMEOUT_MS)
            forceLogout()
        }
    }

    /**
     * Exact translation of stopSessionTimers() from AuthContext.tsx:
     *   clearTimeout(inactivityTimerRef)
     *   clearTimeout(hardTimeoutRef)
     *   inactivityTimerRef = null
     *   hardTimeoutRef = null
     *   loginTimeRef = null
     */
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

    /**
     * Exact translation of forceLogout() from AuthContext.tsx:
     *   clearTimeout(inactivityTimerRef)
     *   clearTimeout(hardTimeoutRef)
     *   await supabase.auth.signOut({ scope: 'local' })
     *   setSession(null)
     *   setUser(null)
     */
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
