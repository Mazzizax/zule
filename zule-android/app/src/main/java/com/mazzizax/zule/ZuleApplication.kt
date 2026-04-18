package com.mazzizax.zule

import android.app.Application
import android.content.Context
import com.mazzizax.zule.data.SupabaseProvider
import dagger.hilt.android.HiltAndroidApp
import io.github.jan.supabase.auth.auth
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File

@HiltAndroidApp
class ZuleApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // One-shot purge of pre-hardening session artifacts. Older builds used
        // Supabase Kotlin's default SessionManager which wrote the full
        // session (access_token + refresh_token + user record) into the
        // default SharedPreferences. The switch to MemorySessionManager stops
        // new writes but leaves the old file on disk. Strip the Supabase key
        // from the default prefs and delete the legacy zule_passkey file so
        // an upgrading install doesn't keep a stale token around.
        purgeLegacySessionArtifacts()

        // Touch the Supabase client at app start so the Auth module runs its
        // initialization (sessionStatus transitions out of Initializing)
        // before the first composition observes it.
        val client = SupabaseProvider.client

        // Force a signed-out starting state on every fresh Application
        // instance. MemorySessionManager alone guarantees nothing persists
        // across a hard process kill, but Samsung (and other OEMs with
        // aggressive retention) often keep the process alive across
        // swipe-away, which lets the prior in-memory session re-surface
        // when the user relaunches the app. An explicit signOut on
        // Application.onCreate makes every new Application lifecycle — hard
        // kill or OS-reclaim-and-restore — start from NotAuthenticated.
        // Re-auth is a single biometric tap once a passkey is enrolled.
        CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
            runCatching { client.auth.signOut() }
        }
    }

    private fun purgeLegacySessionArtifacts() {
        // Default SharedPreferences file Android creates is
        // "<packageName>_preferences". Pre-hardening Supabase SDK stored the
        // session in it under key "sb-<host-with-dashes>-session".
        val defaultPrefs = getSharedPreferences("${packageName}_preferences", Context.MODE_PRIVATE)
        val supabaseSessionKey = "sb-" +
            BuildConfig.SUPABASE_URL
                .removePrefix("https://")
                .removePrefix("http://")
                .replace('.', '-') +
            "-session"
        if (defaultPrefs.contains(supabaseSessionKey)) {
            defaultPrefs.edit().remove(supabaseSessionKey).apply()
        }

        runCatching {
            val sharedPrefsDir = File(applicationInfo.dataDir, "shared_prefs")
            File(sharedPrefsDir, "zule_passkey.xml").takeIf { it.exists() }?.delete()
        }
    }
}
