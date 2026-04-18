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

        // Migration from the pre-MemorySessionManager builds that persisted
        // a full session blob to disk.
        purgeLegacySessionArtifacts()

        // Lazy-initialise so sessionStatus transitions out of Initializing
        // before the first composition observes it (Supabase Kotlin 3.1.x
        // hangs on Initializing if the load step never runs).
        val client = SupabaseProvider.client

        // Counters Samsung's (and similar OEMs') aggressive process retention:
        // swipe-away doesn't always kill the process, so an in-memory session
        // would survive into the next launch. Forcing a signOut on every
        // Application lifecycle guarantees NotAuthenticated on re-entry.
        CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
            runCatching { client.auth.signOut() }
        }
    }

    private fun purgeLegacySessionArtifacts() {
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
