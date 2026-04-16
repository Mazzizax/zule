package com.mazzizax.zule.data

import com.mazzizax.zule.BuildConfig
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.Auth
import io.github.jan.supabase.createSupabaseClient
import io.github.jan.supabase.functions.Functions
import io.github.jan.supabase.postgrest.Postgrest
import io.github.jan.supabase.realtime.Realtime

/**
 * Translation of lib/supabase.ts
 *
 * Creates the Supabase client with Auth, Functions, Postgrest, Realtime.
 * The web app uses sessionStorage for per-tab isolation — on Android,
 * the Supabase Kotlin SDK handles session persistence internally.
 * EncryptedSharedPreferences is used for secure token storage (see SessionManager).
 */
object SupabaseProvider {
    val client: SupabaseClient = createSupabaseClient(
        supabaseUrl = BuildConfig.SUPABASE_URL,
        supabaseKey = BuildConfig.SUPABASE_ANON_KEY,
    ) {
        install(Auth)
        install(Functions)
        install(Postgrest)
        install(Realtime)
    }
}
