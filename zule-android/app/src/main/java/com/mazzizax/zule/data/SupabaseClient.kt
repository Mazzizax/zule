package com.mazzizax.zule.data

import com.mazzizax.zule.BuildConfig
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.Auth
import io.github.jan.supabase.auth.FlowType
import io.github.jan.supabase.auth.MemorySessionManager
import io.github.jan.supabase.createSupabaseClient
import io.github.jan.supabase.functions.Functions
import io.github.jan.supabase.postgrest.Postgrest
import io.github.jan.supabase.realtime.Realtime

/**
 * Centralized Supabase client factory with zero-persistence session policy.
 *
 * The session lives in memory only. Process death invalidates it. No refresh
 * token on disk for a stolen-but-unlocked device to resume. PKCE flow with
 * the App Links host wired in so email-based OTP callbacks (signup
 * confirmation, magic link, password recovery) can resume directly into the
 * app rather than bouncing through a browser.
 */
object SupabaseProvider {
    val client: SupabaseClient = createSupabaseClient(
        supabaseUrl = BuildConfig.SUPABASE_URL,
        supabaseKey = BuildConfig.SUPABASE_ANON_KEY,
    ) {
        install(Auth) {
            flowType = FlowType.PKCE
            scheme = "https"
            host = BuildConfig.AUTH_HOST
            sessionManager = MemorySessionManager()
            autoLoadFromStorage = false
            autoSaveToStorage = false
        }
        install(Functions)
        install(Postgrest)
        install(Realtime)
    }
}
