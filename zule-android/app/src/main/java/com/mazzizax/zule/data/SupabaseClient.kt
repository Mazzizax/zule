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
            // MemorySessionManager has no disk backing; it holds the session
            // in process memory only, so the autoLoad/autoSave flags are
            // effectively no-ops against it. We leave them at their defaults
            // (true) because Supabase 3.1.x uses the load step to transition
            // sessionStatus out of Initializing — flipping it to false keeps
            // the SDK stuck in Initializing forever.
            sessionManager = MemorySessionManager()
        }
        install(Functions)
        install(Postgrest)
        install(Realtime)
    }
}
