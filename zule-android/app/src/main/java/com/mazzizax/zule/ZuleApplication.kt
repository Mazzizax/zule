package com.mazzizax.zule

import android.app.Application
import com.mazzizax.zule.data.SupabaseProvider
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class ZuleApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Touch the Supabase client at app start so the Auth module runs its
        // initialization (sessionStatus transitions out of Initializing)
        // before the first composition observes it.
        SupabaseProvider.client
    }
}
