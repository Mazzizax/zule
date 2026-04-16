package com.mazzizax.zule.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.mazzizax.zule.MainActivity
import com.mazzizax.zule.R
import com.mazzizax.zule.data.SupabaseProvider
import io.github.jan.supabase.auth.auth
import io.github.jan.supabase.functions.functions
import io.ktor.client.call.body
import io.ktor.http.HttpMethod
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Foreground service for monitoring machine auth requests.
 * Polls machine-auth-pending every 3 seconds when authenticated.
 * Shows notification when a machine requests login approval.
 *
 * The web app doesn't have this — it's a mobile-specific feature
 * from the build guide for background auth request monitoring.
 */
class MachineAuthService : Service() {

    companion object {
        const val ACTION_STOP = "com.mazzizax.zule.STOP_MACHINE_AUTH"
        private const val CHANNEL_ID = "machine_auth_channel"
        private const val NOTIFICATION_ID = 1001
        private const val POLL_INTERVAL_MS = 3000L
    }

    private val scope = CoroutineScope(Dispatchers.IO + Job())

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, buildNotification())
        startPolling()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Machine Auth",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Monitors for machine login requests"
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Zule Auth Active")
            .setContentText("Monitoring for machine login requests")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun startPolling() {
        scope.launch {
            val supabase = SupabaseProvider.client
            while (true) {
                try {
                    val token = supabase.auth.currentAccessTokenOrNull()
                    if (token != null) {
                        val response = supabase.functions.invoke("machine-auth-pending") {
                            method = HttpMethod.Get
                        }
                        val body = response.body<String>()
                        if (body.contains("\"id\"")) {
                            showPendingNotification()
                        }
                    }
                } catch (_: Exception) {
                    // Continue polling
                }
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private fun showPendingNotification() {
        val pendingIntent = PendingIntent.getActivity(
            this, 1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Machine Login Request")
            .setContentText("A machine is requesting login approval")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID + 1, notification)
    }
}
