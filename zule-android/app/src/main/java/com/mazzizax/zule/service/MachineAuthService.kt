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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

/**
 * Polls machine-auth-pending every 3 seconds while the user is
 * authenticated; surfaces a notification when a pending session appears.
 */
class MachineAuthService : Service() {

    companion object {
        const val ACTION_STOP = "com.mazzizax.zule.STOP_MACHINE_AUTH"
        private const val CHANNEL_ID = "machine_auth_channel"
        // Separate channel for the actual pending-request alert. Channel
        // importance is fixed at creation time and Android ignores a later
        // per-notification setPriority() override on API 26+ — sharing the
        // LOW-importance "still monitoring" channel meant this alert could
        // never make a sound, vibrate, or show heads-up, regardless of the
        // PRIORITY_HIGH set on the notification itself.
        private const val ALERT_CHANNEL_ID = "machine_auth_alert_channel"
        private const val NOTIFICATION_ID = 1001
        private const val ALERT_NOTIFICATION_ID = 1002
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

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Fires when the user swipes Zule away from the Recents task list —
        // i.e., explicit "close the app". Sign the user out so they have to
        // re-authenticate next launch. Brief backgrounding (notification
        // check, switching apps, screen off) does not trigger this — only
        // an explicit task dismissal.
        kotlinx.coroutines.runBlocking {
            runCatching {
                com.mazzizax.zule.data.SupabaseProvider.client.auth.signOut()
            }
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Machine Auth",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Monitors for machine login requests"
            }
        )
        // IMPORTANCE_HIGH is what actually produces sound + heads-up display;
        // PRIORITY_HIGH on the Notification itself does nothing on its own.
        nm.createNotificationChannel(
            NotificationChannel(
                ALERT_CHANNEL_ID,
                "Machine Login Requests",
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "Alerts when a fleet machine requests login approval"
                enableVibration(true)
            }
        )
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

    // Session IDs already alerted on, so we don't re-notify every 3s for the
    // same pending request while it's still waiting.
    private val alertedSessionIds = mutableSetOf<String>()

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
                        // Real shape: {"sessions":[{"session_id":...,"machine_name":...}]}.
                        // The previous body.contains("\"id\"") check could never match this
                        // (no field is named exactly "id"), so no alert ever fired.
                        val sessions = Json.parseToJsonElement(body).jsonObject["sessions"]?.jsonArray
                        val newSessions = sessions?.mapNotNull { it.jsonObject["session_id"]?.toString()?.trim('"') }
                            ?.filter { it !in alertedSessionIds }
                            ?: emptyList()
                        if (newSessions.isNotEmpty()) {
                            alertedSessionIds.addAll(newSessions)
                            showPendingNotification()
                        }
                        // Sessions that are no longer pending (approved/denied/expired)
                        // can be alerted on again if they somehow reappear later.
                        val stillPendingIds = sessions?.mapNotNull { it.jsonObject["session_id"]?.toString()?.trim('"') }?.toSet() ?: emptySet()
                        alertedSessionIds.retainAll(stillPendingIds)
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
        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setContentTitle("Machine Login Request")
            .setContentText("A machine is requesting login approval")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            // Full-screen intent: on a HIGH-importance channel, this is what
            // actually interrupts a locked/idle phone the way an incoming
            // call does, instead of waiting to be noticed in the shade.
            .setFullScreenIntent(pendingIntent, true)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(ALERT_NOTIFICATION_ID, notification)
    }
}
