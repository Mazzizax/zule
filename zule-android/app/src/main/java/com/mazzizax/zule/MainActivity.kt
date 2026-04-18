package com.mazzizax.zule

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.mazzizax.zule.data.PlaidLinkHelper
import com.mazzizax.zule.data.SessionManager
import com.mazzizax.zule.data.SupabaseProvider
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.service.MachineAuthService
import com.mazzizax.zule.ui.navigation.ZuleNavGraph
import com.mazzizax.zule.ui.theme.ZuleTheme
import com.mazzizax.zule.util.PrivateLog
import com.mazzizax.zule.util.RecoverySignal
import dagger.hilt.android.AndroidEntryPoint
import io.github.jan.supabase.auth.OtpType
import io.github.jan.supabase.auth.auth
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject lateinit var authRepository: AuthRepository
    @Inject lateinit var sessionManager: SessionManager

    // Must be registered before setContent — ActivityResultLauncher requires it
    lateinit var plaidLinkHelper: PlaidLinkHelper
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // FLAG_SECURE — blocks screenshots, screen recording, AssistantUI captures,
        // screen-sharing for every surface (password fields, biometric prompts,
        // passkey lists, account details).
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        enableEdgeToEdge()

        // Register Plaid Link launcher before setContent
        plaidLinkHelper = PlaidLinkHelper(this)

        // Request notification permission (API 33+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    1001,
                )
            }
        }

        val deepLinkRoute = extractDeepLinkRoute(intent)
        intent?.data?.let { handleAuthDeepLink(it) }

        setContent {
            ZuleTheme {
                ZuleNavGraph(
                    authRepository = authRepository,
                    sessionManager = sessionManager,
                    deepLinkRoute = deepLinkRoute,
                )
            }
        }

        // Start machine auth monitoring
        startForegroundService(Intent(this, MachineAuthService::class.java))
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Warm-start path: deep link arriving while the activity is already alive.
        intent.data?.let { handleAuthDeepLink(it) }
    }

    /**
     * Extracts the Vinzrik attestation deep-link route (zule://auth?callback=...)
     * if present. This is zule-specific and unrelated to the Supabase OTP
     * callback handled below.
     */
    private fun extractDeepLinkRoute(intent: Intent?): String? =
        intent?.data?.let { uri ->
            if (uri.scheme == "zule" && uri.host == "auth") {
                val callback = uri.getQueryParameter("callback") ?: ""
                "auth?callback=${java.net.URLEncoder.encode(callback, "UTF-8")}"
            } else null
        }

    /**
     * Handles App Links arriving at https://<AUTH_HOST>/auth with a
     * token_hash + type query pair (signup confirmation, magic-link, password
     * recovery, invite, email change). Exchanges the token for a session via
     * Supabase's verifyEmailOtp. For recovery links, signals RecoverySignal so
     * the auth VM forces a password-change UX before landing.
     */
    private fun handleAuthDeepLink(uri: Uri) {
        if (uri.scheme != "https") return
        if (uri.path?.startsWith("/auth") != true) return

        val tokenHash = uri.getQueryParameter("token_hash") ?: return
        val typeParam = uri.getQueryParameter("type") ?: "email"
        val type = when (typeParam) {
            "signup" -> OtpType.Email.SIGNUP
            "magiclink" -> OtpType.Email.MAGIC_LINK
            "recovery" -> OtpType.Email.RECOVERY
            "invite" -> OtpType.Email.INVITE
            "email_change" -> OtpType.Email.EMAIL_CHANGE
            else -> OtpType.Email.EMAIL
        }

        if (type == OtpType.Email.RECOVERY) {
            RecoverySignal.pendingRecovery.value = true
        }

        lifecycleScope.launch {
            runCatching {
                SupabaseProvider.client.auth.verifyEmailOtp(type, tokenHash)
            }.onFailure { t ->
                PrivateLog.error("MainActivity", "verifyEmailOtp failed", t)
            }
        }
    }
}
