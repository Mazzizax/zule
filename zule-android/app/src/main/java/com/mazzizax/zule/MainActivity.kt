package com.mazzizax.zule

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.mazzizax.zule.data.PlaidLinkHelper
import com.mazzizax.zule.data.SessionManager
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.service.MachineAuthService
import com.mazzizax.zule.ui.navigation.ZuleNavGraph
import com.mazzizax.zule.ui.theme.ZuleTheme
import dagger.hilt.android.AndroidEntryPoint
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

        // Check for deep link: zule://auth?callback=...
        val deepLinkRoute = intent?.data?.let { uri ->
            if (uri.scheme == "zule" && uri.host == "auth") {
                val callback = uri.getQueryParameter("callback") ?: ""
                "auth?callback=${java.net.URLEncoder.encode(callback, "UTF-8")}"
            } else null
        }

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
}
