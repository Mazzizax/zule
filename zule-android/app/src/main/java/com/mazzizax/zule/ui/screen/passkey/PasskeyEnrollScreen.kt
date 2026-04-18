package com.mazzizax.zule.ui.screen.passkey

import android.app.Activity
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import com.mazzizax.zule.data.repository.OrphanedPasskeyException
import com.mazzizax.zule.data.repository.PasskeyRepository
import com.mazzizax.zule.ui.components.LegalFooter
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.ZuleColors
import com.mazzizax.zule.util.DeviceFlags
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.launch
import javax.inject.Inject
import android.content.Context

/**
 * Post-signup / first-time-signin nudge to enrol a passkey on this device.
 * Shown after a fresh Authenticated transition when DeviceFlags says no
 * passkey is enrolled here yet. User can Enable (strict enrol ceremony) or
 * Skip (session-only dismissal; prompt fires again next sign-in).
 */
@HiltViewModel
class PasskeyEnrollViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val passkeyRepository: PasskeyRepository,
) : ViewModel() {
    suspend fun enrollStrict(activity: Activity) {
        passkeyRepository.enrollPasskeyStrict(activity)
        DeviceFlags.markPasskeyEnrolled(appContext)
    }
}

@Composable
fun PasskeyEnrollScreen(
    onEnrolled: () -> Unit,
    onSkip: () -> Unit,
    viewModel: PasskeyEnrollViewModel = hiltViewModel(),
) {
    val activity = LocalContext.current as Activity
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    Box(
        modifier = Modifier.fillMaxSize().background(ZuleColors.Background),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            modifier = Modifier
                .width(380.dp)
                .background(ZuleColors.Surface, RoundedCornerShape(4.dp))
                .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                "FINGERPRINT SIGN-IN",
                style = TextStyle(
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W700,
                    fontSize = 20.sp,
                    letterSpacing = 6.sp,
                    color = ZuleColors.Primary,
                ),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                "Enrol a passkey on this device so you can sign in with a single fingerprint tap. " +
                    "Your password still works as a fallback.",
                style = TextStyle(
                    fontFamily = CormorantGaramond,
                    fontSize = 13.sp,
                    color = ZuleColors.TextSecondary,
                    textAlign = TextAlign.Center,
                ),
            )

            if (error != null) {
                Spacer(Modifier.height(12.dp))
                Text(
                    error ?: "",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontSize = 12.sp,
                        color = ZuleColors.Primary,
                        textAlign = TextAlign.Center,
                    ),
                )
            }

            Spacer(Modifier.height(24.dp))
            Button(
                onClick = {
                    busy = true
                    error = null
                    scope.launch {
                        runCatching { viewModel.enrollStrict(activity) }
                            .onSuccess { onEnrolled() }
                            .onFailure { t ->
                                error = when {
                                    t is OrphanedPasskeyException ->
                                        "Passkey was created on this device but we couldn't save it. Try again."
                                    t.message?.contains("cancel", ignoreCase = true) == true ->
                                        "Cancelled — you can enable it later from Security."
                                    else -> t.message ?: "Couldn't enrol passkey."
                                }
                                busy = false
                            }
                    }
                },
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(4.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
                enabled = !busy,
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(MetalSurfaceBrush, RoundedCornerShape(4.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        if (busy) "Enrolling..." else "Enable fingerprint sign-in",
                        style = TextStyle(
                            fontFamily = CormorantGaramond,
                            fontWeight = FontWeight.W500,
                            fontSize = 18.sp,
                            color = ZuleColors.Background,
                        ),
                    )
                }
            }

            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onSkip, enabled = !busy) { Text("Skip for now") }

            Spacer(Modifier.height(8.dp))
            LegalFooter()
        }
    }
}
