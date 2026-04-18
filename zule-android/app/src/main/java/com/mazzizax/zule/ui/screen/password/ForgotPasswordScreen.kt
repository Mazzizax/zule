package com.mazzizax.zule.ui.screen.password

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
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.ui.components.LegalFooter
import com.mazzizax.zule.ui.screen.login.AuthTextField
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.ZuleColors
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import androidx.lifecycle.ViewModel
import javax.inject.Inject

/**
 * "Forgot password?" flow — single email field, single button, anti-
 * enumeration message. On submit we call the auth-reset Edge Function
 * (which always returns ok:true) and show the same "check your email"
 * copy regardless of whether the account exists.
 */
@HiltViewModel
class ForgotPasswordViewModel @Inject constructor(
    private val authRepository: AuthRepository,
) : ViewModel() {
    suspend fun requestPasswordReset(email: String) {
        authRepository.requestPasswordReset(email)
    }
}

@Composable
fun ForgotPasswordScreen(
    onBack: () -> Unit,
    viewModel: ForgotPasswordViewModel = hiltViewModel(),
) {
    var email by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var info by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

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
                "RESET PASSWORD",
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
                "Enter your email. If an account exists, we'll send a one-tap link to set a new password.",
                style = TextStyle(
                    fontFamily = CormorantGaramond,
                    fontSize = 13.sp,
                    color = ZuleColors.TextSecondary,
                    textAlign = TextAlign.Center,
                ),
            )
            Spacer(Modifier.height(20.dp))

            AuthTextField(
                value = email,
                onValueChange = { email = it; error = null; info = null },
                placeholder = "Email",
                keyboardType = KeyboardType.Email,
                enabled = !loading,
            )

            if (error != null) {
                Spacer(Modifier.height(12.dp))
                Text(
                    error ?: "",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontSize = 12.sp,
                        color = ZuleColors.Primary,
                    ),
                )
            }
            if (info != null) {
                Spacer(Modifier.height(12.dp))
                Text(
                    info ?: "",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontSize = 12.sp,
                        color = ZuleColors.TextSecondary,
                        textAlign = TextAlign.Center,
                    ),
                )
            }

            Spacer(Modifier.height(20.dp))
            Button(
                onClick = {
                    if (email.isBlank()) {
                        error = "Enter an email."
                        return@Button
                    }
                    loading = true
                    error = null
                    info = null
                    scope.launch {
                        runCatching { viewModel.requestPasswordReset(email.trim()) }
                            .onSuccess {
                                info = "If there's an account for $email, check that inbox for a reset link."
                            }
                            .onFailure { info = "If there's an account for $email, check that inbox for a reset link." }
                        loading = false
                    }
                },
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(4.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
                enabled = !loading,
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(MetalSurfaceBrush, RoundedCornerShape(4.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        if (loading) "Sending..." else "Send reset link",
                        style = TextStyle(
                            fontFamily = CormorantGaramond,
                            fontWeight = FontWeight.W500,
                            fontSize = 18.sp,
                            color = ZuleColors.Background,
                        ),
                    )
                }
            }

            Spacer(Modifier.height(12.dp))
            TextButton(onClick = onBack) { Text("Back") }

            Spacer(Modifier.height(8.dp))
            LegalFooter()
        }
    }
}
