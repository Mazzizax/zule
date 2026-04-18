package com.mazzizax.zule.ui.screen.password

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.lifecycle.ViewModel
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.ui.components.LegalFooter
import com.mazzizax.zule.ui.screen.login.AuthTextField
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.ZuleColors
import com.mazzizax.zule.util.PwnedPasswordException
import com.mazzizax.zule.util.PwnedPasswords
import com.mazzizax.zule.util.RecoverySignal
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Fires after the user taps a password-reset link in their email. The deep
 * link handler in MainActivity will have exchanged the OTP for a live
 * session with password-change scope. This screen forces a password change
 * (with HIBP breach check + length + confirm) before handing back to the
 * normal app flow.
 */
@HiltViewModel
class PasswordRecoveryViewModel @Inject constructor(
    private val authRepository: AuthRepository,
) : ViewModel() {
    suspend fun updatePassword(newPassword: String) {
        val hibp = PwnedPasswords.check(newPassword)
        if (hibp is PwnedPasswords.Result.Pwned) {
            throw PwnedPasswordException(hibp.breachCount)
        }
        authRepository.updatePassword(newPassword)
        RecoverySignal.pendingRecovery.value = false
    }

    suspend fun cancelRecovery() {
        RecoverySignal.pendingRecovery.value = false
        authRepository.signOut()
    }
}

@Composable
fun PasswordRecoveryScreen(
    onComplete: () -> Unit,
    onCancel: () -> Unit,
    viewModel: PasswordRecoveryViewModel = hiltViewModel(),
) {
    var pw1 by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    val validate = {
        when {
            pw1.length < 12 -> "Password must be at least 12 characters."
            pw1 != pw2 -> "Passwords don't match."
            else -> null
        }
    }

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
                "SET NEW PASSWORD",
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
                "Choose a new password for your Zule account. Minimum 12 characters; known-breached passwords are rejected.",
                style = TextStyle(
                    fontFamily = CormorantGaramond,
                    fontSize = 13.sp,
                    color = ZuleColors.TextSecondary,
                    textAlign = TextAlign.Center,
                ),
            )
            Spacer(Modifier.height(20.dp))

            AuthTextField(
                value = pw1,
                onValueChange = { pw1 = it; error = null },
                placeholder = "New password",
                keyboardType = KeyboardType.Password,
                isPassword = true,
                enabled = !loading,
            )
            Spacer(Modifier.height(12.dp))
            AuthTextField(
                value = pw2,
                onValueChange = { pw2 = it; error = null },
                placeholder = "Confirm password",
                keyboardType = KeyboardType.Password,
                isPassword = true,
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

            Spacer(Modifier.height(20.dp))
            Button(
                onClick = {
                    val v = validate()
                    if (v != null) { error = v; return@Button }
                    loading = true
                    scope.launch {
                        runCatching { viewModel.updatePassword(pw1) }
                            .onSuccess { onComplete() }
                            .onFailure { t ->
                                error = when (t) {
                                    is PwnedPasswordException ->
                                        "Pick a different password — this one appears in ${t.breachCount} known breaches."
                                    else -> t.message ?: "Couldn't update password."
                                }
                                loading = false
                            }
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
                        if (loading) "Updating..." else "Set new password",
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
            TextButton(onClick = {
                scope.launch {
                    runCatching { viewModel.cancelRecovery() }
                    onCancel()
                }
            }) { Text("Cancel") }

            Spacer(Modifier.height(8.dp))
            LegalFooter()
        }
    }
}
