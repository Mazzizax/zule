package com.mazzizax.zule.ui.screen.verifyemail

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.MetalTextBrush
import com.mazzizax.zule.ui.theme.ZuleColors

@Composable
fun VerifyEmailScreen(
    onNavigateToLogin: () -> Unit,
    viewModel: VerifyEmailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(ZuleColors.Background),
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
            // VERIFY metallic title
            Row(
                horizontalArrangement = Arrangement.Center,
            ) {
                for (letter in listOf("V", "E", "R", "I", "F", "Y")) {
                    Text(
                        text = letter,
                        style = TextStyle(
                            fontFamily = CormorantGaramond,
                            fontWeight = FontWeight.W700,
                            fontSize = 28.sp,
                            letterSpacing = 8.sp,
                            brush = MetalTextBrush,
                        ),
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Subtitle
            Text(
                text = "EMAIL VERIFICATION REQUIRED",
                style = TextStyle(
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W600,
                    fontSize = 11.sp,
                    letterSpacing = 3.sp,
                    color = ZuleColors.TextMuted,
                ),
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Success message with bold email
            Text(
                text = buildAnnotatedString {
                    append("A verification link was sent to ")
                    withStyle(SpanStyle(fontWeight = FontWeight.Bold, color = ZuleColors.TextPrimary)) {
                        append(state.userEmail ?: "")
                    }
                    append(". Check your inbox and click the link to continue.")
                },
                style = TextStyle(
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.TextSecondary,
                ),
                textAlign = TextAlign.Center,
            )

            // "Verification email sent" confirmation
            if (state.sent && state.error == null) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Verification email sent. Check your inbox.",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontSize = 14.sp,
                        color = ZuleColors.TextSecondary,
                    ),
                    textAlign = TextAlign.Center,
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Resend Verification Email button
            Button(
                onClick = { viewModel.resendVerification() },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(4.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent,
                ),
                enabled = !state.isSending && state.cooldown <= 0,
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(MetalSurfaceBrush, RoundedCornerShape(4.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = when {
                            state.isSending -> "Sending..."
                            state.cooldown > 0 -> "Resend in ${state.cooldown}s"
                            else -> "Resend Verification Email"
                        },
                        style = TextStyle(
                            fontFamily = CormorantGaramond,
                            fontWeight = FontWeight.W500,
                            fontSize = 18.sp,
                            color = ZuleColors.Background,
                        ),
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Back to Login button (secondary — signs out first)
            OutlinedButton(
                onClick = {
                    viewModel.signOutAndNavigateBack(onNavigateToLogin)
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(4.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, ZuleColors.Border),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = ZuleColors.TextSecondary,
                ),
            ) {
                Text(
                    text = "Back to Login",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontWeight = FontWeight.W500,
                        fontSize = 18.sp,
                        color = ZuleColors.TextSecondary,
                    ),
                )
            }
        }
    }
}
