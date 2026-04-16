package com.mazzizax.zule.ui.screen.register

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
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
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.ui.platform.LocalContext
import com.mazzizax.zule.ui.screen.login.AuthTextField
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.MetalTextBrush
import com.mazzizax.zule.ui.theme.ZuleColors

@Composable
fun RegisterScreen(
    onNavigateToLogin: () -> Unit,
    onRegisterSuccess: () -> Unit,
    viewModel: RegisterViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(ZuleColors.Background),
        contentAlignment = Alignment.Center,
    ) {
        if (state.success) {
            // Success state: "CHECK YOUR EMAIL" card
            Column(
                modifier = Modifier
                    .width(380.dp)
                    .background(ZuleColors.Surface, RoundedCornerShape(4.dp))
                    .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                    .padding(32.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                // Title
                Text(
                    text = "CHECK YOUR EMAIL",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontWeight = FontWeight.W700,
                        fontSize = 28.sp,
                        letterSpacing = 8.sp,
                        color = ZuleColors.TextPrimary,
                    ),
                )

                Spacer(modifier = Modifier.height(8.dp))

                // Subtitle with email
                Text(
                    text = "We sent a verification link to ${state.email}",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontWeight = FontWeight.W600,
                        fontSize = 11.sp,
                        letterSpacing = 3.sp,
                        color = ZuleColors.TextMuted,
                    ),
                    textAlign = TextAlign.Center,
                )

                Spacer(modifier = Modifier.height(24.dp))

                // Success message
                Text(
                    text = "Click the link in your email to verify your account, then come back to sign in.",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontSize = 14.sp,
                        color = ZuleColors.TextSecondary,
                    ),
                    textAlign = TextAlign.Center,
                )

                Spacer(modifier = Modifier.height(24.dp))

                // Back to Login button
                Button(
                    onClick = onNavigateToLogin,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    shape = RoundedCornerShape(4.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Transparent,
                    ),
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(MetalSurfaceBrush, RoundedCornerShape(4.dp)),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = "Back to Login",
                            style = TextStyle(
                                fontFamily = CormorantGaramond,
                                fontWeight = FontWeight.W500,
                                fontSize = 18.sp,
                                color = ZuleColors.Background,
                            ),
                        )
                    }
                }
            }
        } else {
            // Registration form
            Column(
                modifier = Modifier
                    .width(380.dp)
                    .background(ZuleColors.Surface, RoundedCornerShape(4.dp))
                    .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                    .padding(32.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                // ZULE metallic title
                Row(
                    horizontalArrangement = Arrangement.Center,
                ) {
                    for (letter in listOf("Z", "U", "L", "E")) {
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

                Spacer(modifier = Modifier.height(24.dp))

                // Email field
                AuthTextField(
                    value = state.email,
                    onValueChange = viewModel::onEmailChange,
                    placeholder = "Email",
                    keyboardType = KeyboardType.Email,
                    enabled = !state.isLoading,
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Password field
                AuthTextField(
                    value = state.password,
                    onValueChange = viewModel::onPasswordChange,
                    placeholder = "Password",
                    keyboardType = KeyboardType.Password,
                    isPassword = true,
                    enabled = !state.isLoading,
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Confirm Password field
                AuthTextField(
                    value = state.confirmPassword,
                    onValueChange = viewModel::onConfirmPasswordChange,
                    placeholder = "Confirm Password",
                    keyboardType = KeyboardType.Password,
                    isPassword = true,
                    enabled = !state.isLoading,
                )

                Spacer(modifier = Modifier.height(20.dp))

                // Create Account button
                Button(
                    onClick = { viewModel.signUp(onRegisterSuccess) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    shape = RoundedCornerShape(4.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Transparent,
                    ),
                    enabled = !state.isLoading,
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(MetalSurfaceBrush, RoundedCornerShape(4.dp)),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = if (state.isLoading) "Creating account..." else "Create Account",
                            style = TextStyle(
                                fontFamily = CormorantGaramond,
                                fontWeight = FontWeight.W500,
                                fontSize = 18.sp,
                                color = ZuleColors.Background,
                            ),
                        )
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))

                // Footer: "Already have an account? Sign In"
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) {
                    Text(
                        text = "Already have an account? ",
                        style = TextStyle(
                            fontFamily = CormorantGaramond,
                            fontSize = 14.sp,
                            color = ZuleColors.TextSecondary,
                        ),
                    )
                    Text(
                        text = "Sign In",
                        modifier = Modifier.clickable(onClick = onNavigateToLogin),
                        style = TextStyle(
                            fontFamily = CormorantGaramond,
                            fontSize = 14.sp,
                            color = ZuleColors.Primary,
                        ),
                    )
                }

                // Privacy · Terms links
                Spacer(modifier = Modifier.height(16.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) {
                    val ctx = LocalContext.current
                    Text(
                        text = "Privacy",
                        modifier = Modifier.clickable {
                            CustomTabsIntent.Builder().build()
                                .launchUrl(ctx, Uri.parse("https://zule.mazzizax.net/privacy"))
                        },
                        style = TextStyle(fontSize = 11.sp, color = ZuleColors.TextPrimary.copy(alpha = 0.5f)),
                    )
                    Text(
                        text = " · ",
                        style = TextStyle(fontSize = 11.sp, color = ZuleColors.TextPrimary.copy(alpha = 0.5f)),
                    )
                    Text(
                        text = "Terms",
                        modifier = Modifier.clickable {
                            CustomTabsIntent.Builder().build()
                                .launchUrl(ctx, Uri.parse("https://zule.mazzizax.net/terms"))
                        },
                        style = TextStyle(fontSize = 11.sp, color = ZuleColors.TextPrimary.copy(alpha = 0.5f)),
                    )
                }
            }
        }
    }
}
