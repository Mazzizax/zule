package com.mazzizax.zule.ui.screen.login

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.ui.res.painterResource
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import android.app.Activity
import androidx.compose.ui.platform.LocalContext
import com.mazzizax.zule.ui.components.HintActionRow
import com.mazzizax.zule.ui.components.LegalFooter
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.MetalTextBrush
import com.mazzizax.zule.ui.theme.ZuleColors

@Composable
fun LoginScreen(
    onNavigateToRegister: () -> Unit,
    onNavigateToForgotPassword: () -> Unit,
    onLoginSuccess: () -> Unit,
    onHintAction: (com.mazzizax.zule.util.RecoveryHint) -> Unit = {},
    viewModel: LoginViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()
    val activity = LocalContext.current as Activity

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

            Spacer(modifier = Modifier.height(8.dp))

            // Subtitle
            Text(
                text = "SIGN IN TO YOUR ACCOUNT",
                style = TextStyle(
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W600,
                    fontSize = 11.sp,
                    letterSpacing = 3.sp,
                    color = ZuleColors.TextMuted,
                ),
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Passkey button — matches .btn-passkey CSS:
            //   background: transparent, border: 1px solid var(--zule-gold-dim)
            //   font: Cormorant Garamond 18px weight 500
            //   color: var(--text-primary)
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .border(1.dp, ZuleColors.PrimaryDim, RoundedCornerShape(4.dp))
                    .clickable(enabled = !state.isLoading && !state.passkeyLoading) {
                        viewModel.signInWithPasskey(activity, onLoginSuccess)
                    },
                contentAlignment = Alignment.Center,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center,
                ) {
                    if (!state.passkeyLoading) {
                        Icon(
                            painter = painterResource(com.mazzizax.zule.R.drawable.ic_nav_security),
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                            tint = ZuleColors.TextPrimary,
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                    }
                    Text(
                        text = if (state.passkeyLoading) "Authenticating..." else "Sign in with Passkey",
                        style = TextStyle(
                            fontFamily = CormorantGaramond,
                            fontWeight = FontWeight.W500,
                            fontSize = 18.sp,
                        color = ZuleColors.TextPrimary,
                    ),
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Divider: "or use email"
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                HorizontalDivider(
                    modifier = Modifier.weight(1f),
                    color = ZuleColors.Border,
                )
                Text(
                    text = "or use email",
                    modifier = Modifier.padding(horizontal = 12.dp),
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontSize = 12.sp,
                        color = ZuleColors.TextMuted,
                    ),
                )
                HorizontalDivider(
                    modifier = Modifier.weight(1f),
                    color = ZuleColors.Border,
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

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

            Spacer(modifier = Modifier.height(20.dp))

            // Sign In button
            Button(
                onClick = { viewModel.signIn(onLoginSuccess) },
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
                        text = if (state.isLoading) "Signing in..." else "Sign In",
                        style = TextStyle(
                            fontFamily = CormorantGaramond,
                            fontWeight = FontWeight.W500,
                            fontSize = 18.sp,
                            color = ZuleColors.Background,
                        ),
                    )
                }
            }

            // Error banner + actionable hint row
            if (state.error != null) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = state.error ?: "",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontSize = 13.sp,
                        color = ZuleColors.Primary,
                        textAlign = TextAlign.Center,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
                HintActionRow(
                    hint = state.errorHint,
                    supportRef = state.errorSupportRef,
                    onAction = onHintAction,
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Forgot password?
            Text(
                text = "Forgot password?",
                modifier = Modifier.clickable(onClick = onNavigateToForgotPassword),
                style = TextStyle(
                    fontFamily = CormorantGaramond,
                    fontSize = 13.sp,
                    color = ZuleColors.Primary,
                ),
            )

            Spacer(modifier = Modifier.height(20.dp))

            // Footer: "Don't have an account? Create Account"
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = "Don't have an account? ",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontSize = 14.sp,
                        color = ZuleColors.TextSecondary,
                    ),
                )
                Text(
                    text = "Create Account",
                    modifier = Modifier.clickable(onClick = onNavigateToRegister),
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontSize = 14.sp,
                        color = ZuleColors.Primary,
                    ),
                )
            }

            Spacer(modifier = Modifier.height(8.dp))
            LegalFooter()
        }
    }
}

@Composable
internal fun AuthTextField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    keyboardType: KeyboardType = KeyboardType.Text,
    isPassword: Boolean = false,
    enabled: Boolean = true,
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isFocused by interactionSource.collectIsFocusedAsState()
    val borderColor = if (isFocused) ZuleColors.Primary else ZuleColors.Border

    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = Modifier
            .fillMaxWidth()
            .height(48.dp)
            .background(ZuleColors.Input, RoundedCornerShape(4.dp))
            .border(1.dp, borderColor, RoundedCornerShape(4.dp))
            .padding(horizontal = 14.dp),
        enabled = enabled,
        textStyle = TextStyle(
            fontFamily = CormorantGaramond,
            fontSize = 17.sp,
            color = ZuleColors.TextPrimary,
        ),
        singleLine = true,
        interactionSource = interactionSource,
        cursorBrush = SolidColor(ZuleColors.Primary),
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        visualTransformation = if (isPassword) PasswordVisualTransformation() else VisualTransformation.None,
        decorationBox = { innerTextField ->
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.CenterStart,
            ) {
                if (value.isEmpty()) {
                    Text(
                        text = placeholder,
                        style = TextStyle(
                            fontFamily = CormorantGaramond,
                            fontSize = 17.sp,
                            color = ZuleColors.TextMuted,
                        ),
                    )
                }
                innerTextField()
            }
        },
    )
}
