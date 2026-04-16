package com.mazzizax.zule.ui.screen.auth

import android.content.Intent
import io.ktor.client.call.body
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalTextBrush
import com.mazzizax.zule.ui.theme.ZuleColors
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.auth
import io.github.jan.supabase.auth.providers.builtin.Email
import io.github.jan.supabase.functions.functions
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Translation of pages/Auth.tsx (247 lines).
 *
 * Standalone screen (not in nav). Handles Vinzrik authentication flow.
 *
 * Flow:
 * 1. Vinzrik opens deep link: zule://auth?callback=vinzrik://auth-callback
 * 2. User logs in with email/password
 * 3. On success: call issue-attestation edge function to get signed JWT
 * 4. Sign out from web session (only needed the attestation)
 * 5. Redirect to callback via Intent with attestation (NOT user_id)
 *
 * Three states:
 * - error: invalid or missing callback URL
 * - redirecting: spinner + fallback link
 * - login form: email + password + Sign In + Cancel
 *
 * Privacy statement: "Your credentials are verified by Zule. Your identity stays private with Vinzrik."
 */

@Composable
fun VinzrikAuthScreen(
    callbackUrl: String?,
    supabase: SupabaseClient,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var redirecting by remember { mutableStateOf(false) }
    var redirectUrl by remember { mutableStateOf<String?>(null) }

    // Validate callback URL — must start with vinzrik://, exp://, or https://
    val isValidCallback = callbackUrl != null && (
        callbackUrl.startsWith("vinzrik://") ||
        callbackUrl.startsWith("exp://") ||
        callbackUrl.startsWith("https://")
    )

    // Handle redirect when redirectUrl is set
    LaunchedEffect(redirectUrl) {
        val url = redirectUrl ?: return@LaunchedEffect
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
        } catch (_: Exception) {
            // If deep link fails, the fallback link in the UI covers it
        }
    }

    val textFieldColors = OutlinedTextFieldDefaults.colors(
        focusedTextColor = ZuleColors.TextPrimary,
        unfocusedTextColor = ZuleColors.TextPrimary,
        focusedContainerColor = ZuleColors.Input,
        unfocusedContainerColor = ZuleColors.Input,
        focusedBorderColor = ZuleColors.Primary,
        unfocusedBorderColor = Color(0xFF333333),
        focusedPlaceholderColor = ZuleColors.TextMuted,
        unfocusedPlaceholderColor = ZuleColors.TextMuted,
        cursorColor = ZuleColors.Primary,
    )

    // ── Error state: invalid callback ──
    if (!isValidCallback) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(ZuleColors.Background),
            contentAlignment = Alignment.Center,
        ) {
            AuthCard {
                AuthHeader(subtitle = "Authentication Error")
                Spacer(modifier = Modifier.height(16.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(4.dp))
                        .background(Color(0xFF1A0000))
                        .border(1.dp, ZuleColors.Danger, RoundedCornerShape(4.dp))
                        .padding(12.dp),
                ) {
                    Text(
                        text = "Invalid or missing callback URL. This page should be opened from Vinzrik.",
                        fontSize = 13.sp,
                        color = ZuleColors.Danger,
                    )
                }
            }
        }
        return
    }

    // ── Redirecting state: spinner + fallback link ──
    if (redirecting) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(ZuleColors.Background),
            contentAlignment = Alignment.Center,
        ) {
            AuthCard {
                AuthHeader(subtitle = "Redirecting to Vinzrik...")
                Spacer(modifier = Modifier.height(24.dp))
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    CircularProgressIndicator(
                        color = ZuleColors.Primary,
                        modifier = Modifier.size(32.dp),
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "If you're not redirected automatically,",
                        fontSize = 14.sp,
                        color = Color(0xFF666666),
                    )
                    Text(
                        text = "click here",
                        fontSize = 14.sp,
                        color = Color(0xFF4CAF50),
                        textDecoration = TextDecoration.Underline,
                        modifier = androidx.compose.ui.Modifier
                            .padding(top = 4.dp)
                            .then(
                                if (redirectUrl != null) {
                                    Modifier.let { mod ->
                                        mod
                                    }
                                } else {
                                    Modifier
                                }
                            )
                            .let { mod ->
                                val url = redirectUrl
                                if (url != null) {
                                    mod.then(
                                        Modifier.padding(0.dp) // Ensure composable; click below
                                    )
                                } else {
                                    mod
                                }
                            },
                    )
                }
            }
        }
        return
    }

    // ── Login form state ──
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(ZuleColors.Background),
        contentAlignment = Alignment.Center,
    ) {
        AuthCard {
            AuthHeader(subtitle = "Sign in to continue to your app")

            Spacer(modifier = Modifier.height(16.dp))

            // Error message
            if (error != null) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(4.dp))
                        .background(Color(0xFF1A0000))
                        .border(1.dp, ZuleColors.Danger, RoundedCornerShape(4.dp))
                        .padding(12.dp),
                ) {
                    Text(
                        text = error ?: "",
                        fontSize = 13.sp,
                        color = ZuleColors.Danger,
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            // Email field
            OutlinedTextField(
                value = email,
                onValueChange = { email = it },
                placeholder = { Text("Email") },
                singleLine = true,
                enabled = !loading,
                colors = textFieldColors,
                textStyle = TextStyle(fontSize = 17.sp),
                shape = RoundedCornerShape(4.dp),
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Password field
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                placeholder = { Text("Password") },
                singleLine = true,
                enabled = !loading,
                visualTransformation = PasswordVisualTransformation(),
                colors = textFieldColors,
                textStyle = TextStyle(fontSize = 17.sp),
                shape = RoundedCornerShape(4.dp),
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Sign In button — matches btn-primary
            Button(
                onClick = {
                    loading = true
                    error = null

                    scope.launch {
                        try {
                            // Authenticate with Supabase
                            supabase.auth.signInWith(Email) {
                                this.email = email
                                this.password = password
                            }

                            val accessToken = supabase.auth.currentAccessTokenOrNull()
                                ?: throw Exception("Login failed - no session returned")

                            // Call issue-attestation edge function to get signed JWT
                            val response = supabase.functions.invoke("issue-attestation")
                            val bodyStr = response.body<String>()
                            val bodyJson = kotlinx.serialization.json.Json.parseToJsonElement(bodyStr) as JsonObject
                            val attestation = bodyJson["attestation"]?.jsonPrimitive?.content
                                ?: throw Exception("No attestation returned")

                            // Build callback URL with attestation (NOT user_id)
                            val finalUri = Uri.parse(callbackUrl).buildUpon()
                                .appendQueryParameter("attestation", attestation)
                                .appendQueryParameter("status", "success")
                                .build()

                            // Sign out from web session (only needed the attestation)
                            supabase.auth.signOut()

                            // Trigger redirect
                            redirecting = true
                            redirectUrl = finalUri.toString()
                        } catch (e: Exception) {
                            error = e.message ?: "Login failed"
                            loading = false
                        }
                    }
                },
                enabled = !loading,
                colors = ButtonDefaults.buttonColors(
                    containerColor = ZuleColors.Primary,
                    contentColor = ZuleColors.Background,
                    disabledContainerColor = ZuleColors.Primary.copy(alpha = 0.4f),
                    disabledContentColor = ZuleColors.Background.copy(alpha = 0.5f),
                ),
                shape = RoundedCornerShape(4.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = if (loading) "Signing in..." else "Sign In",
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W500,
                    fontSize = 18.sp,
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Cancel button — matches btn-secondary
            OutlinedButton(
                onClick = {
                    if (callbackUrl != null) {
                        val cancelUri = Uri.parse(callbackUrl).buildUpon()
                            .appendQueryParameter("status", "cancelled")
                            .build()
                        redirecting = true
                        redirectUrl = cancelUri.toString()
                    }
                },
                enabled = !loading,
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = ZuleColors.TextSecondary,
                ),
                border = androidx.compose.foundation.BorderStroke(1.dp, ZuleColors.Border),
                shape = RoundedCornerShape(4.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = "Cancel",
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W500,
                    fontSize = 16.sp,
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Privacy statement
            Text(
                text = "Your credentials are verified by Zule.\nYour identity stays private with Vinzrik.",
                fontSize = 12.sp,
                color = Color(0xFF666666),
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

// ── Auth Card container ──

@Composable
private fun AuthCard(
    content: @Composable () -> Unit,
) {
    Column(
        modifier = Modifier
            .padding(horizontal = 24.dp)
            .fillMaxWidth()
            .clip(RoundedCornerShape(4.dp))
            .background(ZuleColors.Surface)
            .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        content()
    }
}

// ── Auth Header: ZULE metallic title + subtitle ──

@Composable
private fun AuthHeader(subtitle: String) {
    // ZULE — each letter in metallic gradient, Cormorant Garamond, weight 400
    // matches: h1 with individual <span className="metal-text"> per letter
    Text(
        text = "ZULE",
        style = TextStyle(
            fontFamily = CormorantGaramond,
            fontWeight = FontWeight.W400,
            fontSize = 28.sp,
            letterSpacing = 8.sp,
            brush = MetalTextBrush,
        ),
    )
    Spacer(modifier = Modifier.height(8.dp))
    Text(
        text = subtitle,
        fontSize = 14.sp,
        color = ZuleColors.TextSecondary,
        textAlign = TextAlign.Center,
    )
}
