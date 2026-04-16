package com.mazzizax.zule.ui.screen.machineauth

import android.app.Activity
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.MetalTextBrush
import com.mazzizax.zule.ui.theme.SpaceMono
import com.mazzizax.zule.ui.theme.ZuleColors

/**
 * Machine Auth Requests screen.
 *
 * Shows pending machine login sessions. Each session displays:
 *   - Machine name
 *   - Session code (large monospace, matches the code shown on the machine's login screen)
 *   - Approve button (triggers Credential Manager biometric → passkey assertion)
 *   - Deny button
 *
 * Polls machine-auth-pending every 3 seconds.
 */
@Composable
fun AuthRequestsScreen(
    viewModel: AuthRequestsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()
    val activity = LocalContext.current as Activity

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // Title
        Text(
            text = "AUTH REQUESTS",
            style = TextStyle(
                fontFamily = CormorantGaramond,
                fontWeight = FontWeight.W400,
                fontSize = 24.sp,
                letterSpacing = (24 * 0.12).sp,
                brush = MetalTextBrush,
            ),
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Pending machine login requests for your fleet.",
            fontSize = 13.sp,
            color = ZuleColors.TextPrimary.copy(alpha = 0.5f),
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Status message
        if (state.message != null) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                    .background(ZuleColors.PrimaryGlow, RoundedCornerShape(4.dp))
                    .border(1.dp, ZuleColors.PrimaryDim, RoundedCornerShape(4.dp))
                    .padding(12.dp),
            ) {
                Text(
                    text = state.message!!,
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.PrimaryBright,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }

        if (state.isLoading) {
            Box(
                modifier = Modifier.fillMaxWidth().padding(48.dp),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator(color = ZuleColors.Primary, strokeWidth = 2.dp)
            }
        } else if (state.sessions.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(4.dp))
                    .background(ZuleColors.Surface)
                    .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                    .padding(24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "No pending requests",
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.TextMuted,
                )
            }
        } else {
            state.sessions.forEach { session ->
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 12.dp)
                        .clip(RoundedCornerShape(4.dp))
                        .background(ZuleColors.Surface)
                        .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    // Machine name
                    Text(
                        text = session.machineName,
                        fontFamily = CormorantGaramond,
                        fontWeight = FontWeight.W600,
                        fontSize = 11.sp,
                        letterSpacing = 3.sp,
                        color = ZuleColors.PrimaryDim,
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    // Session code — large monospace, matches what the machine's login screen shows
                    Text(
                        text = session.sessionCode,
                        fontFamily = SpaceMono,
                        fontWeight = FontWeight.Bold,
                        fontSize = 32.sp,
                        color = ZuleColors.Primary,
                        textAlign = TextAlign.Center,
                        letterSpacing = 4.sp,
                    )

                    Spacer(modifier = Modifier.height(20.dp))

                    // Approve + Deny buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        // Approve — metallic primary button
                        Button(
                            onClick = { viewModel.approveSession(session.sessionId, activity) },
                            modifier = Modifier.weight(1f).height(48.dp),
                            shape = RoundedCornerShape(4.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
                            enabled = state.isApproving == null,
                        ) {
                            Box(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(MetalSurfaceBrush, RoundedCornerShape(4.dp)),
                                contentAlignment = Alignment.Center,
                            ) {
                                Text(
                                    text = if (state.isApproving == session.sessionId) "Approving..." else "Approve",
                                    fontFamily = CormorantGaramond,
                                    fontWeight = FontWeight.W500,
                                    fontSize = 18.sp,
                                    color = ZuleColors.Background,
                                )
                            }
                        }

                        // Deny — outlined danger button
                        Button(
                            onClick = { viewModel.denySession(session.sessionId) },
                            modifier = Modifier.weight(1f).height(48.dp),
                            shape = RoundedCornerShape(4.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.Transparent,
                                contentColor = ZuleColors.Danger,
                            ),
                            enabled = state.isDenying == null,
                            border = androidx.compose.foundation.BorderStroke(1.dp, ZuleColors.Danger),
                        ) {
                            Text(
                                text = if (state.isDenying == session.sessionId) "Denying..." else "Deny",
                                fontFamily = CormorantGaramond,
                                fontWeight = FontWeight.W500,
                                fontSize = 18.sp,
                                color = ZuleColors.Danger,
                            )
                        }
                    }
                }
            }
        }
    }
}
