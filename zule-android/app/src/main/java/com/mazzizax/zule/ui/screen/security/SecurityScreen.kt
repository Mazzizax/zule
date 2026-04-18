package com.mazzizax.zule.ui.screen.security

import android.app.Activity
import androidx.compose.foundation.background
import androidx.compose.ui.platform.LocalContext
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.mazzizax.zule.domain.model.Passkey
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.ZuleColors

/**
 * Translation of Security.tsx (363 lines).
 *
 * Four stacked cards:
 *   1. Passkeys: description, passkey list (key icon, device name, metadata, red Remove), Register button
 *   2. Change Password: new + confirm fields (8 char min), Update Password button
 *   3. Sessions: description, Sign Out All Devices, divider, Delete Account (two sequential confirms)
 *   4. Account Information: email, created date, last sign-in
 *
 * Web CSS references:
 *   .passkey-item: flex, justify-content space-between, align-items center, padding 12px,
 *     border 1px var(--border), border-radius 4px, margin-bottom 8px
 *   .passkey-name: font-size 15px, color var(--text-primary), display flex, align-items center, gap 8px
 *   .passkey-meta: font-size 12px, color var(--text-muted)
 *   .btn-danger-small: font-size 12px, color var(--danger), border 1px var(--danger)
 */

private fun formatDate(dateStr: String?): String {
    if (dateStr == null) return "Never"
    return try {
        val instant = java.time.Instant.parse(dateStr)
        val zoned = instant.atZone(java.time.ZoneId.systemDefault())
        val formatter = java.time.format.DateTimeFormatter.ofPattern("MMM d, yyyy hh:mm a")
        zoned.format(formatter)
    } catch (_: Exception) {
        dateStr
    }
}

private fun formatDateShort(dateStr: String?): String {
    if (dateStr == null) return "N/A"
    return try {
        val instant = java.time.Instant.parse(dateStr)
        val localDate = instant.atZone(java.time.ZoneId.systemDefault()).toLocalDate()
        val formatter = java.time.format.DateTimeFormatter.ofPattern("M/d/yyyy")
        localDate.format(formatter)
    } catch (_: Exception) {
        dateStr
    }
}

@Composable
fun SecurityScreen(
    onSignOut: () -> Unit,
    viewModel: SecurityViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()
    val activity = LocalContext.current as Activity

    // Delete account confirmation dialog state
    // 0 = hidden, 1 = first confirm, 2 = second confirm
    var deleteConfirmStep by remember { mutableIntStateOf(0) }

    // Sign out all devices confirmation
    var showSignOutConfirm by remember { mutableStateOf(false) }

    // Delete passkey confirmation
    var passkeyToDelete by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // Success message
        if (state.success != null) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                    .background(
                        ZuleColors.PrimaryGlow,
                        RoundedCornerShape(4.dp),
                    )
                    .border(1.dp, ZuleColors.PrimaryDim, RoundedCornerShape(4.dp))
                    .padding(12.dp),
            ) {
                Text(
                    text = state.success!!,
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.PrimaryBright,
                )
            }
        }

        // ── Card 1: Passkeys ──
        SecurityCard {
            CardSectionTitle("Passkeys")
            Text(
                text = "Use your device's biometrics (fingerprint or face) to sign in without a password.",
                fontFamily = CormorantGaramond,
                fontSize = 13.sp,
                color = ZuleColors.TextSecondary,
                lineHeight = 18.sp,
            )

            Spacer(modifier = Modifier.height(16.dp))

            if (state.isLoadingPasskeys) {
                Text(
                    text = "Loading passkeys...",
                    fontFamily = CormorantGaramond,
                    fontSize = 13.sp,
                    color = ZuleColors.TextMuted,
                )
            } else if (state.passkeys.isNotEmpty()) {
                state.passkeys.forEach { passkey ->
                    PasskeyItem(
                        passkey = passkey,
                        isDeleting = state.deletingPasskeyId == passkey.id,
                        onRemove = { passkeyToDelete = passkey.id },
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                }
            } else {
                Text(
                    text = "No passkeys registered yet.",
                    fontFamily = CormorantGaramond,
                    fontSize = 13.sp,
                    color = ZuleColors.TextMuted,
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            SecurityPrimaryButton(
                text = if (state.isRegisteringPasskey) "Registering..." else "Register New Passkey",
                enabled = !state.isRegisteringPasskey,
                onClick = { viewModel.registerPasskey(activity) },
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // ── Card 2: Change Password ──
        SecurityCard {
            CardSectionTitle("Change Password")

            Spacer(modifier = Modifier.height(4.dp))

            // New Password
            FormLabel("New Password")
            Spacer(modifier = Modifier.height(8.dp))
            PasswordField(
                value = state.newPassword,
                onValueChange = viewModel::onNewPasswordChange,
                placeholder = "Enter new password",
            )

            Spacer(modifier = Modifier.height(20.dp))

            // Confirm Password
            FormLabel("Confirm New Password")
            Spacer(modifier = Modifier.height(8.dp))
            PasswordField(
                value = state.confirmPassword,
                onValueChange = viewModel::onConfirmPasswordChange,
                placeholder = "Confirm new password",
            )

            Spacer(modifier = Modifier.height(20.dp))

            SecurityPrimaryButton(
                text = if (state.isChangingPassword) "Updating..." else "Update Password",
                enabled = !state.isChangingPassword,
                onClick = { viewModel.updatePassword() },
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // ── Card 3: Sessions ──
        SecurityCard {
            CardSectionTitle("Sessions")
            Text(
                text = "If you suspect unauthorized access to your account, sign out of all devices and change your password.",
                fontFamily = CormorantGaramond,
                fontSize = 13.sp,
                color = ZuleColors.TextSecondary,
                lineHeight = 18.sp,
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Sign Out All Devices button
            SecondaryButton(
                text = "Sign Out All Devices",
                onClick = { showSignOutConfirm = true },
            )

            // Divider
            Spacer(modifier = Modifier.height(20.dp))
            HorizontalDivider(thickness = 1.dp, color = ZuleColors.Border)
            Spacer(modifier = Modifier.height(16.dp))

            // Delete Account section
            Text(
                text = "Warning: this will delete your account and all personal information.",
                fontFamily = CormorantGaramond,
                fontSize = 13.sp,
                color = ZuleColors.TextSecondary,
                lineHeight = 18.sp,
            )
            Spacer(modifier = Modifier.height(12.dp))
            SecondaryButton(
                text = if (state.isDeletingAccount) "Deleting..." else "Delete Account",
                enabled = !state.isDeletingAccount,
                onClick = { deleteConfirmStep = 1 },
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // ── Card 4: Account Information ──
        SecurityCard {
            CardSectionTitle("Account Information")
            InfoRow(label = "Email:", value = state.email ?: "")
            InfoRow(
                label = "Account Created:",
                value = formatDateShort(state.createdAt),
            )
            InfoRow(
                label = "Last Sign In:",
                value = if (state.lastSignInAt != null) formatDate(state.lastSignInAt) else "N/A",
                showDivider = false,
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        com.mazzizax.zule.ui.components.LegalFooter()

        Spacer(modifier = Modifier.height(16.dp))
    }

    // ── Dialogs ──

    // Delete Account: first confirmation
    if (deleteConfirmStep == 1) {
        AlertDialog(
            onDismissRequest = { deleteConfirmStep = 0 },
            title = {
                Text(
                    text = "Delete Account",
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W600,
                    fontSize = 18.sp,
                    color = ZuleColors.TextPrimary,
                )
            },
            text = {
                Text(
                    text = "This will permanently delete your Zule account and all associated data. This cannot be undone. Continue?",
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.TextSecondary,
                )
            },
            confirmButton = {
                TextButton(onClick = { deleteConfirmStep = 2 }) {
                    Text(
                        text = "Continue",
                        fontFamily = CormorantGaramond,
                        color = ZuleColors.Danger,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteConfirmStep = 0 }) {
                    Text(
                        text = "Cancel",
                        fontFamily = CormorantGaramond,
                        color = ZuleColors.TextSecondary,
                    )
                }
            },
            containerColor = ZuleColors.Surface,
        )
    }

    // Delete Account: second confirmation
    if (deleteConfirmStep == 2) {
        AlertDialog(
            onDismissRequest = { deleteConfirmStep = 0 },
            title = {
                Text(
                    text = "Are you absolutely sure?",
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W600,
                    fontSize = 18.sp,
                    color = ZuleColors.TextPrimary,
                )
            },
            text = {
                Text(
                    text = "Your identity data will be permanently destroyed.",
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.TextSecondary,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    deleteConfirmStep = 0
                    viewModel.deleteAccount(onComplete = onSignOut)
                }) {
                    Text(
                        text = "Delete My Account",
                        fontFamily = CormorantGaramond,
                        color = ZuleColors.Danger,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteConfirmStep = 0 }) {
                    Text(
                        text = "Cancel",
                        fontFamily = CormorantGaramond,
                        color = ZuleColors.TextSecondary,
                    )
                }
            },
            containerColor = ZuleColors.Surface,
        )
    }

    // Sign Out All Devices confirmation
    if (showSignOutConfirm) {
        AlertDialog(
            onDismissRequest = { showSignOutConfirm = false },
            title = {
                Text(
                    text = "Sign Out All Devices",
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W600,
                    fontSize = 18.sp,
                    color = ZuleColors.TextPrimary,
                )
            },
            text = {
                Text(
                    text = "This will sign you out of all devices including this one. Continue?",
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.TextSecondary,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showSignOutConfirm = false
                    viewModel.signOutAllDevices(onComplete = onSignOut)
                }) {
                    Text(
                        text = "Sign Out All",
                        fontFamily = CormorantGaramond,
                        color = ZuleColors.Primary,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showSignOutConfirm = false }) {
                    Text(
                        text = "Cancel",
                        fontFamily = CormorantGaramond,
                        color = ZuleColors.TextSecondary,
                    )
                }
            },
            containerColor = ZuleColors.Surface,
        )
    }

    // Delete Passkey confirmation
    if (passkeyToDelete != null) {
        AlertDialog(
            onDismissRequest = { passkeyToDelete = null },
            title = {
                Text(
                    text = "Remove Passkey",
                    fontFamily = CormorantGaramond,
                    fontWeight = FontWeight.W600,
                    fontSize = 18.sp,
                    color = ZuleColors.TextPrimary,
                )
            },
            text = {
                Text(
                    text = "Are you sure you want to remove this passkey?",
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.TextSecondary,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val id = passkeyToDelete!!
                    passkeyToDelete = null
                    viewModel.deletePasskey(id)
                }) {
                    Text(
                        text = "Remove",
                        fontFamily = CormorantGaramond,
                        color = ZuleColors.Danger,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { passkeyToDelete = null }) {
                    Text(
                        text = "Cancel",
                        fontFamily = CormorantGaramond,
                        color = ZuleColors.TextSecondary,
                    )
                }
            },
            containerColor = ZuleColors.Surface,
        )
    }
}

// ── Reusable Components ──

@Composable
private fun SecurityCard(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(ZuleColors.Surface, RoundedCornerShape(4.dp))
            .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
            .padding(24.dp),
    ) {
        content()
    }
}

@Composable
private fun CardSectionTitle(title: String) {
    Text(
        text = title.uppercase(),
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.W600,
        fontSize = 11.sp,
        letterSpacing = 3.sp,
        color = ZuleColors.PrimaryDim,
    )
    Spacer(modifier = Modifier.height(16.dp))
}

@Composable
private fun InfoRow(
    label: String,
    value: String,
    showDivider: Boolean = true,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            fontFamily = CormorantGaramond,
            fontSize = 16.sp,
            color = ZuleColors.TextSecondary,
        )
        Text(
            text = value,
            fontFamily = CormorantGaramond,
            fontSize = 16.sp,
            color = ZuleColors.TextPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
    if (showDivider) {
        HorizontalDivider(thickness = 1.dp, color = ZuleColors.Border)
    }
}

@Composable
private fun FormLabel(text: String) {
    Text(
        text = text,
        fontFamily = CormorantGaramond,
        fontSize = 16.sp,
        color = ZuleColors.TextSecondary,
    )
}

/**
 * Passkey list item matching .passkey-item CSS:
 *   flex row, space-between, padding 12px, border 1px var(--border), border-radius 4px
 *
 * Left side: key icon + device name + metadata
 * Right side: red Remove button
 */
@Composable
private fun PasskeyItem(
    passkey: Passkey,
    isDeleting: Boolean,
    onRemove: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
            .padding(12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Left: info
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Key,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp),
                    tint = ZuleColors.TextPrimary,
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = passkey.deviceName,
                    fontFamily = CormorantGaramond,
                    fontSize = 15.sp,
                    color = ZuleColors.TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            val metaText = buildString {
                append("Added ${formatDate(passkey.createdAt)}")
                if (passkey.lastUsedAt != null) {
                    append(" \u2022 Last used ${formatDate(passkey.lastUsedAt)}")
                }
            }
            Text(
                text = metaText,
                fontFamily = CormorantGaramond,
                fontSize = 12.sp,
                color = ZuleColors.TextMuted,
                maxLines = 2,
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        // Right: Remove button (red, matching .btn-danger-small)
        Box(
            modifier = Modifier
                .border(1.dp, ZuleColors.Danger, RoundedCornerShape(4.dp))
                .clickable(enabled = !isDeleting, onClick = onRemove)
                .padding(horizontal = 10.dp, vertical = 4.dp),
        ) {
            Text(
                text = if (isDeleting) "Removing..." else "Remove",
                fontFamily = CormorantGaramond,
                fontSize = 12.sp,
                color = ZuleColors.Danger,
            )
        }
    }
}

/**
 * Password field matching form-group input with password visual transformation.
 */
@Composable
private fun PasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
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
        textStyle = TextStyle(
            fontFamily = CormorantGaramond,
            fontSize = 14.sp,
            color = ZuleColors.TextPrimary,
        ),
        singleLine = true,
        interactionSource = interactionSource,
        cursorBrush = SolidColor(ZuleColors.Primary),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        visualTransformation = PasswordVisualTransformation(),
        decorationBox = { innerTextField ->
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.CenterStart,
            ) {
                if (value.isEmpty()) {
                    Text(
                        text = placeholder,
                        fontFamily = CormorantGaramond,
                        fontSize = 14.sp,
                        color = ZuleColors.TextMuted,
                    )
                }
                innerTextField()
            }
        },
    )
}

/**
 * Primary button matching .btn-primary CSS.
 */
@Composable
private fun SecurityPrimaryButton(
    text: String,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Button(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .height(48.dp),
        shape = RoundedCornerShape(4.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color.Transparent,
            disabledContainerColor = Color.Transparent,
        ),
        enabled = enabled,
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    if (enabled) MetalSurfaceBrush
                    else Brush.linearGradient(
                        listOf(ZuleColors.TextMuted, ZuleColors.TextMuted),
                    ),
                    RoundedCornerShape(4.dp),
                ),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = text,
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

/**
 * Secondary button matching the inline-styled buttons in Security.tsx:
 *   font: Cormorant Garamond 14px weight 500, letter-spacing 0.06em
 *   color: var(--text-secondary), border: 1px var(--border)
 *   background: none, padding: 6px 14px, border-radius: 4px
 */
@Composable
private fun SecondaryButton(
    text: String,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 6.dp),
    ) {
        Text(
            text = text,
            fontFamily = CormorantGaramond,
            fontWeight = FontWeight.W500,
            fontSize = 14.sp,
            letterSpacing = 0.84.sp, // 0.06em
            color = ZuleColors.TextSecondary,
        )
    }
}
