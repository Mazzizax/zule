package com.mazzizax.zule.ui.screen.profile

import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.mazzizax.zule.ui.theme.CormorantGaramond
import com.mazzizax.zule.ui.theme.MetalSurfaceBrush
import com.mazzizax.zule.ui.theme.ZuleColors

/**
 * Translation of Profile.tsx.
 *
 * Single card "Personal Information":
 *   - Email (disabled field with hint)
 *   - Display Name (editable, 50 char max)
 *   - Timezone dropdown (11 exact options from TIMEZONES const)
 *   - Save Changes button
 *
 * Web CSS references:
 *   .form-group: margin-bottom 20px
 *   .form-group label: font-size 16px, color var(--text-secondary), margin-bottom 8px
 *   .form-group input: font-size 14px, background var(--bg-input), border 1px var(--border),
 *     border-radius 4px, padding 12px 14px, color var(--text-primary)
 *   .input-disabled: opacity 0.5, cursor not-allowed
 *   .form-hint: font-size 12px, color var(--text-muted), margin-top 6px
 *   select: same styling as input
 */

private val TIMEZONES = listOf(
    "UTC",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Asia/Tokyo",
    "Asia/Shanghai",
    "Australia/Sydney",
)

@Composable
fun ProfileScreen(
    viewModel: ProfileViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()

    if (state.isLoading) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                CircularProgressIndicator(
                    color = ZuleColors.Primary,
                    strokeWidth = 2.dp,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Loading profile...",
                    fontFamily = CormorantGaramond,
                    fontSize = 14.sp,
                    color = ZuleColors.TextSecondary,
                )
            }
        }
        return
    }

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

        // ── Personal Information Card ──
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(ZuleColors.Surface, RoundedCornerShape(4.dp))
                .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                .padding(24.dp),
        ) {
            // Card title
            Text(
                text = "PERSONAL INFORMATION",
                fontFamily = CormorantGaramond,
                fontWeight = FontWeight.W600,
                fontSize = 11.sp,
                letterSpacing = 3.sp,
                color = ZuleColors.PrimaryDim,
            )

            Spacer(modifier = Modifier.height(20.dp))

            // ── Email Field (disabled) ──
            FormLabel("Email")
            Spacer(modifier = Modifier.height(8.dp))
            DisabledTextField(value = state.email)
            Spacer(modifier = Modifier.height(6.dp))
            FormHint("Email cannot be changed here")

            Spacer(modifier = Modifier.height(20.dp))

            // ── Display Name Field ──
            FormLabel("Display Name")
            Spacer(modifier = Modifier.height(8.dp))
            EditableTextField(
                value = state.displayName,
                onValueChange = viewModel::onDisplayNameChange,
                placeholder = "Enter your display name",
            )
            Spacer(modifier = Modifier.height(6.dp))
            FormHint("This name will be shown to apps you connect")

            Spacer(modifier = Modifier.height(20.dp))

            // ── Timezone Dropdown ──
            FormLabel("Timezone")
            Spacer(modifier = Modifier.height(8.dp))
            TimezoneDropdown(
                selected = state.timezone,
                onSelect = viewModel::onTimezoneChange,
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        // ── Save Changes Button ──
        Button(
            onClick = { viewModel.saveProfile() },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(4.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color.Transparent,
                disabledContainerColor = Color.Transparent,
            ),
            enabled = !state.isSaving,
        ) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        if (!state.isSaving) MetalSurfaceBrush
                        else Brush.linearGradient(
                            listOf(ZuleColors.TextMuted, ZuleColors.TextMuted),
                        ),
                        RoundedCornerShape(4.dp),
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = if (state.isSaving) "Saving..." else "Save Changes",
                    style = TextStyle(
                        fontFamily = CormorantGaramond,
                        fontWeight = FontWeight.W500,
                        fontSize = 18.sp,
                        color = ZuleColors.Background,
                    ),
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}

// ── Form Components ──

@Composable
private fun FormLabel(text: String) {
    Text(
        text = text,
        fontFamily = CormorantGaramond,
        fontSize = 16.sp,
        color = ZuleColors.TextSecondary,
    )
}

@Composable
private fun FormHint(text: String) {
    Text(
        text = text,
        fontFamily = CormorantGaramond,
        fontSize = 12.sp,
        color = ZuleColors.TextMuted,
    )
}

/**
 * Disabled text field matching .input-disabled:
 *   Same as input but opacity 0.5
 */
@Composable
private fun DisabledTextField(value: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(48.dp)
            .background(ZuleColors.Input.copy(alpha = 0.5f), RoundedCornerShape(4.dp))
            .border(1.dp, ZuleColors.Border.copy(alpha = 0.5f), RoundedCornerShape(4.dp))
            .padding(horizontal = 14.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        Text(
            text = value,
            fontFamily = CormorantGaramond,
            fontSize = 14.sp,
            color = ZuleColors.TextPrimary.copy(alpha = 0.5f),
        )
    }
}

/**
 * Editable text field matching .form-group input:
 *   font-size: 14px, background: var(--bg-input), border: 1px var(--border)
 *   border-radius: 4px, padding: 12px 14px, color: var(--text-primary)
 *   Focus: border-color var(--zule-gold)
 */
@Composable
private fun EditableTextField(
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
 * Timezone dropdown matching the <select> in Profile.tsx.
 * Styled to match form input appearance.
 */
@Composable
private fun TimezoneDropdown(
    selected: String,
    onSelect: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }

    Box {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
                .background(ZuleColors.Input, RoundedCornerShape(4.dp))
                .border(1.dp, ZuleColors.Border, RoundedCornerShape(4.dp))
                .clickable { expanded = true }
                .padding(horizontal = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = selected,
                fontFamily = CormorantGaramond,
                fontSize = 14.sp,
                color = ZuleColors.TextPrimary,
            )
            Icon(
                imageVector = Icons.Default.ArrowDropDown,
                contentDescription = null,
                tint = ZuleColors.TextSecondary,
            )
        }

        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            modifier = Modifier
                .background(ZuleColors.Surface)
                .border(1.dp, ZuleColors.Border),
        ) {
            TIMEZONES.forEach { tz ->
                DropdownMenuItem(
                    text = {
                        Text(
                            text = tz,
                            fontFamily = CormorantGaramond,
                            fontSize = 14.sp,
                            color = if (tz == selected) ZuleColors.Primary else ZuleColors.TextPrimary,
                        )
                    },
                    onClick = {
                        onSelect(tz)
                        expanded = false
                    },
                    modifier = Modifier.background(
                        if (tz == selected) ZuleColors.PrimaryGlow else Color.Transparent,
                    ),
                )
            }
        }
    }
}
