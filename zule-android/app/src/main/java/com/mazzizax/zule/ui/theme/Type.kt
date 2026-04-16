package com.mazzizax.zule.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.mazzizax.zule.R

/**
 * Translation of CSS font stacks:
 *   --font-body: 'Cormorant Garamond', serif
 *   --font-mono: 'Space Mono', 'Courier New', monospace
 *
 * Cormorant Garamond is a variable-weight font (single TTF covers 300-700).
 * Space Mono has Regular (400) and Bold (700) as separate files.
 *
 * Web app uses Cormorant Garamond weights 300 (light), 400 (normal), 500 (medium).
 * Web app uses Space Mono weights 400 (normal), 700 (bold).
 */
val CormorantGaramond = FontFamily(
    Font(R.font.cormorant_garamond, FontWeight.Light),
    Font(R.font.cormorant_garamond, FontWeight.Normal),
    Font(R.font.cormorant_garamond, FontWeight.Medium),
    Font(R.font.cormorant_garamond, FontWeight.SemiBold),
    Font(R.font.cormorant_garamond, FontWeight.Bold),
)

val SpaceMono = FontFamily(
    Font(R.font.space_mono_regular, FontWeight.Normal),
    Font(R.font.space_mono_bold, FontWeight.Bold),
)

/**
 * Typography scale matching the web app's CSS usage patterns.
 *
 * CSS references (from styles.css and inline styles):
 *   auth-header h1: 28px, weight 700, letter-spacing 8px
 *   card h2: 11px, weight 600, uppercase, letter-spacing 3px, color gold-dim
 *   nav-link: 16px, weight 400, letter-spacing 0.08em
 *   body: 16px
 *   form-group label: 16px, color text-secondary
 *   form-group input: 17px (auth), 14px (forms)
 *   btn-primary: 18px, weight 500
 *   info-row .label: 16px
 *   info-row .value: 16px
 *   info-note: 13px
 *   passkey-name: 15px
 *   passkey-meta: 12px
 *   .user-email: 11px, mono
 */
val ZuleTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.W700,
        fontSize = 28.sp,
        letterSpacing = 8.sp,
        color = ZuleColors.TextPrimary,
    ),
    headlineLarge = TextStyle(
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.W400,
        fontSize = 24.sp,
        letterSpacing = 3.sp,
        color = ZuleColors.TextPrimary,
    ),
    headlineMedium = TextStyle(
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.W400,
        fontSize = 22.sp,
        letterSpacing = 2.sp,
        color = ZuleColors.TextPrimary,
    ),
    titleLarge = TextStyle(
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.W600,
        fontSize = 11.sp,
        letterSpacing = 3.sp,
        color = ZuleColors.PrimaryDim,
    ),
    titleMedium = TextStyle(
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.W500,
        fontSize = 16.sp,
        color = ZuleColors.TextPrimary,
    ),
    bodyLarge = TextStyle(
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        color = ZuleColors.TextPrimary,
    ),
    bodyMedium = TextStyle(
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        color = ZuleColors.TextSecondary,
    ),
    bodySmall = TextStyle(
        fontFamily = CormorantGaramond,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        color = ZuleColors.TextSecondary,
    ),
    labelLarge = TextStyle(
        fontFamily = SpaceMono,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        color = ZuleColors.TextMuted,
    ),
    labelMedium = TextStyle(
        fontFamily = SpaceMono,
        fontWeight = FontWeight.Normal,
        fontSize = 11.sp,
        color = ZuleColors.TextMuted,
    ),
    labelSmall = TextStyle(
        fontFamily = SpaceMono,
        fontWeight = FontWeight.Normal,
        fontSize = 10.sp,
        color = ZuleColors.TextMuted,
    ),
)
