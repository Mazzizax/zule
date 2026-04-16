package com.mazzizax.zule.ui.theme

import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

/**
 * Direct translation of styles.css :root variables.
 *
 * --zule-gold: #C4A882
 * --zule-gold-dim: #A08968
 * --zule-gold-bright: #D4BC9A
 * --zule-gold-glow: rgba(196, 168, 130, 0.12)
 * --zule-gold-glow-strong: rgba(196, 168, 130, 0.22)
 * --bg-deep: #080706
 * --bg-card: #111010
 * --bg-input: #0c0b0a
 * --border: #1e1b18
 * --border-light: #2a2622
 * --text-primary: #ece8e1
 * --text-secondary: #7d766d
 * --text-muted: #4a453e
 * --danger: #c44
 * --warning: #d4943c
 */
object ZuleColors {
    val Primary = Color(0xFFC4A882)
    val PrimaryDim = Color(0xFFA08968)
    val PrimaryBright = Color(0xFFD4BC9A)
    val PrimaryGlow = Color(0x1FC4A882)        // 0.12 alpha
    val PrimaryGlowStrong = Color(0x38C4A882)  // 0.22 alpha
    val Background = Color(0xFF080706)
    val Surface = Color(0xFF111010)
    val Input = Color(0xFF0C0B0A)
    val Border = Color(0xFF1E1B18)
    val BorderLight = Color(0xFF2A2622)
    val TextPrimary = Color(0xFFECE8E1)
    val TextSecondary = Color(0xFF7D766D)
    val TextMuted = Color(0xFF4A453E)
    val Danger = Color(0xFFCC4444)
    val Warning = Color(0xFFD4943C)

    // Mobile header/menu background from .mobile-header, .mobile-menu
    val MenuBackground = Color(0xFF0F0E0C)
    // Sidebar background from .sidebar
    val SidebarBackground = Color(0xFF0C0B09)
}

/**
 * Translation of --metal-text CSS gradient:
 * linear-gradient(135deg, #A08968 0%, #D4BC9A 25%, #C4A882 50%, #E0D0B8 75%, #A08968 100%)
 */
val MetalTextBrush = Brush.linearGradient(
    colors = listOf(
        Color(0xFFA08968),
        Color(0xFFD4BC9A),
        Color(0xFFC4A882),
        Color(0xFFE0D0B8),
        Color(0xFFA08968),
    )
)

/**
 * Translation of --metal-surface CSS gradient:
 * linear-gradient(135deg, #A08968 0%, #C4A882 40%, #D4BC9A 60%, #A08968 100%)
 */
val MetalSurfaceBrush = Brush.linearGradient(
    colors = listOf(
        Color(0xFFA08968),
        Color(0xFFC4A882),
        Color(0xFFD4BC9A),
        Color(0xFFA08968),
    )
)

/**
 * Metallic tier badge gradients from Dashboard.tsx metals object.
 *
 * rose: linear-gradient(145deg, #8a7560..#C4A882..#E0D0B8..#D4BC9A..#A08968..#C4A882..#E0D0B8..#8a7560)
 * titanium: linear-gradient(145deg, #7a8590..#B0BEC5..#CFD8DC..#B0BEC5..#8a9aa5..#B0BEC5..#CFD8DC..#7a8590)
 * gunmetal: linear-gradient(145deg, #3a3e44..#4d5259..#626870..#6e747c..#5a6068..#4d5259..#626870..#6e747c..#5a6068..#3a3e44)
 */
val RoseGoldBrush = Brush.linearGradient(
    colors = listOf(
        Color(0xFF8A7560), Color(0xFFC4A882), Color(0xFFE0D0B8),
        Color(0xFFD4BC9A), Color(0xFFA08968), Color(0xFFC4A882),
        Color(0xFFE0D0B8), Color(0xFF8A7560),
    )
)
val TitaniumBrush = Brush.linearGradient(
    colors = listOf(
        Color(0xFF7A8590), Color(0xFFB0BEC5), Color(0xFFCFD8DC),
        Color(0xFFB0BEC5), Color(0xFF8A9AA5), Color(0xFFB0BEC5),
        Color(0xFFCFD8DC), Color(0xFF7A8590),
    )
)
val GunmetalBrush = Brush.linearGradient(
    colors = listOf(
        Color(0xFF3A3E44), Color(0xFF4D5259), Color(0xFF626870),
        Color(0xFF6E747C), Color(0xFF5A6068), Color(0xFF4D5259),
        Color(0xFF626870), Color(0xFF6E747C), Color(0xFF5A6068),
        Color(0xFF3A3E44),
    )
)

// Text colors for metallic badges (from metals.text in Dashboard.tsx/Subscriptions.tsx)
val RoseGoldTextColor = Color(0xFF1A1510)
val TitaniumTextColor = Color(0xFF1A1E22)
val GunmetalTextColor = Color(0xFF111214)
