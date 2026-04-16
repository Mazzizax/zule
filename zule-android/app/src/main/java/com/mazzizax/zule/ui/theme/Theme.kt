package com.mazzizax.zule.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

/**
 * ZuleTheme — dark only, matching styles.css color scheme.
 *
 * Card border-radius in CSS: 4px (all .card elements)
 */
private val ZuleColorScheme = darkColorScheme(
    primary = ZuleColors.Primary,
    onPrimary = ZuleColors.Background,
    primaryContainer = ZuleColors.PrimaryDim,
    onPrimaryContainer = ZuleColors.TextPrimary,
    secondary = ZuleColors.PrimaryDim,
    onSecondary = ZuleColors.TextPrimary,
    background = ZuleColors.Background,
    onBackground = ZuleColors.TextPrimary,
    surface = ZuleColors.Surface,
    onSurface = ZuleColors.TextPrimary,
    surfaceVariant = ZuleColors.Input,
    onSurfaceVariant = ZuleColors.TextSecondary,
    outline = ZuleColors.Border,
    outlineVariant = ZuleColors.BorderLight,
    error = ZuleColors.Danger,
    onError = ZuleColors.TextPrimary,
)

private val ZuleShapes = Shapes(
    small = RoundedCornerShape(4.dp),
    medium = RoundedCornerShape(4.dp),
    large = RoundedCornerShape(4.dp),
)

@Composable
fun ZuleTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = ZuleColorScheme,
        typography = ZuleTypography,
        shapes = ZuleShapes,
        content = content,
    )
}
