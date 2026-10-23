package com.cyberguard.client.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = CyberBlue,
    secondary = QuantumViolet,
    tertiary = HologramTeal,
    background = DeepSpaceBackground,
    surface = ElevatedSurface,
    surfaceVariant = HighlightSurface,
    onPrimary = DeepSpaceBackground,
    onSecondary = TextPrimary,
    onBackground = TextPrimary,
    onSurface = TextPrimary,
    onSurfaceVariant = TextSecondary,
    error = StatusCritical,
    outline = HolographicGlowBorder
)

@Composable
fun CyberGuardClientTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography,
        content = content
    )
}

@Composable
fun VoiceGuardClientTheme(
    content: @Composable () -> Unit
) = CyberGuardClientTheme(content = content)
