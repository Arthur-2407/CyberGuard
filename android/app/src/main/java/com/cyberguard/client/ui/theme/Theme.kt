package com.cyberguard.client.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/**
 * CyberGuard Centralized Design Tokens for Dark and Light (Lavender & Pastel Sage) themes.
 */
data class CyberGuardColors(
    val isDark: Boolean,
    val background: Color,
    val secondaryBackground: Color,
    val surface: Color,
    val surfaceElevated: Color,
    val surfaceHighlight: Color,
    val surfaceHologram: Color,
    val fieldBackground: Color,
    val border: Color,
    val borderGlow: Color,
    val borderSubtle: Color,
    val divider: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val textTertiary: Color,
    val textDisabled: Color,
    val primaryRed: Color,
    val deepRed: Color,
    val signalYellow: Color,
    val cyberGold: Color,
    val statusOnline: Color,
    val statusWarning: Color,
    val statusCritical: Color,
    val statusOffline: Color,
    val pastelSage: Color,
    val softSage: Color,
    val darkSage: Color,
    val lavenderAccent: Color,
    val lightLavender: Color,
)

// ══════════════════════════════════════════════════════════════════════════════
// 1. AUTHORITATIVE DARK THEME (Obsidian Void & Cyber Red / Amber)
// ══════════════════════════════════════════════════════════════════════════════
val DarkCyberGuardColors = CyberGuardColors(
    isDark = true,
    background = Color(0xFF080A0F),
    secondaryBackground = Color(0xFF04060C),
    surface = Color(0xFF11151D),
    surfaceElevated = Color(0xFF11151D),
    surfaceHighlight = Color(0xFF191F29),
    surfaceHologram = Color(0xFF1F2633),
    fieldBackground = Color(0xFF0D1117),
    border = Color(0xFF2D3748),
    borderGlow = Color(0xFF2D3748),
    borderSubtle = Color(0xFF222938),
    divider = Color(0xFF262D3D),
    textPrimary = Color(0xFFFFFFFF),
    textSecondary = Color(0xFFE9EDF2),
    textTertiary = Color(0xFF87909F),
    textDisabled = Color(0xFF4A5568),
    primaryRed = Color(0xFFF04444),
    deepRed = Color(0xFFB91C2C),
    signalYellow = Color(0xFFFFC928),
    cyberGold = Color(0xFFFACC15),
    statusOnline = Color(0xFF10B981),
    statusWarning = Color(0xFFFFC928),
    statusCritical = Color(0xFFB91C2C),
    statusOffline = Color(0xFF4A5568),
    pastelSage = Color(0xFFB8C9B5),
    softSage = Color(0xFFDDE8DA),
    darkSage = Color(0xFF718B75),
    lavenderAccent = Color(0xFFD8CBEF),
    lightLavender = Color(0xFFE7DFF2),
)

// ══════════════════════════════════════════════════════════════════════════════
// 2. AUTHORITATIVE LIGHT THEME (Soft Lavender & Pastel Sage Palette)
// ══════════════════════════════════════════════════════════════════════════════
val LightCyberGuardColors = CyberGuardColors(
    isDark = false,
    background = Color(0xFFF3EFF9),          // Very soft lavender
    secondaryBackground = Color(0xFFEDEAF5), // Subtle lavender depth
    surface = Color(0xFFFFFFFF),             // Main white cards
    surfaceElevated = Color(0xFFFFFFFF),     // Main cards
    surfaceHighlight = Color(0xFFE7DFF2),    // Light lavender (selected surfaces)
    surfaceHologram = Color(0xFFF8F7FB),     // Secondary panels
    fieldBackground = Color(0xFFFFFFFF),     // Clean input field
    border = Color(0xFFDDD7E8),              // Card outlines
    borderGlow = Color(0xFFDDD7E8),          // Subtle panel boundary
    borderSubtle = Color(0xFFDDD7E8),        // Subtle outlines
    divider = Color(0xFFDDD7E8),             // Dividers
    textPrimary = Color(0xFF262334),         // Dark charcoal typography (11:1 contrast)
    textSecondary = Color(0xFF524F60),       // Supporting text (6.2:1 contrast)
    textTertiary = Color(0xFF787487),        // Secondary labels (4.6:1 contrast)
    textDisabled = Color(0xFFA5A2B2),
    primaryRed = Color(0xFFD94848),          // Security Red
    deepRed = Color(0xFFB91C2C),
    signalYellow = Color(0xFFB98519),        // Warning Yellow
    cyberGold = Color(0xFFB98519),
    statusOnline = Color(0xFF107C41),        // Darker green for high light-contrast
    statusWarning = Color(0xFFB98519),
    statusCritical = Color(0xFFD94848),
    statusOffline = Color(0xFF898596),
    pastelSage = Color(0xFFB8C9B5),          // Secondary accent
    softSage = Color(0xFFDDE8DA),            // Subtle card accents
    darkSage = Color(0xFF5D7862),            // Sage text/icons with accessible contrast
    lavenderAccent = Color(0xFFD8CBEF),      // Gentle visual emphasis
    lightLavender = Color(0xFFE7DFF2),       // Selected surfaces
)

val LocalCyberGuardColors = staticCompositionLocalOf { DarkCyberGuardColors }
val LocalThemeIsDark = staticCompositionLocalOf { true }

object CyberGuardTheme {
    val colors: CyberGuardColors
        @Composable
        get() = LocalCyberGuardColors.current

    val isDark: Boolean
        @Composable
        get() = LocalThemeIsDark.current
}

private val DarkColorScheme = darkColorScheme(
    primary = PrimaryRed,
    secondary = SignalYellow,
    tertiary = OffWhite,
    background = Color(0xFF080A0F),
    surface = Color(0xFF11151D),
    surfaceVariant = Color(0xFF191F29),
    onPrimary = Color(0xFF080A0F),
    onSecondary = Color(0xFF080A0F),
    onBackground = Color(0xFFFFFFFF),
    onSurface = Color(0xFFFFFFFF),
    onSurfaceVariant = Color(0xFFE9EDF2),
    error = DeepRed,
    outline = Color(0xFF2D3748)
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFFD94848),
    secondary = Color(0xFFB98519),
    tertiary = Color(0xFF5D7862),
    background = Color(0xFFF3EFF9),
    surface = Color(0xFFFFFFFF),
    surfaceVariant = Color(0xFFF8F7FB),
    onPrimary = Color(0xFFFFFFFF),
    onSecondary = Color(0xFFFFFFFF),
    onBackground = Color(0xFF262334),
    onSurface = Color(0xFF262334),
    onSurfaceVariant = Color(0xFF524F60),
    error = Color(0xFFD94848),
    outline = Color(0xFFDDD7E8)
)

@Composable
fun CyberGuardClientTheme(
    isDark: Boolean = true,
    content: @Composable () -> Unit
) {
    val colors = if (isDark) DarkCyberGuardColors else LightCyberGuardColors
    val colorScheme = if (isDark) DarkColorScheme else LightColorScheme

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window
            if (window != null) {
                window.statusBarColor = colors.background.toArgb()
                window.navigationBarColor = colors.surfaceElevated.toArgb()
                val controller = WindowCompat.getInsetsController(window, view)
                controller.isAppearanceLightStatusBars = !isDark
                controller.isAppearanceLightNavigationBars = !isDark
            }
        }
    }

    CompositionLocalProvider(
        LocalCyberGuardColors provides colors,
        LocalThemeIsDark provides isDark
    ) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = Typography,
            content = content
        )
    }
}

@Composable
fun VoiceGuardClientTheme(
    isDark: Boolean = true,
    content: @Composable () -> Unit
) = CyberGuardClientTheme(isDark = isDark, content = content)
