package com.cyberguard.client.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
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
 * CyberGuard Centralized Design Tokens.
 *
 * The product ships a single light interface: a sovereign green / lime / orange
 * government palette on warm off-white paper. There is no dark variant and no
 * runtime theme switch.
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
// AUTHORITATIVE LIGHT THEME (Sovereign Green, Lime & Orange on Off-White)
// ══════════════════════════════════════════════════════════════════════════════
val LightCyberGuardColors = CyberGuardColors(
    isDark = false,
    background = Color(0xFFF6FAF4),          // Warm off-white app canvas
    secondaryBackground = Color(0xFFEEF6EA), // Sidebar / rail tint
    surface = Color(0xFFFFFFFF),             // Cards
    surfaceElevated = Color(0xFFFFFFFF),
    surfaceHighlight = Color(0xFFE8F5E5),    // Soft mint selection
    surfaceHologram = Color(0xFFF2F8EF),     // Secondary panels
    fieldBackground = Color(0xFFFFFFFF),
    border = Color(0xFFDCE8D8),
    borderGlow = Color(0xFFDCE8D8),
    borderSubtle = Color(0xFFE7F0E4),
    divider = Color(0xFFE3EDE0),
    textPrimary = Color(0xFF14321F),         // Deep forest typography
    textSecondary = Color(0xFF47614F),
    textTertiary = Color(0xFF6B8272),
    textDisabled = Color(0xFFA3B3A8),
    primaryRed = Color(0xFF14532D),          // Brand accent is now sovereign green
    deepRed = Color(0xFFB42318),             // Genuine critical red only
    signalYellow = Color(0xFFE6812F),        // Orange accent / warning
    cyberGold = Color(0xFFB45309),
    statusOnline = Color(0xFF2E7D4F),
    statusWarning = Color(0xFFB45309),
    statusCritical = Color(0xFFB42318),
    statusOffline = Color(0xFF7A8B80),
    pastelSage = Color(0xFFCFE8CC),
    softSage = Color(0xFFE4F1E3),
    darkSage = Color(0xFF14532D),
    lavenderAccent = Color(0xFFC9E265),      // Lime highlight (legacy token name)
    lightLavender = Color(0xFFEEF7D2),       // Pale lime surface (legacy token name)
)

val LocalCyberGuardColors = staticCompositionLocalOf { LightCyberGuardColors }
val LocalThemeIsDark = staticCompositionLocalOf { false }

object CyberGuardTheme {
    val colors: CyberGuardColors
        @Composable
        get() = LocalCyberGuardColors.current

    val isDark: Boolean
        @Composable
        get() = false
}

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF14532D),
    onPrimary = Color(0xFFFFFFFF),
    secondary = Color(0xFFE6812F),
    onSecondary = Color(0xFFFFFFFF),
    tertiary = Color(0xFF2E7D4F),
    background = Color(0xFFF6FAF4),
    onBackground = Color(0xFF14321F),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF14321F),
    surfaceVariant = Color(0xFFF2F8EF),
    onSurfaceVariant = Color(0xFF47614F),
    error = Color(0xFFB42318),
    onError = Color(0xFFFFFFFF),
    outline = Color(0xFFDCE8D8)
)

@Composable
fun CyberGuardClientTheme(
    content: @Composable () -> Unit
) {
    val colors = LightCyberGuardColors

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window
            if (window != null) {
                window.statusBarColor = colors.background.toArgb()
                window.navigationBarColor = colors.surfaceElevated.toArgb()
                val controller = WindowCompat.getInsetsController(window, view)
                controller.isAppearanceLightStatusBars = true
                controller.isAppearanceLightNavigationBars = true
            }
        }
    }

    CompositionLocalProvider(
        LocalCyberGuardColors provides colors,
        LocalThemeIsDark provides false
    ) {
        MaterialTheme(
            colorScheme = LightColorScheme,
            typography = Typography,
            content = content
        )
    }
}

@Composable
fun VoiceGuardClientTheme(
    content: @Composable () -> Unit
) = CyberGuardClientTheme(content = content)
