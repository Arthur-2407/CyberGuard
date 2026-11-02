package com.cyberguard.client.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

// ══════════════════════════════════════════════════════════════════════════════
// CyberGuard Authoritative Brand Accents & Fixed Constants
// ══════════════════════════════════════════════════════════════════════════════
val PrimaryRed = Color(0xFFF04444)          // Cyber Security Red (Primary Brand Accent)
val DeepRed = Color(0xFFB91C2C)             // Critical Security Breach Laser Crimson
val SignalYellow = Color(0xFFFFC928)        // Tactical Signal Yellow (Warning & Control Accent)
val CyberYellow = Color(0xFFFFD166)         // Tactical Spectrum Yellow
val CyberGold = Color(0xFFFACC15)           // Clearance Gold
val PureWhite = Color(0xFFFFFFFF)           // Primary Pure White
val OffWhite = Color(0xFFE9EDF2)            // Secondary Off White
val MutedGrey = Color(0xFF87909F)           // Muted Tactical Grey
val LightTextPrimary = Color(0xFF262334)     // Light Theme Charcoal Primary Typography
val LightTextSecondary = Color(0xFF524F60)   // Light Theme Supporting Text
val DarkTextPrimary = PureWhite
val DarkTextSecondary = OffWhite

// Functional Bridge Aliases
val CyberRed = PrimaryRed
val CyberAmber = SignalYellow
val CyberBlue = PrimaryRed
val CyberNeonCyan = PrimaryRed
val CyberBlueVariant = DeepRed
val ElectricCyan = SignalYellow
val QuantumViolet = SignalYellow
val HologramTeal = SignalYellow
val MutedSlate = MutedGrey
val FieldBorderFocused = PrimaryRed
val StatusOffline = Color(0xFF4A5568)
val HighAlertOrange = Color(0xFFFF6600)
val RadarGridCyan = Color(0x40F04444)
val LensFlareWhite = PureWhite
val EmeraldGreen = Color(0xFF10B981)
val DeepNeonMagenta = DeepRed
val ThreatAlertRed = PrimaryRed
val LevelVGold = CyberGold

// ══════════════════════════════════════════════════════════════════════════════
// Centralized Dynamic Theme-Aware Tokens (Dark / Lavender-Sage Light Mode)
// ══════════════════════════════════════════════════════════════════════════════
val DeepSpaceBackground: Color
    @Composable
    get() = CyberGuardTheme.colors.background

val ElevatedSurface: Color
    @Composable
    get() = CyberGuardTheme.colors.surfaceElevated

val HighlightSurface: Color
    @Composable
    get() = CyberGuardTheme.colors.surfaceHighlight

val HologramSurface: Color
    @Composable
    get() = CyberGuardTheme.colors.surfaceHologram

val CardSurface: Color
    @Composable
    get() = CyberGuardTheme.colors.surface

val FieldBackground: Color
    @Composable
    get() = CyberGuardTheme.colors.fieldBackground

val SurfaceDark: Color
    @Composable
    get() = CyberGuardTheme.colors.surfaceElevated

val SurfaceLighter: Color
    @Composable
    get() = CyberGuardTheme.colors.surfaceHologram

val TextPrimary: Color
    @Composable
    get() = CyberGuardTheme.colors.textPrimary

val TextSecondary: Color
    @Composable
    get() = CyberGuardTheme.colors.textSecondary

val TextTertiary: Color
    @Composable
    get() = CyberGuardTheme.colors.textTertiary

val TextDisabled: Color
    @Composable
    get() = CyberGuardTheme.colors.textDisabled

val DividerColor: Color
    @Composable
    get() = CyberGuardTheme.colors.divider

val HolographicGlowBorder: Color
    @Composable
    get() = CyberGuardTheme.colors.borderGlow

val FieldBorderIdle: Color
    @Composable
    get() = CyberGuardTheme.colors.border

val CardBorderSubtle: Color
    @Composable
    get() = CyberGuardTheme.colors.borderSubtle

val StatusOnline: Color
    @Composable
    get() = CyberGuardTheme.colors.statusOnline

val StatusWarning: Color
    @Composable
    get() = CyberGuardTheme.colors.statusWarning

val StatusCritical: Color
    @Composable
    get() = CyberGuardTheme.colors.statusCritical

val PastelSage: Color
    @Composable
    get() = CyberGuardTheme.colors.pastelSage

val SoftSage: Color
    @Composable
    get() = CyberGuardTheme.colors.softSage

val DarkSage: Color
    @Composable
    get() = CyberGuardTheme.colors.darkSage

val LavenderAccent: Color
    @Composable
    get() = CyberGuardTheme.colors.lavenderAccent

val LightLavender: Color
    @Composable
    get() = CyberGuardTheme.colors.lightLavender

// ══════════════════════════════════════════════════════════════════════════════
// Tactical Gradients
// ══════════════════════════════════════════════════════════════════════════════
val QuantumHeaderGradient = Brush.horizontalGradient(
    listOf(PrimaryRed, SignalYellow)
)

val HolographicCardGradient: Brush
    @Composable
    get() = if (CyberGuardTheme.isDark) {
        Brush.verticalGradient(listOf(Color(0xFF191F29), Color(0xFF11151D)))
    } else {
        Brush.verticalGradient(listOf(Color(0xFFFFFFFF), Color(0xFFF8F7FB)))
    }

val BreachGradient = Brush.horizontalGradient(
    listOf(DeepRed, PrimaryRed)
)

val GlitchRedYellowGradient = Brush.horizontalGradient(
    listOf(PrimaryRed, SignalYellow, PureWhite)
)
