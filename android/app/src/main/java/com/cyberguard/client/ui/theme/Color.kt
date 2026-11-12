package com.cyberguard.client.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

// ══════════════════════════════════════════════════════════════════════════════
// CyberGuard Authoritative Brand Accents & Fixed Constants
// ══════════════════════════════════════════════════════════════════════════════
val PrimaryRed = Color(0xFF14532D)          // Sovereign Green (Primary Brand Accent)
val DeepRed = Color(0xFFB42318)             // Critical Security Breach Crimson
val SignalYellow = Color(0xFFE6812F)        // Orange Accent (Warning & Control)
val CyberYellow = Color(0xFFF3A45C)         // Soft Orange
val CyberGold = Color(0xFFB45309)           // Deep Amber
val PureWhite = Color(0xFFFFFFFF)           // Primary Pure White
val OffWhite = Color(0xFF47614F)            // Secondary Text (Mid Forest)
val MutedGrey = Color(0xFF6B8272)           // Muted Sage Grey
val LightTextPrimary = Color(0xFF14321F)     // Forest Primary Typography
val LightTextSecondary = Color(0xFF47614F)   // Supporting Text
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
val FieldBorderFocused = Color(0xFF14532D)
val StatusOffline = Color(0xFF7A8B80)
val HighAlertOrange = Color(0xFFE6812F)
val RadarGridCyan = Color(0x2E14532D)
val LensFlareWhite = PureWhite
val EmeraldGreen = Color(0xFF2E7D4F)
val DeepNeonMagenta = DeepRed
val ThreatAlertRed = Color(0xFFB42318)
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
    get() = Brush.verticalGradient(listOf(Color(0xFFFFFFFF), Color(0xFFF6FAF4)))

val BreachGradient = Brush.horizontalGradient(
    listOf(DeepRed, PrimaryRed)
)

val GlitchRedYellowGradient = Brush.horizontalGradient(
    listOf(PrimaryRed, SignalYellow, PureWhite)
)
