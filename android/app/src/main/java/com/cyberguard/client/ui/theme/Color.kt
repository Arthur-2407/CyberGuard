package com.cyberguard.client.ui.theme

import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

// CyberGuard Hyper-Advanced Quantum Defense Palette

// Base Surfaces - Deep Obsidian & Quantum Enclaves
val DeepSpaceBackground = Color(0xFF04060C) // Absolute Deep Void
val ElevatedSurface = Color(0xFF0A0F1D)      // Photonic Shielded Surface
val HighlightSurface = Color(0xFF10172C)     // Active Matrix Layer
val HologramSurface = Color(0xFF141F38)      // Floating Quantum HUD Surface
val CardSurface = Color(0xFF0A1020)          // High-contrast Card Background
val FieldBackground = Color(0xFF070B16)      // Input Field Fill
val SurfaceDark = ElevatedSurface
val SurfaceLighter = HologramSurface

// Photonic Neural Accents
val CyberBlue = Color(0xFF00F0FF)           // Neon Quantum Cyan
val CyberNeonCyan = CyberBlue               // Laser Quantum Cyan
val CyberBlueVariant = Color(0xFF0088FF)    // Deep Electric Laser Blue
val ElectricCyan = Color(0xFF38BDF8)        // Radiant Plasma Cyan
val QuantumViolet = Color(0xFFA855F7)       // Neural Lattice Violet
val HologramTeal = Color(0xFF00FFC2)        // Photonic Bio-Teal
val MutedSlate = Color(0xFF7E8B9F)          // Sub-Shield Titanium Slate
val DividerColor = Color(0xFF1B283F)        // Holographic Micro-Seam
val HolographicGlowBorder = Color(0xFF1E3355) // Quantum Field Boundary
val FieldBorderIdle = Color(0xFF223552)     // High-contrast Input Field Outline
val FieldBorderFocused = CyberNeonCyan      // Laser Focus Outline
val CardBorderSubtle = Color(0xFF182844)    // Refined Card Border

// Functional Telemetry Colors
val StatusOnline = Color(0xFF00FF9D)        // Quantum Harmonized Emerald
val StatusWarning = Color(0xFFFFB703)       // Tactical Solar Flare Amber
val StatusCritical = Color(0xFFFF2A6D)      // Hyper-Laser Breach Crimson
val StatusOffline = Color(0xFF4A5568)       // Inactive Neural Node Gray
val HighAlertOrange = Color(0xFFFF6600)     // High Alert Neon Orange
val CyberAmber = Color(0xFFFF9E0B)          // Tactical Amber Indicator
val RadarGridCyan = Color(0xFF00E5FF)       // 3D Radar Hologram Cyan
val LensFlareWhite = Color(0xFFE2F8FF)      // Radiant Star Flare Glint White
val EmeraldGreen = Color(0xFF10B981)        // Harmonized Bio-Defense Green
val DeepNeonMagenta = Color(0xFFD946EF)     // High-Frequency Neural Magenta
val CyberGold = Color(0xFFFACC15)           // Commander Access Gold
val CyberYellow = Color(0xFFFFD166)         // Tactical Spectrum Yellow
val ThreatAlertRed = Color(0xFFFF1E56)      // Active Breach Red
val LevelVGold = Color(0xFFEAB308)          // Level-V Clearance Gold

// Text Telemetry Colors
val TextPrimary = Color(0xFFFFFFFF)         // Laser White
val TextSecondary = Color(0xFFA8B5CE)       // Matrix Silver
val TextTertiary = Color(0xFF62738E)        // Deep Grid Subtext
val TextDisabled = Color(0xFF3D4B63)        // Disabled Text State

// Tactical Gradients
val QuantumHeaderGradient = Brush.horizontalGradient(
    listOf(CyberBlue, QuantumViolet)
)
val HolographicCardGradient = Brush.verticalGradient(
    listOf(Color(0xFF0E162B), Color(0xFF060913))
)
val BreachGradient = Brush.horizontalGradient(
    listOf(StatusCritical, Color(0xFFFF5722))
)

