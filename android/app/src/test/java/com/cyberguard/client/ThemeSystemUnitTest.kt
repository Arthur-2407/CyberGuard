package com.cyberguard.client

import androidx.compose.ui.graphics.Color
import com.cyberguard.client.ui.theme.DarkCyberGuardColors
import com.cyberguard.client.ui.theme.LightCyberGuardColors
import org.junit.Assert.*
import org.junit.Test
import kotlin.math.pow

class ThemeSystemUnitTest {

    @Test
    fun testDarkThemePreserved() {
        assertTrue(DarkCyberGuardColors.isDark)
        assertEquals(Color(0xFF080A0F), DarkCyberGuardColors.background)
        assertEquals(Color(0xFF11151D), DarkCyberGuardColors.surface)
        assertEquals(Color(0xFF11151D), DarkCyberGuardColors.surfaceElevated)
        assertEquals(Color(0xFFFFFFFF), DarkCyberGuardColors.textPrimary)
        assertEquals(Color(0xFFF04444), DarkCyberGuardColors.primaryRed)
        assertEquals(Color(0xFFFFC928), DarkCyberGuardColors.signalYellow)
        assertEquals(Color(0xFF10B981), DarkCyberGuardColors.statusOnline)
    }
    @Test
    fun testLightThemePaletteTokens() {
        assertFalse(LightCyberGuardColors.isDark)
        assertEquals(Color(0xFFF3EFF9), LightCyberGuardColors.background)          // Soft lavender
        assertEquals(Color(0xFFFFFFFF), LightCyberGuardColors.surface)             // White cards
        assertEquals(Color(0xFFFFFFFF), LightCyberGuardColors.surfaceElevated)     // Elevated surface
        assertEquals(Color(0xFFE7DFF2), LightCyberGuardColors.surfaceHighlight)    // Light lavender
        assertEquals(Color(0xFFF8F7FB), LightCyberGuardColors.surfaceHologram)     // Secondary panels
        assertEquals(Color(0xFF262334), LightCyberGuardColors.textPrimary)         // Dark charcoal typography
        assertEquals(Color(0xFF524F60), LightCyberGuardColors.textSecondary)       // Supporting text
        assertEquals(Color(0xFFB8C9B5), LightCyberGuardColors.pastelSage)          // Pastel sage
        assertEquals(Color(0xFFDDE8DA), LightCyberGuardColors.softSage)            // Soft sage
        assertEquals(Color(0xFF5D7862), LightCyberGuardColors.darkSage)            // High contrast sage
        assertEquals(Color(0xFFDDD7E8), LightCyberGuardColors.border)              // Lavender-grey border
        assertEquals(Color(0xFFD94848), LightCyberGuardColors.primaryRed)          // Security Red
        assertEquals(Color(0xFFB98519), LightCyberGuardColors.signalYellow)        // Warning Yellow
        assertEquals(Color(0xFF107C41), LightCyberGuardColors.statusOnline)        // High-contrast emerald
    }

    @Test
    fun testLightThemeTextContrastAccessibility() {
        // WCAG formula for relative luminance
        fun channelLuminance(c: Float): Double {
            return if (c <= 0.03928f) (c / 12.92) else ((c + 0.055) / 1.055).pow(2.4)
        }

        fun relativeLuminance(color: Color): Double {
            val r = channelLuminance(color.red)
            val g = channelLuminance(color.green)
            val b = channelLuminance(color.blue)
            return 0.2126 * r + 0.7152 * g + 0.0722 * b
        }

        fun contrastRatio(c1: Color, c2: Color): Double {
            val l1 = relativeLuminance(c1)
            val l2 = relativeLuminance(c2)
            val brighter = maxOf(l1, l2)
            val darker = minOf(l1, l2)
            return (brighter + 0.05) / (darker + 0.05)
        }

        val bgLuminance = LightCyberGuardColors.background
        val cardLuminance = LightCyberGuardColors.surface
        val textPrimary = LightCyberGuardColors.textPrimary
        val textSecondary = LightCyberGuardColors.textSecondary

        // Primary text on Main Background (#262334 on #F3EFF9) -> Must exceed WCAG AAA (7.0:1)
        val primaryOnBgContrast = contrastRatio(textPrimary, bgLuminance)
        assertTrue("Primary text on background contrast ratio must be > 7.0:1 (was $primaryOnBgContrast)", primaryOnBgContrast > 7.0)

        // Primary text on Card Surface (#262334 on #FFFFFF) -> Must exceed WCAG AAA (7.0:1)
        val primaryOnCardContrast = contrastRatio(textPrimary, cardLuminance)
        assertTrue("Primary text on card surface contrast ratio must be > 7.0:1 (was $primaryOnCardContrast)", primaryOnCardContrast > 7.0)

        // Secondary text on Card Surface (#524F60 on #FFFFFF) -> Must exceed WCAG AA (4.5:1)
        val secondaryOnCardContrast = contrastRatio(textSecondary, cardLuminance)
        assertTrue("Secondary text on card surface contrast ratio must be > 4.5:1 (was $secondaryOnCardContrast)", secondaryOnCardContrast > 4.5)
    }
}
