package com.cyberguard.client

import androidx.compose.ui.graphics.Color
import com.cyberguard.client.ui.theme.LightCyberGuardColors
import com.cyberguard.client.ui.theme.PrimaryRed
import com.cyberguard.client.ui.theme.SignalYellow
import org.junit.Assert.*
import org.junit.Test
import kotlin.math.pow

/**
 * The app ships one interface only: the sovereign light palette on off-white
 * paper. These tests pin that palette and the contrast it promises.
 */
class ThemeSystemUnitTest {

    @Test
    fun testSingleLightPalette() {
        assertFalse(LightCyberGuardColors.isDark)
        assertEquals(Color(0xFFF6FAF4), LightCyberGuardColors.background)
        assertEquals(Color(0xFFFFFFFF), LightCyberGuardColors.surface)
        assertEquals(Color(0xFFFFFFFF), LightCyberGuardColors.surfaceElevated)
        assertEquals(Color(0xFFE8F5E5), LightCyberGuardColors.surfaceHighlight)
        assertEquals(Color(0xFFF2F8EF), LightCyberGuardColors.surfaceHologram)
        assertEquals(Color(0xFF14321F), LightCyberGuardColors.textPrimary)
        assertEquals(Color(0xFF47614F), LightCyberGuardColors.textSecondary)
        assertEquals(Color(0xFFDCE8D8), LightCyberGuardColors.border)
        assertEquals(Color(0xFF14532D), LightCyberGuardColors.primaryRed)
        assertEquals(Color(0xFFE6812F), LightCyberGuardColors.signalYellow)
        assertEquals(Color(0xFF2E7D4F), LightCyberGuardColors.statusOnline)
    }

    @Test
    fun testBrandAccentsAreGovernmentPalette() {
        assertEquals(Color(0xFF14532D), PrimaryRed)
        assertEquals(Color(0xFFE6812F), SignalYellow)
        // Critical stays red so danger is never mistaken for the brand accent.
        assertEquals(Color(0xFFB42318), LightCyberGuardColors.deepRed)
    }

    @Test
    fun testLightThemeTextContrastAccessibility() {
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

        val bg = LightCyberGuardColors.background
        val card = LightCyberGuardColors.surface
        val textPrimary = LightCyberGuardColors.textPrimary
        val textSecondary = LightCyberGuardColors.textSecondary
        val textTertiary = LightCyberGuardColors.textTertiary

        val primaryOnBg = contrastRatio(textPrimary, bg)
        assertTrue("Primary text on background must exceed WCAG AAA (7:1), was $primaryOnBg", primaryOnBg > 7.0)

        val primaryOnCard = contrastRatio(textPrimary, card)
        assertTrue("Primary text on card must exceed WCAG AAA (7:1), was $primaryOnCard", primaryOnCard > 7.0)

        val secondaryOnCard = contrastRatio(textSecondary, card)
        assertTrue("Secondary text on card must exceed WCAG AA (4.5:1), was $secondaryOnCard", secondaryOnCard > 4.5)

        val tertiaryOnCard = contrastRatio(textTertiary, card)
        assertTrue("Tertiary text on card must exceed WCAG AA (4.5:1), was $tertiaryOnCard", tertiaryOnCard > 4.5)

        val whiteOnBrand = contrastRatio(Color(0xFFFFFFFF), PrimaryRed)
        assertTrue("Button label on brand green must exceed WCAG AA (4.5:1), was $whiteOnBrand", whiteOnBrand > 4.5)
    }
}
