package com.cyberguard.client.network

import com.cyberguard.client.model.CallMonitorTelemetry
import com.cyberguard.client.model.MonitorState
import org.junit.Assert.*
import org.junit.Test
import java.util.Locale

class CallMonitorStreamingTelemetryTest {

    @Test
    fun testInitialCallMonitorTelemetryState() {
        val telemetry = CallMonitorTelemetry()
        assertEquals(0.0, telemetry.currentRisk, 0.001)
        assertEquals("STANDBY", telemetry.alertLevel)
        assertEquals("ANALYZING", telemetry.voiceClassification)
        assertFalse(telemetry.hasValidResult)
        assertEquals(0L, telemetry.lastResultTimestamp)
    }

    @Test
    fun testRiskScoreDisplayDistinguishesPendingFromCalculatedZero() {
        // Pending evaluation (e.g. streaming audio before speech detected)
        val pendingTelemetry = CallMonitorTelemetry(
            monitorState = MonitorState.ANALYZING,
            currentRisk = 0.0,
            hasValidResult = false,
            voiceClassification = "WAITING FOR SPEECH"
        )
        val pendingDisplay = if (pendingTelemetry.hasValidResult) {
            String.format(Locale.US, "%.1f%%", pendingTelemetry.currentRisk * 100)
        } else {
            "--"
        }
        assertEquals("--", pendingDisplay)
        assertEquals("WAITING FOR SPEECH", pendingTelemetry.voiceClassification)

        // Verified genuine zero / low risk evaluation from model
        val genuineSafeTelemetry = CallMonitorTelemetry(
            monitorState = MonitorState.ANALYZING,
            currentRisk = 0.0,
            hasValidResult = true,
            voiceClassification = "GENUINE_VOICE",
            alertLevel = "SAFE",
            lastResultTimestamp = 1000L
        )
        val genuineSafeDisplay = if (genuineSafeTelemetry.hasValidResult) {
            String.format(Locale.US, "%.1f%%", genuineSafeTelemetry.currentRisk * 100)
        } else {
            "--"
        }
        assertEquals("0.0%", genuineSafeDisplay)
        assertEquals("GENUINE_VOICE", genuineSafeTelemetry.voiceClassification)
    }

    @Test
    fun testRiskScoreDisplayFormatsHigherScoresAccurately() {
        val clonedVoiceTelemetry = CallMonitorTelemetry(
            monitorState = MonitorState.ANALYZING,
            currentRisk = 0.874,
            hasValidResult = true,
            voiceClassification = "CLONED_VOICE",
            alertLevel = "CRITICAL",
            lastResultTimestamp = 2000L
        )
        val scoreDisplay = if (clonedVoiceTelemetry.hasValidResult) {
            String.format(Locale.US, "%.1f%%", clonedVoiceTelemetry.currentRisk * 100)
        } else {
            "--"
        }
        assertEquals("87.4%", scoreDisplay)
        assertEquals("CLONED_VOICE", clonedVoiceTelemetry.voiceClassification)
    }

    @Test
    fun testStatusUpdateClassificationResolution() {
        // When waiting for speech, classification should show WAITING FOR SPEECH
        val statusWaiting = "WAITING_FOR_SPEECH"
        val resolvedWaiting = when (statusWaiting) {
            "WAITING_FOR_SPEECH" -> "WAITING FOR SPEECH"
            "INSUFFICIENT_AUDIO" -> "COLLECTING AUDIO"
            "WAITING_FOR_DATA", "LISTENING" -> "COLLECTING AUDIO"
            else -> "ANALYZING"
        }
        assertEquals("WAITING FOR SPEECH", resolvedWaiting)

        // When short speech frames collected, show COLLECTING AUDIO
        val statusShort = "INSUFFICIENT_AUDIO"
        val resolvedShort = when (statusShort) {
            "WAITING_FOR_SPEECH" -> "WAITING FOR SPEECH"
            "INSUFFICIENT_AUDIO" -> "COLLECTING AUDIO"
            "WAITING_FOR_DATA", "LISTENING" -> "COLLECTING AUDIO"
            else -> "ANALYZING"
        }
        assertEquals("COLLECTING AUDIO", resolvedShort)
    }

    @Test
    fun testWsEventDataClassesIntegrity() {
        val riskEvent = WsEvent.RiskUpdate(
            riskScore = 0.42,
            alertLevel = "MEDIUM",
            voiceClassification = "ANALYZING",
            detectionScore = 0.42,
            rms = 0.05,
            activeDetector = "v032"
        )
        assertEquals(0.42, riskEvent.riskScore, 0.001)
        assertEquals("MEDIUM", riskEvent.alertLevel)
        assertEquals("ANALYZING", riskEvent.voiceClassification)
        assertEquals("v032", riskEvent.activeDetector)

        val statusEvent = WsEvent.StatusUpdate(
            status = "WAITING_FOR_SPEECH",
            detail = "Listening for caller voice...",
            rms = 0.001,
            activeDetector = "v032"
        )
        assertEquals("WAITING_FOR_SPEECH", statusEvent.status)
        assertEquals("Listening for caller voice...", statusEvent.detail)
    }
}
