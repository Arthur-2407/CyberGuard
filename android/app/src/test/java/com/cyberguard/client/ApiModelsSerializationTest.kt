package com.cyberguard.client

import com.cyberguard.client.network.*
import com.google.gson.Gson
import org.junit.Assert.*
import org.junit.Test

class ApiModelsSerializationTest {

    private val gson = Gson()

    @Test
    fun testAuthResponseDeserialization() {
        val json = """
            {
                "token": "test-jwt-token-xyz-123",
                "user": {
                    "id": 456,
                    "username": "sec_operator",
                    "email": "operator@cyberguard.internal",
                    "role": "analyst",
                    "is_active": true
                }
            }
        """.trimIndent()

        val response = gson.fromJson(json, AuthResponse::class.java)

        assertEquals("test-jwt-token-xyz-123", response.token)
        assertEquals(456, response.user.id)
        assertEquals("sec_operator", response.user.username)
        assertEquals("operator@cyberguard.internal", response.user.email)
        assertEquals("analyst", response.user.role)
        assertTrue(response.user.isActive)
    }

    @Test
    fun testThreatEventDeserialization() {
        val json = """
            {
                "event_id": "evt_qr_101",
                "modality": "image",
                "threat_category": "quishing_adversarial_qr",
                "severity": "CRITICAL",
                "confidence": 0.94,
                "classification": "MALICIOUS",
                "mitre_technique_id": "T1566.002",
                "threat_score": 0.88,
                "evidence": [
                    {
                        "evidence_type": "url_extracted",
                        "description": "Suspicious login target",
                        "value": "https://malicious-login-auth.com",
                        "severity_contribution": 0.85
                    }
                ]
            }
        """.trimIndent()

        val response = gson.fromJson(json, ThreatEvent::class.java)

        assertEquals("evt_qr_101", response.eventId)
        assertEquals("image", response.modality)
        assertEquals("quishing_adversarial_qr", response.threatCategory)
        assertEquals("CRITICAL", response.severity)
        assertEquals(0.94f, response.confidence, 0.001f)
        assertEquals("T1566.002", response.mitreTechniqueId)
        assertEquals(0.88f, response.threatScore ?: 0f, 0.001f)
        assertEquals(1, response.evidence.size)
        assertEquals("https://malicious-login-auth.com", response.evidence[0].value)
    }

    @Test
    fun testIncidentDeserialization() {
        val json = """
            {
                "incident_id": "inc_2026_001_abc",
                "category": "deepfake_voice_injection",
                "risk": "CRITICAL",
                "status": "INVESTIGATING",
                "event_count": 5,
                "affected_assets": ["mobile_gateway_01", "operator_mic"],
                "recommendations": ["Isolate line", "Rotate session keys"],
                "timestamp": "2026-10-19T12:00:00Z"
            }
        """.trimIndent()

        val response = gson.fromJson(json, Incident::class.java)

        assertEquals("inc_2026_001_abc", response.incidentId)
        assertEquals("deepfake_voice_injection", response.category)
        assertEquals("CRITICAL", response.risk)
        assertEquals("INVESTIGATING", response.status)
        assertEquals(5, response.eventCount)
        assertEquals(2, response.affectedAssets.size)
        assertTrue(response.affectedAssets.contains("mobile_gateway_01"))
        assertEquals("Isolate line", response.recommendations[0])
    }

    @Test
    fun testIncidentSummaryDeserialization() {
        val json = """
            {
                "total_incidents": 14,
                "open_incidents": 3,
                "critical_threats": 2,
                "high_critical_threats": 4,
                "total_events_analyzed": 128
            }
        """.trimIndent()

        val response = gson.fromJson(json, IncidentSummaryResponse::class.java)

        assertEquals(14, response.totalIncidents)
        assertEquals(3, response.openIncidents)
        assertEquals(2, response.criticalThreats)
        assertEquals(4, response.highCriticalThreats)
        assertEquals(128, response.totalEventsAnalyzed)
    }

    @Test
    fun testEnclaveMetricsDeserialization() {
        val json = """
            {
                "total_requests": 420,
                "tokens_saved": 18500,
                "cache_hits": 310,
                "cache_misses": 110,
                "enclave_blocks": 4,
                "active_scope": "phishing_and_url"
            }
        """.trimIndent()

        val response = gson.fromJson(json, EnclaveMetricsResponse::class.java)

        assertEquals(420, response.totalRequests)
        assertEquals(18500, response.tokensSaved)
        assertEquals(310, response.cacheHits)
        assertEquals(110, response.cacheMisses)
        assertEquals(4, response.enclaveBlocks)
        assertEquals("phishing_and_url", response.activeScope)
    }

    @Test
    fun testLoginRequestSerialization() {
        val req = LoginRequest(username = "admin_user", password = "SecureSecretPassword123!")
        val json = gson.toJson(req)

        assertTrue(json.contains("\"username\":\"admin_user\""))
        assertTrue(json.contains("\"password\":\"SecureSecretPassword123!\""))
    }
}
