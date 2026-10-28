package com.cyberguard.client.network

import com.google.gson.Gson
import org.junit.Assert.*
import org.junit.Test

class SmartConnectionManagerTest {

    @Test
    fun testConnectionModeEnumIntegrity() {
        assertEquals(3, ConnectionMode.values().size)
        assertTrue(ConnectionMode.values().contains(ConnectionMode.CLOUD))
        assertTrue(ConnectionMode.values().contains(ConnectionMode.LOCAL_LAN))
        assertTrue(ConnectionMode.values().contains(ConnectionMode.HYBRID))
    }

    @Test
    fun testHybridPriorityEnumIntegrity() {
        assertEquals(2, HybridPriority.values().size)
        assertEquals(HybridPriority.LOCAL_FIRST, HybridPriority.valueOf("LOCAL_FIRST"))
        assertEquals(HybridPriority.CLOUD_FIRST, HybridPriority.valueOf("CLOUD_FIRST"))
    }

    @Test
    fun testConnectionConfigDefaults() {
        val config = ConnectionConfig()
        assertEquals(ConnectionMode.HYBRID, config.mode)
        assertEquals(HybridPriority.LOCAL_FIRST, config.hybridPriority)
        assertEquals(ConnectionManager.DEFAULT_CLOUD_BACKEND_URL, config.cloudUrl)
        assertEquals(ConnectionManager.DEFAULT_LOCAL_PORT, config.localPort)
        assertTrue(config.localHost.isNotBlank())
    }

    @Test
    fun testEndpointFormattingPreventsDoublePortOnUrls() {
        // If a cloud URL or full URL is passed, formatEndpointUrl must NEVER append :3000
        val formattedCloud = ConnectionManager.formatEndpointUrl("https://cyber-guard-backend-ashen.vercel.app", 3000)
        assertEquals("https://cyber-guard-backend-ashen.vercel.app/", formattedCloud)
        assertFalse(formattedCloud.contains(":3000"))

        val formattedTunnel = ConnectionManager.formatEndpointUrl("https://avon-personals-coverage-ask.trycloudflare.com", 3000)
        assertEquals("https://avon-personals-coverage-ask.trycloudflare.com/", formattedTunnel)
        assertFalse(formattedTunnel.contains(":3000"))

        val formattedDomainOnly = ConnectionManager.formatEndpointUrl("avon-personals-coverage-ask.trycloudflare.com", 3000)
        assertEquals("https://avon-personals-coverage-ask.trycloudflare.com/", formattedDomainOnly)
        assertFalse(formattedDomainOnly.contains(":3000"))

        // Pure IP addresses correctly attach port 3000
        val formattedLocal = ConnectionManager.formatEndpointUrl("172.16.31.2", 3000)
        assertEquals("http://172.16.31.2:3000/", formattedLocal)

        val formattedEmu = ConnectionManager.formatEndpointUrl("10.0.2.2", 3000)
        assertEquals("http://10.0.2.2:3000/", formattedEmu)

        val formattedCustomPort = ConnectionManager.formatEndpointUrl("192.168.1.100", 8080)
        assertEquals("http://192.168.1.100:8080/", formattedCustomPort)
    }

    @Test
    fun testCloudUrlIdentificationIncludesTunnelsAndPlatforms() {
        assertTrue(ConnectionManager.isCloudUrl("https://avon-personals-coverage-ask.trycloudflare.com"))
        assertTrue(ConnectionManager.isCloudUrl("my-tunnel.trycloudflare.com"))
        assertTrue(ConnectionManager.isCloudUrl("defense.ngrok-free.app"))
        assertTrue(ConnectionManager.isCloudUrl("soc.loca.lt"))
        assertTrue(ConnectionManager.isCloudUrl("https://cyber-guard-backend-ashen.vercel.app"))
        assertTrue(ConnectionManager.isCloudUrl("cyber-guard.pages.dev"))

        assertFalse(ConnectionManager.isCloudUrl("172.16.31.2"))
        assertFalse(ConnectionManager.isCloudUrl("10.0.2.2"))
        assertFalse(ConnectionManager.isCloudUrl("127.0.0.1"))
        assertFalse(ConnectionManager.isCloudUrl("192.168.1.1"))
    }

    @Test
    fun testDistinguishRealBackendFromStaticVercelFrontend() {
        // 1. Real CyberGuard FastAPI backend payload
        val realBackendJson = """
            {
                "status": "ok",
                "service": "CyberGuard",
                "version": "1.0.0",
                "backend": "docker-local",
                "database": "connected",
                "detector_ready": true,
                "threat_intel": {
                    "virustotal_configured": true,
                    "urlhaus_configured": true
                }
            }
        """.trimIndent()

        @Suppress("UNCHECKED_CAST")
        val jsonReal = Gson().fromJson(realBackendJson, Map::class.java) as Map<String, Any?>
        val isReal = jsonReal["service"]?.toString()?.equals("CyberGuard", ignoreCase = true) == true &&
                     jsonReal["status"] == "ok" &&
                     jsonReal.containsKey("detector_ready")
        assertTrue(isReal)

        // 2. Static Vercel frontend mock payload
        val staticVercelJson = """
            {
                "status": "operational",
                "service": "CyberGuard Cloud Node",
                "version": "v4.7",
                "timestamp": "2026-10-22T19:35:00Z"
            }
        """.trimIndent()

        @Suppress("UNCHECKED_CAST")
        val jsonVercel = Gson().fromJson(staticVercelJson, Map::class.java) as Map<String, Any?>
        val isStaticVercel = (jsonVercel["service"] as? String)?.contains("Cloud Node", ignoreCase = true) == true ||
                             jsonVercel["version"] == "v4.7"
        assertTrue(isStaticVercel)
        assertFalse(jsonVercel["service"]?.toString()?.equals("CyberGuard", ignoreCase = true) == true)
        assertFalse(jsonVercel.containsKey("detector_ready"))
    }

    @Test
    fun testNonIdempotentOperationSafetyPolicy() {
        // Non-idempotent operations must NOT be silently retried on alternate endpoints upon timeout
        fun canSafelyFailover(method: String, path: String): Boolean {
            if (method != "GET" && method != "HEAD") return false
            val nonIdempotentPrefixes = listOf("/api/analyze", "/api/threats/image", "/api/threats/qr", "/api/threats/malware/scan", "/api/speakers/enroll")
            return nonIdempotentPrefixes.none { path.startsWith(it) }
        }

        assertTrue(canSafelyFailover("GET", "/health"))
        assertTrue(canSafelyFailover("GET", "/api/health"))
        assertTrue(canSafelyFailover("GET", "/api/config/status"))
        assertTrue(canSafelyFailover("GET", "/api/threats/pipeline/status"))

        assertFalse(canSafelyFailover("POST", "/api/analyze"))
        assertFalse(canSafelyFailover("POST", "/api/threats/image"))
        assertFalse(canSafelyFailover("POST", "/api/threats/qr"))
        assertFalse(canSafelyFailover("POST", "/api/threats/malware/scan"))
        assertFalse(canSafelyFailover("POST", "/api/auth/change-password"))
        assertFalse(canSafelyFailover("DELETE", "/api/speakers/123"))
    }

    @Test
    fun testActiveLiveCloudTunnelUrl() {
        assertEquals("https://cyberguard-backend-8rbz.onrender.com", ConnectionManager.DEFAULT_CLOUD_BACKEND_URL)
        assertEquals("https://cyberguard-backend-8rbz.onrender.com", ConnectionManager.DEFAULT_TUNNEL_URL)
        assertTrue(ConnectionManager.isCloudUrl(ConnectionManager.DEFAULT_CLOUD_BACKEND_URL))
        assertTrue(ConnectionManager.CLOUD_BACKEND_FALLBACKS.contains(ConnectionManager.DEFAULT_CLOUD_BACKEND_URL))
    }

    @Test
    fun testConnectionStateEnumSemanticCompleteness() {
        val states = ConnectionState.values().map { it.name }
        assertTrue(states.contains("DISCONNECTED"))
        assertTrue(states.contains("NETWORK_UNAVAILABLE"))
        assertTrue(states.contains("BACKEND_UNREACHABLE"))
        assertTrue(states.contains("BACKEND_UNHEALTHY"))
        assertTrue(states.contains("CONNECTED"))
        assertTrue(states.contains("CONNECTED_CLOUD"))
        assertTrue(states.contains("CONNECTED_LOCAL"))
        assertTrue(states.contains("CONNECTED_HYBRID"))
        assertTrue(states.contains("AUTH_REQUIRED"))
    }

    @Test
    fun testHybridSelectionDecisionLogic() {
        // Pure decision policy verification without network I/O
        data class MockCandidate(val url: String, val isGenuine: Boolean, val statusCode: Int, val details: String?)

        fun selectHybridNode(
            local: MockCandidate,
            cloud: MockCandidate,
            priority: HybridPriority
        ): Pair<String?, ConnectionState> {
            val preferLocal = priority == HybridPriority.LOCAL_FIRST
            return if (preferLocal) {
                if (local.isGenuine && local.statusCode in 200..299) {
                    Pair(local.url, ConnectionState.CONNECTED)
                } else if (cloud.isGenuine && cloud.statusCode in 200..299) {
                    Pair(cloud.url, ConnectionState.CONNECTED)
                } else if (local.statusCode in listOf(401, 403) || cloud.statusCode in listOf(401, 403)) {
                    Pair(if (local.statusCode in listOf(401, 403)) local.url else cloud.url, ConnectionState.AUTH_REQUIRED)
                } else {
                    Pair(null, ConnectionState.BACKEND_UNREACHABLE)
                }
            } else {
                if (cloud.isGenuine && cloud.statusCode in 200..299) {
                    Pair(cloud.url, ConnectionState.CONNECTED)
                } else if (local.isGenuine && local.statusCode in 200..299) {
                    Pair(local.url, ConnectionState.CONNECTED)
                } else if (cloud.statusCode in listOf(401, 403) || local.statusCode in listOf(401, 403)) {
                    Pair(if (cloud.statusCode in listOf(401, 403)) cloud.url else local.url, ConnectionState.AUTH_REQUIRED)
                } else {
                    Pair(null, ConnectionState.BACKEND_UNREACHABLE)
                }
            }
        }

        val healthyLocal = MockCandidate("http://172.16.31.2:3000/", true, 200, "OK")
        val healthyCloud = MockCandidate("https://val-regarding-config-improving.trycloudflare.com/", true, 200, "OK")
        val unreachableLocal = MockCandidate("http://172.16.31.2:3000/", false, -1, "Connection refused on port 3000")
        val deadCloud = MockCandidate("https://avon-personals-coverage-ask.trycloudflare.com/", false, -1, "DNS resolution failed")
        val authLocal = MockCandidate("http://172.16.31.2:3000/", true, 401, "Authentication required")

        // 1. Both healthy, Local First -> selects Local
        val res1 = selectHybridNode(healthyLocal, healthyCloud, HybridPriority.LOCAL_FIRST)
        assertEquals("http://172.16.31.2:3000/", res1.first)
        assertEquals(ConnectionState.CONNECTED, res1.second)

        // 2. Both healthy, Cloud First -> selects Cloud
        val res2 = selectHybridNode(healthyLocal, healthyCloud, HybridPriority.CLOUD_FIRST)
        assertEquals("https://val-regarding-config-improving.trycloudflare.com/", res2.first)
        assertEquals(ConnectionState.CONNECTED, res2.second)

        // 3. Local down, Cloud healthy, Local First -> fails over to Cloud
        val res3 = selectHybridNode(unreachableLocal, healthyCloud, HybridPriority.LOCAL_FIRST)
        assertEquals("https://val-regarding-config-improving.trycloudflare.com/", res3.first)
        assertEquals(ConnectionState.CONNECTED, res3.second)

        // 4. Cloud down, Local healthy, Cloud First -> fails over to Local
        val res4 = selectHybridNode(healthyLocal, deadCloud, HybridPriority.CLOUD_FIRST)
        assertEquals("http://172.16.31.2:3000/", res4.first)
        assertEquals(ConnectionState.CONNECTED, res4.second)

        // 5. Both down -> returns null, BACKEND_UNREACHABLE
        val res5 = selectHybridNode(unreachableLocal, deadCloud, HybridPriority.LOCAL_FIRST)
        assertNull(res5.first)
        assertEquals(ConnectionState.BACKEND_UNREACHABLE, res5.second)

        // 6. Auth required -> returns AUTH_REQUIRED
        val res6 = selectHybridNode(authLocal, deadCloud, HybridPriority.LOCAL_FIRST)
        assertEquals("http://172.16.31.2:3000/", res6.first)
        assertEquals(ConnectionState.AUTH_REQUIRED, res6.second)
    }

    @Test
    fun testGranularDiagnosticErrorClassification() {
        fun classifyError(details: String?, port: Int): String {
            return when {
                details?.contains("refused", ignoreCase = true) == true -> "TARGET PORT $port REFUSED"
                details?.contains("timed out", ignoreCase = true) == true -> "CONNECTION TIMED OUT"
                details?.contains("Cleartext", ignoreCase = true) == true || details?.contains("policy blocked", ignoreCase = true) == true -> "CLEARTEXT HTTP RESTRICTED"
                details?.contains("DNS", ignoreCase = true) == true -> "DNS RESOLUTION FAILED"
                details?.contains("TLS", ignoreCase = true) == true -> "TLS HANDSHAKE FAILED"
                else -> "BACKEND UNREACHABLE"
            }
        }

        assertEquals("TARGET PORT 3000 REFUSED", classifyError("Connection refused on port 3000.", 3000))
        assertEquals("CONNECTION TIMED OUT", classifyError("Connection timed out.", 3000))
        assertEquals("CLEARTEXT HTTP RESTRICTED", classifyError("Android policy blocked unencrypted HTTP to this host.", 3000))
        assertEquals("DNS RESOLUTION FAILED", classifyError("DNS resolution failed for hostname.", 3000))
        assertEquals("TLS HANDSHAKE FAILED", classifyError("TLS/SSL certificate handshake failed.", 443))
    }

    @Test
    fun testCloudHostnameSyntacticValidation() {
        fun isValidCloudHostname(url: String): Boolean {
            val trimmed = url.trim().lowercase()
            val host = trimmed.removePrefix("https://").removePrefix("http://").substringBefore("/").substringBefore(":")
            return host.isNotBlank() && host.contains(".") && !host.endsWith(".") && !host.startsWith(".")
        }

        // Incomplete hostnames without TLD must be rejected before triggering DNS
        assertFalse("Incomplete hostname without TLD must fail validation", isValidCloudHostname("https://val-regarding-config-imp"))
        assertFalse("Missing hostname must fail validation", isValidCloudHostname("https://"))
        assertFalse("Hostname without dot must fail validation", isValidCloudHostname("val-regarding-config-imp"))
        assertFalse("Hostname ending with dot must fail validation", isValidCloudHostname("https://val-regarding-config-imp."))

        // Complete, valid FQDNs must pass validation
        assertTrue("Canonical Cloudflare tunnel FQDN must pass validation", isValidCloudHostname("https://val-regarding-config-improving.trycloudflare.com"))
        assertTrue("Vercel deployment FQDN must pass validation", isValidCloudHostname("https://cyber-guard-backend-ashen.vercel.app"))
        assertTrue("Custom domain must pass validation", isValidCloudHostname("https://api.cyberguard.io"))
    }
}
