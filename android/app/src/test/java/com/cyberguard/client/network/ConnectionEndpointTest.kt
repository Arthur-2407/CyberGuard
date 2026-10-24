package com.cyberguard.client.network

import org.junit.Assert.*
import org.junit.Test

class ConnectionEndpointTest {

    @Test
    fun testIsCloudUrlIdentification() {
        assertTrue(ConnectionManager.isCloudUrl("https://cyber-guard-backend-ashen.vercel.app"))
        assertTrue(ConnectionManager.isCloudUrl("cyber-guard-backend-ashen.vercel.app"))
        assertTrue(ConnectionManager.isCloudUrl("https://cyber-guard-backend-j3bo9l8hm-arthur-03fc.vercel.app"))
        assertTrue(ConnectionManager.isCloudUrl("https://arthur-2407.github.io/CyberGuard/"))
        assertTrue(ConnectionManager.isCloudUrl("my-defense.pages.dev"))

        assertFalse(ConnectionManager.isCloudUrl("192.168.29.1"))
        assertFalse(ConnectionManager.isCloudUrl("10.0.2.2"))
        assertFalse(ConnectionManager.isCloudUrl("127.0.0.1"))
        assertFalse(ConnectionManager.isCloudUrl("192.168.1.100"))
    }

    @Test
    fun testFormatEndpointUrl() {
        // Local candidates on port 3000
        val localFormatted = ConnectionManager.formatEndpointUrl("192.168.29.1", 3000)
        assertEquals("http://192.168.29.1:3000/", localFormatted)

        val emuFormatted = ConnectionManager.formatEndpointUrl("10.0.2.2", 3000)
        assertEquals("http://10.0.2.2:3000/", emuFormatted)

        // Deployed cloud node on HTTPS
        val cloudFormatted = ConnectionManager.formatEndpointUrl("cyber-guard-backend-ashen.vercel.app")
        assertEquals("https://cyber-guard-backend-ashen.vercel.app/", cloudFormatted)

        val fullCloudFormatted = ConnectionManager.formatEndpointUrl("https://cyber-guard-backend-ashen.vercel.app")
        assertEquals("https://cyber-guard-backend-ashen.vercel.app/", fullCloudFormatted)
    }

    @Test
    fun testDefaultCloudBackendUrlConstants() {
        assertNotNull(ConnectionManager.DEFAULT_CLOUD_BACKEND_URL)
        assertTrue(ConnectionManager.DEFAULT_CLOUD_BACKEND_URL.startsWith("https://"))
        assertTrue(ConnectionManager.CLOUD_BACKEND_FALLBACKS.isNotEmpty())
        assertTrue(ConnectionManager.CLOUD_BACKEND_FALLBACKS.contains(ConnectionManager.DEFAULT_CLOUD_BACKEND_URL))
    }
}
