package com.cyberguard.client

import com.cyberguard.client.model.AuthTokenProvider
import com.cyberguard.client.network.AuthInterceptor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.*
import org.junit.Assert.*
import org.junit.Test

class AuthInterceptorTest {

    private class FakeTokenProvider(initialToken: String? = null) : AuthTokenProvider {
        private val _token = MutableStateFlow(initialToken)
        override val authToken: StateFlow<String?> = _token

        fun setToken(token: String?) {
            _token.value = token
        }
    }

    @Test
    fun testThreatEndpointAddsEnclaveScopeHeader() {
        val provider = FakeTokenProvider(null)
        val interceptor = AuthInterceptor(provider)

        var capturedRequest: Request? = null

        val client = OkHttpClient.Builder()
            .addInterceptor(interceptor)
            .addInterceptor { chain ->
                capturedRequest = chain.request()
                Response.Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(200)
                    .message("OK")
                    .body(ResponseBody.create(null, "{}"))
                    .build()
            }
            .build()

        val request = Request.Builder()
            .url("http://localhost:3000/api/threats/image")
            .build()

        client.newCall(request).execute()

        assertNotNull(capturedRequest)
        assertEquals("phishing_and_url", capturedRequest?.header("X-Threat-Scope"))
        assertNull(capturedRequest?.header("Authorization"))
        assertNull(capturedRequest?.header("Cookie"))
    }

    @Test
    fun testAuthenticatedUserAttachesBearerAndCookieHeaders() {
        val provider = FakeTokenProvider("jwt-secret-tenant-token-999")
        val interceptor = AuthInterceptor(provider)

        var capturedRequest: Request? = null

        val client = OkHttpClient.Builder()
            .addInterceptor(interceptor)
            .addInterceptor { chain ->
                capturedRequest = chain.request()
                Response.Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(200)
                    .message("OK")
                    .body(ResponseBody.create(null, "{}"))
                    .build()
            }
            .build()

        val request = Request.Builder()
            .url("http://localhost:3000/api/incidents/")
            .build()

        client.newCall(request).execute()

        assertNotNull(capturedRequest)
        assertEquals("Bearer jwt-secret-tenant-token-999", capturedRequest?.header("Authorization"))
        assertEquals("cyberguard_session=jwt-secret-tenant-token-999", capturedRequest?.header("Cookie"))
        assertNull(capturedRequest?.header("X-Threat-Scope"))
    }

    @Test
    fun testThreatEndpointWithAuthenticatedUserAttachesBothHeaders() {
        val provider = FakeTokenProvider("jwt-secret-tenant-token-999")
        val interceptor = AuthInterceptor(provider)

        var capturedRequest: Request? = null

        val client = OkHttpClient.Builder()
            .addInterceptor(interceptor)
            .addInterceptor { chain ->
                capturedRequest = chain.request()
                Response.Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(200)
                    .message("OK")
                    .body(ResponseBody.create(null, "{}"))
                    .build()
            }
            .build()

        val request = Request.Builder()
            .url("http://localhost:3000/api/threats/qr")
            .build()

        client.newCall(request).execute()

        assertNotNull(capturedRequest)
        assertEquals("Bearer jwt-secret-tenant-token-999", capturedRequest?.header("Authorization"))
        assertEquals("cyberguard_session=jwt-secret-tenant-token-999", capturedRequest?.header("Cookie"))
        assertEquals("phishing_and_url", capturedRequest?.header("X-Threat-Scope"))
    }
}
