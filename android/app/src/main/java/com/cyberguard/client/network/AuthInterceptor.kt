package com.cyberguard.client.network

import com.cyberguard.client.model.AuthTokenProvider
import okhttp3.Interceptor
import okhttp3.Response

class AuthInterceptor(private val tokenProvider: AuthTokenProvider) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val requestBuilder = original.newBuilder()

        // Attach authentication credentials if active session exists
        val token = tokenProvider.authToken.value
        if (!token.isNullOrBlank()) {
            if (original.header("Authorization") == null) {
                requestBuilder.addHeader("Authorization", "Bearer $token")
            }
            if (original.header("Cookie") == null) {
                requestBuilder.addHeader("Cookie", "cyberguard_session=$token")
            }
        }

        // Ensure X-Threat-Scope header is applied to all threat analysis routes for enclave isolation
        val path = original.url.encodedPath
        if (path.contains("/api/threats/") && original.header("X-Threat-Scope") == null) {
            requestBuilder.addHeader("X-Threat-Scope", "phishing_and_url")
        }

        return chain.proceed(requestBuilder.build())
    }
}
