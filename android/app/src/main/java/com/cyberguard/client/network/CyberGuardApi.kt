package com.cyberguard.client.network

import okhttp3.MultipartBody
import okhttp3.RequestBody
import retrofit2.http.*

interface CyberGuardApi {

    @GET("health")
    suspend fun getHealth(): HealthResponse

    @Multipart
    @POST("api/analyze")
    suspend fun analyzeAudio(
        @Part file: MultipartBody.Part,
        @Part("speaker_id") speakerId: RequestBody? = null
    ): AnalysisResponse

    @Multipart
    @POST("api/speakers/enroll")
    suspend fun enrollSpeaker(
        @Part("name") name: RequestBody,
        @Part files: List<MultipartBody.Part>,
        @Part("speaker_id") speakerId: RequestBody? = null,
        @Part("organization") organization: RequestBody? = null,
        @Part("role") role: RequestBody? = null
    ): EnrollResponse

    @GET("api/speakers")
    suspend fun listSpeakers(): List<SpeakerInfo>

    @DELETE("api/speakers/{id}")
    suspend fun deleteSpeaker(@Path("id") speakerId: String)

    @GET("api/alerts/recent")
    suspend fun getRecentAlerts(@Query("limit") limit: Int = 50): AlertHistoryResponse

    @GET("api/config/status")
    suspend fun getStatus(): StatusResponse

    // Authentication & User Identity Lifecycle
    @POST("api/auth/login")
    suspend fun login(@Body req: LoginRequest): AuthResponse

    @POST("api/auth/register")
    suspend fun register(@Body req: RegisterRequest): AuthResponse

    @POST("api/auth/logout")
    suspend fun logout(): Map<String, Any>

    @GET("api/auth/me")
    suspend fun getMe(): UserResponse?

    @POST("api/auth/change-password")
    suspend fun changePassword(@Body req: ChangePasswordRequest): Map<String, Any>

    @GET("api/history/me")
    suspend fun getMyAnalysisHistory(@Query("limit") limit: Int = 50): List<AnalysisHistoryItem>

    // Multi-Modal Image & Deepfake Forensics
    @Headers("X-Threat-Scope: phishing_and_url")
    @Multipart
    @POST("api/threats/image")
    suspend fun analyzeImage(
        @Part file: MultipartBody.Part,
        @Part("source") source: RequestBody? = null,
        @Part("correlation_id") correlationId: RequestBody? = null
    ): ThreatEvent

    // Adversarial QR Code / Quishing Forensics
    @Headers("X-Threat-Scope: phishing_and_url")
    @Multipart
    @POST("api/threats/qr")
    suspend fun scanQrImage(
        @Part file: MultipartBody.Part,
        @Part("source") source: RequestBody? = null,
        @Part("correlation_id") correlationId: RequestBody? = null
    ): ThreatEvent

    // Threat Intelligence: URL Scanning
    @Headers("X-Threat-Scope: phishing_and_url")
    @FormUrlEncoded
    @POST("api/threats/url")
    suspend fun scanUrl(
        @Field("url") url: String,
        @Field("source") source: String = "android_client",
        @Field("correlation_id") correlationId: String? = null
    ): ThreatEvent

    // Threat Intelligence: Phishing & Text Analysis
    @Headers("X-Threat-Scope: phishing_and_url")
    @FormUrlEncoded
    @POST("api/threats/phishing")
    suspend fun analyzePhishing(
        @Field("text") text: String,
        @Field("source") source: String = "android_client",
        @Field("correlation_id") correlationId: String? = null
    ): ThreatEvent

    // Cognitive AI Qwen LLM Threat Analysis
    @Headers("X-Threat-Scope: phishing_and_url")
    @POST("api/threats/llm-analysis")
    suspend fun askQwenLlm(
        @Body request: Map<String, Any>
    ): LlmAnalysisResponse

    @Headers("X-Threat-Scope: phishing_and_url")
    @POST("api/threats/llm-analysis")
    suspend fun askLlmCopilot(
        @Body request: Map<String, Any>
    ): LlmAnalysisResponse

    // Sequential Threat Intel Search (VirusTotal + URLhaus + Correlation)
    @Headers("X-Threat-Scope: phishing_and_url")
    @GET("api/threats/search")
    suspend fun searchThreatIntel(
        @Query("ioc") ioc: String,
        @Query("correlation_id") correlationId: String? = null
    ): ThreatEvent

    // Threat Feeds & Engine Pipelines
    @Headers("X-Threat-Scope: phishing_and_url")
    @GET("api/threats/pipeline/status")
    suspend fun getPipelineStatus(): PipelineStatusResponse

    @Headers("X-Threat-Scope: phishing_and_url")
    @GET("api/threats/virustotal/status")
    suspend fun getVirusTotalStatus(): FeedStatusResponse

    @Headers("X-Threat-Scope: phishing_and_url")
    @GET("api/threats/urlhaus/status")
    suspend fun getUrlhausStatus(): FeedStatusResponse

    @Headers("X-Threat-Scope: phishing_and_url")
    @GET("api/threats/enclave/metrics")
    suspend fun getEnclaveMetrics(): EnclaveMetricsResponse

    // Incident Case Management
    @GET("api/incidents")
    suspend fun getIncidents(@Query("limit") limit: Int = 50): List<Incident>

    @GET("api/incidents/dashboard/summary")
    suspend fun getIncidentSummary(): IncidentSummaryResponse

    @PUT("api/incidents/{id}/status")
    suspend fun updateIncidentStatus(
        @Path("id") incidentId: String,
        @Body body: IncidentUpdateStatusRequest
    ): Incident

    // Administrator & Model Governance Endpoints
    @GET("api/admin/users")
    suspend fun getAdminUsers(): List<AdminUserItem>

    @POST("api/admin/users")
    suspend fun createAdminUser(@Body req: CreateUserRequest): AdminUserItem

    @PUT("api/admin/users/{id}/status")
    suspend fun updateAdminUserStatus(
        @Path("id") userId: Int,
        @Body req: UpdateUserStatusRequest
    ): Map<String, Any>

    @DELETE("api/admin/users/{id}")
    suspend fun deleteAdminUser(
        @Path("id") userId: Int,
        @Query("confirm_username") confirmUsername: String? = null
    ): Map<String, Any>

    @GET("api/admin/reviews")
    suspend fun getReviewQueue(
        @Query("status") status: String? = null,
        @Query("risk") risk: String? = null,
        @Query("q") search: String? = null,
        @Query("limit") limit: Int = 100,
        @Query("offset") offset: Int = 0
    ): ReviewQueueResponse

    @POST("api/admin/reviews/{id}/decision")
    suspend fun submitReviewDecision(
        @Path("id") reviewId: String,
        @Body req: ReviewDecisionRequest
    ): Map<String, Any>

    @GET("api/admin/training/status")
    suspend fun getTrainingStatus(): TrainingStatusResponse

    @POST("api/admin/training/trigger")
    suspend fun triggerRetraining(
        @Query("epochs") epochs: Int? = null,
        @Query("learning_rate") learningRate: Float? = null
    ): Map<String, Any>

    @GET("api/admin/audit-logs")
    suspend fun getAdminAuditLogs(
        @Query("limit") limit: Int = 50,
        @Query("offset") offset: Int = 0
    ): AdminAuditLogsResponse

    @POST("api/threats/verify-oem-app")
    suspend fun verifyOemApp(@Body req: Map<String, @JvmSuppressWildcards Any>): Map<String, Any?>
}

typealias VoiceGuardApi = CyberGuardApi

