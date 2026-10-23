package com.cyberguard.client.network

import com.google.gson.annotations.SerializedName

data class HealthResponse(
    val status: String,
    val service: String,
    val version: String
)

data class Recommendation(
    val title: String,
    val message: String,
    val actions: List<String>,
    val color: String
)

data class ChunkScore(
    @SerializedName("chunk_id") val chunkId: Int,
    @SerializedName("detection_score") val detectionScore: Float,
    @SerializedName("risk_score") val riskScore: Float,
    @SerializedName("alert_level") val alertLevel: String,
    @SerializedName("processing_ms") val processingMs: Float
)

data class AnalysisResponse(
    @SerializedName("session_id") val sessionId: String,
    val filename: String,
    @SerializedName("total_chunks") val totalChunks: Int,
    @SerializedName("peak_risk") val peakRisk: Float,
    @SerializedName("mean_risk") val meanRisk: Float,
    @SerializedName("final_risk") val finalRisk: Float,
    @SerializedName("alert_level") val alertLevel: String,
    val recommendation: Recommendation,
    @SerializedName("chunk_scores") val chunkScores: List<ChunkScore>,
    @SerializedName("processing_time_ms") val processingTimeMs: Float
)

data class SpeakerInfo(
    @SerializedName("speaker_id") val speakerId: String,
    val name: String,
    val organization: String?,
    val role: String?,
    @SerializedName("num_samples") val numSamples: Int,
    @SerializedName("created_at") val createdAt: String?
)

data class EnrollResponse(
    @SerializedName("speaker_id") val speakerId: String,
    val name: String,
    @SerializedName("num_samples") val numSamples: Int,
    val message: String
)

data class Alert(
    @SerializedName("session_id") val sessionId: String?,
    @SerializedName("chunk_id") val chunkId: Int?,
    val timestamp: Double,
    @SerializedName("risk_score") val riskScore: Float,
    @SerializedName("alert_level") val alertLevel: String,
    @SerializedName("recommendation_title") val recommendationTitle: String?,
    @SerializedName("recommendation_message") val recommendationMessage: String?,
    @SerializedName("speaker_id") val speakerId: String?
)

data class AlertHistoryResponse(
    val alerts: List<Alert>
)

data class ThresholdConfig(
    val low: Float,
    val medium: Float,
    val high: Float
)

data class StatusResponse(
    val status: String,
    @SerializedName("active_detector_version") val activeDetectorVersion: String? = null,
    @SerializedName("detector_version") val detectorVersion: String? = null,
    @SerializedName("detector_initialized") val detectorInitialized: Boolean,
    @SerializedName("connected_clients") val connectedClients: Int,
    @SerializedName("operational_engine_count") val operationalEngineCount: Int = 0,
    @SerializedName("total_engine_count") val totalEngineCount: Int = 0,
    @SerializedName("detector_mode") val detectorMode: String? = null,
    @SerializedName("capabilities") val capabilities: Map<String, String>? = null
)

fun Throwable.toUserFacingErrorMessage(): String {
    if (this is retrofit2.HttpException) {
        val errorBody = this.response()?.errorBody()?.string()
        if (!errorBody.isNullOrBlank()) {
            try {
                val json = org.json.JSONObject(errorBody)
                if (json.has("detail")) {
                    return json.getString("detail")
                }
                if (json.has("message")) {
                    return json.getString("message")
                }
            } catch (_: Exception) {}
        }
        return when (this.code()) {
            401 -> "Invalid username or password."
            403 -> "Access denied: Account suspended or insufficient privileges."
            404 -> "Requested endpoint not found."
            422 -> "Validation error: Check your input."
            500 -> "CyberGuard core server encountered an error."
            else -> "Request failed (${this.code()})"
        }
    }
    if (this is java.net.ConnectException || this is java.net.SocketTimeoutException) {
        return "Cannot connect to CyberGuard core server. Verify Wi-Fi network."
    }
    return this.message ?: "An unexpected error occurred."
}


// Threat Forensics & Intelligence Models
data class EvidenceItem(
    @SerializedName("evidence_type") val evidenceType: String = "",
    val description: String = "",
    val value: String? = null,
    @SerializedName("severity_contribution") val severityContribution: Float = 0f,
    val confidence: Float = 1f,
    val source: String = ""
)

data class ThreatExplanation(
    val summary: String = "",
    val reasoning: String = "",
    val limitations: String? = null
)

data class ThreatEvent(
    @SerializedName("event_id") val eventId: String = "",
    val timestamp: Double = 0.0,
    val source: String = "",
    @SerializedName("source_type") val sourceType: String = "",
    val modality: String = "",
    @SerializedName("threat_category") val threatCategory: String = "",
    val subcategory: String? = null,
    val severity: String = "SAFE",
    val confidence: Float = 0f,
    val classification: String = "",
    val evidence: List<EvidenceItem> = emptyList(),
    val explanation: ThreatExplanation? = null,
    @SerializedName("recommended_actions") val recommendedActions: List<String> = emptyList(),
    val detector: String = "",
    @SerializedName("detector_version") val detectorVersion: String = "1.0",
    @SerializedName("processing_time_ms") val processingTimeMs: Float = 0f,
    @SerializedName("mitre_technique_id") val mitreTechniqueId: String? = null,
    @SerializedName("mitre_technique_name") val mitreTechniqueName: String? = null,
    @SerializedName("threat_score") val threatScore: Float? = null,
    @SerializedName("threat_intelligence") val threatIntelligence: Map<String, Any>? = null,
    @SerializedName("forensic_metrics") val forensicMetrics: Map<String, Any>? = null,
    @SerializedName("media_info") val mediaInfo: Map<String, Any>? = null,
    @SerializedName("metadata_details") val metadataDetails: Map<String, Any>? = null
)

// Qwen LLM Threat Analysis Models
data class MitreAttackTechnique(
    @SerializedName("technique_id") val techniqueId: String? = null,
    val id: String? = null,
    val name: String? = null,
    val tactic: String? = null,
    val desc: String? = null
)

data class PlaybookStep(
    val step: String? = null,
    val action: String? = null,
    val priority: String? = null
)

data class LlmAnalysisResponse(
    @SerializedName("assessed_severity") val assessedSeverity: String? = null,
    val confidence: Float = 0f,
    @SerializedName("executive_summary") val executiveSummary: String? = null,
    @SerializedName("executive_briefing") val executiveBriefing: String? = null,
    @SerializedName("threat_narrative") val threatNarrative: String? = null,
    val narrative: String? = null,
    @SerializedName("mitre_attack_mapping") val mitreAttackMapping: List<MitreAttackTechnique>? = null,
    @SerializedName("mitre_attack_techniques") val mitreAttackTechniques: List<MitreAttackTechnique>? = null,
    @SerializedName("kill_chain_reconstruction") val killChainReconstruction: Map<String, Any>? = null,
    @SerializedName("kill_chain_stage") val killChainStage: String? = null,
    @SerializedName("incident_response_playbook") val incidentResponsePlaybook: List<PlaybookStep>? = null,
    @SerializedName("immediate_containment") val immediateContainment: List<String>? = null,
    @SerializedName("recommended_containment_window") val recommendedContainmentWindow: String? = null
)

// Incident Management Models
data class Incident(
    @SerializedName("incident_id") val incidentId: String = "",
    val events: List<ThreatEvent> = emptyList(),
    @SerializedName("event_count") val eventCount: Int = 0,
    @SerializedName("first_seen") val firstSeen: Double = 0.0,
    @SerializedName("last_seen") val lastSeen: Double = 0.0,
    val category: String = "UNKNOWN",
    val risk: String = "LOW",
    val status: String = "NEW",
    @SerializedName("affected_assets") val affectedAssets: List<String> = emptyList(),
    val recommendations: List<String> = emptyList()
)

data class IncidentUpdateStatusRequest(
    val status: String,
    @SerializedName("analyst_notes") val analystNotes: String? = null
)

data class IncidentSummaryResponse(
    val status: String? = null,
    @SerializedName("total_incidents") val totalIncidents: Int = 0,
    @SerializedName("open_incidents") val openIncidents: Int = 0,
    @SerializedName("total_events_analyzed") val totalEventsAnalyzed: Int = 0,
    @SerializedName("high_critical_threats") val highCriticalThreats: Int = 0,
    @SerializedName("critical_threats") val criticalThreats: Int = 0
)

// Feed & Pipeline Status Models
data class PipelineStatusResponse(
    val status: String = "ACTIVE",
    val pipelines: Map<String, Any>? = null
)

data class FeedStatusResponse(
    val provider: String = "",
    val enabled: Boolean = true,
    val status: String = "ONLINE"
)

// Authentication & Identity Models
data class LoginRequest(
    @SerializedName("username_or_email") val usernameOrEmail: String? = null,
    val username: String? = null,
    val email: String? = null,
    val password: String
)

data class RegisterRequest(
    val username: String,
    val email: String,
    val password: String
)

data class UserResponse(
    val id: Int = 0,
    val username: String = "",
    val email: String = "",
    val role: String = "user",
    @SerializedName("is_active") val isActive: Boolean = true,
    @SerializedName("created_at") val createdAt: String? = null,
    @SerializedName("last_login_at") val lastLoginAt: String? = null
)

data class AuthResponse(
    val token: String,
    val user: UserResponse
)

data class ChangePasswordRequest(
    @SerializedName("current_password") val currentPassword: String,
    @SerializedName("new_password") val newPassword: String
)

data class AnalysisHistoryItem(
    @SerializedName("analysis_id") val analysisId: String,
    val filename: String,
    @SerializedName("duration_sec") val durationSec: Float? = null,
    @SerializedName("total_chunks") val totalChunks: Int = 0,
    @SerializedName("detector_version") val detectorVersion: String? = null,
    @SerializedName("native_probability") val nativeProbability: Float? = null,
    @SerializedName("peak_risk") val peakRisk: Float = 0f,
    @SerializedName("alert_level") val alertLevel: String = "SAFE",
    @SerializedName("created_at") val createdAt: String? = null
)

data class EnclaveMetricsResponse(
    @SerializedName("total_requests") val totalRequests: Int = 0,
    @SerializedName("tokens_saved") val tokensSaved: Int = 0,
    @SerializedName("cache_hits") val cacheHits: Int = 0,
    @SerializedName("cache_misses") val cacheMisses: Int = 0,
    @SerializedName("enclave_blocks") val enclaveBlocks: Int = 0,
    @SerializedName("active_scope") val activeScope: String? = null
)

// Admin & Model Governance Models
data class AdminUserItem(
    val id: Int,
    val username: String,
    val email: String? = null,
    val role: String = "user",
    @SerializedName("is_active") val isActive: Boolean = true,
    @SerializedName("created_at") val createdAt: String? = null,
    @SerializedName("last_login_at") val lastLoginAt: String? = null,
    @SerializedName("failed_login_count") val failedLoginCount: Int = 0,
    @SerializedName("reset_required") val resetRequired: Boolean = false
)

data class CreateUserRequest(
    val username: String,
    val email: String,
    val password: String,
    val role: String = "user"
)

data class UpdateUserStatusRequest(
    @SerializedName("is_active") val isActive: Boolean? = null,
    @SerializedName("reset_required") val resetRequired: Boolean? = null,
    @SerializedName("new_password") val newPassword: String? = null
)

data class ReviewQueueItem(
    val id: String? = null,
    @SerializedName("review_id") val reviewId: String = "",
    @SerializedName("analysis_id") val analysisId: String = "",
    val username: String? = null,
    @SerializedName("submitted_by") val submittedBy: String? = null,
    val filename: String = "unknown",
    @SerializedName("duration_sec") val durationSec: Float = 0f,
    @SerializedName("native_probability") val nativeProbability: Float? = null,
    @SerializedName("aasist_probability") val aasistProbability: Float? = null,
    @SerializedName("peak_risk") val peakRisk: Float = 0f,
    @SerializedName("alert_level") val alertLevel: String = "SAFE",
    @SerializedName("detector_version") val detectorVersion: String? = null,
    val status: String = "PENDING",
    @SerializedName("ground_truth_label") val groundTruthLabel: String? = null,
    @SerializedName("approved_for_training") val approvedForTraining: Boolean = false,
    val notes: String? = null,
    @SerializedName("has_audio") val hasAudio: Boolean = false,
    @SerializedName("created_at") val createdAt: String? = null
)

data class ReviewQueueResponse(
    val items: List<ReviewQueueItem> = emptyList(),
    val total: Int = 0,
    @SerializedName("total_pending") val totalPending: Int = 0,
    @SerializedName("total_approved") val totalApproved: Int = 0,
    @SerializedName("total_rejected") val totalRejected: Int = 0,
    @SerializedName("total_inconclusive") val totalInconclusive: Int = 0,
    @SerializedName("total_training_queued") val totalTrainingQueued: Int = 0,
    @SerializedName("active_version") val activeVersion: String? = null
)

data class ReviewDecisionRequest(
    @SerializedName("review_id") val reviewId: String? = null,
    @SerializedName("ground_truth") val groundTruth: String? = null,
    val decision: String? = null,
    @SerializedName("approve_for_training") val approveForTraining: Boolean? = null,
    val notes: String? = null,
    @SerializedName("trigger_training") val triggerTraining: Boolean? = false
)

data class TrainingRunItem(
    @SerializedName("run_id") val runId: String = "",
    val status: String = "UNKNOWN",
    @SerializedName("base_version") val baseVersion: String? = null,
    @SerializedName("candidate_version") val candidateVersion: String? = null,
    @SerializedName("sample_count") val sampleCount: Int = 0,
    @SerializedName("started_at") val startedAt: String? = null,
    @SerializedName("completed_at") val completedAt: String? = null,
    @SerializedName("val_f1") val valF1: Float? = null,
    @SerializedName("val_eer") val valEer: Float? = null,
    @SerializedName("failure_reason") val failureReason: String? = null
)

data class TrainingStatusResponse(
    @SerializedName("is_training") val isTraining: Boolean = false,
    @SerializedName("current_production_version") val currentProductionVersion: String? = null,
    @SerializedName("approved_samples_in_queue") val approvedSamplesInQueue: Int = 0,
    @SerializedName("weights_sha256") val weightsSha256: String? = null,
    @SerializedName("recent_runs") val recentRuns: List<TrainingRunItem> = emptyList()
)

data class AdminAuditLogItem(
    val id: Int = 0,
    @SerializedName("actor_username") val actorUsername: String = "System",
    @SerializedName("actor_role") val actorRole: String? = null,
    val action: String = "",
    @SerializedName("target_entity") val targetEntity: String? = null,
    @SerializedName("target_id") val targetId: String? = null,
    val timestamp: String? = null,
    val details: String = ""
)

data class AdminAuditLogsResponse(
    val logs: List<AdminAuditLogItem> = emptyList(),
    val total: Int = 0
)

// Real-Time SMS Monitoring Models
data class SmsThreatRecord(
    val id: String = java.util.UUID.randomUUID().toString(),
    val sender: String,
    val timestamp: Long = System.currentTimeMillis(),
    val body: String,
    val riskScore: Float = 0f,
    val severity: String = "SAFE",
    val classification: String = "CLEAN",
    val threatCategory: String = "SMS_COMMUNICATION",
    val isEmailAlertTriggered: Boolean = false,
    val recipientEmail: String? = null,
    val reasoning: String? = null,
    val detectedUrls: List<String> = emptyList(),
    val recommendedActions: List<String> = emptyList(),
    val urlIntelSummary: String? = null,
    val urlPurpose: String? = null,
    val urlSha256: String? = null,
    val vtStats: String? = null,
    val urlhausStatus: String? = null,
    val qwenBriefing: String? = null,
    val liveOsintHits: Int = 0,
    val livePageTitle: String? = null,
    val liveCredentialProbe: Boolean = false,
    val liveRenderingEngine: String? = null
)

// Device Security Models
data class InstalledAppInfo(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val installTime: Long,
    val lastUpdateTime: Long,
    val isSystemApp: Boolean,
    val isUnknownSource: Boolean,
    val installerName: String = "Unknown",
    val isOfficialStore: Boolean = false,
    val isQuarantined: Boolean = false,
    val sha256: String? = null,
    val riskScore: Float,
    val riskLevel: String, // SAFE, LOW, MEDIUM, HIGH, CRITICAL
    val riskFactors: List<String> = emptyList(),
    val sensitivePermissions: List<String> = emptyList(),
    val isWhitelisted: Boolean = false
)

data class DeviceHardwareInfo(
    val manufacturer: String,
    val model: String,
    val brand: String,
    val deviceCode: String,
    val androidVersion: String,
    val apiLevel: Int,
    val securityPatch: String,
    val buildFingerprint: String,
    val isRooted: Boolean,
    val rootCheckDetails: String,
    val isUsbDebuggingEnabled: Boolean,
    val isUsbConnected: Boolean,
    val isVpnActive: Boolean,
    val isBluetoothActive: Boolean
)

data class DeepInvestigationResult(
    val packageName: String,
    val appName: String,
    val sha256: String,
    val installer: String,
    val isOfficialStore: Boolean,
    val threatEvent: ThreatEvent? = null,
    val llmAnalysis: LlmAnalysisResponse? = null,
    val vtDetections: Int = 0,
    val vtTotalEngines: Int = 0,
    val urlhausStatus: String = "CLEAN / NOT LISTED",
    val finalVerdict: String = "SAFE",
    val executiveSummary: String = "",
    val containmentRecommendation: String = "",
    val osintHits: Int = 0,
    val liveInspectionSummary: String? = null,
    val urlSha256: String? = null
)

data class PackageEvent(
    val id: String = java.util.UUID.randomUUID().toString(),
    val packageName: String,
    val appName: String? = null,
    val eventType: String, // INSTALLED, UPDATED, REMOVED
    val timestamp: Long = System.currentTimeMillis(),
    val riskScore: Float = 0f,
    val riskLevel: String = "SAFE"
)

