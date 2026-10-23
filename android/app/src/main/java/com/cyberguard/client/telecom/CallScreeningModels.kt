package com.cyberguard.client.telecom

/**
 * Standardized risk classification categories for incoming telecommunication calls.
 */
enum class CallRiskClassification(val title: String, val badgeLabel: String) {
    HIGH_RISK("HIGH RISK / SUSPECTED SCAM", "SCAM ALERT"),
    SUSPICIOUS("SUSPICIOUS / CAUTION", "CAUTION"),
    LOWER_RISK("LOWER OBSERVED RISK", "LOWER RISK"),
    UNKNOWN("UNKNOWN / INSUFFICIENT EVIDENCE", "UNKNOWN"),
    DISPUTED("DISPUTED / CONFLICTING EVIDENCE", "DISPUTED"),
    ERROR("UNAVAILABLE / ASSESSMENT ERROR", "ERROR")
}

/**
 * Android framework action applied to the incoming call.
 */
enum class ScreeningAction(val actionCode: String) {
    ALLOW("ALLOWED"),
    SILENCE("SILENCED"),
    BLOCK("BLOCKED")
}

/**
 * STIR/SHAKEN carrier cryptographic caller ID verification status.
 */
enum class CarrierVerificationStatus(val label: String) {
    PASSED("VERIFIED_BY_CARRIER"),
    FAILED("CARRIER_VERIFICATION_FAILED"),
    NOT_VERIFIED("NOT_VERIFIED")
}

/**
 * Locally cached caller reputation record.
 */
data class CallerReputation(
    val normalizedNumber: String,
    val rawNumber: String,
    val countryCode: String? = null,
    val classification: CallRiskClassification = CallRiskClassification.UNKNOWN,
    val riskScore: Float = 0.0f,
    val confidence: Float = 0.0f,
    val reasonCodes: List<String> = emptyList(),
    val evidenceSources: List<String> = emptyList(),
    val explanation: String = "No threat telemetry recorded.",
    val isScam: Boolean = false,
    val isSpoofed: Boolean = false,
    val isDisputed: Boolean = false,
    val lastVerifiedEpochMs: Long = System.currentTimeMillis(),
    val expiresEpochMs: Long? = null
) {
    val isExpired: Boolean
        get() = expiresEpochMs != null && expiresEpochMs > 0 && System.currentTimeMillis() > expiresEpochMs
}

/**
 * Auditable record of a screened incoming call event.
 */
data class ScreenedCallRecord(
    val id: String = java.util.UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val rawNumber: String,
    val normalizedNumber: String,
    val callerDisplayName: String? = null,
    val classification: CallRiskClassification = CallRiskClassification.UNKNOWN,
    val riskScore: Float = 0.0f,
    val confidence: Float = 0.0f,
    val reasonCodes: List<String> = emptyList(),
    val evidenceSources: List<String> = emptyList(),
    val carrierVerificationStatus: CarrierVerificationStatus = CarrierVerificationStatus.NOT_VERIFIED,
    val actionRecommended: ScreeningAction = ScreeningAction.ALLOW,
    val actionApplied: ScreeningAction = ScreeningAction.ALLOW,
    val responseLatencyMs: Long = 0L,
    val explanation: String = "",
    val isSyncedToSoc: Boolean = false
) {
    val incidentId: String
        get() = id
    val recommendedAction: ScreeningAction
        get() = actionRecommended
}

/**
 * User-configurable screening policy preferences.
 */
data class CallScreeningPolicy(
    val autoBlockScams: Boolean = true,
    val autoSilenceSuspicious: Boolean = false,
    val blockUnknownCallers: Boolean = false,
    val skipCallLogOnBlock: Boolean = false,
    val skipNotificationOnBlock: Boolean = false
)
