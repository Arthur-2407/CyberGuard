package com.cyberguard.client.telecom

/**
 * Result of a deterministic, evidence-based call screening risk evaluation.
 */
data class CallAssessmentResult(
    val normalizedNumber: String,
    val rawNumber: String,
    val classification: CallRiskClassification,
    val riskScore: Float,
    val confidence: Float,
    val reasonCodes: List<String>,
    val explanation: String,
    val carrierStatus: CarrierVerificationStatus,
    val recommendedAction: ScreeningAction,
    val isScam: Boolean,
    val isSpoofed: Boolean,
    val isDisputed: Boolean,
    val sourceFreshness: String
)

/**
 * Centralized, explainable risk assessment engine for incoming telecommunication calls.
 * Evaluates verified reputation signals, STIR/SHAKEN carrier verdicts, and formatting evidence.
 */
object CallRiskAssessmentEngine {

    // Threshold boundaries
    const val THRESHOLD_HIGH_RISK = 0.75f
    const val THRESHOLD_SUSPICIOUS = 0.40f

    /**
     * Evaluates available evidence and produces a structured, explainable risk assessment.
     */
    fun evaluate(
        normalized: NormalizedPhoneNumber,
        cachedReputation: CallerReputation?,
        carrierVerification: CarrierVerificationStatus
    ): CallAssessmentResult {
        val reasons = mutableListOf<String>()
        var baseRisk = 0.0f
        var confidence = 0.0f
        var isScam = false
        var isSpoofed = false
        var isDisputed = false
        var freshness = "CURRENT"

        // 1. Check for Anonymous / Restricted Caller ID
        if (normalized.isRestricted) {
            reasons.add("RESTRICTED_OR_ANONYMOUS_CALLER")
            return CallAssessmentResult(
                normalizedNumber = normalized.e164,
                rawNumber = normalized.raw,
                classification = CallRiskClassification.SUSPICIOUS,
                riskScore = 0.55f,
                confidence = 0.70f,
                reasonCodes = reasons,
                explanation = "Caller identity is restricted or suppressed by network origin.",
                carrierStatus = carrierVerification,
                recommendedAction = ScreeningAction.SILENCE,
                isScam = false,
                isSpoofed = false,
                isDisputed = false,
                sourceFreshness = freshness
            )
        }

        // 2. Short codes (Emergency, Verified Carrier Services)
        if (normalized.isShortCode) {
            reasons.add("VERIFIED_SHORT_CODE")
            return CallAssessmentResult(
                normalizedNumber = normalized.e164,
                rawNumber = normalized.raw,
                classification = CallRiskClassification.LOWER_RISK,
                riskScore = 0.05f,
                confidence = 0.85f,
                reasonCodes = reasons,
                explanation = "Standard telecommunications service or emergency short code.",
                carrierStatus = carrierVerification,
                recommendedAction = ScreeningAction.ALLOW,
                isScam = false,
                isSpoofed = false,
                isDisputed = false,
                sourceFreshness = freshness
            )
        }

        // 3. Carrier STIR/SHAKEN cryptographic verification status
        when (carrierVerification) {
            CarrierVerificationStatus.FAILED -> {
                reasons.add("CARRIER_STIR_SHAKEN_FAILED")
                isSpoofed = true
                baseRisk += 0.35f
            }
            CarrierVerificationStatus.PASSED -> {
                reasons.add("CARRIER_IDENTITY_VERIFIED")
                confidence += 0.25f
            }
            CarrierVerificationStatus.NOT_VERIFIED -> {
                // Neutral: missing signal is not treated as evidence of fraud
            }
        }

        // 4. Evaluate Cached Reputation Intelligence
        if (cachedReputation != null) {
            if (cachedReputation.isExpired) {
                freshness = "EXPIRED"
                reasons.add("CACHE_ENTRY_EXPIRED")
                // Expired records do not silently contribute full threat weight
                baseRisk += cachedReputation.riskScore * 0.3f
                confidence = 0.20f
            } else {
                freshness = "FRESH"
                baseRisk += cachedReputation.riskScore
                confidence = Math.max(confidence, cachedReputation.confidence)
                isScam = cachedReputation.isScam
                isSpoofed = isSpoofed || cachedReputation.isSpoofed
                isDisputed = cachedReputation.isDisputed
                reasons.addAll(cachedReputation.reasonCodes)
            }
        } else {
            freshness = "UNAVAILABLE"
            reasons.add("NO_PRIOR_LOCAL_TELEMETRY")
        }

        // Clamp risk score to [0.0, 1.0]
        val finalRisk = baseRisk.coerceIn(0.0f, 1.0f)

        // 5. Determine Classification Boundary
        val classification = when {
            isDisputed -> CallRiskClassification.DISPUTED
            isScam || finalRisk >= THRESHOLD_HIGH_RISK -> CallRiskClassification.HIGH_RISK
            finalRisk >= THRESHOLD_SUSPICIOUS -> CallRiskClassification.SUSPICIOUS
            cachedReputation != null && !cachedReputation.isExpired && finalRisk < THRESHOLD_SUSPICIOUS -> CallRiskClassification.LOWER_RISK
            else -> CallRiskClassification.UNKNOWN
        }

        // 6. Recommended Action mapping
        val recommendedAction = when (classification) {
            CallRiskClassification.HIGH_RISK -> ScreeningAction.BLOCK
            CallRiskClassification.SUSPICIOUS -> ScreeningAction.SILENCE
            CallRiskClassification.DISPUTED -> ScreeningAction.SILENCE
            CallRiskClassification.LOWER_RISK -> ScreeningAction.ALLOW
            CallRiskClassification.UNKNOWN -> ScreeningAction.ALLOW
            CallRiskClassification.ERROR -> ScreeningAction.ALLOW
        }

        // 7. Human-readable explanation generation from verified signals
        val explanation = when (classification) {
            CallRiskClassification.HIGH_RISK -> {
                if (isScam) {
                    "Known scam or fraudulent caller verified by threat intelligence."
                } else if (carrierVerification == CarrierVerificationStatus.FAILED) {
                    "High probability scam: Failed carrier caller-ID verification and suspicious traffic patterns."
                } else {
                    "Severe threat indicators detected in telephone reputation database."
                }
            }
            CallRiskClassification.SUSPICIOUS -> {
                if (carrierVerification == CarrierVerificationStatus.FAILED) {
                    "Caution advised: Telecommunications carrier failed to verify caller identity (possible spoofing)."
                } else {
                    "Suspicious caller profile observed. Proceed with caution."
                }
            }
            CallRiskClassification.DISPUTED -> {
                "Conflicting reputation reports on file for this number. Caution recommended."
            }
            CallRiskClassification.LOWER_RISK -> {
                "Lower observed risk based on verified benign history."
            }
            CallRiskClassification.UNKNOWN -> {
                "No prior threat intelligence on file for this caller. Standard call handling applied."
            }
            CallRiskClassification.ERROR -> {
                "Assessment could not be completed. Defaulting to safe handling."
            }
        }

        return CallAssessmentResult(
            normalizedNumber = normalized.e164,
            rawNumber = normalized.raw,
            classification = classification,
            riskScore = finalRisk,
            confidence = confidence.coerceIn(0.0f, 1.0f),
            reasonCodes = reasons.distinct(),
            explanation = explanation,
            carrierStatus = carrierVerification,
            recommendedAction = recommendedAction,
            isScam = isScam,
            isSpoofed = isSpoofed,
            isDisputed = isDisputed,
            sourceFreshness = freshness
        )
    }
}
