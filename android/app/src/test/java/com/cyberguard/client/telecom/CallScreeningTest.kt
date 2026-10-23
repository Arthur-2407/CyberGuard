package com.cyberguard.client.telecom

import org.junit.Assert.*
import org.junit.Test

class CallScreeningTest {

    // =========================================================================
    // 1. PHONE NUMBER NORMALIZER TESTS
    // =========================================================================

    @Test
    fun testRestrictedAndAnonymousNumbers() {
        val anonymous1 = PhoneNumberNormalizer.normalize("Private Number")
        assertTrue(anonymous1.isRestricted)
        assertFalse(anonymous1.isValid)
        assertEquals("CALLER_ID_RESTRICTED", anonymous1.rejectionReason)

        val anonymous2 = PhoneNumberNormalizer.normalize("UNKNOWN")
        assertTrue(anonymous2.isRestricted)

        val anonymous3 = PhoneNumberNormalizer.normalize("Anonymous")
        assertTrue(anonymous3.isRestricted)

        val empty = PhoneNumberNormalizer.normalize("")
        assertTrue(empty.isRestricted)
        assertEquals("RESTRICTED_OR_EMPTY_NUMBER", empty.rejectionReason)

        val nullNum = PhoneNumberNormalizer.normalize(null)
        assertTrue(nullNum.isRestricted)
    }

    @Test
    fun testShortCodeDetection() {
        val emergency = PhoneNumberNormalizer.normalize("112")
        assertTrue(emergency.isShortCode)
        assertTrue(emergency.isValid)
        assertEquals("112", emergency.e164)

        val police = PhoneNumberNormalizer.normalize("100")
        assertTrue(police.isShortCode)
        assertEquals("100", police.national)

        val bankSmsCode = PhoneNumberNormalizer.normalize("567676")
        assertTrue(bankSmsCode.isShortCode)
        assertTrue(bankSmsCode.isValid)
    }

    @Test
    fun testIndianNumberNormalization() {
        // 10 digits
        val num10 = PhoneNumberNormalizer.normalize("9876543210", defaultRegion = "IN")
        assertTrue(num10.isValid)
        assertEquals("+919876543210", num10.e164)
        assertEquals("9876543210", num10.national)
        assertEquals("91", num10.countryCode)

        // 11 digits with leading 0
        val num0 = PhoneNumberNormalizer.normalize("09876543210", defaultRegion = "IN")
        assertTrue(num0.isValid)
        assertEquals("+919876543210", num0.e164)
        assertEquals("9876543210", num0.national)

        // International format with spaces and dashes
        val formatted = PhoneNumberNormalizer.normalize("+91 98765-43210")
        assertTrue(formatted.isValid)
        assertEquals("+919876543210", formatted.e164)
        assertEquals("9876543210", formatted.national)
    }

    @Test
    fun testUsNumberNormalization() {
        val usNum = PhoneNumberNormalizer.normalize("(415) 555-2671", defaultRegion = "US")
        assertTrue(usNum.isValid)
        assertEquals("+14155552671", usNum.e164)
        assertEquals("4155552671", usNum.national)
        assertEquals("1", usNum.countryCode)
    }

    // =========================================================================
    // 2. CALL RISK ASSESSMENT ENGINE TESTS
    // =========================================================================

    @Test
    fun testRestrictedCallerRiskAssessment() {
        val normalized = PhoneNumberNormalizer.normalize("RESTRICTED")
        val result = CallRiskAssessmentEngine.evaluate(
            normalized = normalized,
            cachedReputation = null,
            carrierVerification = CarrierVerificationStatus.NOT_VERIFIED
        )

        assertEquals(CallRiskClassification.SUSPICIOUS, result.classification)
        assertEquals(ScreeningAction.SILENCE, result.recommendedAction)
        assertTrue(result.reasonCodes.contains("RESTRICTED_OR_ANONYMOUS_CALLER"))
        assertTrue(result.riskScore >= 0.40f)
    }

    @Test
    fun testShortCodeRiskAssessment() {
        val normalized = PhoneNumberNormalizer.normalize("112")
        val result = CallRiskAssessmentEngine.evaluate(
            normalized = normalized,
            cachedReputation = null,
            carrierVerification = CarrierVerificationStatus.NOT_VERIFIED
        )

        assertEquals(CallRiskClassification.LOWER_RISK, result.classification)
        assertEquals(ScreeningAction.ALLOW, result.recommendedAction)
        assertTrue(result.reasonCodes.contains("VERIFIED_SHORT_CODE"))
        assertTrue(result.riskScore <= 0.10f)
    }

    @Test
    fun testKnownScamCachedReputation() {
        val normalized = PhoneNumberNormalizer.normalize("9876543210")
        val cached = CallerReputation(
            normalizedNumber = "+919876543210",
            rawNumber = "9876543210",
            classification = CallRiskClassification.HIGH_RISK,
            riskScore = 0.95f,
            confidence = 0.90f,
            reasonCodes = listOf("CONFIRMED_FRAUD_RING", "HIGH_VOLUME_AUTODIALER"),
            isScam = true
        )

        val result = CallRiskAssessmentEngine.evaluate(
            normalized = normalized,
            cachedReputation = cached,
            carrierVerification = CarrierVerificationStatus.NOT_VERIFIED
        )

        assertEquals(CallRiskClassification.HIGH_RISK, result.classification)
        assertEquals(ScreeningAction.BLOCK, result.recommendedAction)
        assertTrue(result.isScam)
        assertTrue(result.reasonCodes.contains("CONFIRMED_FRAUD_RING"))
        assertEquals("FRESH", result.sourceFreshness)
    }

    @Test
    fun testExpiredCachedReputationDownweightsRisk() {
        val normalized = PhoneNumberNormalizer.normalize("9876543210")
        val expiredCached = CallerReputation(
            normalizedNumber = "+919876543210",
            rawNumber = "9876543210",
            classification = CallRiskClassification.HIGH_RISK,
            riskScore = 0.80f,
            confidence = 0.80f,
            reasonCodes = listOf("PRIOR_REPORT"),
            isScam = false,
            expiresEpochMs = System.currentTimeMillis() - 100000L // Expired
        )

        val result = CallRiskAssessmentEngine.evaluate(
            normalized = normalized,
            cachedReputation = expiredCached,
            carrierVerification = CarrierVerificationStatus.NOT_VERIFIED
        )

        // An expired entry should NOT automatically keep high risk classification without active verification
        assertEquals("EXPIRED", result.sourceFreshness)
        assertTrue(result.reasonCodes.contains("CACHE_ENTRY_EXPIRED"))
        assertTrue(result.riskScore < 0.40f) // 0.80 * 0.3 = 0.24, which is < 0.40
        assertEquals(CallRiskClassification.UNKNOWN, result.classification)
    }

    @Test
    fun testCarrierStirShakenFailureIncreasesRisk() {
        val normalized = PhoneNumberNormalizer.normalize("9876543210")
        val result = CallRiskAssessmentEngine.evaluate(
            normalized = normalized,
            cachedReputation = null,
            carrierVerification = CarrierVerificationStatus.FAILED
        )

        assertTrue(result.isSpoofed)
        assertTrue(result.reasonCodes.contains("CARRIER_STIR_SHAKEN_FAILED"))
        assertTrue(result.riskScore >= 0.35f)
        assertEquals(CarrierVerificationStatus.FAILED, result.carrierStatus)
    }

    @Test
    fun testUnknownCallerDefaultHandling() {
        val normalized = PhoneNumberNormalizer.normalize("9876543210")
        val result = CallRiskAssessmentEngine.evaluate(
            normalized = normalized,
            cachedReputation = null,
            carrierVerification = CarrierVerificationStatus.NOT_VERIFIED
        )

        // Missing data must NOT be marked safe or scam
        assertEquals(CallRiskClassification.UNKNOWN, result.classification)
        assertEquals(ScreeningAction.ALLOW, result.recommendedAction)
        assertTrue(result.reasonCodes.contains("NO_PRIOR_LOCAL_TELEMETRY"))
        assertEquals("UNAVAILABLE", result.sourceFreshness)
    }

    @Test
    fun testDisputedReputationResolvesToCaution() {
        val normalized = PhoneNumberNormalizer.normalize("9876543210")
        val disputedCached = CallerReputation(
            normalizedNumber = "+919876543210",
            rawNumber = "9876543210",
            classification = CallRiskClassification.DISPUTED,
            riskScore = 0.50f,
            confidence = 0.40f,
            isDisputed = true
        )

        val result = CallRiskAssessmentEngine.evaluate(
            normalized = normalized,
            cachedReputation = disputedCached,
            carrierVerification = CarrierVerificationStatus.NOT_VERIFIED
        )

        assertEquals(CallRiskClassification.DISPUTED, result.classification)
        assertEquals(ScreeningAction.SILENCE, result.recommendedAction)
        assertTrue(result.isDisputed)
    }

    // =========================================================================
    // 3. USER SCREENING POLICY RESOLUTION TESTS
    // =========================================================================

    @Test
    fun testPolicyDecisionMapping() {
        // High Risk + Auto Block Enabled -> BLOCK
        val highRiskResult = CallAssessmentResult(
            normalizedNumber = "+919876543210",
            rawNumber = "9876543210",
            classification = CallRiskClassification.HIGH_RISK,
            riskScore = 0.90f,
            confidence = 0.85f,
            reasonCodes = listOf("SCAM"),
            explanation = "Scam",
            carrierStatus = CarrierVerificationStatus.NOT_VERIFIED,
            recommendedAction = ScreeningAction.BLOCK,
            isScam = true,
            isSpoofed = false,
            isDisputed = false,
            sourceFreshness = "FRESH"
        )

        val policyBlock = CallScreeningPolicy(autoBlockScams = true)
        assertEquals(ScreeningAction.BLOCK, resolvePolicyAction(highRiskResult.classification, policyBlock))

        // High Risk + Auto Block Disabled -> ALLOW
        val policyNoBlock = CallScreeningPolicy(autoBlockScams = false)
        assertEquals(ScreeningAction.ALLOW, resolvePolicyAction(highRiskResult.classification, policyNoBlock))

        // Suspicious + Auto Silence Enabled -> SILENCE
        val policySilence = CallScreeningPolicy(autoSilenceSuspicious = true)
        assertEquals(ScreeningAction.SILENCE, resolvePolicyAction(CallRiskClassification.SUSPICIOUS, policySilence))

        // Suspicious + Auto Silence Disabled -> ALLOW
        val policyNoSilence = CallScreeningPolicy(autoSilenceSuspicious = false)
        assertEquals(ScreeningAction.ALLOW, resolvePolicyAction(CallRiskClassification.SUSPICIOUS, policyNoSilence))

        // Unknown + Block Unknown Enabled -> SILENCE
        val policyBlockUnknown = CallScreeningPolicy(blockUnknownCallers = true)
        assertEquals(ScreeningAction.SILENCE, resolvePolicyAction(CallRiskClassification.UNKNOWN, policyBlockUnknown))

        // Unknown + Block Unknown Disabled -> ALLOW (Conservative default)
        val policyAllowUnknown = CallScreeningPolicy(blockUnknownCallers = false)
        assertEquals(ScreeningAction.ALLOW, resolvePolicyAction(CallRiskClassification.UNKNOWN, policyAllowUnknown))
    }

    private fun resolvePolicyAction(classification: CallRiskClassification, policy: CallScreeningPolicy): ScreeningAction {
        return when (classification) {
            CallRiskClassification.HIGH_RISK -> {
                if (policy.autoBlockScams) ScreeningAction.BLOCK else ScreeningAction.ALLOW
            }
            CallRiskClassification.SUSPICIOUS, CallRiskClassification.DISPUTED -> {
                if (policy.autoSilenceSuspicious) ScreeningAction.SILENCE else ScreeningAction.ALLOW
            }
            CallRiskClassification.UNKNOWN -> {
                if (policy.blockUnknownCallers) ScreeningAction.SILENCE else ScreeningAction.ALLOW
            }
            CallRiskClassification.LOWER_RISK, CallRiskClassification.ERROR -> {
                ScreeningAction.ALLOW
            }
        }
    }
}
