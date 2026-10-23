package com.cyberguard.client.telecom

import android.content.Context
import android.content.SharedPreferences
import android.telecom.CallScreeningService.CallResponse

/**
 * Manages user screening policies and converts risk assessment recommendations
 * into concrete Android CallResponse outcomes.
 */
class CallScreeningPolicyManager(context: Context) {

    companion object {
        private const val PREFS_NAME = "cyberguard_call_screening_prefs"
        private const val KEY_AUTO_BLOCK_SCAMS = "auto_block_scams"
        private const val KEY_AUTO_SILENCE_SUSPICIOUS = "auto_silence_suspicious"
        private const val KEY_BLOCK_UNKNOWN = "block_unknown_callers"
        private const val KEY_SKIP_CALL_LOG = "skip_call_log_on_block"
        private const val KEY_SKIP_NOTIFICATION = "skip_notification_on_block"
    }

    private val prefs: SharedPreferences = context.applicationContext.getSharedPreferences(
        PREFS_NAME,
        Context.MODE_PRIVATE
    )

    /**
     * Retrieves the current user-configured screening policy.
     */
    fun getPolicy(): CallScreeningPolicy {
        return CallScreeningPolicy(
            autoBlockScams = prefs.getBoolean(KEY_AUTO_BLOCK_SCAMS, true),
            autoSilenceSuspicious = prefs.getBoolean(KEY_AUTO_SILENCE_SUSPICIOUS, false),
            blockUnknownCallers = prefs.getBoolean(KEY_BLOCK_UNKNOWN, false),
            skipCallLogOnBlock = prefs.getBoolean(KEY_SKIP_CALL_LOG, false),
            skipNotificationOnBlock = prefs.getBoolean(KEY_SKIP_NOTIFICATION, false)
        )
    }

    /**
     * Updates policy settings.
     */
    fun updatePolicy(policy: CallScreeningPolicy) {
        prefs.edit()
            .putBoolean(KEY_AUTO_BLOCK_SCAMS, policy.autoBlockScams)
            .putBoolean(KEY_AUTO_SILENCE_SUSPICIOUS, policy.autoSilenceSuspicious)
            .putBoolean(KEY_BLOCK_UNKNOWN, policy.blockUnknownCallers)
            .putBoolean(KEY_SKIP_CALL_LOG, policy.skipCallLogOnBlock)
            .putBoolean(KEY_SKIP_NOTIFICATION, policy.skipNotificationOnBlock)
            .apply()
    }

    /**
     * Maps the evidence-based assessment to an authorized action under the user's policy.
     */
    fun determineAction(assessment: CallAssessmentResult, policy: CallScreeningPolicy): ScreeningAction {
        return when (assessment.classification) {
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

    /**
     * Constructs the official Android CallResponse based on the resolved screening action.
     */
    fun buildCallResponse(action: ScreeningAction, policy: CallScreeningPolicy): CallResponse {
        val builder = CallResponse.Builder()
        when (action) {
            ScreeningAction.BLOCK -> {
                builder.setDisallowCall(true)
                builder.setRejectCall(true)
                builder.setSkipCallLog(policy.skipCallLogOnBlock)
                builder.setSkipNotification(policy.skipNotificationOnBlock)
            }
            ScreeningAction.SILENCE -> {
                builder.setSilenceCall(true)
            }
            ScreeningAction.ALLOW -> {
                // Pass through normally
            }
        }
        return builder.build()
    }
}
