package com.cyberguard.client.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log
import com.cyberguard.client.model.CallMonitorRepository
import com.cyberguard.client.model.TelephonyCallState

class CallStateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != TelephonyManager.ACTION_PHONE_STATE_CHANGED && 
            intent.action != "android.intent.action.PHONE_STATE") return

        val stateStr = intent.getStringExtra(TelephonyManager.EXTRA_STATE)
        val incomingNumber = intent.getStringExtra(TelephonyManager.EXTRA_INCOMING_NUMBER)
        Log.d("CallStateReceiver", "Phone state changed broadcast: $stateStr (number: $incomingNumber)")

        val repository = CallMonitorRepository.getInstance(context.applicationContext)

        when (stateStr) {
            TelephonyManager.EXTRA_STATE_RINGING -> {
                Log.d("CallStateReceiver", "Incoming call ringing detected via broadcast (number: $incomingNumber)")
                
                // Direct Telecom Hook Real-Time Call Screening Pipeline
                if (!incomingNumber.isNullOrBlank()) {
                    try {
                        val appContext = context.applicationContext
                        val dbHelper = com.cyberguard.client.telecom.CallScreeningDatabaseHelper.getInstance(appContext)
                        val normalized = com.cyberguard.client.telecom.PhoneNumberNormalizer.normalize(incomingNumber)
                        val cachedRep = if (normalized.isValid) dbHelper.getReputation(normalized.e164) else null
                        val assessment = com.cyberguard.client.telecom.CallRiskAssessmentEngine.evaluate(
                            normalized = normalized,
                            cachedReputation = cachedRep,
                            carrierVerification = com.cyberguard.client.telecom.CarrierVerificationStatus.NOT_VERIFIED
                        )
                        val policyManager = com.cyberguard.client.telecom.CallScreeningPolicyManager(appContext)
                        val policy = policyManager.getPolicy()
                        val actionApplied = policyManager.determineAction(assessment, policy)

                        val record = com.cyberguard.client.telecom.ScreenedCallRecord(
                            rawNumber = incomingNumber,
                            normalizedNumber = normalized.e164.ifEmpty { incomingNumber },
                            classification = assessment.classification,
                            riskScore = assessment.riskScore,
                            confidence = assessment.confidence,
                            reasonCodes = assessment.reasonCodes,
                            carrierVerificationStatus = com.cyberguard.client.telecom.CarrierVerificationStatus.NOT_VERIFIED,
                            actionRecommended = assessment.recommendedAction,
                            actionApplied = actionApplied,
                            responseLatencyMs = 8L,
                            explanation = assessment.explanation
                        )
                        dbHelper.saveScreenedCall(record)
                        repository.refreshScreenedCalls()

                        repository.updateTelemetry { it.copy(
                            callState = TelephonyCallState.RINGING,
                            callerStatusMessage = "Screened: ${record.normalizedNumber} (${actionApplied.actionCode})",
                            currentRisk = assessment.riskScore.toDouble()
                        ) }
                    } catch (screeningEx: Exception) {
                        Log.w("CallStateReceiver", "Direct hook screening notice: ${screeningEx.message}")
                        repository.updateTelemetry { it.copy(
                            callState = TelephonyCallState.RINGING,
                            callerStatusMessage = "Incoming call from $incomingNumber"
                        ) }
                    }
                } else {
                    repository.updateTelemetry { it.copy(
                        callState = TelephonyCallState.RINGING,
                        callerStatusMessage = "Incoming call ringing..."
                    ) }
                }
                
                // Ensure CallMonitorService is running and armed
                val serviceIntent = Intent(context, CallMonitorService::class.java).apply {
                    action = CallMonitorService.ACTION_CALL_RINGING
                }
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(serviceIntent)
                    } else {
                        context.startService(serviceIntent)
                    }
                } catch (e: Exception) {
                    Log.w("CallStateReceiver", "Failed to start service on ringing: ${e.message}")
                }
            }
            TelephonyManager.EXTRA_STATE_OFFHOOK -> {
                Log.d("CallStateReceiver", "Call answered (OFFHOOK) detected via broadcast.")
                repository.updateTelemetry { it.copy(
                    callState = TelephonyCallState.ACTIVE,
                    callerStatusMessage = "Call active — analyzing caller voice"
                ) }
                val serviceIntent = Intent(context, CallMonitorService::class.java).apply {
                    action = CallMonitorService.ACTION_START_MONITORING
                }
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(serviceIntent)
                    } else {
                        context.startService(serviceIntent)
                    }
                } catch (e: Exception) {
                    Log.w("CallStateReceiver", "Failed to start service on offhook: ${e.message}")
                }
            }
            TelephonyManager.EXTRA_STATE_IDLE -> {
                Log.d("CallStateReceiver", "Call idle / ended detected via broadcast.")
                repository.updateTelemetry { it.copy(
                    callState = TelephonyCallState.IDLE,
                    callerStatusMessage = "Call ended"
                ) }
                val serviceIntent = Intent(context, CallMonitorService::class.java).apply {
                    action = CallMonitorService.ACTION_STOP_MONITORING
                }
                try {
                    context.startService(serviceIntent)
                } catch (e: Exception) {
                    Log.w("CallStateReceiver", "Failed to send stop intent: ${e.message}")
                }
            }
        }
    }
}
