package com.cyberguard.client.telecom

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.telecom.Call
import android.telecom.CallScreeningService
import android.telecom.Connection
import android.util.Log
import androidx.core.app.NotificationCompat
import com.cyberguard.client.MainActivity
import com.cyberguard.client.model.CallMonitorRepository
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * Official Android CallScreeningService implementation for CyberGuard.
 * Operates under a strict local-first architecture to respond to the Android telecom framework
 * well within the mandatory 5-second deadline (< 20ms typical latency).
 */
class CyberGuardCallScreeningService : CallScreeningService() {

    companion object {
        private const val TAG = "CyberGuardScreening"
        private const val SCREENING_CHANNEL_ID = "cyberguard_call_screening_alerts"
        private const val NOTIFICATION_ID_BASE = 88000
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }

    /**
     * Entry point invoked by Android Telecom framework when an incoming or outgoing call occurs.
     */
    override fun onScreenCall(callDetails: Call.Details) {
        val startTimeMs = System.currentTimeMillis()

        // 1. Verify call direction: screening applies only to INCOMING telephony calls
        if (callDetails.callDirection != Call.Details.DIRECTION_INCOMING) {
            Log.d(TAG, "Ignoring non-incoming call direction: ${callDetails.callDirection}")
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }

        // 2. Extract caller telephone number and metadata
        val rawNumber = callDetails.handle?.schemeSpecificPart
        val callerDisplayName = callDetails.callerDisplayName

        // 3. Extract STIR/SHAKEN carrier cryptographic verification status (Android 11+ / API 30+)
        val carrierStatus = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            when (callDetails.callerNumberVerificationStatus) {
                Connection.VERIFICATION_STATUS_PASSED -> CarrierVerificationStatus.PASSED
                Connection.VERIFICATION_STATUS_FAILED -> CarrierVerificationStatus.FAILED
                else -> CarrierVerificationStatus.NOT_VERIFIED
            }
        } else {
            CarrierVerificationStatus.NOT_VERIFIED
        }

        // 4. E.164 Normalization
        val normalized = PhoneNumberNormalizer.normalize(rawNumber)

        // 5. Bounded Local-First Database Lookup (< 2ms)
        val dbHelper = CallScreeningDatabaseHelper.getInstance(this)
        val cachedReputation = if (normalized.isValid) {
            dbHelper.getReputation(normalized.e164)
        } else null

        // 6. Evidence-Based Risk Assessment
        val assessment = CallRiskAssessmentEngine.evaluate(
            normalized = normalized,
            cachedReputation = cachedReputation,
            carrierVerification = carrierStatus
        )

        // 7. Apply User-Configured Screening Policy
        val policyManager = CallScreeningPolicyManager(this)
        val policy = policyManager.getPolicy()
        val actionToApply = policyManager.determineAction(assessment, policy)
        val callResponse = policyManager.buildCallResponse(actionToApply, policy)

        // 8. MANDATORY: Respond to Android within the 5-second deadline
        try {
            respondToCall(callDetails, callResponse)
            val latencyMs = System.currentTimeMillis() - startTimeMs
            Log.i(TAG, "Screened call from '${normalized.e164}': Action=$actionToApply, Risk=${assessment.riskScore}, Classification=${assessment.classification} (Latency: ${latencyMs}ms)")

            // 9. Post-response audit logging and asynchronous telemetry dispatch
            val record = ScreenedCallRecord(
                id = java.util.UUID.randomUUID().toString(),
                timestamp = System.currentTimeMillis(),
                rawNumber = rawNumber ?: "UNKNOWN",
                normalizedNumber = normalized.e164.ifEmpty { rawNumber ?: "UNKNOWN" },
                callerDisplayName = callerDisplayName,
                classification = assessment.classification,
                riskScore = assessment.riskScore,
                confidence = assessment.confidence,
                reasonCodes = assessment.reasonCodes,
                carrierVerificationStatus = carrierStatus,
                actionRecommended = assessment.recommendedAction,
                actionApplied = actionToApply,
                responseLatencyMs = latencyMs,
                explanation = assessment.explanation,
                isSyncedToSoc = false
            )

            // Persist locally in SQLite
            dbHelper.saveScreenedCall(record)

            // Update in-memory telemetry in repository for live UI updates
            val repository = CallMonitorRepository.getInstance(applicationContext)
            repository.updateTelemetry { telemetry ->
                telemetry.copy(
                    callerStatusMessage = "Screened: ${record.normalizedNumber} (${actionToApply.actionCode})",
                    currentRisk = assessment.riskScore.toDouble()
                )
            }

            // Surface Heads-Up Alert Notification for HIGH_RISK or SUSPICIOUS calls
            if (assessment.classification == CallRiskClassification.HIGH_RISK ||
                assessment.classification == CallRiskClassification.SUSPICIOUS ||
                actionToApply == ScreeningAction.BLOCK || actionToApply == ScreeningAction.SILENCE) {
                showScreeningAlertNotification(record)
            }

            // Asynchronously dispatch incident to backend SOC API
            serviceScope.launch {
                syncScreenedCallToBackend(record)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Exception during call screening response: ${e.message}", e)
            try {
                // Failsafe pass-through
                respondToCall(callDetails, CallResponse.Builder().build())
            } catch (fallbackError: Exception) {
                Log.e(TAG, "Failsafe respondToCall failed: ${fallbackError.message}")
            }
        }
    }

    /**
     * Creates the notification channel for high-priority call screening warnings.
     */
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                SCREENING_CHANNEL_ID,
                "CyberGuard Call Screening Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Real-time threat notifications for blocked or screened scam calls"
                enableVibration(true)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    /**
     * Displays a notification explaining the screening assessment and applied action.
     */
    private fun showScreeningAlertNotification(record: ScreenedCallRecord) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("navigate_to", "comms")
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            record.id.hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val title = when (record.actionApplied) {
            ScreeningAction.BLOCK -> "⛔ SCAM CALL BLOCKED: ${record.normalizedNumber}"
            ScreeningAction.SILENCE -> "🔇 SUSPICIOUS CALL SILENCED: ${record.normalizedNumber}"
            ScreeningAction.ALLOW -> "⚠ SUSPICIOUS INCOMING CALL: ${record.normalizedNumber}"
        }

        val content = "${record.classification.title} (${(record.riskScore * 100).toInt()}% risk). ${record.explanation}"

        val notification = NotificationCompat.Builder(this, SCREENING_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID_BASE + (record.timestamp % 1000).toInt(), notification)
    }

    /**
     * Asynchronously syncs screened call incidents to the CyberGuard backend and SOC dashboard.
     */
    private fun syncScreenedCallToBackend(record: ScreenedCallRecord) {
        try {
            val prefs = getSharedPreferences("cyberguard_prefs", Context.MODE_PRIVATE)
            val serverUrl = prefs.getString("server_url", null) ?: "http://127.0.0.1:3000"
            val endpoint = "$serverUrl/api/threats/screened-calls"

            val json = JSONObject().apply {
                put("incident_id", record.id)
                put("phone_number", record.rawNumber)
                put("caller_display_name", record.callerDisplayName ?: "")
                put("call_direction", "INCOMING")
                put("classification", record.classification.name)
                put("risk_score", record.riskScore.toDouble())
                put("confidence", record.confidence.toDouble())
                put("reasons", org.json.JSONArray(record.reasonCodes))
                put("carrier_verification_status", record.carrierVerificationStatus.name)
                put("action_recommended", record.actionRecommended.name)
                put("action_applied", record.actionApplied.name)
                put("response_latency_ms", record.responseLatencyMs.toDouble())
                put("device_id", Build.MODEL)
                put("timestamp_epoch_ms", record.timestamp)
            }

            val url = URL(endpoint)
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 3000
                readTimeout = 3000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
            }

            OutputStreamWriter(conn.outputStream).use { writer ->
                writer.write(json.toString())
                writer.flush()
            }

            val code = conn.responseCode
            if (code in 200..299) {
                CallScreeningDatabaseHelper.getInstance(this).markCallSynced(record.id)
                Log.d(TAG, "Screened call incident successfully synced to SOC: ${record.id}")
            } else {
                Log.w(TAG, "Backend returned HTTP $code while syncing screened call: ${record.id}")
            }
            conn.disconnect()
        } catch (e: Exception) {
            Log.w(TAG, "Asynchronous backend sync deferred (offline/unreachable): ${e.message}")
        }
    }
}
