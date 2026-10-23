package com.cyberguard.client.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.cyberguard.client.model.CallMonitorRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class SmsMonitorReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION &&
            intent.action != "android.provider.Telephony.SMS_RECEIVED") return

        val repo = CallMonitorRepository.getInstance(context.applicationContext)
        if (!repo.isSmsShieldArmed.value) {
            Log.d("SmsMonitorReceiver", "SMS Shield is disarmed. Skipping incoming message inspection.")
            return
        }

        val messages = try {
            Telephony.Sms.Intents.getMessagesFromIntent(intent)
        } catch (e: Exception) {
            Log.w("SmsMonitorReceiver", "Failed to parse SMS intent: ${e.message}")
            null
        } ?: return

        for (sms in messages) {
            val sender = sms.displayOriginatingAddress ?: "Unknown Sender"
            val body = sms.displayMessageBody ?: ""
            Log.d("SmsMonitorReceiver", "Real-time incoming SMS detected from $sender. Processing threat detection.")

            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val result = repo.analyzeIncomingSms(sender, body)
                    Log.d("SmsMonitorReceiver", "SMS analyzed: severity=${result.severity}, emailAlert=${result.isEmailAlertTriggered}")
                } catch (e: Exception) {
                    Log.e("SmsMonitorReceiver", "Failed to process SMS threat detection: ${e.message}")
                }
            }
        }
    }
}
