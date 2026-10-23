package com.voiceguard.client

import android.app.Application
import com.voiceguard.client.model.CallMonitorRepository

open class CyberGuardApplication : Application() {
    
    lateinit var repository: CallMonitorRepository
        private set

    override fun onCreate() {
        super.onCreate()
        repository = CallMonitorRepository.getInstance(this)
    }
}

// Backwards-compatible alias
class VoiceGuardApplication : CyberGuardApplication()
