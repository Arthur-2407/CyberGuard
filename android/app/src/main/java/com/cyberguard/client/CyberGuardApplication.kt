package com.cyberguard.client

import android.app.Application
import com.cyberguard.client.model.CallMonitorRepository

open class CyberGuardApplication : Application() {
    
    lateinit var repository: CallMonitorRepository
        private set

    override fun onCreate() {
        super.onCreate()
        repository = CallMonitorRepository.getInstance(this)
    }
}

typealias VoiceGuardApplication = CyberGuardApplication

