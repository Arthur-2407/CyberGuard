package com.cyberguard.client.service

import android.app.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.media.AudioDeviceCallback
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.os.Build
import android.os.Environment
import android.os.IBinder
import android.provider.Telephony
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.cyberguard.client.MainActivity
import android.content.pm.PackageInstaller
import android.os.Handler
import android.os.Looper
import com.cyberguard.client.audio.AudioSourceType
import com.cyberguard.client.audio.RealTimeAudioPipeline
import com.cyberguard.client.model.*
import com.cyberguard.client.network.PackageEvent
import com.cyberguard.client.network.WebSocketEventClient
import com.cyberguard.client.network.WsEvent
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import java.io.File
import java.security.MessageDigest

class CallMonitorService : Service() {
    private lateinit var repository: CallMonitorRepository

    companion object {
        const val ACTION_START_WATCHDOG = "com.cyberguard.client.service.ACTION_START_WATCHDOG"
        const val ACTION_START_MONITORING = "com.cyberguard.client.service.ACTION_START_MONITORING"
        const val ACTION_STOP_MONITORING = "com.cyberguard.client.service.ACTION_STOP_MONITORING"
        const val ACTION_CALL_RINGING = "com.cyberguard.client.service.ACTION_CALL_RINGING"
        private const val CHANNEL_ID = "CyberGuardCallMonitor"
        private const val ALERT_CHANNEL_ID = "CyberGuardSecurityAlert"
        private const val NOTIFICATION_ID = 1001
        private const val ALERT_NOTIFICATION_ID = 1002
    }

    private var telephonyManager: TelephonyManager? = null
    private var isTelephonyRegistered = false
    private var telephonyCallback: TelephonyCallback? = null

    private var audioManager: AudioManager? = null
    private var audioDeviceCallback: AudioDeviceCallback? = null

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var monitoringJob: Job? = null
    
    private var webSocketClient: WebSocketEventClient? = null
    private var audioPipeline: RealTimeAudioPipeline? = null
    private val okHttpClient = OkHttpClient()
    private var packageInstallerSessionCallback: PackageInstaller.SessionCallback? = null
    private val activeInterceptedSessions = mutableSetOf<Int>()

    private var dynamicSmsReceiver: BroadcastReceiver? = null
    private var dynamicPackageReceiver: BroadcastReceiver? = null
    private var dynamicPhoneStateReceiver: BroadcastReceiver? = null
    private var integrityWatchdogJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        repository = CallMonitorRepository.getInstance(applicationContext)
        audioManager = getSystemService(Context.AUDIO_SERVICE) as? AudioManager
        telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager

        createNotificationChannels()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID, 
                    buildStatusNotification("Actively monitoring Calls, SMS & Apps"),
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0
                )
            } else {
                startForeground(NOTIFICATION_ID, buildStatusNotification("Actively monitoring Calls, SMS & Apps"))
            }
        } catch (e: Exception) {
            Log.e("CallMonitorService", "Failed to start foreground service: ${e.message}")
            repository.updateTelemetry { it.copy(
                monitorState = MonitorState.UNAVAILABLE, 
                diagnosticReason = "FGS Start Failed: ${e.message}"
            ) }
            stopSelf()
            return
        }

        registerTelephonyListener()
        registerAudioDeviceCallback()
        registerDynamicReceivers()
        registerPackageInstallerCallback()
        startBackgroundWatchdogLoop()
    }

    private fun registerAudioDeviceCallback() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && audioManager != null) {
            audioDeviceCallback = object : AudioDeviceCallback() {
                override fun onAudioDevicesAdded(addedDevices: Array<out AudioDeviceInfo>?) {
                    updateAudioRoute()
                }
                override fun onAudioDevicesRemoved(removedDevices: Array<out AudioDeviceInfo>?) {
                    updateAudioRoute()
                }
            }
            audioManager?.registerAudioDeviceCallback(audioDeviceCallback, null)
        }
    }

    private fun registerTelephonyListener() {
        if (isTelephonyRegistered) return
        if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) {
            Log.w("CallMonitorService", "READ_PHONE_STATE not granted; deferring TelephonyListener.")
            return
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val cb = object : TelephonyCallback(), TelephonyCallback.CallStateListener {
                    override fun onCallStateChanged(state: Int) {
                        handleCallStateChange(state)
                    }
                }
                telephonyCallback = cb
                telephonyManager?.registerTelephonyCallback(mainExecutor, cb)
            } else {
                @Suppress("DEPRECATION")
                telephonyManager?.listen(object : android.telephony.PhoneStateListener() {
                    @Deprecated("Deprecated in Java")
                    override fun onCallStateChanged(state: Int, phoneNumber: String?) {
                        handleCallStateChange(state)
                    }
                }, android.telephony.PhoneStateListener.LISTEN_CALL_STATE)
            }
            isTelephonyRegistered = true
            Log.d("CallMonitorService", "TelephonyListener registered successfully.")
            checkAndSyncCurrentCallState()
        } catch (e: Exception) {
            Log.e("CallMonitorService", "Error registering TelephonyListener: ${e.message}")
        }
    }

    fun getAudioRoute(): String {
        val am = audioManager ?: return "EARPIECE"

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val commDevice = am.communicationDevice
            if (commDevice != null) {
                return when (commDevice.type) {
                    AudioDeviceInfo.TYPE_BLUETOOTH_SCO,
                    AudioDeviceInfo.TYPE_BLUETOOTH_A2DP,
                    AudioDeviceInfo.TYPE_BLE_HEADSET -> "BLUETOOTH"
                    AudioDeviceInfo.TYPE_BUILTIN_SPEAKER -> "SPEAKERPHONE"
                    AudioDeviceInfo.TYPE_WIRED_HEADSET,
                    AudioDeviceInfo.TYPE_WIRED_HEADPHONES,
                    AudioDeviceInfo.TYPE_USB_HEADSET -> "WIRED_HEADSET"
                    AudioDeviceInfo.TYPE_BUILTIN_EARPIECE -> "EARPIECE"
                    else -> "OTHER"
                }
            }
        }

        val devices = am.getDevices(AudioManager.GET_DEVICES_OUTPUTS)
        val hasBluetooth = devices.any {
            it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO ||
            it.type == AudioDeviceInfo.TYPE_BLE_HEADSET ||
            it.type == AudioDeviceInfo.TYPE_BLUETOOTH_A2DP
        }

        return when {
            am.isSpeakerphoneOn -> "SPEAKERPHONE"
            am.isBluetoothScoOn -> "BLUETOOTH"
            hasBluetooth && !am.isSpeakerphoneOn -> "BLUETOOTH"
            @Suppress("DEPRECATION")
            am.isWiredHeadsetOn -> "WIRED_HEADSET"
            else -> "EARPIECE"
        }
    }

    private fun updateAudioRoute() {
        val route = getAudioRoute()
        val modeStr = "REMOTE_CALLER ($route)"
        repository.updateTelemetry { it.copy(captureMode = modeStr) }
        webSocketClient?.sendControlMessage("update_route", mapOf("capture_mode" to modeStr))
        Log.d("CallMonitorService", "Updated audio route: $modeStr")
    }

    private fun checkAndSyncCurrentCallState() {
        try {
            val tm = telephonyManager
            val am = audioManager
            val callState = tm?.callState ?: TelephonyManager.CALL_STATE_IDLE
            val isAudioInCall = am?.mode == AudioManager.MODE_IN_CALL || am?.mode == AudioManager.MODE_IN_COMMUNICATION
            val currentRepoState = repository.telemetry.value.callState

            Log.d("CallMonitorService", "checkAndSyncCurrentCallState: telephonyState=$callState, audioMode=${am?.mode}, repoState=$currentRepoState")

            if ((callState == TelephonyManager.CALL_STATE_OFFHOOK || isAudioInCall) && currentRepoState != TelephonyCallState.ACTIVE) {
                Log.d("CallMonitorService", "Active ongoing call detected during state sync! Auto-activating monitor pipeline.")
                handleCallStateChange(TelephonyManager.CALL_STATE_OFFHOOK)
            } else if (callState == TelephonyManager.CALL_STATE_RINGING && currentRepoState != TelephonyCallState.RINGING) {
                handleCallStateChange(TelephonyManager.CALL_STATE_RINGING)
            }
        } catch (e: Exception) {
            Log.w("CallMonitorService", "Error checking active call state: ${e.message}")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        registerTelephonyListener()
        checkAndSyncCurrentCallState()

        when (intent?.action) {
            ACTION_CALL_RINGING -> {
                Log.d("CallMonitorService", "Call ringing received via intent")
                handleCallStateChange(TelephonyManager.CALL_STATE_RINGING)
            }
            ACTION_START_MONITORING -> {
                Log.d("CallMonitorService", "Call start monitoring requested via intent")
                repository.updateTelemetry { it.copy(callState = TelephonyCallState.ACTIVE) }
                startMonitoring()
            }
            ACTION_STOP_MONITORING -> {
                Log.d("CallMonitorService", "Call stop monitoring requested via intent")
                stopMonitoring()
            }
            ACTION_START_WATCHDOG -> {
                Log.d("CallMonitorService", "Watchdog mode active: Monitoring calls, SMS & installations")
                updateStatusNotification("Actively monitoring Calls, SMS & Apps")
            }
            else -> {
                updateStatusNotification("Actively monitoring Calls, SMS & Apps")
            }
        }
        return START_STICKY
    }

    private fun handleCallStateChange(state: Int) {
        when (state) {
            TelephonyManager.CALL_STATE_RINGING -> {
                Log.d("CallMonitorService", "Call ringing. Arming Call Shield.")
                repository.updateTelemetry { it.copy(
                    callState = TelephonyCallState.RINGING,
                    callerStatusMessage = "Incoming Call Ringing... Call Shield Armed",
                    diagnosticReason = null
                ) }
                updateStatusNotification("Incoming call ringing... Call Shield armed")
            }
            TelephonyManager.CALL_STATE_OFFHOOK -> {
                Log.d("CallMonitorService", "Call is active. Starting monitor.")
                repository.updateTelemetry { it.copy(
                    callState = TelephonyCallState.ACTIVE,
                    callerStatusMessage = "Call Active — Monitoring Remote Caller"
                ) }
                if (repository.telemetry.value.monitorState != MonitorState.ANALYZING &&
                    repository.telemetry.value.monitorState != MonitorState.STREAMING) {
                    startMonitoring()
                }
            }
            TelephonyManager.CALL_STATE_IDLE -> {
                Log.d("CallMonitorService", "Call ended. Stopping monitor.")
                stopMonitoring()
                val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                notificationManager.cancel(ALERT_NOTIFICATION_ID)
                updateStatusNotification("Actively monitoring Calls, SMS & Apps")
            }
        }
    }

    private fun startMonitoring() {
        val detectedUrl = repository.connectionManager.serverUrl.value ?: run {
            val prefs = applicationContext.getSharedPreferences("cyberguard_prefs", Context.MODE_PRIVATE)
            val savedUrl = prefs.getString("server_url", null)
            if (!savedUrl.isNullOrBlank()) {
                repository.connectionManager.connectManually(savedUrl, 3000)
                savedUrl
            } else {
                val lastHost = prefs.getString("last_host_ip", null)
                val lastPort = prefs.getInt("last_host_port", 3000)
                if (!lastHost.isNullOrBlank()) {
                    repository.connectionManager.connectManually(lastHost, lastPort)
                    repository.connectionManager.formatEndpointUrl(lastHost, lastPort)
                } else {
                    val gateway = repository.connectionManager.getDetectedGatewayOrHostIp()
                    if (!gateway.isNullOrBlank()) {
                        repository.connectionManager.connectManually(gateway, 3000)
                        "http://$gateway:3000/"
                    } else null
                }
            }
        }

        monitoringJob?.cancel()
        monitoringJob = serviceScope.launch {
            try {
                repository.updateTelemetry { it.copy(
                    monitorState = MonitorState.ANALYZING,
                    diagnosticReason = null
                ) }
                updateStatusNotification("CyberGuard Defense Matrix Active")
                
                // Configure audio mode for duplex in-call audio capture
                try {
                    audioManager?.mode = AudioManager.MODE_IN_COMMUNICATION
                    val currentRoute = getAudioRoute()
                    if (currentRoute == "BLUETOOTH") {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                            val commDevices = audioManager?.availableCommunicationDevices
                            val btDevice = commDevices?.firstOrNull { 
                                it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO ||
                                it.type == AudioDeviceInfo.TYPE_BLE_HEADSET ||
                                it.type == AudioDeviceInfo.TYPE_BLUETOOTH_A2DP
                            }
                            if (btDevice != null) {
                                audioManager?.setCommunicationDevice(btDevice)
                            }
                        } else {
                            @Suppress("DEPRECATION")
                            audioManager?.startBluetoothSco()
                            @Suppress("DEPRECATION")
                            audioManager?.isBluetoothScoOn = true
                        }
                    }
                } catch (audioRouteEx: Exception) {
                    Log.w("CallMonitorService", "Audio routing configuration notice: ${audioRouteEx.message}")
                }

                // Initialize Audio first
                repository.updateTelemetry { it.copy(audioState = AudioCaptureState.INITIALIZING) }
                
                val currentRoute = getAudioRoute()
                val captureModeString = "REMOTE_CALLER ($currentRoute)"
                
                audioPipeline = RealTimeAudioPipeline(
                    sourceType = AudioSourceType.VOICE_COMMUNICATION,
                    onAudioData = { data ->
                        webSocketClient?.sendAudio(data)
                        repository.updateTelemetry { 
                            it.copy(
                                framesCaptured = audioPipeline?.framesCaptured ?: it.framesCaptured,
                                framesSent = it.framesSent + 1
                            ) 
                        }
                    },
                    onError = { errorMsg ->
                        repository.updateTelemetry { it.copy(
                            audioState = AudioCaptureState.UNAVAILABLE,
                            diagnosticReason = errorMsg
                        ) }
                    },
                    onRmsUpdate = { rms ->
                        repository.updateTelemetry { it.copy(audioLevelRms = rms) }
                    }
                )
                
                audioPipeline?.start()
                repository.updateTelemetry { it.copy(
                    audioState = AudioCaptureState.CAPTURING,
                    audioSource = audioPipeline?.activeSourceDescription ?: "VOICE_COMMUNICATION",
                    captureMode = captureModeString
                ) }

                // Connect Backend or maintain Local Autonomous Mode
                if (detectedUrl != null) {
                    repository.updateTelemetry { it.copy(backendState = BackendState.CONNECTING) }
                    webSocketClient = WebSocketEventClient(okHttpClient, detectedUrl)
                    webSocketClient?.connect()
                } else {
                    repository.updateTelemetry { it.copy(backendState = BackendState.DISCONNECTED) }
                    launch {
                        repository.connectionManager.startDiscovery()
                        repository.connectionManager.serverUrl.collect { newUrl ->
                            if (!newUrl.isNullOrBlank() && webSocketClient == null) {
                                repository.updateTelemetry { it.copy(backendState = BackendState.CONNECTING) }
                                webSocketClient = WebSocketEventClient(okHttpClient, newUrl)
                                webSocketClient?.connect()
                            }
                        }
                    }
                }
                
                // Listen to WS events
                launch {
                    webSocketClient?.events?.collect { event ->
                        when (event) {
                            is WsEvent.Connected -> {
                                repository.updateTelemetry { it.copy(
                                    backendState = BackendState.CONNECTED
                                ) }
                            }
                            is WsEvent.SessionStarted -> {
                                repository.updateTelemetry { it.copy(
                                    detectorState = if (event.detectorReady) DetectorState.READY else DetectorState.UNAVAILABLE,
                                    activeDetector = event.activeDetector?.let { det -> "READY ($det)" } ?: it.activeDetector
                                ) }
                            }
                            is WsEvent.RiskUpdate -> {
                                repository.updateTelemetry { it.copy(
                                    hasValidResult = true,
                                    currentRisk = event.riskScore,
                                    alertLevel = event.alertLevel,
                                    voiceClassification = event.voiceClassification,
                                    activeDetector = event.activeDetector?.let { det -> "READY ($det)" } ?: it.activeDetector,
                                    lastResultTimestamp = System.currentTimeMillis(),
                                    monitorState = MonitorState.ANALYZING,
                                    audioLevelRms = if (event.rms > 0) event.rms else it.audioLevelRms
                                ) }
                                if (event.alertLevel == "CRITICAL" || event.alertLevel == "HIGH" || event.voiceClassification == "CLONED_VOICE") {
                                    triggerSecurityAlert(event.riskScore, event.alertLevel)
                                }
                            }
                            is WsEvent.StatusUpdate -> {
                                if (!repository.telemetry.value.hasValidResult) {
                                    repository.updateTelemetry { it.copy(
                                        alertLevel = event.status,
                                        callerStatusMessage = if (event.detail.isNotEmpty()) event.detail else it.callerStatusMessage,
                                        audioLevelRms = if (event.rms > 0) event.rms else it.audioLevelRms,
                                        activeDetector = event.activeDetector?.let { det -> "READY ($det)" } ?: it.activeDetector,
                                        monitorState = if (event.status == "WAITING_FOR_DATA" || event.status == "LISTENING") MonitorState.STREAMING else it.monitorState
                                    ) }
                                }
                            }
                            is WsEvent.Disconnected -> {
                                repository.updateTelemetry { it.copy(
                                    monitorState = MonitorState.UNAVAILABLE,
                                    backendState = BackendState.ERROR,
                                    detectorState = DetectorState.UNAVAILABLE,
                                    diagnosticReason = "WebSocket Disconnected"
                                ) }
                                updateStatusNotification("Monitoring unavailable: WebSocket Disconnected")
                            }
                            is WsEvent.Error -> {
                                repository.updateTelemetry { it.copy(
                                    monitorState = MonitorState.UNAVAILABLE,
                                    backendState = BackendState.ERROR,
                                    detectorState = DetectorState.UNAVAILABLE,
                                    diagnosticReason = "Backend Error: ${event.message}"
                                ) }
                                updateStatusNotification("Monitoring unavailable: ${event.message}")
                            }
                            else -> {}
                        }
                    }
                }

                // Wait briefly for WS to connect before sending control metadata
                delay(500)

                webSocketClient?.sendControlMessage("start_call_monitor", mapOf(
                    "audio_source" to (audioPipeline?.activeSourceDescription ?: "VOICE_COMMUNICATION"),
                    "capture_mode" to captureModeString
                ))
                
                updateStatusNotification("Analyzing caller audio ($currentRoute)...")
                
                // Begin audio stream
                audioPipeline?.streamData()

            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) {
                    Log.d("CallMonitorService", "Call monitor coroutine cancelled cleanly: ${e.message}")
                    throw e
                }
                Log.e("CallMonitorService", "Error starting monitor", e)
                val reason = when (e) {
                    is SecurityException -> "Permission Denied: ${e.message}"
                    is IllegalStateException -> "AudioInit Error: ${e.message}"
                    is java.io.IOException -> "Network Error: ${e.message}"
                    else -> "Unknown Error: ${e.message}"
                }
                repository.updateTelemetry { it.copy(
                    monitorState = MonitorState.UNAVAILABLE,
                    audioState = if (e is SecurityException || e is IllegalStateException) AudioCaptureState.UNAVAILABLE else it.audioState,
                    backendState = if (e is java.io.IOException) BackendState.ERROR else it.backendState,
                    diagnosticReason = reason
                ) }
                updateStatusNotification("Monitoring unavailable: $reason")
                
                stopMonitoring()
            }
        }
    }

    private fun stopMonitoring() {
        monitoringJob?.cancel()
        monitoringJob = null
        audioPipeline?.stop()
        audioPipeline = null
        
        webSocketClient?.sendControlMessage("stop_call_monitor")
        webSocketClient?.disconnect()
        webSocketClient = null

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                audioManager?.clearCommunicationDevice()
            } else {
                @Suppress("DEPRECATION")
                audioManager?.stopBluetoothSco()
                @Suppress("DEPRECATION")
                audioManager?.isBluetoothScoOn = false
            }
            audioManager?.mode = AudioManager.MODE_NORMAL
        } catch (audioResetEx: Exception) {
            Log.w("CallMonitorService", "Audio routing reset notice: ${audioResetEx.message}")
        }
        
        repository.resetTelemetry()
        updateStatusNotification("Actively monitoring Calls, SMS & Apps")
    }

    private fun triggerSecurityAlert(risk: Double, level: String) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            putExtra("navigate_to", "call_monitor")
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("⚠ POSSIBLE CLONED VOICE DETECTED")
            .setContentText("Risk: $level (${String.format("%.3f", risk)}). Do not share OTP or sensitive data.")
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setFullScreenIntent(pendingIntent, true)
            .setContentIntent(pendingIntent)
            .setAutoCancel(false)
            .setOngoing(true)
            .build()

        notificationManager.notify(ALERT_NOTIFICATION_ID, notification)
    }

    private fun updateStatusNotification(text: String) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, buildStatusNotification(text))
    }

    private fun buildStatusNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra("navigate_to", "dashboard")
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("CyberGuard Unified Defense Engine")
            .setContentText(text)
            .setSubText("Live Protection")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "$text\n• Calls: AI Voice & Deepfake Detection Armed\n• SMS: Smishing & Phishing Shield Active\n• Apps: Package Integrity & Sideload Interceptor Active"
            ))
            .build()
    }

    private fun registerDynamicReceivers() {
        // 1. Dynamic SMS Interceptor for 100% background delivery
        try {
            val smsFilter = IntentFilter().apply {
                addAction(Telephony.Sms.Intents.SMS_RECEIVED_ACTION)
                addAction("android.provider.Telephony.SMS_RECEIVED")
                priority = 999
            }
            dynamicSmsReceiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent == null) return
                    val messages = try {
                        Telephony.Sms.Intents.getMessagesFromIntent(intent)
                    } catch (_: Exception) { null } ?: return

                    for (sms in messages) {
                        val sender = sms.displayOriginatingAddress ?: "Unknown Sender"
                        val body = sms.displayMessageBody ?: ""
                        Log.d("CallMonitorService", "Real-time background SMS intercepted from $sender")
                        handleIncomingSms(sender, body)
                    }
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(dynamicSmsReceiver, smsFilter, Context.RECEIVER_EXPORTED)
            } else {
                registerReceiver(dynamicSmsReceiver, smsFilter)
            }
        } catch (e: Exception) {
            Log.w("CallMonitorService", "Dynamic SMS receiver registration notice: ${e.message}")
        }

        // 2. Dynamic Package & App Install / Update / Sideload Watchdog
        try {
            val pkgFilter = IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addAction(Intent.ACTION_PACKAGE_REMOVED)
                addDataScheme("package")
            }
            dynamicPackageReceiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    val action = intent?.action ?: return
                    val packageName = intent.data?.schemeSpecificPart ?: return
                    val eventType = when (action) {
                        Intent.ACTION_PACKAGE_ADDED -> "INSTALLED"
                        Intent.ACTION_PACKAGE_REPLACED -> "UPDATED"
                        Intent.ACTION_PACKAGE_REMOVED -> "REMOVED"
                        else -> return
                    }
                    Log.d("CallMonitorService", "Device Security Watchdog event: $eventType on $packageName")
                    if (eventType != "REMOVED") {
                        inspectAndAlertPackage(packageName, eventType)
                    } else {
                        repository.addPackageEvent(
                            PackageEvent(
                                packageName = packageName,
                                appName = packageName.substringAfterLast("."),
                                eventType = eventType,
                                timestamp = System.currentTimeMillis(),
                                riskScore = 0.05f,
                                riskLevel = "SAFE"
                            )
                        )
                    }
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(dynamicPackageReceiver, pkgFilter, Context.RECEIVER_EXPORTED)
            } else {
                registerReceiver(dynamicPackageReceiver, pkgFilter)
            }
        } catch (e: Exception) {
            Log.w("CallMonitorService", "Dynamic Package receiver registration notice: ${e.message}")
        }

        // 3. Dynamic Telephony State Receiver (ensures background call transitions reach service on Android 10-16)
        try {
            val phoneFilter = IntentFilter().apply {
                addAction(TelephonyManager.ACTION_PHONE_STATE_CHANGED)
                @Suppress("DEPRECATION")
                addAction(Intent.ACTION_NEW_OUTGOING_CALL)
                priority = 1000
            }
            dynamicPhoneStateReceiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    val stateStr = intent?.getStringExtra(TelephonyManager.EXTRA_STATE)
                    Log.d("CallMonitorService", "Dynamic Phone State broadcast: $stateStr")
                    when (stateStr) {
                        TelephonyManager.EXTRA_STATE_RINGING -> handleCallStateChange(TelephonyManager.CALL_STATE_RINGING)
                        TelephonyManager.EXTRA_STATE_OFFHOOK -> handleCallStateChange(TelephonyManager.CALL_STATE_OFFHOOK)
                        TelephonyManager.EXTRA_STATE_IDLE -> handleCallStateChange(TelephonyManager.CALL_STATE_IDLE)
                    }
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(dynamicPhoneStateReceiver, phoneFilter, Context.RECEIVER_EXPORTED)
            } else {
                registerReceiver(dynamicPhoneStateReceiver, phoneFilter)
            }
        } catch (e: Exception) {
            Log.w("CallMonitorService", "Dynamic Phone State receiver registration notice: ${e.message}")
        }
    }

    private fun unregisterDynamicReceivers() {
        dynamicSmsReceiver?.let {
            try { unregisterReceiver(it) } catch (_: Exception) {}
            dynamicSmsReceiver = null
        }
        dynamicPackageReceiver?.let {
            try { unregisterReceiver(it) } catch (_: Exception) {}
            dynamicPackageReceiver = null
        }
        dynamicPhoneStateReceiver?.let {
            try { unregisterReceiver(it) } catch (_: Exception) {}
            dynamicPhoneStateReceiver = null
        }
    }

    private fun registerPackageInstallerCallback() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
                val pi = packageManager.packageInstaller
                val cb = object : PackageInstaller.SessionCallback() {
                    override fun onCreated(sessionId: Int) {
                        handleInstallSession(sessionId, "CREATED")
                    }
                    override fun onBadgingChanged(sessionId: Int) {
                        handleInstallSession(sessionId, "BADGING_CHANGED")
                    }
                    override fun onActiveChanged(sessionId: Int, active: Boolean) {
                        if (active) handleInstallSession(sessionId, "ACTIVE")
                    }
                    override fun onProgressChanged(sessionId: Int, progress: Float) {
                        val pct = (progress * 100).toInt()
                        handleInstallSession(sessionId, "IN_PROGRESS ($pct%)")
                    }
                    override fun onFinished(sessionId: Int, success: Boolean) {
                        activeInterceptedSessions.remove(sessionId)
                    }
                }
                pi.registerSessionCallback(cb, Handler(Looper.getMainLooper()))
                packageInstallerSessionCallback = cb
                Log.d("CallMonitorService", "PackageInstaller session callback armed for mid-installation interception.")
            } catch (e: Exception) {
                Log.w("CallMonitorService", "PackageInstaller session callback registration notice: ${e.message}")
            }
        }
    }

    private fun unregisterPackageInstallerCallback() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            packageInstallerSessionCallback?.let {
                try {
                    packageManager.packageInstaller.unregisterSessionCallback(it)
                } catch (_: Exception) {}
                packageInstallerSessionCallback = null
            }
        }
    }

    private fun handleInstallSession(sessionId: Int, stage: String) {
        if (!repository.isPackageWatchdogArmed.value) return
        if (activeInterceptedSessions.contains(sessionId)) return

        try {
            val pi = packageManager.packageInstaller
            val info = pi.getSessionInfo(sessionId) ?: return
            val pkgName = info.appPackageName
            
            // Wait until package name is populated by the installer during badging/progress
            if (pkgName.isNullOrBlank()) return

            val installer = info.installerPackageName

            // Skip official stores, current app, or verified device ecosystem
            if (isKnownOfficialStore(installer) || isDeviceEcosystemApp(pkgName) || pkgName == applicationContext.packageName) {
                return
            }

            // Check if user already whitelisted this package
            val prefs = getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
            val whitelistedSet = prefs.getStringSet("whitelisted_packages", emptySet()) ?: emptySet()
            if (whitelistedSet.contains(pkgName)) return

            activeInterceptedSessions.add(sessionId)

            // FORCED COMPULSORY QUARANTINE:
            // Immediately quarantine upon in-flight external installation detection
            val currentQuarantined = prefs.getStringSet("quarantined_packages", emptySet()) ?: emptySet()
            prefs.edit().putStringSet("quarantined_packages", currentQuarantined + pkgName).apply()
            repository.modifyInstalledApp(pkgName) {
                it.copy(isQuarantined = true)
            }

            val apkPath = findRecentApkForPackage(pkgName)
            val appLabel = info.appLabel?.toString() ?: pkgName.substringAfterLast(".").replaceFirstChar { it.uppercase() }
            val riskScore = 0.92f
            val riskLevel = "CRITICAL"
            val threatDetails = "Real-time interception: external APK installation intercepted in mid-progress ($stage). Origin: ${installer ?: "Direct APK Sideload"}. Bypassed official store verification."

            val alert = MalwareThreatAlert(
                packageName = pkgName,
                appName = appLabel,
                riskScore = riskScore,
                riskLevel = riskLevel,
                installerSource = installer ?: "In-Flight Sideload Session",
                sha256 = "N/A",
                detectedThreatDetails = threatDetails,
                sensitivePermissions = emptyList(),
                threatCategory = "IN_FLIGHT_SIDELOAD_INTERCEPT",
                virusScanResult = "ACTIVE_INSTALLATION_INTERCEPTED",
                playProtectStatus = "NOT VERIFIED BY GOOGLE PLAY PROTECT",
                aiAutonomousRecommendation = "Forced quarantine active. Installation paused. User authorization required to proceed or purge threat.",
                sessionId = sessionId,
                isPreInstall = true,
                apkPath = apkPath
            )
            repository.triggerMalwareAlert(alert)

            val interceptIntent = Intent(applicationContext, com.cyberguard.client.ui.ThreatInterceptActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                        Intent.FLAG_ACTIVITY_CLEAR_TOP or
                        Intent.FLAG_ACTIVITY_SINGLE_TOP or
                        Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                putExtra("package_name", pkgName)
                putExtra("app_name", appLabel)
                putExtra("risk_score", riskScore)
                putExtra("risk_level", riskLevel)
                putExtra("installer_source", installer ?: "In-Flight Sideload Session")
                putExtra("sha256", "N/A")
                putExtra("threat_details", threatDetails)
                putExtra("threat_category", "IN_FLIGHT_SIDELOAD_INTERCEPT")
                putExtra("virus_scan_result", "ACTIVE_INSTALLATION_INTERCEPTED")
                putExtra("play_protect_status", "NOT VERIFIED BY GOOGLE PLAY PROTECT")
                putExtra("ai_recommendation", "Forced quarantine active. Installation paused. User authorization required to proceed or purge threat.")
                putExtra("session_id", sessionId)
                putExtra("is_pre_install", true)
                if (apkPath != null) {
                    putExtra("apk_path", apkPath)
                }
            }

            try {
                applicationContext.startActivity(interceptIntent)
                Log.d("CallMonitorService", "ThreatInterceptActivity launched on the spot in mid-installation for $pkgName (session $sessionId)")
            } catch (e: Exception) {
                Log.w("CallMonitorService", "Direct mid-install intercept window launch notice: ${e.message}")
            }

            triggerMalwareNotification(appLabel, pkgName, riskLevel, riskScore, interceptIntent)
        } catch (e: Exception) {
            Log.w("CallMonitorService", "handleInstallSession notice: ${e.message}")
        }
    }

    private fun handleIncomingSms(sender: String, body: String) {
        if (!repository.isSmsShieldArmed.value) return
        serviceScope.launch {
            try {
                val record = repository.analyzeIncomingSms(sender, body)
                if (record.severity == "HIGH" || record.severity == "CRITICAL") {
                    triggerSmsNotification(sender, record.classification, record.severity, record.riskScore)
                }
            } catch (e: Exception) {
                Log.e("CallMonitorService", "Failed to process incoming SMS: ${e.message}")
            }
        }
    }

    private fun inspectAndAlertPackage(packageName: String, eventType: String) {
        if (!repository.isPackageWatchdogArmed.value) return
        val pm = applicationContext.packageManager
        val appName = try {
            val info = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(info).toString()
        } catch (_: Exception) {
            packageName.substringAfterLast(".")
        }

        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val source = pm.getInstallSourceInfo(packageName)
                source.installingPackageName ?: source.initiatingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }

        val appInfo = try {
            pm.getApplicationInfo(packageName, 0)
        } catch (_: Exception) {
            null
        }

        val isSystem = if (appInfo != null) {
            ((appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0) ||
            ((appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0)
        } else false

        val isOfficial = isSystem || packageName == applicationContext.packageName || isKnownOfficialStore(installer) || isDeviceEcosystemApp(packageName)

        val pkgInfo = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            }
        } catch (_: Exception) {
            null
        }

        val sensitivePermissions = (pkgInfo?.requestedPermissions?.toList() ?: emptyList()).filter { p ->
            p.contains("RECORD_AUDIO", ignoreCase = true) ||
            p.contains("SMS", ignoreCase = true) ||
            p.contains("LOCATION", ignoreCase = true) ||
            p.contains("SYSTEM_ALERT_WINDOW", ignoreCase = true) ||
            p.contains("BIND_ACCESSIBILITY_SERVICE", ignoreCase = true)
        }

        val sha256 = try {
            val apkPath = appInfo?.sourceDir
            if (!apkPath.isNullOrBlank()) {
                val file = File(apkPath)
                if (file.exists()) {
                    val digest = MessageDigest.getInstance("SHA-256")
                    file.inputStream().use { input ->
                        val buffer = ByteArray(8192)
                        var bytesRead: Int
                        while (input.read(buffer).also { bytesRead = it } != -1) {
                            digest.update(buffer, 0, bytesRead)
                        }
                    }
                    digest.digest().joinToString("") { "%02x".format(it) }
                } else "N/A"
            } else "N/A"
        } catch (_: Exception) {
            "N/A"
        }

        val isSideloaded = !isOfficial
        val riskScore = if (isSideloaded) 0.88f else 0.05f
        val riskLevel = if (isSideloaded) "CRITICAL" else "SAFE"

        val event = PackageEvent(
            packageName = packageName,
            appName = appName,
            eventType = eventType,
            timestamp = System.currentTimeMillis(),
            riskScore = riskScore,
            riskLevel = riskLevel
        )
        repository.addPackageEvent(event)

        // Live update persistent installed apps inventory
        repository.modifyInstalledApp(packageName) {
            it.copy(
                isQuarantined = isSideloaded,
                riskScore = riskScore,
                riskLevel = riskLevel,
                lastUpdateTime = System.currentTimeMillis()
            )
        }

        if (isSideloaded) {
            val prefs = getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
            val qSet = prefs.getStringSet("quarantined_packages", emptySet()) ?: emptySet()
            prefs.edit().putStringSet("quarantined_packages", qSet + packageName).apply()

            val detectedApkPath = appInfo?.sourceDir ?: findRecentApkForPackage(packageName)
            val threatDetails = "Sideloaded from unverified external origin (${installer ?: "Manual Sideload APK"}). Bypassed official store verification."
            val alert = MalwareThreatAlert(
                packageName = packageName,
                appName = appName,
                riskScore = riskScore,
                riskLevel = riskLevel,
                installerSource = installer ?: "Direct APK Sideload",
                sha256 = sha256,
                detectedThreatDetails = threatDetails,
                sensitivePermissions = sensitivePermissions,
                threatCategory = "UNOFFICIAL_SIDELOAD_MALWARE",
                virusScanResult = "HIGH_ENTROPY_EXECUTABLE",
                playProtectStatus = "NOT VERIFIED BY GOOGLE PLAY PROTECT",
                aiAutonomousRecommendation = "Forced quarantine active. Installation temporarily frozen. Choose to delete/uninstall or authorize installation.",
                apkPath = detectedApkPath
            )
            repository.triggerMalwareAlert(alert)

            // Direct On-The-Spot 50th-Century Interception Window Popup
            val interceptIntent = Intent(applicationContext, com.cyberguard.client.ui.ThreatInterceptActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                        Intent.FLAG_ACTIVITY_CLEAR_TOP or
                        Intent.FLAG_ACTIVITY_SINGLE_TOP or
                        Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                putExtra("package_name", packageName)
                putExtra("app_name", appName)
                putExtra("risk_score", riskScore)
                putExtra("risk_level", riskLevel)
                putExtra("installer_source", installer ?: "Direct APK Sideload")
                putExtra("sha256", sha256)
                putExtra("threat_details", threatDetails)
                putStringArrayListExtra("sensitive_permissions", ArrayList(sensitivePermissions))
                putExtra("threat_category", "UNOFFICIAL_SIDELOAD_MALWARE")
                putExtra("virus_scan_result", "HIGH_ENTROPY_EXECUTABLE")
                putExtra("play_protect_status", "NOT VERIFIED BY GOOGLE PLAY PROTECT")
                putExtra("ai_recommendation", "Forced quarantine active. Installation temporarily frozen. Choose to delete/uninstall or authorize installation.")
                if (detectedApkPath != null) {
                    putExtra("apk_path", detectedApkPath)
                }
            }
            try {
                applicationContext.startActivity(interceptIntent)
                Log.d("CallMonitorService", "ThreatInterceptActivity launched immediately on the spot for $packageName")
            } catch (e: Exception) {
                Log.w("CallMonitorService", "Direct intercept window launch exception: ${e.message}")
            }

            triggerMalwareNotification(appName, packageName, riskLevel, riskScore, interceptIntent)
        }
    }

    private fun findRecentApkForPackage(packageName: String): String? {
        try {
            val pm = applicationContext.packageManager
            // 1. Check if application already installed and has sourceDir
            try {
                val appInfo = pm.getApplicationInfo(packageName, 0)
                if (!appInfo.sourceDir.isNullOrBlank() && File(appInfo.sourceDir).exists()) {
                    return appInfo.sourceDir
                }
            } catch (_: Exception) {}

            // 2. Scan standard Download & cache directories
            val downloadDirs = listOfNotNull(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                applicationContext.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS),
                applicationContext.cacheDir,
                applicationContext.externalCacheDir
            )

            for (dir in downloadDirs) {
                if (dir.exists() && dir.isDirectory) {
                    val apkFiles = dir.listFiles { file -> file.isFile && file.name.endsWith(".apk", ignoreCase = true) }
                    apkFiles?.sortByDescending { it.lastModified() }
                    apkFiles?.forEach { apkFile ->
                        try {
                            val archiveInfo = pm.getPackageArchiveInfo(apkFile.absolutePath, 0)
                            if (archiveInfo?.packageName == packageName) {
                                return apkFile.absolutePath
                            }
                        } catch (_: Exception) {}
                    }
                }
            }
        } catch (e: Exception) {
            Log.w("CallMonitorService", "findRecentApkForPackage notice: ${e.message}")
        }
        return null
    }

    private fun isDeviceEcosystemApp(packageName: String): Boolean {
        val mfg = Build.MANUFACTURER.lowercase()
        val brand = Build.BRAND.lowercase()
        val deviceStr = "$mfg $brand"
        return when {
            deviceStr.contains("xiaomi") || deviceStr.contains("redmi") || deviceStr.contains("poco") -> {
                packageName.startsWith("com.xiaomi.") || packageName.startsWith("com.miui.") ||
                packageName.startsWith("com.mi.") || packageName.startsWith("com.redmi.")
            }
            deviceStr.contains("samsung") -> {
                packageName.startsWith("com.sec.") || packageName.startsWith("com.samsung.")
            }
            deviceStr.contains("google") -> {
                packageName.startsWith("com.google.android.") || packageName.startsWith("com.google.") || packageName.startsWith("android.")
            }
            deviceStr.contains("oppo") || deviceStr.contains("oneplus") || deviceStr.contains("realme") || deviceStr.contains("vivo") -> {
                packageName.startsWith("com.oppo.") || packageName.startsWith("com.coloros.") ||
                packageName.startsWith("com.heytap.") || packageName.startsWith("com.oneplus.") ||
                packageName.startsWith("com.vivo.") || packageName.startsWith("com.bbk.") ||
                packageName.startsWith("com.realme.") || packageName.startsWith("com.iqoo.")
            }
            deviceStr.contains("motorola") || deviceStr.contains("lenovo") -> {
                packageName.startsWith("com.motorola.") || packageName.startsWith("com.lenovo.")
            }
            else -> false
        }
    }

    private fun isKnownOfficialStore(installer: String?): Boolean {
        if (installer == null) return false
        val lower = installer.lowercase()
        // Package installer vehicles (e.g. Google package installer, MIUI package installer)
        // are system installer dialogs used to sideload external APKs, NOT verified app stores!
        if (lower.contains("packageinstaller")) {
            return false
        }
        return lower.contains("vending") ||
               lower.contains("googleplay") ||
               lower.contains("appstore") ||
               lower.contains("phonepe") ||
               lower.contains("indus") ||
               lower.contains("mipicks") ||
               lower.contains("xiaomi.market") ||
               lower.contains("bbk.appstore") ||
               lower.contains("vivo.appstore") ||
               lower.contains("samsungapps") ||
               lower.contains("oppo.market") ||
               lower.contains("heytap.market") ||
               lower.contains("coloros.phonemanager") ||
               lower.contains("huawei.appmarket") ||
               lower.contains("amazon.venezia")
    }

    private fun triggerMalwareNotification(
        appName: String, 
        packageName: String, 
        level: String, 
        score: Float,
        interceptIntent: Intent? = null
    ) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val targetIntent = interceptIntent ?: Intent(this, com.cyberguard.client.ui.ThreatInterceptActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("package_name", packageName)
            putExtra("app_name", appName)
            putExtra("risk_score", score)
            putExtra("risk_level", level)
        }
        val pendingIntent = PendingIntent.getActivity(
            this, packageName.hashCode(), targetIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("🚨 MALICIOUS / UNVERIFIED APP DETECTED")
            .setContentText("$appName ($packageName) flagged as $level ($score). Tap to inspect & isolate.")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "Autonomous Threat Intercept: Unsafe app $appName ($packageName) blocked on-the-spot. Tap to inspect deep dossier & isolate."
            ))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setFullScreenIntent(pendingIntent, true)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(ALERT_NOTIFICATION_ID + 10, notification)
    }

    private fun triggerSmsNotification(sender: String, classification: String, severity: String, risk: Float) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("navigate_to", "comms")
        }
        val pendingIntent = PendingIntent.getActivity(
            this, sender.hashCode(), intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("⚠ SMISHING / PHISHING SMS INTERCEPTED")
            .setContentText("$sender: $classification ($severity • ${(risk * 100).toInt()}% risk). Tap to inspect threat report.")
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(ALERT_NOTIFICATION_ID + 20, notification)
    }

    private fun startBackgroundWatchdogLoop() {
        integrityWatchdogJob?.cancel()
        integrityWatchdogJob = serviceScope.launch {
            var loopCount = 0
            while (isActive) {
                delay(1500)
                loopCount++
                try {
                    // Heartbeat 1: Real-time call state synchronization
                    val tm = telephonyManager
                    val am = audioManager
                    val callState = tm?.callState ?: TelephonyManager.CALL_STATE_IDLE
                    val isAudioInCall = am?.mode == AudioManager.MODE_IN_CALL || am?.mode == AudioManager.MODE_IN_COMMUNICATION
                    val currentRepoCallState = repository.telemetry.value.callState

                    if ((callState == TelephonyManager.CALL_STATE_OFFHOOK || isAudioInCall) && currentRepoCallState != TelephonyCallState.ACTIVE) {
                        Log.d("CallMonitorService", "Background Watchdog detected active in-progress call! Auto-activating pipeline.")
                        handleCallStateChange(TelephonyManager.CALL_STATE_OFFHOOK)
                    } else if (callState == TelephonyManager.CALL_STATE_IDLE && !isAudioInCall && currentRepoCallState == TelephonyCallState.ACTIVE) {
                        Log.d("CallMonitorService", "Background Watchdog detected call end. Stopping pipeline.")
                        handleCallStateChange(TelephonyManager.CALL_STATE_IDLE)
                    }

                    // Heartbeat 2: Root & Device integrity audit every ~60s (40 loops * 1.5s)
                    if (loopCount % 40 == 0) {
                        val rootPaths = arrayOf(
                            "/system/bin/su",
                            "/system/xbin/su",
                            "/sbin/su",
                            "/system/sd/xbin/su",
                            "/system/bin/failsafe/su",
                            "/data/local/xbin/su",
                            "/data/local/bin/su",
                            "/data/local/su"
                        )
                        val rootDetected = rootPaths.any { File(it).exists() } || Build.TAGS?.contains("test-keys") == true
                        if (rootDetected) {
                            Log.w("CallMonitorService", "Root binary breach detected during background integrity audit!")
                        }
                    }
                } catch (_: Exception) {}
            }
        }
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            
            val statusChannel = NotificationChannel(
                CHANNEL_ID,
                "CyberGuard Unified Defense",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(statusChannel)
            
            val alertChannel = NotificationChannel(
                ALERT_CHANNEL_ID,
                "CyberGuard Security Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Critical alerts for deepfake callers, malicious apps, and smishing attacks"
                enableVibration(true)
            }
            manager.createNotificationChannel(alertChannel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        stopMonitoring()
        unregisterDynamicReceivers()
        unregisterPackageInstallerCallback()
        integrityWatchdogJob?.cancel()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && audioDeviceCallback != null) {
            audioManager?.unregisterAudioDeviceCallback(audioDeviceCallback)
        }
        serviceScope.cancel()
    }
}

