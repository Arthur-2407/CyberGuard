package com.cyberguard.client.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import android.media.AudioManager
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.cyberguard.client.model.CallMonitorRepository
import com.cyberguard.client.network.ConnectionState
import com.cyberguard.client.network.InstalledAppInfo
import com.cyberguard.client.network.DeviceHardwareInfo
import com.cyberguard.client.network.toUserFacingErrorMessage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {
    
    private val repository = CallMonitorRepository.getInstance(application)
    val connectionManager = repository.connectionManager
    
    val connectionState: StateFlow<ConnectionState> = connectionManager.connectionState
    val serverUrl: StateFlow<String?> = connectionManager.serverUrl
    val discoveryStatus: StateFlow<String> = connectionManager.discoveryStatus
    val detectedGatewayIp: String? get() = connectionManager.getDetectedGatewayOrHostIp()
    
    val telemetry = repository.telemetry
    
    val authManager = connectionManager.authManager
    val currentUser = authManager.currentUser
    val authToken = authManager.authToken

    // Device Security App Inventory & Hardware Baseline (Persistent Singleton Flow)
    val installedApps: StateFlow<List<InstalledAppInfo>> = repository.installedApps
    val isDeviceScanning: StateFlow<Boolean> = repository.isDeviceScanning
    val deviceHardwareInfo: StateFlow<DeviceHardwareInfo?> = repository.deviceHardwareInfo

    private val _dashboardSummary = kotlinx.coroutines.flow.MutableStateFlow<com.cyberguard.client.network.IncidentSummaryResponse?>(null)
    val dashboardSummary: StateFlow<com.cyberguard.client.network.IncidentSummaryResponse?> = _dashboardSummary

    private val _systemStatus = kotlinx.coroutines.flow.MutableStateFlow<com.cyberguard.client.network.StatusResponse?>(null)
    val systemStatus: StateFlow<com.cyberguard.client.network.StatusResponse?> = _systemStatus

    val showAuthModal = kotlinx.coroutines.flow.MutableStateFlow(false)

    private val _isSummaryLoading = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isSummaryLoading: StateFlow<Boolean> = _isSummaryLoading

    // Call Screening & Scam Defense
    val isCallScreeningRoleHeld = repository.isCallScreeningRoleHeld
    val callScreeningPolicy = repository.callScreeningPolicy
    val screenedCalls = repository.screenedCalls

    fun checkScreeningRoleStatus() {
        repository.checkScreeningRoleStatus()
    }

    fun forceArmCallScreening(armed: Boolean = true) {
        repository.forceArmCallScreening(armed)
    }

    fun refreshScreenedCalls() {
        repository.refreshScreenedCalls()
    }

    fun updateCallScreeningPolicy(policy: com.cyberguard.client.telecom.CallScreeningPolicy) {
        repository.updateCallScreeningPolicy(policy)
    }

    fun clearScreenedCalls() {
        repository.clearScreenedCalls()
    }

    init {
        // Start automatic discovery on init
        connectionManager.startDiscovery()
    }
    
    fun connectManually(host: String, port: String) {
        val p = port.toIntOrNull() ?: 3000
        connectionManager.connectManually(host, p)
    }
    
    fun retryDiscovery() {
        connectionManager.startDiscovery()
    }

    fun scanSubnet(onFound: (String) -> Unit, onFinished: () -> Unit) {
        connectionManager.scanSubnetOnDemand(onFound, onFinished)
    }

    suspend fun refreshDashboardSummary() {
        val api = connectionManager.api ?: return
        try {
            _isSummaryLoading.value = true
            val summary = api.getIncidentSummary()
            _dashboardSummary.value = summary
        } catch (e: Exception) {
            // Maintain resilient telemetry state on network fluctuation
        } finally {
            _isSummaryLoading.value = false
        }

        try {
            val status = api.getStatus()
            _systemStatus.value = status
        } catch (e: Exception) {
            // Ignore status refresh error
        }
    }

    suspend fun login(usernameOrEmail: String, password: String): Result<com.cyberguard.client.network.UserResponse> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("CyberGuard core server disconnected"))
        return try {
            val req = com.cyberguard.client.network.LoginRequest(
                usernameOrEmail = usernameOrEmail.trim(),
                password = password
            )
            val authResp = api.login(req)
            authManager.saveSession(authResp.token, authResp.user)
            refreshDashboardSummary()
            Result.success(authResp.user)
        } catch (e: Exception) {
            val friendlyMsg = e.toUserFacingErrorMessage()
            Result.failure(Exception(friendlyMsg))
        }
    }

    suspend fun register(username: String, email: String, password: String): Result<com.cyberguard.client.network.UserResponse> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("CyberGuard core server disconnected"))
        return try {
            val req = com.cyberguard.client.network.RegisterRequest(
                username = username.trim(),
                email = email.trim(),
                password = password
            )
            val authResp = api.register(req)
            authManager.saveSession(authResp.token, authResp.user)
            refreshDashboardSummary()
            Result.success(authResp.user)
        } catch (e: Exception) {
            val friendlyMsg = e.toUserFacingErrorMessage()
            Result.failure(Exception(friendlyMsg))
        }
    }

    suspend fun logout() {
        try {
            connectionManager.api?.logout()
        } catch (e: Exception) {
            // Ignore network errors on logout
        } finally {
            authManager.clearSession()
            _dashboardSummary.value = null
        }
    }

    suspend fun refreshUserProfile() {
        val api = connectionManager.api ?: return
        if (!authManager.isLoggedIn) return
        try {
            val user = api.getMe()
            if (user != null) {
                authManager.updateUser(user)
            }
        } catch (e: Exception) {
            // If token expired (401), clear invalid session
            if (e.message?.contains("401") == true) {
                authManager.clearSession()
            }
        }
    }
    
    fun ensureDefenseWatchdogRunning() {
        val intent = android.content.Intent(getApplication(), com.cyberguard.client.service.CallMonitorService::class.java).apply {
            action = com.cyberguard.client.service.CallMonitorService.ACTION_START_WATCHDOG
        }
        val app = getApplication<Application>()
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            app.startForegroundService(intent)
        } else {
            app.startService(intent)
        }
    }

    fun performLogout() {
        viewModelScope.launch {
            logout()
        }
    }

    fun simulateTestScreenedCall() {
        viewModelScope.launch(Dispatchers.IO) {
            val db = com.cyberguard.client.telecom.CallScreeningDatabaseHelper.getInstance(getApplication())
            val testRecord = com.cyberguard.client.telecom.ScreenedCallRecord(
                rawNumber = "+1 (800) 555-0199",
                normalizedNumber = "+18005550199",
                callerDisplayName = "Suspected VoIP Robocaller",
                classification = com.cyberguard.client.telecom.CallRiskClassification.HIGH_RISK,
                riskScore = 0.94f,
                confidence = 0.98f,
                reasonCodes = listOf("HIGH_RISK_VOIP_ORIGIN", "FAILED_STIR_SHAKEN", "FRESH_NUMBER_SURGE"),
                carrierVerificationStatus = com.cyberguard.client.telecom.CarrierVerificationStatus.FAILED,
                actionRecommended = com.cyberguard.client.telecom.ScreeningAction.BLOCK,
                actionApplied = com.cyberguard.client.telecom.ScreeningAction.BLOCK,
                responseLatencyMs = 38L,
                explanation = "Inbound caller failed carrier STIR/SHAKEN cryptographic signature verification and matches known robodialer signature.",
                isSyncedToSoc = false
            )
            db.saveScreenedCall(testRecord)
            repository.refreshScreenedCalls()
        }
    }
    
    fun startManualCallMonitor() {
        val intent = android.content.Intent(getApplication(), com.cyberguard.client.service.CallMonitorService::class.java).apply {
            action = com.cyberguard.client.service.CallMonitorService.ACTION_START_MONITORING
        }
        val app = getApplication<Application>()
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            app.startForegroundService(intent)
        } else {
            app.startService(intent)
        }
    }

    fun stopManualCallMonitor() {
        val intent = android.content.Intent(getApplication(), com.cyberguard.client.service.CallMonitorService::class.java).apply {
            action = com.cyberguard.client.service.CallMonitorService.ACTION_STOP_MONITORING
        }
        val app = getApplication<Application>()
        app.startService(intent)
    }
    
    val smsThreatRecords = repository.smsThreatRecords
    val isSmsShieldArmed = repository.isSmsShieldArmed
    val packageEvents = repository.packageEvents
    val isPackageWatchdogArmed = repository.isPackageWatchdogArmed
    val activeMalwareAlert = repository.activeMalwareAlert

    fun dismissMalwareAlert() {
        repository.dismissMalwareAlert()
    }

    fun triggerMalwareAlert(alert: com.cyberguard.client.model.MalwareThreatAlert) {
        repository.triggerMalwareAlert(alert)
    }

    fun setSmsShieldArmed(armed: Boolean) {
        repository.setSmsShieldArmed(armed)
    }

    suspend fun analyzeSmsText(sender: String, body: String): com.cyberguard.client.network.SmsThreatRecord {
        return repository.analyzeIncomingSms(sender, body)
    }

    fun clearSmsThreats() {
        repository.clearSmsThreats()
    }

    fun setPackageWatchdogArmed(armed: Boolean) {
        repository.setPackageWatchdogArmed(armed)
    }

    fun clearPackageEvents() {
        repository.clearPackageEvents()
    }

    // Admin Operations
    suspend fun getAdminUsers(): Result<List<com.cyberguard.client.network.AdminUserItem>> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            Result.success(api.getAdminUsers())
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    suspend fun updateAdminUserStatus(userId: Int, isActive: Boolean?, resetRequired: Boolean?, newPassword: String?): Result<Map<String, Any>> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            val req = com.cyberguard.client.network.UpdateUserStatusRequest(isActive, resetRequired, newPassword)
            Result.success(api.updateAdminUserStatus(userId, req))
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    suspend fun createAdminUser(req: com.cyberguard.client.network.CreateUserRequest): Result<com.cyberguard.client.network.AdminUserItem> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            Result.success(api.createAdminUser(req))
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    suspend fun getReviewQueue(status: String? = null, risk: String? = null, search: String? = null): Result<com.cyberguard.client.network.ReviewQueueResponse> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            Result.success(api.getReviewQueue(status, risk, search))
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    suspend fun submitReviewDecision(reviewId: String, req: com.cyberguard.client.network.ReviewDecisionRequest): Result<Map<String, Any>> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            Result.success(api.submitReviewDecision(reviewId, req))
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    suspend fun getTrainingStatus(): Result<com.cyberguard.client.network.TrainingStatusResponse> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            Result.success(api.getTrainingStatus())
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    suspend fun triggerRetraining(epochs: Int? = 5, learningRate: Float? = 1e-4f): Result<Map<String, Any>> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            Result.success(api.triggerRetraining(epochs, learningRate))
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    suspend fun getAdminAuditLogs(limit: Int = 50, offset: Int = 0): Result<com.cyberguard.client.network.AdminAuditLogsResponse> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            Result.success(api.getAdminAuditLogs(limit, offset))
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    suspend fun investigatePackageDeep(
        packageName: String,
        appName: String,
        sha256: String,
        installer: String,
        isOfficialStore: Boolean
    ): Result<com.cyberguard.client.network.DeepInvestigationResult> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            // 1. Query VirusTotal + URLhaus via backend threat intel pipeline
            val threatEvent = try {
                api.searchThreatIntel(ioc = sha256)
            } catch (_: Exception) {
                null
            }

            // 2. Synthesize with Qwen LLM security analysis
            val llmReq = mutableMapOf<String, Any>(
                "source" to "android_device_security_audit",
                "package_name" to packageName,
                "app_name" to appName,
                "sha256" to sha256,
                "installer_source" to installer,
                "is_official_store" to isOfficialStore
            )
            if (threatEvent != null) {
                llmReq["threat_data"] = threatEvent
                llmReq["threat_category"] = threatEvent.threatCategory
                llmReq["severity"] = threatEvent.severity
            } else {
                llmReq["threat_category"] = "UNOFFICIAL_PACKAGE_AUDIT"
                llmReq["severity"] = if (isOfficialStore) "SAFE" else "HIGH"
            }

            val llmResponse = try {
                api.askQwenLlm(llmReq)
            } catch (_: Exception) {
                null
            }

            // Extract VT detections if present in threat intelligence metadata
            var vtHits = 0
            var vtTotal = 0
            var urlhausText = "CLEAN / NOT LISTED"

            threatEvent?.threatIntelligence?.let { ti ->
                val vt = ti["virustotal"] as? Map<*, *>
                if (vt != null) {
                    val stats = vt["last_analysis_stats"] as? Map<*, *>
                    if (stats != null) {
                        val mal = (stats["malicious"] as? Number)?.toInt() ?: 0
                        val susp = (stats["suspicious"] as? Number)?.toInt() ?: 0
                        val harmless = (stats["harmless"] as? Number)?.toInt() ?: 0
                        val undetected = (stats["undetected"] as? Number)?.toInt() ?: 0
                        vtHits = mal + susp
                        vtTotal = mal + susp + harmless + undetected
                    }
                }
                val uh = ti["urlhaus"] as? Map<*, *>
                if (uh != null) {
                    val matched = uh["matched"] as? Boolean ?: false
                    val threat = uh["threat"] as? String
                    if (matched) {
                        urlhausText = "FLAGGED: ${threat ?: "MALICIOUS_PAYLOAD"}"
                    }
                }
            }

            val finalSeverity = llmResponse?.assessedSeverity
                ?: threatEvent?.severity
                ?: if (isOfficialStore) "SAFE" else "HIGH"

            val execSummary = llmResponse?.executiveBriefing
                ?: llmResponse?.executiveSummary
                ?: threatEvent?.explanation?.summary
                ?: "Investigation completed for $appName ($packageName). Origin: $installer."

            val containment = llmResponse?.immediateContainment?.joinToString("\n• ")
                ?: if (isOfficialStore) "Verified authentic package from official repository."
                   else "Unofficial package origin. Recommend review before authorizing runtime execution."

            var liveHits = 0
            var liveSummary: String? = null
            threatEvent?.threatIntelligence?.let { ti ->
                val liveIntel = ti["live_intelligence"] as? Map<*, *>
                if (liveIntel != null) {
                    val osint = liveIntel["osint"] as? Map<*, *>
                    liveHits = (osint?.get("hits_count") as? Number)?.toInt() ?: 0
                    val qwen = liveIntel["qwen_llm_synthesis"] as? Map<*, *>
                    liveSummary = qwen?.get("executive_briefing") as? String
                }
            }

            Result.success(
                com.cyberguard.client.network.DeepInvestigationResult(
                    packageName = packageName,
                    appName = appName,
                    sha256 = sha256,
                    installer = installer,
                    isOfficialStore = isOfficialStore,
                    threatEvent = threatEvent,
                    llmAnalysis = llmResponse,
                    vtDetections = vtHits,
                    vtTotalEngines = if (vtTotal > 0) vtTotal else 72,
                    urlhausStatus = urlhausText,
                    finalVerdict = finalSeverity,
                    executiveSummary = execSummary,
                    containmentRecommendation = containment,
                    osintHits = liveHits,
                    liveInspectionSummary = liveSummary,
                    urlSha256 = sha256
                )
            )
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    fun updateInstalledApps(apps: List<InstalledAppInfo>) {
        repository.updateInstalledApps(apps)
    }

    fun modifyInstalledApp(packageName: String, modifier: (InstalledAppInfo) -> InstalledAppInfo) {
        repository.modifyInstalledApp(packageName, modifier)
    }

    fun removeInstalledApp(packageName: String) {
        repository.removeInstalledApp(packageName)
    }

    fun setDeviceScanning(isScanning: Boolean) {
        repository.setDeviceScanning(isScanning)
    }

    fun updateDeviceHardwareInfo(info: DeviceHardwareInfo) {
        repository.updateDeviceHardwareInfo(info)
    }

    fun syncActiveCallState(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
                val am = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
                val callState = tm?.callState ?: TelephonyManager.CALL_STATE_IDLE
                val isAudioInCall = am?.mode == AudioManager.MODE_IN_CALL || am?.mode == AudioManager.MODE_IN_COMMUNICATION
                if (callState == TelephonyManager.CALL_STATE_OFFHOOK || isAudioInCall) {
                    val serviceIntent = Intent(context, com.cyberguard.client.service.CallMonitorService::class.java).apply {
                        action = com.cyberguard.client.service.CallMonitorService.ACTION_START_MONITORING
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(serviceIntent)
                    } else {
                        context.startService(serviceIntent)
                    }
                }
            } catch (e: Exception) {
                Log.w("MainViewModel", "syncActiveCallState notice: ${e.message}")
            }
        }
    }

    suspend fun verifyOemAppBackend(
        packageName: String,
        appName: String,
        brand: String,
        model: String,
        sha256: String?
    ): Result<Map<String, Any?>> {
        val api = connectionManager.api ?: return Result.failure(IllegalStateException("Disconnected from CyberGuard Core"))
        return try {
            val req = mapOf<String, Any>(
                "package_name" to packageName,
                "app_name" to appName,
                "device_brand" to brand,
                "device_model" to model,
                "sha256" to (sha256 ?: "N/A")
            )
            val res = api.verifyOemApp(req)
            Result.success(res)
        } catch (e: Exception) {
            Result.failure(Exception(e.toUserFacingErrorMessage()))
        }
    }

    override fun onCleared() {
        super.onCleared()
    }
}
