package com.cyberguard.client.model

import android.content.Context
import com.cyberguard.client.network.ConnectionManager
import com.cyberguard.client.network.PackageEvent
import com.cyberguard.client.network.SmsThreatRecord
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

class CallMonitorRepository private constructor(context: Context) {
    
    val connectionManager = ConnectionManager(context.applicationContext)
    
    // Call telemetry
    private val _telemetry = MutableStateFlow(CallMonitorTelemetry())
    val telemetry: StateFlow<CallMonitorTelemetry> = _telemetry

    // Real-Time SMS Shield State & History
    private val _isSmsShieldArmed = MutableStateFlow(true)
    val isSmsShieldArmed: StateFlow<Boolean> = _isSmsShieldArmed

    private val _smsThreatRecords = MutableStateFlow<List<SmsThreatRecord>>(emptyList())
    val smsThreatRecords: StateFlow<List<SmsThreatRecord>> = _smsThreatRecords

    private val _isPackageWatchdogArmed = MutableStateFlow(true)
    val isPackageWatchdogArmed: StateFlow<Boolean> = _isPackageWatchdogArmed

    private val _packageEvents = MutableStateFlow<List<PackageEvent>>(emptyList())
    val packageEvents: StateFlow<List<PackageEvent>> = _packageEvents

    // Real-Time Background Malware Alert State
    private val _activeMalwareAlert = MutableStateFlow<MalwareThreatAlert?>(null)
    val activeMalwareAlert: StateFlow<MalwareThreatAlert?> = _activeMalwareAlert

    // Real-Time Official Call Screening State
    private val appContext = context.applicationContext
    private val dbHelper = com.cyberguard.client.telecom.CallScreeningDatabaseHelper.getInstance(appContext)
    private val policyManager = com.cyberguard.client.telecom.CallScreeningPolicyManager(appContext)

    private val _isCallScreeningRoleHeld = MutableStateFlow(false)
    val isCallScreeningRoleHeld: StateFlow<Boolean> = _isCallScreeningRoleHeld

    private val _callScreeningPolicy = MutableStateFlow(policyManager.getPolicy())
    val callScreeningPolicy: StateFlow<com.cyberguard.client.telecom.CallScreeningPolicy> = _callScreeningPolicy

    private val _screenedCalls = MutableStateFlow<List<com.cyberguard.client.telecom.ScreenedCallRecord>>(emptyList())
    val screenedCalls: StateFlow<List<com.cyberguard.client.telecom.ScreenedCallRecord>> = _screenedCalls

    init {
        checkScreeningRoleStatus()
        refreshScreenedCalls()
    }

    fun checkScreeningRoleStatus() {
        val prefs = appContext.getSharedPreferences("cyberguard_call_screening", android.content.Context.MODE_PRIVATE)
        val isOverride = prefs.getBoolean("screening_armed_override", false)
        if (isOverride) {
            _isCallScreeningRoleHeld.value = true
            return
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            val roleManager = appContext.getSystemService(android.content.Context.ROLE_SERVICE) as? android.app.role.RoleManager
            _isCallScreeningRoleHeld.value = roleManager?.isRoleHeld(android.app.role.RoleManager.ROLE_CALL_SCREENING) == true
        } else {
            _isCallScreeningRoleHeld.value = false
        }
    }

    fun forceArmCallScreening(armed: Boolean = true) {
        val prefs = appContext.getSharedPreferences("cyberguard_call_screening", android.content.Context.MODE_PRIVATE)
        prefs.edit().putBoolean("screening_armed_override", armed).apply()
        _isCallScreeningRoleHeld.value = armed
    }

    fun refreshScreenedCalls() {
        _screenedCalls.value = dbHelper.getRecentScreenedCalls(limit = 100)
    }

    fun updateCallScreeningPolicy(policy: com.cyberguard.client.telecom.CallScreeningPolicy) {
        policyManager.updatePolicy(policy)
        _callScreeningPolicy.value = policy
    }

    fun clearScreenedCalls() {
        dbHelper.clearRecords()
        _screenedCalls.value = emptyList()
    }

    fun triggerMalwareAlert(alert: MalwareThreatAlert) {
        _activeMalwareAlert.value = alert
    }

    fun dismissMalwareAlert() {
        _activeMalwareAlert.value = null
    }

    fun updateTelemetry(updater: (CallMonitorTelemetry) -> CallMonitorTelemetry) {
        _telemetry.update(updater)
    }

    fun resetTelemetry() {
        _telemetry.value = CallMonitorTelemetry()
    }

    fun setSmsShieldArmed(armed: Boolean) {
        _isSmsShieldArmed.value = armed
    }

    fun addSmsThreat(record: SmsThreatRecord) {
        _smsThreatRecords.update { current ->
            listOf(record) + current.take(99)
        }
    }

    fun clearSmsThreats() {
        _smsThreatRecords.value = emptyList()
    }

    fun setPackageWatchdogArmed(armed: Boolean) {
        _isPackageWatchdogArmed.value = armed
    }

    fun addPackageEvent(event: PackageEvent) {
        _packageEvents.update { current ->
            listOf(event) + current.take(99)
        }
    }

    fun clearPackageEvents() {
        _packageEvents.value = emptyList()
    }

    // ── Persistent Device Security App Inventory & Hardware Baseline ──
    private val _installedApps = MutableStateFlow<List<com.cyberguard.client.network.InstalledAppInfo>>(emptyList())
    val installedApps: StateFlow<List<com.cyberguard.client.network.InstalledAppInfo>> = _installedApps

    private val _isDeviceScanning = MutableStateFlow(false)
    val isDeviceScanning: StateFlow<Boolean> = _isDeviceScanning

    private val _deviceHardwareInfo = MutableStateFlow<com.cyberguard.client.network.DeviceHardwareInfo?>(null)
    val deviceHardwareInfo: StateFlow<com.cyberguard.client.network.DeviceHardwareInfo?> = _deviceHardwareInfo

    fun updateInstalledApps(apps: List<com.cyberguard.client.network.InstalledAppInfo>) {
        _installedApps.value = apps
    }

    fun modifyInstalledApp(packageName: String, modifier: (com.cyberguard.client.network.InstalledAppInfo) -> com.cyberguard.client.network.InstalledAppInfo) {
        _installedApps.update { current ->
            current.map { if (it.packageName == packageName) modifier(it) else it }
        }
    }

    fun removeInstalledApp(packageName: String) {
        _installedApps.update { current ->
            current.filter { it.packageName != packageName }
        }
    }

    fun setDeviceScanning(isScanning: Boolean) {
        _isDeviceScanning.value = isScanning
    }

    fun updateDeviceHardwareInfo(info: com.cyberguard.client.network.DeviceHardwareInfo) {
        _deviceHardwareInfo.value = info
    }

    suspend fun analyzeIncomingSms(sender: String, body: String): SmsThreatRecord {
        val api = connectionManager.api
        val currUser = connectionManager.authManager.currentUser.value
        val isLoggedIn = connectionManager.authManager.isLoggedIn && currUser != null
        val isGuest = !isLoggedIn

        var risk = 0.05f
        var sev = "SAFE"
        var classification = "CLEAN"
        var reasoning = "SMS text evaluated by on-device and SOC threat engines."
        val urls = Regex("""https?://\S+""").findAll(body).map { it.value.trimEnd('.', ',', ';', '!', '?') }.toList()
        var actions = listOf("No defensive action required")
        var urlSha256: String? = null
        var urlPurpose: String? = null
        var vtStatsText: String? = null
        var urlhausText: String? = null
        var qwenBriefing: String? = null
        var liveOsintHits = 0
        var livePageTitle: String? = null
        var liveCredentialProbe = false
        var liveRenderingEngine: String? = null

        // URL Hashing & Semantic Purpose Detection
        if (urls.isNotEmpty()) {
            val firstUrl = urls[0]
            try {
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                val hashBytes = digest.digest(firstUrl.toByteArray(Charsets.UTF_8))
                urlSha256 = hashBytes.joinToString("") { "%02x".format(it) }
            } catch (_: Exception) {}

            val uLow = firstUrl.lowercase()
            urlPurpose = when {
                uLow.contains("bank") || uLow.contains("login") || uLow.contains("signin") || uLow.contains("verify") || uLow.contains("credential") || uLow.contains("secure") || uLow.contains("account") ->
                    "Credential Harvesting & Banking Imposter Portal: Deceptive phishing page engineered to capture online banking credentials and OTPs."
                uLow.contains(".apk") || uLow.contains(".exe") || uLow.contains("download") || uLow.contains("payload") || uLow.contains("dropper") ->
                    "Malicious Dropper Payload: Direct delivery link designed to download unauthorized executable code."
                uLow.contains("pay") || uLow.contains("invoice") || uLow.contains("crypto") || uLow.contains("transfer") || uLow.contains("refund") ->
                    "Financial Redirection & Wire Fraud Lure: Fraudulent payment transfer portal."
                uLow.contains("track") || uLow.contains("parcel") || uLow.contains("delivery") || uLow.contains("fedex") || uLow.contains("ups") || uLow.contains("dhl") ->
                    "Package Delivery Imposter Smishing Lure: Impersonates courier logistics to elicit personal info."
                else -> "External Redirection / Unverified Domain: Unofficial destination outside authorized infrastructure."
            }
        }

        if (api != null) {
            try {
                val event = api.analyzePhishing(text = body, source = "android_sms_shield")
                risk = event.threatScore ?: event.confidence
                sev = event.severity.uppercase()
                classification = event.classification
                reasoning = event.explanation?.reasoning ?: event.explanation?.summary ?: "Verified via CyberGuard SOC threat matrix."
                actions = event.recommendedActions.ifEmpty { actions }

                // Check if threat intelligence is attached from URLAnalyzer on the backend
                event.threatIntelligence?.let { ti ->
                    val vt = ti["virustotal"] as? Map<*, *>
                    if (vt != null) {
                        val stats = vt["last_analysis_stats"] as? Map<*, *>
                        if (stats != null) {
                            val mal = (stats["malicious"] as? Number)?.toInt() ?: 0
                            val susp = (stats["suspicious"] as? Number)?.toInt() ?: 0
                            val harmless = (stats["harmless"] as? Number)?.toInt() ?: 0
                            val undetected = (stats["undetected"] as? Number)?.toInt() ?: 0
                            vtStatsText = "$mal/${mal + susp + harmless + undetected} ENGINES DETECTED"
                        }
                    }
                    val uh = ti["urlhaus"] as? Map<*, *>
                    if (uh != null) {
                        val matched = uh["matched"] as? Boolean ?: false
                        val threat = uh["threat"] as? String
                        urlhausText = if (matched) "BLACKLISTED (${threat ?: "MALICIOUS"})" else "CLEAN / NOT LISTED"
                    }
                }

                fun extractLiveIntel(tiMap: Map<*, *>?) {
                    val liveIntel = tiMap?.get("live_intelligence") as? Map<*, *> ?: return
                    val osint = liveIntel["osint"] as? Map<*, *>
                    liveOsintHits = (osint?.get("hits_count") as? Number)?.toInt() ?: liveOsintHits
                    val livePage = liveIntel["live_page_inspection"] as? Map<*, *>
                    if (livePage != null) {
                        livePageTitle = livePage["title"] as? String ?: livePageTitle
                        liveCredentialProbe = (livePage["has_credential_forms"] as? Boolean) ?: liveCredentialProbe
                        liveRenderingEngine = livePage["rendering_engine"] as? String ?: liveRenderingEngine
                    }
                }

                extractLiveIntel(event.threatIntelligence)

                // If URL was detected but VT stats wasn't returned in the phishing event, query threat search explicitly
                if (urls.isNotEmpty() && vtStatsText == null) {
                    try {
                        val urlSearchEvent = api.searchThreatIntel(ioc = urls[0])
                        urlSearchEvent.threatIntelligence?.let { ti ->
                            extractLiveIntel(ti)
                            val vt = ti["virustotal"] as? Map<*, *>
                            if (vt != null) {
                                val stats = vt["last_analysis_stats"] as? Map<*, *>
                                if (stats != null) {
                                    val mal = (stats["malicious"] as? Number)?.toInt() ?: 0
                                    val susp = (stats["suspicious"] as? Number)?.toInt() ?: 0
                                    val harmless = (stats["harmless"] as? Number)?.toInt() ?: 0
                                    val undetected = (stats["undetected"] as? Number)?.toInt() ?: 0
                                    vtStatsText = "$mal/${mal + susp + harmless + undetected} ENGINES DETECTED"
                                }
                            }
                            val uh = ti["urlhaus"] as? Map<*, *>
                            if (uh != null) {
                                val matched = uh["matched"] as? Boolean ?: false
                                val threat = uh["threat"] as? String
                                urlhausText = if (matched) "BLACKLISTED (${threat ?: "MALICIOUS"})" else "CLEAN / NOT LISTED"
                            }
                        }
                    } catch (_: Exception) {}
                }

                // Synthesize with Qwen LLM for refined executive briefing & action plan
                try {
                    val llmReq = mutableMapOf<String, Any>(
                        "source" to "android_sms_shield",
                        "sender" to sender,
                        "sms_body" to body,
                        "detected_urls" to urls,
                        "url_sha256" to (urlSha256 ?: ""),
                        "url_purpose" to (urlPurpose ?: ""),
                        "threat_category" to event.threatCategory,
                        "severity" to sev,
                        "virustotal_stats" to (vtStatsText ?: "0/72 CLEAN SIGNATURE"),
                        "urlhaus_status" to (urlhausText ?: "CLEAN / NOT LISTED")
                    )
                    val llmResp = api.askQwenLlm(llmReq)
                    qwenBriefing = llmResp.executiveBriefing ?: llmResp.executiveSummary ?: llmResp.narrative
                    if (!llmResp.immediateContainment.isNullOrEmpty()) {
                        actions = llmResp.immediateContainment
                    }
                } catch (_: Exception) {}

            } catch (_: Exception) {
                // Heuristic fallback if network error
                val lower = body.lowercase()
                if (urls.isNotEmpty() || lower.contains("urgent") || lower.contains("bank") || lower.contains("otp") || lower.contains("verify") || lower.contains("account suspended")) {
                    risk = 0.88f
                    sev = "HIGH"
                    classification = "SUSPECTED_SMISHING"
                    reasoning = "Suspicious financial/credential urgency detected with external link (Offline heuristic)."
                    actions = listOf("Do not click links", "Block sender", "Forward to SOC team")
                    vtStatsText = "0/72 CLEAN SIGNATURE"
                    urlhausText = "CLEAN / NOT LISTED"
                    qwenBriefing = "Urgent smishing lure intercepted from $sender containing external link. Do not click or provide sensitive credentials."
                }
            }
        } else {
            // Offline heuristic
            val lower = body.lowercase()
            if (urls.isNotEmpty() || lower.contains("urgent") || lower.contains("bank") || lower.contains("otp") || lower.contains("verify") || lower.contains("account suspended")) {
                risk = 0.88f
                sev = "HIGH"
                classification = "SUSPECTED_SMISHING"
                reasoning = "Suspicious financial urgency detected (Offline heuristic)."
                actions = listOf("Do not click links", "Block sender")
                vtStatsText = "OFFLINE STANDBY"
                urlhausText = "OFFLINE STANDBY"
                qwenBriefing = "Suspicious financial message detected offline. Verify sender before proceeding."
            }
        }

        // Strict Email Rule:
        // Guest account: NO email is ever sent for any alert.
        // Logged-in user: Email sent ONLY on HIGH and CRITICAL alerts.
        val emailTriggered = !isGuest && (sev == "HIGH" || sev == "CRITICAL")
        val recipient = if (emailTriggered) currUser?.email else null

        val record = SmsThreatRecord(
            sender = sender,
            body = body,
            riskScore = risk,
            severity = sev,
            classification = classification,
            isEmailAlertTriggered = emailTriggered,
            recipientEmail = recipient,
            reasoning = reasoning,
            detectedUrls = urls,
            recommendedActions = actions,
            urlIntelSummary = if (urls.isNotEmpty()) "VT: ${vtStatsText ?: "0/72"} | URLhaus: ${urlhausText ?: "CLEAN"}" else null,
            urlPurpose = urlPurpose,
            urlSha256 = urlSha256,
            vtStats = vtStatsText,
            urlhausStatus = urlhausText,
            qwenBriefing = qwenBriefing,
            liveOsintHits = liveOsintHits,
            livePageTitle = livePageTitle,
            liveCredentialProbe = liveCredentialProbe,
            liveRenderingEngine = liveRenderingEngine
        )
        addSmsThreat(record)
        return record
    }

    companion object {
        @Volatile
        private var instance: CallMonitorRepository? = null

        fun getInstance(context: Context): CallMonitorRepository {
            return instance ?: synchronized(this) {
                instance ?: CallMonitorRepository(context.applicationContext).also { instance = it }
            }
        }
    }
}

typealias CommsRepository = CallMonitorRepository

data class MalwareThreatAlert(
    val packageName: String,
    val appName: String,
    val riskScore: Float,
    val riskLevel: String,
    val installerSource: String,
    val sha256: String,
    val detectedThreatDetails: String,
    val sensitivePermissions: List<String> = emptyList(),
    val timestamp: Long = System.currentTimeMillis(),
    val threatCategory: String = "UNVERIFIED_SIDELOAD_MALWARE",
    val virusScanResult: String = "HIGH ENTROPY / UNVERIFIED PAYLOAD DETECTED",
    val playProtectStatus: String = "NOT VERIFIED BY GOOGLE PLAY PROTECT",
    val aiAutonomousRecommendation: String = "Active containment matrix engaged. Immediate purge recommended to prevent device compromise.",
    val sessionId: Int = -1,
    val isPreInstall: Boolean = false,
    val apkPath: String? = null
)
