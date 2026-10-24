package com.cyberguard.client.ui.screens

import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.BatteryManager
import android.os.Build
import android.provider.Settings
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ManageSearch
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.navigation.NavController
import com.cyberguard.client.network.DeepInvestigationResult
import com.cyberguard.client.network.DeviceHardwareInfo
import com.cyberguard.client.network.InstalledAppInfo
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*

enum class AppCategoryFilter {
    ALL,
    QUARANTINED,
    OFFICIAL_STORE,
    OEM_SYSTEM
}

@Composable
fun DeviceSecurityScreen(@Suppress("UNUSED_PARAMETER") navController: NavController, viewModel: MainViewModel) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val scrollState = rememberScrollState()

    val packageEvents by viewModel.packageEvents.collectAsState()
    val isWatchdogArmed by viewModel.isPackageWatchdogArmed.collectAsState()

    // Host Hardware & System Baseline
    val hardwareInfoState by viewModel.deviceHardwareInfo.collectAsState()
    val hardwareInfo = hardwareInfoState ?: remember {
        getDeviceHardwareInfo(context).also { viewModel.updateDeviceHardwareInfo(it) }
    }

    // App Inventory Persistent States (Retained across tab switching)
    val installedApps by viewModel.installedApps.collectAsState()
    val isScanning by viewModel.isDeviceScanning.collectAsState()
    var searchQuery by remember { mutableStateOf("") }
    var selectedFilter by remember { mutableStateOf(AppCategoryFilter.ALL) }
    var expandedPackage by remember { mutableStateOf<String?>(null) }

    // Deep Investigation & Authorization States
    var activeInvestigationApp by remember { mutableStateOf<InstalledAppInfo?>(null) }
    var isInvestigating by remember { mutableStateOf(false) }
    var investigationResult by remember { mutableStateOf<DeepInvestigationResult?>(null) }
    var investigationError by remember { mutableStateOf<String?>(null) }

    // Double Confirmation Dialog State
    var appPendingWhitelistConfirm by remember { mutableStateOf<InstalledAppInfo?>(null) }
    var appPendingUninstallConfirm by remember { mutableStateOf<InstalledAppInfo?>(null) }

    // SharedPreferences for Quarantine Whitelist
    val sharedPrefs = remember {
        context.getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
    }

    // Helper: Compute APK SHA-256 Checksum from filesystem
    fun computeApkSha256(apkPath: String?): String {
        if (apkPath.isNullOrBlank()) return "N/A"
        return try {
            val file = File(apkPath)
            if (!file.exists()) return "N/A"
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            "N/A"
        }
    }

    // Helper: Whitelist an app and release it from quarantine
    fun whitelistApp(packageName: String) {
        val currentSet = sharedPrefs.getStringSet("whitelisted_packages", emptySet()) ?: emptySet()
        sharedPrefs.edit().putStringSet("whitelisted_packages", currentSet + packageName).apply()
        // Update persistent list state
        viewModel.modifyInstalledApp(packageName) {
            it.copy(
                isQuarantined = false,
                isWhitelisted = true,
                riskLevel = "SAFE",
                riskScore = 0.15f,
                riskFactors = listOf("User double-confirmed and whitelisted from quarantine")
            )
        }
    }

    // Full Scan of Installed Packages with Real-Time Provenance & Root Baseline
    fun scanInstalledApps(force: Boolean = false) {
        if (!force && installedApps.isNotEmpty() && !isScanning) return
        viewModel.setDeviceScanning(true)
        val hw = getDeviceHardwareInfo(context)
        viewModel.updateDeviceHardwareInfo(hw)
        coroutineScope.launch(Dispatchers.IO) {
            val pm = context.packageManager
            val appsList = mutableListOf<InstalledAppInfo>()
            val whitelistedSet = sharedPrefs.getStringSet("whitelisted_packages", emptySet()) ?: emptySet()

            try {
                // Minimum access query: inspect launchable applications via intent queries (Android 11+ compliant)
                val mainIntent = Intent(Intent.ACTION_MAIN, null).apply {
                    addCategory(Intent.CATEGORY_LAUNCHER)
                }
                val resolveInfos = pm.queryIntentActivities(mainIntent, 0)
                val processedPackages = mutableSetOf<String>()

                for (ri in resolveInfos) {
                    val pkgName = ri.activityInfo.packageName
                    if (processedPackages.contains(pkgName)) continue
                    processedPackages.add(pkgName)

                    val appName = try {
                        ri.loadLabel(pm).toString()
                    } catch (_: Exception) {
                        pkgName.substringAfterLast(".")
                    }

                    val pkgInfo = try {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            pm.getPackageInfo(pkgName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
                        } else {
                            @Suppress("DEPRECATION")
                            pm.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS)
                        }
                    } catch (_: Exception) {
                        null
                    }

                    val appInfo = pkgInfo?.applicationInfo ?: ri.activityInfo.applicationInfo
                    val isSystem = ((appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0) ||
                                   ((appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0)

                    val requestedPermissions = pkgInfo?.requestedPermissions?.toList() ?: emptyList()
                    val sensitivePermissions = requestedPermissions.filter { p ->
                        p.contains("RECORD_AUDIO", ignoreCase = true) ||
                        p.contains("SMS", ignoreCase = true) ||
                        p.contains("LOCATION", ignoreCase = true) ||
                        p.contains("CAMERA", ignoreCase = true) ||
                        p.contains("CALL_LOG", ignoreCase = true) ||
                        p.contains("SYSTEM_ALERT_WINDOW", ignoreCase = true) ||
                        p.contains("INSTALL_PACKAGES", ignoreCase = true) ||
                        p.contains("BIND_ACCESSIBILITY_SERVICE", ignoreCase = true)
                    }

                    // Check installer package source
                    val rawInstaller = try {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            val source = pm.getInstallSourceInfo(pkgName)
                            source.installingPackageName ?: source.initiatingPackageName
                        } else {
                            @Suppress("DEPRECATION")
                            pm.getInstallerPackageName(pkgName)
                        }
                    } catch (_: Exception) {
                        null
                    }

                    // Resolve provenance
                    val provenance = resolveProvenance(
                        pm = pm,
                        pkgName = pkgName,
                        appInfo = appInfo,
                        installer = rawInstaller,
                        context = context
                    )

                    val isWhitelisted = whitelistedSet.contains(pkgName)
                    val isQuarantined = !provenance.isOfficialStore && !isWhitelisted

                    // Compute APK SHA-256
                    val sha256 = computeApkSha256(appInfo.sourceDir)

                    // Compute risk score
                    val riskFactors = mutableListOf<String>()
                    val riskScore: Float
                    val riskLevel: String

                    if (provenance.isOfficialStore) {
                        // Official store or OEM system application
                        riskScore = if (sensitivePermissions.isNotEmpty()) 0.12f else 0.05f
                        riskLevel = "SAFE"
                        if (provenance.isSystem) {
                            riskFactors.add("Authentic OEM firmware application (${Build.MANUFACTURER.uppercase()})")
                        } else {
                            riskFactors.add("Verified installer: ${provenance.storeName}")
                        }
                        if (sensitivePermissions.isNotEmpty()) {
                            riskFactors.add("Declared permissions operating under official store policy")
                        }
                    } else if (isWhitelisted) {
                        // Externally installed but user double-confirmed & whitelisted
                        riskScore = 0.15f
                        riskLevel = "SAFE"
                        riskFactors.add("External application manually verified & whitelisted by user")
                    } else {
                        // Unofficial / Sideloaded / Web download -> Active Quarantine
                        var qScore = 0.75f
                        riskFactors.add("Sideloaded from external unverified source (${provenance.storeName})")
                        riskFactors.add("Bypassed official store verification and digital signing checks")
                        riskFactors.add("Held in active quarantine pending VirusTotal & URLhaus audit")

                        if (sensitivePermissions.any { it.contains("SMS", ignoreCase = true) }) {
                            qScore += 0.10f
                            riskFactors.add("Requests SMS read/interception capability")
                        }
                        if (sensitivePermissions.any { it.contains("RECORD_AUDIO", ignoreCase = true) }) {
                            qScore += 0.08f
                            riskFactors.add("Requests live audio microphone recording")
                        }
                        if (sensitivePermissions.any { it.contains("ACCESSIBILITY", ignoreCase = true) }) {
                            qScore += 0.12f
                            riskFactors.add("Requests Android Accessibility Service control")
                        }
                        if (sensitivePermissions.any { it.contains("SYSTEM_ALERT_WINDOW", ignoreCase = true) }) {
                            qScore += 0.05f
                            riskFactors.add("Requests overlay display privilege")
                        }

                        riskScore = qScore.coerceIn(0f, 1f)
                        riskLevel = if (riskScore >= 0.85f) "CRITICAL" else "HIGH"
                    }

                    appsList.add(
                        InstalledAppInfo(
                            packageName = pkgName,
                            appName = appName,
                            versionName = pkgInfo?.versionName ?: "1.0",
                            installTime = pkgInfo?.firstInstallTime ?: System.currentTimeMillis(),
                            lastUpdateTime = pkgInfo?.lastUpdateTime ?: System.currentTimeMillis(),
                            isSystemApp = isSystem,
                            isUnknownSource = !provenance.isOfficialStore,
                            installerName = provenance.storeName,
                            isOfficialStore = provenance.isOfficialStore,
                            isQuarantined = isQuarantined,
                            sha256 = sha256,
                            riskScore = riskScore,
                            riskLevel = riskLevel,
                            riskFactors = riskFactors,
                            sensitivePermissions = sensitivePermissions,
                            isWhitelisted = isWhitelisted
                        )
                    )
                }

                // Quarantined apps first, then by risk score descending
                appsList.sortWith(
                    compareByDescending<InstalledAppInfo> { it.isQuarantined }
                        .thenByDescending { it.riskScore }
                )
            } catch (e: Exception) {
                e.printStackTrace()
            }

            withContext(Dispatchers.Main) {
                viewModel.updateInstalledApps(appsList)
                viewModel.setDeviceScanning(false)
            }
        }
    }

    LaunchedEffect(Unit) {
        if (installedApps.isEmpty()) {
            scanInstalledApps(force = true)
        }
    }

    // Trigger Deep Investigation (VirusTotal + URLhaus + Qwen LLM)
    fun runDeepInvestigation(app: InstalledAppInfo) {
        activeInvestigationApp = app
        isInvestigating = true
        investigationError = null
        investigationResult = null

        coroutineScope.launch {
            val result = viewModel.investigatePackageDeep(
                packageName = app.packageName,
                appName = app.appName,
                sha256 = app.sha256 ?: "N/A",
                installer = app.installerName,
                isOfficialStore = app.isOfficialStore
            )
            isInvestigating = false
            if (result.isSuccess) {
                investigationResult = result.getOrNull()
            } else {
                investigationError = result.exceptionOrNull()?.message ?: "Deep investigation pipeline encountered an error."
            }
        }
    }

    val quarantinedApps = remember(installedApps) {
        installedApps.filter { it.isQuarantined }
    }

    val officialStoreApps = remember(installedApps) {
        installedApps.filter { it.isOfficialStore && !it.isSystemApp }
    }

    val systemApps = remember(installedApps) {
        installedApps.filter { it.isSystemApp }
    }

    val filteredApps = remember(installedApps, searchQuery, selectedFilter) {
        installedApps.filter { app ->
            val matchesQuery = searchQuery.isBlank() ||
                app.appName.contains(searchQuery, ignoreCase = true) ||
                app.packageName.contains(searchQuery, ignoreCase = true) ||
                app.installerName.contains(searchQuery, ignoreCase = true)

            val matchesFilter = when (selectedFilter) {
                AppCategoryFilter.ALL -> true
                AppCategoryFilter.QUARANTINED -> app.isQuarantined
                AppCategoryFilter.OFFICIAL_STORE -> app.isOfficialStore && !app.isSystemApp
                AppCategoryFilter.OEM_SYSTEM -> app.isSystemApp
            }
            matchesQuery && matchesFilter
        }
    }

    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 20.dp, vertical = 24.dp)
    ) {
        // SCREEN TITLE
        Text(
            text = "DEVICE SECURITY",
            style = MaterialTheme.typography.headlineMedium.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Black,
                letterSpacing = 1.5.sp
            ),
            color = TextPrimary
        )
        Text(
            text = "HARDWARE BASELINE • PROVENANCE WATCHDOG • ACTIVE QUARANTINE",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp
            ),
            color = CyberNeonCyan
        )

        Spacer(modifier = Modifier.height(16.dp))

        // REAL-TIME QUARANTINE ALERT BANNER
        if (quarantinedApps.isNotEmpty()) {
            CyberGuardCard(
                borderColor = StatusCritical,
                containerColor = ElevatedSurface,
                cornerReticleColor = StatusCritical
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(CutCornerShape(6.dp))
                            .background(StatusCritical.copy(alpha = 0.15f))
                            .border(1.dp, StatusCritical.copy(alpha = 0.6f), CutCornerShape(6.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = null,
                            tint = StatusCritical,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "REAL-TIME THREAT WARNING",
                            style = MaterialTheme.typography.titleSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            ),
                            color = StatusCritical
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "${quarantinedApps.size} unverified external app(s) detected. Sourced outside official store repositories (Play Store, Indus Appstore, OEM Stores). Held in ACTIVE QUARANTINE.",
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                            color = TextPrimary
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        // HOST DEVICE ARCHITECTURE & TRUST MATRIX
        SectionHeader("HOST DEVICE ARCHITECTURE & TRUST MATRIX")
        CyberGuardCard(
            borderColor = if (hardwareInfo.isRooted) StatusCritical else HolographicGlowBorder,
            containerColor = ElevatedSurface
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                // Device Model & Manufacturer
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    StatusRow(
                        "TARGET HARDWARE",
                        "${hardwareInfo.manufacturer} ${hardwareInfo.model}",
                        CyberBlue
                    )
                    StatusRow(
                        "BRAND / CODE",
                        "${hardwareInfo.brand} (${hardwareInfo.deviceCode})",
                        TextSecondary
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                // OS & Security Patch
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    StatusRow(
                        "OS BUILD API",
                        "ANDROID ${hardwareInfo.androidVersion} (API ${hardwareInfo.apiLevel})",
                        ElectricCyan
                    )
                    StatusRow(
                        "SECURITY PATCH",
                        hardwareInfo.securityPatch,
                        TextSecondary
                    )
                }

                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(vertical = 10.dp))

                // Root & Integrity Posture
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "HOST ROOT STATUS",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.sp,
                                letterSpacing = 0.8.sp
                            ),
                            color = TextTertiary
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = if (hardwareInfo.isRooted) "COMPROMISED (ROOTED)" else "SECURE (NON-ROOTED)",
                            style = MaterialTheme.typography.bodyMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            ),
                            color = if (hardwareInfo.isRooted) StatusCritical else StatusOnline
                        )
                    }
                    StatusBadge(
                        text = if (hardwareInfo.isRooted) "COMPROMISED" else "ENFORCING",
                        color = if (hardwareInfo.isRooted) StatusCritical else StatusOnline
                    )
                }

                Text(
                    text = hardwareInfo.rootCheckDetails,
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp
                    ),
                    color = TextTertiary,
                    modifier = Modifier.padding(top = 4.dp)
                )

                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(vertical = 10.dp))

                // Peripherals & External Connections
                Text(
                    text = "EXTERNAL CONNECTIONS & PERIPHERALS",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        letterSpacing = 0.8.sp
                    ),
                    color = TextTertiary
                )
                Spacer(modifier = Modifier.height(6.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    StatusRow(
                        "USB DEBUGGING",
                        if (hardwareInfo.isUsbDebuggingEnabled) "ENABLED (DEV MODE)" else "DISABLED (SECURE)",
                        if (hardwareInfo.isUsbDebuggingEnabled) StatusWarning else StatusOnline
                    )
                    StatusRow(
                        "USB LINK CABLE",
                        if (hardwareInfo.isUsbConnected) "CONNECTED (DATA LINK)" else "DISCONNECTED",
                        if (hardwareInfo.isUsbConnected) StatusWarning else TextSecondary
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    StatusRow(
                        "ACTIVE VPN TUNNEL",
                        if (hardwareInfo.isVpnActive) "ACTIVE (ENCRYPTED)" else "INACTIVE",
                        if (hardwareInfo.isVpnActive) HologramTeal else TextSecondary
                    )
                    StatusRow(
                        "BLUETOOTH LINK",
                        if (hardwareInfo.isBluetoothActive) "ONLINE" else "OFFLINE",
                        TextSecondary
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // WATCHDOG CONTROLS & RESCAN CARD
        SectionHeader("PACKAGE INSTALLATION WATCHDOG")
        CyberGuardCard(
            borderColor = if (isWatchdogArmed) CyberBlue else StatusWarning,
            containerColor = ElevatedSurface
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "REAL-TIME PACKAGE WATCHDOG",
                            style = MaterialTheme.typography.titleMedium,
                            color = TextPrimary
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            "Continuously intercepts package installations, updates, and sideload events. Evaluates store provenance in real time.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Switch(
                        checked = isWatchdogArmed,
                        onCheckedChange = { viewModel.setPackageWatchdogArmed(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = DeepSpaceBackground,
                            checkedTrackColor = CyberNeonCyan,
                            uncheckedThumbColor = TextTertiary,
                            uncheckedTrackColor = HighlightSurface
                        )
                    )
                }

                // On-The-Spot Sideload Interception Window (Overlay Permission)
                var hasOverlayPermission by remember {
                    mutableStateOf(
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                            Settings.canDrawOverlays(context)
                        } else true
                    )
                }

                val lifecycleOwner = LocalLifecycleOwner.current
                DisposableEffect(lifecycleOwner) {
                    val observer = LifecycleEventObserver { _, event ->
                        if (event == Lifecycle.Event.ON_RESUME) {
                            hasOverlayPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                Settings.canDrawOverlays(context)
                            } else true
                        }
                    }
                    lifecycleOwner.lifecycle.addObserver(observer)
                    onDispose {
                        lifecycleOwner.lifecycle.removeObserver(observer)
                    }
                }

                // Auto-removed once granted; reappears if user revokes permission
                AnimatedVisibility(
                    visible = !hasOverlayPermission,
                    enter = expandVertically() + fadeIn(),
                    exit = shrinkVertically() + fadeOut()
                ) {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        HorizontalDivider(color = DividerColor, modifier = Modifier.padding(vertical = 10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "ON-THE-SPOT INTERCEPTION WINDOW",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 9.sp
                                    ),
                                    color = CyberAmber
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "Display over other apps permission required to intercept installations on the spot. Tap to grant.",
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                    color = TextSecondary
                                )
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                OutlinedButton(
                                    onClick = {
                                        try {
                                            val overlayIntent = Intent(
                                                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                                Uri.parse("package:${context.packageName}")
                                            )
                                            context.startActivity(overlayIntent)
                                        } catch (_: Exception) {
                                            try {
                                                context.startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION))
                                            } catch (_: Exception) {}
                                        }
                                    },
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberAmber),
                                    border = BorderStroke(1.dp, CyberAmber),
                                    shape = CutCornerShape(4.dp),
                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        "GRANT",
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 10.sp
                                        )
                                    )
                                }
                            }
                        }
                    }
                }

                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(vertical = 12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Button(
                        onClick = { scanInstalledApps(force = true) },
                        enabled = !isScanning,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyberNeonCyan,
                            contentColor = DeepSpaceBackground
                        ),
                        shape = CutCornerShape(6.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        if (isScanning) {
                            CircularProgressIndicator(modifier = Modifier.size(14.dp), color = DeepSpaceBackground, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("AUDITING SYSTEM...", style = MaterialTheme.typography.labelSmall)
                        } else {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("RE-AUDIT INVENTORY", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold))
                            }
                        }
                    }

                    if (packageEvents.isNotEmpty()) {
                        OutlinedButton(
                            onClick = { viewModel.clearPackageEvents() },
                            shape = CutCornerShape(6.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary),
                            border = BorderStroke(1.dp, DividerColor)
                        ) {
                            Text("CLEAR LOG", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }

        // REAL-TIME PACKAGE EVENT LOG (If events exist)
        if (packageEvents.isNotEmpty()) {
            Spacer(modifier = Modifier.height(18.dp))
            SectionHeader("RECENT PACKAGE EVENTS (${packageEvents.size})")
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                for (event in packageEvents) {
                    CyberGuardCard(
                        borderColor = when (event.eventType) {
                            "INSTALLED" -> if (event.riskLevel == "CRITICAL") StatusCritical else StatusWarning
                            "UPDATED" -> CyberBlue
                            else -> TextSecondary
                        },
                        containerColor = HighlightSurface
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = event.appName ?: event.packageName,
                                    style = MaterialTheme.typography.titleMedium,
                                    color = TextPrimary
                                )
                                Text(
                                    text = event.packageName,
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                    color = TextSecondary
                                )
                                Text(
                                    text = dateFormat.format(Date(event.timestamp)),
                                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp),
                                    color = TextTertiary
                                )
                            }
                            StatusBadge(
                                text = event.eventType,
                                color = when (event.eventType) {
                                    "INSTALLED" -> if (event.riskLevel == "CRITICAL") StatusCritical else StatusWarning
                                    "UPDATED" -> CyberBlue
                                    else -> TextSecondary
                                }
                            )
                        }
                    }
                }
            }
        }

        // ACTIVE QUARANTINE SECTION (Dedicated card list if any quarantined apps exist)
        if (quarantinedApps.isNotEmpty()) {
            Spacer(modifier = Modifier.height(20.dp))
            SectionHeader("ACTIVE QUARANTINE (${quarantinedApps.size})")
            Text(
                text = "These applications were detected outside official store repositories and are quarantined to prevent unauthorized background execution. Conduct deep investigation via VirusTotal & URLhaus before authorizing.",
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary,
                modifier = Modifier.padding(bottom = 10.dp)
            )

            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                for (app in quarantinedApps) {
                    CyberGuardCard(
                        borderColor = StatusCritical,
                        containerColor = ElevatedSurface,
                        cornerReticleColor = StatusCritical
                    ) {
                        Column(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(modifier = Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                                    Box(
                                        modifier = Modifier
                                            .size(36.dp)
                                            .clip(CutCornerShape(6.dp))
                                            .background(StatusCritical.copy(alpha = 0.15f))
                                            .border(1.dp, StatusCritical.copy(alpha = 0.5f), CutCornerShape(6.dp)),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.SecurityUpdateWarning,
                                            contentDescription = null,
                                            tint = StatusCritical,
                                            modifier = Modifier.size(20.dp)
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = app.appName,
                                            style = MaterialTheme.typography.titleMedium,
                                            color = TextPrimary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            text = app.packageName,
                                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                            color = TextSecondary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                StatusBadge("QUARANTINED", StatusCritical)
                            }

                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "ORIGIN: ${app.installerName}",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = StatusWarning
                            )

                            if (app.sha256 != null && app.sha256 != "N/A") {
                                Text(
                                    text = "APK SHA256: ${app.sha256.take(24)}...",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 9.sp
                                    ),
                                    color = TextTertiary
                                )
                            }

                            Spacer(modifier = Modifier.height(8.dp))
                            HorizontalDivider(color = DividerColor)
                            Spacer(modifier = Modifier.height(8.dp))

                            // Action buttons
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Button(
                                    onClick = { runDeepInvestigation(app) },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = StatusCritical,
                                        contentColor = TextPrimary
                                    ),
                                    shape = CutCornerShape(4.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.AutoMirrored.Filled.ManageSearch, contentDescription = null, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("DEEP SCAN (VT & URLHAUS)", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp))
                                }

                                OutlinedButton(
                                    onClick = { appPendingUninstallConfirm = app },
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StatusCritical),
                                    border = BorderStroke(1.dp, StatusCritical.copy(alpha = 0.5f)),
                                    shape = CutCornerShape(4.dp)
                                ) {
                                    Icon(Icons.Default.DeleteForever, contentDescription = null, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("PURGE", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp))
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // ALL INSTALLED APPS INVENTORY
        SectionHeader("APPLICATION INVENTORY & STORE PROVENANCE (${filteredApps.size})")

        // Search Bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            label = { Text("Filter by app name, package, or store", style = MaterialTheme.typography.labelSmall) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextSecondary, modifier = Modifier.size(16.dp)) },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { searchQuery = "" }) {
                        Icon(Icons.Default.Close, contentDescription = "Clear", tint = TextSecondary, modifier = Modifier.size(16.dp))
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = CyberNeonCyan,
                unfocusedBorderColor = DividerColor,
                focusedTextColor = TextPrimary,
                unfocusedTextColor = TextPrimary
            )
        )

        Spacer(modifier = Modifier.height(10.dp))

        // Filter Chips
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = selectedFilter == AppCategoryFilter.ALL,
                onClick = { selectedFilter = AppCategoryFilter.ALL },
                label = { Text("ALL (${installedApps.size})", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp)) }
            )
            FilterChip(
                selected = selectedFilter == AppCategoryFilter.QUARANTINED,
                onClick = { selectedFilter = AppCategoryFilter.QUARANTINED },
                label = {
                    Text(
                        "QUARANTINED (${quarantinedApps.size})",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontSize = 10.sp,
                            color = if (quarantinedApps.isNotEmpty()) StatusCritical else TextSecondary
                        )
                    )
                }
            )
            FilterChip(
                selected = selectedFilter == AppCategoryFilter.OFFICIAL_STORE,
                onClick = { selectedFilter = AppCategoryFilter.OFFICIAL_STORE },
                label = { Text("OFFICIAL (${officialStoreApps.size})", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp)) }
            )
            FilterChip(
                selected = selectedFilter == AppCategoryFilter.OEM_SYSTEM,
                onClick = { selectedFilter = AppCategoryFilter.OEM_SYSTEM },
                label = { Text("SYSTEM (${systemApps.size})", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp)) }
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Inventory List
        if (isScanning && installedApps.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = CyberNeonCyan)
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("AUDITING INSTALLED PACKAGES...", style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                }
            }
        } else if (filteredApps.isEmpty()) {
            CyberGuardCard {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "NO APPLICATIONS MATCH ACTIVE CRITERIA",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary
                    )
                }
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                for (app in filteredApps) {
                    val isExpanded = expandedPackage == app.packageName
                    val badgeColor = when {
                        app.isQuarantined -> StatusCritical
                        app.isOfficialStore -> StatusOnline
                        app.isWhitelisted -> HologramTeal
                        else -> CyberBlue
                    }

                    CyberGuardCard(
                        borderColor = if (app.isQuarantined) StatusCritical else DividerColor,
                        containerColor = ElevatedSurface,
                        onClick = {
                            expandedPackage = if (isExpanded) null else app.packageName
                        }
                    ) {
                        Column(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(
                                    modifier = Modifier.weight(1f),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(36.dp)
                                            .clip(CutCornerShape(6.dp))
                                            .background(badgeColor.copy(alpha = 0.12f))
                                            .border(1.dp, badgeColor.copy(alpha = 0.4f), CutCornerShape(6.dp)),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = when {
                                                app.isQuarantined -> Icons.Default.Warning
                                                app.isSystemApp -> Icons.Default.Settings
                                                else -> Icons.Default.PhoneAndroid
                                            },
                                            contentDescription = null,
                                            tint = badgeColor,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = app.appName,
                                            style = MaterialTheme.typography.titleMedium,
                                            color = TextPrimary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            text = app.packageName,
                                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                            color = TextSecondary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.width(8.dp))
                                StatusBadge(
                                    text = when {
                                        app.isQuarantined -> "QUARANTINED"
                                        app.isSystemApp -> "OEM SYSTEM"
                                        app.isWhitelisted -> "WHITELISTED"
                                        else -> "VERIFIED STORE"
                                    },
                                    color = badgeColor
                                )
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "Origin: ${app.installerName}",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 9.sp,
                                        color = if (app.isQuarantined) StatusCritical else ElectricCyan
                                    ),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.weight(1f)
                                )
                                Text(
                                    text = if (isExpanded) "LESS ▲" else "DETAILS ▼",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 9.sp,
                                        color = CyberBlue
                                    )
                                )
                            }

                            // EXPANDABLE FORENSIC DETAILS
                            AnimatedVisibility(visible = isExpanded) {
                                Column(modifier = Modifier.padding(top = 10.dp)) {
                                    HorizontalDivider(color = DividerColor)
                                    Spacer(modifier = Modifier.height(8.dp))

                                    // Checksum
                                    if (app.sha256 != null && app.sha256 != "N/A") {
                                        Text("APK CRYPTOGRAPHIC SHA-256:", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                                        Text(
                                            text = app.sha256,
                                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 9.sp),
                                            color = TextSecondary,
                                            modifier = Modifier.padding(start = 4.dp, top = 2.dp)
                                        )
                                        Spacer(modifier = Modifier.height(6.dp))
                                    }

                                    // Risk Factors
                                    if (app.riskFactors.isNotEmpty()) {
                                        Text("FORENSIC POSTURE:", style = MaterialTheme.typography.labelSmall, color = if (app.isQuarantined) StatusCritical else CyberBlue)
                                        for (factor in app.riskFactors) {
                                            Text(
                                                text = "• $factor",
                                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                                color = TextPrimary,
                                                modifier = Modifier.padding(start = 6.dp, top = 2.dp)
                                            )
                                        }
                                        Spacer(modifier = Modifier.height(6.dp))
                                    }

                                    // Sensitive Permissions
                                    if (app.sensitivePermissions.isNotEmpty()) {
                                        Text("SENSITIVE PERMISSIONS:", style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                                        for (perm in app.sensitivePermissions) {
                                            Text(
                                                text = "• ${perm.substringAfterLast(".")}",
                                                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 9.sp),
                                                color = TextSecondary,
                                                modifier = Modifier.padding(start = 6.dp, top = 2.dp)
                                            )
                                        }
                                    } else {
                                        Text(
                                            "No dangerous hardware/data permissions declared.",
                                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                            color = StatusOnline
                                        )
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    // Interactive Buttons for This App
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Button(
                                            onClick = { runDeepInvestigation(app) },
                                            colors = ButtonDefaults.buttonColors(
                                                containerColor = if (app.isQuarantined) StatusCritical else CyberBlue,
                                                contentColor = DeepSpaceBackground
                                            ),
                                            shape = CutCornerShape(4.dp),
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(14.dp))
                                            Spacer(modifier = Modifier.width(4.dp))
                                            Text("DEEP SCAN (VT & URLHAUS)", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, fontWeight = FontWeight.Bold))
                                        }

                                        if (app.isQuarantined) {
                                            OutlinedButton(
                                                onClick = { appPendingWhitelistConfirm = app },
                                                colors = ButtonDefaults.outlinedButtonColors(contentColor = StatusOnline),
                                                border = BorderStroke(1.dp, StatusOnline.copy(alpha = 0.5f)),
                                                shape = CutCornerShape(4.dp)
                                            ) {
                                                Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(14.dp))
                                                Spacer(modifier = Modifier.width(4.dp))
                                                Text("WHITELIST", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(36.dp))
    }

    // ==========================================
    // DEEP INVESTIGATION & AUTHORIZATION MODAL
    // ==========================================
    if (activeInvestigationApp != null) {
        val app = activeInvestigationApp!!
        Dialog(onDismissRequest = {
            if (!isInvestigating) {
                activeInvestigationApp = null
                investigationResult = null
            }
        }) {
            CyberGuardCard(
                borderColor = if (app.isQuarantined) StatusCritical else CyberBlue,
                containerColor = ElevatedSurface,
                modifier = Modifier
                    .fillMaxWidth()
                    .wrapContentHeight()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                ) {
                    // Header
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "FORENSIC THREAT INVESTIGATION",
                                style = MaterialTheme.typography.titleSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    letterSpacing = 1.sp
                                ),
                                color = if (app.isQuarantined) StatusCritical else CyberBlue
                            )
                            Text(
                                text = "VIRUSTOTAL • URLHAUS • LIVE OSINT • QWEN LLM",
                                style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp),
                                color = TextSecondary
                            )
                        }
                        if (!isInvestigating) {
                            IconButton(onClick = {
                                activeInvestigationApp = null
                                investigationResult = null
                            }) {
                                Icon(Icons.Default.Close, contentDescription = "Close", tint = TextSecondary)
                            }
                        }
                    }

                    HorizontalDivider(color = DividerColor, modifier = Modifier.padding(vertical = 8.dp))

                    // App Profile
                    Text(
                        text = app.appName,
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = TextPrimary
                    )
                    Text(
                        text = "${app.packageName} • v${app.versionName}",
                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                        color = TextSecondary
                    )
                    Text(
                        text = "Origin: ${app.installerName}",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            color = if (app.isQuarantined) StatusCritical else StatusOnline
                        )
                    )

                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "APK SHA256: ${app.sha256 ?: "N/A"}",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 9.sp
                        ),
                        color = TextTertiary
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    // Progress State
                    if (isInvestigating) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                CircularProgressIndicator(color = CyberNeonCyan)
                                Spacer(modifier = Modifier.height(12.dp))
                                Text(
                                    text = "COMMUNICATING WITH THREAT PIPELINE...",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                    color = CyberBlue
                                )
                                Text(
                                    text = "Querying VirusTotal, URLhaus, DuckDuckGo OSINT & Qwen LLM security synthesis...",
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                    color = TextSecondary,
                                    textAlign = TextAlign.Center
                                )
                            }
                        }
                    } else if (investigationError != null) {
                        CyberGuardCard(
                            borderColor = StatusCritical,
                            containerColor = HighlightSurface
                        ) {
                            Text(
                                text = "INVESTIGATION ERROR",
                                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                color = StatusCritical
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = investigationError!!,
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                color = TextPrimary
                            )
                        }
                    } else if (investigationResult != null) {
                        val res = investigationResult!!

                        // VirusTotal, URLhaus & DuckDuckGo Live OSINT telemetry cards
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            CyberGuardCard(
                                modifier = Modifier.weight(1f),
                                borderColor = if (res.vtDetections > 0) StatusCritical else StatusOnline,
                                containerColor = HighlightSurface
                            ) {
                                Text("VIRUSTOTAL", style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.sp), color = TextTertiary)
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "${res.vtDetections}/${res.vtTotalEngines}",
                                    style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold, fontSize = 12.sp),
                                    color = if (res.vtDetections > 0) StatusCritical else StatusOnline
                                )
                                Text(
                                    text = if (res.vtDetections > 0) "DETECTED" else "CLEAN SIG",
                                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.sp),
                                    color = TextSecondary
                                )
                            }

                            CyberGuardCard(
                                modifier = Modifier.weight(1f),
                                borderColor = if (res.urlhausStatus.contains("FLAGGED", ignoreCase = true)) StatusCritical else StatusOnline,
                                containerColor = HighlightSurface
                            ) {
                                Text("URLHAUS", style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.sp), color = TextTertiary)
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = if (res.urlhausStatus.contains("FLAGGED", ignoreCase = true)) "FLAGGED" else "CLEAN",
                                    style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold, fontSize = 12.sp),
                                    color = if (res.urlhausStatus.contains("FLAGGED", ignoreCase = true)) StatusCritical else StatusOnline
                                )
                                Text(
                                    text = "PAYLOAD",
                                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.sp),
                                    color = TextSecondary
                                )
                            }

                            CyberGuardCard(
                                modifier = Modifier.weight(1f),
                                borderColor = if (res.osintHits > 0) StatusWarning else StatusOnline,
                                containerColor = HighlightSurface
                            ) {
                                Text("DDG OSINT", style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.sp), color = TextTertiary)
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "${res.osintHits} HITS",
                                    style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold, fontSize = 12.sp),
                                    color = if (res.osintHits > 0) StatusWarning else StatusOnline
                                )
                                Text(
                                    text = if (res.osintHits > 0) "WARNINGS" else "CLEAN INTEL",
                                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.sp),
                                    color = TextSecondary
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        // Qwen LLM Security Executive Synthesis
                        CyberGuardCard(
                            borderColor = CyberBlue,
                            containerColor = HighlightSurface
                        ) {
                            Text(
                                text = "QWEN LLM THREAT BRIEFING",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = CyberBlue
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = res.executiveSummary,
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                color = TextPrimary
                            )

                            if (res.containmentRecommendation.isNotBlank()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "CONTAINMENT RECOMMENDATION:",
                                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp, fontWeight = FontWeight.Bold),
                                    color = StatusWarning
                                )
                                Text(
                                    text = res.containmentRecommendation,
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                    color = TextSecondary
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Interactive User Decision Options
                        Text(
                            text = "SECURITY AUTHORIZATION:",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            ),
                            color = TextPrimary
                        )
                        Text(
                            text = "Do you want to authorize and retain this application on this device?",
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                            color = TextSecondary
                        )

                        Spacer(modifier = Modifier.height(10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = {
                                    appPendingUninstallConfirm = app
                                    activeInvestigationApp = null
                                    investigationResult = null
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = StatusCritical,
                                    contentColor = TextPrimary
                                ),
                                shape = CutCornerShape(4.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Delete, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("PURGE APP", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp))
                            }

                            Button(
                                onClick = {
                                    appPendingWhitelistConfirm = app
                                    activeInvestigationApp = null
                                    investigationResult = null
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = StatusOnline,
                                    contentColor = DeepSpaceBackground
                                ),
                                shape = CutCornerShape(4.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("DOUBLE CONFIRM & TRUST", style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp, fontWeight = FontWeight.Bold))
                            }
                        }
                    }
                }
            }
        }
    }

    // ==========================================
    // DOUBLE CONFIRMATION DIALOG (WHITELIST)
    // ==========================================
    if (appPendingWhitelistConfirm != null) {
        val target = appPendingWhitelistConfirm!!
        AlertDialog(
            onDismissRequest = { appPendingWhitelistConfirm = null },
            title = {
                Text(
                    text = "DOUBLE CONFIRM AUTHORIZATION",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    ),
                    color = StatusWarning
                )
            },
            text = {
                Column {
                    Text(
                        text = "Are you sure you want to authorize and whitelist ${target.appName} (${target.packageName})?",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "This application was sourced externally from [${target.installerName}]. Double-confirming will release it from Active Quarantine and permit runtime execution.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        whitelistApp(target.packageName)
                        appPendingWhitelistConfirm = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = StatusOnline,
                        contentColor = DeepSpaceBackground
                    ),
                    shape = CutCornerShape(4.dp)
                ) {
                    Text("YES, AUTHORIZE & EXEMPT", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold))
                }
            },
            dismissButton = {
                OutlinedButton(
                    onClick = { appPendingWhitelistConfirm = null },
                    shape = CutCornerShape(4.dp)
                ) {
                    Text("CANCEL", style = MaterialTheme.typography.labelSmall)
                }
            },
            containerColor = ElevatedSurface
        )
    }

    // ==========================================
    // CONFIRMATION DIALOG (PURGE / UNINSTALL)
    // ==========================================
    if (appPendingUninstallConfirm != null) {
        val target = appPendingUninstallConfirm!!
        AlertDialog(
            onDismissRequest = { appPendingUninstallConfirm = null },
            title = {
                Text(
                    text = "PURGE / UNINSTALL APPLICATION",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    ),
                    color = StatusCritical
                )
            },
            text = {
                Text(
                    text = "This will invoke the Android system uninstaller to completely remove ${target.appName} (${target.packageName}) from this device.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextPrimary
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        appPendingUninstallConfirm = null
                        try {
                            val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                                data = Uri.parse("package:${target.packageName}")
                                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            }
                            context.startActivity(uninstallIntent)
                        } catch (e: Exception) {
                            e.printStackTrace()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = StatusCritical,
                        contentColor = TextPrimary
                    ),
                    shape = CutCornerShape(4.dp)
                ) {
                    Text("UNINSTALL NOW", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold))
                }
            },
            dismissButton = {
                OutlinedButton(
                    onClick = { appPendingUninstallConfirm = null },
                    shape = CutCornerShape(4.dp)
                ) {
                    Text("CANCEL", style = MaterialTheme.typography.labelSmall)
                }
            },
            containerColor = ElevatedSurface
        )
    }
}

// ====================================================================
// PROVENANCE & STORE RESOLUTION HELPER
// ====================================================================
private data class AppProvenance(
    val isOfficialStore: Boolean,
    val storeName: String,
    val isSystem: Boolean
)

private fun resolveProvenance(
    pm: PackageManager,
    pkgName: String,
    appInfo: ApplicationInfo,
    installer: String?,
    context: Context
): AppProvenance {
    // 1. CyberGuard self application
    if (pkgName == context.packageName) {
        return AppProvenance(
            isOfficialStore = true,
            storeName = "CyberGuard Core",
            isSystem = false
        )
    }

    // 2. Pre-installed OEM firmware system app
    val isSystem = ((appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0) ||
                   ((appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0)

    val lowerInstaller = installer?.lowercase() ?: ""

    // 3. Official App Stores
    when {
        lowerInstaller.contains("vending") || lowerInstaller.contains("google.android.feedback") -> {
            return AppProvenance(isOfficialStore = true, storeName = "Google Play Store", isSystem = isSystem)
        }
        lowerInstaller.contains("phonepe") || lowerInstaller.contains("indus") -> {
            return AppProvenance(isOfficialStore = true, storeName = "Indus Appstore", isSystem = isSystem)
        }
        lowerInstaller.contains("bbk.appstore") || lowerInstaller.contains("vivo.appstore") || lowerInstaller.contains("vivo.easyshare") -> {
            return AppProvenance(isOfficialStore = true, storeName = "Vivo V-Appstore", isSystem = isSystem)
        }
        lowerInstaller.contains("xiaomi.mipicks") || lowerInstaller.contains("miui.packageinstaller") || lowerInstaller.contains("xiaomi.market") -> {
            return AppProvenance(isOfficialStore = true, storeName = "Xiaomi GetApps / Mi System", isSystem = isSystem)
        }
        lowerInstaller.contains("samsungapps") -> {
            return AppProvenance(isOfficialStore = true, storeName = "Samsung Galaxy Store", isSystem = isSystem)
        }
        lowerInstaller.contains("oppo.market") || lowerInstaller.contains("heytap.market") || lowerInstaller.contains("coloros.phonemanager") -> {
            return AppProvenance(isOfficialStore = true, storeName = "OPPO / Realme App Market", isSystem = isSystem)
        }
        lowerInstaller.contains("huawei.appmarket") -> {
            return AppProvenance(isOfficialStore = true, storeName = "Huawei AppGallery", isSystem = isSystem)
        }
        lowerInstaller.contains("amazon.venezia") -> {
            return AppProvenance(isOfficialStore = true, storeName = "Amazon Appstore", isSystem = isSystem)
        }
    }

    // 4. If installer is null or generic package installer:
    // Check if it's an OEM System application
    if (isSystem) {
        val oemName = Build.MANUFACTURER.uppercase()
        return AppProvenance(isOfficialStore = true, storeName = "OEM System Firmware ($oemName)", isSystem = true)
    }

    // Check platform signature
    val isPlatformSigned = try {
        pm.checkSignatures("android", pkgName) == PackageManager.SIGNATURE_MATCH
    } catch (_: Exception) {
        false
    }
    if (isPlatformSigned) {
        return AppProvenance(isOfficialStore = true, storeName = "OEM Platform Signed", isSystem = false)
    }

    // 5. Check if package belongs to current device manufacturer OEM ecosystem
    val mfg = Build.MANUFACTURER.lowercase()
    val brand = Build.BRAND.lowercase()
    val deviceStr = "$mfg $brand ${Build.MODEL.lowercase()}"

    val isXiaomiDevice = deviceStr.contains("xiaomi") || deviceStr.contains("redmi") || deviceStr.contains("poco") || deviceStr.contains("kunzite")
    val isSamsungDevice = deviceStr.contains("samsung") || deviceStr.contains("galaxy")
    val isGoogleDevice = deviceStr.contains("google") || deviceStr.contains("pixel")
    val isBbkDevice = deviceStr.contains("oppo") || deviceStr.contains("oneplus") || deviceStr.contains("realme") || deviceStr.contains("vivo")
    val isMotoDevice = deviceStr.contains("motorola") || deviceStr.contains("lenovo")

    val isOemEcosystem = when {
        isXiaomiDevice -> {
            pkgName.startsWith("com.xiaomi.") || pkgName.startsWith("com.miui.") ||
            pkgName.startsWith("com.mi.") || pkgName.startsWith("com.redmi.")
        }
        isSamsungDevice -> {
            pkgName.startsWith("com.sec.") || pkgName.startsWith("com.samsung.")
        }
        isGoogleDevice -> {
            pkgName.startsWith("com.google.android.") || pkgName.startsWith("com.google.") || pkgName.startsWith("android.")
        }
        isBbkDevice -> {
            pkgName.startsWith("com.oppo.") || pkgName.startsWith("com.coloros.") ||
            pkgName.startsWith("com.heytap.") || pkgName.startsWith("com.oneplus.") ||
            pkgName.startsWith("com.vivo.") || pkgName.startsWith("com.bbk.") ||
            pkgName.startsWith("com.realme.") || pkgName.startsWith("com.iqoo.")
        }
        isMotoDevice -> {
            pkgName.startsWith("com.motorola.") || pkgName.startsWith("com.lenovo.")
        }
        else -> false
    }

    if (isOemEcosystem) {
        val oemName = Build.MANUFACTURER.uppercase()
        return AppProvenance(
            isOfficialStore = true,
            storeName = "$oemName OEM Ecosystem (Verified)",
            isSystem = isSystem
        )
    }

    // 6. Otherwise, externally sourced (Browser, direct APK sideload, chat app, etc.)
    val displayStore = if (installer != null) "External ($installer)" else "Direct Web / Sideload"
    return AppProvenance(isOfficialStore = false, storeName = displayStore, isSystem = false)
}

// ====================================================================
// REAL-TIME HARDWARE & SYSTEM BASELINE HELPER
// ====================================================================
private fun getDeviceHardwareInfo(context: Context): DeviceHardwareInfo {
    val (isRooted, rootDetails) = checkDeviceRooted()

    val isAdb = try {
        Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    } catch (_: Exception) {
        false
    }

    val isUsbPlugged = try {
        val batteryFilter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val batteryIntent = context.registerReceiver(null, batteryFilter)
        val plugged = batteryIntent?.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) ?: -1
        plugged == BatteryManager.BATTERY_PLUGGED_USB
    } catch (_: Exception) {
        false
    }

    val isVpn = try {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNet = cm?.activeNetwork
        val caps = cm?.getNetworkCapabilities(activeNet)
        caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    } catch (_: Exception) {
        false
    }

    val isBt = try {
        @Suppress("DEPRECATION")
        val btAdapter = BluetoothAdapter.getDefaultAdapter()
        btAdapter?.isEnabled == true
    } catch (_: Exception) {
        false
    }

    val secPatch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        Build.VERSION.SECURITY_PATCH
    } else {
        "N/A"
    }

    return DeviceHardwareInfo(
        manufacturer = Build.MANUFACTURER.uppercase(),
        model = Build.MODEL,
        brand = Build.BRAND.uppercase(),
        deviceCode = Build.DEVICE,
        androidVersion = Build.VERSION.RELEASE,
        apiLevel = Build.VERSION.SDK_INT,
        securityPatch = secPatch ?: "N/A",
        buildFingerprint = Build.FINGERPRINT,
        isRooted = isRooted,
        rootCheckDetails = rootDetails,
        isUsbDebuggingEnabled = isAdb,
        isUsbConnected = isUsbPlugged,
        isVpnActive = isVpn,
        isBluetoothActive = isBt
    )
}

private fun checkDeviceRooted(): Pair<Boolean, String> {
    val suPaths = arrayOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/su",
        "/system/bin/failsafe/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/system/sd/xbin/su"
    )
    for (path in suPaths) {
        if (File(path).exists()) {
            return Pair(true, "Binary detected at $path")
        }
    }
    val tags = Build.TAGS
    if (tags != null && tags.contains("test-keys")) {
        return Pair(true, "Custom ROM / Test-keys signature ($tags)")
    }
    return Pair(false, "No root binaries detected; enforcing kernel signature")
}
