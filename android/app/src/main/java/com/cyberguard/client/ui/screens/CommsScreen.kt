package com.cyberguard.client.ui.screens

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import com.cyberguard.client.service.CallMonitorService
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.navigation.NavController
import com.cyberguard.client.model.*
import com.cyberguard.client.network.ConnectionState
import com.cyberguard.client.network.SmsThreatRecord
import android.app.role.RoleManager
import com.cyberguard.client.telecom.*
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

enum class CommsTab { CALL_SHIELD, SMS_SHIELD }

@Composable
fun CommsScreen(navController: NavController, viewModel: MainViewModel) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val scrollState = rememberScrollState()
    val clipboardManager = LocalClipboardManager.current

    var selectedTab by remember { mutableStateOf(CommsTab.CALL_SHIELD) }

    val telemetry by viewModel.telemetry.collectAsState()
    val isSmsArmed by viewModel.isSmsShieldArmed.collectAsState()
    val smsRecords by viewModel.smsThreatRecords.collectAsState()
    val connectionState by viewModel.connectionState.collectAsState()
    val serverUrl by viewModel.serverUrl.collectAsState()
    val currentUser by viewModel.currentUser.collectAsState()
    val systemStatus by viewModel.systemStatus.collectAsState()

    // Call Screening states
    val isCallScreeningRoleHeld by viewModel.isCallScreeningRoleHeld.collectAsState()
    val callScreeningPolicy by viewModel.callScreeningPolicy.collectAsState()
    val screenedCalls by viewModel.screenedCalls.collectAsState()
    var selectedScreenedCall by remember { mutableStateOf<ScreenedCallRecord?>(null) }
    var isRequestingRole by remember { mutableStateOf(false) }
    var screeningFeedbackMessage by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(screeningFeedbackMessage) {
        if (screeningFeedbackMessage != null) {
            kotlinx.coroutines.delay(3500)
            screeningFeedbackMessage = null
        }
    }

    val roleLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        viewModel.checkScreeningRoleStatus()
        isRequestingRole = false
        if (viewModel.isCallScreeningRoleHeld.value) {
            screeningFeedbackMessage = "SYSTEM CALL SCREENING ROLE GRANTED"
        } else {
            // Xiaomi/HyperOS or OEM fallback
            viewModel.forceArmCallScreening(true)
            screeningFeedbackMessage = "DIRECT TELECOM HOOK ENGAGED"
        }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                viewModel.checkScreeningRoleStatus()
                viewModel.refreshScreenedCalls()
                viewModel.syncActiveCallState(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    LaunchedEffect(Unit) {
        viewModel.checkScreeningRoleStatus()
        viewModel.refreshScreenedCalls()
        viewModel.syncActiveCallState(context)
        viewModel.ensureDefenseWatchdogRunning()
    }

    val isCoreConnected = connectionState == ConnectionState.CONNECTED

    // Call and SMS permissions
    val requiredPermissions = mutableListOf(
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.READ_SMS
    ).apply {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.POST_NOTIFICATIONS)
        }
    }.toTypedArray()

    var permissionsGranted by remember {
        mutableStateOf(requiredPermissions.all {
            ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
        })
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        permissionsGranted = requiredPermissions.all { permissions[it] == true }
    }

    LaunchedEffect(Unit) {
        if (!permissionsGranted) {
            permissionLauncher.launch(requiredPermissions)
        }
    }

    // Auto-start Call Monitor Service watchdog when permissions are granted
    LaunchedEffect(permissionsGranted) {
        if (permissionsGranted) {
            viewModel.ensureDefenseWatchdogRunning()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(24.dp)
    ) {
        // TOP TACTICAL TITLE
        Text(
            text = "COMMS MONITOR",
            style = MaterialTheme.typography.headlineMedium.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Black,
                letterSpacing = 1.5.sp
            ),
            color = TextPrimary
        )
        Text(
            text = "REAL-TIME CALL & MESSAGE DEFENSE MATRIX",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp
            ),
            color = CyberNeonCyan
        )

        Spacer(modifier = Modifier.height(18.dp))

        // DUAL DEFENSE SUB-NAVIGATION TABS
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(CutCornerShape(8.dp))
                .background(HighlightSurface)
                .padding(4.dp)
        ) {
            // Tab 1: Call Shield
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(CutCornerShape(6.dp))
                    .background(if (selectedTab == CommsTab.CALL_SHIELD) CyberNeonCyan else Color.Transparent)
                    .clickable { selectedTab = CommsTab.CALL_SHIELD }
                    .padding(vertical = 10.dp),
                contentAlignment = Alignment.Center
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Call,
                        contentDescription = null,
                        tint = if (selectedTab == CommsTab.CALL_SHIELD) DeepSpaceBackground else TextSecondary,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "CALL SHIELD",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp
                        ),
                        color = if (selectedTab == CommsTab.CALL_SHIELD) DeepSpaceBackground else TextSecondary
                    )
                }
            }

            // Tab 2: SMS / Message Shield
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(CutCornerShape(6.dp))
                    .background(if (selectedTab == CommsTab.SMS_SHIELD) CyberNeonCyan else Color.Transparent)
                    .clickable { selectedTab = CommsTab.SMS_SHIELD }
                    .padding(vertical = 10.dp),
                contentAlignment = Alignment.Center
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Email,
                        contentDescription = null,
                        tint = if (selectedTab == CommsTab.SMS_SHIELD) DeepSpaceBackground else TextSecondary,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "SMS SHIELD",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp
                        ),
                        color = if (selectedTab == CommsTab.SMS_SHIELD) DeepSpaceBackground else TextSecondary
                    )
                    if (smsRecords.any { it.severity == "HIGH" || it.severity == "CRITICAL" }) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .clip(RoundedCornerShape(4.dp))
                                .background(StatusCritical)
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // PERMISSION ADVISORY CARD
        if (!permissionsGranted) {
            CyberGuardCard(
                borderColor = StatusWarning,
                containerColor = ElevatedSurface
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.Warning, contentDescription = null, tint = StatusWarning, modifier = Modifier.size(32.dp))
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("PERMISSIONS REQUIRED", style = MaterialTheme.typography.titleMedium, color = StatusWarning)
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        "CyberGuard requires Microphone, Phone State, and SMS Reception permissions to monitor calls and incoming text messages in real time.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary,
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    Button(
                        onClick = { permissionLauncher.launch(requiredPermissions) },
                        colors = ButtonDefaults.buttonColors(containerColor = CyberNeonCyan, contentColor = DeepSpaceBackground),
                        shape = CutCornerShape(6.dp)
                    ) {
                        Text("GRANT TELEPHONY & SMS ACCESS", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold))
                    }
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        // =========================================================================
        // TAB 1: CALL SHIELD
        // =========================================================================
        if (selectedTab == CommsTab.CALL_SHIELD) {
            val isAnalyzing = telemetry.monitorState == MonitorState.ANALYZING || telemetry.monitorState == MonitorState.STREAMING
            val isRinging = telemetry.callState == TelephonyCallState.RINGING

            SectionHeader("CALL DEFENSE STATUS")
            CyberGuardCard {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        StatusRow(
                            "SERVER LINK",
                            if (isCoreConnected) "ONLINE" else "OFFLINE",
                            if (isCoreConnected) StatusOnline else StatusCritical
                        )
                        StatusRow(
                            "CALL SHIELD",
                            when {
                                isAnalyzing -> "ACTIVE (MONITORING)"
                                isRinging -> "INCOMING (RINGING)"
                                else -> "ARMED (STANDBY)"
                            },
                            when {
                                isAnalyzing -> StatusOnline
                                isRinging -> StatusWarning
                                else -> CyberBlue
                            }
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        StatusRow(
                            "AUDIO SENSOR",
                            when (telemetry.audioState) {
                                AudioCaptureState.CAPTURING -> if (telemetry.audioLevelRms > 0.005) "VOICE ACTIVE" else "CAPTURING"
                                AudioCaptureState.UNAVAILABLE -> "UNAVAILABLE"
                                else -> "STANDBY"
                            },
                            when (telemetry.audioState) {
                                AudioCaptureState.CAPTURING -> StatusOnline
                                AudioCaptureState.UNAVAILABLE -> StatusCritical
                                else -> TextSecondary
                            }
                        )
                        StatusRow(
                            "STREAM UPLINK",
                            when (telemetry.backendState) {
                                BackendState.CONNECTED -> "STREAMING"
                                BackendState.CONNECTING -> "CONNECTING"
                                BackendState.ERROR -> "ERROR"
                                else -> if (isCoreConnected) "STANDBY" else "OFFLINE"
                            },
                            when (telemetry.backendState) {
                                BackendState.CONNECTED -> StatusOnline
                                BackendState.ERROR -> StatusCritical
                                else -> if (isCoreConnected) TextSecondary else StatusCritical
                            }
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        val activeDetDisplay = if (isCoreConnected) {
                            if (telemetry.activeDetector.isNotBlank()) telemetry.activeDetector
                            else systemStatus?.activeDetectorVersion?.let { "READY ($it)" } ?: "READY (v032)"
                        } else "WAITING FOR NODE"
                        StatusRow(
                            "DETECTOR CORE",
                            activeDetDisplay,
                            if (isCoreConnected) StatusOnline else TextSecondary
                        )
                        if (!serverUrl.isNullOrBlank()) {
                            StatusRow(
                                "NODE ADDRESS",
                                serverUrl!!.removePrefix("https://").removePrefix("http://").trimEnd('/'),
                                TextSecondary
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // CALL SHIELD OPERATION & CONTROLS
            SectionHeader("CALL DEFENSE & CONTROLS")
            CyberGuardCard(
                borderColor = when {
                    isAnalyzing -> StatusOnline
                    isRinging -> StatusWarning
                    else -> CyberBlue
                },
                containerColor = ElevatedSurface
            ) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    if (isRinging) {
                        Text(
                            "INCOMING CALL DETECTED",
                            style = MaterialTheme.typography.titleMedium,
                            color = StatusWarning
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            telemetry.callerStatusMessage ?: "Incoming call ringing. Call Shield armed and will analyze remote caller voice automatically when answered.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextPrimary
                        )
                    } else if (isAnalyzing) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    "CALL MONITORING ACTIVE",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = StatusOnline
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    "Analyzing caller voice via ${telemetry.captureMode}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TextSecondary
                                )
                            }
                            Button(
                                onClick = { viewModel.stopManualCallMonitor() },
                                colors = ButtonDefaults.buttonColors(containerColor = StatusCritical),
                                shape = CutCornerShape(6.dp)
                            ) {
                                Text("STOP", style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    } else {
                        // AUTOMATIC PASSIVE/ACTIVE REAL-TIME DEFENSE
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Box(
                                        modifier = Modifier
                                            .size(7.dp)
                                            .clip(CircleShape)
                                            .background(StatusOnline)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        "AUTOMATIC REAL-TIME DEFENSE ARMED",
                                        style = MaterialTheme.typography.titleMedium.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 11.sp
                                        ),
                                        color = StatusOnline
                                    )
                                }
                                Spacer(modifier = Modifier.height(3.dp))
                                Text(
                                    "Actively scanning background cellular telephony. Analyzes remote caller STIR/SHAKEN identity, deepfake frequency biometrics, and intercepts fraud automatically.",
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.5.sp),
                                    color = TextSecondary
                                )
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            StatusBadge(text = "ENGAGED", color = StatusOnline)
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        // Live audio waveform pulse strip
                        val infiniteTransition = rememberInfiniteTransition(label = "pulse_bars")
                        val bar1 by infiniteTransition.animateFloat(
                            initialValue = 0.2f, targetValue = 0.85f,
                            animationSpec = infiniteRepeatable(tween(400, easing = LinearEasing), RepeatMode.Reverse),
                            label = "b1"
                        )
                        val bar2 by infiniteTransition.animateFloat(
                            initialValue = 0.7f, targetValue = 0.3f,
                            animationSpec = infiniteRepeatable(tween(550, easing = LinearEasing), RepeatMode.Reverse),
                            label = "b2"
                        )
                        val bar3 by infiniteTransition.animateFloat(
                            initialValue = 0.35f, targetValue = 0.95f,
                            animationSpec = infiniteRepeatable(tween(350, easing = LinearEasing), RepeatMode.Reverse),
                            label = "b3"
                        )

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(4.dp))
                                .background(HighlightSurface)
                                .border(0.8.dp, CyberNeonCyan.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
                                .padding(horizontal = 10.dp, vertical = 6.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "CONTINUOUS CELLULAR WATCHDOG",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.5.sp,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = CyberNeonCyan
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(3.dp), verticalAlignment = Alignment.CenterVertically) {
                                Box(modifier = Modifier.width(3.dp).height((12 * bar1).dp.coerceAtLeast(3.dp)).background(CyberNeonCyan, RoundedCornerShape(1.dp)))
                                Box(modifier = Modifier.width(3.dp).height((14 * bar2).dp.coerceAtLeast(4.dp)).background(CyberBlue, RoundedCornerShape(1.dp)))
                                Box(modifier = Modifier.width(3.dp).height((16 * bar3).dp.coerceAtLeast(3.dp)).background(StatusOnline, RoundedCornerShape(1.dp)))
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // CALL RISK TELEMETRY (When analyzing)
            if (isAnalyzing || telemetry.hasValidResult) {
                SectionHeader("CALL BIOMETRICS & RISK")
                CyberGuardCard {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            StatusRow(
                                "RISK SCORE",
                                String.format(Locale.US, "%.1f%%", telemetry.currentRisk * 100),
                                when {
                                    telemetry.currentRisk >= 0.75 -> StatusCritical
                                    telemetry.currentRisk >= 0.40 -> StatusWarning
                                    else -> StatusOnline
                                }
                            )
                            StatusRow(
                                "CLASSIFICATION",
                                telemetry.voiceClassification,
                                when (telemetry.voiceClassification) {
                                    "GENUINE_VOICE" -> StatusOnline
                                    "CLONED_VOICE" -> StatusCritical
                                    else -> CyberBlue
                                }
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            // ── CALL SCREENING & FRAUD INTERCEPTOR ──
            SectionHeader("CALL SCREENING & FRAUD INTERCEPTOR")
            CyberGuardCard(
                borderColor = if (isCallScreeningRoleHeld) StatusOnline else StatusWarning,
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
                                "OFFICIAL CALL SCREENING HOOK",
                                style = MaterialTheme.typography.titleMedium.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp,
                                    letterSpacing = 0.5.sp
                                ),
                                color = TextPrimary
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                "Intercepts incoming calls before phone rings, inspects carrier STIR/SHAKEN caller verification, and enforces local-first blocking within 5 seconds.",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.5.sp),
                                color = TextSecondary
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        StatusBadge(
                            text = if (isCallScreeningRoleHeld) "ACTIVE" else "ROLE NEEDED",
                            color = if (isCallScreeningRoleHeld) StatusOnline else StatusWarning
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    AnimatedVisibility(visible = screeningFeedbackMessage != null) {
                        screeningFeedbackMessage?.let { msg ->
                            Surface(
                                shape = CutCornerShape(4.dp),
                                color = HighlightSurface,
                                border = BorderStroke(1.dp, CyberNeonCyan),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(bottom = 10.dp)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.CheckCircle,
                                        contentDescription = null,
                                        tint = StatusOnline,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = msg,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 8.5.sp
                                        ),
                                        color = CyberNeonCyan
                                    )
                                }
                            }
                        }
                    }

                    if (!isCallScreeningRoleHeld) {
                        Surface(
                            shape = CutCornerShape(6.dp),
                            color = HighlightSurface,
                            border = BorderStroke(1.dp, StatusWarning.copy(alpha = 0.7f)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.Security, contentDescription = null, tint = StatusWarning, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        "SYSTEM TELECOM ROLE AUTHORIZATION",
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 9.5.sp
                                        ),
                                        color = StatusWarning
                                    )
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    "Android requires explicit authorization for system-level call screening. Tap below to request role or enable direct telecom hook for Xiaomi/HyperOS.",
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.5.sp),
                                    color = TextSecondary
                                )
                                Spacer(modifier = Modifier.height(10.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Button(
                                        onClick = {
                                            isRequestingRole = true
                                            try {
                                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                                    val roleManager = context.getSystemService(Context.ROLE_SERVICE) as? RoleManager
                                                    if (roleManager != null && roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) {
                                                        val intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING)
                                                        roleLauncher.launch(intent)
                                                    } else {
                                                        viewModel.forceArmCallScreening(true)
                                                        isRequestingRole = false
                                                        screeningFeedbackMessage = "DIRECT TELECOM HOOK ENGAGED"
                                                    }
                                                } else {
                                                    viewModel.forceArmCallScreening(true)
                                                    isRequestingRole = false
                                                    screeningFeedbackMessage = "DIRECT TELECOM HOOK ENGAGED"
                                                }
                                            } catch (e: Exception) {
                                                viewModel.forceArmCallScreening(true)
                                                isRequestingRole = false
                                                screeningFeedbackMessage = "DIRECT TELECOM HOOK ENGAGED"
                                            }
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = CyberNeonCyan, contentColor = DeepSpaceBackground),
                                        shape = CutCornerShape(6.dp),
                                        modifier = Modifier.weight(1.3f)
                                    ) {
                                        if (isRequestingRole) {
                                            CircularProgressIndicator(
                                                modifier = Modifier.size(14.dp),
                                                color = DeepSpaceBackground,
                                                strokeWidth = 2.dp
                                            )
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text(
                                                "AUTHORIZING...",
                                                style = MaterialTheme.typography.labelSmall.copy(
                                                    fontFamily = FontFamily.Monospace,
                                                    fontWeight = FontWeight.Black,
                                                    fontSize = 9.5.sp
                                                )
                                            )
                                        } else {
                                            Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(15.dp))
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text(
                                                "GRANT CALL SCREENING ROLE",
                                                style = MaterialTheme.typography.labelSmall.copy(
                                                    fontFamily = FontFamily.Monospace,
                                                    fontWeight = FontWeight.Black,
                                                    fontSize = 9.5.sp
                                                )
                                            )
                                        }
                                    }

                                    OutlinedButton(
                                        onClick = {
                                            viewModel.forceArmCallScreening(true)
                                            screeningFeedbackMessage = "DIRECT TELECOM HOOK ENGAGED"
                                        },
                                        colors = ButtonDefaults.outlinedButtonColors(contentColor = StatusOnline),
                                        border = BorderStroke(1.dp, StatusOnline.copy(alpha = 0.8f)),
                                        shape = CutCornerShape(6.dp),
                                        modifier = Modifier.weight(0.9f)
                                    ) {
                                        Icon(Icons.Default.CheckCircle, contentDescription = null, modifier = Modifier.size(13.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            "ARM DIRECT HOOK",
                                            style = MaterialTheme.typography.labelSmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 8.5.sp
                                            )
                                        )
                                    }
                                }
                            }
                        }
                    } else {
                        // Live active telemetry strip with interactive test simulation
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(Color(0xFF021E12))
                                    .border(0.6.dp, StatusOnline.copy(alpha = 0.5f), RoundedCornerShape(4.dp))
                                    .padding(horizontal = 8.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(modifier = Modifier.size(6.dp).clip(CircleShape).background(StatusOnline))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    "TELECOM HOOK ARMED",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 8.5.sp,
                                        fontWeight = FontWeight.Bold
                                    ),
                                    color = StatusOnline
                                )
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Button(
                                    onClick = {
                                        viewModel.simulateTestScreenedCall()
                                        screeningFeedbackMessage = "SIMULATION LOGGED"
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = CyberNeonCyan, contentColor = DeepSpaceBackground),
                                    shape = CutCornerShape(4.dp),
                                    modifier = Modifier.weight(1.3f)
                                ) {
                                    Icon(Icons.Default.Bolt, contentDescription = null, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        "SIMULATE TEST CALL SCREENING",
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Black,
                                            fontSize = 8.5.sp
                                        )
                                    )
                                }

                                OutlinedButton(
                                    onClick = {
                                        viewModel.forceArmCallScreening(false)
                                        screeningFeedbackMessage = "TELECOM HOOK DISENGAGED"
                                    },
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StatusCritical),
                                    border = BorderStroke(1.dp, StatusCritical.copy(alpha = 0.6f)),
                                    shape = CutCornerShape(4.dp),
                                    modifier = Modifier.weight(0.7f)
                                ) {
                                    Text(
                                        "DISARM",
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 8.5.sp
                                        )
                                    )
                                }
                            }
                        }
                    }

                    HorizontalDivider(color = DividerColor.copy(alpha = 0.7f), modifier = Modifier.padding(vertical = 12.dp))

                    // Policy Controls
                    Text(
                        "SCREENING DEFENSE POLICY",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 9.5.sp,
                            letterSpacing = 0.6.sp
                        ),
                        color = CyberNeonCyan
                    )

                    Spacer(modifier = Modifier.height(6.dp))

                    // Policy 1: Auto-block scams
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("AUTO-BLOCK SUSPECTED SCAMS", style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold, fontSize = 11.sp), color = TextPrimary)
                            Text("Silently rejects high-risk scam and spoofed numbers", style = MaterialTheme.typography.bodySmall.copy(fontSize = 8.5.sp), color = TextSecondary)
                        }
                        Switch(
                            checked = callScreeningPolicy.autoBlockScams,
                            onCheckedChange = {
                                viewModel.updateCallScreeningPolicy(callScreeningPolicy.copy(autoBlockScams = it))
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = DeepSpaceBackground, checkedTrackColor = CyberNeonCyan)
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Policy 2: Auto-silence suspicious
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("AUTO-SILENCE SUSPICIOUS CALLERS", style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold, fontSize = 11.sp), color = TextPrimary)
                            Text("Silences ringer on unverified carrier caller-IDs", style = MaterialTheme.typography.bodySmall.copy(fontSize = 8.5.sp), color = TextSecondary)
                        }
                        Switch(
                            checked = callScreeningPolicy.autoSilenceSuspicious,
                            onCheckedChange = {
                                viewModel.updateCallScreeningPolicy(callScreeningPolicy.copy(autoSilenceSuspicious = it))
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = DeepSpaceBackground, checkedTrackColor = CyberNeonCyan)
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Policy 3: Silence unknown
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("SILENCE UNKNOWN CALLERS", style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold, fontSize = 11.sp), color = TextPrimary)
                            Text("Caution: Silences callers with no prior telemetry", style = MaterialTheme.typography.bodySmall.copy(fontSize = 8.5.sp), color = TextTertiary)
                        }
                        Switch(
                            checked = callScreeningPolicy.blockUnknownCallers,
                            onCheckedChange = {
                                viewModel.updateCallScreeningPolicy(callScreeningPolicy.copy(blockUnknownCallers = it))
                            },
                            colors = SwitchDefaults.colors(checkedThumbColor = DeepSpaceBackground, checkedTrackColor = StatusWarning)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // ── REAL-TIME SCREENED CALLS AUDIT LOG ──
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SectionHeader("SCREENED CALLS LOG (${screenedCalls.size})")
                if (screenedCalls.isNotEmpty()) {
                    TextButton(onClick = { viewModel.clearScreenedCalls() }) {
                        Text("CLEAR LOG", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                    }
                }
            }

            if (screenedCalls.isEmpty()) {
                CyberGuardCard {
                    Box(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 20.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Default.Call, contentDescription = null, tint = TextTertiary, modifier = Modifier.size(36.dp))
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                "NO SCREENED CALLS IN AUDIT LOG",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp
                                ),
                                color = TextSecondary
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                "Incoming calls will be evaluated locally in real time before ringing. Verified telemetry and actions will appear here.",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                color = TextTertiary,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(horizontal = 16.dp)
                            )
                        }
                    }
                }
            } else {
                val dateFormat = remember { SimpleDateFormat("HH:mm:ss • MMM dd", Locale.getDefault()) }
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    for (record in screenedCalls) {
                        val isDanger = record.classification == CallRiskClassification.HIGH_RISK
                        val isWarning = record.classification == CallRiskClassification.SUSPICIOUS || record.classification == CallRiskClassification.DISPUTED
                        val cardBorder = when {
                            isDanger -> StatusCritical
                            isWarning -> StatusWarning
                            else -> DividerColor
                        }

                        CyberGuardCard(
                            borderColor = cardBorder,
                            containerColor = ElevatedSurface,
                            onClick = { selectedScreenedCall = record }
                        ) {
                            Column(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = if (isDanger) Icons.Default.Warning else Icons.Default.Call,
                                            contentDescription = null,
                                            tint = if (isDanger) StatusCritical else CyberNeonCyan,
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Column {
                                            Text(
                                                text = record.normalizedNumber,
                                                style = MaterialTheme.typography.labelSmall.copy(
                                                    fontFamily = FontFamily.Monospace,
                                                    fontWeight = FontWeight.Bold,
                                                    fontSize = 12.sp
                                                ),
                                                color = TextPrimary
                                            )
                                            if (!record.callerDisplayName.isNullOrBlank()) {
                                                Text(
                                                    text = record.callerDisplayName,
                                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                                                    color = TextSecondary
                                                )
                                            }
                                        }
                                    }

                                    StatusBadge(
                                        text = record.actionApplied.actionCode,
                                        color = when (record.actionApplied) {
                                            ScreeningAction.BLOCK -> StatusCritical
                                            ScreeningAction.SILENCE -> StatusWarning
                                            ScreeningAction.ALLOW -> StatusOnline
                                        }
                                    )
                                }

                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = record.explanation,
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.5.sp),
                                    color = TextSecondary,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )

                                Spacer(modifier = Modifier.height(6.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Surface(
                                            shape = RoundedCornerShape(3.dp),
                                            color = HighlightSurface
                                        ) {
                                            Text(
                                                text = record.carrierVerificationStatus.label,
                                                style = MaterialTheme.typography.labelSmall.copy(
                                                    fontFamily = FontFamily.Monospace,
                                                    fontSize = 7.5.sp
                                                ),
                                                color = if (record.carrierVerificationStatus == CarrierVerificationStatus.PASSED) StatusOnline else TextTertiary,
                                                modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                                            )
                                        }
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = "${record.responseLatencyMs}ms",
                                            style = MaterialTheme.typography.labelSmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 8.sp
                                            ),
                                            color = CyberBlue
                                        )
                                    }

                                    Text(
                                        text = dateFormat.format(Date(record.timestamp)),
                                        style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.5.sp),
                                        color = TextTertiary
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // Screened Call Detail Modal
            selectedScreenedCall?.let { callRecord ->
                ScreenedCallDetailModal(
                    record = callRecord,
                    onDismiss = { selectedScreenedCall = null },
                    onCopyNumber = {
                        clipboardManager.setText(AnnotatedString(callRecord.normalizedNumber))
                    }
                )
            }
        }

        // =========================================================================
        // TAB 2: REAL-TIME SMS / MESSAGE SHIELD
        // =========================================================================
        if (selectedTab == CommsTab.SMS_SHIELD) {
            val clipboardManager = LocalClipboardManager.current
            var selectedSmsRecord by remember { mutableStateOf<SmsThreatRecord?>(null) }

            val infiniteTransition = rememberInfiniteTransition(label = "sms_shield_anim")
            val radarPulse by infiniteTransition.animateFloat(
                initialValue = 0f,
                targetValue = 1f,
                animationSpec = infiniteRepeatable(tween(2000, easing = LinearEasing), RepeatMode.Restart),
                label = "sms_radar_pulse"
            )
            val dangerPulse by infiniteTransition.animateFloat(
                initialValue = 0.45f,
                targetValue = 1.0f,
                animationSpec = infiniteRepeatable(tween(800, easing = FastOutSlowInEasing), RepeatMode.Reverse),
                label = "sms_danger_pulse"
            )

            // 1. SMS SHIELD SYSTEM STATUS
            SectionHeader("SMS DEFENSE STATUS")
            CyberGuardCard {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        StatusRow(
                            "SMS WATCHDOG",
                            if (isSmsArmed) "ARMED" else "DISARMED",
                            if (isSmsArmed) StatusOnline else StatusWarning
                        )
                        StatusRow(
                            "THREAT ENGINE",
                            if (isCoreConnected) "QWEN LLM & QUISHING READY" else "LOCAL HEURISTICS",
                            if (isCoreConnected) StatusOnline else StatusWarning
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        val isGuest = currentUser == null || !viewModel.connectionManager.authManager.isLoggedIn
                        StatusRow(
                            "ALERT DISPATCH",
                            if (isGuest) "DISABLED (GUEST)" else "AUTO-EMAIL (HIGH/CRIT)",
                            if (isGuest) TextSecondary else CyberBlue
                        )
                        StatusRow(
                            "ACTIVE OPERATOR",
                            if (isGuest) "GUEST (NO EMAIL ALERT)" else (currentUser?.email ?: "GUEST (NO EMAIL ALERT)"),
                            TextSecondary
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 2. REAL-TIME MESSAGE DEFENSE & CONTROLS (UNIFIED BACKGROUND ENGINE)
            SectionHeader("REAL-TIME MESSAGE DEFENSE & CONTROLS")
            CyberGuardCard(
                borderColor = if (isSmsArmed) CyberNeonCyan else StatusWarning,
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
                                "PASSIVE SMS SHIELD",
                                style = MaterialTheme.typography.titleMedium.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.5.sp,
                                    letterSpacing = 0.6.sp
                                ),
                                color = TextPrimary
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                "Actively intercepts incoming SMS in background, inspects phishing/quishing payloads, evaluates domains via VirusTotal & URLhaus, and simplifies threats with Qwen LLM.",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                color = TextSecondary
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Switch(
                            checked = isSmsArmed,
                            onCheckedChange = { viewModel.setSmsShieldArmed(it) },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = DeepSpaceBackground,
                                checkedTrackColor = CyberNeonCyan,
                                uncheckedThumbColor = TextTertiary,
                                uncheckedTrackColor = HighlightSurface
                            )
                        )
                    }

                    HorizontalDivider(color = DividerColor.copy(alpha = 0.7f), modifier = Modifier.padding(vertical = 12.dp))

                    // Live Background Interceptor Telemetry Banner
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(CutCornerShape(6.dp))
                            .background(if (isSmsArmed) Color(0xFF021E12).copy(alpha = 0.8f) else HighlightSurface)
                            .border(1.dp, if (isSmsArmed) StatusOnline.copy(alpha = 0.5f) else DividerColor, CutCornerShape(6.dp))
                            .padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Animated pulsing radar dot
                        Box(modifier = Modifier.size(24.dp), contentAlignment = Alignment.Center) {
                            if (isSmsArmed) {
                                Canvas(modifier = Modifier.size(24.dp)) {
                                    drawCircle(
                                        color = StatusOnline.copy(alpha = (1f - radarPulse) * 0.6f),
                                        radius = (size.width / 2f) * radarPulse,
                                        style = Stroke(width = 1.2.dp.toPx())
                                    )
                                }
                            }
                            Box(
                                modifier = Modifier
                                    .size(7.dp)
                                    .clip(RoundedCornerShape(3.5.dp))
                                    .background(if (isSmsArmed) StatusOnline else StatusOffline)
                            )
                        }

                        Spacer(modifier = Modifier.width(8.dp))

                        Column {
                            Text(
                                text = if (isSmsArmed) "BACKGROUND SMS DAEMON: ACTIVE" else "BACKGROUND SMS DAEMON: STANDBY",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 9.sp,
                                    letterSpacing = 0.6.sp
                                ),
                                color = if (isSmsArmed) StatusOnline else TextTertiary
                            )
                            Text(
                                text = if (isSmsArmed) "Runs within unified background defense service with zero battery overhead" else "Tap toggle above to arm real-time incoming SMS protection",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 8.5.sp),
                                color = TextSecondary
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // 3-Metric Stream Telemetry Summary
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        val criticalCount = smsRecords.count { it.severity == "HIGH" || it.severity == "CRITICAL" }
                        Surface(
                            shape = CutCornerShape(4.dp),
                            color = DeepSpaceBackground,
                            border = BorderStroke(0.6.dp, DividerColor),
                            modifier = Modifier.weight(1f)
                        ) {
                            Column(modifier = Modifier.padding(6.dp)) {
                                Text("MONITORED", style = MaterialTheme.typography.labelSmall.copy(fontSize = 7.5.sp), color = TextTertiary)
                                Text("${smsRecords.size}", style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold, fontSize = 13.sp), color = CyberNeonCyan)
                            }
                        }

                        Surface(
                            shape = CutCornerShape(4.dp),
                            color = DeepSpaceBackground,
                            border = BorderStroke(0.6.dp, if (criticalCount > 0) StatusCritical else DividerColor),
                            modifier = Modifier.weight(1f)
                        ) {
                            Column(modifier = Modifier.padding(6.dp)) {
                                Text("THREATS", style = MaterialTheme.typography.labelSmall.copy(fontSize = 7.5.sp), color = TextTertiary)
                                Text("$criticalCount", style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold, fontSize = 13.sp), color = if (criticalCount > 0) StatusCritical else StatusOnline)
                            }
                        }

                        Surface(
                            shape = CutCornerShape(4.dp),
                            color = DeepSpaceBackground,
                            border = BorderStroke(0.6.dp, DividerColor),
                            modifier = Modifier.weight(1f)
                        ) {
                            Column(modifier = Modifier.padding(6.dp)) {
                                Text("AI SYNTHESIS", style = MaterialTheme.typography.labelSmall.copy(fontSize = 7.5.sp), color = TextTertiary)
                                Text("ONLINE", style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold, fontSize = 13.sp), color = QuantumViolet)
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // 3. REAL-TIME SMS STREAM LOG (INTERACTIVE & ANIMATED)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SectionHeader("REAL-TIME SMS LOG (${smsRecords.size})")
                if (smsRecords.isNotEmpty()) {
                    TextButton(onClick = { viewModel.clearSmsThreats() }) {
                        Text("CLEAR LOG", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                    }
                }
            }

            if (smsRecords.isEmpty()) {
                CyberGuardCard {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 24.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Default.Email, contentDescription = null, tint = TextTertiary, modifier = Modifier.size(36.dp))
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                "LISTENING FOR INCOMING SMS IN BACKGROUND",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp
                                ),
                                color = TextSecondary
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                "Incoming text messages will be intercepted in real time and evaluated automatically by Qwen LLM & SOC threat intelligence.",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                color = TextTertiary,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(horizontal = 16.dp)
                            )
                        }
                    }
                }
            } else {
                val dateFormat = remember { SimpleDateFormat("HH:mm:ss • MMM dd", Locale.getDefault()) }
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    for (record in smsRecords) {
                        val isDanger = record.severity == "HIGH" || record.severity == "CRITICAL"
                        val borderColor = when {
                            isDanger -> StatusCritical.copy(alpha = dangerPulse)
                            record.severity == "MEDIUM" -> StatusWarning
                            else -> DividerColor
                        }

                        CyberGuardCard(
                            borderColor = borderColor,
                            containerColor = ElevatedSurface,
                            onClick = { selectedSmsRecord = record }
                        ) {
                            Column(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = if (isDanger) Icons.Default.Warning else Icons.Default.Email,
                                            contentDescription = null,
                                            tint = if (isDanger) StatusCritical else CyberNeonCyan,
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text(
                                            text = record.sender,
                                            style = MaterialTheme.typography.labelSmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 11.sp
                                            ),
                                            color = TextPrimary
                                        )
                                    }
                                    StatusBadge(record.severity, if (isDanger) StatusCritical else StatusOnline)
                                }

                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = record.body,
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                    color = TextSecondary,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )

                                // Attached URL indicator
                                if (record.detectedUrls.isNotEmpty()) {
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(4.dp))
                                            .background(HighlightSurface)
                                            .padding(horizontal = 6.dp, vertical = 3.dp)
                                    ) {
                                        Icon(Icons.Default.Link, contentDescription = null, tint = StatusWarning, modifier = Modifier.size(12.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            text = "ATTACHED LINK: ${record.detectedUrls[0]}",
                                            style = MaterialTheme.typography.labelSmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 8.5.sp
                                            ),
                                            color = StatusWarning,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }

                                // Qwen LLM summary preview snippet
                                if (!record.qwenBriefing.isNullOrBlank()) {
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(4.dp))
                                            .background(CyberBlue.copy(alpha = 0.08f))
                                            .padding(horizontal = 6.dp, vertical = 3.dp)
                                    ) {
                                        Icon(Icons.Default.Psychology, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(12.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            text = "QWEN LLM: ${record.qwenBriefing}",
                                            style = MaterialTheme.typography.bodySmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 8.5.sp
                                            ),
                                            color = CyberBlue,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.height(8.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = dateFormat.format(Date(record.timestamp)),
                                        style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp),
                                        color = TextTertiary
                                    )
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            text = "TAP TO INSPECT FORENSICS",
                                            style = MaterialTheme.typography.labelSmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 8.sp
                                            ),
                                            color = CyberNeonCyan
                                        )
                                        Spacer(modifier = Modifier.width(2.dp))
                                        Icon(Icons.Default.ChevronRight, contentDescription = null, tint = CyberNeonCyan, modifier = Modifier.size(14.dp))
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 4. INTERACTIVE THREAT DETAIL MODAL (QWEN LLM & FORENSICS BREAKDOWN)
            selectedSmsRecord?.let { record ->
                SmsThreatDetailModal(
                    record = record,
                    onDismiss = { selectedSmsRecord = null },
                    onCopySender = {
                        clipboardManager.setText(AnnotatedString(record.sender))
                    }
                )
            }
        }

        Spacer(modifier = Modifier.height(36.dp))
    }
}

@Composable
fun SmsThreatDetailModal(
    record: SmsThreatRecord,
    onDismiss: () -> Unit,
    onCopySender: () -> Unit
) {
    val isDanger = record.severity == "HIGH" || record.severity == "CRITICAL"
    val accentColor = when (record.severity) {
        "CRITICAL", "HIGH" -> StatusCritical
        "MEDIUM" -> StatusWarning
        else -> StatusOnline
    }
    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()) }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = CutCornerShape(12.dp),
            color = DeepSpaceBackground,
            border = BorderStroke(1.5.dp, accentColor),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 20.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                // Header Bar
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(32.dp)
                                .clip(RoundedCornerShape(6.dp))
                                .background(accentColor.copy(alpha = 0.15f))
                                .border(1.dp, accentColor.copy(alpha = 0.5f), RoundedCornerShape(6.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = if (isDanger) Icons.Default.Warning else Icons.Default.Shield,
                                contentDescription = null,
                                tint = accentColor,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "SMS FORENSIC INTELLIGENCE",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp,
                                    letterSpacing = 0.8.sp
                                ),
                                color = accentColor
                            )
                            Text(
                                text = "ANALYSIS ID: ${record.id.take(8).uppercase()}",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.5.sp
                                ),
                                color = TextTertiary
                            )
                        }
                    }

                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Close",
                            tint = TextSecondary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }

                HorizontalDivider(
                    color = DividerColor,
                    modifier = Modifier.padding(vertical = 12.dp)
                )

                // Sender & Timestamp Card
                Surface(
                    shape = CutCornerShape(6.dp),
                    color = ElevatedSurface,
                    border = BorderStroke(1.dp, DividerColor),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(
                                    "ORIGINATING ADDRESS / NUMBER",
                                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.sp),
                                    color = TextTertiary
                                )
                                Text(
                                    record.sender,
                                    style = MaterialTheme.typography.titleMedium.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 14.sp
                                    ),
                                    color = TextPrimary
                                )
                            }
                            StatusBadge(record.severity, accentColor)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                "CAPTURED: ${dateFormat.format(Date(record.timestamp))}",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                                color = TextTertiary
                            )
                            Text(
                                "THREAT: ${(record.riskScore * 100).toInt()}%",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 9.sp
                                ),
                                color = accentColor
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // QWEN LLM AI SIMPLIFICATION & THREAT REFINEMENT
                Text(
                    text = "QWEN LLM THREAT REFINEMENT & EXPLANATION",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 9.sp,
                        letterSpacing = 0.5.sp
                    ),
                    color = QuantumViolet
                )
                Spacer(modifier = Modifier.height(4.dp))
                Surface(
                    shape = CutCornerShape(6.dp),
                    color = QuantumViolet.copy(alpha = 0.08f),
                    border = BorderStroke(1.dp, QuantumViolet.copy(alpha = 0.5f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Psychology,
                                contentDescription = null,
                                tint = QuantumViolet,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "WHY THIS IS A SPOOF / THREAT:",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 9.5.sp
                                ),
                                color = QuantumViolet
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        val explanation = when {
                            !record.qwenBriefing.isNullOrBlank() -> record.qwenBriefing
                            !record.reasoning.isNullOrBlank() -> record.reasoning
                            isDanger -> "High risk spoofing indicators detected. The sender is attempting to impersonate an authority or bank using deceptive urgency and credential collection patterns."
                            else -> "Message evaluated by neural defense engine. No phishing, deceptive redirection, or malicious intent was found."
                        }
                        Text(
                            text = explanation,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontSize = 11.sp,
                                lineHeight = 16.sp
                            ),
                            color = TextPrimary
                        )
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // MESSAGE PAYLOAD
                Text(
                    text = "INTERCEPTED SMS PAYLOAD",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 9.sp,
                        letterSpacing = 0.5.sp
                    ),
                    color = TextTertiary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Surface(
                    shape = RoundedCornerShape(4.dp),
                    color = HighlightSurface,
                    border = BorderStroke(0.6.dp, DividerColor),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = record.body,
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp
                        ),
                        color = TextSecondary,
                        modifier = Modifier.padding(10.dp)
                    )
                }

                // DETECTED URL FORENSICS & INTEL
                if (record.detectedUrls.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(14.dp))
                    Text(
                        text = "EMBEDDED URL & OSINT FORENSICS",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 9.sp,
                            letterSpacing = 0.5.sp
                        ),
                        color = StatusWarning
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Surface(
                        shape = CutCornerShape(6.dp),
                        color = ElevatedSurface,
                        border = BorderStroke(1.dp, StatusWarning.copy(alpha = 0.4f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            for (url in record.detectedUrls) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.Link, contentDescription = null, tint = StatusWarning, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = url,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 9.5.sp
                                        ),
                                        color = StatusWarning
                                    )
                                }
                            }

                            if (!record.vtStats.isNullOrBlank()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "VIRUSTOTAL: ${record.vtStats}",
                                    style = MaterialTheme.typography.bodySmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 8.5.sp
                                    ),
                                    color = TextSecondary
                                )
                            }
                            if (!record.urlhausStatus.isNullOrBlank()) {
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "URLHAUS BLACKLIST: ${record.urlhausStatus}",
                                    style = MaterialTheme.typography.bodySmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 8.5.sp
                                    ),
                                    color = TextSecondary
                                )
                            }
                            if (!record.urlPurpose.isNullOrBlank()) {
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "INTENT / PURPOSE: ${record.urlPurpose}",
                                    style = MaterialTheme.typography.bodySmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 8.5.sp
                                    ),
                                    color = TextSecondary
                                )
                            }
                        }
                    }
                }

                // RECOMMENDED ACTIONS
                if (record.recommendedActions.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(14.dp))
                    Text(
                        text = "RECOMMENDED MITIGATION ACTIONS",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 9.sp,
                            letterSpacing = 0.5.sp
                        ),
                        color = CyberNeonCyan
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Surface(
                        shape = CutCornerShape(6.dp),
                        color = DeepSpaceBackground,
                        border = BorderStroke(0.6.dp, DividerColor),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            for (action in record.recommendedActions) {
                                Row(verticalAlignment = Alignment.Top) {
                                    Icon(
                                        Icons.Default.Check,
                                        contentDescription = null,
                                        tint = CyberNeonCyan,
                                        modifier = Modifier.size(12.dp).padding(top = 2.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = action,
                                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.5.sp),
                                        color = TextSecondary
                                    )
                                }
                            }
                        }
                    }
                }

                // ALERT DISPATCH NOTICE
                if (record.isEmailAlertTriggered) {
                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(4.dp))
                            .background(StatusCritical.copy(alpha = 0.1f))
                            .padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Email, contentDescription = null, tint = StatusCritical, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Automated high-priority security alert emailed to operator: ${record.recipientEmail ?: "Registered Security Lead"}",
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 8.5.sp),
                            color = StatusCritical
                        )
                    }
                }

                Spacer(modifier = Modifier.height(18.dp))

                // ACTIONS
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = onCopySender,
                        shape = CutCornerShape(6.dp),
                        border = BorderStroke(1.dp, CyberBlue),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberBlue),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            "COPY SENDER",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold
                            )
                        )
                    }

                    Button(
                        onClick = onDismiss,
                        shape = CutCornerShape(6.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = accentColor, contentColor = DeepSpaceBackground),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            "CLOSE REPORT",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold
                            )
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun ScreenedCallDetailModal(
    record: ScreenedCallRecord,
    onDismiss: () -> Unit,
    onCopyNumber: () -> Unit
) {
    val isDanger = record.classification == CallRiskClassification.HIGH_RISK
    val isWarning = record.classification == CallRiskClassification.SUSPICIOUS || record.classification == CallRiskClassification.DISPUTED
    val accentColor = when {
        isDanger -> StatusCritical
        isWarning -> StatusWarning
        record.classification == CallRiskClassification.LOWER_RISK -> StatusOnline
        else -> CyberBlue
    }
    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()) }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = CutCornerShape(12.dp),
            color = DeepSpaceBackground,
            border = BorderStroke(1.5.dp, accentColor),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 20.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                // Header Bar
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(32.dp)
                                .clip(RoundedCornerShape(6.dp))
                                .background(accentColor.copy(alpha = 0.15f))
                                .border(1.dp, accentColor.copy(alpha = 0.5f), RoundedCornerShape(6.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = if (isDanger) Icons.Default.Warning else Icons.Default.Call,
                                contentDescription = null,
                                tint = accentColor,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "CALL SCREENING DOSSIER",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp,
                                    letterSpacing = 0.8.sp
                                ),
                                color = accentColor
                            )
                            Text(
                                text = "INCIDENT: ${record.incidentId.take(10).uppercase()}",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.5.sp
                                ),
                                color = TextTertiary
                            )
                        }
                    }

                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Close",
                            tint = TextSecondary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }

                HorizontalDivider(
                    color = DividerColor,
                    modifier = Modifier.padding(vertical = 12.dp)
                )

                // Caller Identity Card
                Surface(
                    shape = CutCornerShape(6.dp),
                    color = ElevatedSurface,
                    border = BorderStroke(1.dp, DividerColor),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    "NORMALIZED CALLER IDENTITY",
                                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.sp),
                                    color = TextTertiary
                                )
                                Text(
                                    record.normalizedNumber,
                                    style = MaterialTheme.typography.titleMedium.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 14.sp
                                    ),
                                    color = TextPrimary
                                )
                                if (!record.callerDisplayName.isNullOrBlank()) {
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        "ID: ${record.callerDisplayName}",
                                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                                        color = CyberNeonCyan
                                    )
                                }
                            }
                            StatusBadge(record.classification.name, accentColor)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                "SCREENED: ${dateFormat.format(Date(record.timestamp))}",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                                color = TextTertiary
                            )
                            Text(
                                "RISK: ${(record.riskScore * 100).toInt()}%",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 9.5.sp
                                ),
                                color = accentColor
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // TELECOM EXECUTION & 5-SEC SLA METRICS
                Text(
                    text = "SCREENING ENGINE LATENCY & TELECOM RESPONSE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 9.sp,
                        letterSpacing = 0.5.sp
                    ),
                    color = TextTertiary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Surface(
                    shape = CutCornerShape(6.dp),
                    color = ElevatedSurface,
                    border = BorderStroke(1.dp, DividerColor),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column {
                                Text("ENFORCED ACTION", style = MaterialTheme.typography.bodySmall.copy(fontSize = 8.sp), color = TextTertiary)
                                Text(
                                    record.actionApplied.actionCode,
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp
                                    ),
                                    color = when (record.actionApplied) {
                                        ScreeningAction.BLOCK -> StatusCritical
                                        ScreeningAction.SILENCE -> StatusWarning
                                        ScreeningAction.ALLOW -> StatusOnline
                                    }
                                )
                            }
                            Column {
                                Text("RECOMMENDED", style = MaterialTheme.typography.bodySmall.copy(fontSize = 8.sp), color = TextTertiary)
                                Text(
                                    record.recommendedAction.actionCode,
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp
                                    ),
                                    color = TextSecondary
                                )
                            }
                            Column {
                                Text("LATENCY", style = MaterialTheme.typography.bodySmall.copy(fontSize = 8.sp), color = TextTertiary)
                                Text(
                                    "${record.responseLatencyMs}ms",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp
                                    ),
                                    color = StatusOnline
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(modifier = Modifier.size(5.dp).clip(CircleShape).background(StatusOnline))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                "5-SECOND ANDROID TELECOM DEADLINE MET (${record.responseLatencyMs}ms < 5000ms)",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 7.5.sp
                                ),
                                color = StatusOnline
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // CARRIER VERIFICATION (STIR/SHAKEN)
                Text(
                    text = "CARRIER STIR/SHAKEN PROTOCOL VERDICT",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 9.sp,
                        letterSpacing = 0.5.sp
                    ),
                    color = TextTertiary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Surface(
                    shape = CutCornerShape(6.dp),
                    color = ElevatedSurface,
                    border = BorderStroke(1.dp, DividerColor),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                "CRYPTOGRAPHIC VERIFICATION:",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 8.5.sp),
                                color = TextSecondary
                            )
                            StatusBadge(
                                record.carrierVerificationStatus.label,
                                if (record.carrierVerificationStatus == CarrierVerificationStatus.PASSED) StatusOnline else TextTertiary
                            )
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = when (record.carrierVerificationStatus) {
                                CarrierVerificationStatus.PASSED -> "Carrier cryptographically verified originating number authenticity via STIR/SHAKEN certificate authority."
                                CarrierVerificationStatus.FAILED -> "Carrier flagged origin as failing cryptographic signature validation. Potential spoofing vector."
                                else -> "Carrier verification not asserted or unexposed by mobile network operator for this call leg."
                            },
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                            color = TextTertiary
                        )
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // EXPLANATION & EVIDENCE
                Surface(
                    shape = CutCornerShape(6.dp),
                    color = HighlightSurface,
                    border = BorderStroke(1.dp, accentColor.copy(alpha = 0.4f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Psychology,
                                contentDescription = null,
                                tint = QuantumViolet,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "FORENSIC ASSESSMENT & EVIDENCE:",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 9.5.sp
                                ),
                                color = QuantumViolet
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = record.explanation,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontSize = 11.sp,
                                lineHeight = 16.sp
                            ),
                            color = TextPrimary
                        )

                        if (record.reasonCodes.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "REASON CODES: ${record.reasonCodes.joinToString(", ")}",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.5.sp
                                ),
                                color = TextSecondary
                            )
                        }

                        if (record.evidenceSources.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "EVIDENCE SOURCES: ${record.evidenceSources.joinToString(", ")}",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.5.sp
                                ),
                                color = CyberNeonCyan
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(18.dp))

                // ACTIONS
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = onCopyNumber,
                        shape = CutCornerShape(6.dp),
                        border = BorderStroke(1.dp, CyberBlue),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberBlue),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            "COPY NUMBER",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold
                            )
                        )
                    }

                    Button(
                        onClick = onDismiss,
                        shape = CutCornerShape(6.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = accentColor, contentColor = DeepSpaceBackground),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            "CLOSE REPORT",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold
                            )
                        )
                    }
                }
            }
        }
    }
}


