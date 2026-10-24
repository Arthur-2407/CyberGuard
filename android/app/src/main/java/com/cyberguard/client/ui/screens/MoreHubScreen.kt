package com.cyberguard.client.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.cyberguard.client.network.ConnectionState
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.Screen
import com.cyberguard.client.ui.theme.*
import kotlin.math.cos
import kotlin.math.sin

/**
 * Hyper-Advanced Holographic Command Nexus & Subsystem Matrix.
 * Provides the operator with complete command authority over the neural defense infrastructure.
 */
@Composable
fun MoreHubScreen(navController: NavController, viewModel: MainViewModel) {
    val currentUser by viewModel.currentUser.collectAsState()
    val connectionState by viewModel.connectionState.collectAsState()
    val scrollState = rememberScrollState()
    val isAdmin = currentUser?.role.equals("admin", ignoreCase = true)
    val isConnected = connectionState == ConnectionState.CONNECTED
    var showLogoutConfirm by remember { mutableStateOf(false) }

    // Global ambient animation clock
    val infiniteTransition = rememberInfiniteTransition(label = "nexus_anim")
    val laserY by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(2400, easing = LinearEasing), RepeatMode.Reverse),
        label = "scanner_laser"
    )
    val coreRotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(14000, easing = LinearEasing), RepeatMode.Restart),
        label = "core_rotation"
    )
    val counterRotation by infiniteTransition.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(tween(9000, easing = LinearEasing), RepeatMode.Restart),
        label = "counter_rotation"
    )
    val radarPulse by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(2200, easing = LinearEasing), RepeatMode.Restart),
        label = "radar_pulse"
    )
    val beaconPulse by infiniteTransition.animateFloat(
        initialValue = 0.45f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(tween(900, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "beacon_pulse"
    )

    // Interactive core stabilization feedback state
    var coreTapFeedback by remember { mutableStateOf(false) }
    LaunchedEffect(coreTapFeedback) {
        if (coreTapFeedback) {
            kotlinx.coroutines.delay(2600)
            coreTapFeedback = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 20.dp, vertical = 20.dp)
    ) {
        // =========================================================================
        // 1. TOP HEADER & HOLOGRAPHIC BREADCRUMB
        // =========================================================================
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "SYSTEM HUB",
                    style = MaterialTheme.typography.headlineMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Black,
                        fontSize = 24.sp,
                        letterSpacing = 1.5.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "SECONDARY DESTINATIONS & GOVERNANCE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 9.sp,
                        letterSpacing = 1.2.sp
                    ),
                    color = CyberNeonCyan
                )
            }

            // Live Neural Clock Indicator
            Surface(
                shape = CutCornerShape(4.dp),
                color = HighlightSurface,
                border = BorderStroke(0.8.dp, CyberBlue.copy(alpha = 0.5f))
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .clip(CircleShape)
                            .background(if (isConnected) StatusOnline else StatusWarning)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (isConnected) "ONLINE" else "STANDBY",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 8.sp,
                            letterSpacing = 0.6.sp
                        ),
                        color = if (isConnected) StatusOnline else StatusWarning
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // =========================================================================
        // 2. COMMANDER-IN-CHARGE HOLOGRAPHIC CREDENTIAL & ACCESS MODULE
        // =========================================================================
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .clip(CutCornerShape(10.dp))
                .clickable {
                    if (currentUser == null) {
                        viewModel.showAuthModal.value = true
                    } else {
                        showLogoutConfirm = true
                    }
                },
            shape = CutCornerShape(10.dp),
            color = ElevatedSurface,
            border = BorderStroke(1.2.dp, if (isAdmin) LevelVGold.copy(alpha = 0.7f) else CyberBlue.copy(alpha = 0.5f))
        ) {
            Box(modifier = Modifier.fillMaxWidth()) {
                // Subtle holographic ambient grid background
                Canvas(modifier = Modifier.matchParentSize()) {
                    val step = 16.dp.toPx()
                    var x = 0f
                    while (x < size.width) {
                        drawLine(
                            color = CyberBlue.copy(alpha = 0.03f),
                            start = Offset(x, 0f),
                            end = Offset(x, size.height),
                            strokeWidth = 0.8f
                        )
                        x += step
                    }
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Biometric Reticle Scanner
                    Box(
                        modifier = Modifier
                            .size(48.dp)
                            .clip(CutCornerShape(8.dp))
                            .background(if (isAdmin) LevelVGold.copy(alpha = 0.12f) else CyberBlue.copy(alpha = 0.12f))
                            .border(1.dp, if (isAdmin) LevelVGold.copy(alpha = 0.5f) else CyberBlue.copy(alpha = 0.5f), CutCornerShape(8.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Canvas(modifier = Modifier.fillMaxSize().padding(4.dp)) {
                            drawBiometricScanner(laserY, if (isAdmin) LevelVGold else CyberNeonCyan)
                        }
                    }

                    Spacer(modifier = Modifier.width(14.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = if (currentUser != null) {
                                    "COMMANDER: ${currentUser?.username?.uppercase() ?: "OPERATOR"}"
                                } else {
                                    "COMMANDER IN CHARGE"
                                },
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp,
                                    letterSpacing = 0.8.sp
                                ),
                                color = if (isAdmin) LevelVGold else TextPrimary
                            )
                        }

                        Spacer(modifier = Modifier.height(2.dp))

                        Text(
                            text = if (currentUser != null) {
                                "ROLE: ${currentUser?.role?.uppercase()} • STATUS: VERIFIED"
                            } else {
                                "Tap to authenticate & link commander credentials..."
                            },
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.sp
                            ),
                            color = if (currentUser != null) TextSecondary else CyberBlue,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Spacer(modifier = Modifier.width(8.dp))

                    // Clearance Level Badge & Logout Action
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Surface(
                            shape = CutCornerShape(4.dp),
                            color = if (isAdmin) LevelVGold.copy(alpha = 0.15f) else HighlightSurface,
                            border = BorderStroke(1.dp, if (isAdmin) LevelVGold else DividerColor)
                        ) {
                            Text(
                                text = if (isAdmin) "LEVEL-V\nACCESS" else if (currentUser != null) "USER\nACCESS" else "GUEST\nLINK",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 8.sp,
                                    lineHeight = 10.sp,
                                    textAlign = TextAlign.Center
                                ),
                                color = if (isAdmin) LevelVGold else TextTertiary,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)
                            )
                        }

                        if (currentUser != null) {
                            Surface(
                                modifier = Modifier
                                    .clip(CutCornerShape(4.dp))
                                    .clickable { showLogoutConfirm = true },
                                shape = CutCornerShape(4.dp),
                                color = StatusCritical.copy(alpha = 0.15f),
                                border = BorderStroke(1.dp, StatusCritical.copy(alpha = 0.6f))
                            ) {
                                Column(
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 5.dp),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.PowerSettingsNew,
                                        contentDescription = "Log Out",
                                        tint = StatusCritical,
                                        modifier = Modifier.size(13.dp)
                                    )
                                    Text(
                                        text = "LOG OUT",
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 7.sp
                                        ),
                                        color = StatusCritical
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // =========================================================================
        // 3. INTERACTIVE QUANTUM AI CORE VISUALIZER
        // =========================================================================
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .clip(CutCornerShape(10.dp))
                .clickable { coreTapFeedback = true },
            shape = CutCornerShape(10.dp),
            color = DeepSpaceBackground,
            border = BorderStroke(1.dp, if (coreTapFeedback) HologramTeal else DividerColor)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .clip(CircleShape)
                                .background(if (coreTapFeedback) HologramTeal else QuantumViolet)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "NEURAL CORE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 9.5.sp,
                                letterSpacing = 0.8.sp
                            ),
                            color = if (coreTapFeedback) HologramTeal else TextSecondary
                        )
                    }

                    Text(
                        text = "TAP TO PULSE",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold
                        ),
                        color = TextTertiary
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Interactive Canvas Core
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(80.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val cx = size.width / 2f
                        val cy = size.height / 2f
                        val outerRadius = 34.dp.toPx()
                        val innerRadius = 22.dp.toPx()

                        // Radiating radar pulse wave
                        drawCircle(
                            color = (if (coreTapFeedback) HologramTeal else CyberNeonCyan).copy(alpha = (1f - radarPulse) * 0.4f),
                            radius = outerRadius * (1f + (radarPulse * 0.8f)),
                            style = Stroke(width = 1.dp.toPx())
                        )

                        // Outer Hexagonal Rotating Ring
                        drawPolygonRing(
                            center = Offset(cx, cy),
                            radius = outerRadius,
                            sides = 6,
                            angleDegrees = coreRotation,
                            color = if (coreTapFeedback) HologramTeal else CyberBlue.copy(alpha = 0.6f),
                            strokeWidth = 1.4.dp.toPx()
                        )

                        // Counter-Rotating Inner Square Reticle
                        drawPolygonRing(
                            center = Offset(cx, cy),
                            radius = innerRadius,
                            sides = 4,
                            angleDegrees = counterRotation,
                            color = if (coreTapFeedback) ElectricCyan else QuantumViolet.copy(alpha = 0.7f),
                            strokeWidth = 1.2.dp.toPx()
                        )

                        // Center Pulsing Neural Core
                        val coreGlow = if (coreTapFeedback) 1.4f else beaconPulse
                        drawCircle(
                            color = if (coreTapFeedback) HologramTeal else CyberNeonCyan,
                            radius = 6.dp.toPx() * coreGlow
                        )
                        drawCircle(
                            color = Color.White,
                            radius = 2.5.dp.toPx()
                        )

                        // Lateral Synaptic Data Streams
                        for (i in -3..3) {
                            if (i == 0) continue
                            val streamX = cx + (i * 45.dp.toPx())
                            if (streamX > 20 && streamX < size.width - 20) {
                                drawLine(
                                    color = CyberBlue.copy(alpha = 0.15f),
                                    start = Offset(streamX, cy - 18.dp.toPx()),
                                    end = Offset(streamX, cy + 18.dp.toPx()),
                                    strokeWidth = 0.8.dp.toPx()
                                )
                                drawCircle(
                                    color = if (i % 2 == 0) CyberNeonCyan.copy(alpha = 0.4f) else QuantumViolet.copy(alpha = 0.4f),
                                    radius = 2.dp.toPx(),
                                    center = Offset(streamX, cy + (sin((coreRotation + (i * 40)) * Math.PI / 180.0).toFloat() * 14.dp.toPx()))
                                )
                            }
                        }
                    }

                    if (coreTapFeedback) {
                        Surface(
                            shape = CutCornerShape(4.dp),
                            color = DeepSpaceBackground.copy(alpha = 0.92f),
                            border = BorderStroke(1.dp, HologramTeal)
                        ) {
                            Text(
                                text = "CORE SYNAPSE STABILIZED",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 8.5.sp
                                ),
                                color = HologramTeal,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                // 3 Live Micro-Telemetry Strips
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    CyberTelemetryChip("AI COGNITION", "99.98% OPTIMAL", HologramTeal, Modifier.weight(1f))
                    CyberTelemetryChip("WATCHDOG", "DAEMON ACTIVE", CyberBlue, Modifier.weight(1f))
                    CyberTelemetryChip("HEURISTICS", "ZERO-DAY ARMED", QuantumViolet, Modifier.weight(1f))
                }
            }
        }

        Spacer(modifier = Modifier.height(22.dp))

        // =========================================================================
        // 4. SECTION 1: CORE TACTICAL DESTINATIONS
        // =========================================================================
        SectionHeader("MORE — SECONDARY DESTINATIONS")

        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            // Destination 1: Device Security
            FuturisticSubsystemCard(
                title = "Device Security",
                subtitle = "App installations, removals, updates, and risk findings",
                telemetryTag = "KERNEL INTEGRITY: 100%",
                icon = Icons.Default.PhoneAndroid,
                accentColor = CyberBlue,
                pulseFactor = 1.0f,
                badgeText = "ACTIVE",
                onClick = { navController.navigate(Screen.DeviceSecurity.route) }
            )

            // Destination 2: Security Alerts
            FuturisticSubsystemCard(
                title = "Security Alerts",
                subtitle = "Incident notifications and investigation status",
                telemetryTag = "AI SOC RADAR",
                icon = Icons.Default.Warning,
                accentColor = StatusCritical,
                pulseFactor = beaconPulse,
                badgeText = "RADAR",
                onClick = { navController.navigate(Screen.Alerts.route) }
            )

            // Destination 3: Speaker Profiles
            FuturisticSubsystemCard(
                title = "Speaker Profiles",
                subtitle = "Voice identity enrollment and management",
                telemetryTag = "ACOUSTIC BIOMETRICS",
                icon = Icons.Default.GraphicEq,
                accentColor = ElectricCyan,
                pulseFactor = 1.0f,
                badgeText = "VOICE",
                onClick = { navController.navigate(Screen.Speakers.route) }
            )

            // Destination 4: File Analysis
            FuturisticSubsystemCard(
                title = "File Analysis",
                subtitle = "Offline audio inspection and deepfake forensics",
                telemetryTag = "SPECTROGRAM FORENSICS",
                icon = Icons.Default.Search,
                accentColor = StatusWarning,
                pulseFactor = 1.0f,
                badgeText = "SCANNER",
                onClick = { navController.navigate(Screen.FileAnalysis.route) }
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        // =========================================================================
        // 5. SECTION 2: ADMINISTRATION & MODEL GOVERNANCE
        // =========================================================================
        if (currentUser == null) {
            // Universal authentication directive for unauthenticated users
            SectionHeader("ACCESS DIRECTIVE")
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(CutCornerShape(10.dp))
                    .clickable { viewModel.showAuthModal.value = true },
                shape = CutCornerShape(10.dp),
                color = ElevatedSurface,
                border = BorderStroke(1.2.dp, CyberNeonCyan.copy(alpha = 0.6f))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .clip(RoundedCornerShape(6.dp))
                                .background(HighlightSurface)
                                .border(1.dp, CyberNeonCyan.copy(alpha = 0.5f), RoundedCornerShape(6.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = null,
                                tint = CyberNeonCyan,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "OPERATOR AUTHENTICATION DIRECTIVE",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 10.sp,
                                    letterSpacing = 0.6.sp
                                ),
                                color = TextPrimary
                            )
                            Text(
                                text = "Operator authentication required to synchronize defense telemetry, access system governance, and link commander credentials.",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                                color = TextSecondary
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = { viewModel.showAuthModal.value = true },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyberNeonCyan,
                            contentColor = DeepSpaceBackground
                        ),
                        shape = CutCornerShape(6.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            imageVector = Icons.Default.Fingerprint,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "AUTHENTICATE CREDENTIALS",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Black,
                                fontSize = 10.sp,
                                letterSpacing = 0.8.sp
                            )
                        )
                    }
                }
            }
        } else {
            // Once authenticated, the authentication directive is auto-removed!
            // Admin-exclusive controls are shown if admin:
            if (isAdmin) {
                SectionHeader("ADMINISTRATION & MODEL GOVERNANCE")
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    FuturisticSubsystemCard(
                        title = "Admin Console",
                        subtitle = "Tenant management, audit trail & active model engines",
                        telemetryTag = "MULTI-TENANT ORCHESTRATOR",
                        icon = Icons.Default.AdminPanelSettings,
                        accentColor = CyberNeonCyan,
                        pulseFactor = 1.0f,
                        badgeText = "LEVEL-V",
                        onClick = { navController.navigate(Screen.AdminConsole.route) }
                    )

                    FuturisticSubsystemCard(
                        title = "Training Review",
                        subtitle = "Ground-truth review queue & continuous retraining approvals",
                        telemetryTag = "NEURAL GROUND-TRUTH PIPELINE",
                        icon = Icons.Default.Psychology,
                        accentColor = QuantumViolet,
                        pulseFactor = 1.0f,
                        badgeText = "QUEUE",
                        onClick = { navController.navigate(Screen.TrainingReview.route) }
                    )
                }
                Spacer(modifier = Modifier.height(20.dp))
            }

            // Universal Log Out button for all authenticated sessions
            SectionHeader("OPERATOR SESSION CONTROL")
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(CutCornerShape(10.dp)),
                shape = CutCornerShape(10.dp),
                color = ElevatedSurface,
                border = BorderStroke(1.2.dp, StatusCritical.copy(alpha = 0.5f))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .clip(RoundedCornerShape(6.dp))
                                .background(StatusCritical.copy(alpha = 0.15f))
                                .border(1.dp, StatusCritical.copy(alpha = 0.5f), RoundedCornerShape(6.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.ExitToApp,
                                contentDescription = null,
                                tint = StatusCritical,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "ACTIVE SESSION: ${currentUser?.username?.uppercase() ?: "OPERATOR"}",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 10.sp,
                                    letterSpacing = 0.6.sp
                                ),
                                color = TextPrimary
                            )
                            Text(
                                text = "Role: ${currentUser?.role?.uppercase()} • Disengage operator session and revert to local telemetry standby.",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                                color = TextSecondary
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = { showLogoutConfirm = true },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = StatusCritical.copy(alpha = 0.18f),
                            contentColor = StatusCritical
                        ),
                        border = BorderStroke(1.dp, StatusCritical.copy(alpha = 0.8f)),
                        shape = CutCornerShape(6.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            imageVector = Icons.Default.PowerSettingsNew,
                            contentDescription = null,
                            tint = StatusCritical,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "DISENGAGE OPERATOR SESSION",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.sp,
                                letterSpacing = 0.8.sp
                            )
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(36.dp))
    }

    if (showLogoutConfirm) {
        AlertDialog(
            onDismissRequest = { showLogoutConfirm = false },
            title = {
                Text(
                    text = "DISENGAGE OPERATOR SESSION?",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    ),
                    color = StatusCritical
                )
            },
            text = {
                Text(
                    text = "Are you sure you want to log out from commander session '${currentUser?.username ?: "Operator"}'? Defense monitoring will remain active in local fallback mode.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.performLogout()
                        showLogoutConfirm = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = StatusCritical, contentColor = Color.White),
                    shape = CutCornerShape(4.dp)
                ) {
                    Text("LOG OUT")
                }
            },
            dismissButton = {
                OutlinedButton(
                    onClick = { showLogoutConfirm = false },
                    shape = CutCornerShape(4.dp)
                ) {
                    Text("CANCEL")
                }
            },
            containerColor = DeepSpaceBackground,
            shape = CutCornerShape(8.dp)
        )
    }
}

/**
 * Ultra-futuristic, interactive subsystem node card with spring bounce animation,
 * sci-fi corner reticles, telemetry subtext, and active glow.
 */
@Composable
private fun FuturisticSubsystemCard(
    title: String,
    subtitle: String,
    telemetryTag: String,
    icon: ImageVector,
    accentColor: Color,
    pulseFactor: Float = 1.0f,
    badgeText: String? = null,
    onClick: () -> Unit
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.97f else 1.0f,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "subsystem_card_press"
    )

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .scale(scale)
            .clip(CutCornerShape(10.dp))
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                onClick = onClick
            ),
        shape = CutCornerShape(10.dp),
        color = ElevatedSurface,
        border = BorderStroke(1.dp, if (isPressed) accentColor else HolographicGlowBorder)
    ) {
        Box(modifier = Modifier.fillMaxWidth()) {
            // Sci-Fi corner reticles
            Canvas(modifier = Modifier.matchParentSize()) {
                val bracketLen = 10.dp.toPx()
                val sw = 1.5.dp.toPx()
                val reticleColor = accentColor.copy(alpha = 0.4f * pulseFactor)

                // Top-Left ┌
                drawLine(reticleColor, Offset(0f, 0f), Offset(bracketLen, 0f), sw)
                drawLine(reticleColor, Offset(0f, 0f), Offset(0f, bracketLen), sw)

                // Bottom-Right ┘
                drawLine(reticleColor, Offset(size.width, size.height), Offset(size.width - bracketLen, size.height), sw)
                drawLine(reticleColor, Offset(size.width, size.height), Offset(size.width, size.height - bracketLen), sw)
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Futuristic Avatar with glowing border
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(CutCornerShape(8.dp))
                            .background(accentColor.copy(alpha = 0.12f))
                            .border(1.dp, accentColor.copy(alpha = 0.5f * pulseFactor), CutCornerShape(8.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = icon,
                            contentDescription = null,
                            tint = accentColor,
                            modifier = Modifier.size(22.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(14.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = title,
                                style = MaterialTheme.typography.titleMedium.copy(
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 14.sp
                                ),
                                color = TextPrimary
                            )
                            if (badgeText != null) {
                                Surface(
                                    shape = CutCornerShape(4.dp),
                                    color = accentColor.copy(alpha = 0.15f),
                                    border = BorderStroke(0.8.dp, accentColor.copy(alpha = 0.6f))
                                ) {
                                    Text(
                                        text = badgeText,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 7.5.sp,
                                            letterSpacing = 0.5.sp
                                        ),
                                        color = accentColor,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(2.dp))

                        Text(
                            text = subtitle,
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                            color = TextSecondary,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Spacer(modifier = Modifier.width(10.dp))

                    // Tactical targeting reticle icon
                    Box(
                        modifier = Modifier
                            .size(24.dp)
                            .clip(RoundedCornerShape(4.dp))
                            .background(HighlightSurface),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.ChevronRight,
                            contentDescription = null,
                            tint = accentColor,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                // Telemetry Subtext Pill
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(3.dp))
                        .background(DeepSpaceBackground.copy(alpha = 0.8f))
                        .border(0.6.dp, DividerColor, RoundedCornerShape(3.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(4.dp)
                            .clip(CircleShape)
                            .background(accentColor)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = telemetryTag,
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 8.sp,
                            fontWeight = FontWeight.SemiBold
                        ),
                        color = TextTertiary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

/**
 * Tactical micro-telemetry chip
 */
@Composable
private fun CyberTelemetryChip(
    label: String,
    value: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = CutCornerShape(4.dp),
        color = HighlightSurface,
        border = BorderStroke(0.6.dp, DividerColor),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(horizontal = 6.dp, vertical = 5.dp)) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 7.5.sp,
                    fontWeight = FontWeight.Bold
                ),
                color = TextTertiary
            )
            Spacer(modifier = Modifier.height(1.dp))
            Text(
                text = value,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 8.5.sp,
                    fontWeight = FontWeight.Bold
                ),
                color = color,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

/**
 * Draws a rotating polygon ring (hexagon or square)
 */
private fun DrawScope.drawPolygonRing(
    center: Offset,
    radius: Float,
    sides: Int,
    angleDegrees: Float,
    color: Color,
    strokeWidth: Float
) {
    val angleStep = (2 * Math.PI / sides).toFloat()
    val startAngle = (angleDegrees * Math.PI / 180.0).toFloat()

    for (i in 0 until sides) {
        val a1 = startAngle + (i * angleStep)
        val a2 = startAngle + ((i + 1) * angleStep)

        val p1 = Offset(center.x + (radius * cos(a1)), center.y + (radius * sin(a1)))
        val p2 = Offset(center.x + (radius * cos(a2)), center.y + (radius * sin(a2)))

        drawLine(color, p1, p2, strokeWidth, StrokeCap.Round)
    }
}

/**
 * Draws an interactive biometric fingerprint scanner with laser sweep
 */
private fun DrawScope.drawBiometricScanner(
    laserYFraction: Float,
    accentColor: Color
) {
    val cx = size.width / 2f
    val cy = size.height / 2f
    val maxRadius = size.width * 0.42f

    // Concentric arch ridges
    for (i in 1..4) {
        val r = maxRadius * (i / 4f)
        drawArc(
            color = accentColor.copy(alpha = 0.35f + (i * 0.12f)),
            startAngle = 180f,
            sweepAngle = 180f,
            useCenter = false,
            topLeft = Offset(cx - r, cy - r),
            size = Size(r * 2, r * 2),
            style = Stroke(width = 1.1.dp.toPx(), cap = StrokeCap.Round)
        )
        drawArc(
            color = accentColor.copy(alpha = 0.25f + (i * 0.10f)),
            startAngle = 15f,
            sweepAngle = 150f,
            useCenter = false,
            topLeft = Offset(cx - r * 0.85f, cy - r * 0.35f),
            size = Size(r * 1.7f, r * 1.7f),
            style = Stroke(width = 1.1.dp.toPx(), cap = StrokeCap.Round)
        )
    }

    // Laser scan beam
    val laserY = size.height * laserYFraction
    drawLine(
        brush = Brush.horizontalGradient(
            listOf(Color.Transparent, Color.White, accentColor, Color.Transparent)
        ),
        start = Offset(2.dp.toPx(), laserY),
        end = Offset(size.width - 2.dp.toPx(), laserY),
        strokeWidth = 1.6.dp.toPx(),
        cap = StrokeCap.Round
    )
}
