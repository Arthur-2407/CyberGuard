package com.cyberguard.client.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.cyberguard.client.network.ConnectionState
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.Screen
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.math.*

/**
 * High-Security Threat Level state for dynamic console adaptation.
 */
enum class ThreatAlertLevel {
    NORMAL,     // Calm Bio-Defense Cyan / Emerald
    ELEVATED,   // Solar Amber / Gold Watch
    CRITICAL    // Active Breach Crimson / High-Alert Orange
}

@Composable
fun DashboardScreen(navController: NavController, viewModel: MainViewModel) {
    val state by viewModel.connectionState.collectAsState()
    val serverUrl by viewModel.serverUrl.collectAsState()
    val activeEndpointType by viewModel.activeEndpointType.collectAsState()
    val showConnectionSettings by viewModel.showConnectionSettings.collectAsState()
    val currentUser by viewModel.currentUser.collectAsState()
    val summary by viewModel.dashboardSummary.collectAsState()
    val systemStatus by viewModel.systemStatus.collectAsState()
    val isSummaryLoading by viewModel.isSummaryLoading.collectAsState()
    val showSharedAuthModal by viewModel.showAuthModal.collectAsState()
    val coroutineScope = rememberCoroutineScope()

    var showAuthModal by remember { mutableStateOf(false) }
    var isRegisterMode by remember { mutableStateOf(false) }
    var authUsername by remember { mutableStateOf("") }
    var authEmail by remember { mutableStateOf("") }
    var authPassword by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var authError by remember { mutableStateOf<String?>(null) }
    var isSubmittingAuth by remember { mutableStateOf(false) }

    // Interactive Alert Simulation Override (allows operator to inspect console adaptation)
    var simulatedAlertLevel by remember { mutableStateOf<ThreatAlertLevel?>(null) }
    var interactiveInspectionNotice by remember { mutableStateOf<String?>(null) }

    val openCases = summary?.openIncidents ?: 0
    val analyzedEvents = summary?.totalEventsAnalyzed ?: 0
    val criticalThreats = (summary?.highCriticalThreats ?: 0) + (summary?.criticalThreats ?: 0)

    // Compute live alert adaptation level unless operator overrides via tap inspection
    val currentAlertLevel = simulatedAlertLevel ?: when {
        criticalThreats > 0 -> ThreatAlertLevel.CRITICAL
        openCases > 0 -> ThreatAlertLevel.ELEVATED
        else -> ThreatAlertLevel.NORMAL
    }

    LaunchedEffect(showSharedAuthModal) {
        if (showSharedAuthModal) {
            showAuthModal = true
        }
    }

    LaunchedEffect(state) {
        if (state == ConnectionState.CONNECTED) {
            viewModel.refreshDashboardSummary()
            viewModel.refreshUserProfile()
        }
    }

    // High-Precision Continuous Animations
    val infiniteTransition = rememberInfiniteTransition(label = "dashboardAnimations")

    val orbitRotation1 by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(12000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "orbitRotation1"
    )

    val orbitRotation2 by infiniteTransition.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(8500, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "orbitRotation2"
    )

    val flareScale by infiniteTransition.animateFloat(
        initialValue = 0.85f,
        targetValue = 1.25f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "flareScale"
    )

    val biometricLaserY by infiniteTransition.animateFloat(
        initialValue = 0.1f,
        targetValue = 0.9f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "biometricLaserY"
    )

    val wavePhase by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = (2 * Math.PI).toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = when (currentAlertLevel) {
                    ThreatAlertLevel.NORMAL -> 2800
                    ThreatAlertLevel.ELEVATED -> 1800
                    ThreatAlertLevel.CRITICAL -> 1100
                },
                easing = LinearEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "wavePhase"
    )

    val radarReticleAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(4000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "radarReticleAngle"
    )

    // Interactive & Continuous Animations for Tactical Strips
    val commsRadarPulse by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "commsRadarPulse"
    )

    val speakerWavePhase by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = (2 * Math.PI).toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "speakerWavePhase"
    )

    val incidentPulse by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(900, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "incidentPulse"
    )

    var isCommsPressed by remember { mutableStateOf(false) }
    val commsScale by animateFloatAsState(if (isCommsPressed) 0.96f else 1.0f, label = "commsScale")

    var isSpeakersPressed by remember { mutableStateOf(false) }
    val speakersScale by animateFloatAsState(if (isSpeakersPressed) 0.96f else 1.0f, label = "speakersScale")

    var isIncidentsPressed by remember { mutableStateOf(false) }
    val incidentsScale by animateFloatAsState(if (isIncidentsPressed) 0.96f else 1.0f, label = "incidentsScale")

    // TACTICAL OPERATOR AUTHENTICATION & REGISTRATION TERMINAL DIALOG
    if (showAuthModal) {
        val keyboardController = LocalSoftwareKeyboardController.current
        val isFormValid = if (isRegisterMode) {
            authUsername.isNotBlank() && authEmail.contains("@") && authPassword.length >= 6
        } else {
            authUsername.isNotBlank() && authPassword.isNotBlank()
        }

        AlertDialog(
            onDismissRequest = {
                if (!isSubmittingAuth) {
                    showAuthModal = false
                    viewModel.showAuthModal.value = false
                    authError = null
                }
            },
            confirmButton = {},
            containerColor = ElevatedSurface,
            shape = CutCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth(0.96f)
                .imePadding()
                .border(1.5.dp, CyberNeonCyan.copy(alpha = 0.85f), CutCornerShape(12.dp)),
            title = {
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
                                .size(34.dp)
                                .clip(CutCornerShape(6.dp))
                                .background(CyberNeonCyan.copy(alpha = 0.15f))
                                .border(1.dp, CyberNeonCyan.copy(alpha = 0.6f), CutCornerShape(6.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = if (isRegisterMode) Icons.Default.Person else Icons.Default.Fingerprint,
                                contentDescription = null,
                                tint = CyberNeonCyan,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = if (isRegisterMode) "OPERATOR REGISTRATION" else "COMMANDER AUTHENTICATION",
                                style = MaterialTheme.typography.titleMedium.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Black,
                                    fontSize = 13.sp,
                                    letterSpacing = 1.sp
                                ),
                                color = TextPrimary
                            )
                            Text(
                                text = "ZERO-TRUST SOC CREDENTIAL LINK",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.sp,
                                    letterSpacing = 0.5.sp
                                ),
                                color = CyberNeonCyan
                            )
                        }
                    }
                }
            },
            text = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(CutCornerShape(6.dp))
                            .background(FieldBackground)
                            .border(1.dp, HolographicGlowBorder, CutCornerShape(6.dp))
                            .padding(2.dp)
                    ) {
                        Surface(
                            onClick = { isRegisterMode = false },
                            modifier = Modifier.weight(1f),
                            shape = CutCornerShape(4.dp),
                            color = if (!isRegisterMode) HighlightSurface else Color.Transparent,
                            border = if (!isRegisterMode) BorderStroke(1.dp, CyberNeonCyan.copy(alpha = 0.75f)) else null
                        ) {
                            Row(
                                modifier = Modifier.padding(vertical = 8.dp),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                if (!isRegisterMode) {
                                    Box(
                                        modifier = Modifier
                                            .size(5.dp)
                                            .background(CyberNeonCyan, CutCornerShape(1.dp))
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                }
                                Text(
                                    text = "LOGIN",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = if (!isRegisterMode) FontWeight.Bold else FontWeight.Medium,
                                        fontSize = 10.sp,
                                        letterSpacing = 0.8.sp
                                    ),
                                    color = if (!isRegisterMode) CyberNeonCyan else TextTertiary
                                )
                            }
                        }

                        Surface(
                            onClick = { isRegisterMode = true },
                            modifier = Modifier.weight(1f),
                            shape = CutCornerShape(4.dp),
                            color = if (isRegisterMode) HighlightSurface else Color.Transparent,
                            border = if (isRegisterMode) BorderStroke(1.dp, CyberNeonCyan.copy(alpha = 0.75f)) else null
                        ) {
                            Row(
                                modifier = Modifier.padding(vertical = 8.dp),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                if (isRegisterMode) {
                                    Box(
                                        modifier = Modifier
                                            .size(5.dp)
                                            .background(CyberNeonCyan, CutCornerShape(1.dp))
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                }
                                Text(
                                    text = "REGISTER",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = if (isRegisterMode) FontWeight.Bold else FontWeight.Medium,
                                        fontSize = 10.sp,
                                        letterSpacing = 0.8.sp
                                    ),
                                    color = if (isRegisterMode) CyberNeonCyan else TextTertiary
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    // HIGH-CONTRAST FORM FIELDS
                    CyberTextField(
                        value = authUsername,
                        onValueChange = { authUsername = it },
                        label = if (isRegisterMode) "OPERATOR USERNAME" else "USERNAME / EMAIL",
                        placeholder = if (isRegisterMode) "e.g. secops_commander" else "Username or official email",
                        singleLine = true,
                        leadingIcon = {
                            Icon(Icons.Default.Person, contentDescription = null, tint = CyberNeonCyan, modifier = Modifier.size(16.dp))
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Email,
                            imeAction = ImeAction.Next
                        )
                    )

                    if (isRegisterMode) {
                        Spacer(modifier = Modifier.height(10.dp))
                        CyberTextField(
                            value = authEmail,
                            onValueChange = { authEmail = it },
                            label = "OFFICIAL EMAIL ADDRESS",
                            placeholder = "commander@cyberguard.network",
                            singleLine = true,
                            leadingIcon = {
                                Icon(Icons.Default.Email, contentDescription = null, tint = CyberNeonCyan, modifier = Modifier.size(16.dp))
                            },
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Email,
                                imeAction = ImeAction.Next
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    CyberTextField(
                        value = authPassword,
                        onValueChange = { authPassword = it },
                        label = "ENCRYPTED PASSCODE",
                        placeholder = if (isRegisterMode) "Min 6 characters" else "Enter operator passcode",
                        singleLine = true,
                        visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                        leadingIcon = {
                            Icon(Icons.Default.Lock, contentDescription = null, tint = CyberNeonCyan, modifier = Modifier.size(16.dp))
                        },
                        trailingIcon = {
                            TextButton(
                                onClick = { showPassword = !showPassword },
                                contentPadding = PaddingValues(horizontal = 8.dp)
                            ) {
                                Text(
                                    text = if (showPassword) "HIDE" else "SHOW",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp
                                    ),
                                    color = if (showPassword) CyberNeonCyan else TextTertiary
                                )
                            }
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(
                            onDone = {
                                keyboardController?.hide()
                            }
                        )
                    )

                    if (authError != null) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = CutCornerShape(6.dp),
                            color = StatusCritical.copy(alpha = 0.12f),
                            border = BorderStroke(1.dp, StatusCritical.copy(alpha = 0.7f))
                        ) {
                            Row(
                                modifier = Modifier.padding(10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Warning,
                                    contentDescription = null,
                                    tint = StatusCritical,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = authError!!,
                                    color = StatusCritical,
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp
                                    )
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(18.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        CyberButton(
                            text = "CANCEL",
                            onClick = {
                                showAuthModal = false
                                viewModel.showAuthModal.value = false
                                authError = null
                            },
                            variant = CyberButtonVariant.OUTLINED,
                            modifier = Modifier.weight(1f)
                        )

                        CyberButton(
                            text = if (isRegisterMode) "CREATE ID" else "AUTHENTICATE",
                            onClick = {
                                if (isFormValid) {
                                    keyboardController?.hide()
                                    isSubmittingAuth = true
                                    authError = null
                                    coroutineScope.launch {
                                        val result = if (isRegisterMode) {
                                            viewModel.register(authUsername, authEmail, authPassword)
                                        } else {
                                            viewModel.login(authUsername, authPassword)
                                        }
                                        isSubmittingAuth = false
                                        if (result.isSuccess) {
                                            showAuthModal = false
                                            viewModel.showAuthModal.value = false
                                            authPassword = ""
                                            authError = null
                                        } else {
                                            authError = result.exceptionOrNull()?.message ?: "Authentication failed"
                                        }
                                    }
                                }
                            },
                            variant = CyberButtonVariant.PRIMARY,
                            enabled = isFormValid,
                            isLoading = isSubmittingAuth,
                            modifier = Modifier.weight(1.4f)
                        )
                    }
                }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 18.dp)
    ) {
        // ══════════════════════════════════════════════════════════════════════
        // 1. TOP BRAND HEADER WITH MULTI-COLOR QUANTUM SHIELD & ORBITAL RINGS
        // ══════════════════════════════════════════════════════════════════════
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Multi-Color Orbital Ring Quantum Shield Matrix Badge
            Box(
                modifier = Modifier.size(62.dp),
                contentAlignment = Alignment.Center
            ) {
                Canvas(modifier = Modifier.size(62.dp)) {
                    val cx = size.width / 2f
                    val cy = size.height / 2f

                    // Ring 1: Solar Amber Ellipse
                    rotate(orbitRotation1, pivot = Offset(cx, cy)) {
                        drawOval(
                            color = CyberAmber.copy(alpha = 0.55f),
                            topLeft = Offset(cx - 28.dp.toPx(), cy - 13.dp.toPx()),
                            size = Size(56.dp.toPx(), 26.dp.toPx()),
                            style = Stroke(width = 1.1.dp.toPx())
                        )
                        // Orbiting Node 1
                        drawCircle(CyberAmber, radius = 2.5.dp.toPx(), center = Offset(cx + 28.dp.toPx(), cy))
                        drawCircle(Color.White, radius = 1.2.dp.toPx(), center = Offset(cx + 28.dp.toPx(), cy))
                    }

                    // Ring 2: Deep Neon Magenta Ellipse
                    rotate(orbitRotation2, pivot = Offset(cx, cy)) {
                        drawOval(
                            color = DeepNeonMagenta.copy(alpha = 0.50f),
                            topLeft = Offset(cx - 15.dp.toPx(), cy - 28.dp.toPx()),
                            size = Size(30.dp.toPx(), 56.dp.toPx()),
                            style = Stroke(width = 1.1.dp.toPx())
                        )
                        // Orbiting Node 2
                        drawCircle(DeepNeonMagenta, radius = 2.5.dp.toPx(), center = Offset(cx, cy - 28.dp.toPx()))
                        drawCircle(Color.White, radius = 1.2.dp.toPx(), center = Offset(cx, cy - 28.dp.toPx()))
                    }

                    // Ring 3: Emerald Green Diagonal Orbit
                    rotate(orbitRotation1 * 0.7f + 45f, pivot = Offset(cx, cy)) {
                        drawOval(
                            color = EmeraldGreen.copy(alpha = 0.40f),
                            topLeft = Offset(cx - 26.dp.toPx(), cy - 15.dp.toPx()),
                            size = Size(52.dp.toPx(), 30.dp.toPx()),
                            style = Stroke(width = 0.9.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(6f, 8f), 0f))
                        )
                    }

                    // Ring 4: Laser Cyan Circular Boundary Reticle
                    drawCircle(
                        color = CyberNeonCyan.copy(alpha = 0.75f),
                        radius = 29.dp.toPx(),
                        style = Stroke(width = 1.2.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(10f, 6f), 0f))
                    )

                    // Inner Faceted Holographic Quantum Shield
                    drawQuantumShieldFacet(
                        center = Offset(cx, cy),
                        width = 22.dp.toPx(),
                        height = 26.dp.toPx()
                    )
                }
            }

            Spacer(modifier = Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Box(contentAlignment = Alignment.TopEnd) {
                    Text(
                        text = "CYBERGUARD",
                        style = TextStyle(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Black,
                            fontSize = 20.sp,
                            letterSpacing = 2.4.sp,
                            brush = Brush.verticalGradient(
                                colors = listOf(
                                    Color(0xFFFFFFFF),
                                    Color(0xFFE2F8FF),
                                    Color(0xFF7DD3FC),
                                    CyberNeonCyan
                                )
                            )
                        ),
                        maxLines = 1,
                        softWrap = false
                    )

                    // 4-Point Radiant Diamond Star Flare Glint
                    Canvas(
                        modifier = Modifier
                            .size(14.dp)
                            .offset(x = 8.dp, y = (-3).dp)
                    ) {
                        drawStarGlint(
                            center = Offset(size.width / 2, size.height / 2),
                            radius = 6.dp.toPx() * flareScale,
                            color = LensFlareWhite
                        )
                    }
                }

                Spacer(modifier = Modifier.height(2.dp))

                Text(
                    text = "MULTI-MODAL SOC DEFENSE MATRIX",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 1.sp
                    ),
                    color = CyberNeonCyan
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 2. COMMANDER IN CHARGE // LEVEL-V ACCESS COMMAND BAR
        // ══════════════════════════════════════════════════════════════════════
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .clip(CutCornerShape(8.dp))
                .border(
                    BorderStroke(
                        1.dp,
                        Brush.horizontalGradient(
                            listOf(
                                CyberNeonCyan.copy(alpha = 0.65f),
                                HolographicGlowBorder,
                                CyberGold.copy(alpha = 0.65f)
                            )
                        )
                    ),
                    CutCornerShape(8.dp)
                )
                .clickable {
                    showAuthModal = true
                },
            color = HighlightSurface.copy(alpha = 0.95f),
            shape = CutCornerShape(8.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Left: Biometric Holographic Fingerprint Reticle Scanner
                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .clip(CutCornerShape(6.dp))
                        .background(ElevatedSurface)
                        .border(1.dp, CyberNeonCyan.copy(alpha = 0.7f), CutCornerShape(6.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Canvas(modifier = Modifier.size(44.dp)) {
                        drawBiometricFingerprint(
                            laserYFraction = biometricLaserY,
                            accentColor = if (currentUser != null) CyberGold else CyberNeonCyan
                        )
                    }
                }

                Spacer(modifier = Modifier.width(12.dp))

                // Center: Tactical Rank & Operator State
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = if (currentUser != null)
                            "COMMANDER: ${currentUser!!.username.uppercase()} //"
                        else
                            "COMMANDER IN CHARGE //",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Black,
                            fontSize = 11.5.sp,
                            letterSpacing = 0.8.sp
                        ),
                        color = TextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )

                    Spacer(modifier = Modifier.height(2.dp))

                    Text(
                        text = if (currentUser != null)
                            "CLEARANCE: ${currentUser!!.role.uppercase()} • TENANT #${currentUser!!.id}"
                        else
                            "Tap to authenticate & link ...",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 9.sp,
                            letterSpacing = 0.5.sp
                        ),
                        color = if (currentUser != null) CyberGold else ElectricCyan,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Spacer(modifier = Modifier.width(8.dp))

                // Right: High-Tech Metallic Golden "LEVEL-V ACCESS" Action Badge
                Surface(
                    shape = CutCornerShape(6.dp),
                    color = Color(0xFF261D08).copy(alpha = 0.92f),
                    border = BorderStroke(
                        1.2.dp,
                        Brush.verticalGradient(
                            listOf(CyberGold, CyberAmber.copy(alpha = 0.8f), Color(0xFF5A440D))
                        )
                    ),
                    modifier = Modifier.clickable { showAuthModal = true }
                ) {
                    Column(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "LEVEL-V",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Black,
                                fontSize = 10.sp,
                                letterSpacing = 0.6.sp
                            ),
                            color = CyberGold
                        )
                        Text(
                            text = "ACCESS",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 9.sp,
                                letterSpacing = 1.sp
                            ),
                            color = Color(0xFFE2F8FF)
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 3. SYSTEM STATE & DEFENSE MATRIX (HERO SECTION & SPECTROGRAM)
        // ══════════════════════════════════════════════════════════════════════
        SectionHeader("SYSTEM STATE & DEFENSE MATRIX")

        CyberGuardCard(
            modifier = Modifier.fillMaxWidth(),
            containerColor = ElevatedSurface,
            borderColor = when (currentAlertLevel) {
                ThreatAlertLevel.NORMAL -> HolographicGlowBorder
                ThreatAlertLevel.ELEVATED -> CyberAmber.copy(alpha = 0.65f)
                ThreatAlertLevel.CRITICAL -> StatusCritical.copy(alpha = 0.85f)
            }
        ) {
            // Header Row: Connection Title & Online Status
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f, fill = false)) {
                    Text(
                        text = "CORE CONNECTION",
                        style = MaterialTheme.typography.titleMedium.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.5.sp,
                            letterSpacing = 0.8.sp
                        ),
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = when {
                            state == ConnectionState.CONNECTED && activeEndpointType == "LOCAL_LAN" -> "Connected via Local LAN (Docker)"
                            state == ConnectionState.CONNECTED && activeEndpointType == "CLOUD_TUNNEL" -> "Connected via Cloud Defense Node"
                            state == ConnectionState.CONNECTED -> "Connected to CyberGuard Core"
                            state == ConnectionState.DISCOVERING -> "Scanning network for CyberGuard host..."
                            state == ConnectionState.VALIDATING -> "Validating core telemetry link..."
                            else -> "Core connection disconnected (Tap to Configure)"
                        },
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp
                        ),
                        color = TextSecondary
                    )
                    if (serverUrl != null && state == ConnectionState.CONNECTED) {
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "ENDPOINT: $serverUrl",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 8.5.sp
                            ),
                            color = TextTertiary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                Spacer(modifier = Modifier.width(8.dp))

                // Online Status Pill with Settings Trigger
                Surface(
                    shape = CutCornerShape(4.dp),
                    color = Color(0xFF032617).copy(alpha = 0.9f),
                    border = BorderStroke(1.dp, StatusOnline.copy(alpha = 0.75f)),
                    modifier = Modifier.clickable { viewModel.openConnectionSettings() }
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(6.dp)
                                .clip(RoundedCornerShape(3.dp))
                                .background(if (state == ConnectionState.CONNECTED) StatusOnline else StatusCritical)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = when (state) {
                                ConnectionState.CONNECTED -> "ONLINE"
                                ConnectionState.DISCOVERING -> "DISCOVERING"
                                ConnectionState.VALIDATING -> "VALIDATING"
                                else -> "OFFLINE"
                            },
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 9.sp,
                                letterSpacing = 0.6.sp
                            ),
                            color = when (state) {
                                ConnectionState.CONNECTED -> StatusOnline
                                ConnectionState.DISCOVERING, ConnectionState.VALIDATING -> StatusWarning
                                else -> StatusCritical
                            }
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Configure Backend",
                            tint = CyberNeonCyan,
                            modifier = Modifier.size(11.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // ── Dynamic Multi-Color Threat Spectrum Wave ──
            // Interactively tap to cycle threat alert inspection states!
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(68.dp)
                    .pointerInput(Unit) {
                        detectTapGestures {
                            // Cycle inspection simulation mode
                            simulatedAlertLevel = when (simulatedAlertLevel) {
                                null -> ThreatAlertLevel.ELEVATED
                                ThreatAlertLevel.ELEVATED -> ThreatAlertLevel.CRITICAL
                                ThreatAlertLevel.CRITICAL -> ThreatAlertLevel.NORMAL
                                ThreatAlertLevel.NORMAL -> null
                            }
                            interactiveInspectionNotice = simulatedAlertLevel?.let {
                                "SIMULATED TELEMETRY: ${it.name} SPECTRUM ADAPTATION"
                            }
                        }
                    }
            ) {
                Canvas(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(68.dp)
                ) {
                    drawMultiHarmonicThreatWave(
                        phase = wavePhase,
                        alertLevel = currentAlertLevel
                    )
                }
            }

            // Sub-Wave Cyber HUD Readouts (directly matching Image 2)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 2.dp, vertical = 2.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "REAL-TIME THREAT SCANNING",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 7.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.4.sp
                    ),
                    color = CyberNeonCyan
                )
                Text(
                    text = "AUTO-SWITCHING BASED ON THREATS",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 6.5.sp,
                        letterSpacing = 0.4.sp
                    ),
                    color = TextTertiary
                )
                Text(
                    text = "LEAD 10   STAR GO +0.80",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 7.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.4.sp
                    ),
                    color = CyberAmber
                )
            }

            if (interactiveInspectionNotice != null) {
                Text(
                    text = interactiveInspectionNotice!!,
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 7.sp,
                        color = CyberGold
                    ),
                    modifier = Modifier.padding(top = 2.dp)
                )
            }

            HorizontalDivider(
                color = DividerColor.copy(alpha = 0.7f),
                modifier = Modifier.padding(vertical = 10.dp)
            )

            // ── 3 High-Density Core Metric Displays with Circular Radar Reticles & Status Arcs ──
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                // Metric 1: OPEN CASES with Mini Radar Reticle
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "OPEN CASES",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 8.5.sp,
                            letterSpacing = 0.6.sp
                        ),
                        color = TextTertiary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = if (state == ConnectionState.CONNECTED) (if (isSummaryLoading && summary == null) "..." else openCases.toString()) else "--",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp
                            ),
                            color = if (openCases > 0) StatusWarning else StatusOnline
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Canvas(modifier = Modifier.size(16.dp)) {
                            drawCircle(CyberNeonCyan.copy(alpha = 0.35f), style = Stroke(width = 0.8.dp.toPx()))
                            rotate(radarReticleAngle) {
                                drawArc(
                                    color = CyberNeonCyan,
                                    startAngle = 0f,
                                    sweepAngle = 90f,
                                    useCenter = false,
                                    style = Stroke(width = 1.2.dp.toPx())
                                )
                            }
                        }
                    }
                }

                // Metric 2: ANALYZED with Mini Targeting Reticle
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "ANALYZED",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 8.5.sp,
                            letterSpacing = 0.6.sp
                        ),
                        color = TextTertiary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = if (state == ConnectionState.CONNECTED) (if (isSummaryLoading && summary == null) "..." else analyzedEvents.toString()) else "--",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp
                            ),
                            color = CyberBlue
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Canvas(modifier = Modifier.size(16.dp)) {
                            drawCircle(ElectricCyan.copy(alpha = 0.35f), style = Stroke(width = 0.8.dp.toPx()))
                            drawCircle(Color.White.copy(alpha = 0.8f), radius = 2.dp.toPx())
                        }
                    }
                }

                // Metric 3: CRITICAL with Circular Gauge Arc
                Column(modifier = Modifier.weight(1f)) {
                    Surface(
                        shape = CutCornerShape(4.dp),
                        color = when {
                            criticalThreats > 0 -> StatusCritical.copy(alpha = 0.15f)
                            openCases > 0 -> StatusWarning.copy(alpha = 0.12f)
                            else -> HighlightSurface.copy(alpha = 0.6f)
                        },
                        border = BorderStroke(
                            0.8.dp,
                            when {
                                criticalThreats > 0 -> StatusCritical.copy(alpha = 0.8f)
                                openCases > 0 -> StatusWarning.copy(alpha = 0.7f)
                                else -> StatusOnline.copy(alpha = 0.35f)
                            }
                        ),
                        modifier = Modifier.padding(end = 4.dp)
                    ) {
                        Column(modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp)) {
                            Text(
                                text = "CRITICAL",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.sp,
                                    letterSpacing = 0.6.sp
                                ),
                                color = if (criticalThreats > 0) StatusCritical else StatusOnline
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = if (state == ConnectionState.CONNECTED) (if (isSummaryLoading && summary == null) "..." else criticalThreats.toString()) else "--",
                                    style = MaterialTheme.typography.titleMedium.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 15.sp
                                    ),
                                    color = if (criticalThreats > 0) StatusCritical else StatusOnline
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Canvas(modifier = Modifier.size(16.dp)) {
                                    val arcColor = if (criticalThreats > 0) StatusCritical else StatusOnline
                                    drawCircle(arcColor.copy(alpha = 0.25f), style = Stroke(width = 1.dp.toPx()))
                                    drawArc(
                                        color = arcColor,
                                        startAngle = -90f,
                                        sweepAngle = if (criticalThreats > 0) 270f else 60f,
                                        useCenter = false,
                                        style = Stroke(width = 1.8.dp.toPx(), cap = StrokeCap.Round)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(22.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 4. COMMAND CENTER (FEATURED THREAT HUB & MULTI-SPECTRAL CARDS)
        // ══════════════════════════════════════════════════════════════════════
        SectionHeader("COMMAND CENTER")

        // PRIMARY FEATURED THREAT & FORENSICS HUB CARD (MATCHING IMAGE 2)
        CyberGuardCard(
            modifier = Modifier.fillMaxWidth(),
            borderColor = CyberNeonCyan.copy(alpha = 0.8f),
            containerColor = HighlightSurface.copy(alpha = 0.95f),
            onClick = { navController.navigate(Screen.ThreatCenter.route) }
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Left: 3D Holographic Quantum Shield with Multi-Color Aura Rings
                Box(
                    modifier = Modifier.size(52.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Canvas(modifier = Modifier.size(52.dp)) {
                        val cx = size.width / 2f
                        val cy = size.height / 2f

                        // Outer Fiery Amber / Gold Aura Ring
                        rotate(orbitRotation1 * 0.8f, pivot = Offset(cx, cy)) {
                            drawCircle(
                                color = CyberAmber.copy(alpha = 0.45f),
                                radius = 23.dp.toPx(),
                                style = Stroke(width = 1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(6f, 8f), 0f))
                            )
                            drawCircle(CyberAmber, radius = 2.dp.toPx(), center = Offset(cx + 23.dp.toPx(), cy))
                        }

                        // Inner Laser Cyan Ring
                        rotate(orbitRotation2 * 0.9f, pivot = Offset(cx, cy)) {
                            drawCircle(
                                color = CyberNeonCyan.copy(alpha = 0.6f),
                                radius = 17.dp.toPx(),
                                style = Stroke(width = 1.2.dp.toPx())
                            )
                        }

                        // Faceted Shield Contour
                        drawQuantumShieldFacet(
                            center = Offset(cx, cy),
                            width = 20.dp.toPx(),
                            height = 24.dp.toPx()
                        )
                    }

                    // Centered Glowing Lock Icon
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = null,
                        tint = CyberNeonCyan,
                        modifier = Modifier.size(15.dp)
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
                            text = "THREAT & FORENSICS HUB",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.5.sp,
                                letterSpacing = 0.8.sp
                            ),
                            color = TextPrimary
                        )

                        // Cyan "NEW" Pill Badge
                        Surface(
                            shape = CutCornerShape(4.dp),
                            color = CyberNeonCyan.copy(alpha = 0.15f),
                            border = BorderStroke(0.8.dp, CyberNeonCyan)
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(4.dp)
                                        .clip(RoundedCornerShape(2.dp))
                                        .background(CyberNeonCyan)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    text = "NEW",
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

                    Spacer(modifier = Modifier.height(3.dp))

                    Text(
                        text = "Image Deepfake • QR Quishing • URL Feeds • Qwen LLM",
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 9.sp
                        ),
                        color = TextSecondary
                    )

                    Spacer(modifier = Modifier.height(5.dp))

                    // Auto-Adapting Status Telemetry Banner
                    Text(
                        text = when (currentAlertLevel) {
                            ThreatAlertLevel.NORMAL -> "ACTIVE"
                            ThreatAlertLevel.ELEVATED -> "ELEVATED"
                            ThreatAlertLevel.CRITICAL -> "CRITICAL"
                        },
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 8.5.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.6.sp
                        ),
                        color = when (currentAlertLevel) {
                            ThreatAlertLevel.NORMAL -> StatusOnline
                            ThreatAlertLevel.ELEVATED -> CyberAmber
                            ThreatAlertLevel.CRITICAL -> StatusCritical
                        }
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // ── DUAL TACTICAL GRID (FILE ANALYSIS & DEVICE SECURITY) ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // CARD 1: FILE ANALYSIS with Real-Time HUD Gauge
            CyberGuardCard(
                modifier = Modifier.weight(1f),
                containerColor = ElevatedSurface,
                onClick = { navController.navigate(Screen.FileAnalysis.route) }
            ) {
                // Top Row: Holographic Icon & Top-Right Scan Status HUD
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.Top
                ) {
                    // Holographic cybernetic magnifying glass with dual arcs
                    Box(modifier = Modifier.size(32.dp), contentAlignment = Alignment.Center) {
                        Canvas(modifier = Modifier.size(32.dp)) {
                            val cx = size.width / 2f
                            val cy = size.height / 2f
                            drawCircle(CyberNeonCyan.copy(alpha = 0.35f), center = Offset(cx, cy), style = Stroke(width = 1.dp.toPx()))
                            rotate(radarReticleAngle * 0.7f, pivot = Offset(cx, cy)) {
                                drawArc(
                                    color = CyberNeonCyan,
                                    startAngle = 30f,
                                    sweepAngle = 100f,
                                    useCenter = false,
                                    style = Stroke(width = 1.4.dp.toPx())
                                )
                            }
                        }
                        Icon(
                            imageVector = Icons.Default.Search,
                            contentDescription = null,
                            tint = CyberNeonCyan,
                            modifier = Modifier.size(16.dp)
                        )
                    }

                    // Mini Top-Right Scan Active HUD Widget
                    Column(horizontalAlignment = Alignment.End) {
                        Text(
                            text = "REAL-TIME SCAN ACTIVE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 6.sp,
                                letterSpacing = 0.3.sp
                            ),
                            color = TextTertiary
                        )
                        Spacer(modifier = Modifier.height(3.dp))
                        // Horizontal cyan slider bar
                        Canvas(modifier = Modifier.size(46.dp, 4.dp)) {
                            drawLine(
                                color = TextDisabled,
                                start = Offset(0f, size.height / 2),
                                end = Offset(size.width, size.height / 2),
                                strokeWidth = 1.5.dp.toPx()
                            )
                            drawLine(
                                color = CyberNeonCyan,
                                start = Offset(0f, size.height / 2),
                                end = Offset(size.width * 0.68f, size.height / 2),
                                strokeWidth = 1.5.dp.toPx()
                            )
                            drawCircle(Color.White, radius = 2.dp.toPx(), center = Offset(size.width * 0.68f, size.height / 2))
                        }
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = "FILE ANALYSIS",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp,
                        letterSpacing = 0.6.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "Audio inspection",
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp
                    ),
                    color = TextSecondary,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }

            // CARD 2: DEVICE SECURITY with Phone + Biometric Reticle & Danger Meter
            CyberGuardCard(
                modifier = Modifier.weight(1f),
                containerColor = ElevatedSurface,
                onClick = { navController.navigate(Screen.DeviceSecurity.route) }
            ) {
                // Top Row: Smartphone + Biometric Icon & Top-Right Danger Meter HUD
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.Top
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.PhoneAndroid,
                            contentDescription = null,
                            tint = CyberNeonCyan,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Icon(
                            imageVector = Icons.Default.Fingerprint,
                            contentDescription = null,
                            tint = CyberAmber,
                            modifier = Modifier.size(16.dp)
                        )
                    }

                    // Mini Top-Right Danger Meter HUD Widget
                    Column(horizontalAlignment = Alignment.End) {
                        Text(
                            text = "REAL-TIME SCAN ACTIVE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 6.sp,
                                letterSpacing = 0.3.sp
                            ),
                            color = TextTertiary
                        )
                        Spacer(modifier = Modifier.height(3.dp))
                        // Danger Meter Bar with Amber/Red Gradient
                        Canvas(modifier = Modifier.size(46.dp, 4.dp)) {
                            drawRect(
                                brush = Brush.horizontalGradient(
                                    listOf(StatusOnline, CyberAmber, StatusCritical)
                                ),
                                topLeft = Offset(0f, 0f),
                                size = Size(size.width, size.height)
                            )
                        }
                        Text(
                            text = "DANGER",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 6.sp,
                                fontWeight = FontWeight.Bold
                            ),
                            color = StatusCritical,
                            modifier = Modifier.padding(top = 1.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = "DEVICE SECURITY",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp,
                        letterSpacing = 0.6.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "App watchdog & risk",
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp
                    ),
                    color = TextSecondary,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // ── COMMS DEFENSE MATRIX FULL-WIDTH STRIP (INTERACTIVE & ANIMATED) ──
        CyberGuardCard(
            modifier = Modifier
                .fillMaxWidth()
                .scale(commsScale)
                .clickable {
                    coroutineScope.launch {
                        isCommsPressed = true
                        delay(120)
                        isCommsPressed = false
                        navController.navigate(Screen.Comms.route)
                    }
                },
            borderColor = StatusOnline.copy(alpha = 0.5f + 0.3f * sin(speakerWavePhase)),
            containerColor = ElevatedSurface
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    // Animated Radar Antenna Icon Box
                    Box(
                        modifier = Modifier
                            .size(46.dp)
                            .clip(CutCornerShape(8.dp))
                            .background(StatusOnline.copy(alpha = 0.12f))
                            .border(1.dp, StatusOnline.copy(alpha = 0.6f), CutCornerShape(8.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Canvas(modifier = Modifier.size(46.dp)) {
                            val cx = size.width / 2f
                            val cy = size.height / 2f
                            // Radiating Radar Waves
                            drawCircle(
                                color = StatusOnline.copy(alpha = (1f - commsRadarPulse) * 0.5f),
                                center = Offset(cx, cy),
                                radius = 8.dp.toPx() + (commsRadarPulse * 14.dp.toPx()),
                                style = Stroke(width = 1.2.dp.toPx())
                            )
                        }
                        Icon(
                            Icons.Default.CellTower,
                            contentDescription = null,
                            tint = StatusOnline,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(14.dp))
                    Column {
                        Text(
                            "COMMS DEFENSE MATRIX",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                letterSpacing = 0.7.sp
                            ),
                            color = TextPrimary
                        )
                        Text(
                            "Real-time call shield & SMS threat intelligence",
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                            color = TextSecondary,
                            modifier = Modifier.padding(top = 2.dp)
                        )
                    }
                }

                // Active Telemetry Status Chip with Pulsing Green Dot
                Surface(
                    shape = CutCornerShape(4.dp),
                    color = Color(0xFF032617).copy(alpha = 0.8f),
                    border = BorderStroke(0.8.dp, StatusOnline.copy(alpha = 0.7f))
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(5.dp)
                                .clip(RoundedCornerShape(2.5.dp))
                                .background(StatusOnline.copy(alpha = 0.6f + 0.4f * sin(speakerWavePhase)))
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "ARMED",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 8.5.sp
                            ),
                            color = StatusOnline
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // ── DUAL TACTICAL STRIP: SPEAKERS & INCIDENTS (INTERACTIVE & ANIMATED) ──
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            // CARD 1: SPEAKERS (Animated Waveform Equalizer)
            CyberGuardCard(
                modifier = Modifier
                    .weight(1f)
                    .scale(speakersScale)
                    .clickable {
                        coroutineScope.launch {
                            isSpeakersPressed = true
                            delay(120)
                            isSpeakersPressed = false
                            navController.navigate(Screen.Speakers.route)
                        }
                    },
                borderColor = ElectricCyan.copy(alpha = 0.65f),
                containerColor = ElevatedSurface
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.Top
                ) {
                    // Animated 5-Bar Waveform Equalizer
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(CutCornerShape(6.dp))
                            .background(ElectricCyan.copy(alpha = 0.12f))
                            .border(1.dp, ElectricCyan.copy(alpha = 0.4f), CutCornerShape(6.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Canvas(modifier = Modifier.size(24.dp, 18.dp)) {
                            val barCount = 5
                            val barW = 2.5.dp.toPx()
                            val totalW = size.width
                            val spacing = (totalW - (barCount * barW)) / (barCount - 1)
                            for (i in 0 until barCount) {
                                val waveFactor = ((sin(speakerWavePhase + (i * 1.2f)) + 1f) / 2f).coerceIn(0.2f, 1f)
                                val barH = size.height * waveFactor
                                val x = i * (barW + spacing)
                                drawLine(
                                    color = ElectricCyan,
                                    start = Offset(x, size.height),
                                    end = Offset(x, size.height - barH),
                                    strokeWidth = barW,
                                    cap = StrokeCap.Round
                                )
                            }
                        }
                    }

                    // Mini live badge
                    Surface(
                        shape = CutCornerShape(3.dp),
                        color = ElectricCyan.copy(alpha = 0.15f),
                        border = BorderStroke(0.6.dp, ElectricCyan.copy(alpha = 0.6f))
                    ) {
                        Text(
                            text = "VOICE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 7.5.sp,
                                fontWeight = FontWeight.Bold
                            ),
                            color = ElectricCyan,
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "SPEAKERS",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp,
                        letterSpacing = 0.6.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "Voice profiles",
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp
                    ),
                    color = TextSecondary,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }

            // CARD 2: INCIDENTS (Animated Pulsing Warning Beacon)
            CyberGuardCard(
                modifier = Modifier
                    .weight(1f)
                    .scale(incidentsScale)
                    .clickable {
                        coroutineScope.launch {
                            isIncidentsPressed = true
                            delay(120)
                            isIncidentsPressed = false
                            navController.navigate(Screen.Alerts.route)
                        }
                    },
                borderColor = StatusCritical.copy(alpha = incidentPulse * 0.8f),
                containerColor = ElevatedSurface
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.Top
                ) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(CutCornerShape(6.dp))
                            .background(StatusCritical.copy(alpha = 0.14f))
                            .border(1.dp, StatusCritical.copy(alpha = incidentPulse * 0.7f), CutCornerShape(6.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Canvas(modifier = Modifier.size(38.dp)) {
                            drawCircle(
                                color = StatusCritical.copy(alpha = (1f - incidentPulse) * 0.4f),
                                radius = size.width * 0.45f,
                                style = Stroke(width = 1.dp.toPx())
                            )
                        }
                        Icon(
                            Icons.Default.Warning,
                            contentDescription = null,
                            tint = StatusCritical,
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    // Mini live badge showing incident count
                    Surface(
                        shape = CutCornerShape(3.dp),
                        color = if (criticalThreats > 0) StatusCritical.copy(alpha = 0.2f) else StatusOnline.copy(alpha = 0.15f),
                        border = BorderStroke(0.6.dp, if (criticalThreats > 0) StatusCritical else StatusOnline)
                    ) {
                        Text(
                            text = if (criticalThreats > 0) "! BREACH" else "CLEAN",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 7.5.sp,
                                fontWeight = FontWeight.Bold
                            ),
                            color = if (criticalThreats > 0) StatusCritical else StatusOnline,
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "INCIDENTS",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp,
                        letterSpacing = 0.6.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "SOC cases log",
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp
                    ),
                    color = TextSecondary,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }
        }

        // ADMINISTRATION & MODEL GOVERNANCE COMMAND SECTION (VISIBLE WHEN ADMIN)
        if (currentUser?.role.equals("admin", ignoreCase = true)) {
            Spacer(modifier = Modifier.height(24.dp))
            SectionHeader("ADMINISTRATION & MODEL GOVERNANCE")

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                CyberGuardCard(
                    modifier = Modifier.weight(1f),
                    borderColor = CyberNeonCyan,
                    containerColor = HighlightSurface,
                    onClick = { navController.navigate(Screen.AdminConsole.route) }
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.AdminPanelSettings, contentDescription = null, tint = CyberNeonCyan, modifier = Modifier.size(26.dp))
                        StatusBadge("ADMIN", CyberNeonCyan)
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Text("ADMIN CONSOLE", style = MaterialTheme.typography.labelSmall, color = TextPrimary)
                    Text("Tenant & model ops", style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = Modifier.padding(top = 2.dp))
                }

                CyberGuardCard(
                    modifier = Modifier.weight(1f),
                    borderColor = QuantumViolet,
                    containerColor = HighlightSurface,
                    onClick = { navController.navigate(Screen.TrainingReview.route) }
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Psychology, contentDescription = null, tint = QuantumViolet, modifier = Modifier.size(26.dp))
                        StatusBadge("QUEUE", QuantumViolet)
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Text("TRAINING REVIEW", style = MaterialTheme.typography.labelSmall, color = TextPrimary)
                    Text("Retraining queue", style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = Modifier.padding(top = 2.dp))
                }
            }
        }

        Spacer(modifier = Modifier.height(36.dp))
    }

    if (showConnectionSettings) {
        com.cyberguard.client.ui.components.ConnectionSettingsModal(
            viewModel = viewModel,
            onDismiss = { viewModel.closeConnectionSettings() }
        )
    }
}

/**
 * Draws the Faceted Quantum Shield emblem geometry.
 */
private fun DrawScope.drawQuantumShieldFacet(
    center: Offset,
    width: Float,
    height: Float
) {
    val cx = center.x
    val cy = center.y
    val halfW = width / 2f
    val halfH = height / 2f

    val outerShield = Path().apply {
        moveTo(cx - halfW, cy - halfH * 0.7f)
        quadraticBezierTo(cx, cy - halfH * 0.5f, cx + halfW, cy - halfH * 0.7f)
        quadraticBezierTo(cx + halfW * 1.05f, cy, cx + halfW * 0.8f, cy + halfH * 0.45f)
        quadraticBezierTo(cx + halfW * 0.5f, cy + halfH * 0.85f, cx, cy + halfH)
        quadraticBezierTo(cx - halfW * 0.5f, cy + halfH * 0.85f, cx - halfW * 0.8f, cy + halfH * 0.45f)
        quadraticBezierTo(cx - halfW * 1.05f, cy, cx - halfW, cy - halfH * 0.7f)
        close()
    }

    drawPath(
        path = outerShield,
        color = CyberNeonCyan,
        style = Stroke(width = 1.3.dp.toPx())
    )

    // Electric Vertical Spine
    drawLine(
        brush = Brush.verticalGradient(listOf(Color.White, CyberNeonCyan, Color.Transparent)),
        start = Offset(cx, cy - halfH * 0.5f),
        end = Offset(cx, cy + halfH * 0.9f),
        strokeWidth = 1.dp.toPx()
    )

    // Center Quantum Diamond
    val dSize = 3.dp.toPx()
    val diamondPath = Path().apply {
        moveTo(cx, cy - dSize)
        lineTo(cx + dSize, cy)
        lineTo(cx, cy + dSize)
        lineTo(cx - dSize, cy)
        close()
    }
    drawPath(diamondPath, color = Color.White)
}

/**
 * Procedurally draws biometric fingerprint ridge arcs with vertical laser sweep.
 */
private fun DrawScope.drawBiometricFingerprint(
    laserYFraction: Float,
    accentColor: Color
) {
    val cx = size.width / 2f
    val cy = size.height / 2f
    val maxRadius = size.width * 0.38f

    // 4 Concentric Fingerprint Ridge Loops with natural arch cuts
    for (i in 1..4) {
        val r = maxRadius * (i / 4f)
        drawArc(
            color = accentColor.copy(alpha = 0.45f + (i * 0.1f)),
            startAngle = 180f,
            sweepAngle = 180f,
            useCenter = false,
            topLeft = Offset(cx - r, cy - r),
            size = Size(r * 2, r * 2),
            style = Stroke(width = 1.1.dp.toPx(), cap = StrokeCap.Round)
        )
        // Lower loops
        drawArc(
            color = accentColor.copy(alpha = 0.35f + (i * 0.1f)),
            startAngle = 15f,
            sweepAngle = 150f,
            useCenter = false,
            topLeft = Offset(cx - r * 0.8f, cy - r * 0.4f),
            size = Size(r * 1.6f, r * 1.6f),
            style = Stroke(width = 1.1.dp.toPx(), cap = StrokeCap.Round)
        )
    }

    // Animated Vertical Laser Scan Line
    val laserY = size.height * laserYFraction
    drawLine(
        brush = Brush.horizontalGradient(
            listOf(Color.Transparent, Color.White, accentColor, Color.Transparent)
        ),
        start = Offset(4.dp.toPx(), laserY),
        end = Offset(size.width - 4.dp.toPx(), laserY),
        strokeWidth = 1.5.dp.toPx()
    )
}

/**
 * Draws the Multi-Harmonic Threat Waveform with multi-color particle integration and alert auto-adaptation.
 */
private fun DrawScope.drawMultiHarmonicThreatWave(
    phase: Float,
    alertLevel: ThreatAlertLevel
) {
    val midY = size.height * 0.62f
    val step = 3f

    // Alert-adapted parameters
    val (primaryColor, midColor, spikeColor) = when (alertLevel) {
        ThreatAlertLevel.NORMAL -> Triple(EmeraldGreen, CyberAmber, ThreatAlertRed)
        ThreatAlertLevel.ELEVATED -> Triple(CyberAmber, CyberYellow, ThreatAlertRed)
        ThreatAlertLevel.CRITICAL -> Triple(ThreatAlertRed, HighAlertOrange, Color(0xFFFF0055))
    }

    val ampMultiplier = when (alertLevel) {
        ThreatAlertLevel.NORMAL -> 1.0f
        ThreatAlertLevel.ELEVATED -> 1.35f
        ThreatAlertLevel.CRITICAL -> 1.75f
    }

    // Baseline carrier wave (Emerald Green / Cyan)
    val wavePath1 = Path()
    // Threat analysis mid wave (Solar Amber)
    val wavePath2 = Path()
    // Critical barrier spike wave (Fiery Crimson)
    val wavePath3 = Path()

    var x = 0f
    wavePath1.moveTo(0f, midY)
    wavePath2.moveTo(0f, midY)
    wavePath3.moveTo(0f, midY)

    while (x <= size.width) {
        val prog = x / size.width

        // Wave 1: Carrier frequency
        val y1 = midY - (sin(prog * 3.5 * Math.PI + phase) * (10.dp.toPx() * ampMultiplier)).toFloat()
        wavePath1.lineTo(x, y1)

        // Wave 2: Mid-tier threat harmonic (higher peaks toward right-center)
        val env2 = sin(prog * Math.PI).toFloat().coerceAtLeast(0f)
        val y2 = midY - (sin(prog * 5.0 * Math.PI + phase * 1.2) * (16.dp.toPx() * ampMultiplier) * env2).toFloat()
        wavePath2.lineTo(x, y2)

        // Wave 3: Critical spike wave (sharp localized crests)
        val env3 = (prog * prog).coerceIn(0f, 1f) // peaks towards the right
        val y3 = midY - (sin(prog * 7.5 * Math.PI + phase * 1.5) * (24.dp.toPx() * ampMultiplier) * env3).toFloat()
        wavePath3.lineTo(x, y3)

        // Draw vertical dotted spectral stems for peaks (like high-tech spectrum analyzer)
        if (x.toInt() % 18 == 0) {
            val peakY = minOf(y1, minOf(y2, y3))
            drawLine(
                color = midColor.copy(alpha = 0.25f),
                start = Offset(x, midY),
                end = Offset(x, peakY),
                strokeWidth = 0.8.dp.toPx(),
                pathEffect = PathEffect.dashPathEffect(floatArrayOf(3f, 5f), 0f)
            )
            // Particle dot on top
            drawCircle(
                color = if (y3 < y2 && y3 < y1) spikeColor else if (y2 < y1) midColor else primaryColor,
                radius = 1.4.dp.toPx(),
                center = Offset(x, peakY)
            )
        }

        x += step
    }

    // Draw Carrier Wave (Cyan / Emerald)
    drawPath(
        path = wavePath1,
        color = primaryColor.copy(alpha = 0.65f),
        style = Stroke(width = 1.4.dp.toPx(), cap = StrokeCap.Round)
    )

    // Draw Threat Wave (Amber / Gold)
    drawPath(
        path = wavePath2,
        color = midColor.copy(alpha = 0.80f),
        style = Stroke(width = 1.6.dp.toPx(), cap = StrokeCap.Round)
    )

    // Draw Critical Spike Wave (Red / Crimson)
    drawPath(
        path = wavePath3,
        color = spikeColor,
        style = Stroke(width = 1.8.dp.toPx(), cap = StrokeCap.Round)
    )
}
