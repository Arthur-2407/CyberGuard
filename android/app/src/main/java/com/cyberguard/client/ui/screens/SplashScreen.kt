package com.cyberguard.client.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.cyberguard.client.network.ConnectionManager
import com.cyberguard.client.network.ConnectionState
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.Screen
import com.cyberguard.client.ui.components.ConnectionSettingsModal
import com.cyberguard.client.ui.theme.*
import kotlin.math.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SplashScreen(navController: NavController, viewModel: MainViewModel) {
    val state by viewModel.connectionState.collectAsState()
    val discoveryStatusText by viewModel.discoveryStatus.collectAsState()
    val detectedGateway = viewModel.detectedGatewayIp
    val connectionConfig by viewModel.connectionConfig.collectAsState()
    val failoverNotice by viewModel.failoverNotice.collectAsState()

    // Interactive state for tactical HUD & radar inspection
    var selectedThreatDetail by remember { mutableStateOf<String?>(null) }
    var shieldShockwaveActive by remember { mutableStateOf(false) }

    LaunchedEffect(state) {
        if (state == ConnectionState.CONNECTED) {
            navController.navigate(Screen.Dashboard.route) {
                popUpTo(Screen.Splash.route) { inclusive = true }
            }
        }
    }

    // High-Precision Continuous Animations
    val transition = rememberInfiniteTransition(label = "quantum_core")

    // 1. Primary Photonic Core Glow & Heartbeat Pulse
    val pulseAlpha by transition.animateFloat(
        initialValue = 0.45f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseAlpha"
    )

    // 2. High-speed Gyroscopic Ring 1 Rotation (Clockwise)
    val gyroRotation1 by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(10000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "gyroRotation1"
    )

    // 3. Counter Gyroscopic Ring 2 Rotation (Counter-Clockwise)
    val gyroRotation2 by transition.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(7500, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "gyroRotation2"
    )

    // 4. 3D Holographic Perspective Radar Sweep Angle (Smooth 360° Continuous Radar Conical Sweep)
    val radarSweepAngle by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(2600, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "radarSweep"
    )

    // 5. Threat Target Lock Beacon Pulsing Ring (Expanding Red Warning Ring)
    val targetLockExpansion by transition.animateFloat(
        initialValue = 0.2f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = LinearOutSlowInEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "targetLock"
    )

    // 6. Star Lens Flare Shimmer on Title
    val flareScale by transition.animateFloat(
        initialValue = 0.85f,
        targetValue = 1.25f,
        animationSpec = infiniteRepeatable(
            animation = tween(1600, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "flareScale"
    )

    // 7. Visualizer Frequency Wave Phase
    val visualizerPhase by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2 * PI).toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(1800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "visWave"
    )

    // Shockwave animation trigger on user tap
    val shockwaveAnim = remember { Animatable(0f) }
    LaunchedEffect(shieldShockwaveActive) {
        if (shieldShockwaveActive) {
            shockwaveAnim.snapTo(0f)
            shockwaveAnim.animateTo(
                targetValue = 1f,
                animationSpec = tween(700, easing = FastOutSlowInEasing)
            )
            shieldShockwaveActive = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpaceBackground)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 18.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        Spacer(modifier = Modifier.height(6.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 1. TOP HUD TELEMETRY HEADER
        // ══════════════════════════════════════════════════════════════════════
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            // Left HUD block: System ID & Optical Barcode Ticks
            Column(horizontalAlignment = Alignment.Start) {
                Text(
                    text = "┌  [SYS.ID: CG-CORE-4096]",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 1.sp
                    ),
                    color = TextTertiary
                )
                Spacer(modifier = Modifier.height(3.dp))
                // High-tech optical barcode ticks
                Row(
                    modifier = Modifier.padding(start = 14.dp),
                    horizontalArrangement = Arrangement.spacedBy(2.5.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val tickHeights = listOf(7, 12, 10, 4, 11, 8, 12, 5, 9, 13, 6, 10, 8, 4, 11, 7)
                    tickHeights.forEachIndexed { idx, h ->
                        Box(
                            modifier = Modifier
                                .width(1.5.dp)
                                .height(h.dp)
                                .background(if (idx % 3 == 0) CyberNeonCyan.copy(alpha = 0.8f) else TextTertiary.copy(alpha = 0.5f))
                        )
                    }
                }
            }

            // Right HUD block: Security Level & Telemetry Matrix Readout
            Column(horizontalAlignment = Alignment.End) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "[SEC.LVL: 09",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                            letterSpacing = 1.2.sp
                        ),
                        color = CyberAmber
                    )
                    Text(
                        text = "  ┐",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        ),
                        color = CyberAmber
                    )
                }

                Text(
                    text = "// HIGH ALERT",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Black,
                        fontSize = 11.sp,
                        letterSpacing = 1.sp
                    ),
                    color = HighAlertOrange,
                    modifier = Modifier.padding(top = 1.dp)
                )

                Spacer(modifier = Modifier.height(4.dp))

                // High-density micro-telemetry readouts
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "DIGITAL TELEMETRICS ",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 7.5.sp,
                            letterSpacing = 0.5.sp
                        ),
                        color = TextTertiary
                    )
                    // Mini segmented progress blocks
                    Row(horizontalArrangement = Arrangement.spacedBy(1.5.dp)) {
                        for (i in 0 until 14) {
                            Box(
                                modifier = Modifier
                                    .width(2.dp)
                                    .height(5.dp)
                                    .background(if (i < 11) HighAlertOrange.copy(alpha = 0.9f) else TextTertiary.copy(alpha = 0.3f))
                            )
                        }
                    }
                }

                Text(
                    text = "| GRID NCID-M018 | DISP 0.89-6048",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 7.5.sp
                    ),
                    color = TextTertiary.copy(alpha = 0.85f)
                )

                Text(
                    text = "| METRIC 0.887%  | SECURITY ACTIVE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 7.5.sp
                    ),
                    color = TextTertiary.copy(alpha = 0.85f)
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 2. CENTERPIECE HOLOGRAPHIC 3D QUANTUM SHIELD & ORBITAL MATRIX
        // ══════════════════════════════════════════════════════════════════════
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(236.dp)
                .pointerInput(Unit) {
                    detectTapGestures {
                        shieldShockwaveActive = true
                        selectedThreatDetail = "QUANTUM SHIELD HARMONIZED"
                    }
                },
            contentAlignment = Alignment.Center
        ) {
            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(236.dp)
            ) {
                val cx = size.width / 2f
                val cy = size.height / 2f

                // ── A. Photonic Plasma Backlight Glow ──
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(
                            CyberNeonCyan.copy(alpha = 0.28f * pulseAlpha),
                            QuantumViolet.copy(alpha = 0.15f * pulseAlpha),
                            Color.Transparent
                        ),
                        center = Offset(cx, cy),
                        radius = 110.dp.toPx()
                    )
                )

                // ── B. User Shockwave Ripple Effect on Tap ──
                if (shockwaveAnim.value > 0f) {
                    val swRadius = shockwaveAnim.value * 140.dp.toPx()
                    val swAlpha = (1f - shockwaveAnim.value) * 0.85f
                    drawCircle(
                        color = CyberNeonCyan.copy(alpha = swAlpha),
                        radius = swRadius,
                        style = Stroke(width = 2.dp.toPx())
                    )
                }

                // ── C. Outer Tactical Frame Corner Brackets ──
                val frameHalfW = 105.dp.toPx()
                val frameHalfH = 88.dp.toPx()
                val bracketLen = 14.dp.toPx()
                val bracketColor = CyberNeonCyan.copy(alpha = 0.45f)
                val bracketStroke = 1.2.dp.toPx()

                // Top-Left [
                drawLine(bracketColor, Offset(cx - frameHalfW, cy - frameHalfH), Offset(cx - frameHalfW + bracketLen, cy - frameHalfH), bracketStroke)
                drawLine(bracketColor, Offset(cx - frameHalfW, cy - frameHalfH), Offset(cx - frameHalfW, cy - frameHalfH + bracketLen), bracketStroke)
                // Top-Right ]
                drawLine(bracketColor, Offset(cx + frameHalfW, cy - frameHalfH), Offset(cx + frameHalfW - bracketLen, cy - frameHalfH), bracketStroke)
                drawLine(bracketColor, Offset(cx + frameHalfW, cy - frameHalfH), Offset(cx + frameHalfW, cy - frameHalfH + bracketLen), bracketStroke)
                // Bottom-Left [
                drawLine(bracketColor, Offset(cx - frameHalfW, cy + frameHalfH), Offset(cx - frameHalfW + bracketLen, cy + frameHalfH), bracketStroke)
                drawLine(bracketColor, Offset(cx - frameHalfW, cy + frameHalfH), Offset(cx - frameHalfW, cy + frameHalfH - bracketLen), bracketStroke)
                // Bottom-Right ]
                drawLine(bracketColor, Offset(cx + frameHalfW, cy + frameHalfH), Offset(cx + frameHalfW - bracketLen, cy + frameHalfH), bracketStroke)
                drawLine(bracketColor, Offset(cx + frameHalfW, cy + frameHalfH), Offset(cx + frameHalfW, cy + frameHalfH - bracketLen), bracketStroke)

                // ── D. Multi-Axis 3D Gyroscopic Planetary Rings ──
                val ringRadiusX = 92.dp.toPx()
                val ringRadiusY = 36.dp.toPx()

                // Ring 1 (Inclined -26°)
                rotate(-26f, pivot = Offset(cx, cy)) {
                    drawOval(
                        brush = Brush.sweepGradient(
                            listOf(
                                CyberNeonCyan.copy(alpha = 0.12f),
                                CyberNeonCyan.copy(alpha = 0.85f),
                                ElectricCyan.copy(alpha = 0.25f),
                                CyberNeonCyan.copy(alpha = 0.12f)
                            )
                        ),
                        topLeft = Offset(cx - ringRadiusX, cy - ringRadiusY),
                        size = Size(ringRadiusX * 2, ringRadiusY * 2),
                        style = Stroke(width = 1.2.dp.toPx())
                    )

                    // Orbiting Satellite Node 1
                    val rad1 = Math.toRadians(gyroRotation1.toDouble())
                    val sat1X = cx + (ringRadiusX * cos(rad1)).toFloat()
                    val sat1Y = cy + (ringRadiusY * sin(rad1)).toFloat()
                    drawCircle(CyberNeonCyan, radius = 3.5.dp.toPx(), center = Offset(sat1X, sat1Y))
                    drawCircle(Color.White, radius = 1.8.dp.toPx(), center = Offset(sat1X, sat1Y))
                    drawCircle(CyberNeonCyan.copy(alpha = 0.45f * pulseAlpha), radius = 6.dp.toPx(), center = Offset(sat1X, sat1Y))
                }

                // Ring 2 (Inclined +34°)
                rotate(34f, pivot = Offset(cx, cy)) {
                    drawOval(
                        brush = Brush.sweepGradient(
                            listOf(
                                ElectricCyan.copy(alpha = 0.10f),
                                QuantumViolet.copy(alpha = 0.75f),
                                CyberNeonCyan.copy(alpha = 0.30f),
                                ElectricCyan.copy(alpha = 0.10f)
                            )
                        ),
                        topLeft = Offset(cx - (ringRadiusX * 1.05f), cy - (ringRadiusY * 1.02f)),
                        size = Size(ringRadiusX * 2.1f, ringRadiusY * 2.04f),
                        style = Stroke(width = 1.2.dp.toPx())
                    )

                    // Orbiting Satellite Node 2
                    val rad2 = Math.toRadians(gyroRotation2.toDouble())
                    val sat2X = cx + (ringRadiusX * 1.05f * cos(rad2)).toFloat()
                    val sat2Y = cy + (ringRadiusY * 1.02f * sin(rad2)).toFloat()
                    drawCircle(ElectricCyan, radius = 3.5.dp.toPx(), center = Offset(sat2X, sat2Y))
                    drawCircle(Color.White, radius = 1.8.dp.toPx(), center = Offset(sat2X, sat2Y))
                }

                // Ring 3: Outer Planetary Reticle Halo with Segmented Arc Ticks
                rotate(gyroRotation1 * 0.4f, pivot = Offset(cx, cy)) {
                    drawCircle(
                        color = HolographicGlowBorder.copy(alpha = 0.35f),
                        radius = 82.dp.toPx(),
                        style = Stroke(width = 1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(10f, 14f), 0f))
                    )
                }

                // ── E. Holographic Quantum Shield Lattice ──
                drawQuantumShieldMesh(
                    center = Offset(cx, cy),
                    width = 82.dp.toPx(),
                    height = 98.dp.toPx(),
                    pulseAlpha = pulseAlpha
                )
            }

            // Left & Right Cybernetic Defense HUD Overlays
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Left HUD Tag Block
                Column(horizontalAlignment = Alignment.Start) {
                    Text(
                        text = "DA1502-4098",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 7.5.sp),
                        color = TextTertiary
                    )
                    Text(
                        text = "THREAT.DTI",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 7.sp),
                        color = TextTertiary
                    )
                    Text(
                        text = "DISCRIPTION",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 6.5.sp),
                        color = TextTertiary.copy(alpha = 0.7f)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Surface(
                        color = ElevatedSurface.copy(alpha = 0.85f),
                        border = BorderStroke(0.8.dp, CyberNeonCyan.copy(alpha = 0.5f)),
                        shape = CutCornerShape(4.dp)
                    ) {
                        Text(
                            text = "CYBERNETIC\nDEFENSE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 7.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 0.5.sp
                            ),
                            color = CyberNeonCyan,
                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 3.dp)
                        )
                    }
                }

                // Right HUD Tag Block
                Column(horizontalAlignment = Alignment.End) {
                    Surface(
                        color = ElevatedSurface.copy(alpha = 0.85f),
                        border = BorderStroke(0.8.dp, ElectricCyan.copy(alpha = 0.5f)),
                        shape = CutCornerShape(4.dp)
                    ) {
                        Text(
                            text = "COORDINATION\nPRIME",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 7.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 0.5.sp
                            ),
                            color = ElectricCyan,
                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 3.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "DATA BOOT-CON",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 7.5.sp),
                        color = TextTertiary
                    )
                    Text(
                        text = "10886107TICS",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 7.sp),
                        color = TextTertiary
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 3. TITLE & NEURAL MATRIX STATUS BAR
        // ══════════════════════════════════════════════════════════════════════
        Box(contentAlignment = Alignment.TopEnd) {
            Text(
                text = "CYBERGUARD",
                style = TextStyle(
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Black,
                    fontSize = 28.sp,
                    letterSpacing = 5.5.sp,
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

            // Radiant 4-Point Star Lens Flare Glint on 'D'
            Canvas(
                modifier = Modifier
                    .size(18.dp)
                    .offset(x = 10.dp, y = (-4).dp)
            ) {
                drawStarGlint(
                    center = Offset(size.width / 2, size.height / 2),
                    radius = 8.dp.toPx() * flareScale,
                    color = LensFlareWhite
                )
            }
        }

        Spacer(modifier = Modifier.height(3.dp))

        Text(
            text = "━━━ THREAT DETECTION & DEFENSE SYSTEM ━━━",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 9.sp,
                letterSpacing = 1.4.sp,
                fontWeight = FontWeight.SemiBold
            ),
            color = TextSecondary
        )

        Spacer(modifier = Modifier.height(10.dp))

        // Cybernetic Quantum Neural Matrix Pill with Amber Indicator
        Surface(
            shape = CutCornerShape(6.dp),
            color = HighlightSurface.copy(alpha = 0.9f),
            border = BorderStroke(1.dp, CyberNeonCyan.copy(alpha = 0.55f))
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Amber pulsating status beacon
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .clip(RoundedCornerShape(3.5.dp))
                        .background(CyberAmber)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "QUANTUM NEURAL MATRIX",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.5.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.2.sp
                    ),
                    color = ElectricCyan
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        // 48-Segment Animated Digital Equalizer / Neural Stream Bar
        Canvas(
            modifier = Modifier
                .fillMaxWidth(0.85f)
                .height(10.dp)
        ) {
            val totalBars = 48
            val barW = 2.dp.toPx()
            val totalSpacing = size.width - (totalBars * barW)
            val gap = totalSpacing / (totalBars - 1)

            for (i in 0 until totalBars) {
                val waveVal = sin(visualizerPhase + (i * 0.28f))
                val barH = (3.dp.toPx() + (waveVal * 2.5.dp.toPx()).absoluteValue).coerceAtLeast(1.5.dp.toPx())
                val x = i * (barW + gap)
                val y = (size.height - barH) / 2f
                val color = if (i % 7 == 0) CyberAmber else CyberNeonCyan.copy(alpha = 0.45f + (waveVal * 0.35f).absoluteValue)
                drawRect(
                    color = color,
                    topLeft = Offset(x, y),
                    size = Size(barW, barH)
                )
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 4. 3D PERSPECTIVE HOLOGRAPHIC CYBER RADAR GRID (CENTERPIECE TACTICAL SONAR)
        // ══════════════════════════════════════════════════════════════════════
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(156.dp)
                .pointerInput(Unit) {
                    detectTapGestures { offset ->
                        selectedThreatDetail = "INTERCEPT TARGET LOCKED"
                    }
                },
            contentAlignment = Alignment.Center
        ) {
            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(156.dp)
            ) {
                drawHolographic3DRadar(
                    cx = size.width / 2f,
                    cy = size.height / 2f,
                    radiusX = 148.dp.toPx(),
                    radiusY = 56.dp.toPx(),
                    sweepAngle = radarSweepAngle,
                    targetLockExpansion = targetLockExpansion
                )
            }

            // Top-Right Tactical HUD Overlay for Threat Targets
            Box(
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(end = 4.dp, top = 2.dp)
            ) {
                Column(horizontalAlignment = Alignment.End) {
                    Text(
                        text = "THREAT TARGETS",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 8.5.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.8.sp
                        ),
                        color = TextSecondary
                    )
                    Text(
                        text = "NODE-METRICS",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 6.5.sp),
                        color = TextTertiary
                    )
                    Text(
                        text = "MSH-LOAD: MONITORED",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 6.5.sp),
                        color = TextTertiary
                    )
                    Text(
                        text = "DATA-METRIC: TARGETED",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 6.5.sp),
                        color = TextTertiary
                    )
                }
            }

            // Interactive Target Telemetry Readout popup on Tap
            if (selectedThreatDetail != null) {
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = 2.dp)
                ) {
                    Surface(
                        color = ElevatedSurface.copy(alpha = 0.95f),
                        border = BorderStroke(1.dp, HighAlertOrange),
                        shape = CutCornerShape(4.dp)
                    ) {
                        Text(
                            text = selectedThreatDetail!!,
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 8.5.sp,
                                fontWeight = FontWeight.Bold
                            ),
                            color = HighAlertOrange,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 5. CONNECTION DIAGNOSTICS & RETRY CARDS (PRESERVED FUNCTIONALITY)
        // ══════════════════════════════════════════════════════════════════════
        when (state) {
            ConnectionState.ERROR, ConnectionState.DISCONNECTED, ConnectionState.NETWORK_UNAVAILABLE,
            ConnectionState.DISCOVERY_TIMEOUT, ConnectionState.BACKEND_UNREACHABLE, ConnectionState.BACKEND_UNHEALTHY -> {
                CyberGuardCard(
                    modifier = Modifier.fillMaxWidth(),
                    borderColor = if (state == ConnectionState.BACKEND_UNHEALTHY) StatusCritical else HolographicGlowBorder,
                    containerColor = ElevatedSurface
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(34.dp)
                                .clip(RoundedCornerShape(6.dp))
                                .background(StatusWarning.copy(alpha = 0.15f))
                                .border(1.dp, StatusWarning.copy(alpha = 0.5f), RoundedCornerShape(6.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Warning,
                                contentDescription = null,
                                tint = StatusWarning,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            val failureTitle = when {
                                state == ConnectionState.NETWORK_UNAVAILABLE -> "LOCAL INTERFACE OFFLINE"
                                state == ConnectionState.DISCOVERY_TIMEOUT -> "BROADCAST BEACON TIMEOUT"
                                state == ConnectionState.AUTH_REQUIRED -> "AUTHENTICATION REQUIRED"
                                state == ConnectionState.BACKEND_UNHEALTHY -> "NODE HEALTH CHECK FAILED"
                                !discoveryStatusText.isNullOrBlank() && discoveryStatusText != "ALL CONFIGURED NODES UNREACHABLE" -> discoveryStatusText
                                else -> "TARGET BACKEND UNREACHABLE"
                            }
                            Text(
                                text = failureTitle,
                                style = MaterialTheme.typography.titleMedium.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = StatusWarning
                            )
                            val failureSubtitle = when {
                                !failoverNotice.isNullOrBlank() -> failoverNotice!!
                                state == ConnectionState.NETWORK_UNAVAILABLE -> "Activate Wi-Fi or Ethernet to enable peer discovery."
                                state == ConnectionState.AUTH_REQUIRED -> "Node reachable but requires operator login credentials."
                                state == ConnectionState.BACKEND_UNHEALTHY -> "Node responded with non-200 status code."
                                else -> "Ensure server is running on PC or configure active tunnel."
                            }
                            Text(
                                text = failureSubtitle,
                                style = MaterialTheme.typography.bodyMedium.copy(fontSize = 10.5.sp),
                                color = TextSecondary,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                    }

                    // 1. Priority Candidate: Auto-Detected Local Host Candidate
                    val localCandidateIp = if (connectionConfig.localHost.isNotBlank()) {
                        connectionConfig.localHost
                    } else {
                        val rawHost = detectedGateway ?: if (ConnectionManager.isEmulatorEnvironment()) "10.0.2.2" else ConnectionManager.DEFAULT_LOCAL_HOST
                        rawHost.removePrefix("http://").removePrefix("https://").substringBefore(":").substringBefore("/").trim()
                    }
                    val localPort = connectionConfig.localPort
                    Spacer(modifier = Modifier.height(10.dp))
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        color = HighlightSurface,
                        border = BorderStroke(1.dp, CyberNeonCyan.copy(alpha = 0.6f))
                    ) {
                        Row(
                            modifier = Modifier.padding(10.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "CONFIGURED LOCAL CANDIDATE",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 8.5.sp),
                                    color = CyberNeonCyan
                                )
                                Text(
                                    text = "$localCandidateIp:$localPort",
                                    style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 12.5.sp),
                                    color = TextPrimary
                                )
                            }
                            Button(
                                onClick = { viewModel.connectManually(localCandidateIp, localPort.toString()) },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberNeonCyan, contentColor = DeepSpaceBackground),
                                shape = RoundedCornerShape(6.dp),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                            ) {
                                Text("CONNECT", style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold))
                            }
                        }
                    }

                    // 2. Secondary Candidate: Deployed Cloud Defense Node
                    val candidateCloudUrl = if (connectionConfig.cloudUrl.isNotBlank()) connectionConfig.cloudUrl else ConnectionManager.DEFAULT_CLOUD_BACKEND_URL
                    val displayCloudText = candidateCloudUrl.removePrefix("https://").removePrefix("http://").trimEnd('/')
                    val formattedDisplay = if (displayCloudText.length > 35) displayCloudText.take(15) + "..." + displayCloudText.takeLast(17) else displayCloudText
                    Spacer(modifier = Modifier.height(8.dp))
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        color = HighlightSurface,
                        border = BorderStroke(1.dp, CyberBlue.copy(alpha = 0.6f))
                    ) {
                        Row(
                            modifier = Modifier.padding(10.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "VERIFIED CLOUD BACKEND (TUNNEL / API)",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 8.5.sp),
                                    color = CyberBlue
                                )
                                Text(
                                    text = formattedDisplay,
                                    style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 11.sp),
                                    color = TextPrimary
                                )
                            }
                            Button(
                                onClick = { viewModel.connectToDeployedBackend(candidateCloudUrl) },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberBlue, contentColor = DeepSpaceBackground),
                                shape = RoundedCornerShape(6.dp),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                            ) {
                                Text("CONNECT", style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold))
                            }
                        }
                    }

                    // 3. Smart Connection Settings Modal Trigger Button
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = { viewModel.openConnectionSettings() },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = HighlightSurface, contentColor = CyberNeonCyan),
                        shape = RoundedCornerShape(6.dp),
                        border = BorderStroke(1.dp, CyberNeonCyan.copy(alpha = 0.7f)),
                        contentPadding = PaddingValues(vertical = 8.dp)
                    ) {
                        Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "CONFIGURE ENDPOINT & HYBRID MODES",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.sp,
                                letterSpacing = 0.6.sp
                            )
                        )
                    }

                    // 4. Autonomous System Auto-Detect & Re-Sync Trigger
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = { viewModel.retryDiscovery() },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = CyberNeonCyan, contentColor = DeepSpaceBackground),
                        shape = RoundedCornerShape(6.dp),
                        contentPadding = PaddingValues(vertical = 10.dp)
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "AUTO-CONNECT / RE-SYNC DEFENSE NODE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.5.sp,
                                letterSpacing = 0.8.sp
                            )
                        )
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }
            else -> {}
        }

        // ══════════════════════════════════════════════════════════════════════
        // 6. BOTTOM SYSTEM TELEMETRY & HIGH-ALERT INTRUSION BANNER
        // ══════════════════════════════════════════════════════════════════════
        val nodeIpDisplay = detectedGateway ?: "192.168.29.141"
        val dynamicProbeText = if (!discoveryStatusText.isNullOrBlank()) {
            discoveryStatusText.uppercase()
        } else {
            "PROBING LAST KNOWN NODE: $nodeIpDisplay:3000..."
        }
        Text(
            text = dynamicProbeText,
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 1.sp
            ),
            color = CyberNeonCyan
        )

        Spacer(modifier = Modifier.height(3.dp))

        Text(
            text = "PROTOCOL: ZERO-TRUST",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 8.5.sp,
                letterSpacing = 0.8.sp
            ),
            color = TextTertiary
        )

        Spacer(modifier = Modifier.height(10.dp))

        // High-Alert Glowing Intrusion Prevention Banner
        Surface(
            shape = CutCornerShape(5.dp),
            color = Color(0xFF1E0E00).copy(alpha = 0.85f),
            border = BorderStroke(1.2.dp, HighAlertOrange.copy(alpha = 0.85f))
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .clip(RoundedCornerShape(3.dp))
                        .background(HighAlertOrange)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "THREAT INTRUSION PREVENTION ACTIVE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.1.sp
                    ),
                    color = HighAlertOrange
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Bottom HUD Reticle Footer
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            Text(
                text = "└  QUANTUM DEFENSE GRID  ┘",
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 9.sp,
                    letterSpacing = 0.8.sp
                ),
                color = TextTertiary
            )
        }

        Spacer(modifier = Modifier.height(12.dp))
    }

    val showConnectionSettings by viewModel.showConnectionSettings.collectAsState()
    if (showConnectionSettings) {
        ConnectionSettingsModal(
            viewModel = viewModel,
            onDismiss = { viewModel.closeConnectionSettings() }
        )
    }
}

/**
 * Renders the multi-faceted 3D Quantum Wireframe Shield with Bezier Lattice Lines.
 */
private fun DrawScope.drawQuantumShieldMesh(
    center: Offset,
    width: Float,
    height: Float,
    pulseAlpha: Float
) {
    val cx = center.x
    val cy = center.y
    val halfW = width / 2f
    val halfH = height / 2f

    // 1. Outer Faceted Shield Path
    val outerShield = Path().apply {
        moveTo(cx - halfW, cy - halfH * 0.75f)
        // Top dip
        quadraticBezierTo(cx, cy - halfH * 0.55f, cx + halfW, cy - halfH * 0.75f)
        // Right shoulder to hip
        quadraticBezierTo(cx + halfW * 1.08f, cy, cx + halfW * 0.82f, cy + halfH * 0.45f)
        // Right hip to bottom apex
        quadraticBezierTo(cx + halfW * 0.55f, cy + halfH * 0.85f, cx, cy + halfH)
        // Bottom apex to left hip
        quadraticBezierTo(cx - halfW * 0.55f, cy + halfH * 0.85f, cx - halfW * 0.82f, cy + halfH * 0.45f)
        // Left hip to shoulder
        quadraticBezierTo(cx - halfW * 1.08f, cy, cx - halfW, cy - halfH * 0.75f)
        close()
    }

    // Outer Glowing Contour
    drawPath(
        path = outerShield,
        brush = Brush.verticalGradient(
            colors = listOf(
                Color(0xFF00F0FF),
                Color(0xFF38BDF8),
                Color(0xFFA855F7),
                Color(0xFF00F0FF)
            )
        ),
        style = Stroke(width = 2.2.dp.toPx())
    )

    // Inset Inner Contour Line
    val innerShield = Path().apply {
        val s = 0.88f
        moveTo(cx - halfW * s, cy - halfH * 0.70f)
        quadraticBezierTo(cx, cy - halfH * 0.50f, cx + halfW * s, cy - halfH * 0.70f)
        quadraticBezierTo(cx + halfW * 0.95f, cy, cx + halfW * 0.72f, cy + halfH * 0.40f)
        quadraticBezierTo(cx + halfW * 0.48f, cy + halfH * 0.76f, cx, cy + halfH * 0.90f)
        quadraticBezierTo(cx - halfW * 0.48f, cy + halfH * 0.76f, cx - halfW * 0.72f, cy + halfH * 0.40f)
        quadraticBezierTo(cx - halfW * 0.95f, cy, cx - halfW * s, cy - halfH * 0.70f)
        close()
    }
    drawPath(
        path = innerShield,
        color = CyberNeonCyan.copy(alpha = 0.35f),
        style = Stroke(width = 1.dp.toPx())
    )

    // 2. Parametric Curving Wireframe Lattice Mesh (Diamond Cross-Hatch Web)
    val meshColor = CyberNeonCyan.copy(alpha = 0.55f * pulseAlpha)
    val meshStroke = 1.1.dp.toPx()

    // Left-to-Right Curving Arcs
    for (i in 1..4) {
        val frac = i / 5f
        val p = Path().apply {
            moveTo(cx - halfW * (1f - frac * 0.4f), cy - halfH * 0.7f + (i * 12.dp.toPx()))
            quadraticBezierTo(
                cx + (frac * 20.dp.toPx()),
                cy - (10.dp.toPx()) + (i * 8.dp.toPx()),
                cx + halfW * (0.8f - frac * 0.3f),
                cy + halfH * (0.1f + frac * 0.7f)
            )
        }
        drawPath(path = p, color = meshColor, style = Stroke(width = meshStroke))
    }

    // Right-to-Left Symmetrical Curving Arcs
    for (i in 1..4) {
        val frac = i / 5f
        val p = Path().apply {
            moveTo(cx + halfW * (1f - frac * 0.4f), cy - halfH * 0.7f + (i * 12.dp.toPx()))
            quadraticBezierTo(
                cx - (frac * 20.dp.toPx()),
                cy - (10.dp.toPx()) + (i * 8.dp.toPx()),
                cx - halfW * (0.8f - frac * 0.3f),
                cy + halfH * (0.1f + frac * 0.7f)
            )
        }
        drawPath(path = p, color = meshColor, style = Stroke(width = meshStroke))
    }

    // 3. Central Ridge Laser Spine with Electric White Core Highlight
    drawLine(
        brush = Brush.verticalGradient(
            colors = listOf(
                Color.Transparent,
                Color.White,
                CyberNeonCyan,
                Color.Transparent
            )
        ),
        start = Offset(cx, cy - halfH * 0.55f),
        end = Offset(cx, cy + halfH * 0.95f),
        strokeWidth = 2.dp.toPx()
    )

    // 4. Central Core Quantum Diamond Vertex
    val diamondPath = Path().apply {
        val dSize = 9.dp.toPx()
        moveTo(cx, cy - dSize)
        lineTo(cx + dSize, cy)
        lineTo(cx, cy + dSize)
        lineTo(cx - dSize, cy)
        close()
    }
    drawPath(
        path = diamondPath,
        brush = Brush.radialGradient(
            listOf(Color.White, CyberNeonCyan, Color.Transparent),
            center = Offset(cx, cy),
            radius = 12.dp.toPx()
        )
    )
}

/**
 * Renders the 3D Perspective Holographic Cyber Radar with Sweeping Beam and Plotted Threat Targets.
 */
private fun DrawScope.drawHolographic3DRadar(
    cx: Float,
    cy: Float,
    radiusX: Float,
    radiusY: Float,
    sweepAngle: Float,
    targetLockExpansion: Float
) {
    // ── 1. Concentric Perspective Ellipses ──
    val ringLevels = listOf(1.0f, 0.78f, 0.54f, 0.28f, 0.12f)
    ringLevels.forEachIndexed { idx, frac ->
        val rx = radiusX * frac
        val ry = radiusY * frac
        val strokeW = if (idx == 0) 1.5.dp.toPx() else 0.9.dp.toPx()
        val color = when (idx) {
            0 -> CyberNeonCyan.copy(alpha = 0.75f)
            1 -> RadarGridCyan.copy(alpha = 0.55f)
            2 -> ElectricCyan.copy(alpha = 0.40f)
            else -> TextTertiary.copy(alpha = 0.30f)
        }
        val pathEffect = if (idx == 0) PathEffect.dashPathEffect(floatArrayOf(8f, 6f), 0f) else null

        drawOval(
            color = color,
            topLeft = Offset(cx - rx, cy - ry),
            size = Size(rx * 2, ry * 2),
            style = Stroke(width = strokeW, pathEffect = pathEffect)
        )
    }

    // ── 2. Radiating Polar Perspective Grid Lines (12 Radial Spines) ──
    val numSpines = 12
    for (i in 0 until numSpines) {
        val angleDeg = i * (360f / numSpines)
        val rad = Math.toRadians(angleDeg.toDouble())
        val endX = cx + (radiusX * cos(rad)).toFloat()
        val endY = cy + (radiusY * sin(rad)).toFloat()

        drawLine(
            color = RadarGridCyan.copy(alpha = 0.25f),
            start = Offset(cx, cy),
            end = Offset(endX, endY),
            strokeWidth = 0.8.dp.toPx()
        )

        // Micro ticks extending outside perimeter
        val tickX = cx + ((radiusX + 5.dp.toPx()) * cos(rad)).toFloat()
        val tickY = cy + ((radiusY + 4.dp.toPx()) * sin(rad)).toFloat()
        drawLine(
            color = CyberNeonCyan.copy(alpha = 0.6f),
            start = Offset(endX, endY),
            end = Offset(tickX, tickY),
            strokeWidth = 1.2.dp.toPx()
        )
    }

    // ── 3. Rotating 3D Conical Sweeping Radar Beam ──
    val sweepRad2 = Math.toRadians((sweepAngle + 50f).toDouble())

    val sweepPath = Path().apply {
        moveTo(cx, cy)
        // Sample points along the elliptical arc for realistic 3D perspective projection
        val steps = 14
        for (step in 0..steps) {
            val stepAngle = Math.toRadians((sweepAngle + (50f * (step / steps.toFloat()))).toDouble())
            val x = cx + (radiusX * cos(stepAngle)).toFloat()
            val y = cy + (radiusY * sin(stepAngle)).toFloat()
            lineTo(x, y)
        }
        close()
    }

    // Translucent Glowing Radar Sweep Cone
    drawPath(
        path = sweepPath,
        brush = Brush.radialGradient(
            colors = listOf(
                CyberNeonCyan.copy(alpha = 0.38f),
                ElectricCyan.copy(alpha = 0.16f),
                Color.Transparent
            ),
            center = Offset(cx, cy),
            radius = radiusX
        )
    )

    // Bright Laser Leading Edge
    val leadX = cx + (radiusX * cos(sweepRad2)).toFloat()
    val leadY = cy + (radiusY * sin(sweepRad2)).toFloat()
    drawLine(
        brush = Brush.horizontalGradient(listOf(CyberNeonCyan.copy(alpha = 0.3f), Color.White)),
        start = Offset(cx, cy),
        end = Offset(leadX, leadY),
        strokeWidth = 1.6.dp.toPx()
    )

    // ── 4. Plotted 3D Threat Target Blips ──

    // TARGET 1: RED CRITICAL BREACH (Top-Left)
    val redX = cx - radiusX * 0.64f
    val redY = cy - radiusY * 0.48f
    // Expanding lock-on ring
    drawCircle(
        color = StatusCritical.copy(alpha = (1f - targetLockExpansion) * 0.85f),
        radius = 5.dp.toPx() + (targetLockExpansion * 12.dp.toPx()),
        center = Offset(redX, redY),
        style = Stroke(width = 1.2.dp.toPx())
    )
    drawCircle(StatusCritical, radius = 4.dp.toPx(), center = Offset(redX, redY))
    drawCircle(Color.White, radius = 1.8.dp.toPx(), center = Offset(redX, redY))
    // HUD Leader Line
    drawLine(
        color = StatusCritical.copy(alpha = 0.7f),
        start = Offset(redX, redY),
        end = Offset(redX - 16.dp.toPx(), redY - 14.dp.toPx()),
        strokeWidth = 0.9.dp.toPx()
    )
    drawLine(
        color = StatusCritical.copy(alpha = 0.7f),
        start = Offset(redX - 16.dp.toPx(), redY - 14.dp.toPx()),
        end = Offset(redX - 32.dp.toPx(), redY - 14.dp.toPx()),
        strokeWidth = 0.9.dp.toPx()
    )

    // TARGET 2: SOLAR AMBER PROBE (Top-Right)
    val ambX = cx + radiusX * 0.68f
    val ambY = cy - radiusY * 0.28f
    drawCircle(StatusWarning.copy(alpha = 0.4f), radius = 6.dp.toPx(), center = Offset(ambX, ambY))
    drawCircle(StatusWarning, radius = 3.5.dp.toPx(), center = Offset(ambX, ambY))
    drawCircle(Color.White, radius = 1.5.dp.toPx(), center = Offset(ambX, ambY))

    // TARGET 3: ELECTRIC CYAN NODE (Far-Right)
    val cyanX = cx + radiusX * 0.82f
    val cyanY = cy + radiusY * 0.32f
    drawCircle(CyberNeonCyan.copy(alpha = 0.4f), radius = 6.dp.toPx(), center = Offset(cyanX, cyanY))
    drawCircle(CyberNeonCyan, radius = 3.5.dp.toPx(), center = Offset(cyanX, cyanY))

    // TARGET 4: SECONDARY AMBER ANOMALY (Bottom-Left)
    val amb2X = cx - radiusX * 0.72f
    val amb2Y = cy + radiusY * 0.42f
    drawCircle(CyberAmber.copy(alpha = 0.35f), radius = 5.dp.toPx(), center = Offset(amb2X, amb2Y))
    drawCircle(CyberAmber, radius = 3.dp.toPx(), center = Offset(amb2X, amb2Y))

    // TARGET 5: ORANGE DATA METRIC BLIP (Bottom-Center)
    val orgX = cx + radiusX * 0.18f
    val orgY = cy + radiusY * 0.62f
    drawCircle(HighAlertOrange.copy(alpha = 0.35f), radius = 5.dp.toPx(), center = Offset(orgX, orgY))
    drawCircle(HighAlertOrange, radius = 3.dp.toPx(), center = Offset(orgX, orgY))

    // ── 5. Center Bullseye Core ──
    drawCircle(DeepSpaceBackground, radius = 5.dp.toPx(), center = Offset(cx, cy))
    drawCircle(CyberNeonCyan, radius = 2.dp.toPx(), center = Offset(cx, cy))
}
