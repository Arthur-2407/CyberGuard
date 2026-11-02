package com.cyberguard.client.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.cyberguard.client.R
import com.cyberguard.client.network.ConnectionManager
import com.cyberguard.client.network.ConnectionState
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.Screen
import com.cyberguard.client.ui.components.ConnectionSettingsModal
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SplashScreen(navController: NavController, viewModel: MainViewModel) {
    val state by viewModel.connectionState.collectAsState()
    val discoveryStatusText by viewModel.discoveryStatus.collectAsState()
    val detectedGateway = viewModel.detectedGatewayIp
    val connectionConfig by viewModel.connectionConfig.collectAsState()
    val failoverNotice by viewModel.failoverNotice.collectAsState()

    // Real-Time System Clock formatted for cyber terminal
    var currentTimeMillis by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            currentTimeMillis = System.currentTimeMillis()
            delay(50) // 20 FPS digital micro-tick
        }
    }

    val timeFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }
    val dateFormat = remember { SimpleDateFormat("yyyy.MM.dd", Locale.US) }
    val millisPart = (currentTimeMillis % 1000).toString().padStart(3, '0')
    val timeString = "${timeFormat.format(Date(currentTimeMillis))}.$millisPart"
    val dateString = dateFormat.format(Date(currentTimeMillis))

    // One-shot subtle boot-up glitch transition (decays in 400ms without continuous overhead)
    val glitchTransition = remember { Animatable(1f) }
    LaunchedEffect(Unit) {
        glitchTransition.animateTo(
            targetValue = 0f,
            animationSpec = tween(450, easing = FastOutSlowInEasing)
        )
    }
    val glitchOffset = glitchTransition.value

    LaunchedEffect(state) {
        if (state == ConnectionState.CONNECTED) {
            navController.navigate(Screen.Dashboard.route) {
                popUpTo(Screen.Splash.route) { inclusive = true }
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpaceBackground)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        Spacer(modifier = Modifier.height(4.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 1. TOP TACTICAL HUD TELEMETRY HEADER
        // ══════════════════════════════════════════════════════════════════════
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            Column(horizontalAlignment = Alignment.Start) {
                Text(
                    text = "┌  [SYS.ID: CG-ENDPOINT-X]",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 1.sp
                    ),
                    color = TextTertiary
                )
                Spacer(modifier = Modifier.height(3.dp))
                Row(
                    modifier = Modifier.padding(start = 14.dp),
                    horizontalArrangement = Arrangement.spacedBy(2.5.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val tickHeights = listOf(6, 11, 9, 4, 10, 7, 11, 5, 8, 12, 6, 9)
                    tickHeights.forEachIndexed { idx, h ->
                        Box(
                            modifier = Modifier
                                .width(1.5.dp)
                                .height(h.dp)
                                .background(if (idx % 2 == 0) PrimaryRed.copy(alpha = 0.8f) else SignalYellow.copy(alpha = 0.6f))
                        )
                    }
                }
            }

            Column(horizontalAlignment = Alignment.End) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "[SEC.LVL: ROOT",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.5.sp,
                            letterSpacing = 1.sp
                        ),
                        color = SignalYellow
                    )
                    Text(
                        text = "  ┐",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.5.sp
                        ),
                        color = SignalYellow
                    )
                }

                Text(
                    text = "ACTIVE DEFENSE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Black,
                        fontSize = 10.5.sp,
                        letterSpacing = 0.8.sp
                    ),
                    color = PrimaryRed,
                    modifier = Modifier.padding(top = 1.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 2. UPDATED CYBERGUARD LOGO & BRANDING HEADER (OBJECTIVE B)
        // ══════════════════════════════════════════════════════════════════════
        Box(
            modifier = Modifier
                .size(68.dp)
                .clip(RoundedCornerShape(14.dp))
                .background(ElevatedSurface)
                .border(1.2.dp, PrimaryRed.copy(alpha = 0.6f), RoundedCornerShape(14.dp)),
            contentAlignment = Alignment.Center
        ) {
            Image(
                painter = painterResource(id = R.drawable.ic_cyberguard_emblem),
                contentDescription = "CyberGuard Logo",
                modifier = Modifier
                    .size(54.dp)
                    .clip(RoundedCornerShape(10.dp)),
                contentScale = ContentScale.Fit
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = "CYBERGUARD",
            style = TextStyle(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Black,
                fontSize = 26.sp,
                letterSpacing = 4.sp,
                color = PureWhite
            )
        )

        Spacer(modifier = Modifier.height(2.dp))

        Text(
            text = "━━━ ENDPOINT SECURITY & THREAT DEFENSE ━━━",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 8.5.sp,
                letterSpacing = 1.2.sp,
                fontWeight = FontWeight.SemiBold
            ),
            color = SignalYellow
        )

        Spacer(modifier = Modifier.height(14.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 3. GLITCH-INSPIRED DIGITAL TIME VISUAL (OBJECTIVE D)
        // ══════════════════════════════════════════════════════════════════════
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .clip(CutCornerShape(8.dp)),
            color = ElevatedSurface,
            border = BorderStroke(1.dp, PrimaryRed.copy(alpha = 0.45f))
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 16.dp, horizontal = 14.dp)
            ) {
                // Background scanline texture
                Canvas(modifier = Modifier.matchParentSize()) {
                    val step = 4.dp.toPx()
                    var y = 0f
                    while (y <= size.height) {
                        drawLine(
                            color = Color(0x0CFFFFFF),
                            start = Offset(0f, y),
                            end = Offset(size.width, y),
                            strokeWidth = 1f
                        )
                        y += step
                    }
                }

                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    // Header metadata row
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(RoundedCornerShape(3.dp))
                                    .background(SignalYellow)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "TEMPORAL NODE",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    letterSpacing = 0.8.sp
                                ),
                                color = SignalYellow
                            )
                        }

                        Text(
                            text = "[UTC TIME-LOCK]",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 8.5.sp,
                                letterSpacing = 0.8.sp
                            ),
                            color = TextTertiary
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Prominent Digital Time Display with Chromatic Glitch Accents
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier.padding(vertical = 4.dp)
                    ) {
                        // Red Chromatic Glitch Layer (Offset Left)
                        if (glitchOffset > 0.05f) {
                            Text(
                                text = timeString,
                                style = TextStyle(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Black,
                                    fontSize = 28.sp,
                                    letterSpacing = 2.sp,
                                    color = PrimaryRed.copy(alpha = 0.7f * glitchOffset)
                                ),
                                modifier = Modifier.offset(x = (-3 * glitchOffset).dp, y = (1 * glitchOffset).dp)
                            )
                            // Yellow Chromatic Glitch Layer (Offset Right)
                            Text(
                                text = timeString,
                                style = TextStyle(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Black,
                                    fontSize = 28.sp,
                                    letterSpacing = 2.sp,
                                    color = SignalYellow.copy(alpha = 0.6f * glitchOffset)
                                ),
                                modifier = Modifier.offset(x = (3 * glitchOffset).dp, y = (-1 * glitchOffset).dp)
                            )
                        }

                        // Sharp Crisp Pure White Primary Digits
                        Text(
                            text = timeString,
                            style = TextStyle(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Black,
                                fontSize = 28.sp,
                                letterSpacing = 2.sp,
                                color = PureWhite
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(4.dp))

                    // Date & Terminal Status
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "$dateString • ACTIVE ZERO-TRUST EPOCH",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Medium,
                                letterSpacing = 1.sp
                            ),
                            color = TextSecondary
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Horizontal Micro-Glitch Accent Bar
                    Row(
                        modifier = Modifier.fillMaxWidth(0.9f),
                        horizontalArrangement = Arrangement.spacedBy(3.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(modifier = Modifier.weight(2f).height(2.dp).background(PrimaryRed))
                        Box(modifier = Modifier.weight(1f).height(2.dp).background(SignalYellow))
                        Box(modifier = Modifier.weight(3f).height(2.dp).background(PureWhite.copy(alpha = 0.6f)))
                        Box(modifier = Modifier.weight(1f).height(2.dp).background(SignalYellow))
                        Box(modifier = Modifier.weight(2f).height(2.dp).background(PrimaryRed))
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // ══════════════════════════════════════════════════════════════════════
        // 4. CONNECTION HEALTH STATUS & CANDIDATE CARDS (OBJECTIVE A & E)
        // ══════════════════════════════════════════════════════════════════════
        CyberGuardCard(
            modifier = Modifier.fillMaxWidth(),
            borderColor = when (state) {
                ConnectionState.CONNECTED, ConnectionState.CONNECTED_LOCAL, ConnectionState.CONNECTED_CLOUD, ConnectionState.CONNECTED_HYBRID -> StatusOnline
                ConnectionState.VALIDATING, ConnectionState.DISCOVERING -> SignalYellow
                else -> PrimaryRed
            },
            containerColor = ElevatedSurface
        ) {
            // Status Header Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(
                            when (state) {
                                ConnectionState.CONNECTED, ConnectionState.CONNECTED_LOCAL, ConnectionState.CONNECTED_CLOUD, ConnectionState.CONNECTED_HYBRID -> StatusOnline.copy(alpha = 0.15f)
                                ConnectionState.VALIDATING, ConnectionState.DISCOVERING -> SignalYellow.copy(alpha = 0.15f)
                                else -> PrimaryRed.copy(alpha = 0.15f)
                            }
                        )
                        .border(
                            1.dp,
                            when (state) {
                                ConnectionState.CONNECTED, ConnectionState.CONNECTED_LOCAL, ConnectionState.CONNECTED_CLOUD, ConnectionState.CONNECTED_HYBRID -> StatusOnline.copy(alpha = 0.6f)
                                ConnectionState.VALIDATING, ConnectionState.DISCOVERING -> SignalYellow.copy(alpha = 0.6f)
                                else -> PrimaryRed.copy(alpha = 0.6f)
                            },
                            RoundedCornerShape(8.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = when (state) {
                            ConnectionState.CONNECTED, ConnectionState.CONNECTED_LOCAL, ConnectionState.CONNECTED_CLOUD, ConnectionState.CONNECTED_HYBRID -> Icons.Default.CheckCircle
                            ConnectionState.VALIDATING, ConnectionState.DISCOVERING -> Icons.Default.Sync
                            else -> Icons.Default.Warning
                        },
                        contentDescription = null,
                        tint = when (state) {
                            ConnectionState.CONNECTED, ConnectionState.CONNECTED_LOCAL, ConnectionState.CONNECTED_CLOUD, ConnectionState.CONNECTED_HYBRID -> StatusOnline
                            ConnectionState.VALIDATING, ConnectionState.DISCOVERING -> SignalYellow
                            else -> PrimaryRed
                        },
                        modifier = Modifier.size(20.dp)
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    val statusTitle = when {
                        !discoveryStatusText.isNullOrBlank() && discoveryStatusText != "ALL CONFIGURED NODES UNREACHABLE" -> discoveryStatusText
                        state == ConnectionState.CONNECTED || state == ConnectionState.CONNECTED_LOCAL ||
                        state == ConnectionState.CONNECTED_CLOUD || state == ConnectionState.CONNECTED_HYBRID -> "DEFENSE NODE SYNCHRONIZED"
                        state == ConnectionState.VALIDATING -> "VALIDATING BACKEND PROTOCOL..."
                        state == ConnectionState.DISCOVERING -> "PROBING ACTIVE NODES..."
                        state == ConnectionState.NETWORK_UNAVAILABLE -> "LOCAL INTERFACE OFFLINE"
                        state == ConnectionState.AUTH_REQUIRED -> "AUTHENTICATION REQUIRED"
                        state == ConnectionState.BACKEND_UNHEALTHY -> "NODE HEALTH CHECK FAILED"
                        else -> "CONNECTION TIMED OUT"
                    }
                    Text(
                        text = statusTitle,
                        style = MaterialTheme.typography.titleMedium.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold
                        ),
                        color = when (state) {
                            ConnectionState.CONNECTED, ConnectionState.CONNECTED_LOCAL, ConnectionState.CONNECTED_CLOUD, ConnectionState.CONNECTED_HYBRID -> StatusOnline
                            ConnectionState.VALIDATING, ConnectionState.DISCOVERING -> SignalYellow
                            else -> PrimaryRed
                        }
                    )

                    val statusSubtitle = when {
                        !failoverNotice.isNullOrBlank() -> failoverNotice!!
                        state == ConnectionState.CONNECTED -> "Zero-trust session established with security node."
                        state == ConnectionState.VALIDATING -> "Executing verified health check handshake..."
                        state == ConnectionState.NETWORK_UNAVAILABLE -> "Activate Wi-Fi or cellular connectivity."
                        state == ConnectionState.AUTH_REQUIRED -> "Node reachable. Operator credentials required."
                        else -> "Verify local service is running or check cloud connection."
                    }
                    Text(
                        text = statusSubtitle,
                        style = MaterialTheme.typography.bodyMedium.copy(fontSize = 10.5.sp),
                        color = TextSecondary,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // 1. Local Workstation Candidate Card
            val localCandidateIp = if (connectionConfig.localHost.isNotBlank()) {
                connectionConfig.localHost
            } else {
                val rawHost = detectedGateway ?: if (ConnectionManager.isEmulatorEnvironment()) "10.0.2.2" else ConnectionManager.DEFAULT_LOCAL_HOST
                rawHost.removePrefix("http://").removePrefix("https://").substringBefore(":").substringBefore("/").trim()
            }
            val localPort = connectionConfig.localPort

            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp),
                color = HighlightSurface,
                border = BorderStroke(1.dp, PrimaryRed.copy(alpha = 0.5f))
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
                            color = PrimaryRed
                        )
                        Text(
                            text = "$localCandidateIp:$localPort",
                            style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 12.sp),
                            color = PureWhite
                        )
                    }
                    Button(
                        onClick = { viewModel.connectManually(localCandidateIp, localPort.toString()) },
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed, contentColor = PureWhite),
                        shape = RoundedCornerShape(6.dp),
                        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
                    ) {
                        Text("CONNECT", style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold))
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // 2. Verified Cloud Backend Card (Render Production)
            val candidateCloudUrl = if (connectionConfig.cloudUrl.isNotBlank()) connectionConfig.cloudUrl else ConnectionManager.DEFAULT_CLOUD_BACKEND_URL
            val displayCloudText = candidateCloudUrl.removePrefix("https://").removePrefix("http://").trimEnd('/')
            val formattedDisplay = if (displayCloudText.length > 35) displayCloudText.take(15) + "..." + displayCloudText.takeLast(17) else displayCloudText

            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp),
                color = HighlightSurface,
                border = BorderStroke(1.dp, SignalYellow.copy(alpha = 0.5f))
            ) {
                Row(
                    modifier = Modifier.padding(10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "VERIFIED CLOUD BACKEND (API)",
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 8.5.sp),
                            color = SignalYellow
                        )
                        Text(
                            text = formattedDisplay,
                            style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 11.5.sp),
                            color = PureWhite
                        )
                    }
                    Button(
                        onClick = { viewModel.connectToDeployedBackend(candidateCloudUrl) },
                        colors = ButtonDefaults.buttonColors(containerColor = SignalYellow, contentColor = DeepSpaceBackground),
                        shape = RoundedCornerShape(6.dp),
                        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
                    ) {
                        Text("CONNECT", style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold))
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // 3. Configure Endpoint & Hybrid Modes Modal Trigger
            Button(
                onClick = { viewModel.openConnectionSettings() },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = HighlightSurface, contentColor = SignalYellow),
                shape = RoundedCornerShape(6.dp),
                border = BorderStroke(1.dp, SignalYellow.copy(alpha = 0.6f)),
                contentPadding = PaddingValues(vertical = 9.dp)
            ) {
                Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(15.dp), tint = SignalYellow)
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

            Spacer(modifier = Modifier.height(8.dp))

            // 4. Autonomous System Auto-Connect / Re-Sync Trigger
            Button(
                onClick = { viewModel.retryDiscovery() },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed, contentColor = PureWhite),
                shape = RoundedCornerShape(6.dp),
                contentPadding = PaddingValues(vertical = 10.dp)
            ) {
                Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(15.dp), tint = PureWhite)
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

        // ══════════════════════════════════════════════════════════════════════
        // 5. BOTTOM TELEMETRY FOOTER
        // ══════════════════════════════════════════════════════════════════════
        Text(
            text = "PROTOCOL: ZERO-TRUST ENCLAVE",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 9.sp,
                letterSpacing = 0.8.sp
            ),
            color = TextTertiary
        )

        Spacer(modifier = Modifier.height(6.dp))

        Surface(
            shape = CutCornerShape(4.dp),
            color = ElevatedSurface,
            border = BorderStroke(1.dp, PrimaryRed.copy(alpha = 0.6f))
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .clip(RoundedCornerShape(3.dp))
                        .background(PrimaryRed)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "THREAT INTRUSION PREVENTION ACTIVE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.5.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.sp
                    ),
                    color = PrimaryRed
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = "└  QUANTUM DEFENSE GRID  ┘",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 8.5.sp,
                letterSpacing = 0.8.sp
            ),
            color = TextTertiary
        )

        Spacer(modifier = Modifier.height(10.dp))
    }

    // Modal dialog for configuration
    val showConnectionSettings by viewModel.showConnectionSettings.collectAsState()
    if (showConnectionSettings) {
        ConnectionSettingsModal(
            viewModel = viewModel,
            onDismiss = { viewModel.closeConnectionSettings() }
        )
    }
}
