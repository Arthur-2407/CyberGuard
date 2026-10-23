package com.cyberguard.client.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.navigation.NavController
import com.cyberguard.client.network.ConnectionState
import com.cyberguard.client.network.WebSocketEventClient
import com.cyberguard.client.network.WsEvent
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.sqrt

data class DetectionLogEntry(
    val timestamp: String,
    val riskScore: Double,
    val alertLevel: String,
    val classification: String
)

@Composable
fun LiveMonitorScreen(navController: NavController, viewModel: MainViewModel) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    
    val connectionState by viewModel.connectionState.collectAsState()
    val serverUrl by viewModel.serverUrl.collectAsState()
    val isCoreConnected = connectionState == ConnectionState.CONNECTED
    
    var isRecording by remember { mutableStateOf(false) }
    var hasPermission by remember { mutableStateOf(
        ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
    ) }
    
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        hasPermission = granted
    }
    
    var riskScore by remember { mutableStateOf(0.0) }
    var alertLevel by remember { mutableStateOf("SAFE") }
    var framesCaptured by remember { mutableStateOf(0L) }
    var framesSent by remember { mutableStateOf(0L) }
    var streamStatusText by remember { mutableStateOf("STANDBY") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var currentRms by remember { mutableStateOf(0f) }
    var sessionDurationSec by remember { mutableStateOf(0L) }
    var recentEvents by remember { mutableStateOf<List<DetectionLogEntry>>(emptyList()) }
    
    var eventClient by remember { mutableStateOf<WebSocketEventClient?>(null) }
    var audioRecord by remember { mutableStateOf<AudioRecord?>(null) }

    // Session timer ticker
    LaunchedEffect(isRecording) {
        if (isRecording) {
            sessionDurationSec = 0L
            while (isActive && isRecording) {
                delay(1000L)
                sessionDurationSec++
            }
        } else {
            sessionDurationSec = 0L
            currentRms = 0f
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            isRecording = false
            try { audioRecord?.stop() } catch (e: Exception) {}
            audioRecord?.release()
            audioRecord = null
            eventClient?.disconnect()
            eventClient = null
        }
    }
    
    LaunchedEffect(eventClient) {
        eventClient?.events?.collect { event ->
            when (event) {
                is WsEvent.Connected -> {
                    streamStatusText = "TRANSMITTING"
                    errorMessage = null
                }
                is WsEvent.RiskUpdate -> {
                    riskScore = event.riskScore
                    alertLevel = event.alertLevel
                    val timeStr = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
                    val newEntry = DetectionLogEntry(
                        timestamp = timeStr,
                        riskScore = event.riskScore,
                        alertLevel = event.alertLevel,
                        classification = event.voiceClassification
                    )
                    recentEvents = (listOf(newEntry) + recentEvents).take(5)
                }
                is WsEvent.SessionStarted -> {
                    streamStatusText = if (event.detectorReady) "ANALYZING" else "STREAMING (HEURISTIC)"
                }
                is WsEvent.StatusUpdate -> {
                    if (event.status == "WAITING_FOR_DATA") {
                        streamStatusText = "AWAITING VOICE ACTIVITY"
                    }
                }
                is WsEvent.Error -> {
                    errorMessage = event.message
                    streamStatusText = "ERROR"
                }
                is WsEvent.Disconnected -> {
                    if (isRecording) {
                        streamStatusText = "DISCONNECTED"
                    }
                }
                else -> {}
            }
        }
    }

    val animatedRms by animateFloatAsState(targetValue = currentRms, label = "RmsLevel")

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp)
            .padding(bottom = 72.dp)
    ) {
        // SCREEN TITLE
        Text(
            text = "LIVE MONITOR",
            style = MaterialTheme.typography.headlineMedium.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Black,
                fontSize = 20.sp,
                letterSpacing = 1.5.sp
            ),
            color = TextPrimary
        )
        Text(
            text = "REAL-TIME ACOUSTIC TELEMETRY UPLINK // FRAME-BY-FRAME INFERENCE",
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp,
                fontSize = 10.sp
            ),
            color = CyberNeonCyan
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // UPLINK CONTROL CARD
        SectionHeader("UPLINK CONTROL & INGESTION")
        CyberGuardCard(
            borderColor = if (isRecording) CyberNeonCyan else DividerColor,
            containerColor = SurfaceDark
        ) {
            if (!hasPermission) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(CutCornerShape(8.dp))
                            .background(StatusWarning.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = StatusWarning, modifier = Modifier.size(20.dp))
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "MICROPHONE AUTHORIZATION REQUIRED",
                            style = MaterialTheme.typography.titleSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            ),
                            color = StatusWarning
                        )
                        Text(
                            text = "HARDWARE SENSOR INGESTION RESTRICTED",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.sp
                            ),
                            color = TextTertiary
                        )
                    }
                }
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Real-time deepfake analysis streams linear 16-bit PCM mono audio at 16,000 Hz directly to the backend detection engine. Grant microphone access to enable real-time acoustic ingestion.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary
                )
                Spacer(modifier = Modifier.height(16.dp))
                CyberButton(
                    text = "AUTHORIZE MICROPHONE",
                    onClick = { permissionLauncher.launch(Manifest.permission.RECORD_AUDIO) },
                    modifier = Modifier.fillMaxWidth(),
                    icon = { Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(16.dp)) }
                )
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("STREAM PIPELINE STATE", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                        Spacer(modifier = Modifier.height(4.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(
                                        when {
                                            isRecording && streamStatusText != "ERROR" -> StatusOnline
                                            streamStatusText == "ERROR" -> StatusCritical
                                            else -> TextTertiary
                                        }
                                    )
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = if (isRecording) streamStatusText else "STANDBY (ARMED)",
                                style = MaterialTheme.typography.bodyMedium.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = when {
                                    isRecording && streamStatusText != "ERROR" -> StatusOnline
                                    streamStatusText == "ERROR" -> StatusCritical
                                    else -> TextSecondary
                                }
                            )
                        }
                    }

                    CyberButton(
                        text = if (isRecording) "TERMINATE UPLINK" else "INITIALIZE UPLINK",
                        onClick = {
                            if (isRecording) {
                                isRecording = false
                                try { audioRecord?.stop() } catch (e: Exception) {}
                                audioRecord?.release()
                                audioRecord = null
                                eventClient?.disconnect()
                                eventClient = null
                                streamStatusText = "STANDBY"
                                currentRms = 0f
                            } else {
                                val url = viewModel.serverUrl.value
                                if (url != null) {
                                    errorMessage = null
                                    streamStatusText = "INITIALIZING..."
                                    val client = WebSocketEventClient(viewModel.connectionManager.okHttpClient, url)
                                    eventClient = client
                                    client.connect()
                                    
                                    try {
                                        val bufferSize = AudioRecord.getMinBufferSize(
                                            16000,
                                            AudioFormat.CHANNEL_IN_MONO,
                                            AudioFormat.ENCODING_PCM_16BIT
                                        )
                                        if (bufferSize <= 0) throw IllegalStateException("Invalid buffer size: $bufferSize")
                                        val rec = AudioRecord(
                                            MediaRecorder.AudioSource.MIC,
                                            16000,
                                            AudioFormat.CHANNEL_IN_MONO,
                                            AudioFormat.ENCODING_PCM_16BIT,
                                            bufferSize * 2
                                        )
                                        if (rec.state != AudioRecord.STATE_INITIALIZED) {
                                            throw IllegalStateException("AudioRecord hardware allocation failed")
                                        }
                                        rec.startRecording()
                                        audioRecord = rec
                                        isRecording = true
                                        framesCaptured = 0L
                                        framesSent = 0L
                                        
                                        coroutineScope.launch(Dispatchers.IO) {
                                            val buffer = ByteArray(bufferSize)
                                            while (isActive && isRecording) {
                                                val read = rec.read(buffer, 0, buffer.size)
                                                if (read > 0) {
                                                    framesCaptured++
                                                    client.sendAudio(buffer.copyOf(read))
                                                    framesSent++
                                                    
                                                    // Calculate real acoustic RMS from PCM samples
                                                    var sum = 0.0
                                                    val numSamples = read / 2
                                                    for (i in 0 until numSamples) {
                                                        val sample = (buffer[i * 2 + 1].toInt() shl 8) or (buffer[i * 2].toInt() and 0xFF)
                                                        val shortVal = sample.toShort()
                                                        sum += (shortVal * shortVal).toDouble()
                                                    }
                                                    val mean = if (numSamples > 0) sum / numSamples else 0.0
                                                    val rawRms = sqrt(mean)
                                                    currentRms = (rawRms / 15000.0).toFloat().coerceIn(0f, 1f)
                                                }
                                            }
                                        }
                                    } catch (e: Exception) {
                                        errorMessage = "Microphone capture failure: ${e.message}"
                                        isRecording = false
                                        client.disconnect()
                                    }
                                } else {
                                    errorMessage = "Cannot start: Core server disconnected. Please reconnect on Dashboard screen."
                                }
                            }
                        },
                        variant = if (isRecording) CyberButtonVariant.DESTRUCTIVE else CyberButtonVariant.PRIMARY,
                        enabled = isRecording || isCoreConnected
                    )
                }

                // DYNAMIC ACOUSTIC LEVEL METER (Driven by real AudioRecord PCM RMS)
                Spacer(modifier = Modifier.height(14.dp))
                HorizontalDivider(color = DividerColor)
                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("MICROPHONE INPUT SIGNAL (PCM RMS)", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                    Text(
                        if (isRecording) String.format(Locale.US, "%.1f dBFS", if (animatedRms > 0.001f) 20 * kotlin.math.log10(animatedRms) else -60f) else "MUTED",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                        color = if (isRecording) CyberNeonCyan else TextTertiary
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                
                // 16-segment tactical VU meter
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(3.dp)
                ) {
                    val segments = 16
                    for (i in 0 until segments) {
                        val threshold = (i + 1).toFloat() / segments
                        val isActiveSegment = isRecording && animatedRms >= threshold * 0.85f
                        val segColor = when {
                            i >= 13 -> StatusCritical
                            i >= 9 -> StatusWarning
                            else -> StatusOnline
                        }
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxHeight()
                                .clip(RoundedCornerShape(1.dp))
                                .background(if (isActiveSegment) segColor else SurfaceLighter)
                        )
                    }
                }
            }
        }

        if (errorMessage != null) {
            Spacer(modifier = Modifier.height(14.dp))
            CyberGuardCard(containerColor = StatusCritical.copy(alpha = 0.12f), borderColor = StatusCritical) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Warning, contentDescription = null, tint = StatusCritical, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("STREAM UPLINK FAULT", style = MaterialTheme.typography.labelSmall, color = StatusCritical)
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(errorMessage!!, style = MaterialTheme.typography.bodySmall, color = TextPrimary)
            }
        }
        
        Spacer(modifier = Modifier.height(20.dp))
        
        if (isRecording) {
            // ACTIVE LIVE TELEMETRY DASHBOARD
            SectionHeader("LIVE INFERENCE & ANOMALY MATRIX")
            CyberGuardCard {
                val riskColor = when (alertLevel.uppercase()) {
                    "CRITICAL" -> StatusCritical
                    "HIGH" -> StatusWarning
                    "MODERATE" -> StatusWarning
                    else -> StatusOnline
                }
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.Top
                ) {
                    MetricDisplay(
                        label = "CURRENT SYNTHESIS RISK",
                        value = String.format(Locale.US, "%.3f", riskScore),
                        color = riskColor
                    )
                    StatusBadge(text = alertLevel, color = riskColor, isPulsing = alertLevel in listOf("HIGH", "CRITICAL"))
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Continuous risk gauge bar
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(RoundedCornerShape(3.dp))
                        .background(SurfaceLighter)
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth(if (riskScore > 0) riskScore.toFloat().coerceIn(0.05f, 1f) else 0.05f)
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp))
                            .background(riskColor)
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("AUTHENTIC VOICE (0.00)", style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp), color = TextTertiary)
                    Text("SYNTHESIS / CLONE (1.00)", style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp), color = TextTertiary)
                }

                Spacer(modifier = Modifier.height(16.dp))
                HorizontalDivider(color = DividerColor)
                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text("FRAMES CAPTURED", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                        Text("$framesCaptured", style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), color = TextPrimary)
                    }
                    Column {
                        Text("FRAMES TRANSMITTED", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                        Text("$framesSent", style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), color = StatusOnline)
                    }
                    Column {
                        Text("SESSION DURATION", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                        val mins = sessionDurationSec / 60
                        val secs = sessionDurationSec % 60
                        Text(String.format(Locale.US, "%02d:%02d", mins, secs), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), color = CyberNeonCyan)
                    }
                }
            }

            // RECENT DETECTIONS LOG
            if (recentEvents.isNotEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))
                SectionHeader("RECENT INFERENCE EVENTS")
                CyberGuardCard {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        for (event in recentEvents) {
                            val evtColor = when (event.alertLevel.uppercase()) {
                                "CRITICAL" -> StatusCritical
                                "HIGH" -> StatusWarning
                                else -> StatusOnline
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = event.timestamp,
                                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 10.sp),
                                        color = TextTertiary
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = event.classification,
                                        style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold),
                                        color = TextPrimary
                                    )
                                }
                                StatusBadge(text = "${String.format(Locale.US, "%.2f", event.riskScore)} [${event.alertLevel}]", color = evtColor, isPulsing = false)
                            }
                        }
                    }
                }
            }
        } else {
            // STANDBY READINESS & CAPABILITIES PANEL (Elevated for Screen 5)
            SectionHeader("UPLINK CAPABILITIES & SPECIFICATION")
            CyberGuardCard {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "STANDBY // 16kHz LINEAR PCM READY", 
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            ), 
                            color = CyberNeonCyan
                        )
                        StatusBadge(
                            text = if (isCoreConnected) "READY" else "OFFLINE",
                            color = if (isCoreConnected) StatusOnline else StatusCritical
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Live Monitor captures linear 16-bit PCM microphone audio and streams it to the CyberGuard core for frame-by-frame deepfake and voice synthesis detection.",
                        style = MaterialTheme.typography.bodySmall, 
                        color = TextSecondary
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text("SAMPLE RATE", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                            Text("16,000 Hz", style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), color = TextPrimary)
                        }
                        Column {
                            Text("CHANNELS", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                            Text("1 (Mono)", style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), color = TextPrimary)
                        }
                        Column {
                            Text("ENCODING", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                            Text("PCM 16-BIT", style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), color = TextPrimary)
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    HorizontalDivider(color = DividerColor)
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text("CORE LINK STATUS", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                            Text(
                                text = if (isCoreConnected) "ONLINE" else "DISCONNECTED", 
                                style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold), 
                                color = if (isCoreConnected) StatusOnline else StatusCritical
                            )
                        }
                        if (!serverUrl.isNullOrBlank()) {
                            Column {
                                Text("TARGET HOST", style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                                Text(
                                    text = serverUrl!!.removePrefix("http://").removePrefix("https://").trimEnd('/'), 
                                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), 
                                    color = TextPrimary
                                )
                            }
                        }
                    }
                    if (!isCoreConnected) {
                        Spacer(modifier = Modifier.height(16.dp))
                        CyberButton(
                            text = "RECONNECT TO CYBERGUARD HOST",
                            onClick = { viewModel.retryDiscovery() },
                            modifier = Modifier.fillMaxWidth(),
                            icon = { Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(14.dp)) }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Operational Ingestion Matrix
            CyberGuardCard(containerColor = HighlightSurface) {
                Text(
                    text = "[ ACOUSTIC SENSOR PIPELINE ARCHITECTURE ]",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        color = CyberBlue
                    )
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "• Sensor: AudioRecord Hardware Mic Channel (Mono, Low Latency)\n" +
                           "• Transport: WebSocket Binary Framing (`/ws/audio`)\n" +
                           "• Processing: Streaming acoustic mel-spectrogram feature extractor\n" +
                           "• Threat Verdicts: Frame-by-frame confidence scoring & anomaly alerts",
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        lineHeight = 18.sp
                    ),
                    color = TextPrimary
                )
            }
        }
    }
}

