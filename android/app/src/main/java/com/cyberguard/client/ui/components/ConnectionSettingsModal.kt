package com.cyberguard.client.ui.components

import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberguard.client.network.*
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.launch

/**
 * CyberGuard Smart Backend Connection Manager Modal.
 * Supports Cloud, Local Wi-Fi/LAN, and Hybrid Failover modes with live endpoint testing.
 */
@Composable
fun ConnectionSettingsModal(
    viewModel: MainViewModel,
    onDismiss: () -> Unit
) {
    val coroutineScope = rememberCoroutineScope()
    val keyboardController = LocalSoftwareKeyboardController.current

    val currentConfig by viewModel.connectionConfig.collectAsState()
    val connectionState by viewModel.connectionState.collectAsState()
    val activeMode by viewModel.activeMode.collectAsState()
    val activeEndpoint by viewModel.activeEndpoint.collectAsState()
    val activeEndpointType by viewModel.activeEndpointType.collectAsState()
    val failoverNotice by viewModel.failoverNotice.collectAsState()
    val isFailoverActive by viewModel.isFailoverActive.collectAsState()

    var selectedMode by remember(currentConfig) { mutableStateOf(currentConfig.mode) }
    var selectedPriority by remember(currentConfig) { mutableStateOf(currentConfig.hybridPriority) }
    var cloudUrlInput by remember(currentConfig) { mutableStateOf(currentConfig.cloudUrl) }
    var localHostInput by remember(currentConfig) { mutableStateOf(currentConfig.localHost) }
    var localPortInput by remember(currentConfig) { mutableStateOf(currentConfig.localPort.toString()) }

    var isTestingConnection by remember { mutableStateOf(false) }
    var cloudTestResult by remember { mutableStateOf<EndpointHealthResult?>(null) }
    var localTestResult by remember { mutableStateOf<EndpointHealthResult?>(null) }
    var validationError by remember { mutableStateOf<String?>(null) }
    var isScanningLan by remember { mutableStateOf(false) }

    val isConnected = connectionState == ConnectionState.CONNECTED

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {},
        containerColor = DeepSpaceBackground,
        shape = CutCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth(0.96f)
            .fillMaxHeight(0.90f)
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
                            .size(36.dp)
                            .clip(CutCornerShape(6.dp))
                            .background(CyberNeonCyan.copy(alpha = 0.15f))
                            .border(1.dp, CyberNeonCyan.copy(alpha = 0.7f), CutCornerShape(6.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.SettingsEthernet,
                            contentDescription = null,
                            tint = CyberNeonCyan,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "SMART BACKEND CONNECTION MANAGER",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Black,
                                fontSize = 11.5.sp,
                                letterSpacing = 0.8.sp
                            ),
                            color = TextPrimary
                        )
                        Text(
                            text = "CLOUD • LOCAL WI-FI/LAN • HYBRID FAILOVER",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 8.5.sp,
                                letterSpacing = 0.6.sp
                            ),
                            color = CyberNeonCyan
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
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
            ) {
                // 1. ACTIVE CONNECTION STATUS BANNER
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = ElevatedSurface,
                    border = BorderStroke(1.dp, if (isConnected) StatusOnline.copy(alpha = 0.6f) else StatusWarning.copy(alpha = 0.5f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier
                                        .size(8.dp)
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(if (isConnected) StatusOnline else StatusCritical)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = if (isConnected) "ONLINE: ${activeEndpointType ?: "CONNECTED"}" else "DISCONNECTED",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 10.sp
                                    ),
                                    color = if (isConnected) StatusOnline else StatusCritical
                                )
                            }
                            Text(
                                text = "MODE: ${activeMode.name}",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.5.sp,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = CyberNeonCyan
                            )
                        }

                        if (!activeEndpoint.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "ACTIVE: $activeEndpoint",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 9.sp
                                ),
                                color = TextSecondary,
                                maxLines = 1
                            )
                        }

                        if (!failoverNotice.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "⚡ ${failoverNotice}",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.SemiBold
                                ),
                                color = HighAlertOrange
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // 2. PRIMARY MODE SELECTOR
                Text(
                    text = "SELECT CONNECTION MODE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.5.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.8.sp
                    ),
                    color = CyberNeonCyan
                )
                Spacer(modifier = Modifier.height(6.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    ConnectionMode.values().forEach { mode ->
                        val isSelected = selectedMode == mode
                        val label = when (mode) {
                            ConnectionMode.CLOUD -> "☁ CLOUD"
                            ConnectionMode.LOCAL_LAN -> "📶 LOCAL LAN"
                            ConnectionMode.HYBRID -> "🔀 HYBRID"
                        }
                        Surface(
                            modifier = Modifier
                                .weight(1f)
                                .clickable {
                                    selectedMode = mode
                                    validationError = null
                                },
                            shape = RoundedCornerShape(6.dp),
                            color = if (isSelected) CyberNeonCyan.copy(alpha = 0.2f) else HighlightSurface,
                            border = BorderStroke(
                                1.2.dp,
                                if (isSelected) CyberNeonCyan else HolographicGlowBorder.copy(alpha = 0.4f)
                            )
                        ) {
                            Box(
                                modifier = Modifier.padding(vertical = 8.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = label,
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = if (isSelected) FontWeight.Black else FontWeight.Normal,
                                        fontSize = 9.sp
                                    ),
                                    color = if (isSelected) CyberNeonCyan else TextSecondary
                                )
                            }
                        }
                    }
                }

                // Mode Explanation Banner
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = when (selectedMode) {
                        ConnectionMode.CLOUD -> "Mode A: Connects strictly to verified remote CyberGuard backend or secure Cloudflare tunnel."
                        ConnectionMode.LOCAL_LAN -> "Mode B: Connects directly to local Docker backend on your workstation (port 3000) over Wi-Fi/LAN."
                        ConnectionMode.HYBRID -> "Mode C: Evaluates both local & cloud backends; safely selects verified node with automatic failover."
                    },
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.5.sp),
                    color = TextTertiary
                )

                // 3. HYBRID PRIORITY SELECTOR (Only in Hybrid Mode)
                if (selectedMode == ConnectionMode.HYBRID) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "HYBRID FAILOVER PRIORITY",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.6.sp
                        ),
                        color = HighAlertOrange
                    )
                    Spacer(modifier = Modifier.height(6.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        HybridPriority.values().forEach { priority ->
                            val isSelected = selectedPriority == priority
                            val title = when (priority) {
                                HybridPriority.LOCAL_FIRST -> "⚡ LOCAL-FIRST (LAN Preferred)"
                                HybridPriority.CLOUD_FIRST -> "☁ CLOUD-FIRST (Remote Preferred)"
                            }
                            Surface(
                                modifier = Modifier
                                    .weight(1f)
                                    .clickable { selectedPriority = priority },
                                shape = RoundedCornerShape(6.dp),
                                color = if (isSelected) HighAlertOrange.copy(alpha = 0.2f) else HighlightSurface,
                                border = BorderStroke(
                                    1.dp,
                                    if (isSelected) HighAlertOrange else HolographicGlowBorder.copy(alpha = 0.3f)
                                )
                            ) {
                                Box(
                                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 6.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = title,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                            fontSize = 8.5.sp
                                        ),
                                        color = if (isSelected) HighAlertOrange else TextSecondary
                                    )
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // 4. CLOUD ENDPOINT CONFIGURATION
                if (selectedMode == ConnectionMode.CLOUD || selectedMode == ConnectionMode.HYBRID) {
                    Text(
                        text = "CLOUD BACKEND HTTPS ENDPOINT",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold
                        ),
                        color = CyberNeonCyan
                    )
                    Spacer(modifier = Modifier.height(4.dp))

                    OutlinedTextField(
                        value = cloudUrlInput,
                        onValueChange = { 
                            cloudUrlInput = it
                            validationError = null 
                        },
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.5.sp,
                            color = TextPrimary
                        ),
                        placeholder = {
                            Text(
                                "https://*.trycloudflare.com or backend URL",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp, color = TextTertiary)
                            )
                        },
                        singleLine = false,
                        maxLines = 2,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CyberNeonCyan,
                            unfocusedBorderColor = HolographicGlowBorder.copy(alpha = 0.6f),
                            focusedContainerColor = HighlightSurface,
                            unfocusedContainerColor = HighlightSurface
                        )
                    )

                    Spacer(modifier = Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        AssistChip(
                            onClick = { cloudUrlInput = ConnectionManager.DEFAULT_TUNNEL_URL },
                            label = { Text("Active Cloudflare Tunnel", fontSize = 8.5.sp, fontFamily = FontFamily.Monospace) },
                            colors = AssistChipDefaults.assistChipColors(containerColor = HighlightSurface, labelColor = CyberNeonCyan)
                        )
                        AssistChip(
                            onClick = { cloudUrlInput = ConnectionManager.DEFAULT_STATIC_FRONTEND_URL },
                            label = { Text("Vercel (Static Web)", fontSize = 8.5.sp, fontFamily = FontFamily.Monospace) },
                            colors = AssistChipDefaults.assistChipColors(containerColor = HighlightSurface, labelColor = TextSecondary)
                        )
                    }

                    // Cloud Test Result Badge
                    cloudTestResult?.let { result ->
                        Spacer(modifier = Modifier.height(6.dp))
                        EndpointDiagnosticPill(result = result)
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                }

                // 5. LOCAL WI-FI / LAN CONFIGURATION
                if (selectedMode == ConnectionMode.LOCAL_LAN || selectedMode == ConnectionMode.HYBRID) {
                    Text(
                        text = "LOCAL WORKSTATION HOST (DOCKER)",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold
                        ),
                        color = CyberNeonCyan
                    )
                    Spacer(modifier = Modifier.height(4.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = localHostInput,
                            onValueChange = { localHostInput = it },
                            modifier = Modifier.weight(0.7f),
                            textStyle = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                color = TextPrimary
                            ),
                            placeholder = { Text("172.16.31.2 or LAN IP", fontSize = 10.sp, color = TextTertiary) },
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = CyberNeonCyan,
                                unfocusedBorderColor = HolographicGlowBorder.copy(alpha = 0.6f),
                                focusedContainerColor = HighlightSurface,
                                unfocusedContainerColor = HighlightSurface
                            )
                        )

                        OutlinedTextField(
                            value = localPortInput,
                            onValueChange = { localPortInput = it },
                            modifier = Modifier.weight(0.3f),
                            textStyle = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                color = TextPrimary
                            ),
                            placeholder = { Text("3000", fontSize = 10.sp, color = TextTertiary) },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = CyberNeonCyan,
                                unfocusedBorderColor = HolographicGlowBorder.copy(alpha = 0.6f),
                                focusedContainerColor = HighlightSurface,
                                unfocusedContainerColor = HighlightSurface
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(6.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        AssistChip(
                            onClick = {
                                isScanningLan = true
                                viewModel.scanSubnet(
                                    onFound = { foundIp ->
                                        localHostInput = foundIp
                                        isScanningLan = false
                                        coroutineScope.launch {
                                            localTestResult = viewModel.testEndpoint(foundIp, localPortInput.toIntOrNull() ?: 3000)
                                        }
                                    },
                                    onFinished = {
                                        isScanningLan = false
                                    }
                                )
                            },
                            leadingIcon = {
                                if (isScanningLan) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(11.dp),
                                        strokeWidth = 1.5.dp,
                                        color = CyberNeonCyan
                                    )
                                } else {
                                    Icon(
                                        imageVector = Icons.Default.Search,
                                        contentDescription = null,
                                        modifier = Modifier.size(13.dp),
                                        tint = CyberNeonCyan
                                    )
                                }
                            },
                            label = {
                                Text(
                                    if (isScanningLan) "Scanning LAN..." else "Auto-Scan LAN",
                                    fontSize = 8.5.sp,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold
                                )
                            },
                            colors = AssistChipDefaults.assistChipColors(
                                containerColor = CyberNeonCyan.copy(alpha = 0.15f),
                                labelColor = CyberNeonCyan
                            )
                        )
                        AssistChip(
                            onClick = { localHostInput = "10.103.174.181" },
                            label = { Text("Host Wi-Fi (10.103.174.181)", fontSize = 8.5.sp, fontFamily = FontFamily.Monospace) },
                            colors = AssistChipDefaults.assistChipColors(containerColor = HighlightSurface, labelColor = CyberNeonCyan)
                        )
                        val detectedGw = viewModel.detectedGatewayIp
                        if (!detectedGw.isNullOrBlank()) {
                            AssistChip(
                                onClick = { localHostInput = detectedGw },
                                label = { Text("Gateway ($detectedGw)", fontSize = 8.5.sp, fontFamily = FontFamily.Monospace) },
                                colors = AssistChipDefaults.assistChipColors(containerColor = HighlightSurface, labelColor = TextSecondary)
                            )
                        }
                        AssistChip(
                            onClick = { localHostInput = "172.16.31.2" },
                            label = { Text("Hotspot (172.16.31.2)", fontSize = 8.5.sp, fontFamily = FontFamily.Monospace) },
                            colors = AssistChipDefaults.assistChipColors(containerColor = HighlightSurface, labelColor = TextSecondary)
                        )
                        AssistChip(
                            onClick = { localHostInput = "10.0.2.2" },
                            label = { Text("Emulator (10.0.2.2)", fontSize = 8.5.sp, fontFamily = FontFamily.Monospace) },
                            colors = AssistChipDefaults.assistChipColors(containerColor = HighlightSurface, labelColor = TextSecondary)
                        )
                    }

                    // Local Test Result Badge
                    localTestResult?.let { result ->
                        Spacer(modifier = Modifier.height(6.dp))
                        EndpointDiagnosticPill(result = result)
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                }

                // Error Banner
                validationError?.let { err ->
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = StatusCritical.copy(alpha = 0.15f),
                        border = BorderStroke(1.dp, StatusCritical.copy(alpha = 0.6f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = err,
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.5.sp),
                            color = StatusCritical,
                            modifier = Modifier.padding(8.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                }

                // 6. ACTION CONTROLS
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Test Button
                    Button(
                        onClick = {
                            keyboardController?.hide()
                            validationError = null

                            if (selectedMode == ConnectionMode.CLOUD || selectedMode == ConnectionMode.HYBRID) {
                                val trimmedCloud = cloudUrlInput.trim()
                                val host = trimmedCloud.removePrefix("https://").removePrefix("http://").substringBefore("/").substringBefore(":")
                                if (trimmedCloud.isBlank()) {
                                    validationError = "Please enter a valid HTTPS cloud backend URL."
                                    return@Button
                                }
                                if (!host.contains(".")) {
                                    validationError = "Incomplete cloud hostname '$host'. Fully qualified domain name required (e.g. *.trycloudflare.com)."
                                    return@Button
                                }
                            }

                            isTestingConnection = true
                            coroutineScope.launch {
                                val p = localPortInput.toIntOrNull() ?: 3000
                                if (selectedMode == ConnectionMode.CLOUD || selectedMode == ConnectionMode.HYBRID) {
                                    cloudTestResult = viewModel.testEndpoint(cloudUrlInput, 443)
                                }
                                if (selectedMode == ConnectionMode.LOCAL_LAN || selectedMode == ConnectionMode.HYBRID) {
                                    localTestResult = viewModel.testEndpoint(localHostInput, p)
                                }
                                isTestingConnection = false
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = !isTestingConnection,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = HighlightSurface,
                            contentColor = CyberNeonCyan
                        ),
                        shape = RoundedCornerShape(6.dp),
                        border = BorderStroke(1.dp, CyberNeonCyan.copy(alpha = 0.8f))
                    ) {
                        if (isTestingConnection) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(14.dp),
                                color = CyberNeonCyan,
                                strokeWidth = 1.5.dp
                            )
                        } else {
                            Icon(Icons.Default.Speed, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                "TEST",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 10.sp
                                )
                            )
                        }
                    }

                    // Save & Connect Button
                    Button(
                        onClick = {
                            keyboardController?.hide()
                            val port = localPortInput.toIntOrNull() ?: 3000
                            if (localHostInput.isBlank() && (selectedMode == ConnectionMode.LOCAL_LAN || selectedMode == ConnectionMode.HYBRID)) {
                                validationError = "Please enter a valid local host IP or domain."
                                return@Button
                            }
                            if (selectedMode == ConnectionMode.CLOUD || selectedMode == ConnectionMode.HYBRID) {
                                val trimmedCloud = cloudUrlInput.trim()
                                val host = trimmedCloud.removePrefix("https://").removePrefix("http://").substringBefore("/").substringBefore(":")
                                if (trimmedCloud.isBlank()) {
                                    validationError = "Please enter a valid HTTPS cloud backend URL."
                                    return@Button
                                }
                                if (!host.contains(".")) {
                                    validationError = "Incomplete cloud hostname '$host'. Fully qualified domain name required (e.g. *.trycloudflare.com)."
                                    return@Button
                                }
                            }

                            val newConfig = ConnectionConfig(
                                mode = selectedMode,
                                hybridPriority = selectedPriority,
                                cloudUrl = cloudUrlInput.trim(),
                                localHost = localHostInput.trim(),
                                localPort = port
                            )
                            viewModel.applyConnectionConfig(newConfig)
                            onDismiss()
                        },
                        modifier = Modifier.weight(1.5f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyberNeonCyan,
                            contentColor = DeepSpaceBackground
                        ),
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            "SAVE & CONNECT",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.sp
                            )
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                // Bottom Utilities Row (Disconnect / Restore Defaults)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    TextButton(
                        onClick = {
                            val def = viewModel.restoreDefaultConnectionConfig()
                            selectedMode = def.mode
                            selectedPriority = def.hybridPriority
                            cloudUrlInput = def.cloudUrl
                            localHostInput = def.localHost
                            localPortInput = def.localPort.toString()
                            cloudTestResult = null
                            localTestResult = null
                        }
                    ) {
                        Text(
                            "RESTORE DEFAULTS",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 8.5.sp,
                                color = TextTertiary
                            )
                        )
                    }

                    if (isConnected) {
                        TextButton(
                            onClick = {
                                viewModel.disconnectBackend()
                                onDismiss()
                            }
                        ) {
                            Text(
                                "DISCONNECT",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.5.sp,
                                    color = StatusCritical
                                )
                            )
                        }
                    }
                }
            }
        }
    )
}

@Composable
private fun EndpointDiagnosticPill(result: EndpointHealthResult) {
    val bgColor = when {
        result.isCyberGuardBackend -> StatusOnline.copy(alpha = 0.15f)
        result.isStaticFrontend -> StatusWarning.copy(alpha = 0.15f)
        else -> StatusCritical.copy(alpha = 0.15f)
    }
    val borderColor = when {
        result.isCyberGuardBackend -> StatusOnline.copy(alpha = 0.7f)
        result.isStaticFrontend -> StatusWarning.copy(alpha = 0.7f)
        else -> StatusCritical.copy(alpha = 0.7f)
    }
    val titleText = when {
        result.isCyberGuardBackend -> "✓ VERIFIED BACKEND (${result.latencyMs}ms)"
        result.isStaticFrontend -> "⚠ STATIC FRONTEND ONLY"
        else -> "✗ UNREACHABLE / REJECTED"
    }

    Surface(
        shape = RoundedCornerShape(6.dp),
        color = bgColor,
        border = BorderStroke(1.dp, borderColor),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(8.dp)) {
            Text(
                text = titleText,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 9.sp
                ),
                color = when {
                    result.isCyberGuardBackend -> StatusOnline
                    result.isStaticFrontend -> StatusWarning
                    else -> StatusCritical
                }
            )
            result.details?.let { details ->
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = details,
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 8.5.sp
                    ),
                    color = TextPrimary
                )
            }
        }
    }
}
