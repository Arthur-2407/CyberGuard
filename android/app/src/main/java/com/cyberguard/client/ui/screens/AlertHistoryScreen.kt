package com.cyberguard.client.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.cyberguard.client.network.Alert
import com.cyberguard.client.network.Incident
import com.cyberguard.client.network.IncidentUpdateStatusRequest
import com.cyberguard.client.network.LlmAnalysisResponse
import com.cyberguard.client.network.toUserFacingErrorMessage
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.Screen
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.launch
import java.util.Locale

enum class AlertViewMode {
    INCIDENTS,
    RAW_ALERTS
}

@Composable
fun AlertHistoryScreen(navController: NavController, viewModel: MainViewModel) {
    val coroutineScope = rememberCoroutineScope()
    var viewMode by remember { mutableStateOf(AlertViewMode.INCIDENTS) }
    
    var incidents by remember { mutableStateOf<List<Incident>>(emptyList()) }
    var alerts by remember { mutableStateOf<List<Alert>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    val currentUser by viewModel.currentUser.collectAsState()
    var refreshTrigger by remember { mutableStateOf(0) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedSeverityFilter by remember { mutableStateOf("ALL") }

    // Case Details & AI Playbook States
    var expandedIncidentId by remember { mutableStateOf<String?>(null) }
    var activePlaybookIncidentId by remember { mutableStateOf<String?>(null) }
    var playbookResult by remember { mutableStateOf<LlmAnalysisResponse?>(null) }
    var isPlaybookLoading by remember { mutableStateOf(false) }
    var playbookError by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(refreshTrigger, viewMode, currentUser) {
        try {
            isLoading = true
            errorMessage = null
            val api = viewModel.connectionManager.api
            if (api != null) {
                if (viewMode == AlertViewMode.INCIDENTS) {
                    if (currentUser != null) {
                        incidents = api.getIncidents(50)
                    } else {
                        incidents = emptyList()
                    }
                } else {
                    alerts = api.getRecentAlerts(50).alerts
                }
            } else {
                errorMessage = "CORE CONNECTION OFFLINE: Backend service unreachable."
            }
        } catch (e: Exception) {
            errorMessage = e.toUserFacingErrorMessage()
        } finally {
            isLoading = false
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 16.dp)) {
        // TOP HEADER
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "SECURITY INCIDENTS",
                    style = MaterialTheme.typography.headlineMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Black,
                        fontSize = 20.sp,
                        letterSpacing = 1.5.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "SOC CASE MANAGEMENT & EVENT TIMELINE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 1.sp,
                        fontSize = 10.sp
                    ),
                    color = CyberNeonCyan
                )
            }
            IconButton(
                onClick = { refreshTrigger++ },
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(SurfaceDark)
            ) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh Telemetry", tint = CyberNeonCyan)
            }
        }
        
        Spacer(modifier = Modifier.height(14.dp))

        // VIEW MODE TOGGLE
        TabRow(
            selectedTabIndex = viewMode.ordinal,
            containerColor = ElevatedSurface,
            contentColor = CyberNeonCyan,
            divider = { HorizontalDivider(color = DividerColor) }
        ) {
            Tab(
                selected = viewMode == AlertViewMode.INCIDENTS,
                onClick = { viewMode = AlertViewMode.INCIDENTS },
                text = { Text("INCIDENT CASES (${incidents.size})", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold) },
                icon = { Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(16.dp)) }
            )
            Tab(
                selected = viewMode == AlertViewMode.RAW_ALERTS,
                onClick = { viewMode = AlertViewMode.RAW_ALERTS },
                text = { Text("RAW TELEMETRY LOG (${alerts.size})", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold) },
                icon = { Icon(Icons.Default.Info, contentDescription = null, modifier = Modifier.size(16.dp)) }
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        // SEARCH BAR (Using high-contrast CyberTextField)
        CyberTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            label = "FILTER INCIDENT CASES",
            placeholder = "Filter cases by category, ID, asset...",
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = CyberNeonCyan, modifier = Modifier.size(18.dp)) },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { searchQuery = "" }) {
                        Icon(Icons.Default.Clear, contentDescription = "Clear", tint = TextTertiary, modifier = Modifier.size(16.dp))
                    }
                }
            }
        )

        Spacer(modifier = Modifier.height(10.dp))

        // FILTER CHIPS ROW
        LazyRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            val filters = listOf("ALL", "CRITICAL", "HIGH", "INVESTIGATING", "RESOLVED")
            items(filters) { filter ->
                val isSelected = selectedSeverityFilter == filter
                FilterChip(
                    selected = isSelected,
                    onClick = { selectedSeverityFilter = filter },
                    label = { Text(filter, style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 10.sp)) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = CyberNeonCyan.copy(alpha = 0.2f),
                        selectedLabelColor = CyberNeonCyan,
                        containerColor = SurfaceDark,
                        labelColor = TextTertiary
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        borderColor = if (isSelected) CyberNeonCyan else DividerColor,
                        enabled = true,
                        selected = isSelected
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
        
        if (isLoading) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = CyberNeonCyan, strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "SYNCHRONIZING SOC INCIDENT DATABASE...",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            color = CyberNeonCyan
                        )
                    )
                }
            }
        } else if (errorMessage != null) {
            CyberGuardCard(borderColor = StatusCritical, containerColor = StatusCritical.copy(alpha = 0.12f)) {
                Text("SECURITY TELEMETRY OFFLINE", style = MaterialTheme.typography.labelSmall, color = StatusCritical)
                Spacer(modifier = Modifier.height(6.dp))
                Text(errorMessage!!, style = MaterialTheme.typography.bodyMedium, color = TextPrimary)
                Spacer(modifier = Modifier.height(14.dp))
                CyberButton(
                    text = "RETRY CONNECTION",
                    onClick = { refreshTrigger++ }
                )
            }
        } else if (viewMode == AlertViewMode.INCIDENTS) {
            // INCIDENT CASES VIEW
            if (currentUser == null) {
                val infiniteTransition = rememberInfiniteTransition(label = "soc_locked_anim")
                val borderGlow by infiniteTransition.animateFloat(
                    initialValue = 0.4f,
                    targetValue = 0.95f,
                    animationSpec = infiniteRepeatable(tween(1400, easing = FastOutSlowInEasing), RepeatMode.Reverse),
                    label = "border_glow"
                )

                CyberGuardCard(
                    borderColor = CyberNeonCyan.copy(alpha = borderGlow),
                    containerColor = HighlightSurface
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .clip(CutCornerShape(4.dp))
                                .background(StatusWarning.copy(alpha = 0.15f))
                                .border(1.dp, StatusWarning.copy(alpha = borderGlow), CutCornerShape(4.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.Lock, contentDescription = null, tint = StatusWarning, modifier = Modifier.size(16.dp))
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                "SOC INCIDENT DATABASE LOCKED",
                                style = MaterialTheme.typography.titleSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Black,
                                    letterSpacing = 1.sp
                                ),
                                color = StatusWarning
                            )
                            Text(
                                "AUTHENTICATION REQUIRED",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 8.sp,
                                    letterSpacing = 0.5.sp
                                ),
                                color = CyberNeonCyan
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "Multi-tenant SOC incident records and remediation playbooks are cryptographically isolated per authenticated operator. Sign in or register to review open investigation dockets.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        CyberButton(
                            text = "AUTHENTICATE",
                            onClick = {
                                viewModel.showAuthModal.value = true
                            },
                            modifier = Modifier.weight(1f),
                            icon = { Icon(Icons.Default.LockOpen, contentDescription = null, modifier = Modifier.size(14.dp)) }
                        )
                        CyberButton(
                            text = "RAW LOGS",
                            onClick = { viewMode = AlertViewMode.RAW_ALERTS },
                            variant = CyberButtonVariant.OUTLINED,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            } else {
                val filteredIncidents = incidents.filter { inc ->
                    val matchesSearch = searchQuery.isBlank() ||
                        inc.category.contains(searchQuery, ignoreCase = true) ||
                        inc.incidentId.contains(searchQuery, ignoreCase = true) ||
                        inc.affectedAssets.any { it.contains(searchQuery, ignoreCase = true) }
                    
                    val matchesFilter = when (selectedSeverityFilter) {
                        "CRITICAL" -> inc.risk.equals("CRITICAL", ignoreCase = true)
                        "HIGH" -> inc.risk.equals("HIGH", ignoreCase = true)
                        "INVESTIGATING" -> inc.status.equals("INVESTIGATING", ignoreCase = true)
                        "RESOLVED" -> inc.status.equals("RESOLVED", ignoreCase = true)
                        else -> true
                    }
                    matchesSearch && matchesFilter
                }

                if (filteredIncidents.isEmpty()) {
                    CyberGuardCard {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = StatusOnline, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("ACTIVE THREAT SURFACE CLEAR", style = MaterialTheme.typography.titleSmall, color = StatusOnline)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            if (incidents.isEmpty())
                                "All perimeter sensors, endpoint telemetry feeds, and deepfake detectors report zero uncontained security incidents within the active retention window."
                            else
                                "No security incidents match the current search or severity filter.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    }
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(14.dp),
                        contentPadding = PaddingValues(bottom = 80.dp)
                    ) {
                        items(filteredIncidents) { inc ->
                            val isDetailsExpanded = expandedIncidentId == inc.incidentId
                            val isPlaybookActive = activePlaybookIncidentId == inc.incidentId

                            CyberGuardCard {
                                val riskColor = when (inc.risk.uppercase()) {
                                    "CRITICAL" -> StatusCritical
                                    "HIGH" -> StatusWarning
                                    "MEDIUM" -> StatusWarning
                                    else -> StatusOnline
                                }

                                val statusColor = when (inc.status.uppercase()) {
                                    "RESOLVED" -> StatusOnline
                                    "CONTAINED" -> ElectricCyan
                                    "INVESTIGATING" -> StatusWarning
                                    else -> StatusCritical
                                }
                                
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            inc.category.replace("_", " "),
                                            style = MaterialTheme.typography.titleMedium.copy(
                                                fontFamily = FontFamily.Monospace,
                                                fontWeight = FontWeight.Bold
                                            ),
                                            color = TextPrimary
                                        )
                                        Text(
                                            text = "CASE: ${inc.incidentId.take(16)}...",
                                            style = MaterialTheme.typography.labelSmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 10.sp
                                            ),
                                            color = TextTertiary
                                        )
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        StatusBadge(text = inc.risk, color = riskColor, isPulsing = inc.risk.uppercase() in listOf("HIGH", "CRITICAL"))
                                        StatusBadge(text = inc.status, color = statusColor, isPulsing = false)
                                    }
                                }
                                
                                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(vertical = 10.dp))
                                
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    MetricDisplay("CORRELATED EVENTS", inc.eventCount.toString(), ElectricCyan, modifier = Modifier.weight(1f))
                                    MetricDisplay("AFFECTED ASSETS", inc.affectedAssets.size.toString(), TextPrimary, modifier = Modifier.weight(1f))
                                }

                                if (inc.recommendations.isNotEmpty()) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(
                                        text = "REMEDIATION: ${inc.recommendations.first()}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = TextSecondary
                                    )
                                }

                                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(vertical = 10.dp))

                                // PRIMARY ACTIONS: INVESTIGATE & COPILOT PLAYBOOK
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    CyberButton(
                                        text = if (isDetailsExpanded) "COLLAPSE" else "INVESTIGATE",
                                        onClick = {
                                            expandedIncidentId = if (isDetailsExpanded) null else inc.incidentId
                                            if (!isDetailsExpanded && inc.status == "NEW") {
                                                coroutineScope.launch {
                                                    try {
                                                        viewModel.connectionManager.api?.updateIncidentStatus(
                                                            inc.incidentId,
                                                            IncidentUpdateStatusRequest("INVESTIGATING", "Analyst investigation initiated on mobile")
                                                        )
                                                        refreshTrigger++
                                                    } catch (ignored: Exception) {}
                                                }
                                            }
                                        },
                                        variant = CyberButtonVariant.OUTLINED,
                                        modifier = Modifier.weight(1f)
                                    )

                                    if (inc.status != "RESOLVED") {
                                        CyberButton(
                                            text = "RESOLVE",
                                            onClick = {
                                                coroutineScope.launch {
                                                    try {
                                                        viewModel.connectionManager.api?.updateIncidentStatus(
                                                            inc.incidentId,
                                                            IncidentUpdateStatusRequest("RESOLVED", "Incident verified resolved by operator")
                                                        )
                                                        refreshTrigger++
                                                    } catch (ignored: Exception) {}
                                                }
                                            },
                                            variant = CyberButtonVariant.PRIMARY,
                                            modifier = Modifier.weight(1f)
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.height(8.dp))

                                // Real Incident-level Qwen LLM Playbook Trigger
                                CyberButton(
                                    text = if (isPlaybookActive) "HIDE QWEN PLAYBOOK" else "LAUNCH QWEN PLAYBOOK",
                                    onClick = {
                                        if (isPlaybookActive) {
                                            activePlaybookIncidentId = null
                                        } else {
                                            activePlaybookIncidentId = inc.incidentId
                                            playbookResult = null
                                            isPlaybookLoading = true
                                            playbookError = null
                                            coroutineScope.launch {
                                                try {
                                                    val api = viewModel.connectionManager.api
                                                    if (api != null) {
                                                        playbookResult = api.askQwenLlm(mapOf("incident_id" to inc.incidentId))
                                                    } else {
                                                        playbookError = "CORE CONNECTION OFFLINE"
                                                    }
                                                } catch (e: Exception) {
                                                    playbookError = e.message ?: "FAILED TO SYNTHESIZE PLAYBOOK"
                                                } finally {
                                                    isPlaybookLoading = false
                                                }
                                            }
                                        }
                                    },
                                    variant = CyberButtonVariant.SECONDARY,
                                    modifier = Modifier.fillMaxWidth(),
                                    icon = { Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(14.dp)) }
                                )

                                // EXPANDABLE INVESTIGATION DETAILS DRAWER
                                AnimatedVisibility(visible = isDetailsExpanded) {
                                    Column(modifier = Modifier.padding(top = 12.dp)) {
                                        HorizontalDivider(color = DividerColor)
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            text = "INVESTIGATION EVIDENCE & ASSET MATRIX",
                                            style = MaterialTheme.typography.labelSmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                color = CyberNeonCyan,
                                                fontWeight = FontWeight.Bold
                                            )
                                        )
                                        Spacer(modifier = Modifier.height(6.dp))
                                        
                                        if (inc.affectedAssets.isNotEmpty()) {
                                            Text("AFFECTED ASSETS:", style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp, color = TextTertiary))
                                            Spacer(modifier = Modifier.height(4.dp))
                                            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                                inc.affectedAssets.forEach { asset ->
                                                    StatusBadge(text = asset, color = ElectricCyan)
                                                }
                                            }
                                            Spacer(modifier = Modifier.height(8.dp))
                                        }

                                        Text(
                                            text = "First seen: ${inc.firstSeen} • Last seen: ${inc.lastSeen}",
                                            style = MaterialTheme.typography.bodySmall.copy(
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 10.sp,
                                                color = TextTertiary
                                            )
                                        )

                                        Spacer(modifier = Modifier.height(10.dp))
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            if (inc.status != "CONTAINED") {
                                                CyberButton(
                                                    text = "CONTAIN THREAT",
                                                    onClick = {
                                                        coroutineScope.launch {
                                                            try {
                                                                viewModel.connectionManager.api?.updateIncidentStatus(
                                                                    inc.incidentId,
                                                                    IncidentUpdateStatusRequest("CONTAINED", "Threat perimeter quarantined")
                                                                )
                                                                refreshTrigger++
                                                            } catch (ignored: Exception) {}
                                                        }
                                                    },
                                                    variant = CyberButtonVariant.OUTLINED,
                                                    modifier = Modifier.weight(1f)
                                                )
                                            }
                                        }
                                    }
                                }

                                // EXPANDABLE COPILOT PLAYBOOK DRAWER (Directly Synthesized from Real Incident)
                                AnimatedVisibility(visible = isPlaybookActive) {
                                    Column(modifier = Modifier.padding(top = 12.dp)) {
                                        HorizontalDivider(color = DividerColor)
                                        Spacer(modifier = Modifier.height(10.dp))

                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = "AUTONOMOUS INCIDENT RESPONSE PLAYBOOK",
                                                style = MaterialTheme.typography.labelSmall.copy(
                                                    fontFamily = FontFamily.Monospace,
                                                    fontWeight = FontWeight.Bold,
                                                    color = CyberNeonCyan
                                                )
                                            )
                                            if (isPlaybookLoading) {
                                                StatusBadge(text = "SYNTHESIZING...", color = CyberNeonCyan)
                                            } else if (playbookResult != null) {
                                                StatusBadge(text = "ADVISORY READY", color = StatusOnline)
                                            }
                                        }

                                        if (isPlaybookLoading) {
                                            Spacer(modifier = Modifier.height(8.dp))
                                            LinearProgressIndicator(
                                                modifier = Modifier.fillMaxWidth().height(2.dp),
                                                color = CyberNeonCyan,
                                                trackColor = DividerColor
                                            )
                                            Spacer(modifier = Modifier.height(6.dp))
                                            Text(
                                                text = "Synthesizing MITRE ATT&CK techniques, Kill Chain phase, and incident response playbook...",
                                                style = MaterialTheme.typography.bodySmall.copy(
                                                    fontFamily = FontFamily.Monospace,
                                                    fontSize = 10.sp,
                                                    color = TextSecondary
                                                )
                                            )
                                        }

                                        if (playbookError != null) {
                                            Spacer(modifier = Modifier.height(8.dp))
                                            Text(
                                                text = "Playbook Generation Notice: $playbookError",
                                                style = MaterialTheme.typography.bodySmall.copy(color = StatusWarning, fontSize = 11.sp)
                                            )
                                        }

                                        playbookResult?.let { pb ->
                                            Spacer(modifier = Modifier.height(10.dp))

                                            val briefing = pb.executiveSummary ?: pb.executiveBriefing ?: pb.threatNarrative ?: pb.narrative
                                            if (!briefing.isNullOrBlank()) {
                                                Text(
                                                    text = "EXECUTIVE BRIEFING:",
                                                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, color = CyberBlue)
                                                )
                                                Spacer(modifier = Modifier.height(4.dp))
                                                Text(briefing, style = MaterialTheme.typography.bodySmall, color = TextPrimary)
                                                Spacer(modifier = Modifier.height(8.dp))
                                            }

                                            // Playbook Steps
                                            val steps = pb.incidentResponsePlaybook ?: emptyList()
                                            if (steps.isNotEmpty()) {
                                                Text(
                                                    text = "ACTIONABLE RESPONSE PLAYBOOK:",
                                                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, color = StatusWarning)
                                                )
                                                Spacer(modifier = Modifier.height(4.dp))
                                                steps.forEach { step ->
                                                    Row(modifier = Modifier.padding(vertical = 3.dp), verticalAlignment = Alignment.Top) {
                                                        Text("▶ ", color = StatusWarning, fontSize = 10.sp)
                                                        Column {
                                                            if (!step.step.isNullOrBlank()) {
                                                                Text(
                                                                    text = step.step.uppercase(),
                                                                    style = MaterialTheme.typography.labelSmall.copy(
                                                                        fontSize = 10.sp,
                                                                        fontWeight = FontWeight.Bold,
                                                                        color = StatusWarning
                                                                    )
                                                                )
                                                            }
                                                            Text(
                                                                text = step.action ?: "",
                                                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp, color = TextSecondary)
                                                            )
                                                        }
                                                    }
                                                }
                                            }

                                            Spacer(modifier = Modifier.height(8.dp))
                                            Text(
                                                text = "ADVISORY ONLY",
                                                style = MaterialTheme.typography.bodySmall.copy(
                                                    fontFamily = FontFamily.Monospace,
                                                    fontSize = 9.sp,
                                                    color = TextTertiary
                                                )
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // RAW TELEMETRY LOG VIEW
            val filteredAlerts = alerts.filter { alert ->
                val matchesSearch = searchQuery.isBlank() ||
                    alert.alertLevel.contains(searchQuery, ignoreCase = true) ||
                    (alert.speakerId != null && alert.speakerId.contains(searchQuery, ignoreCase = true)) ||
                    (!alert.recommendationTitle.isNullOrEmpty() && alert.recommendationTitle.contains(searchQuery, ignoreCase = true))
                
                val matchesFilter = when (selectedSeverityFilter) {
                    "CRITICAL" -> alert.alertLevel.equals("CRITICAL", ignoreCase = true)
                    "HIGH" -> alert.alertLevel.equals("HIGH", ignoreCase = true)
                    else -> true
                }
                matchesSearch && matchesFilter
            }

            if (filteredAlerts.isEmpty()) {
                CyberGuardCard {
                    Text("NO RAW ALERTS DETECTED", style = MaterialTheme.typography.labelSmall, color = StatusOnline)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Zero raw anomalous signal frames logged across monitoring channels.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                    contentPadding = PaddingValues(bottom = 80.dp)
                ) {
                    items(filteredAlerts) { alert ->
                        CyberGuardCard {
                            val riskColor = when (alert.alertLevel.uppercase()) {
                                "CRITICAL" -> StatusCritical
                                "HIGH" -> StatusWarning
                                "MODERATE" -> StatusWarning
                                else -> StatusOnline
                            }
                            
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                StatusBadge(text = alert.alertLevel, color = riskColor, isPulsing = alert.alertLevel.uppercase() in listOf("HIGH", "CRITICAL"))
                                Text(
                                    text = if (alert.timestamp > 0.0) alert.timestamp.toString() else "LIVE",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 9.sp
                                    ),
                                    color = TextTertiary
                                )
                            }
                            
                            HorizontalDivider(color = DividerColor, modifier = Modifier.padding(vertical = 10.dp))
                            
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                MetricDisplay("RISK SCORE", String.format(Locale.US, "%.3f", alert.riskScore), riskColor)
                                if (alert.speakerId != null) {
                                    MetricDisplay("TARGET ID", alert.speakerId, TextPrimary)
                                }
                            }

                            if (!alert.recommendationTitle.isNullOrEmpty()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(alert.recommendationTitle.uppercase(), style = MaterialTheme.typography.labelSmall, color = CyberNeonCyan)
                                if (!alert.recommendationMessage.isNullOrEmpty()) {
                                    Text(alert.recommendationMessage, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
