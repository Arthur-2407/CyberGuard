package com.cyberguard.client.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.cyberguard.client.network.*
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.launch
import java.util.Locale

enum class AdminConsoleTab { USERS, DETECTOR, AUDIT_LOGS }

@Composable
fun AdminConsoleScreen(navController: NavController, viewModel: MainViewModel) {
    val coroutineScope = rememberCoroutineScope()
    val scrollState = rememberScrollState()
    val currentUser by viewModel.currentUser.collectAsState()

    var selectedTab by remember { mutableStateOf(AdminConsoleTab.USERS) }

    // Users state
    var usersList by remember { mutableStateOf<List<AdminUserItem>>(emptyList()) }
    var isLoadingUsers by remember { mutableStateOf(false) }
    var userActionMessage by remember { mutableStateOf<String?>(null) }
    var showCreateUserDialog by remember { mutableStateOf(false) }
    var newUsername by remember { mutableStateOf("") }
    var newEmail by remember { mutableStateOf("") }
    var newPassword by remember { mutableStateOf("") }
    var newRole by remember { mutableStateOf("user") }

    // Training / Detector state
    var trainingStatus by remember { mutableStateOf<TrainingStatusResponse?>(null) }
    var isLoadingTraining by remember { mutableStateOf(false) }
    var isTriggeringRetrain by remember { mutableStateOf(false) }
    var retrainStatusMessage by remember { mutableStateOf<String?>(null) }

    // Audit logs state
    var auditLogs by remember { mutableStateOf<List<AdminAuditLogItem>>(emptyList()) }
    var isLoadingAudit by remember { mutableStateOf(false) }

    fun refreshUsers() {
        isLoadingUsers = true
        coroutineScope.launch {
            val res = viewModel.getAdminUsers()
            if (res.isSuccess) {
                usersList = res.getOrNull() ?: emptyList()
            }
            isLoadingUsers = false
        }
    }

    fun refreshTrainingStatus() {
        isLoadingTraining = true
        coroutineScope.launch {
            val res = viewModel.getTrainingStatus()
            if (res.isSuccess) {
                trainingStatus = res.getOrNull()
            }
            isLoadingTraining = false
        }
    }

    fun refreshAuditLogs() {
        isLoadingAudit = true
        coroutineScope.launch {
            val res = viewModel.getAdminAuditLogs()
            if (res.isSuccess) {
                auditLogs = res.getOrNull()?.logs ?: emptyList()
            }
            isLoadingAudit = false
        }
    }

    LaunchedEffect(selectedTab) {
        when (selectedTab) {
            AdminConsoleTab.USERS -> refreshUsers()
            AdminConsoleTab.DETECTOR -> refreshTrainingStatus()
            AdminConsoleTab.AUDIT_LOGS -> refreshAuditLogs()
        }
    }

    // CREATE USER MODAL
    if (showCreateUserDialog) {
        AlertDialog(
            onDismissRequest = { showCreateUserDialog = false },
            title = {
                Text(
                    "CREATE OPERATOR / ADMIN",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    ),
                    color = TextPrimary
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = newUsername,
                        onValueChange = { newUsername = it },
                        label = { Text("Username") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = newEmail,
                        onValueChange = { newEmail = it },
                        label = { Text("Email Address") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = newPassword,
                        onValueChange = { newPassword = it },
                        label = { Text("Initial Password") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Role: ", style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                        Spacer(modifier = Modifier.width(8.dp))
                        FilterChip(
                            selected = newRole == "user",
                            onClick = { newRole = "user" },
                            label = { Text("OPERATOR") }
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        FilterChip(
                            selected = newRole == "admin",
                            onClick = { newRole = "admin" },
                            label = { Text("ADMIN") }
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (newUsername.isNotBlank() && newPassword.isNotBlank()) {
                            coroutineScope.launch {
                                val req = CreateUserRequest(
                                    username = newUsername.trim(),
                                    email = newEmail.trim(),
                                    password = newPassword,
                                    role = newRole
                                )
                                val res = viewModel.createAdminUser(req)
                                if (res.isSuccess) {
                                    showCreateUserDialog = false
                                    newUsername = ""
                                    newEmail = ""
                                    newPassword = ""
                                    refreshUsers()
                                    userActionMessage = "User successfully created."
                                } else {
                                    userActionMessage = res.exceptionOrNull()?.message ?: "Failed to create user."
                                }
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = CyberNeonCyan, contentColor = DeepSpaceBackground),
                    shape = CutCornerShape(6.dp)
                ) {
                    Text("CREATE ID")
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { showCreateUserDialog = false }, shape = CutCornerShape(6.dp)) {
                    Text("CANCEL")
                }
            },
            containerColor = ElevatedSurface,
            shape = CutCornerShape(8.dp)
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(24.dp)
    ) {
        // TOP HEADER
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "ADMIN CONSOLE",
                    style = MaterialTheme.typography.headlineMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.5.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "TENANT MANAGEMENT & MODEL GOVERNANCE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 1.sp
                    ),
                    color = CyberNeonCyan
                )
            }
            StatusBadge("ADMIN", CyberNeonCyan)
        }

        Spacer(modifier = Modifier.height(18.dp))

        // TAB SWITCHER
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(CutCornerShape(8.dp))
                .background(HighlightSurface)
                .padding(4.dp)
        ) {
            listOf(
                Triple(AdminConsoleTab.USERS, "USERS", Icons.Default.Person),
                Triple(AdminConsoleTab.DETECTOR, "DETECTOR", Icons.Default.Settings),
                Triple(AdminConsoleTab.AUDIT_LOGS, "AUDIT", Icons.Default.List)
            ).forEach { (tab, label, icon) ->
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(CutCornerShape(6.dp))
                        .background(if (selectedTab == tab) CyberNeonCyan else Color.Transparent)
                        .clickable { selectedTab = tab }
                        .padding(vertical = 10.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = icon,
                            contentDescription = null,
                            tint = if (selectedTab == tab) DeepSpaceBackground else TextSecondary,
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.sp
                            ),
                            color = if (selectedTab == tab) DeepSpaceBackground else TextSecondary
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // =========================================================================
        // TAB 1: USERS & OPERATORS
        // =========================================================================
        if (selectedTab == AdminConsoleTab.USERS) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SectionHeader("REGISTERED OPERATORS (${usersList.size})")
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    IconButton(onClick = { refreshUsers() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberBlue, modifier = Modifier.size(18.dp))
                    }
                    Button(
                        onClick = { showCreateUserDialog = true },
                        colors = ButtonDefaults.buttonColors(containerColor = CyberNeonCyan, contentColor = DeepSpaceBackground),
                        shape = CutCornerShape(4.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("NEW USER", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp))
                    }
                }
            }

            userActionMessage?.let { msg ->
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = msg,
                    style = MaterialTheme.typography.bodySmall,
                    color = CyberNeonCyan
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            if (isLoadingUsers && usersList.isEmpty()) {
                Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = CyberNeonCyan)
                }
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    for (user in usersList) {
                        CyberGuardCard(
                            borderColor = if (user.role == "admin") CyberNeonCyan else DividerColor,
                            containerColor = ElevatedSurface
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            text = user.username.uppercase(),
                                            style = MaterialTheme.typography.titleMedium,
                                            color = TextPrimary
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        StatusBadge(
                                            text = user.role.uppercase(),
                                            color = if (user.role == "admin") CyberNeonCyan else CyberBlue
                                        )
                                    }
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        text = user.email ?: "no email registered",
                                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                        color = TextSecondary
                                    )
                                    Text(
                                        text = "ID #${user.id} • ${if (user.isActive) "ACTIVE ACCOUNT" else "SUSPENDED"}",
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontSize = 9.sp,
                                            color = if (user.isActive) StatusOnline else StatusCritical
                                        )
                                    )
                                }

                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    // Toggle active status
                                    Switch(
                                        checked = user.isActive,
                                        onCheckedChange = { active ->
                                            coroutineScope.launch {
                                                val res = viewModel.updateAdminUserStatus(user.id, active, null, null)
                                                if (res.isSuccess) {
                                                    refreshUsers()
                                                }
                                            }
                                        },
                                        colors = SwitchDefaults.colors(
                                            checkedThumbColor = DeepSpaceBackground,
                                            checkedTrackColor = StatusOnline,
                                            uncheckedThumbColor = TextTertiary,
                                            uncheckedTrackColor = HighlightSurface
                                        )
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // =========================================================================
        // TAB 2: DETECTOR & CONTINUOUS RETRAINING
        // =========================================================================
        if (selectedTab == AdminConsoleTab.DETECTOR) {
            SectionHeader("ACTIVE DETECTOR TELEMETRY")
            CyberGuardCard {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        StatusRow(
                            "PRODUCTION ENGINE",
                            trainingStatus?.currentProductionVersion ?: "v1.0-AASIST",
                            StatusOnline
                        )
                        StatusRow(
                            "PIPELINE STATUS",
                            if (trainingStatus?.isTraining == true) "RETRAINING ACTIVE" else "STANDBY / IDLE",
                            if (trainingStatus?.isTraining == true) StatusWarning else CyberBlue
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        StatusRow(
                            "APPROVED SAMPLES WAITING",
                            "${trainingStatus?.approvedSamplesInQueue ?: 0} SAMPLES",
                            if ((trainingStatus?.approvedSamplesInQueue ?: 0) > 0) StatusOnline else TextSecondary
                        )
                        StatusRow(
                            "WEIGHTS SHA-256",
                            trainingStatus?.weightsSha256?.take(12) ?: "verified",
                            TextTertiary
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // RETRAINING CONTROLS
            SectionHeader("CONTINUOUS RETRAINING CONTROL")
            CyberGuardCard(containerColor = ElevatedSurface) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        "TRIGGER RETRAINING PIPELINE",
                        style = MaterialTheme.typography.titleMedium,
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "Consolidates human ground-truth approved samples from the Training Review queue, computes candidate weights, and validates against validation F1 & EER benchmarks.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary
                    )

                    retrainStatusMessage?.let { msg ->
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(msg, style = MaterialTheme.typography.bodySmall, color = CyberNeonCyan)
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = {
                            isTriggeringRetrain = true
                            retrainStatusMessage = null
                            coroutineScope.launch {
                                val res = viewModel.triggerRetraining(epochs = 5, learningRate = 1e-4f)
                                isTriggeringRetrain = false
                                if (res.isSuccess) {
                                    retrainStatusMessage = "Retraining job successfully submitted to backend worker."
                                    refreshTrainingStatus()
                                } else {
                                    retrainStatusMessage = res.exceptionOrNull()?.message ?: "Retraining trigger failed."
                                }
                            }
                        },
                        enabled = !isTriggeringRetrain,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyberNeonCyan,
                            contentColor = DeepSpaceBackground
                        ),
                        shape = CutCornerShape(6.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (isTriggeringRetrain) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = DeepSpaceBackground, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("SUBMITTING JOB...", style = MaterialTheme.typography.labelSmall)
                        } else {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("INITIATE MODEL RETRAINING", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold))
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            // RECENT RUNS
            SectionHeader("RECENT TRAINING RUNS")
            val runs = trainingStatus?.recentRuns ?: emptyList()
            if (runs.isEmpty()) {
                CyberGuardCard {
                    Text("No prior retraining jobs recorded in database.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (run in runs) {
                        CyberGuardCard(
                            borderColor = if (run.status == "COMPLETED") StatusOnline else DividerColor,
                            containerColor = ElevatedSurface
                        ) {
                            Column(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = run.runId,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold
                                        ),
                                        color = TextPrimary
                                    )
                                    StatusBadge(
                                        text = run.status,
                                        color = when (run.status) {
                                            "COMPLETED" -> StatusOnline
                                            "RUNNING", "VALIDATING" -> StatusWarning
                                            else -> StatusCritical
                                        }
                                    )
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = "Base: ${run.baseVersion ?: "v1.0"} • Candidate: ${run.candidateVersion ?: "auto"} • Samples: ${run.sampleCount}",
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                    color = TextSecondary
                                )
                                if (run.valF1 != null) {
                                    Text(
                                        text = String.format(Locale.US, "Validation F1: %.3f • EER: %.3f", run.valF1, run.valEer ?: 0f),
                                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 9.sp),
                                        color = CyberBlue
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // =========================================================================
        // TAB 3: ADMIN AUDIT LOGS
        // =========================================================================
        if (selectedTab == AdminConsoleTab.AUDIT_LOGS) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                SectionHeader("AUDIT LOG (${auditLogs.size})")
                IconButton(onClick = { refreshAuditLogs() }) {
                    Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberBlue, modifier = Modifier.size(18.dp))
                }
            }

            if (isLoadingAudit && auditLogs.isEmpty()) {
                Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = CyberNeonCyan)
                }
            } else if (auditLogs.isEmpty()) {
                CyberGuardCard {
                    Text("No administrative audit entries logged yet.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (log in auditLogs) {
                        CyberGuardCard(
                            borderColor = DividerColor,
                            containerColor = ElevatedSurface
                        ) {
                            Column(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = log.action,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold
                                        ),
                                        color = CyberNeonCyan
                                    )
                                    Text(
                                        text = log.timestamp?.take(16)?.replace("T", " ") ?: "",
                                        style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp),
                                        color = TextTertiary
                                    )
                                }
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "Operator: ${log.actorUsername} (${log.actorRole ?: "ADMIN"}) • Target: ${log.targetEntity ?: "system"}/${log.targetId ?: ""}",
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                    color = TextSecondary
                                )
                                if (log.details.isNotBlank()) {
                                    Text(
                                        text = log.details,
                                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                                        color = TextTertiary,
                                        maxLines = 2,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(36.dp))
    }
}
