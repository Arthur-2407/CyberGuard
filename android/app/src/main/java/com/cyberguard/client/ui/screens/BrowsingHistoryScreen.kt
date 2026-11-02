package com.cyberguard.client.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.cyberguard.client.model.BrowsingHistoryRecord
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BrowsingHistoryScreen(
    navController: NavController,
    viewModel: MainViewModel
) {
    val context = LocalContext.current
    val historyItems by viewModel.browsingHistory.collectAsState()
    val isRecordingActive by viewModel.isBrowsingHistoryRecordingActive.collectAsState()
    val isVpnArmed by viewModel.isVpnShieldArmed.collectAsState()

    var searchQuery by remember { mutableStateOf("") }
    var selectedFilter by remember { mutableStateOf("ALL") } // "ALL", "ALLOWED", "BLOCKED"
    var showClearConfirmDialog by remember { mutableStateOf(false) }

    val filteredItems = remember(historyItems, searchQuery, selectedFilter) {
        historyItems.filter { item ->
            val matchesSearch = searchQuery.isBlank() || item.domain.contains(searchQuery.trim(), ignoreCase = true)
            val matchesFilter = when (selectedFilter) {
                "ALLOWED" -> item.action.equals("ALLOWED", ignoreCase = true)
                "BLOCKED" -> item.action.equals("BLOCKED", ignoreCase = true)
                else -> true
            }
            matchesSearch && matchesFilter
        }
    }

    val totalDomains = historyItems.size
    val allowedCount = historyItems.count { it.action.equals("ALLOWED", ignoreCase = true) }
    val blockedCount = historyItems.count { it.action.equals("BLOCKED", ignoreCase = true) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            "BROWSING HISTORY",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.2.sp
                            ),
                            color = CyberNeonCyan
                        )
                        Text(
                            "DNS-Level Outbound Telemetry",
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                            color = TextSecondary
                        )
                    }
                },
                actions = {
                    IconButton(onClick = {
                        val textToCopy = historyItems.joinToString("\n") { "${it.domain} [${it.action}] (x${it.queryCount})" }
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        clipboard?.setPrimaryClip(ClipData.newPlainText("CyberGuard Browsing History", textToCopy))
                        Toast.makeText(context, "Exported ${historyItems.size} domains to clipboard", Toast.LENGTH_SHORT).show()
                    }) {
                        Icon(Icons.Default.Share, contentDescription = "Export History", tint = HologramTeal)
                    }
                    IconButton(onClick = { showClearConfirmDialog = true }) {
                        Icon(Icons.Default.DeleteSweep, contentDescription = "Clear History", tint = StatusCritical)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = DeepSpaceBackground)
            )
        },
        containerColor = DeepSpaceBackground
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // ── 1. Truthful Privacy Disclosure Banner ──
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, CardBorderSubtle, RoundedCornerShape(10.dp)),
                    colors = CardDefaults.cardColors(containerColor = ElevatedSurface),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(
                            Icons.Default.Info,
                            contentDescription = null,
                            tint = ElectricCyan,
                            modifier = Modifier
                                .size(20.dp)
                                .padding(top = 2.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                "DNS-OBSERVED ACTIVITY DISCLOSURE",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = ElectricCyan
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                "Entries reflect on-device DNS resolution queries intercepted by CyberGuard. " +
                                        "A logged query confirms domain resolution by an application, background sync, or asset prefetcher, " +
                                        "but does not indicate interactive user navigation, full URLs, page titles, or TLS-encrypted content.",
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp, lineHeight = 16.sp),
                                color = TextSecondary
                            )
                        }
                    }
                }
            }

            // ── 2. Telemetry Metrics Matrix ──
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    MetricCounterBox(
                        title = "TOTAL DOMAINS",
                        count = totalDomains.toString(),
                        accentColor = CyberNeonCyan,
                        modifier = Modifier.weight(1f)
                    )
                    MetricCounterBox(
                        title = "ALLOWED",
                        count = allowedCount.toString(),
                        accentColor = HologramTeal,
                        modifier = Modifier.weight(1f)
                    )
                    MetricCounterBox(
                        title = "BLOCKED",
                        count = blockedCount.toString(),
                        accentColor = StatusCritical,
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            // ── 3. Privacy Controls & Shield Status ──
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, HolographicGlowBorder, RoundedCornerShape(10.dp)),
                    colors = CardDefaults.cardColors(containerColor = ElevatedSurface),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(
                                    "DNS SHIELD PROTECTION",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold
                                    ),
                                    color = TextPrimary
                                )
                                Text(
                                    if (isVpnArmed) "ACTIVE (PROTECTED)" else "STANDBY (INACTIVE)",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                    color = if (isVpnArmed) HologramTeal else StatusWarning
                                )
                            }
                            Button(
                                onClick = {
                                    navController.navigate("device_security")
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = HighlightSurface,
                                    contentColor = CyberNeonCyan
                                ),
                                shape = RoundedCornerShape(6.dp),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                            ) {
                                Text(
                                    "Configure Shield",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace)
                                )
                            }
                        }

                        Divider(color = DividerColor, modifier = Modifier.padding(vertical = 10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(
                                    "RECORDING CONTROL",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold
                                    ),
                                    color = TextPrimary
                                )
                                Text(
                                    if (isRecordingActive) "Observing and indexing DNS queries" else "Recording paused by user",
                                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                    color = TextSecondary
                                )
                            }
                            Switch(
                                checked = isRecordingActive,
                                onCheckedChange = { active ->
                                    viewModel.setBrowsingHistoryRecording(active)
                                    Toast.makeText(
                                        context,
                                        if (active) "DNS History recording resumed" else "DNS History recording paused",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = HologramTeal,
                                    checkedTrackColor = HighlightSurface,
                                    uncheckedThumbColor = StatusOffline,
                                    uncheckedTrackColor = DeepSpaceBackground
                                )
                            )
                        }
                    }
                }
            }

            // ── 4. Search and Filter Controls ──
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = {
                            Text(
                                "Search observed domains...",
                                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                color = TextSecondary
                            )
                        },
                        leadingIcon = {
                            Icon(Icons.Default.Search, contentDescription = null, tint = CyberNeonCyan)
                        },
                        trailingIcon = {
                            if (searchQuery.isNotEmpty()) {
                                IconButton(onClick = { searchQuery = "" }) {
                                    Icon(Icons.Default.Close, contentDescription = "Clear", tint = TextSecondary)
                                }
                            }
                        },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedContainerColor = FieldBackground,
                            unfocusedContainerColor = FieldBackground,
                            focusedBorderColor = FieldBorderFocused,
                            unfocusedBorderColor = FieldBorderIdle,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        shape = RoundedCornerShape(8.dp),
                        singleLine = true
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        listOf("ALL", "ALLOWED", "BLOCKED").forEach { filterKey ->
                            val isSelected = selectedFilter == filterKey
                            FilterChip(
                                selected = isSelected,
                                onClick = { selectedFilter = filterKey },
                                label = {
                                    Text(
                                        filterKey,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                                        )
                                    )
                                },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = HighlightSurface,
                                    selectedLabelColor = if (filterKey == "BLOCKED") StatusCritical else CyberNeonCyan,
                                    containerColor = ElevatedSurface,
                                    labelColor = TextSecondary
                                ),
                                border = FilterChipDefaults.filterChipBorder(
                                    borderColor = if (isSelected) CyberNeonCyan else CardBorderSubtle,
                                    borderWidth = 1.dp,
                                    enabled = true,
                                    selected = isSelected
                                )
                            )
                        }
                    }
                }
            }

            // ── 5. Domain History Activity Log ──
            if (filteredItems.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 24.dp)
                            .border(1.dp, CardBorderSubtle, RoundedCornerShape(10.dp)),
                        colors = CardDefaults.cardColors(containerColor = ElevatedSurface)
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Icon(
                                Icons.Default.Language,
                                contentDescription = null,
                                tint = StatusOffline,
                                modifier = Modifier.size(48.dp)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text(
                                if (historyItems.isEmpty()) "NO OBSERVED DOMAIN ACTIVITY" else "NO MATCHING DOMAINS FOUND",
                                style = MaterialTheme.typography.titleSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold
                                ),
                                color = TextPrimary
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                if (historyItems.isEmpty())
                                    "When the Local DNS Domain Shield is active, device outbound DNS queries will be verified against malicious matrices and cataloged here."
                                else
                                    "Try adjusting your search criteria or filter selection.",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary,
                                modifier = Modifier.padding(horizontal = 16.dp)
                            )
                        }
                    }
                }
            } else {
                items(filteredItems, key = { it.id }) { item ->
                    DomainHistoryCard(
                        record = item,
                        onClick = {
                            navController.navigate("browsing_history_detail/${item.domain}")
                        },
                        onDelete = {
                            viewModel.deleteBrowsingHistoryRecord(item.id)
                            Toast.makeText(context, "Deleted ${item.domain}", Toast.LENGTH_SHORT).show()
                        }
                    )
                }
            }

            item {
                Spacer(modifier = Modifier.height(32.dp))
            }
        }
    }

    // Confirmation dialog for clearing all history
    if (showClearConfirmDialog) {
        AlertDialog(
            onDismissRequest = { showClearConfirmDialog = false },
            title = {
                Text(
                    "Clear Browsing History?",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    ),
                    color = TextPrimary
                )
            },
            text = {
                Text(
                    "This will delete all DNS-observed domain activity records on this device. This operation cannot be undone.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.clearBrowsingHistory()
                        showClearConfirmDialog = false
                        Toast.makeText(context, "Browsing history cleared", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = StatusCritical)
                ) {
                    Text("Clear All", color = Color.White)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirmDialog = false }) {
                    Text("Cancel", color = TextSecondary)
                }
            },
            containerColor = ElevatedSurface
        )
    }
}

@Composable
fun MetricCounterBox(
    title: String,
    count: String,
    accentColor: Color,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.border(1.dp, CardBorderSubtle, RoundedCornerShape(8.dp)),
        colors = CardDefaults.cardColors(containerColor = ElevatedSurface),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(
            modifier = Modifier.padding(10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                title,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    letterSpacing = 0.5.sp
                ),
                color = TextSecondary
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                count,
                style = MaterialTheme.typography.titleMedium.copy(
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold
                ),
                color = accentColor
            )
        }
    }
}

@Composable
fun DomainHistoryCard(
    record: BrowsingHistoryRecord,
    onClick: () -> Unit,
    onDelete: () -> Unit
) {
    val isBlocked = record.action.equals("BLOCKED", ignoreCase = true)
    val badgeColor = if (isBlocked) StatusCritical else HologramTeal
    val timeFormat = remember { SimpleDateFormat("HH:mm:ss · dd MMM", Locale.getDefault()) }
    val formattedTime = remember(record.lastSeenTimestamp) {
        timeFormat.format(Date(record.lastSeenTimestamp))
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, if (isBlocked) StatusCritical.copy(alpha = 0.5f) else CardBorderSubtle, RoundedCornerShape(8.dp))
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = ElevatedSurface),
        shape = RoundedCornerShape(8.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        record.domain,
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold
                        ),
                        color = TextPrimary,
                        maxLines = 1
                    )
                }

                Spacer(modifier = Modifier.height(4.dp))

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Action Badge
                    Surface(
                        color = badgeColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(4.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, badgeColor.copy(alpha = 0.4f))
                    ) {
                        Text(
                            if (isBlocked) "BLOCKED" else "ALLOWED",
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            ),
                            color = badgeColor
                        )
                    }

                    // Query count
                    Text(
                        "x${record.queryCount} queries",
                        style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, fontFamily = FontFamily.Monospace),
                        color = TextSecondary
                    )

                    // Time
                    Text(
                        "• $formattedTime",
                        style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
                        color = TextSecondary
                    )
                }

                if (record.resolvedIps.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "IPs: ${record.resolvedIps.take(3).joinToString(", ")}",
                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp, fontFamily = FontFamily.Monospace),
                        color = MutedSlate,
                        maxLines = 1
                    )
                }

                if (isBlocked && !record.blockReason.isNullOrBlank()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "Reason: ${record.blockReason}",
                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                        color = StatusCritical
                    )
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onDelete, modifier = Modifier.size(32.dp)) {
                    Icon(
                        Icons.Default.Close,
                        contentDescription = "Delete",
                        tint = TextSecondary,
                        modifier = Modifier.size(16.dp)
                    )
                }
                Icon(
                    Icons.Default.ChevronRight,
                    contentDescription = "View Details",
                    tint = CyberNeonCyan,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}
