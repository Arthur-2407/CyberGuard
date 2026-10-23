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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.cyberguard.client.network.ReviewDecisionRequest
import com.cyberguard.client.network.ReviewQueueItem
import com.cyberguard.client.network.ReviewQueueResponse
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.launch
import java.util.Locale

@Composable
fun TrainingReviewScreen(navController: NavController, viewModel: MainViewModel) {
    val coroutineScope = rememberCoroutineScope()
    val scrollState = rememberScrollState()

    var reviewData by remember { mutableStateOf<ReviewQueueResponse?>(null) }
    var isLoading by remember { mutableStateOf(false) }
    var selectedFilter by remember { mutableStateOf("PENDING") }
    var expandedReviewId by remember { mutableStateOf<String?>(null) }

    // Decision form state
    var selectedGroundTruth by remember { mutableStateOf<String?>("BONAFIDE") }
    var approveForTraining by remember { mutableStateOf(true) }
    var analystNotes by remember { mutableStateOf("") }
    var isSubmittingDecision by remember { mutableStateOf(false) }
    var decisionFeedback by remember { mutableStateOf<String?>(null) }

    fun refreshQueue() {
        isLoading = true
        coroutineScope.launch {
            val statusParam = if (selectedFilter == "ALL") null else selectedFilter
            val res = viewModel.getReviewQueue(status = statusParam)
            if (res.isSuccess) {
                reviewData = res.getOrNull()
            }
            isLoading = false
        }
    }

    LaunchedEffect(selectedFilter) {
        refreshQueue()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(24.dp)
    ) {
        // SCREEN TITLE
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "TRAINING REVIEW",
                    style = MaterialTheme.typography.headlineMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.5.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "HUMAN-IN-THE-LOOP CONTINUOUS LEARNING",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 1.sp
                    ),
                    color = CyberNeonCyan
                )
            }
            IconButton(onClick = { refreshQueue() }) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberNeonCyan)
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // QUEUE METRIC STRIP
        SectionHeader("REVIEW QUEUE METRICS")
        CyberGuardCard {
            Column(modifier = Modifier.fillMaxWidth()) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    MetricDisplay(
                        "PENDING",
                        (reviewData?.totalPending ?: 0).toString(),
                        StatusWarning,
                        modifier = Modifier.weight(1f)
                    )
                    MetricDisplay(
                        "APPROVED",
                        (reviewData?.totalApproved ?: 0).toString(),
                        StatusOnline,
                        modifier = Modifier.weight(1f)
                    )
                    MetricDisplay(
                        "REJECTED",
                        (reviewData?.totalRejected ?: 0).toString(),
                        StatusCritical,
                        modifier = Modifier.weight(1f)
                    )
                    MetricDisplay(
                        "RETRAIN QUEUE",
                        (reviewData?.totalTrainingQueued ?: 0).toString(),
                        CyberNeonCyan,
                        modifier = Modifier.weight(1.2f)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // STATUS FILTER CHIPS
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("PENDING", "APPROVED", "REJECTED", "ALL").forEach { status ->
                FilterChip(
                    selected = selectedFilter == status,
                    onClick = { selectedFilter = status },
                    label = {
                        Text(
                            text = status,
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp
                            )
                        )
                    }
                )
            }
        }

        decisionFeedback?.let { msg ->
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = msg,
                style = MaterialTheme.typography.bodySmall,
                color = CyberNeonCyan
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // REVIEW ITEMS LIST
        val items = reviewData?.items ?: emptyList()
        SectionHeader("SAMPLES FOR AUDIT (${items.size})")

        if (isLoading && items.isEmpty()) {
            Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = CyberNeonCyan)
            }
        } else if (items.isEmpty()) {
            CyberGuardCard {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "NO AUDIT SAMPLES IN QUEUE FOR FILTER '$selectedFilter'",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary
                    )
                }
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                for (item in items) {
                    val isExpanded = expandedReviewId == item.reviewId
                    val riskColor = when (item.alertLevel.uppercase()) {
                        "CRITICAL", "HIGH" -> StatusCritical
                        "SUSPICIOUS", "MEDIUM" -> StatusWarning
                        else -> StatusOnline
                    }

                    CyberGuardCard(
                        borderColor = if (item.status == "PENDING") StatusWarning else DividerColor,
                        containerColor = ElevatedSurface,
                        onClick = {
                            expandedReviewId = if (isExpanded) null else item.reviewId
                            selectedGroundTruth = item.groundTruthLabel ?: "BONAFIDE"
                            approveForTraining = item.approvedForTraining || true
                            analystNotes = item.notes ?: ""
                        }
                    ) {
                        Column(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = item.filename,
                                        style = MaterialTheme.typography.titleMedium,
                                        color = TextPrimary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        text = "ID: ${item.reviewId} • Submitter: ${item.submittedBy ?: item.username ?: "System"}",
                                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp),
                                        color = TextSecondary
                                    )
                                }
                                StatusBadge(item.status, when (item.status) {
                                    "APPROVED" -> StatusOnline
                                    "PENDING" -> StatusWarning
                                    else -> StatusCritical
                                })
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                val synthText = if (item.nativeProbability != null)
                                    String.format(Locale.US, "Synthetic Prob: %.1f%%", item.nativeProbability * 100)
                                    else "Risk: ${item.alertLevel}"
                                Text(
                                    text = synthText,
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 10.sp
                                    ),
                                    color = riskColor
                                )

                                Text(
                                    text = if (isExpanded) "CLOSE REVIEW ▲" else "AUDIT & LABEL ▼",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 10.sp,
                                        color = CyberBlue
                                    )
                                )
                            }

                            // EXPANDED DECISION & LABELING FORM
                            AnimatedVisibility(visible = isExpanded) {
                                Column(modifier = Modifier.padding(top = 14.dp)) {
                                    HorizontalDivider(color = DividerColor)
                                    Spacer(modifier = Modifier.height(10.dp))

                                    Text(
                                        "ASSIGN GROUND-TRUTH LABEL:",
                                        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                        color = CyberNeonCyan
                                    )
                                    Spacer(modifier = Modifier.height(6.dp))

                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Button(
                                            onClick = { selectedGroundTruth = "BONAFIDE" },
                                            colors = ButtonDefaults.buttonColors(
                                                containerColor = if (selectedGroundTruth == "BONAFIDE") StatusOnline else HighlightSurface,
                                                contentColor = if (selectedGroundTruth == "BONAFIDE") DeepSpaceBackground else TextSecondary
                                            ),
                                            shape = CutCornerShape(4.dp),
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Text("BONAFIDE (HUMAN)", style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp))
                                        }

                                        Button(
                                            onClick = { selectedGroundTruth = "SPOOF" },
                                            colors = ButtonDefaults.buttonColors(
                                                containerColor = if (selectedGroundTruth == "SPOOF") StatusCritical else HighlightSurface,
                                                contentColor = if (selectedGroundTruth == "SPOOF") DeepSpaceBackground else TextSecondary
                                            ),
                                            shape = CutCornerShape(4.dp),
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Text("SPOOF (CLONED)", style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp))
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(8.dp))

                                    // Checkbox for training promotion
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Checkbox(
                                            checked = approveForTraining,
                                            onCheckedChange = { approveForTraining = it },
                                            colors = CheckboxDefaults.colors(
                                                checkedColor = CyberNeonCyan,
                                                checkmarkColor = DeepSpaceBackground
                                            )
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            "Approve sample for continuous detector retraining",
                                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                            color = TextPrimary
                                        )
                                    }

                                    Spacer(modifier = Modifier.height(8.dp))

                                    OutlinedTextField(
                                        value = analystNotes,
                                        onValueChange = { analystNotes = it },
                                        label = { Text("Analyst Verification Notes", style = MaterialTheme.typography.labelSmall) },
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth()
                                    )

                                    Spacer(modifier = Modifier.height(10.dp))

                                    Button(
                                        onClick = {
                                            if (selectedGroundTruth != null) {
                                                isSubmittingDecision = true
                                                decisionFeedback = null
                                                coroutineScope.launch {
                                                    val req = ReviewDecisionRequest(
                                                        reviewId = item.reviewId,
                                                        groundTruth = selectedGroundTruth,
                                                        decision = if (approveForTraining) "APPROVE" else "REJECT",
                                                        approveForTraining = approveForTraining,
                                                        notes = analystNotes,
                                                        triggerTraining = false
                                                    )
                                                    val res = viewModel.submitReviewDecision(item.reviewId, req)
                                                    isSubmittingDecision = false
                                                    if (res.isSuccess) {
                                                        decisionFeedback = "Decision recorded for ${item.reviewId}."
                                                        expandedReviewId = null
                                                        refreshQueue()
                                                    } else {
                                                        decisionFeedback = res.exceptionOrNull()?.message ?: "Failed to record decision."
                                                    }
                                                }
                                            }
                                        },
                                        enabled = !isSubmittingDecision && selectedGroundTruth != null,
                                        colors = ButtonDefaults.buttonColors(
                                            containerColor = CyberNeonCyan,
                                            contentColor = DeepSpaceBackground
                                        ),
                                        shape = CutCornerShape(6.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        if (isSubmittingDecision) {
                                            CircularProgressIndicator(modifier = Modifier.size(14.dp), color = DeepSpaceBackground, strokeWidth = 2.dp)
                                            Spacer(modifier = Modifier.width(8.dp))
                                            Text("SUBMITTING DECISION...", style = MaterialTheme.typography.labelSmall)
                                        } else {
                                            Text("COMMIT HUMAN AUDIT VERDICT", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold))
                                        }
                                    }
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
