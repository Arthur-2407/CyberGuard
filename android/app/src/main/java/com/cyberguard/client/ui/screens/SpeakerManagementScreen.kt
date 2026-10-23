package com.cyberguard.client.ui.screens

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Search
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
import androidx.navigation.NavController
import com.cyberguard.client.network.SpeakerInfo
import com.cyberguard.client.network.toUserFacingErrorMessage
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.io.FileOutputStream

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SpeakerManagementScreen(navController: NavController, viewModel: MainViewModel) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val currentUser by viewModel.currentUser.collectAsState()

    var speakers by remember { mutableStateOf<List<SpeakerInfo>>(emptyList()) }
    var searchQuery by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var refreshTrigger by remember { mutableStateOf(0) }

    // Enrollment form state
    var showEnrollDialog by remember { mutableStateOf(false) }
    var enrollName by remember { mutableStateOf("") }
    var enrollOrg by remember { mutableStateOf("") }
    var enrollRole by remember { mutableStateOf("") }
    var audioUris by remember { mutableStateOf<List<Uri>>(emptyList()) }
    var audioFileNames by remember { mutableStateOf<List<String>>(emptyList()) }
    var isEnrolling by remember { mutableStateOf(false) }
    var enrollFeedback by remember { mutableStateOf<String?>(null) }

    val audioFilePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetMultipleContents()) { uris: List<Uri> ->
        audioUris = uris
        val names = uris.map { uri ->
            var name = "sample.wav"
            val cursor = context.contentResolver.query(uri, null, null, null, null)
            cursor?.use { c ->
                val nameIndex = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (c.moveToFirst() && nameIndex >= 0) {
                    name = c.getString(nameIndex)
                }
            }
            name
        }
        audioFileNames = names
    }

    LaunchedEffect(refreshTrigger, currentUser) {
        if (currentUser == null) {
            speakers = emptyList()
            isLoading = false
            errorMessage = null
            return@LaunchedEffect
        }

        coroutineScope.launch {
            try {
                isLoading = true
                errorMessage = null
                val api = viewModel.connectionManager.api
                if (api != null) {
                    speakers = api.listSpeakers()
                } else {
                    errorMessage = "CyberGuard core server connection offline"
                }
            } catch (e: Exception) {
                if (e.message?.contains("401") == true) {
                    errorMessage = "Session expired. Please authenticate again to access trusted registry."
                    viewModel.logout()
                } else {
                    errorMessage = e.toUserFacingErrorMessage()
                }
            } finally {
                isLoading = false
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "SPEAKER PROFILES",
                    style = MaterialTheme.typography.headlineMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Black,
                        fontSize = 20.sp,
                        letterSpacing = 1.5.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "TRUSTED IDENTITY REGISTRY // BIO-ACOUSTIC ENCLAVE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 1.sp,
                        fontSize = 10.sp
                    ),
                    color = CyberNeonCyan
                )
            }

            if (currentUser != null) {
                CyberButton(
                    text = if (showEnrollDialog) "CANCEL" else "ENROLL",
                    onClick = { showEnrollDialog = !showEnrollDialog },
                    variant = if (showEnrollDialog) CyberButtonVariant.OUTLINED else CyberButtonVariant.PRIMARY,
                    icon = {
                        Icon(
                            imageVector = if (showEnrollDialog) Icons.Default.Close else Icons.Default.Add,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                )
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))

        // GUEST OPERATOR STATE (Tenant Isolation)
        if (currentUser == null) {
            CyberGuardCard(
                containerColor = HighlightSurface,
                borderColor = CyberBlue
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(CutCornerShape(8.dp))
                            .background(StatusWarning.copy(alpha = 0.15f))
                            .border(1.dp, StatusWarning.copy(alpha = 0.5f), CutCornerShape(8.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Lock,
                            contentDescription = null,
                            tint = StatusWarning,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "OPERATOR AUTHENTICATION REQUIRED",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            ),
                            color = StatusWarning
                        )
                        Text(
                            text = "TENANT-ISOLATED BIOMETRIC DATABASE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.sp
                            ),
                            color = TextTertiary
                        )
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))
                Text(
                    text = "The Trusted Identity Registry stores cryptographic voice embeddings inside your tenant-isolated database. You are currently in an ephemeral guest session. Authenticate with your operator profile to inspect or enroll trusted executive voice signatures.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary
                )

                Spacer(modifier = Modifier.height(16.dp))
                CyberButton(
                    text = "AUTHENTICATE OPERATOR",
                    onClick = { viewModel.showAuthModal.value = true },
                    modifier = Modifier.fillMaxWidth(),
                    icon = {
                        Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(16.dp))
                    }
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Informational Architecture Card
            CyberGuardCard {
                Text(
                    text = "[ BIO-ACOUSTIC REGISTRY SPECIFICATION ]",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    ),
                    color = CyberBlue
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "• Model: ECAPA-TDNN 192-Dimensional Neural Embeddings\n" +
                           "• Metric: Cosine Similarity against dynamic enrolled threshold\n" +
                           "• Privacy: Zero raw audio persistence; embeddings stored as mathematical vectors\n" +
                           "• Accuracy: Baidu NeurIPS benchmark recommends 3+ speech samples per speaker",
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                    color = TextSecondary
                )
            }
        } else {
            // ENROLLMENT SECTION (When Authenticated)
            if (showEnrollDialog) {
                CyberGuardCard(borderColor = CyberNeonCyan) {
                    Text(
                        text = "ENROLL NEW TRUSTED VOICE PROFILE",
                        style = MaterialTheme.typography.titleMedium.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold
                        ),
                        color = ElectricCyan
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Upload 1 to 5 reference voice samples to generate 192-D biometric neural embeddings.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary
                    )
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    CyberTextField(
                        value = enrollName,
                        onValueChange = { enrollName = it },
                        label = "EXECUTIVE / OPERATOR FULL NAME *",
                        placeholder = "e.g., Sarah Chen"
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        CyberTextField(
                            value = enrollOrg,
                            onValueChange = { enrollOrg = it },
                            label = "ORGANIZATION",
                            placeholder = "e.g., SOC Global",
                            modifier = Modifier.weight(1f)
                        )
                        CyberTextField(
                            value = enrollRole,
                            onValueChange = { enrollRole = it },
                            label = "ROLE / TITLE",
                            placeholder = "e.g., CISO / Lead Analyst",
                            modifier = Modifier.weight(1f)
                        )
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    OutlinedButton(
                        onClick = { audioFilePicker.launch("audio/*") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = CutCornerShape(6.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberNeonCyan),
                        border = BorderStroke(1.dp, CyberNeonCyan)
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (audioFileNames.isEmpty()) "SELECT AUDIO SAMPLES (*.WAV)" else "${audioFileNames.size} SAMPLE(S) SELECTED",
                            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold)
                        )
                    }

                    if (audioFileNames.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            audioFileNames.forEachIndexed { idx, name ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(HighlightSurface, CutCornerShape(4.dp))
                                        .padding(horizontal = 8.dp, vertical = 4.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "${idx + 1}. $name",
                                        style = MaterialTheme.typography.bodySmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontSize = 11.sp,
                                            color = TextPrimary
                                        )
                                    )
                                    StatusBadge(text = "READY", color = StatusOnline)
                                }
                            }
                        }
                    }

                    if (enrollFeedback != null) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = CutCornerShape(4.dp),
                            color = StatusWarning.copy(alpha = 0.12f),
                            border = BorderStroke(1.dp, StatusWarning.copy(alpha = 0.5f))
                        ) {
                            Text(
                                text = enrollFeedback!!,
                                style = MaterialTheme.typography.bodySmall,
                                color = StatusWarning,
                                modifier = Modifier.padding(10.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    CyberButton(
                        text = "SUBMIT VOICE ENROLLMENT",
                        onClick = {
                            if (enrollName.isNotBlank() && audioUris.isNotEmpty() && viewModel.connectionManager.api != null) {
                                isEnrolling = true
                                enrollFeedback = null

                                coroutineScope.launch {
                                    try {
                                        val parts = withContext(Dispatchers.IO) {
                                            audioUris.mapIndexed { idx, uri ->
                                                val fName = audioFileNames.getOrNull(idx) ?: "sample_$idx.wav"
                                                val temp = File(context.cacheDir, "enroll_$idx.wav")
                                                context.contentResolver.openInputStream(uri)?.use { input ->
                                                    FileOutputStream(temp).use { output -> input.copyTo(output) }
                                                }
                                                val req = temp.asRequestBody("audio/*".toMediaTypeOrNull())
                                                MultipartBody.Part.createFormData("files", fName, req)
                                            }
                                        }

                                        val nameBody = enrollName.trim().toRequestBody("text/plain".toMediaTypeOrNull())
                                        val orgBody = if (enrollOrg.isNotBlank()) enrollOrg.trim().toRequestBody("text/plain".toMediaTypeOrNull()) else null
                                        val roleBody = if (enrollRole.isNotBlank()) enrollRole.trim().toRequestBody("text/plain".toMediaTypeOrNull()) else null

                                        val api = viewModel.connectionManager.api
                                        if (api != null) {
                                            val resp = api.enrollSpeaker(nameBody, parts, null, orgBody, roleBody)
                                            enrollFeedback = "Enrolled: ${resp.name} (${resp.numSamples} samples)"
                                            enrollName = ""
                                            enrollOrg = ""
                                            enrollRole = ""
                                            audioUris = emptyList()
                                            audioFileNames = emptyList()
                                            showEnrollDialog = false
                                            refreshTrigger++
                                        }
                                    } catch (e: Exception) {
                                        enrollFeedback = "Enrollment error: ${e.toUserFacingErrorMessage()}"
                                    } finally {
                                        isEnrolling = false
                                    }
                                }
                            } else {
                                enrollFeedback = "Please provide Full Name and select at least 1 audio sample."
                            }
                        },
                        isLoading = isEnrolling,
                        enabled = enrollName.isNotBlank() && audioUris.isNotEmpty() && !isEnrolling,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
                Spacer(modifier = Modifier.height(20.dp))
            }

            if (isLoading) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator(color = CyberNeonCyan, strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "RETRIEVING REGISTERED IDENTITIES...",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                color = CyberNeonCyan
                            )
                        )
                    }
                }
            } else if (errorMessage != null) {
                CyberGuardCard(
                    containerColor = StatusCritical.copy(alpha = 0.12f),
                    borderColor = StatusCritical
                ) {
                    Text("REGISTRY RETRIEVAL NOTICE", style = MaterialTheme.typography.labelSmall, color = StatusCritical)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(errorMessage!!, style = MaterialTheme.typography.bodyMedium, color = TextPrimary)
                    Spacer(modifier = Modifier.height(16.dp))
                    CyberButton(
                        text = if (errorMessage!!.contains("authenticate", ignoreCase = true)) "AUTHENTICATE" else "RETRY",
                        onClick = {
                            if (errorMessage!!.contains("expired", ignoreCase = true) || errorMessage!!.contains("authenticate", ignoreCase = true)) {
                                viewModel.showAuthModal.value = true
                            } else {
                                refreshTrigger++
                            }
                        }
                    )
                }
            } else if (speakers.isEmpty()) {
                // INTENTIONAL, SOPHISTICATED EMPTY STATE (Addresses Screenshot 3)
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    CyberGuardCard(borderColor = CyberBlue.copy(alpha = 0.5f)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "BIO-ACOUSTIC REGISTRY STATUS",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        color = CyberNeonCyan
                                    )
                                )
                                Text(
                                    text = "TENANT ISOLATED // ZERO PROFILES REGISTERED",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 9.sp,
                                        color = TextTertiary
                                    )
                                )
                            }
                            StatusBadge(text = "EMPTY REGISTRY", color = StatusWarning)
                        }

                        HorizontalDivider(color = DividerColor, modifier = Modifier.padding(vertical = 12.dp))

                        Text(
                            text = "Speaker enrollment enables real-time acoustic identity verification during incoming voice communications. Without registered executive signatures, deepfake detection operates on synthetic acoustic artifacts alone without speaker identity cross-matching.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        CyberButton(
                            text = "ENROLL FIRST VOICE PROFILE",
                            onClick = { showEnrollDialog = true },
                            modifier = Modifier.fillMaxWidth(),
                            icon = {
                                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                            }
                        )
                    }

                    // Prerequisites & Guidelines Card
                    CyberGuardCard(containerColor = HighlightSurface) {
                        Text(
                            text = "[ ENROLLMENT PREREQUISITES & BEST PRACTICES ]",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                color = CyberBlue
                            )
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = "1. Reference Audio: 1 to 5 lossless PCM WAV files (3-10 sec duration).\n" +
                                   "2. Acoustic Environment: High signal-to-noise ratio (> 15 dB) without echo.\n" +
                                   "3. Identity Binding: Full legal name, organization, and tenant role.\n" +
                                   "4. Neural Extraction: ECAPA-TDNN computes 192-D d-vector embeddings.",
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                lineHeight = 18.sp
                            ),
                            color = TextPrimary
                        )
                    }

                    // Acoustic Telemetry Specification Card
                    CyberGuardCard {
                        Text(
                            text = "[ ACOUSTIC RECOGNITION SPECIFICATION ]",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                color = CyberBlue
                            )
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            MetricDisplay("NEURAL DIM", "192-D", ElectricCyan, modifier = Modifier.weight(1f))
                            MetricDisplay("SIMILARITY", "COSINE", TextPrimary, modifier = Modifier.weight(1f))
                            MetricDisplay("STORAGE", "ENCLAVE", StatusOnline, modifier = Modifier.weight(1f))
                        }
                    }
                }
            } else {
                // SEARCH & FILTER BAR
                CyberTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    label = "SEARCH TRUSTED REGISTRY",
                    placeholder = "Filter by name, role, organization, or ID...",
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextTertiary) }
                )

                Spacer(modifier = Modifier.height(14.dp))

                val filteredSpeakers = speakers.filter {
                    searchQuery.isBlank() ||
                    it.name.contains(searchQuery, ignoreCase = true) ||
                    (it.role?.contains(searchQuery, ignoreCase = true) == true) ||
                    (it.organization?.contains(searchQuery, ignoreCase = true) == true) ||
                    it.speakerId.contains(searchQuery, ignoreCase = true)
                }

                LazyColumn(verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    items(filteredSpeakers) { speaker ->
                        CyberGuardCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = speaker.name.uppercase(),
                                        style = MaterialTheme.typography.titleMedium.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold
                                        ),
                                        color = TextPrimary
                                    )
                                    if (!speaker.role.isNullOrEmpty() || !speaker.organization.isNullOrEmpty()) {
                                        val subtitle = listOfNotNull(speaker.role, speaker.organization).joinToString(" • ")
                                        Text(subtitle, style = MaterialTheme.typography.bodySmall, color = ElectricCyan)
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = "REGISTRY ID: ${speaker.speakerId}",
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                            fontSize = 9.sp
                                        ),
                                        color = TextTertiary
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        StatusBadge(text = "${speaker.numSamples} ACOUSTIC SAMPLES", color = CyberNeonCyan)
                                        StatusBadge(text = "VERIFIED IDENTITY", color = StatusOnline)
                                    }
                                }
                                CyberButton(
                                    text = "REVOKE",
                                    onClick = {
                                        coroutineScope.launch {
                                            try {
                                                viewModel.connectionManager.api?.deleteSpeaker(speaker.speakerId)
                                                refreshTrigger++
                                            } catch (e: Exception) {
                                                errorMessage = e.toUserFacingErrorMessage()
                                            }
                                        }
                                    },
                                    variant = CyberButtonVariant.DESTRUCTIVE
                                )
                            }
                        }
                    }
                    item {
                        Spacer(modifier = Modifier.height(36.dp))
                    }
                }
            }
        }
    }
}
