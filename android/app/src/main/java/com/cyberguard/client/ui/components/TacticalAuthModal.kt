package com.cyberguard.client.ui.components

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CutCornerShape
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
import androidx.compose.ui.text.input.*
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.theme.*
import kotlinx.coroutines.launch

/**
 * Shared Ultra-Futuristic Cyber Tactical Authentication & Registration Modal.
 * Usable from any screen in CyberGuard (Security Incidents, Dashboard, Comms, More Hub).
 */
@Composable
fun TacticalAuthModal(
    viewModel: MainViewModel,
    onDismiss: () -> Unit
) {
    val coroutineScope = rememberCoroutineScope()
    val keyboardController = LocalSoftwareKeyboardController.current

    var isRegisterMode by remember { mutableStateOf(false) }
    var authUsername by remember { mutableStateOf("") }
    var authEmail by remember { mutableStateOf("") }
    var authPassword by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var isSubmittingAuth by remember { mutableStateOf(false) }
    var authError by remember { mutableStateOf<String?>(null) }

    val isFormValid = if (isRegisterMode) {
        authUsername.isNotBlank() && authEmail.contains("@") && authPassword.length >= 6
    } else {
        authUsername.isNotBlank() && authPassword.isNotBlank()
    }

    AlertDialog(
        onDismissRequest = {
            if (!isSubmittingAuth) {
                authError = null
                onDismiss()
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
                            .size(36.dp)
                            .clip(CutCornerShape(6.dp))
                            .background(CyberNeonCyan.copy(alpha = 0.15f))
                            .border(1.dp, CyberNeonCyan.copy(alpha = 0.7f), CutCornerShape(6.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = if (isRegisterMode) Icons.Default.PersonAdd else Icons.Default.Lock,
                            contentDescription = null,
                            tint = CyberNeonCyan,
                            modifier = Modifier.size(20.dp)
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
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
            ) {
                // Tab Switcher: LOGIN vs REGISTER
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(CutCornerShape(6.dp))
                        .background(FieldBackground)
                        .border(1.dp, HolographicGlowBorder, CutCornerShape(6.dp))
                        .padding(3.dp)
                ) {
                    Surface(
                        onClick = {
                            isRegisterMode = false
                            authError = null
                        },
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
                                text = "SIGN IN",
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
                        onClick = {
                            isRegisterMode = true
                            authError = null
                        },
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
                            authError = null
                            onDismiss()
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
                                        authPassword = ""
                                        authError = null
                                        onDismiss()
                                    } else {
                                        authError = result.exceptionOrNull()?.message ?: "Authentication failed. Verify credentials."
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
