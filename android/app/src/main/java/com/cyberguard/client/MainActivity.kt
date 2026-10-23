package com.cyberguard.client

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.Dialog
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.cyberguard.client.ui.BottomNavScreens
import com.cyberguard.client.ui.MainViewModel
import com.cyberguard.client.ui.Screen
import com.cyberguard.client.ui.CyberGuardNavHost
import com.cyberguard.client.ui.components.InteractiveMalwareAlertModal
import com.cyberguard.client.ui.components.TacticalAuthModal
import com.cyberguard.client.ui.theme.*

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CyberGuardClientTheme {
                val context = LocalContext.current
                val navController = rememberNavController()
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route
                
                // Hide bottom nav on splash screen
                val showBottomNav = currentRoute != Screen.Splash.route

                // Active background malware alert popup
                val activeMalwareAlert by viewModel.activeMalwareAlert.collectAsState()

                Scaffold(
                    bottomBar = {
                        if (showBottomNav) {
                            AnimatedCyberBottomBar(
                                currentRoute = currentRoute,
                                onNavigate = { screen ->
                                    if (currentRoute != screen.route) {
                                        navController.navigate(screen.route) {
                                            popUpTo(Screen.Dashboard.route) {
                                                inclusive = false
                                            }
                                            launchSingleTop = true
                                        }
                                    }
                                }
                            )
                        }
                    }
                ) { innerPadding ->
                    Surface(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        color = MaterialTheme.colorScheme.background
                    ) {
                        CyberGuardNavHost(navController = navController, viewModel = viewModel)
                    }
                }

                // ── Interactive Background Malware Threat Alert Popup ──
                activeMalwareAlert?.let { alert ->
                    InteractiveMalwareAlertModal(
                        alert = alert,
                        onUninstall = {
                            val pkg = alert.packageName
                            val sid = alert.sessionId
                            if (sid != -1 && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
                                try {
                                    context.packageManager.packageInstaller.abandonSession(sid)
                                } catch (_: Exception) {}
                            }
                            alert.apkPath?.let { path ->
                                try {
                                    val f = java.io.File(path)
                                    if (f.exists()) f.delete()
                                } catch (_: Exception) {}
                            }
                            val prefs = context.getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
                            val qSet = prefs.getStringSet("quarantined_packages", emptySet()) ?: emptySet()
                            prefs.edit().putStringSet("quarantined_packages", qSet - pkg).apply()

                            try {
                                val uri = Uri.fromParts("package", pkg, null)
                                val uninstallIntent = Intent(Intent.ACTION_DELETE, uri).apply {
                                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                                    putExtra(Intent.EXTRA_RETURN_RESULT, true)
                                }
                                context.startActivity(uninstallIntent)
                            } catch (_: Exception) {
                                try {
                                    val fallbackIntent = Intent(Intent.ACTION_UNINSTALL_PACKAGE, Uri.fromParts("package", pkg, null)).apply {
                                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                                    }
                                    context.startActivity(fallbackIntent)
                                } catch (_: Exception) {}
                            }
                            viewModel.dismissMalwareAlert()
                        },
                        onQuarantine = {
                            val prefs = context.getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
                            val currentSet = prefs.getStringSet("quarantined_packages", emptySet()) ?: emptySet()
                            prefs.edit().putStringSet("quarantined_packages", currentSet + alert.packageName).apply()
                            viewModel.modifyInstalledApp(alert.packageName) {
                                it.copy(isQuarantined = true)
                            }
                            viewModel.dismissMalwareAlert()
                        },
                        onWhitelist = {
                            val pkg = alert.packageName
                            val prefs = context.getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
                            val currentSet = prefs.getStringSet("whitelisted_packages", emptySet()) ?: emptySet()
                            prefs.edit().putStringSet("whitelisted_packages", currentSet + pkg).apply()
                            val qSet = prefs.getStringSet("quarantined_packages", emptySet()) ?: emptySet()
                            if (qSet.contains(pkg)) {
                                prefs.edit().putStringSet("quarantined_packages", qSet - pkg).apply()
                            }
                            viewModel.modifyInstalledApp(pkg) {
                                it.copy(isQuarantined = false, isWhitelisted = true)
                            }

                            val targetApk = alert.apkPath ?: run {
                                try {
                                    val downloadDir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
                                    if (downloadDir.exists() && downloadDir.isDirectory) {
                                        downloadDir.listFiles { f -> f.isFile && f.name.endsWith(".apk", ignoreCase = true) }
                                            ?.firstOrNull { f ->
                                                try {
                                                    context.packageManager.getPackageArchiveInfo(f.absolutePath, 0)?.packageName == pkg
                                                } catch (_: Exception) { false }
                                            }?.absolutePath
                                    } else null
                                } catch (_: Exception) { null }
                            }

                            if (targetApk != null) {
                                try {
                                    val file = java.io.File(targetApk)
                                    if (file.exists()) {
                                        val apkUri = androidx.core.content.FileProvider.getUriForFile(
                                            context,
                                            "${context.packageName}.provider",
                                            file
                                        )
                                        val installIntent = Intent(Intent.ACTION_VIEW).apply {
                                            setDataAndType(apkUri, "application/vnd.android.package-archive")
                                            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
                                        }
                                        context.startActivity(installIntent)
                                    }
                                } catch (e: Exception) {
                                    android.util.Log.w("MainActivity", "Failed to launch package installer: ${e.message}")
                                }
                            } else {
                                try {
                                    val launchIntent = context.packageManager.getLaunchIntentForPackage(pkg)
                                    if (launchIntent != null) {
                                        launchIntent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                                        context.startActivity(launchIntent)
                                    }
                                } catch (_: Exception) {}
                            }
                            viewModel.dismissMalwareAlert()
                        },
                        onInspectDossier = {
                            navController.navigate(Screen.DeviceSecurity.route) {
                                launchSingleTop = true
                            }
                            viewModel.dismissMalwareAlert()
                        },
                        onDismiss = {
                            viewModel.dismissMalwareAlert()
                        }
                    )
                }

                // ── Global Operator Authentication Modal ──
                val showAuthModal by viewModel.showAuthModal.collectAsState()
                if (showAuthModal) {
                    TacticalAuthModal(
                        viewModel = viewModel,
                        onDismiss = { viewModel.showAuthModal.value = false }
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.checkScreeningRoleStatus()
        viewModel.refreshScreenedCalls()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }
}

/**
 * Ultra-Futuristic, Highly Animated & Interactive Cyber Bottom Dock
 */
@Composable
fun AnimatedCyberBottomBar(
    currentRoute: String?,
    onNavigate: (Screen) -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "bottom_dock_anim")
    
    // Glimmer rotation for "More" glint
    val glintRotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(4000, easing = LinearEasing), RepeatMode.Restart),
        label = "glint_rot"
    )

    // Pulse for danger/amber indicators
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.45f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1200, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "pulse_alpha"
    )

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .border(
                BorderStroke(
                    1.dp,
                    Brush.verticalGradient(
                        listOf(HolographicGlowBorder.copy(alpha = 0.85f), Color.Transparent)
                    )
                )
            ),
        color = ElevatedSurface,
        tonalElevation = 12.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 6.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.SpaceAround,
            verticalAlignment = Alignment.CenterVertically
        ) {
            for (screen in BottomNavScreens) {
                val isSelected = currentRoute == screen.route

                // Scale animation on selection
                val scale by animateFloatAsState(
                    targetValue = if (isSelected) 1.08f else 1.0f,
                    animationSpec = spring(dampingRatio = 0.6f, stiffness = Spring.StiffnessMedium),
                    label = "tab_scale"
                )

                val contentColor by animateColorAsState(
                    targetValue = if (isSelected) CyberNeonCyan else TextTertiary,
                    animationSpec = tween(220),
                    label = "content_color"
                )

                val pillBgColor by animateColorAsState(
                    targetValue = if (isSelected) CyberNeonCyan.copy(alpha = 0.14f) else Color.Transparent,
                    animationSpec = tween(220),
                    label = "pill_bg"
                )

                Box(
                    modifier = Modifier
                        .scale(scale)
                        .clip(CutCornerShape(8.dp))
                        .background(pillBgColor)
                        .clickable(
                            indication = null,
                            interactionSource = remember { MutableInteractionSource() }
                        ) {
                            onNavigate(screen)
                        }
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            // Icon with tint
                            CompositionLocalProvider(LocalContentColor provides contentColor) {
                                screen.icon()
                            }

                            // Device Security: Animated Pulsing Amber Watchdog Badge
                            if (screen.route == Screen.DeviceSecurity.route) {
                                Box(
                                    modifier = Modifier
                                        .size(7.dp)
                                        .align(Alignment.TopEnd)
                                        .offset(x = 6.dp, y = (-2).dp)
                                        .clip(RoundedCornerShape(3.5.dp))
                                        .background(CyberAmber.copy(alpha = pulseAlpha))
                                )
                            }

                            // Comms: Live Radar Pulse Ring when selected
                            if (screen.route == Screen.Comms.route && isSelected) {
                                Canvas(
                                    modifier = Modifier
                                        .size(24.dp)
                                        .align(Alignment.Center)
                                ) {
                                    drawCircle(
                                        color = CyberNeonCyan.copy(alpha = 0.25f * pulseAlpha),
                                        radius = size.width * 0.7f,
                                        style = Stroke(width = 1.dp.toPx())
                                    )
                                }
                            }

                            // More: Holographic Rotating Star Glint
                            if (screen.route == Screen.More.route) {
                                Canvas(
                                    modifier = Modifier
                                        .size(14.dp)
                                        .align(Alignment.TopEnd)
                                        .offset(x = 7.dp, y = (-4).dp)
                                ) {
                                    rotate(glintRotation) {
                                        drawStarGlint(
                                            center = Offset(size.width / 2, size.height / 2),
                                            radius = 4.5.dp.toPx(),
                                            color = LensFlareWhite
                                        )
                                    }
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(3.dp))

                        Text(
                            text = screen.title,
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 9.5.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                letterSpacing = 0.5.sp
                            ),
                            color = contentColor,
                            maxLines = 1,
                            softWrap = false
                        )

                        // Subtle glowing holographic laser underline bracket for active tab
                        AnimatedVisibility(
                            visible = isSelected,
                            enter = fadeIn() + scaleIn(),
                            exit = fadeOut() + scaleOut()
                        ) {
                            Canvas(
                                modifier = Modifier
                                    .padding(top = 2.dp)
                                    .size(16.dp, 2.dp)
                            ) {
                                drawLine(
                                    color = CyberNeonCyan,
                                    start = Offset(0f, size.height / 2),
                                    end = Offset(size.width, size.height / 2),
                                    strokeWidth = 2.dp.toPx()
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
