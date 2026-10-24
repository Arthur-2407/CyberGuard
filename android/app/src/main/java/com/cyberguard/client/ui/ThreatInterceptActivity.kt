package com.cyberguard.client.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.cyberguard.client.MainActivity
import com.cyberguard.client.model.CallMonitorRepository
import com.cyberguard.client.model.MalwareThreatAlert
import com.cyberguard.client.ui.components.InteractiveMalwareAlertContent
import com.cyberguard.client.ui.theme.CyberGuardClientTheme
import java.io.File

/**
 * 50th-Century On-The-Spot Sideload & Malware Threat Interception Window.
 * Displays directly on top of package installers, web browsers, or system security scan dialogs
 * the millisecond an unverified or sideloaded APK is detected.
 */
class ThreatInterceptActivity : ComponentActivity() {

    private lateinit var repository: CallMonitorRepository
    private val alertState = mutableStateOf<MalwareThreatAlert?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        repository = CallMonitorRepository.getInstance(applicationContext)

        // Wake screen, turn on display, and show above keyguard/installer dialogs
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
            )
        }
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        parseAlertFromIntent(intent)

        setContent {
            CyberGuardClientTheme {
                val currentAlert by alertState

                if (currentAlert != null) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(Color.Black.copy(alpha = 0.72f))
                            .clickable(
                                interactionSource = remember { MutableInteractionSource() },
                                indication = null,
                                onClick = { /* Retain alert until explicit user decision */ }
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        InteractiveMalwareAlertContent(
                            alert = currentAlert!!,
                            onUninstall = {
                                val pkg = currentAlert!!.packageName
                                val sid = currentAlert!!.sessionId
                                
                                // 1. Abandon installer session if in flight
                                if (sid != -1 && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                                    try {
                                        packageManager.packageInstaller.abandonSession(sid)
                                    } catch (_: Exception) {}
                                }
                                
                                // 2. Delete APK file if known
                                currentAlert!!.apkPath?.let { path ->
                                    try {
                                        val file = File(path)
                                        if (file.exists()) file.delete()
                                    } catch (_: Exception) {}
                                }

                                // 3. Remove from quarantine records
                                val prefs = getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
                                val qSet = prefs.getStringSet("quarantined_packages", emptySet()) ?: emptySet()
                                prefs.edit().putStringSet("quarantined_packages", qSet - pkg).apply()

                                // 4. Launch official system uninstall prompt
                                try {
                                    val uri = Uri.fromParts("package", pkg, null)
                                    val uninstallIntent = Intent(Intent.ACTION_DELETE, uri).apply {
                                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                                        putExtra(Intent.EXTRA_RETURN_RESULT, true)
                                    }
                                    startActivity(uninstallIntent)
                                } catch (_: Exception) {
                                    try {
                                        val fallbackIntent = Intent(Intent.ACTION_UNINSTALL_PACKAGE, Uri.fromParts("package", pkg, null)).apply {
                                            flags = Intent.FLAG_ACTIVITY_NEW_TASK
                                        }
                                        startActivity(fallbackIntent)
                                    } catch (_: Exception) {}
                                }
                                repository.dismissMalwareAlert()
                                finish()
                            },
                            onQuarantine = {
                                // Forced quarantine already active, safe fallback
                                val prefs = getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
                                val currentSet = prefs.getStringSet("quarantined_packages", emptySet()) ?: emptySet()
                                prefs.edit().putStringSet("quarantined_packages", currentSet + currentAlert!!.packageName).apply()
                                repository.modifyInstalledApp(currentAlert!!.packageName) {
                                    it.copy(isQuarantined = true)
                                }
                                repository.dismissMalwareAlert()
                                finish()
                            },
                            onWhitelist = {
                                val pkg = currentAlert!!.packageName
                                val prefs = getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
                                val currentSet = prefs.getStringSet("whitelisted_packages", emptySet()) ?: emptySet()
                                prefs.edit().putStringSet("whitelisted_packages", currentSet + pkg).apply()
                                val qSet = prefs.getStringSet("quarantined_packages", emptySet()) ?: emptySet()
                                if (qSet.contains(pkg)) {
                                    prefs.edit().putStringSet("quarantined_packages", qSet - pkg).apply()
                                }
                                repository.modifyInstalledApp(pkg) {
                                    it.copy(isQuarantined = false, isWhitelisted = true)
                                }

                                // 1. Attempt to install APK via FileProvider if file path available or searchable in Downloads
                                val targetApk = currentAlert?.apkPath ?: run {
                                    try {
                                        val downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                                        if (downloadDir.exists() && downloadDir.isDirectory) {
                                            downloadDir.listFiles { f -> f.isFile && f.name.endsWith(".apk", ignoreCase = true) }
                                                ?.firstOrNull { f ->
                                                    try {
                                                        packageManager.getPackageArchiveInfo(f.absolutePath, 0)?.packageName == pkg
                                                    } catch (_: Exception) { false }
                                                }?.absolutePath
                                        } else null
                                    } catch (_: Exception) { null }
                                }

                                if (targetApk != null) {
                                    try {
                                        val file = File(targetApk)
                                        if (file.exists()) {
                                            val apkUri = androidx.core.content.FileProvider.getUriForFile(
                                                this@ThreatInterceptActivity,
                                                "${packageName}.provider",
                                                file
                                            )
                                            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                                                setDataAndType(apkUri, "application/vnd.android.package-archive")
                                                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
                                            }
                                            startActivity(installIntent)
                                        }
                                    } catch (e: Exception) {
                                        android.util.Log.w("ThreatInterceptActivity", "Failed to launch package installer: ${e.message}")
                                    }
                                } else {
                                    // Package already installed on device, launch or bring to foreground
                                    try {
                                        val launchIntent = packageManager.getLaunchIntentForPackage(pkg)
                                        if (launchIntent != null) {
                                            launchIntent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                                            startActivity(launchIntent)
                                        }
                                    } catch (_: Exception) {}
                                }
                                repository.dismissMalwareAlert()
                                finish()
                            },
                            onInspectDossier = {
                                val mainIntent = Intent(this@ThreatInterceptActivity, MainActivity::class.java).apply {
                                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                                    putExtra("navigate_to", "device_security")
                                }
                                startActivity(mainIntent)
                                repository.dismissMalwareAlert()
                                finish()
                            },
                            onDismiss = {
                                repository.dismissMalwareAlert()
                                finish()
                            }
                        )
                    }
                } else {
                    LaunchedEffect(Unit) {
                        finish()
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        parseAlertFromIntent(intent)
    }

    private fun parseAlertFromIntent(targetIntent: Intent?) {
        val pkg = targetIntent?.getStringExtra("package_name")
        if (!pkg.isNullOrBlank()) {
            val app = targetIntent.getStringExtra("app_name") ?: pkg.substringAfterLast(".")
            val riskScore = targetIntent.getFloatExtra("risk_score", 0.88f)
            val riskLevel = targetIntent.getStringExtra("risk_level") ?: "CRITICAL"
            val source = targetIntent.getStringExtra("installer_source") ?: "Direct APK Sideload"
            val sha256 = targetIntent.getStringExtra("sha256") ?: "N/A"
            val details = targetIntent.getStringExtra("threat_details") ?: "Sideloaded from unverified external origin. Bypassed official store verification."
            val perms = targetIntent.getStringArrayListExtra("sensitive_permissions") ?: arrayListOf()
            val category = targetIntent.getStringExtra("threat_category") ?: "UNOFFICIAL_SIDELOAD_MALWARE"
            val virusScan = targetIntent.getStringExtra("virus_scan_result") ?: "HIGH_ENTROPY_EXECUTABLE"
            val playProtect = targetIntent.getStringExtra("play_protect_status") ?: "NOT VERIFIED BY GOOGLE PLAY PROTECT"
            val aiRec = targetIntent.getStringExtra("ai_recommendation") ?: "Autonomous containment active. Immediate purge recommended to prevent device compromise."

            val sessionId = targetIntent.getIntExtra("session_id", -1)
            val isPreInstall = targetIntent.getBooleanExtra("is_pre_install", false)
            val apkPath = targetIntent.getStringExtra("apk_path")

            alertState.value = MalwareThreatAlert(
                packageName = pkg,
                appName = app,
                riskScore = riskScore,
                riskLevel = riskLevel,
                installerSource = source,
                sha256 = sha256,
                detectedThreatDetails = details,
                sensitivePermissions = perms,
                threatCategory = category,
                virusScanResult = virusScan,
                playProtectStatus = playProtect,
                aiAutonomousRecommendation = aiRec,
                sessionId = sessionId,
                isPreInstall = isPreInstall,
                apkPath = apkPath
            )
        } else {
            // Fallback to repository state
            alertState.value = repository.activeMalwareAlert.value
        }
    }
}
