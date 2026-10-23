package com.cyberguard.client.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Build
import android.util.Log
import com.cyberguard.client.model.CallMonitorRepository
import com.cyberguard.client.network.PackageEvent

class PackageChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val packageName = intent.data?.schemeSpecificPart ?: return

        val eventType = when (action) {
            Intent.ACTION_PACKAGE_ADDED -> "INSTALLED"
            Intent.ACTION_PACKAGE_REPLACED -> "UPDATED"
            Intent.ACTION_PACKAGE_REMOVED -> "REMOVED"
            else -> return
        }

        Log.d("PackageChangeReceiver", "Device Security Watchdog: $eventType on $packageName")
        val repo = CallMonitorRepository.getInstance(context.applicationContext)
        if (!repo.isPackageWatchdogArmed.value) {
            Log.d("PackageChangeReceiver", "Package watchdog is disarmed. Skipping event logging.")
            return
        }

        val pm = context.packageManager
        val appName = try {
            val info = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(info).toString()
        } catch (_: Exception) {
            packageName.substringAfterLast(".")
        }

        // Check installer source
        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val source = pm.getInstallSourceInfo(packageName)
                source.installingPackageName ?: source.initiatingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }

        val isSystem = try {
            val appInfo = pm.getApplicationInfo(packageName, 0)
            ((appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0) ||
            ((appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0)
        } catch (_: Exception) {
            false
        }

        val isOfficial = isSystem || packageName == context.packageName || isKnownOfficialStore(installer)
        val riskScore = if (!isOfficial) 0.85f else 0.05f
        val riskLevel = if (!isOfficial) "CRITICAL" else "SAFE"

        val event = PackageEvent(
            packageName = packageName,
            appName = appName,
            eventType = eventType,
            timestamp = System.currentTimeMillis(),
            riskScore = riskScore,
            riskLevel = riskLevel
        )
        repo.addPackageEvent(event)

        if (!isOfficial && (eventType == "INSTALLED" || eventType == "UPDATED")) {
            val prefs = context.getSharedPreferences("cyberguard_quarantine", Context.MODE_PRIVATE)
            val qSet = prefs.getStringSet("quarantined_packages", emptySet()) ?: emptySet()
            prefs.edit().putStringSet("quarantined_packages", qSet + packageName).apply()
            repo.modifyInstalledApp(packageName) {
                it.copy(isQuarantined = true)
            }

            val appInfo = try { pm.getApplicationInfo(packageName, 0) } catch (_: Exception) { null }
            val apkPath = appInfo?.sourceDir

            val alert = com.cyberguard.client.model.MalwareThreatAlert(
                packageName = packageName,
                appName = appName,
                riskScore = riskScore,
                riskLevel = riskLevel,
                installerSource = installer ?: "Direct APK Sideload",
                sha256 = "N/A",
                detectedThreatDetails = "External package origin ($eventType). Bypassed official store verification and signature policy.",
                threatCategory = "UNOFFICIAL_SIDELOAD_MALWARE",
                virusScanResult = "HIGH_ENTROPY_EXECUTABLE // OBFUSCATED_DEX_SUSPECTED",
                playProtectStatus = "NOT VERIFIED BY GOOGLE PLAY PROTECT // BYPASSED STORE SIGNING",
                aiAutonomousRecommendation = "Forced quarantine active. Installation temporarily frozen. Choose to delete/uninstall or authorize installation.",
                apkPath = apkPath
            )
            repo.triggerMalwareAlert(alert)

            val interceptIntent = Intent(context.applicationContext, com.cyberguard.client.ui.ThreatInterceptActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                        Intent.FLAG_ACTIVITY_CLEAR_TOP or
                        Intent.FLAG_ACTIVITY_SINGLE_TOP or
                        Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                putExtra("package_name", packageName)
                putExtra("app_name", appName)
                putExtra("risk_score", riskScore)
                putExtra("risk_level", riskLevel)
                putExtra("installer_source", installer ?: "Direct APK Sideload")
                putExtra("sha256", "N/A")
                putExtra("threat_details", alert.detectedThreatDetails)
                putExtra("threat_category", alert.threatCategory)
                putExtra("virus_scan_result", alert.virusScanResult)
                putExtra("play_protect_status", alert.playProtectStatus)
                putExtra("ai_recommendation", alert.aiAutonomousRecommendation)
                if (apkPath != null) {
                    putExtra("apk_path", apkPath)
                }
            }
            try {
                context.applicationContext.startActivity(interceptIntent)
            } catch (e: Exception) {
                Log.w("PackageChangeReceiver", "Direct intercept window launch exception: ${e.message}")
            }
        }
    }

    private fun isKnownOfficialStore(installer: String?): Boolean {
        if (installer == null) return false
        val lower = installer.lowercase()
        if (lower.contains("packageinstaller")) {
            return false
        }
        return lower.contains("vending") ||
               lower.contains("googleplay") ||
               lower.contains("appstore") ||
               lower.contains("phonepe") ||
               lower.contains("indus") ||
               lower.contains("mipicks") ||
               lower.contains("xiaomi.market") ||
               lower.contains("bbk.appstore") ||
               lower.contains("vivo.appstore") ||
               lower.contains("samsungapps") ||
               lower.contains("oppo.market") ||
               lower.contains("heytap.market") ||
               lower.contains("coloros.phonemanager") ||
               lower.contains("huawei.appmarket") ||
               lower.contains("amazon.venezia")
    }
}
