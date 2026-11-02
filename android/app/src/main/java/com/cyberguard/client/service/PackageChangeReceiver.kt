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
        val riskScore = if (!isOfficial) 0.35f else 0.05f
        val riskLevel = if (!isOfficial) "SUSPICIOUS" else "SAFE"

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
            val realSha256 = computeApkSha256(apkPath) ?: "PENDING_VERIFICATION"
            val entropy = computeShannonEntropy(apkPath)
            val scanEvidence = when {
                entropy != null && entropy > 7.4f -> "MEASURED_HIGH_ENTROPY (%.2f/8.0 - Packed/Encrypted)".format(entropy)
                entropy != null -> "MEASURED_NORMAL_ENTROPY (%.2f/8.0)".format(entropy)
                else -> "LOCAL_REPUTATION_UNVERIFIED (Awaiting Cloud AV Scan)"
            }

            val alert = com.cyberguard.client.model.MalwareThreatAlert(
                packageName = packageName,
                appName = appName,
                riskScore = riskScore,
                riskLevel = riskLevel,
                installerSource = installer ?: "Direct APK Sideload",
                sha256 = realSha256,
                detectedThreatDetails = "External package origin ($eventType). Bypassed official store verification and signature policy.",
                threatCategory = "UNVERIFIED_SIDELOAD_ORIGIN",
                virusScanResult = scanEvidence,
                playProtectStatus = "NOT VERIFIED BY GOOGLE PLAY PROTECT",
                aiAutonomousRecommendation = "Package flagged in CyberGuard monitoring database. Note: OS-level process freezing requires Android Device Owner privileges. Review declared permissions and choose to uninstall or trust application.",
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
                putExtra("sha256", realSha256)
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

    private fun computeApkSha256(apkPath: String?): String? {
        if (apkPath.isNullOrBlank()) return null
        return try {
            val file = java.io.File(apkPath)
            if (!file.exists() || !file.canRead()) return null
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            null
        }
    }

    private fun computeShannonEntropy(apkPath: String?): Float? {
        if (apkPath.isNullOrBlank()) return null
        return try {
            val file = java.io.File(apkPath)
            if (!file.exists() || !file.canRead()) return null
            val sampleSize = 65536
            val buffer = ByteArray(sampleSize)
            val bytesRead = file.inputStream().use { it.read(buffer) }
            if (bytesRead <= 0) return null

            val freqs = IntArray(256)
            for (i in 0 until bytesRead) {
                freqs[buffer[i].toInt() and 0xFF]++
            }
            var entropy = 0.0
            val total = bytesRead.toDouble()
            for (count in freqs) {
                if (count > 0) {
                    val p = count / total
                    entropy -= p * (Math.log(p) / Math.log(2.0))
                }
            }
            entropy.toFloat()
        } catch (_: Exception) {
            null
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
