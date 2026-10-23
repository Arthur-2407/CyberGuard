package com.cyberguard.client.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import com.cyberguard.client.ui.screens.*

sealed class Screen(val route: String, val title: String, val icon: @Composable () -> Unit) {
    object Splash : Screen("splash", "Splash", { Icon(Icons.Default.Build, contentDescription = null) })
    object Dashboard : Screen("dashboard", "Home", { Icon(Icons.Default.Home, contentDescription = "Home") })
    object ThreatCenter : Screen("threat_center", "Threats", { Icon(Icons.Default.Shield, contentDescription = "Threats") })
    object Comms : Screen("comms", "Comms", { Icon(Icons.Default.CellTower, contentDescription = "Comms") })
    object DeviceSecurity : Screen("device_security", "Device", { Icon(Icons.Default.PhoneAndroid, contentDescription = "Device") })
    object More : Screen("more", "More", { Icon(Icons.Default.Menu, contentDescription = "More") })

    // Secondary & Admin Destinations
    object Alerts : Screen("alerts", "Alerts", { Icon(Icons.Default.Warning, contentDescription = "Alerts") })
    object Speakers : Screen("speakers", "Speakers", { Icon(Icons.Default.GraphicEq, contentDescription = "Speakers") })
    object FileAnalysis : Screen("file_analysis", "Audio", { Icon(Icons.Default.Search, contentDescription = "Audio") })
    object LiveMonitor : Screen("live_monitor", "Monitor", { Icon(Icons.Default.PlayArrow, contentDescription = "Monitor") })
    object AdminConsole : Screen("admin_console", "Admin", { Icon(Icons.Default.AdminPanelSettings, contentDescription = "Admin") })
    object TrainingReview : Screen("training_review", "Training", { Icon(Icons.Default.Psychology, contentDescription = "Training") })

    // Legacy aliases
    val CallMonitor get() = Comms
}

val BottomNavScreens = listOf(
    Screen.Dashboard,
    Screen.ThreatCenter,
    Screen.Comms,
    Screen.DeviceSecurity,
    Screen.More
)

@Composable
fun CyberGuardNavHost(
    navController: NavHostController,
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    NavHost(navController = navController, startDestination = Screen.Splash.route, modifier = modifier) {
        composable(Screen.Splash.route) { SplashScreen(navController, viewModel) }
        composable(Screen.Dashboard.route) { DashboardScreen(navController, viewModel) }
        composable(Screen.ThreatCenter.route) { ThreatCenterScreen(navController, viewModel) }
        composable(Screen.Comms.route) { CommsScreen(navController, viewModel) }
        composable("call_monitor") { CommsScreen(navController, viewModel) } // Backward compatibility
        composable(Screen.DeviceSecurity.route) { DeviceSecurityScreen(navController, viewModel) }
        composable(Screen.More.route) { MoreHubScreen(navController, viewModel) }

        // Secondary destinations
        composable(Screen.Alerts.route) { AlertHistoryScreen(navController, viewModel) }
        composable(Screen.Speakers.route) { SpeakerManagementScreen(navController, viewModel) }
        composable(Screen.FileAnalysis.route) { FileAnalysisScreen(navController, viewModel) }
        composable(Screen.LiveMonitor.route) { LiveMonitorScreen(navController, viewModel) }

        // Admin-privileged destinations
        composable(Screen.AdminConsole.route) { AdminConsoleScreen(navController, viewModel) }
        composable(Screen.TrainingReview.route) { TrainingReviewScreen(navController, viewModel) }
    }
}

@Composable
fun VoiceGuardNavHost(
    navController: NavHostController,
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) = CyberGuardNavHost(navController = navController, viewModel = viewModel, modifier = modifier)
