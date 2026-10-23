package com.cyberguard.client.ui.screens

import androidx.compose.runtime.Composable
import androidx.navigation.NavController
import com.cyberguard.client.ui.MainViewModel

/**
 * Backward-compatibility proxy for CallMonitorScreen.
 * Seamlessly delegates to the upgraded CommsScreen.
 */
@Composable
fun CallMonitorScreen(navController: NavController, viewModel: MainViewModel) {
    CommsScreen(navController = navController, viewModel = viewModel)
}
