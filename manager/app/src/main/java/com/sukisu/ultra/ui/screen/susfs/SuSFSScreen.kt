package com.sukisu.ultra.ui.screen.susfs

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.screen.susfs.viewmodel.SuSFSViewModel

@Composable
fun SuSFSScreen(tab: String? = null) {
    val context = LocalContext.current
    val navigator = LocalNavigator.current
    val viewModel: SuSFSViewModel = viewModel()
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) { viewModel.loadInitial(context) }
    LaunchedEffect(tab) {
        tab?.let { id -> SuSFSTab.fromRouteId(id)?.let(viewModel::setSelectedTab) }
    }
    LaunchedEffect(state.selectedTab) {
        if (state.selectedTab == SuSFSTab.ENABLED_FEATURES) viewModel.loadEnabledFeatures(context)
    }
    val onBack = dropUnlessResumed { navigator.pop() }
    val content: @Composable () -> Unit = {
        SuSFSDialogs(state, viewModel)
        SuSFSTabContent(state, viewModel)
    }
    when (LocalUiMode.current) {
        UiMode.Miuix -> SuSFSMiuix(state, viewModel::setSelectedTab, onBack, content)
        UiMode.Material -> SuSFSMaterial(state, viewModel::setSelectedTab, onBack, content)
    }
}
