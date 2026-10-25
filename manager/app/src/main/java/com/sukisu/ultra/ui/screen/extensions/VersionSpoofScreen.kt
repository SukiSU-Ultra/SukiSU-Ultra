package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator

/** Navigation and state wiring only; no shell commands or layout logic. */
@Composable
fun VersionSpoofScreen() {
    val navigator = LocalNavigator.current
    val model: VersionSpoofViewModel = viewModel()
    val state by model.uiState.collectAsStateWithLifecycle()
    val actions = VersionSpoofActions(
        onBack = { navigator.pop() },
        onVersion = model::editVersion,
        onFull = model::editFull,
        onUapi = model::editUapi,
        onAcknowledge = model::acknowledge,
        onHideWarning = model::hideWarning,
        onSave = { model.apply() },
        onReset = { model.apply(reset = true) },
        onReload = model::reload,
    )
    if (LocalUiMode.current == UiMode.Miuix) {
        VersionSpoofMiuix(state, actions, model.managerVersion, model.managerUapi)
    } else {
        VersionSpoofMaterial(state, actions, model.managerVersion, model.managerUapi)
    }
}

internal data class VersionSpoofActions(
    val onBack: () -> Unit,
    val onVersion: (String) -> Unit,
    val onFull: (String) -> Unit,
    val onUapi: (String) -> Unit,
    val onAcknowledge: (Boolean) -> Unit,
    val onHideWarning: (Boolean) -> Unit,
    val onSave: () -> Unit,
    val onReset: () -> Unit,
    val onReload: () -> Unit,
)
