package com.sukisu.nova.ui.screen.kpm

import androidx.compose.runtime.Immutable
import com.sukisu.nova.ui.component.ConfigResult
import com.sukisu.nova.ui.viewmodel.KpmViewModel

@Immutable
data class KpmUiState(
    val operationResults: List<ConfigResult> = emptyList(),
    val isRefreshing: Boolean = false,
    val isBusy: Boolean = false,
    val hasLoaded: Boolean = false,
    val moduleList: List<KpmViewModel.ModuleInfo> = emptyList(),
    val searchQuery: String = "",
    val error: Throwable? = null,
    val showInstallModeDialog: Boolean = false,
    val tempModuleName: String? = null,
    val inputDialogState: InputDialogState = InputDialogState(),
) {
    val visibleModules: List<KpmViewModel.ModuleInfo>
        get() {
            val query = searchQuery.trim()
            return if (query.isEmpty()) moduleList else moduleList.filter { module ->
                listOf(module.id, module.name, module.description, module.author, module.version)
                    .any { it.contains(query, ignoreCase = true) }
            }
        }
}

@Immutable
data class InputDialogState(
    val visible: Boolean = false,
    val moduleId: String? = null,
    val args: String = "",
)

@Immutable
data class KpmActions(
    val onRefresh: () -> Unit,
    val onSearchTextChange: (String) -> Unit,
    val onRequestInstall: () -> Unit,
    val onConfirmInstall: (Boolean) -> Unit,
    val onDismissInstallDialog: () -> Unit,
    val onRequestUninstall: (String) -> Unit,
    val onShowInputDialog: (String) -> Unit,
    val onHideInputDialog: () -> Unit,
    val onInputArgsChange: (String) -> Unit,
    val onExecuteControl: () -> Unit,
)
