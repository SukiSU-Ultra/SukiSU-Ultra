package com.sukisu.ultra.ui.screen.module

import android.net.Uri
import androidx.compose.runtime.Immutable
import com.sukisu.ultra.data.registry.ExpectedFile
import com.sukisu.ultra.data.model.Module
import com.sukisu.ultra.data.model.ModuleUpdateInfo
import com.sukisu.ultra.ui.component.SearchStatus

enum class ModuleNameSort {
    DEFAULT,
    ASCENDING,
    DESCENDING;

    companion object {
        fun fromStored(name: String?): ModuleNameSort =
            entries.firstOrNull { it.name == name } ?: DEFAULT
    }
}

sealed interface ModuleConfirmRequest {
    data class Update(
        val module: Module,
        val downloadUrl: String,
        val fileName: String,
        /** Set when the update is a registry release: size + SHA-256 are enforced. */
        val expected: ExpectedFile? = null,
    ) : ModuleConfirmRequest

    data class Uninstall(
        val module: Module,
    ) : ModuleConfirmRequest
}

@Immutable
data class ModuleConfirmDialogState(
    val request: ModuleConfirmRequest,
    val title: String,
    val content: String? = null,
    val markdown: Boolean = false,
    val html: Boolean = false,
    /** Registry-hosted content: render with JavaScript off and network locked to the registry. */
    val restricted: Boolean = false,
    val confirm: String? = null,
    val dismiss: String? = null,
)

sealed interface ModuleEffect {
    data class Toast(
        val message: String,
    ) : ModuleEffect

    data class SnackBar(
        val message: String,
    ) : ModuleEffect
}

@Immutable
data class ModuleUiState(
    val isRefreshing: Boolean = false,
    val hasLoaded: Boolean = false,
    val modules: List<Module> = emptyList(),
    val moduleList: List<Module> = emptyList(),
    val updateInfo: Map<String, ModuleUpdateInfo> = emptyMap(),
    val searchStatus: SearchStatus = SearchStatus(""),
    val searchResults: List<Module> = emptyList(),
    val sortEnabledFirst: Boolean = false,
    val sortActionFirst: Boolean = false,
    val sortWebUiFirst: Boolean = false,
    val sortZygiskFirst: Boolean = false,
    val sortMetamoduleFirst: Boolean = false,
    val sortNameOrder: ModuleNameSort = ModuleNameSort.DEFAULT,
    val sortManual: Boolean = false,
    /** Module IDs in the user-defined order, used while [sortManual] is active. */
    val manualOrder: List<String> = emptyList(),
    val checkModuleUpdate: Boolean = true,
    val isSafeMode: Boolean = false,
    val magiskInstalled: Boolean = false,
    val confirmDialogState: ModuleConfirmDialogState? = null,
) {
    val installButtonVisible: Boolean
        get() = !(isSafeMode || magiskInstalled)
}

@Immutable
data class ModuleActions(
    val onRefresh: () -> Unit,
    val onSearchStatusChange: (SearchStatus) -> Unit,
    val onSearchTextChange: (String) -> Unit,
    val onClearSearch: () -> Unit,
    val onRequestUpdateConfirmation: (Module, ModuleUpdateInfo) -> Unit,
    val onRequestUninstallConfirmation: (Module) -> Unit,
    val onDismissConfirmRequest: () -> Unit,
    val onConfirmUpdate: (ModuleConfirmRequest.Update) -> Unit,
    val onOpenRepo: () -> Unit,
    val onToggleSortActionFirst: () -> Unit,
    val onToggleSortEnabledFirst: () -> Unit,
    val onToggleSortWebUiFirst: () -> Unit,
    val onToggleSortZygiskFirst: () -> Unit,
    val onToggleSortMetamoduleFirst: () -> Unit,
    val onSetSortNameOrder: (ModuleNameSort) -> Unit,
    val onToggleSortManual: () -> Unit,
    val onMoveModule: (Module, Module) -> Unit,
    val onCommitManualOrder: () -> Unit,
    val onOpenWebUi: (Module) -> Unit,
    val onToggleModule: (Module) -> Unit,
    val onUninstallModule: (Module) -> Unit,
    val onUndoUninstallModule: (Module) -> Unit,
    val onOpenFlash: (List<Uri>) -> Unit,
    val onExecuteModuleAction: (Module) -> Unit,
)
