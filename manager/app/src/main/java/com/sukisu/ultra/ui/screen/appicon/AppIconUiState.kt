package com.sukisu.ultra.ui.screen.appicon

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.ui.util.AppIconEntry
import com.sukisu.ultra.ui.util.AppIconPack
import com.sukisu.ultra.ui.util.BuiltinAppIcon

@Immutable
data class AppIconUiState(
    val selectedBuiltinId: String,
    val packs: List<AppIconPack> = emptyList(),
    val loading: Boolean = true,
    val importing: Boolean = false,
    val pendingDelete: AppIconPack? = null,
)

@Immutable
data class AppIconActions(
    val onBack: () -> Unit,
    val onSelectBuiltin: (BuiltinAppIcon) -> Unit,
    val onImportPack: () -> Unit,
    val onPinCustomIcon: (AppIconPack, AppIconEntry) -> Unit,
    val onRequestDeletePack: (AppIconPack) -> Unit,
    val onDismissDeletePack: () -> Unit,
    val onConfirmDeletePack: (AppIconPack) -> Unit,
)
