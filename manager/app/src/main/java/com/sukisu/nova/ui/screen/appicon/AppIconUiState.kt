package com.sukisu.nova.ui.screen.appicon

import androidx.compose.runtime.Immutable
import com.sukisu.nova.ui.util.AppIconEntry
import com.sukisu.nova.ui.util.AppIconPack
import com.sukisu.nova.ui.util.BuiltinAppIcon

@Immutable
data class AppIconUiState(
    val selectedBuiltinId: String,
    val dynamicColor: Boolean = false,
    val packs: List<AppIconPack> = emptyList(),
    val loading: Boolean = true,
    val importing: Boolean = false,
    val pendingDelete: AppIconPack? = null,
)

@Immutable
data class AppIconActions(
    val onBack: () -> Unit,
    val onSelectBuiltin: (BuiltinAppIcon) -> Unit,
    val onSetDynamicColor: (Boolean) -> Unit,
    val onImportPack: () -> Unit,
    val onPinCustomIcon: (AppIconPack, AppIconEntry) -> Unit,
    val onRequestDeletePack: (AppIconPack) -> Unit,
    val onDismissDeletePack: () -> Unit,
    val onConfirmDeletePack: (AppIconPack) -> Unit,
)
