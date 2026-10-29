package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.data.model.Module
import com.sukisu.ultra.ui.util.BuiltinZygiskStatus

@Immutable
data class BuiltinZygiskUiState(
    val isLoading: Boolean = true,
    val isRearming: Boolean = false,
    val status: BuiltinZygiskStatus = BuiltinZygiskStatus(),
    val zygiskModules: List<Module> = emptyList(),
)
