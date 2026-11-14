package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.data.model.Module
import com.sukisu.ultra.ui.util.BuiltinZygiskConfig
import com.sukisu.ultra.ui.util.BuiltinZygiskStatus
import com.sukisu.ultra.ui.util.ZygiskImplementationInfo
import com.sukisu.ultra.ui.util.ZygiskProcesses

@Immutable
data class BuiltinZygiskUiState(
    val isLoading: Boolean = true,
    val isSwitching: Boolean = false,
    val status: BuiltinZygiskStatus = BuiltinZygiskStatus(),
    val implementation: ZygiskImplementationInfo = ZygiskImplementationInfo(),
    val config: BuiltinZygiskConfig = BuiltinZygiskConfig(),
    val zygiskModules: List<Module> = emptyList(),
    // Module whose process rows are open in the module list, if any.
    val expandedModuleId: String? = null,
    val moduleProcesses: ZygiskProcesses = ZygiskProcesses(),
)
