package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.data.model.Module
import com.sukisu.ultra.ui.util.BuiltinZygiskConfig
import com.sukisu.ultra.ui.util.BuiltinZygiskStatus
import com.sukisu.ultra.ui.util.InjectedZygiskModule
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
    // Modules the built-in is serving, with the processes each one reaches.
    val injectedModules: List<InjectedZygiskModule> = emptyList(),
    // Injected module whose process rows are open, if any.
    val expandedInjectedId: String? = null,
    // Module whose process rows are open in the module list, if any.
    val expandedModuleId: String? = null,
    val moduleProcesses: ZygiskProcesses = ZygiskProcesses(),
)

/// The localized state ksud reported for an injected module.
internal fun injectedStateText(state: String): Int = when (state) {
    "injected" -> com.sukisu.ultra.R.string.builtin_zygisk_state_injected
    "loaded" -> com.sukisu.ultra.R.string.builtin_zygisk_state_loaded
    "failed" -> com.sukisu.ultra.R.string.builtin_zygisk_state_failed
    else -> com.sukisu.ultra.R.string.builtin_zygisk_state_unknown
}
