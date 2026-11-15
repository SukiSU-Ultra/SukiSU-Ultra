package com.sukisu.nova.ui.screen.builtinzygisk

import androidx.compose.runtime.Immutable
import com.sukisu.nova.data.model.Module
import com.sukisu.nova.ui.util.BuiltinZygiskConfig
import com.sukisu.nova.ui.util.BuiltinZygiskStatus
import com.sukisu.nova.ui.util.InjectedZygiskModule
import com.sukisu.nova.ui.util.ZygiskImplementationInfo

@Immutable
data class BuiltinZygiskUiState(
    val isLoading: Boolean = true,
    val status: BuiltinZygiskStatus = BuiltinZygiskStatus(),
    val implementation: ZygiskImplementationInfo = ZygiskImplementationInfo(),
    val config: BuiltinZygiskConfig = BuiltinZygiskConfig(),
    val zygiskModules: List<Module> = emptyList(),
    // Modules the built-in is serving, with the processes each one reaches.
    val injectedModules: List<InjectedZygiskModule> = emptyList(),
    // Injected module whose process rows are open, if any.
    val expandedInjectedId: String? = null,
    // Whether the served modules are listed in the status card.
    val injectedGroupExpanded: Boolean = true,
)

/// The localized state ksud reported for an injected module.
internal fun injectedStateText(state: String): Int = when (state) {
    "injected" -> com.sukisu.nova.R.string.builtin_zygisk_state_injected
    "loaded" -> com.sukisu.nova.R.string.builtin_zygisk_state_loaded
    "failed" -> com.sukisu.nova.R.string.builtin_zygisk_state_failed
    else -> com.sukisu.nova.R.string.builtin_zygisk_state_unknown
}

/// The localized state of one zygote's injection, from `zygote_<abi>_status`.
internal fun zygoteStateText(status: String): Int = when (status) {
    "injected" -> com.sukisu.nova.R.string.builtin_zygisk_state_injected
    else -> com.sukisu.nova.R.string.builtin_zygisk_zygote_not_injected
}

/// Title for a Zygisk state that still needs a soft restart to finish.
internal fun problemTitle(problem: String): Int = when (problem) {
    "pending" -> com.sukisu.nova.R.string.builtin_zygisk_pending_title
    else -> com.sukisu.nova.R.string.builtin_zygisk_switch_failed
}

/// Body for the same state.
internal fun problemMessage(problem: String): Int = when (problem) {
    "pending" -> com.sukisu.nova.R.string.builtin_zygisk_pending_message
    else -> com.sukisu.nova.R.string.builtin_zygisk_switch_failed_message
}
