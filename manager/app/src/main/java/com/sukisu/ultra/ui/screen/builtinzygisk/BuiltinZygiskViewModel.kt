package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.data.repository.ModuleRepository
import com.sukisu.ultra.data.repository.ModuleRepositoryImpl
import com.sukisu.ultra.ui.util.getBuiltinZygiskConfig
import com.sukisu.ultra.ui.util.getBuiltinZygiskStatus
import com.sukisu.ultra.ui.util.getInjectedZygiskModules
import com.sukisu.ultra.ui.util.getZygiskImplementationInfo
import com.sukisu.ultra.ui.util.setBuiltinZygiskConfig
import com.sukisu.ultra.ui.util.switchToZygisk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class BuiltinZygiskViewModel(
    private val moduleRepo: ModuleRepository = ModuleRepositoryImpl()
) : ViewModel() {

    private val _uiState = MutableStateFlow(BuiltinZygiskUiState())
    val uiState = _uiState.asStateFlow()

    fun load() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            val status = withContext(Dispatchers.IO) { getBuiltinZygiskStatus() }
            val implementation = withContext(Dispatchers.IO) { getZygiskImplementationInfo() }
            val config = withContext(Dispatchers.IO) { getBuiltinZygiskConfig() }
            val injectedModules = withContext(Dispatchers.IO) { getInjectedZygiskModules() }
            val modulesResult = moduleRepo.getModules()
            val zygiskModules = modulesResult.getOrDefault(emptyList()).filter {
                it.zygisk || it.suppressedByBuiltin
            }
            _uiState.update {
                it.copy(
                    isLoading = false,
                    status = status,
                    implementation = implementation,
                    config = config,
                    injectedModules = injectedModules,
                    zygiskModules = zygiskModules,
                    expandedInjectedId = null
                )
            }
        }
    }

    /** Writes one option, then re-reads the file so the UI shows what ksud actually stored. */
    fun setOption(key: String, value: String, onFailure: () -> Unit) {
        viewModelScope.launch {
            val ok = withContext(Dispatchers.IO) { setBuiltinZygiskConfig(key, value) }
            val config = withContext(Dispatchers.IO) { getBuiltinZygiskConfig() }
            _uiState.update { it.copy(config = config) }
            if (!ok) onFailure()
        }
    }

    /**
     * Hands Zygisk to `target` and leaves the panel to the caller.
     *
     * The switch runs in the background: selecting a provider closes this dashboard and
     * asks for a restart anyway, so waiting here would only keep a panel the user cannot
     * use any more on screen.
     */
    fun switchInBackground(target: String, onResult: (Boolean) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val ok = switchToZygisk(target)
            // Toasts and Compose state belong to the main thread.
            withContext(Dispatchers.Main) { onResult(ok) }
        }
    }

    /** Opens or closes the process rows of an injected module. */
    fun toggleInjectedModule(id: String) {
        _uiState.update {
            it.copy(expandedInjectedId = if (it.expandedInjectedId == id) null else id)
        }
    }

    /** Opens or closes the served-module rows of the status card. */
    fun toggleInjectedGroup() {
        _uiState.update { it.copy(injectedGroupExpanded = !it.injectedGroupExpanded) }
    }
}
