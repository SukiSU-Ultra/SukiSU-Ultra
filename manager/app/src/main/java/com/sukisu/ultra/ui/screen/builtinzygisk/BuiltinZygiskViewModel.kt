package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.data.repository.ModuleRepository
import com.sukisu.ultra.data.repository.ModuleRepositoryImpl
import com.sukisu.ultra.ui.util.getBuiltinZygiskConfig
import com.sukisu.ultra.ui.util.getBuiltinZygiskStatus
import com.sukisu.ultra.ui.util.getZygiskImplementationInfo
import com.sukisu.ultra.ui.util.getZygiskProcesses
import com.sukisu.ultra.ui.util.setBuiltinZygiskConfig
import com.sukisu.ultra.ui.util.switchToZygisk
import com.sukisu.ultra.ui.util.ZygiskProcesses
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
                    zygiskModules = zygiskModules,
                    expandedModuleId = null,
                    moduleProcesses = ZygiskProcesses()
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

    /** Hands Zygisk to `target` (`builtin` or a module id) and reloads everything after it. */
    fun switchTo(target: String, onResult: (Boolean) -> Unit) {
        viewModelScope.launch {
            _uiState.update { it.copy(isSwitching = true) }
            val ok = withContext(Dispatchers.IO) { switchToZygisk(target) }
            val status = withContext(Dispatchers.IO) { getBuiltinZygiskStatus() }
            val implementation = withContext(Dispatchers.IO) { getZygiskImplementationInfo() }
            val zygiskModules = moduleRepo.getModules().getOrDefault(emptyList()).filter {
                it.zygisk || it.suppressedByBuiltin
            }
            _uiState.update {
                it.copy(
                    isSwitching = false,
                    status = status,
                    implementation = implementation,
                    zygiskModules = zygiskModules,
                    expandedModuleId = null,
                    moduleProcesses = ZygiskProcesses()
                )
            }
            onResult(ok)
        }
    }

    /** Opens or closes the process rows of the module that currently owns Zygisk. */
    fun toggleModuleProcesses(id: String) {
        if (_uiState.value.expandedModuleId == id) {
            _uiState.update { it.copy(expandedModuleId = null, moduleProcesses = ZygiskProcesses()) }
            return
        }
        viewModelScope.launch {
            _uiState.update { it.copy(expandedModuleId = id, moduleProcesses = ZygiskProcesses()) }
            val processes = withContext(Dispatchers.IO) { getZygiskProcesses(id) }
            _uiState.update {
                if (it.expandedModuleId == id) it.copy(moduleProcesses = processes) else it
            }
        }
    }
}
