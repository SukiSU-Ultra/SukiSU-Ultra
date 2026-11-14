package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.data.repository.ModuleRepository
import com.sukisu.ultra.data.repository.ModuleRepositoryImpl
import com.sukisu.ultra.ui.util.getBuiltinZygiskConfig
import com.sukisu.ultra.ui.util.getBuiltinZygiskStatus
import com.sukisu.ultra.ui.util.setBuiltinZygiskConfig
import com.sukisu.ultra.ui.util.rearmBuiltinZygisk
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
            val config = withContext(Dispatchers.IO) { getBuiltinZygiskConfig() }
            val modulesResult = moduleRepo.getModules()
            val zygiskModules = modulesResult.getOrDefault(emptyList()).filter {
                it.zygisk || it.suppressedByBuiltin
            }
            _uiState.update {
                it.copy(
                    isLoading = false,
                    status = status,
                    config = config,
                    zygiskModules = zygiskModules
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

    fun rearm(onSuccess: () -> Unit) {
        viewModelScope.launch {
            _uiState.update { it.copy(isRearming = true) }
            val ok = withContext(Dispatchers.IO) { rearmBuiltinZygisk() }
            val status = withContext(Dispatchers.IO) { getBuiltinZygiskStatus() }
            _uiState.update {
                it.copy(
                    isRearming = false,
                    status = status
                )
            }
            if (ok) {
                onSuccess()
            }
        }
    }
}
