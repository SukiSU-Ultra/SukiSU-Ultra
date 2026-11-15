package com.sukisu.nova.ui.viewmodel

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.nova.data.repository.KpmRepository
import com.sukisu.nova.data.repository.KpmRepositoryImpl
import com.sukisu.nova.ui.component.ConfigResult
import com.sukisu.nova.ui.screen.kpm.InputDialogState
import com.sukisu.nova.ui.screen.kpm.KpmUiState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File

class KpmViewModel(
    private val repo: KpmRepository = KpmRepositoryImpl()
) : ViewModel() {
    private val _uiState = MutableStateFlow(KpmUiState())
    val uiState: StateFlow<KpmUiState> = _uiState.asStateFlow()
    private var refreshJob: Job? = null
    private var operationJob: Job? = null
    private var tempFile: File? = null

    // Reserve before launching so rapid clicks cannot start concurrent root operations.
    fun runOperation(block: suspend () -> Unit) {
        if (_uiState.value.isBusy) return
        _uiState.update { it.copy(isBusy = true) }
        operationJob = viewModelScope.launch {
            try {
                refreshJob?.join()
                block()
            } finally {
                _uiState.update { it.copy(isBusy = false) }
                fetchModuleList()
            }
        }
    }

    fun prepareInstall(file: File, moduleName: String) {
        clearTempFile()
        tempFile = file
        _uiState.update { it.copy(showInstallModeDialog = true, tempModuleName = moduleName) }
    }

    fun clearTempFile() {
        tempFile?.delete()
        tempFile = null
    }

    fun getTempFile(): File? = tempFile

    fun setOperationResult(result: ConfigResult) {
        _uiState.update { it.copy(operationResults = listOf(result)) }
    }

    fun fetchModuleList(silent: Boolean = false) {
        if (refreshJob?.isActive == true || _uiState.value.isBusy) return
        refreshJob = viewModelScope.launch {
            _uiState.update { it.copy(isRefreshing = !silent || !it.hasLoaded) }
            try {
                repo.getModuleList()
                    .onSuccess { modules ->
                        _uiState.update {
                            it.copy(moduleList = modules, hasLoaded = true, error = null)
                        }
                    }
                    .onFailure { e ->
                        if (e is CancellationException) throw e
                        Log.e("KpmViewModel", "Failed to refresh modules", e)
                        _uiState.update { it.copy(error = e) }
                    }
            } finally {
                _uiState.update { it.copy(isRefreshing = false) }
            }
        }
    }

    fun dismissInstallDialog() {
        _uiState.update { it.copy(showInstallModeDialog = false, tempModuleName = null) }
    }

    fun showInputDialog(moduleId: String) {
        if (_uiState.value.isBusy) return
        _uiState.update {
            it.copy(inputDialogState = InputDialogState(
                visible = true,
                moduleId = moduleId,
                args = it.moduleList.find { module -> module.id == moduleId }?.args.orEmpty()
            ))
        }
    }

    fun hideInputDialog() {
        if (_uiState.value.isBusy) return
        _uiState.update { it.copy(inputDialogState = InputDialogState()) }
    }

    fun updateInputArgs(args: String) {
        _uiState.update { it.copy(inputDialogState = it.inputDialogState.copy(args = args)) }
    }

    suspend fun executeControl(): Int {
        val input = _uiState.value.inputDialogState
        val moduleId = input.moduleId ?: return -1
        val result = repo.controlModule(moduleId, input.args).getOrElse { e ->
            if (e is CancellationException) throw e
            Log.e("KpmViewModel", "Failed to control module", e)
            -1
        }
        // Preserve the user's parameters on failure so the command can be retried.
        if (result == 0) _uiState.update { it.copy(inputDialogState = InputDialogState()) }
        return result
    }

    fun updateSearchText(text: String) {
        _uiState.update { it.copy(searchQuery = text) }
    }

    override fun onCleared() {
        // Shell execution can still be reading the staged file after cancellation.
        val operation = operationJob
        if (operation == null || operation.isCompleted) clearTempFile()
        else operation.invokeOnCompletion { clearTempFile() }
    }

    data class ModuleInfo(
        val id: String,
        val name: String,
        val version: String,
        val author: String,
        val description: String,
        val args: String,
        val enabled: Boolean,
        val hasAction: Boolean
    )
}
