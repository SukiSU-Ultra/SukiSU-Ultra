package com.sukisu.ultra.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.data.repository.ExtensionRepository
import com.sukisu.ultra.data.repository.ExtensionRepositoryImpl
import com.sukisu.ultra.ui.util.ExtensionId
import com.sukisu.ultra.ui.util.ExtensionState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class ExtensionsUiState(
    val loading: Boolean = false,
    val states: Map<ExtensionId, ExtensionState> = emptyMap(),
    val errorMessage: String? = null,
)

class ExtensionsViewModel(
    private val repo: ExtensionRepository = ExtensionRepositoryImpl()
) : ViewModel() {

    private val _uiState = MutableStateFlow(ExtensionsUiState())
    val uiState: StateFlow<ExtensionsUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            _uiState.update { it.copy(loading = true, errorMessage = null) }
            val newStates = mutableMapOf<ExtensionId, ExtensionState>()
            try {
                for (ext in ExtensionId.ALL) {
                    val state = withContext(Dispatchers.IO) { repo.probe(ext) }
                    newStates[ext] = state
                }
            } catch (t: Throwable) {
                _uiState.update {
                    it.copy(loading = false, errorMessage = t.message)
                }
                return@launch
            }
            _uiState.update { it.copy(loading = false, states = newStates) }
        }
    }

    fun toggle(id: ExtensionId, enabled: Boolean) {
        val current = _uiState.value.states[id] ?: return
        if (!current.userToggleable) return
        viewModelScope.launch {
            val ok = withContext(Dispatchers.IO) { repo.setEnabled(id, enabled) }
            if (!ok) {
                _uiState.update { it.copy(errorMessage = "set_failed:${id.wireName}") }
                return@launch
            }
            val refreshed = withContext(Dispatchers.IO) { repo.probe(id) }
            _uiState.update { current ->
                current.copy(
                    states = current.states.toMutableMap().also {
                        it[id] = refreshed
                    }
                )
            }
        }
    }

    fun consumeError() {
        _uiState.update { it.copy(errorMessage = null) }
    }
}
