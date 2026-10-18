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
)

/**
 * Read-only view model for the extension overview screen.
 *
 * The overview never toggles extensions: every subsystem that has a
 * runtime sticky bit (currently only DynamicManager) exposes its own
 * sub-screen with the appropriate controls, and the other three
 * extensions (KPM, CPU spoof, umount paths) are either compile-time
 * capabilities or purely io-driven. Refresh is the only operation.
 */
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
            _uiState.update { it.copy(loading = true) }
            val newStates = mutableMapOf<ExtensionId, ExtensionState>()
            for (ext in ExtensionId.ALL) {
                val state = withContext(Dispatchers.IO) { repo.probe(ext) }
                newStates[ext] = state
            }
            _uiState.update { it.copy(loading = false, states = newStates) }
        }
    }
}
