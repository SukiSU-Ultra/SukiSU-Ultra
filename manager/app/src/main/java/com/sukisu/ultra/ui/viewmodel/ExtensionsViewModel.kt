package com.sukisu.ultra.ui.viewmodel

import androidx.compose.runtime.Immutable
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.data.repository.ExtensionRepository
import com.sukisu.ultra.data.repository.ExtensionRepositoryImpl
import com.sukisu.ultra.ui.screen.extensions.ExtensionCatalog
import com.sukisu.ultra.ui.screen.extensions.ExtensionDescriptor
import com.sukisu.ultra.ui.util.ExtensionState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


@Immutable
data class ExtensionItem(
    val state: ExtensionState,
    val descriptor: ExtensionDescriptor,
) {
    val wireName: String get() = state.wireName
}

data class ExtensionsUiState(
    val loading: Boolean = false,
    val items: List<ExtensionItem> = emptyList(),
    
    val busy: Set<String> = emptySet(),
    val error: String? = null,
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
            _uiState.update { it.copy(loading = true, error = null) }
            loadItems().fold(
                onSuccess = { items -> _uiState.update { it.copy(loading = false, items = items) } },
                onFailure = { e -> _uiState.update { it.copy(loading = false, error = e.message) } },
            )
        }
    }

    /**
     * Toggle a generic sticky extension. Known extensions with a dedicated
     * sub-screen keep their own flow; the screen only calls this for
     * [com.sukisu.ultra.ui.screen.extensions.ExtensionEntry.Generic] cards.
     */
    fun setEnabled(item: ExtensionItem, enabled: Boolean) {
        val wireName = item.wireName
        if (wireName in _uiState.value.busy) return

        viewModelScope.launch {
            _uiState.update { it.copy(busy = it.busy + wireName, error = null) }
            try {
                val result = withContext(Dispatchers.IO) { repo.setEnabled(item.state.id, enabled) }
                if (result.isFailure) {
                    _uiState.update { it.copy(error = result.exceptionOrNull()?.message) }
                    return@launch
                }
                loadItems().fold(
                    onSuccess = { items -> _uiState.update { it.copy(items = items) } },
                    onFailure = { e -> _uiState.update { it.copy(error = e.message) } },
                )
            } finally {
                _uiState.update { it.copy(busy = it.busy - wireName) }
            }
        }
    }

    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }

    /**
     * Probe on IO and keep cancellation out of [Result], so a screen leaving
     * the back stack does not get reported as a load failure.
     */
    private suspend fun loadItems(): Result<List<ExtensionItem>> = try {
        Result.success(withContext(Dispatchers.IO) { repo.probeAll().map(::toItem) })
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Result.failure(e)
    }
}

private fun toItem(state: ExtensionState): ExtensionItem =
    ExtensionItem(
        state = state,
        descriptor = ExtensionCatalog.descriptorFor(state.wireName, state.id),
    )
