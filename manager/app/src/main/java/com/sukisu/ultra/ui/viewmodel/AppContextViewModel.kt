package com.sukisu.ultra.ui.viewmodel

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.appcontext.AppContextUiState
import com.sukisu.ultra.ui.util.getAppContexts
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class AppContextViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(AppContextUiState())
    val uiState: StateFlow<AppContextUiState> = _uiState.asStateFlow()

    private var refreshJob: Job? = null

    init {
        refresh()
    }

    fun refresh(silent: Boolean = false) {
        if (refreshJob?.isActive == true) return
        refreshJob = viewModelScope.launch {
            if (!silent) _uiState.update { it.copy(isLoading = true, error = null) }

            try {
                val contexts = getAppContexts()
                _uiState.update {
                    it.copy(
                        contexts = contexts,
                        isLoading = false,
                        error = null
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e("AppContext", "Failed to load shared state", e)
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        error = R.string.app_context_load_failed
                    )
                }
            }
        }
    }
}
