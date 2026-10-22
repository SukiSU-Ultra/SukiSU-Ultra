package com.sukisu.ultra.ui.viewmodel

import android.util.Log
import com.sukisu.ultra.ui.screen.appcontext.AppContextJson
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.ui.screen.appcontext.AppContextEntry
import com.sukisu.ultra.ui.screen.appcontext.AppContextUiState
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.getKsuDaemonPath
import com.sukisu.ultra.ui.util.getRootShell
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppContextViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(AppContextUiState())
    val uiState: StateFlow<AppContextUiState> = _uiState.asStateFlow()

    private var refreshJob: Job? = null

    init {
        refresh()
    }

    fun refresh() {
        if (refreshJob?.isActive == true) return
        refreshJob = viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }

            try {
                val contexts = withContext(Dispatchers.IO) {
                    loadAppContexts()
                }
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
                        contexts = emptyList(),
                        error = R.string.app_context_load_failed
                    )
                }
            }
        }
    }

    private suspend fun loadAppContexts(): List<AppContextEntry> {
        val result = getRootShell().newJob()
            .add("\"${getKsuDaemonPath()}\" extension app-context list --json").exec()
        if (!result.isSuccess) {
            throw java.io.IOException("ksud App Context list failed: ${result.err.joinToString("\n")}")
        }
        val entries = AppContextJson.decode(result.out.joinToString("\n"))
        if (entries.isEmpty()) return entries
        val packages = mutableMapOf<Long, String>()
        // One package-manager invocation for the entire snapshot, not one per UID.
        val packageResult = getRootShell().newJob().add("cmd package list packages -U --user all").exec()
        if (packageResult.isSuccess) {
            val pattern = Regex("^package:(\\S+)\\s+uid:(\\d+)$")
            for (line in packageResult.out) {
                coroutineContext.ensureActive()
                val match = pattern.matchEntire(line.trim()) ?: continue
                val uid = match.groupValues[2].toLongOrNull() ?: continue
                val name = match.groupValues[1]
                packages[uid] = packages[uid]?.let { "$it\n$name" } ?: name
            }
        }
        return entries.map { entry ->
            coroutineContext.ensureActive()
            entry.copy(packageName = packages[entry.uid])
        }
    }
}
