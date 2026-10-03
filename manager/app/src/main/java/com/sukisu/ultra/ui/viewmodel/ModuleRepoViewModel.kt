package com.sukisu.ultra.ui.viewmodel

import android.util.Log
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.sukisu.ultra.R
import com.sukisu.ultra.data.repository.ModuleRepoRepository
import com.sukisu.ultra.data.repository.ModuleRepoRepositoryImpl
import com.sukisu.ultra.data.repository.RepoSourceRepository
import com.sukisu.ultra.data.repository.RepoSourceRepositoryImpl
import com.sukisu.ultra.data.repository.SettingsRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.component.SearchStatus
import com.sukisu.ultra.ui.screen.modulerepo.ModuleRepoUiState
import com.sukisu.ultra.ui.screen.modulerepo.RepoSort
import com.sukisu.ultra.ui.util.PinyinUtil
import com.sukisu.ultra.ui.util.hasAnyNetwork
import java.text.Collator
import java.util.Locale

class ModuleRepoViewModel(
    private val repo: ModuleRepoRepository = ModuleRepoRepositoryImpl(),
    private val sourceRepo: RepoSourceRepository = RepoSourceRepositoryImpl(),
    private val settingsRepo: SettingsRepository = SettingsRepositoryImpl()
) : ViewModel() {

    companion object {
        private const val TAG = "ModuleRepoViewModel"
    }

    typealias RepoModule = com.sukisu.ultra.data.model.RepoModule

    private val _uiState = MutableStateFlow(ModuleRepoUiState())
    val uiState: StateFlow<ModuleRepoUiState> = _uiState.asStateFlow()

    private val searchQuery = MutableStateFlow("")

    init {
        val ordinal = settingsRepo.moduleRepoSortOrder
        val initial = RepoSort.entries.getOrElse(ordinal) { RepoSort.UPDATED }
        _uiState.update {
            it.copy(
                sortOrder = initial,
                offline = !hasAnyNetwork(ksuApp),
                sources = sourceRepo.loadSources()
            )
        }

        viewModelScope.launchSearchQueryCollector(searchQuery, ::applySearchText)
    }

    private fun sortModules(list: List<RepoModule>, order: RepoSort): List<RepoModule> {
        if (list.isEmpty()) return list
        return when (order) {
            RepoSort.UPDATED -> list.sortedByDescending { it.latestReleaseTime }
            RepoSort.CREATED -> list.sortedByDescending { it.createdAt }
            RepoSort.NAME -> {
                val collator = Collator.getInstance(Locale.getDefault())
                list.sortedWith(compareBy(collator) { it.moduleName })
            }

            RepoSort.STARS -> list.sortedByDescending { it.stargazerCount }
        }
    }

    private fun filterModules(modules: List<RepoModule>, text: String): List<RepoModule> {
        if (text.isEmpty()) return emptyList()

        return modules.filter {
            it.moduleId.contains(text, true) ||
                    it.moduleName.contains(text, true) ||
                    it.authors.contains(text, true) ||
                    it.summary.contains(text, true) ||
                    it.sourceName.contains(text, true) ||
                    PinyinUtil.toPinyin(it.moduleName).contains(text, true)
        }
    }

    private suspend fun applySearchText(text: String) {
        _uiState.update {
            it.copy(
                searchStatus = it.searchStatus.copy(
                    resultStatus = searchLoadingStatusFor(text)
                )
            )
        }

        if (text.isEmpty()) {
            _uiState.update { state ->
                state.copy(
                    searchResults = emptyList(),
                    searchStatus = state.searchStatus.copy(resultStatus = SearchStatus.ResultStatus.DEFAULT)
                )
            }
            return
        }

        val result = withContext(Dispatchers.IO) {
            sortModules(filterModules(_uiState.value.modules, text), _uiState.value.sortOrder)
        }

        _uiState.update {
            it.copy(
                searchResults = result,
                searchStatus = it.searchStatus.copy(resultStatus = searchResultStatusFor(text, result.isEmpty()))
            )
        }
    }

    private fun refreshSearchResults() {
        val state = _uiState.value
        val text = state.searchStatus.searchText
        val results = sortModules(filterModules(state.modules, text), state.sortOrder)
        _uiState.update {
            it.copy(
                searchResults = results,
                searchStatus = it.searchStatus.copy(resultStatus = searchResultStatusFor(text, results.isEmpty()))
            )
        }
    }

    private var pendingRefresh = false

    fun refresh() {
        if (_uiState.value.isRefreshing) {
            pendingRefresh = true
            return
        }
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isRefreshing = true,
                    error = null,
                    offline = !hasAnyNetwork(ksuApp)
                )
            }
            val result = repo.fetchModules()

            withContext(Dispatchers.Main) {
                result.onSuccess { outcome ->
                    val current = _uiState.value
                    // When every source fails, keep the previous list instead of blanking the page.
                    val keepOld = outcome.modules.isEmpty() && outcome.sourceErrors.isNotEmpty() && current.modules.isNotEmpty()
                    val order = current.sortOrder
                    val sorted = if (keepOld) {
                        current.modules
                    } else {
                        withContext(Dispatchers.Default) { sortModules(outcome.modules, order) }
                    }
                    _uiState.update {
                        it.copy(
                            modules = sorted,
                            sourceErrors = outcome.sourceErrors,
                            offline = !hasAnyNetwork(ksuApp)
                        )
                    }
                    refreshSearchResults()
                    if (outcome.modules.isEmpty() && outcome.sourceErrors.isNotEmpty()) {
                        Toast.makeText(
                            ksuApp,
                            ksuApp.getString(R.string.module_repo_fetch_failed, outcome.sourceErrors.values.first()),
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                    _uiState.update { it.copy(isRefreshing = false) }
                    runPendingRefresh()
                }.onFailure { e ->
                    Log.e(TAG, "fetch modules failed", e)
                    Toast.makeText(
                        ksuApp,
                        ksuApp.getString(R.string.network_offline), Toast.LENGTH_SHORT
                    ).show()
                    _uiState.update {
                        it.copy(
                            isRefreshing = false,
                            error = e,
                            offline = !hasAnyNetwork(ksuApp)
                        )
                    }
                    runPendingRefresh()
                }
            }
        }
    }

    fun setSortOrder(order: RepoSort) {
        if (_uiState.value.sortOrder == order) return
        settingsRepo.moduleRepoSortOrder = order.ordinal
        viewModelScope.launch {
            val state = _uiState.value
            val (sortedModules, sortedSearch) = withContext(Dispatchers.Default) {
                sortModules(state.modules, order) to sortModules(state.searchResults, order)
            }
            _uiState.update {
                it.copy(
                    sortOrder = order,
                    modules = sortedModules,
                    searchResults = sortedSearch,
                )
            }
        }
    }

    fun updateSearchStatus(status: SearchStatus) {
        val previous = _uiState.value.searchStatus
        _uiState.update { it.copy(searchStatus = status) }
        if (previous.searchText != status.searchText) {
            searchQuery.value = status.searchText
        }
    }

    fun updateSearchText(text: String) {
        updateSearchStatus(_uiState.value.searchStatus.copy(searchText = text))
    }

    fun addSource(rawUrl: String) {
        if (_uiState.value.isAddingSource) return
        viewModelScope.launch {
            _uiState.update { it.copy(isAddingSource = true) }
            val result = sourceRepo.addSource(rawUrl)
            withContext(Dispatchers.Main) {
                _uiState.update { it.copy(isAddingSource = false, sources = sourceRepo.loadSources()) }
                result.onSuccess {
                    Toast.makeText(ksuApp, ksuApp.getString(R.string.module_repo_source_added), Toast.LENGTH_SHORT).show()
                    refresh()
                }.onFailure { e ->
                    Toast.makeText(ksuApp, e.message ?: e.javaClass.simpleName, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    fun removeSource(id: String) {
        sourceRepo.removeSource(id)
        _uiState.update { it.copy(sources = sourceRepo.loadSources()) }
        refresh()
    }

    fun setSourceEnabled(id: String, enabled: Boolean) {
        sourceRepo.setSourceEnabled(id, enabled)
        _uiState.update { it.copy(sources = sourceRepo.loadSources()) }
        refresh()
    }

    fun renameSource(id: String, name: String) {
        if (name.isBlank()) return
        val trimmed = name.trim()
        val previousName = _uiState.value.sources.firstOrNull { it.id == id }?.name ?: return
        sourceRepo.renameSource(id, trimmed)
        _uiState.update { st ->
            st.copy(
                sources = sourceRepo.loadSources(),
                modules = st.modules.map { m -> if (m.sourceId == id) m.copy(sourceName = trimmed) else m },
                searchResults = st.searchResults.map { m -> if (m.sourceId == id) m.copy(sourceName = trimmed) else m },
                sourceErrors = if (previousName == trimmed) {
                    st.sourceErrors
                } else {
                    st.sourceErrors.mapKeys { (key, value) -> if (key == previousName) trimmed else key }
                },
            )
        }
    }

    private fun runPendingRefresh() {
        if (pendingRefresh) {
            pendingRefresh = false
            refresh()
        }
    }
}
