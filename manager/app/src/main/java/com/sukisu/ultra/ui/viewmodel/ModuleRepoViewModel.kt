package com.sukisu.ultra.ui.viewmodel

import android.content.Context
import android.util.Log
import android.widget.Toast
import android.util.Patterns
import androidx.core.content.edit
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
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.component.SearchStatus
import com.sukisu.ultra.ui.screen.modulerepo.ModuleRepoUiState
import com.sukisu.ultra.ui.screen.modulerepo.RepoSort
import com.sukisu.ultra.ui.util.isNetworkAvailable
import java.text.Collator
import java.util.Locale

private const val PREFS_REPO_SORT_ORDER = "module_repo_sort_order"
private const val PREFS_REPO_URLS = "module_repo_urls"
private const val DEFAULT_MODULES_URL = "https://modules.kernelsu.org/modules.json"

class ModuleRepoViewModel(
    private val repo: ModuleRepoRepository = ModuleRepoRepositoryImpl()
) : ViewModel() {

    companion object {
        private const val TAG = "ModuleRepoViewModel"
    }

    typealias RepoModule = com.sukisu.ultra.data.model.RepoModule
    
    private val _uiState = MutableStateFlow(ModuleRepoUiState())
    val uiState: StateFlow<ModuleRepoUiState> = _uiState.asStateFlow()

    private val prefs = ksuApp.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val searchQuery = MutableStateFlow("")

    init {
        val ordinal = prefs.getInt(PREFS_REPO_SORT_ORDER, RepoSort.UPDATED.ordinal)
        val initial = RepoSort.entries.getOrElse(ordinal) { RepoSort.UPDATED }
        val savedUrls = prefs.getStringSet(PREFS_REPO_URLS, null)
        val repoUrls = if (savedUrls.isNullOrEmpty()) {
            listOf(DEFAULT_MODULES_URL)
        } else {
            savedUrls.toList()
        }
        _uiState.update {
            it.copy(
                sortOrder = initial,
                offline = !isNetworkAvailable(ksuApp),
                repoUrls = repoUrls
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
                    com.sukisu.ultra.ui.util.HanziToPinyin.getInstance().toPinyinString(it.moduleName)
                        .contains(text, true)
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

    fun refresh() {
        if (_uiState.value.isRefreshing) return
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isRefreshing = true,
                    error = null,
                    offline = !isNetworkAvailable(ksuApp)
                )
            }
            val result = repo.fetchModules(_uiState.value.repoUrls)

            withContext(Dispatchers.Main) {
                result.onSuccess { modules ->
                    val order = _uiState.value.sortOrder
                    val sorted = withContext(Dispatchers.Default) { sortModules(modules, order) }
                    _uiState.update {
                        it.copy(
                            modules = sorted,
                            offline = !isNetworkAvailable(ksuApp)
                        )
                    }
                    refreshSearchResults()
                    _uiState.update { it.copy(isRefreshing = false) }
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
                            offline = !isNetworkAvailable(ksuApp)
                        )
                    }
                }
            }
        }
    }

    fun setSortOrder(order: RepoSort) {
        if (_uiState.value.sortOrder == order) return
        prefs.edit { putInt(PREFS_REPO_SORT_ORDER, order.ordinal) }
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

    fun showManageRepoUrlsDialog() {
        _uiState.update { it.copy(showManageRepoUrlsDialog = true, editingUrlIndex = -1) }
    }

    fun dismissManageRepoUrlsDialog() {
        _uiState.update { it.copy(showManageRepoUrlsDialog = false, editingUrlIndex = -1) }
    }

    fun addRepoUrl(url: String) {
        val trimmedUrl = url.trim()
        if (trimmedUrl.isEmpty()) {
            Toast.makeText(ksuApp, ksuApp.getString(R.string.module_repos_url_empty), Toast.LENGTH_SHORT).show()
            return
        }
        if (!Patterns.WEB_URL.matcher(trimmedUrl).matches()) {
            Toast.makeText(ksuApp, ksuApp.getString(R.string.module_repos_url_invalid), Toast.LENGTH_SHORT).show()
            return
        }
        val currentUrls = _uiState.value.repoUrls.toMutableList()
        if (!currentUrls.contains(trimmedUrl)) {
            currentUrls.add(trimmedUrl)
            saveRepoUrls(currentUrls)
            _uiState.update { it.copy(repoUrls = currentUrls, editingUrlIndex = -1) }
        } else {
            _uiState.update { it.copy(editingUrlIndex = -1) }
        }
    }

    fun editRepoUrl(index: Int, newUrl: String) {
        val trimmedUrl = newUrl.trim()
        if (trimmedUrl.isEmpty()) {
            Toast.makeText(ksuApp, ksuApp.getString(R.string.module_repos_url_empty), Toast.LENGTH_SHORT).show()
            return
        }
        if (!Patterns.WEB_URL.matcher(trimmedUrl).matches()) {
            Toast.makeText(ksuApp, ksuApp.getString(R.string.module_repos_url_invalid), Toast.LENGTH_SHORT).show()
            return
        }
        val currentUrls = _uiState.value.repoUrls.toMutableList()
        if (index in currentUrls.indices) {
            currentUrls[index] = trimmedUrl
            saveRepoUrls(currentUrls)
            _uiState.update { it.copy(repoUrls = currentUrls, editingUrlIndex = -1) }
        }
    }

    fun deleteRepoUrl(index: Int) {
        val currentUrls = _uiState.value.repoUrls.toMutableList()
        if (index in currentUrls.indices && currentUrls.size > 1) {
            currentUrls.removeAt(index)
            saveRepoUrls(currentUrls)
            _uiState.update { it.copy(repoUrls = currentUrls, editingUrlIndex = -1) }
        }
    }

    fun setEditingUrlIndex(index: Int) {
        _uiState.update { it.copy(editingUrlIndex = index) }
    }

    private fun saveRepoUrls(urls: List<String>) {
        prefs.edit { putStringSet(PREFS_REPO_URLS, urls.toSet()) }
    }
}
