package com.sukisu.ultra.ui.screen.modulerepo

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.data.model.RepoModule
import com.sukisu.ultra.data.repository.RepoSource
import com.sukisu.ultra.ui.component.SearchStatus

enum class RepoSort {
    UPDATED,
    CREATED,
    NAME,
    STARS,
}

data class ModuleRepoUiState(
    val isRefreshing: Boolean = false,
    /** True once a fetch has settled, so an empty list stops reading as "still loading". */
    val hasLoadedOnce: Boolean = false,
    val sortOrder: RepoSort = RepoSort.UPDATED,
    val offline: Boolean = false,
    val modules: List<RepoModule> = emptyList(),
    val searchStatus: SearchStatus = SearchStatus(""),
    val searchResults: List<RepoModule> = emptyList(),
    val error: Throwable? = null,
    val sources: List<RepoSource> = emptyList(),
    val sourceErrors: Map<String, String> = emptyMap(),
    val isAddingSource: Boolean = false,
)

@Immutable
data class ModuleRepoActions(
    val onBack: () -> Unit,
    val onRefresh: () -> Unit,
    val onSearchTextChange: (String) -> Unit,
    val onClearSearch: () -> Unit,
    val onSearchStatusChange: (SearchStatus) -> Unit,
    val onSetSortOrder: (RepoSort) -> Unit,
    val onOpenRepoDetail: (RepoModule) -> Unit,
    val onAddSource: (String) -> Unit,
    val onRemoveSource: (String) -> Unit,
    val onSetSourceEnabled: (String, Boolean) -> Unit,
    val onRenameSource: (String, String) -> Unit,
)

@Immutable
data class ModuleRepoDetailUiState(
    val module: RepoModuleArg,
    val readmeHtml: String?,
    val readmeLoaded: Boolean,
    val detailReleases: List<ReleaseArg>,
    val webUrl: String,
    val sourceUrl: String,
)

@Immutable
data class ModuleRepoDetailActions(
    val onBack: () -> Unit,
    val onOpenWebUrl: () -> Unit,
    val onOpenUrl: (String) -> Unit,
    val onInstallModule: (android.net.Uri) -> Unit,
)
