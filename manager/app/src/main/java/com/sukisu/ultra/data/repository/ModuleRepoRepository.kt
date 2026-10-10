package com.sukisu.ultra.data.repository

import com.sukisu.ultra.data.model.RepoModule

data class ModuleRepoFetchResult(
    val modules: List<RepoModule>,
    /** Per-source fetch failures of the last run, keyed by source name. */
    val sourceErrors: Map<String, String> = emptyMap(),
)

interface ModuleRepoRepository {
    suspend fun fetchModules(): Result<ModuleRepoFetchResult>
}
