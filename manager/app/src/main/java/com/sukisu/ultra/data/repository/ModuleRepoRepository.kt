package com.sukisu.ultra.data.repository

import com.sukisu.ultra.data.model.RepoModule

interface ModuleRepoRepository {
    companion object {
        const val DEFAULT_MODULES_URL = "https://modules.kernelsu.org/modules.json"
    }
    suspend fun fetchModules(repoUrls: List<String>): Result<List<RepoModule>>
}
