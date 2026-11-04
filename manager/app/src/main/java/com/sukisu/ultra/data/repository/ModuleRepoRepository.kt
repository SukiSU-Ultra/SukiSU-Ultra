package com.sukisu.ultra.data.repository

import com.sukisu.ultra.data.model.RepoModuleDetail
import com.sukisu.ultra.data.model.RepoModuleList
import com.sukisu.ultra.data.registry.UpdateVerification

interface ModuleRepoRepository {
    
    suspend fun fetchModules(): Result<RepoModuleList>

    /**
     * Detail (and readme) of a module in the current index. Fails with
     * [com.sukisu.ultra.data.registry.ModuleNotInIndexException] if it is not listed.
     */
    suspend fun fetchDetail(moduleId: String): Result<RepoModuleDetail>

    
    suspend fun fetchChangelogHtml(moduleId: String, tag: String?): String?

    /**
     * How an `updateJson` update of an installed module must be verified: against the matching
     * registry release, rejected, or legacy (not a registry update).
     */
    suspend fun resolveUpdate(moduleId: String, updateJsonUrl: String, zipUrl: String, versionCode: Long): UpdateVerification

    
    suspend fun fetchRegistryText(url: String): String?

    
    fun isRegistryUrl(url: String): Boolean
}
