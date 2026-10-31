package com.sukisu.ultra.ai.host

import com.sukisu.ultra.ai.api.AiModuleService
import com.sukisu.ultra.ai.api.GithubModuleAsset

/** Combines the read-only module data surface with registry install actions. */
object AiModuleServiceHost : AiModuleService {

    override suspend fun installedModules(limit: Int): String =
        AiManagerData.installedModules(limit)

    override fun moduleCapabilities(): String = AiManagerData.moduleCapabilities()

    override suspend fun search(query: String?, limit: Int): String =
        AiModuleController.search(query, limit)

    override suspend fun install(
        moduleId: String,
        version: String?,
        onProgress: (String) -> Unit,
    ): String = AiModuleController.install(moduleId, version, onProgress)

    override suspend fun installGithubAsset(
        asset: GithubModuleAsset,
        onProgress: (String) -> Unit,
    ): String = AiModuleController.installGithubAsset(asset, onProgress)
}
