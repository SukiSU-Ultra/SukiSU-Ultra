package com.sukisu.ultra.data.repository

import com.sukisu.ultra.data.model.RepoModule
import com.sukisu.ultra.ksuApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.Request

class ModuleRepoRepositoryImpl(
    private val sourceRepo: RepoSourceRepository = RepoSourceRepositoryImpl(),
) : ModuleRepoRepository {

    override suspend fun fetchModules(): Result<ModuleRepoFetchResult> = withContext(Dispatchers.IO) {
        runCatching {
            val sources = sourceRepo.loadSources().filter { it.enabled }
            if (sources.isEmpty()) {
                return@runCatching ModuleRepoFetchResult(emptyList(), emptyMap())
            }

            coroutineScope {
                val outcomes = sources.map { source ->
                    async { fetchSource(source) }
                }.awaitAll()

                // First source wins on module id conflicts.
                val modules = LinkedHashMap<String, RepoModule>()
                val errors = LinkedHashMap<String, String>()
                sources.forEachIndexed { index, source ->
                    outcomes[index].fold(
                        onSuccess = { list -> list.forEach { module -> modules.putIfAbsent(module.moduleId, module) } },
                        onFailure = { e -> errors[source.name] = e.message ?: e.javaClass.simpleName },
                    )
                }

                ModuleRepoFetchResult(modules.values.toList(), errors)
            }
        }
    }

    private suspend fun fetchSource(source: RepoSource): Result<List<RepoModule>> = withContext(Dispatchers.IO) {
        runCatching {
            val request = Request.Builder().url(source.url).build()
            ksuApp.okhttpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw Exception("HTTP ${response.code}")
                }
                val body = response.body.string()
                RepoModuleParser.parse(body, source.id, source.name)
            }
        }
    }
}
