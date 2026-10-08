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
        try {
            val sources = sourceRepo.loadSources().filter { it.enabled }
            if (sources.isEmpty()) {
                return@withContext Result.success(ModuleRepoFetchResult(emptyList(), emptyMap()))
            }

            coroutineScope {
                val outcomes = sources.map { source ->
                    async { fetchSource(source) }
                }.awaitAll()
                Result.success(aggregateModuleSources(sources, outcomes))
            }
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private suspend fun fetchSource(source: RepoSource): Result<List<RepoModule>> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder().url(source.url).build()
            ksuApp.okhttpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw Exception("HTTP ${response.code}")
                }
                val body = response.body.string()
                Result.success(RepoModuleParser.parse(body, source.id, source.name, source.url))
            }
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

/**
 * Merges per-source fetch outcomes into the page result: modules are deduplicated
 * by id with the first source winning; failures are keyed by source name.
 */
fun aggregateModuleSources(
    sources: List<RepoSource>,
    outcomes: List<Result<List<RepoModule>>>,
): ModuleRepoFetchResult {
    val modules = LinkedHashMap<String, RepoModule>()
    val errors = LinkedHashMap<String, String>()
    sources.forEachIndexed { index, source ->
        outcomes.getOrNull(index)?.fold(
            onSuccess = { list -> list.forEach { module -> modules.putIfAbsent(module.moduleId, module) } },
            onFailure = { e -> errors[source.name] = e.message ?: e.javaClass.simpleName },
        )
    }
    return ModuleRepoFetchResult(modules.values.toList(), errors)
}
