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
 * Merges per-source fetch outcomes into the page result.
 *
 * Community repositories mirror each other heavily, and they do not agree on how a module is
 * identified: the same module is published as `copg` and `COPG`, or as `trickystore` and
 * `tricky_store`. Entries are therefore deduplicated on both the module id and the module name,
 * compared after dropping case and punctuation, and the surviving entry is the installable one:
 * a module with a download address wins over one whose index carries none, and a newer version
 * wins over an older one. Repositories that lost the merge are recorded in
 * [RepoModule.alternateSourceNames] instead of being dropped, so the page can still show that the
 * module is published elsewhere. Failures are keyed by source name.
 */
fun aggregateModuleSources(
    sources: List<RepoSource>,
    outcomes: List<Result<List<RepoModule>>>,
): ModuleRepoFetchResult {
    val modules = LinkedHashMap<String, RepoModule>()
    val canonicalByKey = HashMap<String, String>()
    val errors = LinkedHashMap<String, String>()

    fun absorb(module: RepoModule) {
        val keys = dedupKeys(module)
        if (keys.isEmpty()) {
            modules["${module.sourceId}\u0000${module.moduleId}"] = module
            return
        }
        val existing = keys.mapNotNull { canonicalByKey[it] }.distinct()
        // The id of an incoming module may point at one entry while its name points at another;
        // collapse them onto the first, which also keeps the earliest position in the list.
        val target = existing.firstOrNull() ?: keys.first()
        var entry = modules[target] ?: module
        existing.drop(1).forEach { other ->
            modules.remove(other)?.let { entry = entry.mergedWith(it) }
        }
        entry = entry.mergedWith(module)
        modules[target] = entry
        keys.forEach { canonicalByKey[it] = target }
    }

    sources.forEachIndexed { index, source ->
        outcomes.getOrNull(index)?.fold(
            onSuccess = { list -> list.forEach(::absorb) },
            onFailure = { e -> errors[source.name] = e.message ?: e.javaClass.simpleName },
        )
    }
    return ModuleRepoFetchResult(modules.values.toList(), errors)
}

/**
 * The identities a module can be recognised by across repositories: its name and its id, each
 * reduced to lowercase letters and digits. Names matter because sources disagree about ids, ids
 * because a source may rename a module; within one repository neither ever repeats, so a match on
 * either is a match on the module.
 */
internal fun dedupKeys(module: RepoModule): List<String> =
    listOf(module.moduleName, module.moduleId)
        .map { key -> key.lowercase().filter { it.isLetterOrDigit() } }
        .filter { it.isNotEmpty() }
        .distinct()

/**
 * Folds [other] into this entry, keeping whichever of the two is installable and remembering the
 * repository it came from.
 */
private fun RepoModule.mergedWith(other: RepoModule): RepoModule {
    if (other === this) return this
    val (winner, loser) = if (isBetterThan(other, this)) other to this else this to other
    val alternates = (winner.alternateSourceNames + loser.sourceName + loser.alternateSourceNames)
        .filter { it.isNotEmpty() && it != winner.sourceName }
        .distinct()
    return winner.copy(alternateSourceNames = alternates)
}

/**
 * Whether [candidate] should represent the merged module instead of [current]: an entry the user
 * can actually install beats one whose index carries no download address, and otherwise the newer
 * version beats the older one.
 */
private fun isBetterThan(candidate: RepoModule, current: RepoModule): Boolean {
    val candidateDownloadable = !candidate.latestAsset?.downloadUrl.isNullOrBlank()
    val currentDownloadable = !current.latestAsset?.downloadUrl.isNullOrBlank()
    if (candidateDownloadable != currentDownloadable) return candidateDownloadable
    return candidate.latestVersionCode > current.latestVersionCode
}
