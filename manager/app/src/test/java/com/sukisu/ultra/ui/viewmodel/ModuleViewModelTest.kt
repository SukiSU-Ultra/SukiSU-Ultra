package com.sukisu.ultra.ui.viewmodel

import com.sukisu.ultra.data.model.Module
import com.sukisu.ultra.data.model.ModuleUpdateInfo
import com.sukisu.ultra.data.repository.ModuleRepoRepository
import com.sukisu.ultra.data.repository.ModuleRepository
import com.sukisu.ultra.data.repository.SettingsRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.lang.reflect.Proxy

internal fun testSettings(): SettingsRepository = Proxy.newProxyInstance(
    SettingsRepository::class.java.classLoader, arrayOf(SettingsRepository::class.java)
) { _, method, _ ->
    when (method.name) {
        "getCheckModuleUpdate" -> true
        "getModuleManualOrder" -> "[]"
        "getModuleRepoSortOrder" -> "UPDATED"
        else -> when (method.returnType) {
            Boolean::class.javaPrimitiveType -> false
            String::class.java -> ""
            Void.TYPE -> null
            else -> error("Unexpected settings call: ${method.name}")
        }
    }
} as SettingsRepository

internal fun unusedRegistry(): ModuleRepoRepository = Proxy.newProxyInstance(
    ModuleRepoRepository::class.java.classLoader, arrayOf(ModuleRepoRepository::class.java)
) { _, method, _ -> error("Unexpected registry call: ${method.name}") } as ModuleRepoRepository

class ModuleViewModelTest {
    private val module = Module(
        id = "module", name = "Module", author = "author", version = "1", versionCode = 1,
        description = "", enabled = true, update = false, remove = false,
        updateJson = "https://example.com/update.json", hasWebUi = false, hasActionScript = false,
        metamodule = false, actionIconPath = null, webUiIconPath = null,
    )
    private val update = ModuleUpdateInfo("https://example.com/module.zip", "2", "", 2)

    private class FakeRepository : ModuleRepository {
        val started = Channel<Module>(Channel.UNLIMITED)
        var check: suspend (Module) -> Result<ModuleUpdateInfo> = { Result.success(ModuleUpdateInfo.Empty) }
        override suspend fun getModules(): Result<List<Module>> = error("Not used")
        override suspend fun checkUpdate(module: Module): Result<ModuleUpdateInfo> {
            started.send(module)
            return check(module)
        }
    }

    private suspend fun withViewModel(block: suspend (ModuleViewModel, FakeRepository) -> Unit) {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val repo = FakeRepository()
        try {
            block(ModuleViewModel(repo, testSettings(), unusedRegistry(), scope), repo)
        } finally {
            scope.cancel()
        }
    }

    @Test
    fun shouldReleaseOwnedMarkers_whenBatchIsCancelled() = runBlocking {
        withViewModel { vm, repo ->
            repo.check = { awaitCancellation() }
            val batch = async { vm.syncModuleUpdateInfo(listOf(module)) }
            withTimeout(2_000) { repo.started.receive() }
            vm.syncModuleUpdateInfo(listOf(module))
            assertTrue(repo.started.tryReceive().isFailure)
            batch.cancelAndJoin()
            assertTrue(vm.uiState.value.updateInfo.isEmpty())

            repo.check = { Result.success(update) }
            vm.syncModuleUpdateInfo(listOf(module))
            assertEquals(module, repo.started.receive())
            assertEquals(update, vm.uiState.value.updateInfo[module.id])
            vm.syncModuleUpdateInfo(listOf(module))
            assertTrue(repo.started.tryReceive().isFailure)
        }
    }

    @Test(timeout = 10_000)
    fun shouldRetryWithoutEmptyCache_whenUpdateTimesOut() = runBlocking {
        withViewModel { vm, repo ->
            repo.check = { awaitCancellation() }
            vm.syncModuleUpdateInfo(listOf(module))
            assertTrue(vm.uiState.value.updateInfo.isEmpty())
            assertEquals(module, repo.started.receive())
            repo.check = { Result.success(update) }
            vm.syncModuleUpdateInfo(listOf(module))
            assertEquals(module, repo.started.receive())
            assertEquals(update, vm.uiState.value.updateInfo[module.id])
        }
    }

    @Test
    fun shouldRetryFailuresAndPropagateCancellationResults() = runBlocking {
        withViewModel { vm, repo ->
            repo.check = { Result.failure(IOException("offline")) }
            vm.syncModuleUpdateInfo(listOf(module))
            assertTrue(vm.uiState.value.updateInfo.isEmpty())
            repo.check = { Result.failure(CancellationException("cancelled")) }
            val result = runCatching { vm.syncModuleUpdateInfo(listOf(module)) }
            assertTrue(result.exceptionOrNull() is CancellationException)
            assertTrue(vm.uiState.value.updateInfo.isEmpty())
            repo.check = { Result.success(ModuleUpdateInfo.Empty) }
            vm.syncModuleUpdateInfo(listOf(module))
            assertEquals(ModuleUpdateInfo.Empty, vm.uiState.value.updateInfo[module.id])
            repeat(3) { repo.started.receive() }
            vm.syncModuleUpdateInfo(listOf(module))
            assertTrue(repo.started.tryReceive().isFailure)
        }
    }

    @Test
    fun shouldKeepNewOwnerMarker_whenRemovedModuleIsReaddedAndOldBatchCancelled() = runBlocking {
        withViewModel { vm, repo ->
            val result = CompletableDeferred<ModuleUpdateInfo>()
            repo.check = { Result.success(result.await()) }
            val old = async { vm.syncModuleUpdateInfo(listOf(module)) }
            withTimeout(2_000) { repo.started.receive() }
            vm.syncModuleUpdateInfo(emptyList())
            val newer = async { vm.syncModuleUpdateInfo(listOf(module)) }
            withTimeout(2_000) { repo.started.receive() }
            old.cancelAndJoin()
            vm.syncModuleUpdateInfo(listOf(module))
            assertTrue(repo.started.tryReceive().isFailure)
            result.complete(update)
            newer.await()
            assertEquals(update, vm.uiState.value.updateInfo[module.id])
        }
    }

    @Test
    fun shouldIgnoreOldResults_whenSignatureChangesDuringFetch() = runBlocking {
        withViewModel { vm, repo ->
            val oldResult = CompletableDeferred<ModuleUpdateInfo>()
            repo.check = { if (it.versionCode == 1L) Result.success(oldResult.await()) else Result.success(ModuleUpdateInfo.Empty) }
            val old = async { vm.syncModuleUpdateInfo(listOf(module)) }
            withTimeout(2_000) { repo.started.receive() }
            val newer = module.copy(versionCode = 2)
            vm.syncModuleUpdateInfo(listOf(newer))
            assertEquals(newer, repo.started.receive())
            oldResult.complete(update)
            old.await()
            assertEquals(ModuleUpdateInfo.Empty, vm.uiState.value.updateInfo[module.id])
            vm.syncModuleUpdateInfo(listOf(newer))
            assertTrue(repo.started.tryReceive().isFailure)
        }
    }

    @Test
    fun shouldFetchConcurrentlyAndInvalidateEverySignatureField() = runBlocking {
        withViewModel { vm, repo ->
            val result = CompletableDeferred<ModuleUpdateInfo>()
            repo.check = { Result.success(result.await()) }
            val other = module.copy(id = "other")
            val batch = async { vm.syncModuleUpdateInfo(listOf(module, other)) }
            val started = withTimeout(2_000) { setOf(repo.started.receive().id, repo.started.receive().id) }
            assertEquals(setOf(module.id, other.id), started)
            result.complete(update)
            batch.await()
            for (changed in listOf(
                module.copy(updateJson = "https://other.example/update.json"),
                module.copy(versionCode = 3), module.copy(enabled = false),
                module.copy(update = true), module.copy(remove = true),
            )) {
                vm.syncModuleUpdateInfo(listOf(changed, other))
                assertEquals(changed, repo.started.receive())
                vm.syncModuleUpdateInfo(listOf(changed, other))
                assertTrue(repo.started.tryReceive().isFailure)
            }
        }
    }
}
