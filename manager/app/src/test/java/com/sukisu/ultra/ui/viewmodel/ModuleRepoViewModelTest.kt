package com.sukisu.ultra.ui.viewmodel

import com.sukisu.ultra.data.model.RepoModule
import com.sukisu.ultra.ui.component.SearchStatus
import com.sukisu.ultra.ui.screen.modulerepo.ModuleRepoUiState
import com.sukisu.ultra.ui.screen.modulerepo.RepoSort
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class ModuleRepoViewModelTest {
    private fun module(id: String, stars: Int) = RepoModule(
        moduleId = "match-$id", moduleName = "Same", authors = "", authorList = emptyList(),
        summary = "", tags = emptyList(), metamodule = false, iconUrl = null,
        latestVersion = "1", latestVersionCode = 1, latestReleaseTime = "", latestReleaseEpoch = 100,
        stars = stars,
    )

    @Suppress("UNCHECKED_CAST")
    private fun state(vm: ModuleRepoViewModel): MutableStateFlow<ModuleRepoUiState> =
        ModuleRepoViewModel::class.java.getDeclaredField("_uiState").let {
            it.isAccessible = true
            it.get(vm) as MutableStateFlow<ModuleRepoUiState>
        }

    private suspend fun withViewModel(block: suspend (ModuleRepoViewModel) -> Unit) {
        Executors.newSingleThreadExecutor { Thread(it, "module-repo-test-main") }.asCoroutineDispatcher().use { dispatcher ->
            val scope = CoroutineScope(SupervisorJob() + dispatcher)
            try {
                block(ModuleRepoViewModel(unusedRegistry(), testSettings(), scope) { true })
            } finally {
                scope.cancel()
            }
        }
    }

    @Test(timeout = 5_000)
    fun shouldFilterOnDefaultAndRejectOldQuery_whenInputAndSortChangeDuringFiltering() = runBlocking {
        withViewModel { vm ->
            val modules = listOf(module("first", 1), module("second", 2))
            val filtering = CompletableDeferred<String>()
            val release = CountDownLatch(1)
            val firstRead = AtomicBoolean(true)
            val blockingList = object : AbstractList<RepoModule>() {
                override val size = modules.size
                override fun get(index: Int): RepoModule {
                    if (firstRead.compareAndSet(true, false)) {
                        filtering.complete(Thread.currentThread().name)
                        check(release.await(2, TimeUnit.SECONDS))
                    }
                    return modules[index]
                }
            }
            state(vm).value = vm.uiState.value.copy(modules = blockingList)
            val publishedResults = mutableListOf<List<RepoModule>>()
            val collector = launch(start = CoroutineStart.UNDISPATCHED) {
                vm.uiState.collect { publishedResults += it.searchResults }
            }
            try {
                vm.updateSearchText("match")
                val thread = withTimeout(2_000) { filtering.await() }
                assertTrue(thread.startsWith("DefaultDispatcher"))
                vm.updateSearchText("")
                vm.setSortOrder(RepoSort.STARS)
                release.countDown()
                val latest = withTimeout(2_000) {
                    vm.uiState.first { it.sortOrder == RepoSort.STARS && it.searchStatus.resultStatus == SearchStatus.ResultStatus.DEFAULT }
                }
                assertEquals(modules.reversed(), latest.modules)
                assertTrue(latest.searchResults.isEmpty())
                assertTrue(publishedResults.all { it.isEmpty() })
            } finally {
                release.countDown()
                collector.cancelAndJoin()
            }
        }
    }

    @Test(timeout = 5_000)
    fun shouldKeepStableTies_whenSearchingAndChangingSort() = runBlocking {
        withViewModel { vm ->
            val modules = listOf(module("z", 5), module("a", 5), module("b", 10))
            state(vm).value = vm.uiState.value.copy(modules = modules)
            vm.updateSearchText("match")
            withTimeout(2_000) { vm.uiState.first { it.searchResults == modules } }
            vm.setSortOrder(RepoSort.STARS)
            val expected = listOf(modules[2], modules[0], modules[1])
            val latest = withTimeout(2_000) {
                vm.uiState.first { it.sortOrder == RepoSort.STARS && it.searchResults == expected }
            }
            assertEquals(expected, latest.modules)
        }
    }
}
