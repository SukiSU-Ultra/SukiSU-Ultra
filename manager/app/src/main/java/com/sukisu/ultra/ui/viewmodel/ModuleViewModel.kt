package com.sukisu.ultra.ui.viewmodel

import android.os.SystemClock
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.Module
import com.sukisu.ultra.data.model.ModuleUpdateInfo
import com.sukisu.ultra.data.registry.UpdateVerification
import com.sukisu.ultra.data.repository.ModuleRepoRepository
import com.sukisu.ultra.data.repository.ModuleRepoRepositoryImpl
import com.sukisu.ultra.data.repository.ModuleRepository
import com.sukisu.ultra.data.repository.ModuleRepositoryImpl
import com.sukisu.ultra.data.repository.SettingsRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.component.SearchStatus
import com.sukisu.ultra.ui.screen.module.ModuleConfirmDialogState
import com.sukisu.ultra.ui.screen.module.ModuleConfirmRequest
import com.sukisu.ultra.ui.screen.module.ModuleEffect
import com.sukisu.ultra.ui.screen.module.ModuleNameSort
import com.sukisu.ultra.ui.screen.module.ModuleSortOptions
import com.sukisu.ultra.ui.screen.module.ModuleUiState
import com.sukisu.ultra.ui.screen.module.sortModules
import com.sukisu.ultra.ui.util.PinyinUtil
import com.sukisu.ultra.ui.util.hasMagisk
import okhttp3.Request
import org.json.JSONArray
import kotlin.time.Duration.Companion.milliseconds
import com.sukisu.ultra.ui.util.toggleModule as toggleModuleUtil
import com.sukisu.ultra.ui.util.undoUninstallModule as undoUninstallModuleUtil
import com.sukisu.ultra.ui.util.uninstallModule as uninstallModuleUtil

class ModuleViewModel(
    private val repo: ModuleRepository = ModuleRepositoryImpl(),
    private val settingsRepo: SettingsRepository = SettingsRepositoryImpl(),
    private val registryRepo: ModuleRepoRepository = ModuleRepoRepositoryImpl(),
    scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate),
) : ViewModel(scope) {
    
    companion object {
        private const val TAG = "ModuleViewModel"
    }

    private data class ModuleUpdateSignature(
        val updateJson: String,
        val versionCode: Long,
        val enabled: Boolean,
        val update: Boolean,
        val remove: Boolean
    )

    private data class ModuleUpdateCache(
        val signature: ModuleUpdateSignature,
        val info: ModuleUpdateInfo
    )

    private class ModuleUpdateRequest(
        val module: Module,
        val signature: ModuleUpdateSignature
    )

    private val _uiState = MutableStateFlow(ModuleUiState())
    val uiState: StateFlow<ModuleUiState> = _uiState.asStateFlow()

    // One-shot UI events (toast/snackbar): buffered Channel, never dropped/duplicated/overwritten
    private val _moduleEvent = Channel<ModuleEffect>(Channel.BUFFERED)
    val moduleEvent: Flow<ModuleEffect> = _moduleEvent.receiveAsFlow()

    private val updateInfoMutex = Mutex()
    private var updateInfoCache: MutableMap<String, ModuleUpdateCache> = mutableMapOf()
    private val updateInfoInFlight = mutableMapOf<String, ModuleUpdateRequest>()
    private val searchQuery = MutableStateFlow("")

    private var fetchJob: Job? = null

    var isNeedRefresh = false
        private set

    init {
        viewModelScope.launchSearchQueryCollector(searchQuery, ::applySearchText)
        initializePreferences()
    }

    fun markNeedRefresh() {
        isNeedRefresh = true
    }

    fun initializePreferences() {
        _uiState.update {
            it.copy(
                checkModuleUpdate = settingsRepo.checkModuleUpdate,
                sortEnabledFirst = settingsRepo.moduleSortEnabledFirst,
                sortActionFirst = settingsRepo.moduleSortActionFirst,
                sortWebUiFirst = settingsRepo.moduleSortWebUiFirst,
                sortZygiskFirst = settingsRepo.moduleSortZygiskFirst,
                sortMetamoduleFirst = settingsRepo.moduleSortMetamoduleFirst,
                sortNameOrder = ModuleNameSort.fromStored(settingsRepo.moduleSortNameOrder),
                sortManual = settingsRepo.moduleSortManual,
                manualOrder = parseManualOrder(settingsRepo.moduleManualOrder),
            )
        }
        if (_uiState.value.modules.isNotEmpty()) {
            updateModuleList()
        }
    }

    fun toggleSortActionFirst() {
        val newValue = !_uiState.value.sortActionFirst
        disableManualSort()
        settingsRepo.moduleSortActionFirst = newValue
        _uiState.update { it.copy(sortActionFirst = newValue) }
        updateModuleList()
    }

    fun toggleSortEnabledFirst() {
        val newValue = !_uiState.value.sortEnabledFirst
        disableManualSort()
        settingsRepo.moduleSortEnabledFirst = newValue
        _uiState.update { it.copy(sortEnabledFirst = newValue) }
        updateModuleList()
    }

    fun toggleSortWebUiFirst() {
        val newValue = !_uiState.value.sortWebUiFirst
        disableManualSort()
        settingsRepo.moduleSortWebUiFirst = newValue
        _uiState.update { it.copy(sortWebUiFirst = newValue) }
        updateModuleList()
    }

    fun toggleSortZygiskFirst() {
        val newValue = !_uiState.value.sortZygiskFirst
        disableManualSort()
        settingsRepo.moduleSortZygiskFirst = newValue
        _uiState.update { it.copy(sortZygiskFirst = newValue) }
        updateModuleList()
    }

    fun toggleSortMetamoduleFirst() {
        val newValue = !_uiState.value.sortMetamoduleFirst
        disableManualSort()
        settingsRepo.moduleSortMetamoduleFirst = newValue
        _uiState.update { it.copy(sortMetamoduleFirst = newValue) }
        updateModuleList()
    }

    fun setSortNameOrder(order: ModuleNameSort) {
        val newValue = if (_uiState.value.sortNameOrder == order) ModuleNameSort.DEFAULT else order
        disableManualSort()
        settingsRepo.moduleSortNameOrder = newValue.name
        _uiState.update { it.copy(sortNameOrder = newValue) }
        updateModuleList()
    }

    fun toggleSortManual() {
        val newValue = !_uiState.value.sortManual
        val previousOrder = _uiState.value.manualOrder
        if (newValue) {
            clearAutomaticSort()
        }
        settingsRepo.moduleSortManual = newValue
        _uiState.update {
            val manualOrder = if (newValue && it.manualOrder.isEmpty()) {
                it.moduleList.map(Module::id)
            } else {
                it.manualOrder
            }
            it.copy(sortManual = newValue, manualOrder = manualOrder)
        }
        if (_uiState.value.manualOrder != previousOrder) {
            persistManualOrder(_uiState.value.manualOrder)
        }
        updateModuleList()
    }

    fun moveModule(from: Module, to: Module) {
        if (!_uiState.value.sortManual) return
        _uiState.update { state ->
            val fromIndex = state.moduleList.indexOfFirst { it.id == from.id }
            val toIndex = state.moduleList.indexOfFirst { it.id == to.id }
            if (fromIndex == -1 || toIndex == -1 || fromIndex == toIndex) return@update state
            val reordered = state.moduleList.toMutableList().apply {
                add(toIndex, removeAt(fromIndex))
            }
            state.copy(
                moduleList = reordered,
                manualOrder = reordered.map(Module::id),
            )
        }
    }

    fun commitManualOrder() {
        if (!_uiState.value.sortManual) return
        persistManualOrder(_uiState.value.manualOrder)
    }

    private fun disableManualSort() {
        if (!_uiState.value.sortManual) return
        settingsRepo.moduleSortManual = false
        _uiState.update { it.copy(sortManual = false) }
    }

    private fun clearAutomaticSort() {
        val state = _uiState.value
        val hasAutomaticSort = state.sortActionFirst || state.sortEnabledFirst ||
                state.sortWebUiFirst || state.sortZygiskFirst || state.sortMetamoduleFirst ||
                state.sortNameOrder != ModuleNameSort.DEFAULT
        if (!hasAutomaticSort) return
        settingsRepo.moduleSortActionFirst = false
        settingsRepo.moduleSortEnabledFirst = false
        settingsRepo.moduleSortWebUiFirst = false
        settingsRepo.moduleSortZygiskFirst = false
        settingsRepo.moduleSortMetamoduleFirst = false
        settingsRepo.moduleSortNameOrder = ModuleNameSort.DEFAULT.name
        _uiState.update {
            it.copy(
                sortActionFirst = false,
                sortEnabledFirst = false,
                sortWebUiFirst = false,
                sortZygiskFirst = false,
                sortMetamoduleFirst = false,
                sortNameOrder = ModuleNameSort.DEFAULT,
            )
        }
    }

    private fun parseManualOrder(raw: String): List<String> = runCatching {
        val array = JSONArray(raw)
        buildList {
            for (index in 0 until array.length()) {
                array.optString(index).takeIf { it.isNotEmpty() }?.let(::add)
            }
        }
    }.getOrDefault(emptyList())

    private fun persistManualOrder(order: List<String>) {
        settingsRepo.moduleManualOrder = JSONArray(order).toString()
    }

    fun refreshEnvironmentState() {
        viewModelScope.launch {
            val magiskInstalled = withContext(Dispatchers.IO) { hasMagisk() }
            val isSafeMode = Natives.isSafeMode
            _uiState.update {
                it.copy(
                    magiskInstalled = magiskInstalled,
                    isSafeMode = isSafeMode,
                )
            }
        }
    }

    fun updateSearchStatus(status: SearchStatus) {
        val previous = _uiState.value.searchStatus
        _uiState.update { it.copy(searchStatus = status) }
        if (previous.searchText != status.searchText) {
            searchQuery.value = status.searchText
        }
    }

    fun updateSearchText(text: String) {
        updateSearchStatus(_uiState.value.searchStatus.copy(searchText = text))
    }

    private fun filterModules(modules: List<Module>, text: String): List<Module> {
        if (text.isEmpty()) return emptyList()

        return modules.filter {
            it.id.contains(text, true) || it.name.contains(text, true) ||
                    it.description.contains(text, true) || it.author.contains(text, true) ||
                    PinyinUtil.toPinyin(it.name).contains(text, true)
        }
    }

    private suspend fun applySearchText(text: String) {
        _uiState.update {
            it.copy(
                searchStatus = it.searchStatus.copy(
                    resultStatus = searchLoadingStatusFor(text)
                )
            )
        }

        if (text.isEmpty()) {
            updateModuleList()
            return
        }

        val result = withContext(Dispatchers.IO) {
            val state = _uiState.value
            sortModules(filterModules(state.modules, text), state.sortOptions())
        }

        _uiState.update {
            it.copy(
                searchResults = result,
                searchStatus = it.searchStatus.copy(
                    resultStatus = searchResultStatusFor(text, result.isEmpty())
                )
            )
        }
    }

    private fun updateModuleList(resort: Boolean = true) {
        viewModelScope.launch(Dispatchers.IO) {
            val state = _uiState.value
            val searchText = state.searchStatus.searchText
            val shorted = if (resort || state.moduleList.isEmpty()) {
                sortModules(state.modules, state.sortOptions())
            } else {
                // Order-preserving reload: keep order, refresh data, drop removed, append new (no re-sort on toggle/uninstall)
                val byId = state.modules.associateBy { it.id }
                val existingIds = state.moduleList.mapTo(HashSet()) { it.id }
                state.moduleList.mapNotNull { byId[it.id] } + state.modules.filter { it.id !in existingIds }
            }
            val searchResults = filterModules(shorted, searchText)
            // Never overwrite the saved order while the module list is not loaded yet.
            val manualOrder = if (state.sortManual && shorted.isNotEmpty()) {
                shorted.map(Module::id)
            } else {
                state.manualOrder
            }
            if (state.sortManual && manualOrder != state.manualOrder) {
                persistManualOrder(manualOrder)
            }

            _uiState.update {
                it.copy(
                    moduleList = shorted,
                    searchResults = searchResults,
                    manualOrder = manualOrder,
                    searchStatus = it.searchStatus.copy(
                        resultStatus = searchResultStatusFor(searchText, searchResults.isEmpty())
                    )
                )
            }
        }
    }

    private fun ModuleUiState.sortOptions() = ModuleSortOptions(
        enabledFirst = sortEnabledFirst,
        metamoduleFirst = sortMetamoduleFirst,
        zygiskFirst = sortZygiskFirst,
        webUiFirst = sortWebUiFirst,
        actionFirst = sortActionFirst,
        nameOrder = sortNameOrder,
        manual = sortManual,
        manualOrder = manualOrder,
    )

    suspend fun loadModuleList(resort: Boolean = true) {
        val parsedModules = withContext(Dispatchers.IO) {
            repo.getModules().getOrElse {
                Log.e(TAG, "fetchModuleList: ", it)
                emptyList()
            }
        }

        withContext(Dispatchers.Main) {
            _uiState.update {
                it.copy(
                    modules = parsedModules,
                )
            }
            // Trigger recalculation of moduleList
            updateModuleList(resort)
            isNeedRefresh = false
        }
    }

    fun fetchModuleList(checkUpdate: Boolean = false, resort: Boolean = true) {
        fetchJob?.cancel()
        _uiState.update { it.copy(isRefreshing = true) }
        fetchJob = viewModelScope.launch {
            try {
                val start = SystemClock.elapsedRealtime()

                loadModuleList(resort)

                if (checkUpdate) syncModuleUpdateInfo(_uiState.value.modules)

                Log.i(TAG, "load cost: ${SystemClock.elapsedRealtime() - start}, modules: ${_uiState.value.modules}")
            } finally {
                _uiState.update { it.copy(isRefreshing = false, hasLoaded = true) }
            }
        }
    }

    private fun Module.toSignature(): ModuleUpdateSignature {
        return ModuleUpdateSignature(
            updateJson = updateJson,
            versionCode = versionCode,
            enabled = enabled,
            update = update,
            remove = remove
        )
    }

    suspend fun syncModuleUpdateInfo(modules: List<Module>) {
        if (!_uiState.value.checkModuleUpdate) return

        val requests = mutableListOf<ModuleUpdateRequest>()
        try {
            updateInfoMutex.withLock {
                val ids = modules.map { it.id }.toSet()
                val removedIds = (updateInfoCache.keys + updateInfoInFlight.keys).filter { it !in ids }.toSet()
                removedIds.forEach { id ->
                    updateInfoCache.remove(id)
                    updateInfoInFlight.remove(id)
                }
                if (removedIds.isNotEmpty()) {
                    _uiState.update { it.copy(updateInfo = it.updateInfo - removedIds) }
                }

                modules.forEach { module ->
                    val signature = module.toSignature()
                    val cached = updateInfoCache[module.id]
                    if (updateInfoInFlight[module.id]?.signature != signature) {
                        updateInfoInFlight.remove(module.id)
                    }
                    if ((cached == null || cached.signature != signature) && module.id !in updateInfoInFlight) {
                        val request = ModuleUpdateRequest(module, signature)
                        requests += request
                        updateInfoInFlight[module.id] = request
                    }
                }
            }

            val fetchedEntries = coroutineScope {
                requests.map { request ->
                    async {
                        val info = withTimeoutOrNull(5_000L.milliseconds) {
                            withContext(Dispatchers.IO) { checkUpdate(request.module) }
                        }
                        info?.let { request to ModuleUpdateCache(request.signature, it) }
                    }
                }.awaitAll().filterNotNull()
            }

            updateInfoMutex.withLock {
                val changedEntries = mutableMapOf<String, ModuleUpdateInfo>()
                fetchedEntries.forEach { (request, entry) ->
                    val id = request.module.id
                    // A newer signature or remove/re-add may have replaced this request.
                    if (updateInfoInFlight[id] !== request) return@forEach
                    val existing = updateInfoCache[id]
                    if (existing != entry) {
                        updateInfoCache[id] = entry
                        changedEntries[id] = entry.info
                    }
                }
                if (changedEntries.isNotEmpty()) {
                    // StateFlow is thread-safe; publish with the cache under the same lock.
                    _uiState.update { it.copy(updateInfo = it.updateInfo + changedEntries) }
                }
            }
        } finally {
            withContext(NonCancellable) {
                updateInfoMutex.withLock {
                    requests.forEach { request ->
                        val id = request.module.id
                        if (updateInfoInFlight[id] === request) updateInfoInFlight.remove(id)
                    }
                }
            }
        }
    }

    fun requestUpdateConfirmation(module: Module, updateInfo: ModuleUpdateInfo) {
        viewModelScope.launch {
            val verification = registryRepo.resolveUpdate(
                moduleId = module.id,
                updateJsonUrl = module.updateJson,
                zipUrl = updateInfo.downloadUrl,
                versionCode = updateInfo.versionCode,
            )
            if (verification is UpdateVerification.Rejected) {
                Log.w(TAG, "refusing update of ${module.id}: ${verification.reason}")
                emitEffect(ModuleEffect.Toast(ksuApp.getString(R.string.module_update_unverifiable, module.name)))
                return@launch
            }
            val dialogState = buildUpdateConfirmDialogState(module, updateInfo, verification)
            _uiState.update { it.copy(confirmDialogState = dialogState) }
        }
    }

    fun requestUninstallConfirmation(module: Module) {
        val res = ksuApp.resources
        _uiState.update {
            it.copy(
                confirmDialogState = ModuleConfirmDialogState(
                    request = ModuleConfirmRequest.Uninstall(module),
                    title = res.getString(R.string.module),
                    content = (if (module.metamodule) res.getString(R.string.metamodule_uninstall_confirm) else res.getString(R.string.module_uninstall_confirm)).format(
                        module.name
                    ),
                    confirm = res.getString(R.string.uninstall),
                    dismiss = res.getString(android.R.string.cancel),
                )
            )
        }
    }

    fun dismissConfirmRequest() {
        _uiState.update { it.copy(confirmDialogState = null) }
    }

    fun emitEffect(effect: ModuleEffect) {
        _moduleEvent.trySend(effect)
    }

    fun toggleModule(module: Module) {
        viewModelScope.launch {
            val res = ksuApp.resources
            val success = withContext(Dispatchers.IO) {
                toggleModuleUtil(module.id, !module.enabled)
            }
            if (success) {
                fetchModuleList(checkUpdate = true, resort = false)
                emitEffect(ModuleEffect.SnackBar(res.getString(R.string.reboot_to_apply)))
            } else {
                val message = if (module.enabled) R.string.module_failed_to_disable else R.string.module_failed_to_enable
                emitEffect(ModuleEffect.SnackBar(res.getString(message).format(module.name)))
            }
        }
    }

    fun uninstallModule(module: Module) {
        viewModelScope.launch {
            val res = ksuApp.resources
            val success = withContext(Dispatchers.IO) {
                uninstallModuleUtil(module.id)
            }
            if (success) {
                fetchModuleList(checkUpdate = true, resort = false)
            }
            _uiState.update { it.copy(confirmDialogState = null) }
            emitEffect(
                ModuleEffect.SnackBar(
                    res.getString(
                        if (success) R.string.module_uninstall_success else R.string.module_uninstall_failed
                    ).format(module.name)
                )
            )
        }
    }

    fun undoUninstallModule(module: Module) {
        viewModelScope.launch {
            val res = ksuApp.resources
            val success = withContext(Dispatchers.IO) {
                undoUninstallModuleUtil(module.id)
            }
            if (success) {
                fetchModuleList(checkUpdate = true, resort = false)
            }
            emitEffect(
                ModuleEffect.SnackBar(
                    res.getString(
                        if (success) R.string.module_undo_uninstall_success else R.string.module_undo_uninstall_failed
                    ).format(module.name)
                )
            )
        }
    }

    private suspend fun buildUpdateConfirmDialogState(
        module: Module,
        updateInfo: ModuleUpdateInfo,
        verification: UpdateVerification,
    ): ModuleConfirmDialogState {
        val res = ksuApp.resources
        val changelogUrl = updateInfo.changelog

        var changelog = ""
        var html = false
        // Registry-hosted content is always shown in the restricted (JavaScript-off) renderer.
        var restricted = false

        withContext(Dispatchers.IO) {
            if (verification is UpdateVerification.Registry) {
                // A registry release: only ever show the registry's own release notes.
                verification.release.changelogHtml?.takeIf { it.isNotBlank() }?.let {
                    changelog = it
                    html = true
                    restricted = true
                }
                if (changelog.isBlank() && registryRepo.isRegistryUrl(changelogUrl)) {
                    registryRepo.fetchRegistryText(changelogUrl)?.let {
                        changelog = it
                        restricted = true
                    }
                }
                return@withContext
            }
            if (changelogUrl.isBlank()) return@withContext
            if (changelogUrl.startsWith("#") && changelogUrl.contains('@')) {
                val parts = changelogUrl.substring(1).split('@', limit = 2)
                if (parts.size == 2) {
                    registryRepo.fetchChangelogHtml(parts[0], parts[1])?.let {
                        changelog = it
                        html = true
                        restricted = true
                    }
                }
                return@withContext
            }
            if (registryRepo.isRegistryUrl(changelogUrl)) {
                registryRepo.fetchRegistryText(changelogUrl)?.let {
                    changelog = it
                    restricted = true
                }
                return@withContext
            }
            changelog = runCatching {
                ksuApp.okhttpClient.newCall(
                    Request.Builder().url(changelogUrl).build()
                ).execute().use { it.body.string() }
            }.getOrDefault("")
        }

        val registry = verification as? UpdateVerification.Registry
        return ModuleConfirmDialogState(
            request = ModuleConfirmRequest.Update(
                module = module,
                downloadUrl = registry?.zipUrl ?: updateInfo.downloadUrl,
                fileName = "${module.name}-${updateInfo.version}.zip",
                expected = registry?.expected,
            ),
            title = if (changelog.isNotBlank()) res.getString(R.string.module_changelog) else res.getString(R.string.module_update),
            content = changelog.ifBlank { res.getString(R.string.module_start_downloading).format(module.name) },
            markdown = changelog.isNotBlank() && !html,
            html = changelog.isNotBlank() && html,
            restricted = changelog.isNotBlank() && restricted,
            confirm = res.getString(R.string.module_update),
        )
    }

    private suspend fun checkUpdate(m: Module): ModuleUpdateInfo? {
        return repo.checkUpdate(m).getOrElse {
            if (it is CancellationException) throw it
            null
        }
    }
}
