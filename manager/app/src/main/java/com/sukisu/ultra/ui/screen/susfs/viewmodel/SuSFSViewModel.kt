package com.sukisu.ultra.ui.screen.susfs.viewmodel

import android.content.Context
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.ConfigResult
import com.sukisu.ultra.ui.component.ConfigRuntimeStatus
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSPathManager
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSCommands
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSRepository
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.ui.screen.susfs.SuSFSTab
import com.sukisu.ultra.ui.screen.susfs.SuSFSUiState
import com.sukisu.ultra.ui.screen.susfs.SuSFSRuntimeInfo
import com.sukisu.ultra.ui.util.getSuSFSVersion
import com.sukisu.ultra.ui.util.getSuSFSVariant
import com.sukisu.ultra.ui.util.getSuSFSImplementation
import com.sukisu.ultra.ui.screen.susfs.repository.SuSFSRepositoryInterface
import com.sukisu.ultra.ui.screen.susfs.repository.SuSFSRepositoryImpl
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SuSFSViewModel(
    private val repo: SuSFSRepositoryInterface = SuSFSRepositoryImpl()
) : ViewModel() {

    private val _uiState = MutableStateFlow(SuSFSUiState())
    val uiState: StateFlow<SuSFSUiState> = _uiState.asStateFlow()

    fun setSelectedTab(tab: SuSFSTab) {
        _uiState.update { it.copy(selectedTab = tab) }
    }

    private var loaded = false
    private var appContext: Context? = null

    fun loadInitial(context: Context) {
        if (loaded) return
        loaded = true
        appContext = context.applicationContext
        loadRuntimeInfo()
        _uiState.update { it.copy(isLoading = true, error = null) }
        viewModelScope.launch {
            try {
            repo.loadInitialConfig(context).onSuccess { config ->
                val canEnableAutoStart = SuSFSManager.hasConfigurationForAutoStart(context, config)
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        unameValue = config.unameValue,
                        buildTimeValue = config.buildTimeValue,
                        autoStartEnabled = config.autoStartEnabled,
                        executeInPostFsData = config.executeInPostFsData,
                        susPaths = config.susPaths,
                        susLoopPaths = config.susLoopPaths,
                        susMaps = config.susMaps,
                        kstatConfigs = config.kstatConfigs,
                        addKstatPaths = config.addKstatPaths,
                        hideSusMountsForAllProcs = config.hideSusMountsForAllProcs,
                        enableHideBl = config.enableHideBl,
                        enableLog = config.enableLog,
                        enableCleanupResidue = config.enableCleanupResidue,
                        enableAvcLogSpoofing = config.enableAvcLogSpoofing,
                        cmdlineOrBootconfigPath = config.cmdlineOrBootconfigPath,
                        canEnableAutoStart = canEnableAutoStart
                    )
                }
            }.onFailure { e ->
                loaded = false
                _uiState.update { it.copy(error = e) }
            }
            } catch (e: CancellationException) {
                loaded = false
                throw e
            } catch (e: Exception) {
                loaded = false
                _uiState.update { it.copy(error = e) }
            } finally {
                _uiState.update { it.copy(isLoading = false) }
            }
        }
    }

    private fun loadRuntimeInfo() {
        viewModelScope.launch(Dispatchers.IO) {
            fun readValue(query: () -> String): String? {
                return try {
                    query().trim().takeIf {
                        it.isNotBlank() && !it.equals("unsupport", true) &&
                            !it.equals("unsupported", true) && !it.equals("unknown", true)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    null
                }
            }
            // Read independently: a missing optional query must not hide version/variant.
            val version = readValue(::getSuSFSVersion)
            val variant = readValue(::getSuSFSVariant)
            val implementation = when (readValue(::getSuSFSImplementation)?.lowercase()) {
                "lkm" -> "LKM"
                "builtin", "built-in" -> "Built-in"
                else -> null
            }
            _uiState.update { it.copy(runtimeInfo = SuSFSRuntimeInfo(version, variant, implementation)) }
        }
    }

    fun loadEnabledFeatures(context: Context) {
        if (_uiState.value.isLoadingFeatures) return
        _uiState.update { it.copy(isLoadingFeatures = true, error = null) }
        viewModelScope.launch {
            repo.getEnabledFeatures(context).onSuccess { features ->
                _uiState.update { it.copy(enabledFeatures = features, isLoadingFeatures = false) }
            }.onFailure { e ->
                _uiState.update { it.copy(isLoadingFeatures = false, error = e) }
            }
        }
    }

    private var loadingApps = false

    fun loadInstalledApps() {
        if (loadingApps || _uiState.value.installedApps.isNotEmpty()) return
        loadingApps = true
        _uiState.update { it.copy(isLoadingApps = true) }
        viewModelScope.launch {
            repo.getInstalledApps().onSuccess { apps ->
                _uiState.update { it.copy(installedApps = apps) }
            }.onFailure { e ->
                _uiState.update { it.copy(error = e) }
            }
            loadingApps = false
            _uiState.update { it.copy(isLoadingApps = false) }
        }
    }

    fun loadSlotInfo(context: Context) {
        if (_uiState.value.isLoadingSlotInfo) return
        _uiState.update { it.copy(isLoadingSlotInfo = true, slotInfoError = null) }
        viewModelScope.launch {
            repo.getSlotInfo(context = context).onSuccess { (list, current) ->
                _uiState.update {
                    it.copy(
                        slotInfoList = list,
                        currentActiveSlot = current,
                        isLoadingSlotInfo = false
                    )
                }
            }.onFailure { e ->
                _uiState.update { it.copy(isLoadingSlotInfo = false, slotInfoError = e.localizedMessage) }
            }
        }
    }

    fun updateUname(value: String) {
        _uiState.update { it.copy(unameValue = value) }
    }

    fun updateBuildTime(value: String) {
        _uiState.update { it.copy(buildTimeValue = value) }
    }

    fun setExecuteInPostFsData(value: Boolean) {
        _uiState.update { it.copy(executeInPostFsData = value) }
    }

    fun toggleConfirmReset(show: Boolean) {
        _uiState.update { it.copy(showConfirmReset = show) }
    }

    fun showSlotInfoDialog(show: Boolean) {
        _uiState.update { it.copy(showSlotInfoDialog = show) }
    }

    fun openAddPathDialog(editing: String? = null) {
        _uiState.update { it.copy(showAddPathDialog = true, editingPath = editing) }
    }

    fun closeAddPathDialog() {
        _uiState.update { it.copy(showAddPathDialog = false, editingPath = null) }
    }

    fun openAddLoopPathDialog(editing: String? = null) {
        _uiState.update { it.copy(showAddLoopPathDialog = true, editingLoopPath = editing) }
    }

    fun closeAddLoopPathDialog() {
        _uiState.update { it.copy(showAddLoopPathDialog = false, editingLoopPath = null) }
    }

    fun openAddSusMapDialog(editing: String? = null) {
        _uiState.update { it.copy(showAddSusMapDialog = true, editingSusMap = editing) }
    }

    fun closeAddSusMapDialog() {
        _uiState.update { it.copy(showAddSusMapDialog = false, editingSusMap = null) }
    }

    fun openAddAppPathDialog() {
        _uiState.update { it.copy(showAddAppPathDialog = true) }
    }

    fun closeAddAppPathDialog() {
        _uiState.update { it.copy(showAddAppPathDialog = false) }
    }

    fun openAddKstatStaticallyDialog(editing: String? = null) {
        _uiState.update {
            it.copy(
                showAddKstatStaticallyDialog = true,
                editingKstatConfig = editing
            )
        }
    }

    fun closeAddKstatStaticallyDialog() {
        _uiState.update {
            it.copy(
                showAddKstatStaticallyDialog = false,
                editingKstatConfig = null
            )
        }
    }

    fun openAddKstatDialog(editing: String? = null) {
        _uiState.update {
            it.copy(
                showAddKstatDialog = true,
                editingKstatPath = editing
            )
        }
    }

    fun closeAddKstatDialog() {
        _uiState.update {
            it.copy(
                showAddKstatDialog = false,
                editingKstatPath = null
            )
        }
    }

    fun toggleResetPathsDialog(show: Boolean) {
        _uiState.update { it.copy(showResetPathsDialog = show) }
    }

    fun toggleResetLoopPathsDialog(show: Boolean) {
        _uiState.update { it.copy(showResetLoopPathsDialog = show) }
    }

    fun toggleResetSusMapsDialog(show: Boolean) {
        _uiState.update { it.copy(showResetSusMapsDialog = show) }
    }

    fun toggleResetKstatDialog(show: Boolean) {
        _uiState.update { it.copy(showResetKstatDialog = show) }
    }

    private suspend fun report(
        context: Context,
        name: String,
        status: ConfigRuntimeStatus = ConfigRuntimeStatus.UNVERIFIED,
        operation: suspend () -> Boolean,
    ) {
        val result = try {
            if (operation()) ConfigResult(name, true, status)
            else ConfigResult(name, null, ConfigRuntimeStatus.FAILED,
                context.getString(R.string.config_command_rejected))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            ConfigResult(name, null, ConfigRuntimeStatus.FAILED,
                e.localizedMessage ?: context.getString(R.string.config_command_rejected))
        }
        _uiState.update { it.copy(operationResults = it.operationResults + result) }
    }

    private fun beginResults() {
        _uiState.update { it.copy(operationResults = emptyList()) }
    }

    fun applyBasicSettings(context: Context) = performOperation {
        beginResults()
        val current = _uiState.value
        report(context, context.getString(R.string.susfs_tab_basic_settings)) {
            SuSFSManager.setUname(context, current.unameValue.trim(), current.buildTimeValue.trim())
        }
        report(context, "post-fs-data") {
            SuSFSManager.saveExecuteInPostFsData(current.executeInPostFsData)
            true
        }
        if (SuSFSManager.isAutoStartEnabled()) {
            report(context, context.getString(R.string.susfs_autostart_title)) {
                SuSFSManager.configureAutoStart(context, true)
            }
        }
        refreshConfig()
    }

    fun addAppPaths(context: Context, packages: List<String>) = performOperation {
        beginResults()
        packages.forEach { packageName ->
            val paths = SuSFSPathManager.getAppPaths(context, packageName)
            if (paths.isEmpty()) report(context, packageName) { false }
            else paths.forEach { path ->
                report(context, path) {
                    val result = SuSFSPathManager.addSusPathWithResult(context, path)
                    check(result.isSuccess) {
                        result.errorOutput.ifBlank { result.output }.ifBlank {
                            context.getString(R.string.config_command_rejected)
                        }
                    }
                    true
                }
            }
        }
        refreshConfig()
        closeAddAppPathDialog()
    }

    fun performOperation(operation: suspend () -> Unit) {
        if (_uiState.value.isLoading) return
        _uiState.update { it.copy(isLoading = true, error = null) }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { operation() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update { it.copy(error = e) }
            } finally {
                _uiState.update { it.copy(isLoading = false) }
            }
        }
    }

    fun resetAll(context: Context) = performOperation {
        check(SuSFSManager.resetToDefault(context))
        _uiState.update { it.copy(showConfirmReset = false) }
        refreshConfig()
    }

    fun configureAutoStart(context: Context, enabled: Boolean) = performOperation {
        if (enabled && !_uiState.value.canEnableAutoStart) return@performOperation
        check(SuSFSManager.configureAutoStart(context, enabled))
        _uiState.update { it.copy(autoStartEnabled = enabled) }
    }

    private fun setRuntimeToggle(
        context: Context,
        title: Int,
        command: String,
        enabled: Boolean,
        save: suspend (Boolean) -> Unit,
    ) = performOperation {
        beginResults()
        val result = SuSFSCommands.executeSusfsCommandWithOutput("$command ${if (enabled) 1 else 0}")
        if (!result.isSuccess) {
            _uiState.update { it.copy(operationResults = listOf(ConfigResult(
                context.getString(title), null, ConfigRuntimeStatus.FAILED,
                result.errorOutput.ifBlank { result.output }.ifBlank {
                    context.getString(R.string.config_command_rejected)
                }
            ))) }
            return@performOperation
        }
        report(context, context.getString(title)) {
            save(enabled)
            true
        }
        if (SuSFSManager.isAutoStartEnabled()) {
            report(context, context.getString(R.string.susfs_autostart_title)) {
                SuSFSManager.configureAutoStart(context, true)
            }
        }
        refreshConfig()
    }

    fun setEnableLog(context: Context, enabled: Boolean) = setRuntimeToggle(
        context, R.string.susfs_enable_log_label, "enable-log", enabled,
        SuSFSRepository::saveEnableLogState
    )

    private fun saveBootToggle(
        context: Context,
        title: Int,
        enabled: Boolean,
        save: suspend (Boolean) -> Unit,
    ) = performOperation {
        beginResults()
        val autoStart = SuSFSManager.isAutoStartEnabled()
        report(context, context.getString(title)) {
            save(enabled)
            true
        }
        val saved = _uiState.value.operationResults.lastOrNull()?.saved == true
        val scheduled = saved && autoStart && SuSFSManager.configureAutoStart(context, true)
        _uiState.update { state -> state.copy(operationResults = state.operationResults.map { result ->
            if (!saved) result else result.copy(
                runtime = if (scheduled) ConfigRuntimeStatus.REBOOT_REQUIRED
                    else if (autoStart) ConfigRuntimeStatus.FAILED else ConfigRuntimeStatus.UNVERIFIED,
                reason = if (!autoStart) context.getString(R.string.config_autostart_required)
                    else if (!scheduled) context.getString(R.string.config_command_rejected) else null
            )
        }) }
        refreshConfig()
    }

    fun setEnableHideBl(context: Context, enabled: Boolean) = saveBootToggle(
        context, R.string.hide_bl_script, enabled, SuSFSRepository::saveEnableHideBl
    )

    fun setEnableCleanupResidue(context: Context, enabled: Boolean) = saveBootToggle(
        context, R.string.cleanup_residue, enabled, SuSFSRepository::saveEnableCleanupResidue
    )

    fun setEnableAvcLogSpoofing(context: Context, enabled: Boolean) = setRuntimeToggle(
        context, R.string.avc_log_spoofing, "enable-avc-log-spoofing", enabled,
        SuSFSRepository::saveEnableAvcLogSpoofing
    )

    fun setHideSusMountsForAllProcs(context: Context, hideForAll: Boolean) = setRuntimeToggle(
        context, R.string.susfs_hide_mounts_for_all_procs_label,
        "hide-sus-mnts-for-non-su-procs", hideForAll, SuSFSRepository::saveHideSusMountsForAllProcs
    )

    fun reloadConfig() {
        viewModelScope.launch {
            try {
                refreshConfig()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update { it.copy(error = e) }
            }
        }
    }

    internal suspend fun refreshConfig() {
        val config = SuSFSManager.getCurrentModuleConfig()
        val canEnable = appContext?.let { SuSFSManager.hasConfigurationForAutoStart(it, config) } ?: false
        _uiState.update {
            it.copy(
                unameValue = config.unameValue,
                buildTimeValue = config.buildTimeValue,
                autoStartEnabled = config.autoStartEnabled,
                executeInPostFsData = config.executeInPostFsData,
                susPaths = config.susPaths,
                susLoopPaths = config.susLoopPaths,
                susMaps = config.susMaps,
                kstatConfigs = config.kstatConfigs,
                addKstatPaths = config.addKstatPaths,
                hideSusMountsForAllProcs = config.hideSusMountsForAllProcs,
                enableHideBl = config.enableHideBl,
                        enableLog = config.enableLog,
                enableCleanupResidue = config.enableCleanupResidue,
                enableAvcLogSpoofing = config.enableAvcLogSpoofing,
                cmdlineOrBootconfigPath = config.cmdlineOrBootconfigPath,
                canEnableAutoStart = canEnable
            )
        }
    }


    fun applyCmdlineOrBootconfig(context: Context, sourceUri: String) = performOperation {
        check(SuSFSManager.setCmdlineOrBootconfigFile(context, sourceUri))
        val path = SuSFSManager.getCmdlineOrBootconfigPath()
        _uiState.update { it.copy(cmdlineOrBootconfigPath = path, cmdlineOrBootconfigError = null) }
    }
}
