package com.sukisu.ultra.ui.screen.susfs.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.ui.screen.susfs.SuSFSTab
import com.sukisu.ultra.ui.screen.susfs.SuSFSUiState
import com.sukisu.ultra.ui.screen.susfs.repository.SuSFSRepositoryInterface
import com.sukisu.ultra.ui.screen.susfs.repository.SuSFSRepositoryImpl
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
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

    fun loadInitial(context: Context) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }

            val canEnableAutoStart = withContext(Dispatchers.IO) {
                SuSFSManager.hasConfigurationForAutoStart(context)
            }

            repo.loadInitialConfig(context).onSuccess { config ->
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        unameValue = config.unameValue,
                        buildTimeValue = config.buildTimeValue,
                        autoStartEnabled = SuSFSManager.isAutoStartEnabled(),
                        executeInPostFsData = config.executeInPostFsData,
                        susPaths = config.susPaths,
                        susLoopPaths = config.susLoopPaths,
                        susMaps = config.susMaps,
                        kstatConfigs = config.kstatConfigs,
                        addKstatPaths = config.addKstatPaths,
                        hideSusMountsForAllProcs = config.hideSusMountsForAllProcs,
                        enableHideBl = config.enableHideBl,
                        enableCleanupResidue = config.enableCleanupResidue,
                        enableAvcLogSpoofing = config.enableAvcLogSpoofing,
                        canEnableAutoStart = canEnableAutoStart
                    )
                }
                loadSlotInfo(context)
            }.onFailure { e ->
                _uiState.update { it.copy(isLoading = false, error = e) }
            }
        }
    }

    fun loadEnabledFeatures(context: Context) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoadingFeatures = true) }
            repo.getEnabledFeatures(context).onSuccess { features ->
                _uiState.update { it.copy(enabledFeatures = features, isLoadingFeatures = false) }
            }.onFailure { e ->
                _uiState.update { it.copy(isLoadingFeatures = false, error = e) }
            }
        }
    }

    fun loadInstalledApps() {
        viewModelScope.launch {
            repo.getInstalledApps().onSuccess { apps ->
                _uiState.update { it.copy(installedApps = apps) }
            }.onFailure { e ->
                _uiState.update { it.copy(error = e) }
            }
        }
    }

    fun loadSlotInfo(context: Context) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoadingSlotInfo = true) }
            repo.getSlotInfo(context = context).onSuccess { (list, current) ->
                _uiState.update {
                    it.copy(
                        slotInfoList = list,
                        currentActiveSlot = current,
                        isLoadingSlotInfo = false
                    )
                }
            }.onFailure { e ->
                _uiState.update { it.copy(isLoadingSlotInfo = false, error = e) }
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

    fun applyBasicSettings(context: Context) {
        viewModelScope.launch {
            val current = _uiState.value
            _uiState.update { it.copy(isLoading = true) }
            val success = SuSFSManager.setUname(
                context,
                current.unameValue.trim(),
                current.buildTimeValue.trim()
            )
            if (success) {
                SuSFSManager.saveExecuteInPostFsData(current.executeInPostFsData)
                if (SuSFSManager.isAutoStartEnabled()) {
                    SuSFSManager.configureAutoStart(context, true)
                }
            }
            _uiState.update { it.copy(isLoading = false) }
            reloadConfig()
        }
    }

    fun resetAll() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            _uiState.update { it.copy(isLoading = false, showConfirmReset = false) }
            reloadConfig()
        }
    }

    fun configureAutoStart(context: Context, enabled: Boolean) {
        viewModelScope.launch {
            val canEnable = _uiState.value.canEnableAutoStart
            if (!canEnable) return@launch
            _uiState.update { it.copy(isLoading = true) }
            val success = SuSFSManager.configureAutoStart(context, enabled)
            _uiState.update {
                it.copy(
                    isLoading = false,
                    autoStartEnabled = if (success) enabled else it.autoStartEnabled
                )
            }
        }
    }

    fun setEnableHideBl(context: Context, enabled: Boolean) {
        viewModelScope.launch {
            _uiState.update { it.copy(enableHideBl = enabled) }
            SuSFSManager.saveEnableHideBl(enabled)
            if (SuSFSManager.isAutoStartEnabled()) {
                SuSFSManager.configureAutoStart(context, true)
            }
        }
    }

    fun setEnableCleanupResidue(context: Context, enabled: Boolean) {
        viewModelScope.launch {
            _uiState.update { it.copy(enableCleanupResidue = enabled) }
            SuSFSManager.saveEnableCleanupResidue(enabled)
            if (SuSFSManager.isAutoStartEnabled()) {
                SuSFSManager.configureAutoStart(context, true)
            }
        }
    }

    fun setEnableAvcLogSpoofing(context: Context, enabled: Boolean) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            val success = withContext(Dispatchers.IO) {
                SuSFSManager.setEnableAvcLogSpoofing(context, enabled)
            }
            _uiState.update {
                it.copy(
                    enableAvcLogSpoofing = if (success) enabled else it.enableAvcLogSpoofing,
                    isLoading = false
                )
            }
        }
    }

    fun setHideSusMountsForAllProcs(context: Context, hideForAll: Boolean) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            val success = withContext(Dispatchers.IO) {
                SuSFSManager.setHideSusMountsForAllProcs(context, hideForAll)
            }
            _uiState.update {
                it.copy(
                    hideSusMountsForAllProcs = if (success) hideForAll else it.hideSusMountsForAllProcs,
                    isLoading = false
                )
            }
        }
    }

    fun reloadConfig() {
        viewModelScope.launch {
            val config = SuSFSManager.getCurrentModuleConfig()
            _uiState.update {
                it.copy(
                    unameValue = config.unameValue,
                    buildTimeValue = config.buildTimeValue,
                    autoStartEnabled = SuSFSManager.isAutoStartEnabled(),
                    executeInPostFsData = config.executeInPostFsData,
                    susPaths = config.susPaths,
                    susLoopPaths = config.susLoopPaths,
                    susMaps = config.susMaps,
                    kstatConfigs = config.kstatConfigs,
                    addKstatPaths = config.addKstatPaths,
                    hideSusMountsForAllProcs = config.hideSusMountsForAllProcs,
                    enableHideBl = config.enableHideBl,
                    enableCleanupResidue = config.enableCleanupResidue,
                    enableAvcLogSpoofing = config.enableAvcLogSpoofing
                )
            }
        }
    }
}

