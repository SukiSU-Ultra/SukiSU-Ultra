package com.sukisu.ultra.ui.screen.susfs

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.component.*
import com.sukisu.ultra.ui.screen.susfs.content.*
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.screen.susfs.viewmodel.SuSFSViewModel

@RequiresApi(Build.VERSION_CODES.Q)
@Composable
internal fun SuSFSDialogs(uiState: SuSFSUiState, viewModel: SuSFSViewModel) {
    val context = LocalContext.current
    PriorityUidFilterDialog(
        showDialog = uiState.showPriorityAppsDialog && uiState.selectedTab == SuSFSTab.PRIORITY_UID_FILTER,
        onDismiss = { viewModel.showPriorityAppsDialog(false) },
        onConfirm = { viewModel.applyPriorityUidFilter(context, it.toSet()) },
        isLoading = uiState.isLoading,
        apps = uiState.priorityApps,
        isLoadingApps = uiState.isLoadingPriorityApps,
        selectedPackages = uiState.priorityUidFilter,
    )
    SlotInfoDialog(
        showDialog = uiState.showSlotInfoDialog,
        onDismiss = { viewModel.showSlotInfoDialog(false) },
        slotInfoList = uiState.slotInfoList,
        currentActiveSlot = uiState.currentActiveSlot,
        isLoadingSlotInfo = uiState.isLoadingSlotInfo,
        error = uiState.slotInfoError,
        onRefresh = { viewModel.loadSlotInfo(context) },
        onUseUname = { uname ->
            viewModel.updateUname(uname)
        },
        onUseBuildTime = { buildTime ->
            viewModel.updateBuildTime(buildTime)
        }
    )

    AddPathDialog(
        showDialog = uiState.showAddPathDialog,
        onDismiss = { viewModel.closeAddPathDialog() },
        onConfirm = { path ->
            val oldPath = uiState.editingPath
            viewModel.performOperation {
                val success = if (oldPath != null) {
                    SuSFSManager.editSusPath(context, oldPath, path)
                } else {
                    SuSFSManager.addSusPath(context, path)
                }
                check(success)
                viewModel.refreshConfig()
                viewModel.closeAddPathDialog()
            }
        },
        isLoading = uiState.isLoading,
        titleRes = if (uiState.editingPath != null) R.string.susfs_edit_sus_path else R.string.susfs_add_sus_path,
        labelRes = R.string.susfs_path_label,
        initialValue = uiState.editingPath ?: ""
    )

    AddPathDialog(
        showDialog = uiState.showAddLoopPathDialog,
        onDismiss = { viewModel.closeAddLoopPathDialog() },
        onConfirm = { path ->
            val oldPath = uiState.editingLoopPath
            viewModel.performOperation {
                val success = if (oldPath != null) {
                    SuSFSManager.editSusLoopPath(context, oldPath, path)
                } else {
                    SuSFSManager.addSusLoopPath(context, path)
                }
                check(success)
                viewModel.refreshConfig()
                viewModel.closeAddLoopPathDialog()
            }
        },
        isLoading = uiState.isLoading,
        titleRes = if (uiState.editingLoopPath != null) R.string.susfs_edit_sus_loop_path else R.string.susfs_add_sus_loop_path,
        labelRes = R.string.susfs_loop_path_label,
        initialValue = uiState.editingLoopPath ?: ""
    )

    AddPathDialog(
        showDialog = uiState.showAddSusMapDialog,
        onDismiss = { viewModel.closeAddSusMapDialog() },
        onConfirm = { path ->
            val oldPath = uiState.editingSusMap
            viewModel.performOperation {
                val success = if (oldPath != null) {
                    SuSFSManager.editSusMap(context, oldPath, path)
                } else {
                    SuSFSManager.addSusMap(context, path)
                }
                check(success)
                viewModel.refreshConfig()
                viewModel.closeAddSusMapDialog()
            }
        },
        isLoading = uiState.isLoading,
        titleRes = if (uiState.editingSusMap != null) R.string.susfs_edit_sus_map else R.string.susfs_add_sus_map,
        labelRes = R.string.susfs_sus_map_label,
        initialValue = uiState.editingSusMap ?: ""
    )

    AddAppPathDialog(
        showDialog = uiState.showAddAppPathDialog,
        onDismiss = { viewModel.closeAddAppPathDialog() },
        onConfirm = { packageNames ->
            viewModel.addAppPaths(context, packageNames.toList())
        },
        isLoading = uiState.isLoading,
        apps = uiState.installedApps,
        isLoadingApps = uiState.isLoadingApps,
        onLoadApps = { viewModel.loadInstalledApps() },
        existingSusPaths = uiState.susPaths
    )

    AddKstatStaticallyDialog(
        showDialog = uiState.showAddKstatStaticallyDialog,
        onDismiss = { viewModel.closeAddKstatStaticallyDialog() },
        onConfirm = { path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize ->
            val oldConfig = uiState.editingKstatConfig
            viewModel.performOperation {
                val success = if (oldConfig != null) {
                    SuSFSManager.editKstatConfig(context, oldConfig, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)
                } else {
                    SuSFSManager.addKstatStatically(context, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)
                }
                check(success)
                viewModel.refreshConfig()
                viewModel.closeAddKstatStaticallyDialog()
            }
        },
        isLoading = uiState.isLoading,
        initialConfig = uiState.editingKstatConfig ?: ""
    )

    AddPathDialog(
        showDialog = uiState.showAddKstatDialog,
        onDismiss = { viewModel.closeAddKstatDialog() },
        onConfirm = { path ->
            val oldPath = uiState.editingKstatPath
            viewModel.performOperation {
                val success = if (oldPath != null) {
                    SuSFSManager.editAddKstat(context, oldPath, path)
                } else {
                    SuSFSManager.addKstat(context, path)
                }
                check(success)
                viewModel.refreshConfig()
                viewModel.closeAddKstatDialog()
            }
        },
        isLoading = uiState.isLoading,
        titleRes = if (uiState.editingKstatPath != null) R.string.edit_kstat_path_title else R.string.add_kstat_path_title,
        labelRes = R.string.file_or_directory_path_label,
        initialValue = uiState.editingKstatPath ?: ""
    )

    ConfirmDialog(
        showDialog = uiState.showConfirmReset,
        onDismiss = { viewModel.toggleConfirmReset(false) },
        onConfirm = { viewModel.resetAll(context) },
        titleRes = R.string.susfs_reset_confirm_title,
        messageRes = R.string.susfs_reset_confirm_title,
        isLoading = uiState.isLoading
    )

    ConfirmDialog(
        showDialog = uiState.showResetPathsDialog,
        onDismiss = { viewModel.toggleResetPathsDialog(false) },
        onConfirm = {
            viewModel.performOperation {
                SuSFSManager.saveSusPaths(emptySet())
                if (SuSFSManager.isAutoStartEnabled()) SuSFSManager.configureAutoStart(context, true)
                viewModel.refreshConfig()
                viewModel.toggleResetPathsDialog(false)
            }
        },
        titleRes = R.string.susfs_reset_paths_title,
        messageRes = R.string.susfs_reset_paths_message,
        isLoading = uiState.isLoading
    )

    ConfirmDialog(
        showDialog = uiState.showResetLoopPathsDialog,
        onDismiss = { viewModel.toggleResetLoopPathsDialog(false) },
        onConfirm = {
            viewModel.performOperation {
                SuSFSManager.saveSusLoopPaths(emptySet())
                if (SuSFSManager.isAutoStartEnabled()) SuSFSManager.configureAutoStart(context, true)
                viewModel.refreshConfig()
                viewModel.toggleResetLoopPathsDialog(false)
            }
        },
        titleRes = R.string.susfs_reset_loop_paths_title,
        messageRes = R.string.susfs_reset_loop_paths_message,
        isLoading = uiState.isLoading
    )

    ConfirmDialog(
        showDialog = uiState.showResetSusMapsDialog,
        onDismiss = { viewModel.toggleResetSusMapsDialog(false) },
        onConfirm = {
            viewModel.performOperation {
                SuSFSManager.saveSusMaps(emptySet())
                if (SuSFSManager.isAutoStartEnabled()) SuSFSManager.configureAutoStart(context, true)
                viewModel.refreshConfig()
                viewModel.toggleResetSusMapsDialog(false)
            }
        },
        titleRes = R.string.susfs_reset_sus_maps_title,
        messageRes = R.string.susfs_reset_sus_maps_message,
        isLoading = uiState.isLoading
    )

    ConfirmDialog(
        showDialog = uiState.showResetKstatDialog,
        onDismiss = { viewModel.toggleResetKstatDialog(false) },
        onConfirm = {
            viewModel.performOperation {
                SuSFSManager.saveKstatConfigs(emptySet())
                SuSFSManager.saveAddKstatPaths(emptySet())
                if (SuSFSManager.isAutoStartEnabled()) SuSFSManager.configureAutoStart(context, true)
                viewModel.refreshConfig()
                viewModel.toggleResetKstatDialog(false)
            }
        },
        titleRes = R.string.reset_kstat_config_title,
        messageRes = R.string.reset_kstat_config_message,
        isLoading = uiState.isLoading
    )

}

@Composable
internal fun SuSFSTabContent(uiState: SuSFSUiState, viewModel: SuSFSViewModel) {
    val context = LocalContext.current
    com.sukisu.ultra.ui.component.ConfigResults(uiState.operationResults)
    when (uiState.selectedTab) {
        SuSFSTab.BASIC_SETTINGS -> {
            RuntimeInfoContent(uiState.runtimeInfo)
            BasicSettingsContent(
                unameValue = uiState.unameValue,
                onUnameValueChange = { viewModel.updateUname(it) },
                buildTimeValue = uiState.buildTimeValue,
                onBuildTimeValueChange = { viewModel.updateBuildTime(it) },
                executeInPostFsData = uiState.executeInPostFsData,
                onExecuteInPostFsDataChange = { viewModel.setExecuteInPostFsData(it) },
                isLoading = uiState.isLoading,
                onShowSlotInfo = {
                    viewModel.showSlotInfoDialog(true)
                    viewModel.loadSlotInfo(context)
                },
                cmdlineOrBootconfigPath = uiState.cmdlineOrBootconfigPath,
                onCmdlineOrBootconfigApply = { uri -> viewModel.applyCmdlineOrBootconfig(context, uri) },
                onReset = { viewModel.toggleConfirmReset(true) },
                onApply = { viewModel.applyBasicSettings(context) },
                onConfigReload = { viewModel.reloadConfig() }
            )
        }
        SuSFSTab.FEATURE_TOGGLES -> {
            FeatureTogglesContent(
                enableLog = uiState.enableLog,
                onEnableLogChange = { viewModel.setEnableLog(context, it) },
                autoStartEnabled = uiState.autoStartEnabled,
                canEnableAutoStart = uiState.canEnableAutoStart,
                isLoading = uiState.isLoading,
                onAutoStartToggle = { viewModel.configureAutoStart(context, it) },
                enableHideBl = uiState.enableHideBl,
                onEnableHideBlChange = { viewModel.setEnableHideBl(context, it) },
                enableCleanupResidue = uiState.enableCleanupResidue,
                onEnableCleanupResidueChange = { viewModel.setEnableCleanupResidue(context, it) },
                enableAvcLogSpoofing = uiState.enableAvcLogSpoofing,
                onEnableAvcLogSpoofingChange = { viewModel.setEnableAvcLogSpoofing(context, it) },
                hideSusMountsForAllProcs = uiState.hideSusMountsForAllProcs,
                onHideSusMountsForAllProcsChange = { viewModel.setHideSusMountsForAllProcs(context, it) },
            )
        }
        SuSFSTab.SUS_PATHS -> {
            SusPathsContent(
                susPaths = uiState.susPaths,
                isLoading = uiState.isLoading,
                onAddPath = { viewModel.openAddPathDialog() },
                onAddAppPath = {
                    viewModel.openAddAppPathDialog()
                    viewModel.loadInstalledApps()
                },
                onRemovePath = { path ->
                    viewModel.performOperation {
                        check(SuSFSManager.removeSusPath(path))
                        viewModel.refreshConfig()
                    }
                },
                onEditPath = { viewModel.openAddPathDialog(it) },
                onReset = { viewModel.toggleResetPathsDialog(true) }
            )
        }
        SuSFSTab.SUS_LOOP_PATHS -> {
            SusLoopPathsContent(
                susLoopPaths = uiState.susLoopPaths,
                isLoading = uiState.isLoading,
                onAddLoopPath = { viewModel.openAddLoopPathDialog() },
                onRemoveLoopPath = { path ->
                    viewModel.performOperation {
                        check(SuSFSManager.removeSusLoopPath(path))
                        viewModel.refreshConfig()
                    }
                },
                onEditLoopPath = { viewModel.openAddLoopPathDialog(it) },
                onReset = { viewModel.toggleResetLoopPathsDialog(true) }
            )
        }
        SuSFSTab.SUS_MAPS -> {
            SusMapsContent(
                susMaps = uiState.susMaps,
                isLoading = uiState.isLoading,
                onAddSusMap = { viewModel.openAddSusMapDialog() },
                onRemoveSusMap = { map ->
                    viewModel.performOperation {
                        check(SuSFSManager.removeSusMap(map))
                        viewModel.refreshConfig()
                    }
                },
                onEditSusMap = { viewModel.openAddSusMapDialog(it) },
                onReset = { viewModel.toggleResetSusMapsDialog(true) }
            )
        }
        SuSFSTab.KSTAT_CONFIG -> {
            KstatConfigContent(
                kstatConfigs = uiState.kstatConfigs,
                addKstatPaths = uiState.addKstatPaths,
                isLoading = uiState.isLoading,
                onAddKstatStatically = { viewModel.openAddKstatStaticallyDialog() },
                onAddKstat = { viewModel.openAddKstatDialog() },
                onRemoveKstatConfig = { config ->
                    viewModel.performOperation {
                        check(SuSFSManager.removeKstatConfig(config))
                        viewModel.refreshConfig()
                    }
                },
                onEditKstatConfig = { viewModel.openAddKstatStaticallyDialog(it) },
                onRemoveAddKstat = { path ->
                    viewModel.performOperation {
                        check(SuSFSManager.removeAddKstat(path))
                        viewModel.refreshConfig()
                    }
                },
                onEditAddKstat = { viewModel.openAddKstatDialog(it) },
                onUpdateKstat = { path -> viewModel.performOperation { check(SuSFSManager.updateKstat(context, path)) } },
                onUpdateKstatFullClone = { path -> viewModel.performOperation { check(SuSFSManager.updateKstatFullClone(context, path)) } }
            )
        }
        SuSFSTab.PRIORITY_UID_FILTER -> {
            com.sukisu.ultra.ui.component.ConfigResults(uiState.priorityUidFilterResults)
            PriorityUidFilterContent(
                packages = uiState.priorityUidFilter,
                isLoading = uiState.isLoading,
                onSelectApps = { viewModel.showPriorityAppsDialog(true) },
                onApply = { viewModel.applyPriorityUidFilter(context, uiState.priorityUidFilter) },
                onClear = { viewModel.applyPriorityUidFilter(context, emptySet()) },
            )
        }
        SuSFSTab.ENABLED_FEATURES -> {
            EnabledFeaturesContent(
                enabledFeatures = uiState.enabledFeatures,
                isLoading = uiState.isLoadingFeatures,
                onRefresh = { viewModel.loadEnabledFeatures(context) }
            )
        }
    }
}
