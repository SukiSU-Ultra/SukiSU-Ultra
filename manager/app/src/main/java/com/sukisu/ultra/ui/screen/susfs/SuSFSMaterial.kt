package com.sukisu.ultra.ui.screen.susfs

import android.annotation.SuppressLint
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.systemBars
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import kotlinx.coroutines.launch
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.ui.screen.susfs.component.AddAppPathDialog
import com.sukisu.ultra.ui.screen.susfs.component.AddKstatStaticallyDialog
import com.sukisu.ultra.ui.screen.susfs.component.AddPathDialog
import com.sukisu.ultra.ui.screen.susfs.component.ConfirmDialog
import com.sukisu.ultra.ui.screen.susfs.component.SlotInfoDialog
import com.sukisu.ultra.ui.screen.susfs.content.BasicSettingsContent
import com.sukisu.ultra.ui.screen.susfs.content.EnabledFeaturesContent
import com.sukisu.ultra.ui.screen.susfs.content.KstatConfigContent
import com.sukisu.ultra.ui.screen.susfs.content.SusLoopPathsContent
import com.sukisu.ultra.ui.screen.susfs.content.SusMapsContent
import com.sukisu.ultra.ui.screen.susfs.content.SusPathsContent
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.screen.susfs.viewmodel.SuSFSViewModel

@OptIn(ExperimentalMaterial3Api::class)
@SuppressLint("SdCardPath", "AutoboxingStateCreation")
@Composable
fun SuSFSMaterial() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    val viewModel: SuSFSViewModel = viewModel()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val coroutineScope = rememberCoroutineScope()

    var isNavigating by remember { mutableStateOf(false) }
    val allTabs = SuSFSTab.getAllTabs()

    LaunchedEffect(Unit) {
        viewModel.loadInitial(context)
    }

    LaunchedEffect(uiState.selectedTab) {
        if (uiState.selectedTab == SuSFSTab.ENABLED_FEATURES) {
            viewModel.loadEnabledFeatures(context)
        }
    }

    LaunchedEffect(uiState.canEnableAutoStart, uiState.autoStartEnabled) {
        if (!uiState.canEnableAutoStart && uiState.autoStartEnabled) {
            viewModel.configureAutoStart(context, false)
        }
    }


    SlotInfoDialog(
        showDialog = uiState.showSlotInfoDialog,
        onDismiss = { viewModel.showSlotInfoDialog(false) },
        slotInfoList = uiState.slotInfoList,
        currentActiveSlot = uiState.currentActiveSlot,
        isLoadingSlotInfo = uiState.isLoadingSlotInfo,
        onRefresh = { viewModel.loadSlotInfo(context) },
        onUseUname = { uname ->
            viewModel.updateUname(uname)
            viewModel.showSlotInfoDialog(false)
        },
        onUseBuildTime = { buildTime ->
            viewModel.updateBuildTime(buildTime)
            viewModel.showSlotInfoDialog(false)
        }
    )

    AddPathDialog(
        showDialog = uiState.showAddPathDialog,
        onDismiss = { viewModel.closeAddPathDialog() },
        onConfirm = { path ->
            val oldPath = uiState.editingPath
            coroutineScope.launch {
                val success = if (oldPath != null) {
                    SuSFSManager.editSusPath(context, oldPath, path)
                } else {
                    SuSFSManager.addSusPath(context, path)
                }
                if (success) viewModel.reloadConfig(context)
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
            coroutineScope.launch {
                val success = if (oldPath != null) {
                    SuSFSManager.editSusLoopPath(context, oldPath, path)
                } else {
                    SuSFSManager.addSusLoopPath(context, path)
                }
                if (success) viewModel.reloadConfig(context)
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
            coroutineScope.launch {
                val success = if (oldPath != null) {
                    SuSFSManager.editSusMap(context, oldPath, path)
                } else {
                    SuSFSManager.addSusMap(context, path)
                }
                if (success) viewModel.reloadConfig(context)
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
            coroutineScope.launch {
                var successCount = 0
                packageNames.forEach { packageName ->
                    if (SuSFSManager.addAppPaths(context, packageName)) successCount++
                }
                if (successCount > 0) viewModel.reloadConfig(context)
                viewModel.closeAddAppPathDialog()
            }
        },
        isLoading = uiState.isLoading,
        apps = uiState.installedApps,
        onLoadApps = { viewModel.loadInstalledApps() },
        existingSusPaths = uiState.susPaths
    )

    AddKstatStaticallyDialog(
        showDialog = uiState.showAddKstatStaticallyDialog,
        onDismiss = { viewModel.closeAddKstatStaticallyDialog() },
        onConfirm = { path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize ->
            val oldConfig = uiState.editingKstatConfig
            coroutineScope.launch {
                val success = if (oldConfig != null) {
                    SuSFSManager.editKstatConfig(context, oldConfig, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)
                } else {
                    SuSFSManager.addKstatStatically(context, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)
                }
                if (success) viewModel.reloadConfig(context)
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
            coroutineScope.launch {
                val success = if (oldPath != null) {
                    SuSFSManager.editAddKstat(context, oldPath, path)
                } else {
                    SuSFSManager.addKstat(context, path)
                }
                if (success) viewModel.reloadConfig(context)
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
            coroutineScope.launch {
                SuSFSManager.saveSusPaths(context, emptySet())
                if (SuSFSManager.isAutoStartEnabled(context)) SuSFSManager.configureAutoStart(context, true)
                viewModel.reloadConfig(context)
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
            coroutineScope.launch {
                SuSFSManager.saveSusLoopPaths(context, emptySet())
                if (SuSFSManager.isAutoStartEnabled(context)) SuSFSManager.configureAutoStart(context, true)
                viewModel.reloadConfig(context)
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
            coroutineScope.launch {
                SuSFSManager.saveSusMaps(context, emptySet())
                if (SuSFSManager.isAutoStartEnabled(context)) SuSFSManager.configureAutoStart(context, true)
                viewModel.reloadConfig(context)
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
            coroutineScope.launch {
                SuSFSManager.saveKstatConfigs(context, emptySet())
                SuSFSManager.saveAddKstatPaths(context, emptySet())
                if (SuSFSManager.isAutoStartEnabled(context)) SuSFSManager.configureAutoStart(context, true)
                viewModel.reloadConfig(context)
                viewModel.toggleResetKstatDialog(false)
            }
        },
        titleRes = R.string.reset_kstat_config_title,
        messageRes = R.string.reset_kstat_config_message,
        isLoading = uiState.isLoading
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.susfs_config_title)) },
                navigationIcon = {
                    IconButton(onClick = {
                        if (!isNavigating) {
                            isNavigating = true
                            navigator.pop()
                        }
                    }) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.log_viewer_back)
                        )
                    }
                },
                scrollBehavior = scrollBehavior,
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(horizontal = 12.dp),
            contentPadding = innerPadding
        ) {
            item {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    contentPadding = PaddingValues(vertical = 8.dp)
                ) {
                    items(allTabs.size) { index ->
                        val tab = allTabs[index]
                        val isSelected = uiState.selectedTab == tab
                        FilterChip(
                            selected = isSelected,
                            onClick = { viewModel.setSelectedTab(tab) },
                            label = { Text(stringResource(tab.displayNameRes)) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                                selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        )
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(12.dp))

                when (uiState.selectedTab) {
                    SuSFSTab.BASIC_SETTINGS -> {
                        BasicSettingsContent(
                            unameValue = uiState.unameValue,
                            onUnameValueChange = { viewModel.updateUname(it) },
                            buildTimeValue = uiState.buildTimeValue,
                            onBuildTimeValueChange = { viewModel.updateBuildTime(it) },
                            executeInPostFsData = uiState.executeInPostFsData,
                            onExecuteInPostFsDataChange = { viewModel.setExecuteInPostFsData(it) },
                            autoStartEnabled = uiState.autoStartEnabled,
                            canEnableAutoStart = uiState.canEnableAutoStart,
                            isLoading = uiState.isLoading,
                            onAutoStartToggle = { viewModel.configureAutoStart(context, it) },
                            onShowSlotInfo = {
                                viewModel.showSlotInfoDialog(true)
                                viewModel.loadSlotInfo(context)
                            },
                            context = context,
                            enableHideBl = uiState.enableHideBl,
                            onEnableHideBlChange = { viewModel.setEnableHideBl(context, it) },
                            enableCleanupResidue = uiState.enableCleanupResidue,
                            onEnableCleanupResidueChange = { viewModel.setEnableCleanupResidue(context, it) },
                            enableAvcLogSpoofing = uiState.enableAvcLogSpoofing,
                            onEnableAvcLogSpoofingChange = { viewModel.setEnableAvcLogSpoofing(context, it) },
                            hideSusMountsForAllProcs = uiState.hideSusMountsForAllProcs,
                            onHideSusMountsForAllProcsChange = { viewModel.setHideSusMountsForAllProcs(context, it) },
                            onReset = { viewModel.toggleConfirmReset(true) },
                            onApply = { viewModel.applyBasicSettings(context) },
                            onConfigReload = { viewModel.reloadConfig(context) }
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
                                coroutineScope.launch {
                                    if (SuSFSManager.removeSusPath(context, path)) viewModel.reloadConfig(context)
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
                                coroutineScope.launch {
                                    if (SuSFSManager.removeSusLoopPath(context, path)) viewModel.reloadConfig(context)
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
                                coroutineScope.launch {
                                    if (SuSFSManager.removeSusMap(context, map)) viewModel.reloadConfig(context)
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
                                coroutineScope.launch {
                                    if (SuSFSManager.removeKstatConfig(context, config)) viewModel.reloadConfig(context)
                                }
                            },
                            onEditKstatConfig = { viewModel.openAddKstatStaticallyDialog(it) },
                            onRemoveAddKstat = { path ->
                                coroutineScope.launch {
                                    if (SuSFSManager.removeAddKstat(context, path)) viewModel.reloadConfig(context)
                                }
                            },
                            onEditAddKstat = { viewModel.openAddKstatDialog(it) },
                            onUpdateKstat = { path -> coroutineScope.launch { SuSFSManager.updateKstat(
                                path) } },
                            onUpdateKstatFullClone = { path -> coroutineScope.launch { SuSFSManager.updateKstatFullClone(
                                path) } }
                        )
                    }
                    SuSFSTab.ENABLED_FEATURES -> {
                        EnabledFeaturesContent(
                            enabledFeatures = uiState.enabledFeatures,
                            onRefresh = { viewModel.loadEnabledFeatures(context) }
                        )
                    }
                }
            }
        }
    }
}
