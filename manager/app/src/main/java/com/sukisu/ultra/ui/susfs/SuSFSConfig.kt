package com.sukisu.ultra.ui.susfs

import android.annotation.SuppressLint
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.systemBars
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.HazeStyle
import dev.chrisbanes.haze.HazeTint
import dev.chrisbanes.haze.hazeEffect
import dev.chrisbanes.haze.hazeSource
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.susfs.component.*
import com.sukisu.ultra.ui.susfs.content.BasicSettingsContent
import com.sukisu.ultra.ui.susfs.content.EnabledFeaturesContent
import com.sukisu.ultra.ui.susfs.content.KstatConfigContent
import com.sukisu.ultra.ui.susfs.content.PathSettingsContent
import com.sukisu.ultra.ui.susfs.content.SusLoopPathsContent
import com.sukisu.ultra.ui.susfs.content.SusMapsContent
import com.sukisu.ultra.ui.susfs.content.SusPathsContent
import com.sukisu.ultra.ui.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.util.isAbDevice
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.extra.SuperDialog
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

enum class SuSFSTab(val displayNameRes: Int) {
    BASIC_SETTINGS(R.string.susfs_tab_basic_settings),
    SUS_PATHS(R.string.susfs_tab_sus_paths),
    SUS_LOOP_PATHS(R.string.susfs_tab_sus_loop_paths),
    SUS_MAPS(R.string.susfs_tab_sus_maps),
    KSTAT_CONFIG(R.string.susfs_tab_kstat_config),
    PATH_SETTINGS(R.string.susfs_tab_path_settings),
    ENABLED_FEATURES(R.string.susfs_tab_enabled_features);

    companion object {
        fun getAllTabs(): List<SuSFSTab> {
            return entries.toList()
        }
    }
}

@SuppressLint("SdCardPath", "AutoboxingStateCreation")
@Composable
fun SuSFSConfigScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val scrollBehavior = MiuixScrollBehavior()
    val hazeState = remember { HazeState() }
    val hazeStyle = HazeStyle(
        backgroundColor = colorScheme.surface,
        tint = HazeTint(colorScheme.surface.copy(0.8f))
    )

    var selectedTab by remember { mutableStateOf(SuSFSTab.BASIC_SETTINGS) }
    var unameValue by remember { mutableStateOf("") }
    var buildTimeValue by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var showConfirmReset by remember { mutableStateOf(false) }
    var autoStartEnabled by remember { mutableStateOf(false) }
    var executeInPostFsData by remember { mutableStateOf(false) }
    var enableHideBl by remember { mutableStateOf(true) }
    var enableCleanupResidue by remember { mutableStateOf(false) }
    var enableAvcLogSpoofing by remember { mutableStateOf(false) }

    // 槽位信息相关状态
    var slotInfoList by remember { mutableStateOf(emptyList<SuSFSManager.SlotInfo>()) }
    var currentActiveSlot by remember { mutableStateOf("") }
    var isLoadingSlotInfo by remember { mutableStateOf(false) }
    var showSlotInfoDialog by remember { mutableStateOf(false) }

    // 路径管理相关状态
    var susPaths by remember { mutableStateOf(emptySet<String>()) }
    var susLoopPaths by remember { mutableStateOf(emptySet<String>()) }
    var susMaps by remember { mutableStateOf(emptySet<String>()) }
    var androidDataPath by remember { mutableStateOf("") }
    var sdcardPath by remember { mutableStateOf("") }

    // SUS挂载隐藏控制状态
    var hideSusMountsForAllProcs by remember { mutableStateOf(true) }

    // Kstat配置相关状态
    var kstatConfigs by remember { mutableStateOf(emptySet<String>()) }
    var addKstatPaths by remember { mutableStateOf(emptySet<String>()) }

    // 启用功能状态相关
    var enabledFeatures by remember { mutableStateOf(emptyList<SuSFSManager.EnabledFeature>()) }

    // 应用列表相关状态
    var installedApps by remember { mutableStateOf(emptyList<SuSFSManager.AppInfo>()) }

    // 对话框状态
    var showAddPathDialog by remember { mutableStateOf(false) }
    var showAddLoopPathDialog by remember { mutableStateOf(false) }
    var showAddSusMapDialog by remember { mutableStateOf(false) }
    var showAddAppPathDialog by remember { mutableStateOf(false) }
    var showAddKstatStaticallyDialog by remember { mutableStateOf(false) }
    var showAddKstatDialog by remember { mutableStateOf(false) }

    // 编辑状态
    var editingPath by remember { mutableStateOf<String?>(null) }
    var editingLoopPath by remember { mutableStateOf<String?>(null) }
    var editingSusMap by remember { mutableStateOf<String?>(null) }
    var editingKstatConfig by remember { mutableStateOf<String?>(null) }
    var editingKstatPath by remember { mutableStateOf<String?>(null) }

    // 重置确认对话框状态
    var showResetPathsDialog by remember { mutableStateOf(false) }
    var showResetLoopPathsDialog by remember { mutableStateOf(false) }
    var showResetSusMapsDialog by remember { mutableStateOf(false) }
    var showResetKstatDialog by remember { mutableStateOf(false) }


    var isNavigating by remember { mutableStateOf(false) }

    val allTabs = SuSFSTab.getAllTabs()

    // 实时判断是否可以启用开机自启动
    val canEnableAutoStart by remember {
        derivedStateOf {
            SuSFSManager.hasConfigurationForAutoStart(context)
        }
    }



    // 加载启用功能状态
    fun loadEnabledFeatures() {
        coroutineScope.launch {
            enabledFeatures = SuSFSManager.getEnabledFeatures(context)
        }
    }

    // 加载应用列表
    fun loadInstalledApps() {
        coroutineScope.launch {
            installedApps = SuSFSManager.getInstalledApps()
        }
    }

    // 加载槽位信息
    fun loadSlotInfo() {
        coroutineScope.launch {
            isLoadingSlotInfo = true
            slotInfoList = SuSFSManager.getCurrentSlotInfo()
            currentActiveSlot = SuSFSManager.getCurrentActiveSlot()
            isLoadingSlotInfo = false
        }
    }

    // 加载当前配置
    LaunchedEffect(Unit) {
        coroutineScope.launch {

            unameValue = SuSFSManager.getUnameValue(context)
            buildTimeValue = SuSFSManager.getBuildTimeValue(context)
            autoStartEnabled = SuSFSManager.isAutoStartEnabled(context)
            executeInPostFsData = SuSFSManager.getExecuteInPostFsData(context)
            susPaths = SuSFSManager.getSusPaths(context)
            susLoopPaths = SuSFSManager.getSusLoopPaths(context)
            susMaps = SuSFSManager.getSusMaps(context)
            androidDataPath = SuSFSManager.getAndroidDataPath(context)
            sdcardPath = SuSFSManager.getSdcardPath(context)
            kstatConfigs = SuSFSManager.getKstatConfigs(context)
            addKstatPaths = SuSFSManager.getAddKstatPaths(context)
            hideSusMountsForAllProcs = SuSFSManager.getHideSusMountsForAllProcs(context)
            enableHideBl = SuSFSManager.getEnableHideBl(context)
            enableCleanupResidue = SuSFSManager.getEnableCleanupResidue(context)
            enableAvcLogSpoofing = SuSFSManager.getEnableAvcLogSpoofing(context)

            loadSlotInfo()
        }
    }

    // 当切换到启用功能状态标签页时加载数据
    LaunchedEffect(selectedTab) {
        if (selectedTab == SuSFSTab.ENABLED_FEATURES) {
            loadEnabledFeatures()
        }
    }

    // 当配置变化时，自动调整开机自启动状态
    LaunchedEffect(canEnableAutoStart) {
        if (!canEnableAutoStart && autoStartEnabled) {
            autoStartEnabled = false
            SuSFSManager.configureAutoStart(context, false)
        }
    }


    // 槽位信息对话框
    SlotInfoDialog(
        showDialog = showSlotInfoDialog,
        onDismiss = { },
        slotInfoList = slotInfoList,
        currentActiveSlot = currentActiveSlot,
        isLoadingSlotInfo = isLoadingSlotInfo,
        onRefresh = { loadSlotInfo() },
        onUseUname = { uname: String ->
            unameValue = uname
        },
        onUseBuildTime = { buildTime: String ->
            buildTimeValue = buildTime
        }
    )

    // 各种对话框
    AddPathDialog(
        showDialog = showAddPathDialog,
        onDismiss = { },
        onConfirm = { path ->
            val oldPath = editingPath
            coroutineScope.launch {
                isLoading = true
                val success = if (oldPath != null) {
                    SuSFSManager.editSusPath(context, oldPath, path)
                } else {
                    SuSFSManager.addSusPath(context, path)
                }
                if (success) {
                    susPaths = SuSFSManager.getSusPaths(context)
                }
                isLoading = false
                editingPath = null
            }
        },
        isLoading = isLoading,
        titleRes = if (editingPath != null) R.string.susfs_edit_sus_path else R.string.susfs_add_sus_path,
        labelRes = R.string.susfs_path_label,
        initialValue = editingPath ?: ""
    )

    AddPathDialog(
        showDialog = showAddLoopPathDialog,
        onDismiss = { },
        onConfirm = { path ->
            val oldPath = editingLoopPath
            coroutineScope.launch {
                isLoading = true
                val success = if (oldPath != null) {
                    SuSFSManager.editSusLoopPath(context, oldPath, path)
                } else {
                    SuSFSManager.addSusLoopPath(context, path)
                }
                if (success) {
                    susLoopPaths = SuSFSManager.getSusLoopPaths(context)
                }
                isLoading = false
                editingLoopPath = null
            }
        },
        isLoading = isLoading,
        titleRes = if (editingLoopPath != null) R.string.susfs_edit_sus_loop_path else R.string.susfs_add_sus_loop_path,
        labelRes = R.string.susfs_loop_path_label,
        initialValue = editingLoopPath ?: ""
    )

    AddPathDialog(
        showDialog = showAddSusMapDialog,
        onDismiss = { },
        onConfirm = { path ->
            val oldPath = editingSusMap
            coroutineScope.launch {
                isLoading = true
                val success = if (oldPath != null) {
                    SuSFSManager.editSusMap(context, oldPath, path)
                } else {
                    SuSFSManager.addSusMap(context, path)
                }
                if (success) {
                    susMaps = SuSFSManager.getSusMaps(context)
                }
                isLoading = false
                editingSusMap = null
            }
        },
        isLoading = isLoading,
        titleRes = if (editingSusMap != null) R.string.susfs_edit_sus_map else R.string.susfs_add_sus_map,
        labelRes = R.string.susfs_sus_map_label,
        initialValue = editingSusMap ?: ""
    )

    AddAppPathDialog(
        showDialog = showAddAppPathDialog,
        onDismiss = { },
        onConfirm = { packageNames ->
            coroutineScope.launch {
                isLoading = true
                var successCount = 0
                packageNames.forEach { packageName ->
                    if (SuSFSManager.addAppPaths(context, packageName)) {
                        successCount++
                    }
                }
                if (successCount > 0) {
                    susPaths = SuSFSManager.getSusPaths(context)
                }
                isLoading = false
            }
        },
        isLoading = isLoading,
        apps = installedApps,
        onLoadApps = { loadInstalledApps() },
        existingSusPaths = susPaths
    )


    AddKstatStaticallyDialog(
        showDialog = showAddKstatStaticallyDialog,
        onDismiss = { },
        onConfirm = { path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize ->
            val oldConfig = editingKstatConfig
            coroutineScope.launch {
                isLoading = true
                val success = if (oldConfig != null) {
                    SuSFSManager.editKstatConfig(
                        context,
                        oldConfig,
                        path,
                        ino,
                        dev,
                        nlink,
                        size,
                        atime,
                        atimeNsec,
                        mtime,
                        mtimeNsec,
                        ctime,
                        ctimeNsec,
                        blocks,
                        blksize
                    )
                } else {
                    SuSFSManager.addKstatStatically(
                        context, path, ino, dev, nlink, size, atime, atimeNsec,
                        mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize
                    )
                }
                if (success) {
                    kstatConfigs = SuSFSManager.getKstatConfigs(context)
                }
                isLoading = false
                editingKstatConfig = null
            }
        },
        isLoading = isLoading,
        initialConfig = editingKstatConfig ?: ""
    )

    AddPathDialog(
        showDialog = showAddKstatDialog,
        onDismiss = { },
        onConfirm = { path ->
            val oldPath = editingKstatPath
            coroutineScope.launch {
                isLoading = true
                val success = if (oldPath != null) {
                    SuSFSManager.editAddKstat(context, oldPath, path)
                } else {
                    SuSFSManager.addKstat(context, path)
                }
                if (success) {
                    addKstatPaths = SuSFSManager.getAddKstatPaths(context)
                }
                isLoading = false
                editingKstatPath = null
            }
        },
        isLoading = isLoading,
        titleRes = if (editingKstatPath != null) R.string.edit_kstat_path_title else R.string.add_kstat_path_title,
        labelRes = R.string.file_or_directory_path_label,
        initialValue = editingKstatPath ?: ""
    )

    // 确认对话框
    ConfirmDialog(
        showDialog = showConfirmReset,
        onDismiss = { },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                if (SuSFSManager.resetToDefault(context)) {
                    unameValue = "default"
                    buildTimeValue = "default"
                    autoStartEnabled = false
                }
                isLoading = false
            }
        },
        titleRes = R.string.susfs_reset_confirm_title,
        messageRes = R.string.susfs_reset_confirm_title,
        isLoading = isLoading
    )

    // 重置对话框
    ConfirmDialog(
        showDialog = showResetPathsDialog,
        onDismiss = { },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.saveSusPaths(context, emptySet())
                susPaths = emptySet()
                if (SuSFSManager.isAutoStartEnabled(context)) {
                    SuSFSManager.configureAutoStart(context, true)
                }
                isLoading = false
            }
        },
        titleRes = R.string.susfs_reset_paths_title,
        messageRes = R.string.susfs_reset_paths_message,
        isLoading = isLoading
    )

    ConfirmDialog(
        showDialog = showResetLoopPathsDialog,
        onDismiss = { },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.saveSusLoopPaths(context, emptySet())
                susLoopPaths = emptySet()
                if (SuSFSManager.isAutoStartEnabled(context)) {
                    SuSFSManager.configureAutoStart(context, true)
                }
                isLoading = false
            }
        },
        titleRes = R.string.susfs_reset_loop_paths_title,
        messageRes = R.string.susfs_reset_loop_paths_message,
        isLoading = isLoading
    )

    ConfirmDialog(
        showDialog = showResetSusMapsDialog,
        onDismiss = { },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.saveSusMaps(context, emptySet())
                susMaps = emptySet()
                if (SuSFSManager.isAutoStartEnabled(context)) {
                    SuSFSManager.configureAutoStart(context, true)
                }
                isLoading = false
            }
        },
        titleRes = R.string.susfs_reset_sus_maps_title,
        messageRes = R.string.susfs_reset_sus_maps_message,
        isLoading = isLoading
    )


    ConfirmDialog(
        showDialog = showResetKstatDialog,
        onDismiss = { },
        onConfirm = {
            coroutineScope.launch {
                isLoading = true
                SuSFSManager.saveKstatConfigs(context, emptySet())
                SuSFSManager.saveAddKstatPaths(context, emptySet())
                kstatConfigs = emptySet()
                addKstatPaths = emptySet()
                if (SuSFSManager.isAutoStartEnabled(context)) {
                    SuSFSManager.configureAutoStart(context, true)
                }
                isLoading = false
            }
        },
        titleRes = R.string.reset_kstat_config_title,
        messageRes = R.string.reset_kstat_config_message,
        isLoading = isLoading
    )

    // 主界面布局
    Scaffold(
        topBar = {
            TopAppBar(
                modifier = Modifier.hazeEffect(hazeState) {
                    style = hazeStyle
                    blurRadius = 30.dp
                    noiseFactor = 0f
                },
                color = Color.Transparent,
                title = stringResource(R.string.susfs_config_title),
                navigationIcon = {
                    IconButton(onClick = {
                        if (!isNavigating) {
                            isNavigating = true
                            navigator.pop()
                        }
                    }) {
                        val layoutDirection = LocalLayoutDirection.current
                        Icon(
                            modifier = Modifier.graphicsLayer {
                                if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                            },
                            imageVector = MiuixIcons.Back,
                            contentDescription = stringResource(R.string.log_viewer_back),
                            tint = colorScheme.onBackground
                        )
                    }
                },
                scrollBehavior = scrollBehavior
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .hazeSource(state = hazeState)
                .padding(horizontal = 12.dp),
            contentPadding = innerPadding,
            overscrollEffect = null,
        ) {
            item {
                // 标签页
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    contentPadding = PaddingValues(vertical = 8.dp)
                ) {
                    items(allTabs.size) { index ->
                        val tab = allTabs[index]
                        val isSelected = selectedTab == tab
                        Card(
                            modifier = Modifier
                                .clickable { selectedTab = tab },
                            colors = CardDefaults.defaultColors(
                                if (isSelected) {
                                    colorScheme.primaryContainer
                                } else {
                                    colorScheme.surfaceVariant.copy(alpha = 0.3f)
                                }
                            ),
                            cornerRadius = 8.dp
                        ) {
                            Text(
                                text = stringResource(tab.displayNameRes),
                                modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                                style = MiuixTheme.textStyles.body1,
                                fontWeight = if (isSelected) FontWeight.Medium else FontWeight.Normal,
                                color = if (isSelected) {
                                    colorScheme.onPrimaryContainer
                                } else {
                                    colorScheme.onSurfaceVariantSummary
                                }
                            )
                        }
                    }
                }

            }

            item {
                Spacer(modifier = Modifier.height(12.dp))

                // 标签页内容
                when (selectedTab) {
                    SuSFSTab.BASIC_SETTINGS -> {
                        BasicSettingsContent(
                            unameValue = unameValue,
                            onUnameValueChange = { value -> unameValue = value },
                            buildTimeValue = buildTimeValue,
                            onBuildTimeValueChange = { value -> buildTimeValue = value },
                            executeInPostFsData = executeInPostFsData,
                            onExecuteInPostFsDataChange = { value -> executeInPostFsData = value },
                            autoStartEnabled = autoStartEnabled,
                            canEnableAutoStart = canEnableAutoStart,
                            isLoading = isLoading,
                            onAutoStartToggle = { enabled: Boolean ->
                                if (canEnableAutoStart) {
                                    coroutineScope.launch {
                                        isLoading = true
                                        if (SuSFSManager.configureAutoStart(context, enabled)) {
                                            autoStartEnabled = enabled
                                        }
                                        isLoading = false
                                    }
                                }
                            },
                            onShowSlotInfo = { },
                            context = context,
                            enableHideBl = enableHideBl,
                            onEnableHideBlChange = { enabled: Boolean ->
                                enableHideBl = enabled
                                SuSFSManager.saveEnableHideBl(context, enabled)
                                if (SuSFSManager.isAutoStartEnabled(context)) {
                                    coroutineScope.launch {
                                        SuSFSManager.configureAutoStart(context, true)
                                    }
                                }
                            },
                            enableCleanupResidue = enableCleanupResidue,
                            onEnableCleanupResidueChange = { enabled: Boolean ->
                                enableCleanupResidue = enabled
                                SuSFSManager.saveEnableCleanupResidue(context, enabled)
                                if (SuSFSManager.isAutoStartEnabled(context)) {
                                    coroutineScope.launch {
                                        SuSFSManager.configureAutoStart(context, true)
                                    }
                                }
                            },
                            enableAvcLogSpoofing = enableAvcLogSpoofing,
                            onEnableAvcLogSpoofingChange = { enabled: Boolean ->
                                coroutineScope.launch {
                                    isLoading = true
                                    val success =
                                        SuSFSManager.setEnableAvcLogSpoofing(context, enabled)
                                    if (success) {
                                        enableAvcLogSpoofing = enabled
                                    }
                                    isLoading = false
                                }
                            },
                            hideSusMountsForAllProcs = hideSusMountsForAllProcs,
                            onHideSusMountsForAllProcsChange = { hideForAll: Boolean ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.setHideSusMountsForAllProcs(
                                            context,
                                            hideForAll
                                        )
                                    ) {
                                        hideSusMountsForAllProcs = hideForAll
                                    }
                                    isLoading = false
                                }
                            },
                            onReset = { },
                            onApply = {
                                coroutineScope.launch {
                                    isLoading = true
                                    val success = SuSFSManager.setUname(
                                        context,
                                        unameValue.trim(),
                                        buildTimeValue.trim()
                                    )
                                    if (success) {
                                        SuSFSManager.saveExecuteInPostFsData(
                                            context,
                                            executeInPostFsData
                                        )
                                        if (SuSFSManager.isAutoStartEnabled(context)) {
                                            SuSFSManager.configureAutoStart(context, true)
                                        }
                                    }
                                    isLoading = false
                                }
                            },
                            onConfigReload = {
                                coroutineScope.launch {
                                    unameValue = SuSFSManager.getUnameValue(context)
                                    buildTimeValue = SuSFSManager.getBuildTimeValue(context)
                                    autoStartEnabled = SuSFSManager.isAutoStartEnabled(context)
                                    executeInPostFsData =
                                        SuSFSManager.getExecuteInPostFsData(context)
                                    susPaths = SuSFSManager.getSusPaths(context)
                                    susLoopPaths = SuSFSManager.getSusLoopPaths(context)
                                    susMaps = SuSFSManager.getSusMaps(context)
                                    androidDataPath = SuSFSManager.getAndroidDataPath(context)
                                    sdcardPath = SuSFSManager.getSdcardPath(context)
                                    kstatConfigs = SuSFSManager.getKstatConfigs(context)
                                    addKstatPaths = SuSFSManager.getAddKstatPaths(context)
                                    hideSusMountsForAllProcs =
                                        SuSFSManager.getHideSusMountsForAllProcs(context)
                                    enableHideBl = SuSFSManager.getEnableHideBl(context)
                                    enableCleanupResidue =
                                        SuSFSManager.getEnableCleanupResidue(context)
                                    enableAvcLogSpoofing =
                                        SuSFSManager.getEnableAvcLogSpoofing(context)
                                }
                            }
                        )
                    }
                    SuSFSTab.SUS_PATHS -> {
                        SusPathsContent(
                            susPaths = susPaths,
                            isLoading = isLoading,
                            onAddPath = { },
                            onAddAppPath = { },
                            onRemovePath = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeSusPath(context, path)) {
                                        susPaths = SuSFSManager.getSusPaths(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditPath = { path ->
                                editingPath = path
                            },
                            forceRefreshApps = selectedTab == SuSFSTab.SUS_PATHS,
                            onReset = { }
                        )
                    }
                    SuSFSTab.SUS_LOOP_PATHS -> {
                        SusLoopPathsContent(
                            susLoopPaths = susLoopPaths,
                            isLoading = isLoading,
                            onAddLoopPath = { },
                            onRemoveLoopPath = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeSusLoopPath(context, path)) {
                                        susLoopPaths = SuSFSManager.getSusLoopPaths(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditLoopPath = { path ->
                                editingLoopPath = path
                            },
                            onReset = { }
                        )
                    }
                    SuSFSTab.SUS_MAPS -> {
                        SusMapsContent(
                            susMaps = susMaps,
                            isLoading = isLoading,
                            onAddSusMap = { },
                            onRemoveSusMap = { map ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeSusMap(context, map)) {
                                        susMaps = SuSFSManager.getSusMaps(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditSusMap = { map ->
                                editingSusMap = map
                            },
                            onReset = { }
                        )
                    }
                    SuSFSTab.KSTAT_CONFIG -> {
                        KstatConfigContent(
                            kstatConfigs = kstatConfigs,
                            addKstatPaths = addKstatPaths,
                            isLoading = isLoading,
                            onAddKstatStatically = { },
                            onAddKstat = { },
                            onRemoveKstatConfig = { config ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeKstatConfig(context, config)) {
                                        kstatConfigs = SuSFSManager.getKstatConfigs(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditKstatConfig = { config ->
                                editingKstatConfig = config
                            },
                            onRemoveAddKstat = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    if (SuSFSManager.removeAddKstat(context, path)) {
                                        addKstatPaths = SuSFSManager.getAddKstatPaths(context)
                                    }
                                    isLoading = false
                                }
                            },
                            onEditAddKstat = { path ->
                                editingKstatPath = path
                            },
                            onUpdateKstat = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    SuSFSManager.updateKstat(context, path)
                                    isLoading = false
                                }
                            },
                            onUpdateKstatFullClone = { path ->
                                coroutineScope.launch {
                                    isLoading = true
                                    SuSFSManager.updateKstatFullClone(context, path)
                                    isLoading = false
                                }
                            }
                        )
                    }
                    SuSFSTab.PATH_SETTINGS -> {
                        PathSettingsContent(
                            androidDataPath = androidDataPath,
                            onAndroidDataPathChange = { androidDataPath = it },
                            sdcardPath = sdcardPath,
                            onSdcardPathChange = { sdcardPath = it },
                            isLoading = isLoading,
                            onSetAndroidDataPath = {
                                coroutineScope.launch {
                                    isLoading = true
                                    SuSFSManager.setAndroidDataPath(context, androidDataPath.trim())
                                    isLoading = false
                                }
                            },
                            onSetSdcardPath = {
                                coroutineScope.launch {
                                    isLoading = true
                                    SuSFSManager.setSdcardPath(context, sdcardPath.trim())
                                    isLoading = false
                                }
                            },
                            onReset = {
                                androidDataPath = "/sdcard/Android/data"
                                sdcardPath = "/sdcard"
                                coroutineScope.launch {
                                    isLoading = true
                                    SuSFSManager.setAndroidDataPath(context, androidDataPath)
                                    SuSFSManager.setSdcardPath(context, sdcardPath)
                                    isLoading = false
                                }
                            }
                        )
                    }
                    SuSFSTab.ENABLED_FEATURES -> {
                        EnabledFeaturesContent(
                            enabledFeatures = enabledFeatures,
                            onRefresh = { loadEnabledFeatures() }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun SlotInfoDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    slotInfoList: List<SuSFSManager.SlotInfo>,
    currentActiveSlot: String,
    isLoadingSlotInfo: Boolean,
    onRefresh: () -> Unit,
    onUseUname: (String) -> Unit,
    onUseBuildTime: (String) -> Unit
) {
    val isAbDevice = produceState(initialValue = false) {
        value = isAbDevice()
    }.value

    val showDialogState = remember { mutableStateOf(showDialog && isAbDevice) }
    
    LaunchedEffect(showDialog, isAbDevice) {
        showDialogState.value = showDialog && isAbDevice
    }

    if (showDialogState.value) {
        SuperDialog(
            show = showDialogState,
            title = stringResource(R.string.susfs_slot_info_title),
            onDismissRequest = onDismiss,
            content = {
                Column(
                    modifier = Modifier.padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = stringResource(R.string.susfs_current_active_slot, currentActiveSlot),
                        style = MiuixTheme.textStyles.body2,
                        fontWeight = FontWeight.Medium,
                        color = colorScheme.primary
                    )

                    if (slotInfoList.isNotEmpty()) {
                        slotInfoList.forEach { slotInfo ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.defaultColors(
                                    if (slotInfo.slotName == currentActiveSlot) {
                                        colorScheme.primary.copy(alpha = 0.1f)
                                    } else {
                                        colorScheme.surface.copy(alpha = 0.5f)
                                    }
                                ),
                                cornerRadius = 8.dp
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Storage,
                                            contentDescription = null,
                                            tint = if (slotInfo.slotName == currentActiveSlot) {
                                                colorScheme.primary
                                            } else {
                                                colorScheme.onSurface
                                            },
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = slotInfo.slotName,
                                            style = MiuixTheme.textStyles.body1,
                                            fontWeight = FontWeight.Bold,
                                            color = if (slotInfo.slotName == currentActiveSlot) {
                                                colorScheme.primary
                                            } else {
                                                colorScheme.onSurface
                                            }
                                        )
                                        if (slotInfo.slotName == currentActiveSlot) {
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Box(
                                                modifier = Modifier
                                                    .background(
                                                        color = colorScheme.primary,
                                                        shape = RoundedCornerShape(4.dp)
                                                    )
                                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                                            ) {
                                                Text(
                                                    text = stringResource(R.string.susfs_slot_current_badge),
                                                    style = MiuixTheme.textStyles.body2,
                                                    color = colorScheme.onPrimary
                                                )
                                            }
                                        }
                                    }
                                    Text(
                                        text = stringResource(R.string.susfs_slot_uname, slotInfo.uname),
                                        style = MiuixTheme.textStyles.body2.copy(fontSize = 13.sp),
                                        color = colorScheme.onSurface
                                    )
                                    Text(
                                        text = stringResource(R.string.susfs_slot_build_time, slotInfo.buildTime),
                                        style = MiuixTheme.textStyles.body2.copy(fontSize = 13.sp),
                                        color = colorScheme.onSurface
                                    )

                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Button(
                                            onClick = { onUseUname(slotInfo.uname) },
                                            modifier = Modifier
                                                .weight(1f)
                                                .heightIn(min = 48.dp)
                                                .padding(vertical = 8.dp),
                                            cornerRadius = 8.dp
                                        ) {
                                            Text(
                                                text = stringResource(R.string.susfs_slot_use_uname),
                                                style = MiuixTheme.textStyles.body2,
                                                maxLines = 2
                                            )
                                        }
                                        Button(
                                            onClick = { onUseBuildTime(slotInfo.buildTime) },
                                            modifier = Modifier
                                                .weight(1f)
                                                .heightIn(min = 48.dp)
                                                .padding(vertical = 8.dp),
                                            cornerRadius = 8.dp
                                        ) {
                                            Text(
                                                text = stringResource(R.string.susfs_slot_use_build_time),
                                                style = MiuixTheme.textStyles.body2,
                                                maxLines = 2
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        Text(
                            text = stringResource(R.string.susfs_slot_info_unavailable),
                            style = MiuixTheme.textStyles.body2,
                            color = colorScheme.error
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    Button(
                        onClick = onRefresh,
                        enabled = !isLoadingSlotInfo,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .padding(vertical = 8.dp),
                        cornerRadius = 8.dp
                    ) {
                        Text(
                            text = stringResource(R.string.refresh)
                        )
                    }

                    Button(
                        onClick = onDismiss,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .padding(vertical = 8.dp),
                        cornerRadius = 8.dp
                    ) {
                        Text(
                            text = stringResource(android.R.string.cancel)
                        )
                    }
                }
            }
        )
    }
}