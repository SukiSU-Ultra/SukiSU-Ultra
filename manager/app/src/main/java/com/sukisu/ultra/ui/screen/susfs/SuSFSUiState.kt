package com.sukisu.ultra.ui.screen.susfs

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.util.AppInfo
import com.sukisu.ultra.ui.screen.susfs.util.EnabledFeature
import com.sukisu.ultra.ui.screen.susfs.util.ModuleConfig
import com.sukisu.ultra.ui.screen.susfs.util.SlotInfo

@Immutable
data class SuSFSUiState(
    val operationResults: List<com.sukisu.ultra.ui.component.ConfigResult> = emptyList(),
    val priorityUidFilterResults: List<com.sukisu.ultra.ui.component.ConfigResult> = emptyList(),
    val isLoading: Boolean = false,
    val runtimeInfo: SuSFSRuntimeInfo? = null,
    val isNavigatingBack: Boolean = false,

    val selectedTab: SuSFSTab = SuSFSTab.BASIC_SETTINGS,

    // 基础配置
    val unameValue: String = "",
    val buildTimeValue: String = "",
    val autoStartEnabled: Boolean = false,
    val canEnableAutoStart: Boolean = false,
    val executeInPostFsData: Boolean = false,
    val enableHideBl: Boolean = false,
    val enableLog: Boolean = false,
    val enableCleanupResidue: Boolean = false,
    val enableAvcLogSpoofing: Boolean = false,
    val hideSusMountsForAllProcs: Boolean = false,
    val cmdlineOrBootconfigPath: String = "",
    val cmdlineOrBootconfigError: String? = null,

    // 槽位信息
    val slotInfoList: List<SlotInfo> = emptyList(),
    val currentActiveSlot: String = "",
    val isLoadingSlotInfo: Boolean = false,
    val slotInfoError: String? = null,
    val showSlotInfoDialog: Boolean = false,

    // 路径配置
    val susPaths: Set<String> = emptySet(),
    val susLoopPaths: Set<String> = emptySet(),
    val susMaps: Set<String> = emptySet(),
    val priorityUidFilter: Set<String> = emptySet(),
    val priorityApps: List<AppInfo> = emptyList(),
    val isLoadingPriorityApps: Boolean = false,
    val showPriorityAppsDialog: Boolean = false,

    // Kstat 配置
    val kstatConfigs: Set<String> = emptySet(),
    val addKstatPaths: Set<String> = emptySet(),

    // 已启用功能
    val enabledFeatures: List<EnabledFeature> = emptyList(),
    val isLoadingFeatures: Boolean = false,

    // 应用列表（用于添加路径）
    val installedApps: List<AppInfo> = emptyList(),
    val isLoadingApps: Boolean = false,

    // 对话框状态
    val showConfirmReset: Boolean = false,
    val showAddPathDialog: Boolean = false,
    val showAddLoopPathDialog: Boolean = false,
    val showAddSusMapDialog: Boolean = false,
    val showAddAppPathDialog: Boolean = false,
    val showAddKstatStaticallyDialog: Boolean = false,
    val showAddKstatDialog: Boolean = false,

    val showResetPathsDialog: Boolean = false,
    val showResetLoopPathsDialog: Boolean = false,
    val showResetSusMapsDialog: Boolean = false,
    val showResetKstatDialog: Boolean = false,

    // 编辑中项
    val editingPath: String? = null,
    val editingLoopPath: String? = null,
    val editingSusMap: String? = null,
    val editingKstatConfig: String? = null,
    val editingKstatPath: String? = null,

    val error: Throwable? = null,
)

enum class SuSFSTab(val displayNameRes: Int) {
    BASIC_SETTINGS(R.string.susfs_tab_basic_settings),
    FEATURE_TOGGLES(R.string.susfs_tab_feature_toggles),
    SUS_PATHS(R.string.susfs_tab_sus_paths),
    SUS_LOOP_PATHS(R.string.susfs_tab_sus_loop_paths),
    SUS_MAPS(R.string.susfs_tab_sus_maps),
    KSTAT_CONFIG(R.string.susfs_tab_kstat_config),
    PRIORITY_UID_FILTER(R.string.susfs_priority_uid_filter),
    ENABLED_FEATURES(R.string.susfs_tab_enabled_features);

    companion object {
        fun getAllTabs(): List<SuSFSTab> {
            return entries.toList()
        }

        /** Map the route/AI tab id to a tab. */
        fun fromRouteId(id: String): SuSFSTab? = when (id.trim().lowercase().replace('-', '_')) {
            "basic", "basic_settings" -> BASIC_SETTINGS
            "features", "feature_toggles" -> FEATURE_TOGGLES
            "sus_paths" -> SUS_PATHS
            "sus_loop_paths" -> SUS_LOOP_PATHS
            "sus_maps" -> SUS_MAPS
            "kstat", "kstat_config" -> KSTAT_CONFIG
            "priority_uid", "priority_uid_filter" -> PRIORITY_UID_FILTER
            "enabled_features" -> ENABLED_FEATURES
            else -> null
        }
    }
}

data class SuSFSRuntimeInfo(
    val version: String?,
    val variant: String?,
    val implementation: String?,
)
