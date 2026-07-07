package com.sukisu.ultra.ui.screen.susfs

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.util.AppInfo
import com.sukisu.ultra.ui.screen.susfs.util.EnabledFeature
import com.sukisu.ultra.ui.screen.susfs.util.ModuleConfig
import com.sukisu.ultra.ui.screen.susfs.util.SlotInfo

@Immutable
data class SuSFSUiState(
    val isLoading: Boolean = false,
    val isNavigatingBack: Boolean = false,

    val selectedTab: SuSFSTab = SuSFSTab.BASIC_SETTINGS,

    // 基础配置
    val unameValue: String = "",
    val buildTimeValue: String = "",
    val autoStartEnabled: Boolean = false,
    val canEnableAutoStart: Boolean = false,
    val executeInPostFsData: Boolean = false,
    val enableHideBl: Boolean = false,
    val enableCleanupResidue: Boolean = false,
    val enableAvcLogSpoofing: Boolean = false,
    val hideSusMountsForAllProcs: Boolean = false,

    // 槽位信息
    val slotInfoList: List<SlotInfo> = emptyList(),
    val currentActiveSlot: String = "",
    val isLoadingSlotInfo: Boolean = false,
    val showSlotInfoDialog: Boolean = false,

    // 路径配置
    val susPaths: Set<String> = emptySet(),
    val susLoopPaths: Set<String> = emptySet(),
    val susMaps: Set<String> = emptySet(),

    // Kstat 配置
    val kstatConfigs: Set<String> = emptySet(),
    val addKstatPaths: Set<String> = emptySet(),

    // 已启用功能
    val enabledFeatures: List<EnabledFeature> = emptyList(),
    val isLoadingFeatures: Boolean = false,

    // 应用列表（用于添加路径）
    val installedApps: List<AppInfo> = emptyList(),

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
    SUS_PATHS(R.string.susfs_tab_sus_paths),
    SUS_LOOP_PATHS(R.string.susfs_tab_sus_loop_paths),
    SUS_MAPS(R.string.susfs_tab_sus_maps),
    KSTAT_CONFIG(R.string.susfs_tab_kstat_config),
    ENABLED_FEATURES(R.string.susfs_tab_enabled_features);

    companion object {
        fun getAllTabs(): List<SuSFSTab> {
            return entries.toList()
        }
    }
}
