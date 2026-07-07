package com.sukisu.ultra.ui.screen.susfs.repository

import android.content.Context
import com.sukisu.ultra.ui.screen.susfs.util.AppInfo
import com.sukisu.ultra.ui.screen.susfs.util.EnabledFeature
import com.sukisu.ultra.ui.screen.susfs.util.ModuleConfig
import com.sukisu.ultra.ui.screen.susfs.util.SlotInfo

interface SuSFSRepositoryInterface {
    suspend fun loadInitialConfig(context: Context): Result<ModuleConfig>
    suspend fun getEnabledFeatures(context: Context): Result<List<EnabledFeature>>
    suspend fun getInstalledApps(): Result<List<AppInfo>>
    suspend fun getSlotInfo(context: Context): Result<Pair<List<SlotInfo>, String>>
}
