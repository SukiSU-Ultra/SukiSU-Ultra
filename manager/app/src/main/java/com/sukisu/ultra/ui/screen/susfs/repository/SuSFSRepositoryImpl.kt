package com.sukisu.ultra.ui.screen.susfs.repository

import android.content.Context
import com.sukisu.ultra.ui.screen.susfs.util.AppInfo
import com.sukisu.ultra.ui.screen.susfs.util.EnabledFeature
import com.sukisu.ultra.ui.screen.susfs.util.ModuleConfig
import com.sukisu.ultra.ui.screen.susfs.util.SlotInfo
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class SuSFSRepositoryImpl : SuSFSRepositoryInterface {

    override suspend fun loadInitialConfig(context: Context): Result<ModuleConfig> =
        try {
            Result.success(SuSFSManager.getCurrentModuleConfig())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(e)
        }

    override suspend fun getEnabledFeatures(context: Context): Result<List<EnabledFeature>> =
        withContext(Dispatchers.IO) {
            runCatching { SuSFSManager.getEnabledFeatures(context) }
        }

    override suspend fun getInstalledApps(): Result<List<AppInfo>> =
        withContext(Dispatchers.IO) {
            runCatching { SuSFSManager.getInstalledApps() }
        }

    override suspend fun getSlotInfo(
        context: Context
    ): Result<Pair<List<SlotInfo>, String>> = withContext(Dispatchers.IO) {
        runCatching {
            val slotInfo = SuSFSManager.getCurrentSlotInfo()
            val currentActive = SuSFSManager.getCurrentActiveSlot()
            slotInfo to currentActive
        }
    }
}
