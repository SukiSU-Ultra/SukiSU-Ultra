package com.sukisu.nova.data.repository

import com.sukisu.nova.data.model.AppInfo

interface SuperUserRepository {
    suspend fun getAppList(force: Boolean = false): Result<Pair<List<AppInfo>, List<Int>>>
    suspend fun refreshProfiles(currentApps: List<AppInfo>): Result<List<AppInfo>>
}
