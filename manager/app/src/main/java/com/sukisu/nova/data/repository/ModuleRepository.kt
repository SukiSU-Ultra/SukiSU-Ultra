package com.sukisu.nova.data.repository

import com.sukisu.nova.data.model.Module
import com.sukisu.nova.data.model.ModuleUpdateInfo

interface ModuleRepository {
    suspend fun getModules(): Result<List<Module>>
    suspend fun checkUpdate(module: Module): Result<ModuleUpdateInfo>
}
