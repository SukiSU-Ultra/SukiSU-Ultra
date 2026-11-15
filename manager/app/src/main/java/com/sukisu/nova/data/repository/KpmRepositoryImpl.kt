package com.sukisu.nova.data.repository

import android.util.Log
import com.sukisu.nova.ui.util.controlKpmModule
import com.sukisu.nova.ui.util.getKpmModuleInfo
import com.sukisu.nova.ui.util.listKpmModules
import com.sukisu.nova.ui.util.loadKpmModule
import com.sukisu.nova.ui.util.unloadKpmModule
import com.sukisu.nova.ui.viewmodel.KpmViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext

class KpmRepositoryImpl : KpmRepository {

    companion object {
        private const val TAG = "KpmRepository"
    }

    override suspend fun getModuleList(): Result<List<KpmViewModel.ModuleInfo>> = withContext(Dispatchers.IO) {
        runCatching {
            val moduleNames = listKpmModules().lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .distinct()
                .toList()

            moduleNames.mapNotNull { name ->
                try {
                    parseModuleInfo(name)
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    Log.e(TAG, "Error processing module $name", e)
                    null
                }
            }.sortedWith(compareBy<KpmViewModel.ModuleInfo> { it.id.lowercase() }.thenBy { it.id })
        }
    }

    override suspend fun getModuleInfo(moduleId: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            getKpmModuleInfo(moduleId)
        }
    }

    override suspend fun loadModule(path: String, args: String?): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val success = loadKpmModule(path, args)
            if (!success) throw Exception("Failed to load module")
        }
    }

    override suspend fun unloadModule(moduleId: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val success = unloadKpmModule(moduleId)
            if (!success) throw Exception("Failed to unload module")
        }
    }

    override suspend fun controlModule(moduleId: String, args: String?): Result<Int> = withContext(Dispatchers.IO) {
        runCatching {
            controlKpmModule(moduleId, args)
        }
    }

    private fun parseModuleInfo(name: String): KpmViewModel.ModuleInfo {
        val info = getKpmModuleInfo(name)
        if (info.isBlank()) {
            return KpmViewModel.ModuleInfo(
                id = name,
                name = name,
                version = "",
                author = "",
                description = "",
                args = "",
                enabled = true,
                hasAction = true
            )
        }

        val properties = info.lineSequence()
            .filter { line ->
                val trimmed = line.trim()
                trimmed.isNotEmpty() && !trimmed.startsWith("#")
            }
            .mapNotNull { line ->
                line.split("=", limit = 2).let { parts ->
                    when (parts.size) {
                        2 -> parts[0].trim() to parts[1].trim()
                        1 -> parts[0].trim() to ""
                        else -> null
                    }
                }
            }
            .toMap()

        return KpmViewModel.ModuleInfo(
            id = name,
            name = properties["name"] ?: name,
            version = properties["version"] ?: "",
            author = properties["author"] ?: "",
            description = properties["description"] ?: "",
            args = properties["args"] ?: "",
            enabled = true,
            hasAction = true
        )
    }
}
