package com.sukisu.ultra.ui.viewmodel

import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.ui.util.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
class KpmViewModel : ViewModel() {
    var moduleList by mutableStateOf(emptyList<ModuleInfo>())
        private set

    var search by mutableStateOf("")
        internal set

    var isRefreshing by mutableStateOf(false)
        private set

    var currentModuleDetail by mutableStateOf("")
        private set

    fun fetchModuleList() {
        viewModelScope.launch {
            isRefreshing = true
            try {
                val moduleCount = getKpmModuleCount()
                Log.d("KsuCli", "Module count: $moduleCount")

                moduleList = getAllKpmModuleInfo()

                // 获取 KPM 版本信息
                val kpmVersion = getKpmVersion()
                Log.d("KsuCli", "KPM Version: $kpmVersion")
            } catch (e: Exception) {
                Log.e("KsuCli", "获取模块列表失败", e)
            } finally {
                isRefreshing = false
            }
        }
    }

    private fun getAllKpmModuleInfo(): List<ModuleInfo> {
        val result = mutableListOf<ModuleInfo>()
        try {
            val str = listKpmModules()
            val moduleNames = str
                .split("\n")
                .filter { it.isNotBlank() }

            for (name in moduleNames) {
                try {
                    val moduleInfo = parseModuleInfo(name)
                    moduleInfo?.let { result.add(it) }
                } catch (e: Exception) {
                    Log.e("KsuCli", "Error processing module $name", e)
                }
            }
        } catch (e: Exception) {
            Log.e("KsuCli", "Failed to get module list", e)
        }
        return result
    }

    private fun parseModuleInfo(name: String): ModuleInfo? {
        val info = getKpmModuleInfo(name)
        if (info.isBlank()) return null

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

        return ModuleInfo(
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

    fun loadModuleDetail(moduleId: String) {
        viewModelScope.launch {
            try {
                currentModuleDetail = withContext(Dispatchers.IO) {
                    getKpmModuleInfo(moduleId)
                }
                Log.d("KsuCli", "Module detail loaded: $currentModuleDetail")
            } catch (e: Exception) {
                Log.e("KsuCli", "Failed to load module detail", e)
                currentModuleDetail = "Error: ${e.message}"
            }
        }
    }

    var showInputDialog by mutableStateOf(false)
        private set

    var selectedModuleId by mutableStateOf<String?>(null)
        private set

    var inputArgs by mutableStateOf("")
        private set

    fun showInputDialog(moduleId: String) {
        selectedModuleId = moduleId
        showInputDialog = true
    }

    fun hideInputDialog() {
        showInputDialog = false
        selectedModuleId = null
        inputArgs = ""
    }

    fun updateInputArgs(args: String) {
        inputArgs = args
    }

    fun executeControl(): Int {
        val moduleId = selectedModuleId ?: return -1
        val result = controlKpmModule(moduleId, inputArgs)
        hideInputDialog()
        return result
    }

    data class ModuleInfo(
        val id: String,
        val name: String,
        val version: String,
        val author: String,
        val description: String,
        val args: String,
        val enabled: Boolean,
        val hasAction: Boolean
    )
}
