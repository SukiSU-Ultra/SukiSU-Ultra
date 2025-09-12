package zako.zako.zako.zakoui.activity.util

import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.util.getKpmModuleCount
import com.sukisu.ultra.ui.util.getKpmVersion
import com.sukisu.ultra.ui.util.getModuleCount
import com.sukisu.ultra.ui.util.getSuperuserCount
import com.sukisu.ultra.ui.util.rootAvailable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object AppData {
    object DataRefreshManager {
        // 私有状态流
        private val _superuserCount = MutableStateFlow(0)
        private val _moduleCount = MutableStateFlow(0)
        private val _kpmModuleCount = MutableStateFlow(0)

        // 公开的只读状态流
        val superuserCount: StateFlow<Int> = _superuserCount.asStateFlow()
        val moduleCount: StateFlow<Int> = _moduleCount.asStateFlow()
        val kpmModuleCount: StateFlow<Int> = _kpmModuleCount.asStateFlow()

        /**
         * 刷新所有数据计数
         */
        fun refreshData() {
            _superuserCount.value = getSuperuserCountUse()
            _moduleCount.value = getModuleCountUse()
            _kpmModuleCount.value = getKpmModuleCountUse()
        }

    }

    /**
     * 获取超级用户应用计数
     */
    fun getSuperuserCountUse(): Int {
        return try {
            if (!rootAvailable()) return 0
            getSuperuserCount()
        } catch (_: Exception) {
            0
        }
    }

    /**
     * 获取模块计数
     */
    fun getModuleCountUse(): Int {
        return try {
            if (!rootAvailable()) return 0
            getModuleCount()
        } catch (_: Exception) {
            0
        }
    }

    /**
     * 获取KPM模块计数
     */
    fun getKpmModuleCountUse(): Int {
        return try {
            if (!rootAvailable()) return 0
            val kpmVersion = getKpmVersionUse()
            if (kpmVersion.isEmpty() || kpmVersion.startsWith("Error")) return 0
            getKpmModuleCount()
        } catch (_: Exception) {
            0
        }
    }

    /**
     * 获取KPM版本
     */
    fun getKpmVersionUse(): String {
        return try {
            if (!rootAvailable()) return ""
            val version = getKpmVersion()
            version.ifEmpty { "" }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    /**
     * 检查是否具有管理员权限
     */
    fun isManager(packageName: String): Boolean {
        return Natives.becomeManager(packageName)
    }

    /**
     * 检查是否是完整功能模式
     */
    fun isFullFeatured(packageName: String): Boolean {
        val isManager = Natives.becomeManager(packageName)
        return isManager && !Natives.requireNewKernel() && rootAvailable()
    }
}