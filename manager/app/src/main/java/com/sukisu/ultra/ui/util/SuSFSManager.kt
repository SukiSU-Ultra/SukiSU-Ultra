package com.sukisu.ultra.ui.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.widget.Toast
import com.dergoogler.mmrl.platform.Platform.Companion.context
import com.sukisu.ultra.R
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.FileOutputStream
import java.io.IOException
import java.io.File

/**
 * SuSFS 配置管理器
 * 用于管理SuSFS相关的配置和命令执行
 */
object SuSFSManager {
    private const val PREFS_NAME = "susfs_config"
    private const val KEY_UNAME_VALUE = "uname_value"
    private const val KEY_BUILD_TIME_VALUE = "build_time_value"
    private const val KEY_IS_ENABLED = "is_enabled"
    private const val KEY_AUTO_START_ENABLED = "auto_start_enabled"
    private const val KEY_LAST_APPLIED_VALUE = "last_applied_value"
    private const val KEY_LAST_APPLIED_BUILD_TIME = "last_applied_build_time"
    private const val KEY_SUS_PATHS = "sus_paths"
    private const val KEY_SUS_MOUNTS = "sus_mounts"
    private const val KEY_TRY_UMOUNTS = "try_umounts"
    private const val KEY_ANDROID_DATA_PATH = "android_data_path"
    private const val KEY_SDCARD_PATH = "sdcard_path"
    private const val KEY_ENABLE_LOG = "enable_log"
    private const val SUSFS_BINARY_BASE_NAME = "ksu_susfs"
    private const val DEFAULT_UNAME = "default"
    private const val DEFAULT_BUILD_TIME = "default"
    private const val STARTUP_SCRIPT_PATH = "/data/adb/service.d/susfs_startup.sh"

    private fun getSuSFS(): String {
        return try {
            getSuSFSVersion()
        } catch (_: Exception) {
            "1.5.8"
        }
    }

    private fun getSuSFSBinaryName(): String {
        val variant = getSuSFS().removePrefix("v")
        return "${SUSFS_BINARY_BASE_NAME}_${variant}"
    }

    /**
     * 获取SuSFS二进制文件的完整路径
     */
    private fun getSuSFSTargetPath(): String {
        return "/data/adb/ksu/bin/${getSuSFSBinaryName()}"
    }

    /**
     * 启用功能状态数据类
     */
    data class EnabledFeature(
        val name: String,
        val isEnabled: Boolean,
        val statusText: String = if (isEnabled) context.getString(R.string.susfs_feature_enabled) else context.getString(R.string.susfs_feature_disabled),
        val canConfigure: Boolean = false // 是否可配置（通过弹窗）
    )

    /**
     * 功能配置映射数据类
     */
    private data class FeatureMapping(
        val id: String,
        val config: String
    )

    /**
     * 执行Shell命令并返回输出
     */
    private fun runCmd(shell: Shell, cmd: String): String {
        return shell.newJob()
            .add(cmd)
            .to(mutableListOf<String>(), null)
            .exec().out
            .joinToString("\n")
    }

    /**
     * 获取Root Shell实例
     */
    private fun getRootShell(): Shell {
        return Shell.getShell()
    }

    /**
     * 获取SuSFS配置的SharedPreferences
     */
    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /**
     * 保存uname值
     */
    fun saveUnameValue(context: Context, value: String) {
        getPrefs(context).edit().apply {
            putString(KEY_UNAME_VALUE, value)
            apply()
        }
    }

    /**
     * 获取保存的uname值
     */
    fun getUnameValue(context: Context): String {
        return getPrefs(context).getString(KEY_UNAME_VALUE, DEFAULT_UNAME) ?: DEFAULT_UNAME
    }

    /**
     * 保存构建时间值
     */
    fun saveBuildTimeValue(context: Context, value: String) {
        getPrefs(context).edit().apply {
            putString(KEY_BUILD_TIME_VALUE, value)
            apply()
        }
    }

    /**
     * 获取保存的构建时间值
     */
    fun getBuildTimeValue(context: Context): String {
        return getPrefs(context).getString(KEY_BUILD_TIME_VALUE, DEFAULT_BUILD_TIME) ?: DEFAULT_BUILD_TIME
    }

    /**
     * 保存最后应用的值
     */
    private fun saveLastAppliedValue(context: Context, value: String) {
        getPrefs(context).edit().apply {
            putString(KEY_LAST_APPLIED_VALUE, value)
            apply()
        }
    }

    /**
     * 获取最后应用的值
     */
    fun getLastAppliedValue(context: Context): String {
        return getPrefs(context).getString(KEY_LAST_APPLIED_VALUE, DEFAULT_UNAME) ?: DEFAULT_UNAME
    }

    /**
     * 保存最后应用的构建时间值
     */
    private fun saveLastAppliedBuildTime(context: Context, value: String) {
        getPrefs(context).edit().apply {
            putString(KEY_LAST_APPLIED_BUILD_TIME, value)
            apply()
        }
    }

    /**
     * 获取最后应用的构建时间值
     */
    fun getLastAppliedBuildTime(context: Context): String {
        return getPrefs(context).getString(KEY_LAST_APPLIED_BUILD_TIME, DEFAULT_BUILD_TIME) ?: DEFAULT_BUILD_TIME
    }

    /**
     * 保存SuSFS启用状态
     */
    fun setEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().apply {
            putBoolean(KEY_IS_ENABLED, enabled)
            apply()
        }
    }

    /**
     * 设置开机自启动状态
     */
    fun setAutoStartEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().apply {
            putBoolean(KEY_AUTO_START_ENABLED, enabled)
            apply()
        }
    }

    /**
     * 获取开机自启动状态
     */
    fun isAutoStartEnabled(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_AUTO_START_ENABLED, false)
    }

    /**
     * 保存日志启用状态
     */
    fun saveEnableLogState(context: Context, enabled: Boolean) {
        getPrefs(context).edit().apply {
            putBoolean(KEY_ENABLE_LOG, enabled)
            apply()
        }
    }

    /**
     * 获取日志启用状态
     */
    fun getEnableLogState(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_ENABLE_LOG, false)
    }

    /**
     * 保存SUS路径列表
     */
    fun saveSusPaths(context: Context, paths: Set<String>) {
        getPrefs(context).edit().apply {
            putStringSet(KEY_SUS_PATHS, paths)
            apply()
        }
    }

    /**
     * 获取SUS路径列表
     */
    fun getSusPaths(context: Context): Set<String> {
        return getPrefs(context).getStringSet(KEY_SUS_PATHS, emptySet()) ?: emptySet()
    }

    /**
     * 保存SUS挂载列表
     */
    fun saveSusMounts(context: Context, mounts: Set<String>) {
        getPrefs(context).edit().apply {
            putStringSet(KEY_SUS_MOUNTS, mounts)
            apply()
        }
    }

    /**
     * 获取SUS挂载列表
     */
    fun getSusMounts(context: Context): Set<String> {
        return getPrefs(context).getStringSet(KEY_SUS_MOUNTS, emptySet()) ?: emptySet()
    }

    /**
     * 保存尝试卸载列表
     */
    fun saveTryUmounts(context: Context, umounts: Set<String>) {
        getPrefs(context).edit().apply {
            putStringSet(KEY_TRY_UMOUNTS, umounts)
            apply()
        }
    }

    /**
     * 获取尝试卸载列表
     */
    fun getTryUmounts(context: Context): Set<String> {
        return getPrefs(context).getStringSet(KEY_TRY_UMOUNTS, emptySet()) ?: emptySet()
    }

    /**
     * 保存Android Data路径
     */
    fun saveAndroidDataPath(context: Context, path: String) {
        getPrefs(context).edit().apply {
            putString(KEY_ANDROID_DATA_PATH, path)
            apply()
        }
    }

    /**
     * 获取Android Data路径
     */
    @SuppressLint("SdCardPath")
    fun getAndroidDataPath(context: Context): String {
        return getPrefs(context).getString(KEY_ANDROID_DATA_PATH, "/sdcard/Android/data") ?: "/sdcard/Android/data"
    }

    /**
     * 保存SD卡路径
     */
    fun saveSdcardPath(context: Context, path: String) {
        getPrefs(context).edit().apply {
            putString(KEY_SDCARD_PATH, path)
            apply()
        }
    }

    /**
     * 获取SD卡路径
     */
    @SuppressLint("SdCardPath")
    fun getSdcardPath(context: Context): String {
        return getPrefs(context).getString(KEY_SDCARD_PATH, "/sdcard") ?: "/sdcard"
    }

    /**
     * 从assets复制ksu_susfs文件到/data/adb/ksu/bin/
     */
    private suspend fun copyBinaryFromAssets(context: Context): String? = withContext(Dispatchers.IO) {
        try {
            val binaryName = getSuSFSBinaryName()
            val targetPath = getSuSFSTargetPath()
            val inputStream = context.assets.open(binaryName)
            val tempFile = File(context.cacheDir, binaryName)

            FileOutputStream(tempFile).use { outputStream ->
                inputStream.copyTo(outputStream)
            }

            // 创建目标目录并复制文件到/data/adb/ksu/bin/
            val shell = getRootShell()
            val commands = arrayOf(
                "cp '${tempFile.absolutePath}' '$targetPath'",
                "chmod 755 '$targetPath'",
            )

            var success = true
            for (command in commands) {
                val result = shell.newJob().add(command).exec()
                if (!result.isSuccess) {
                    success = false
                    break
                }
            }

            // 清理临时文件
            tempFile.delete()

            if (success) {
                val verifyResult = shell.newJob().add("test -f '$targetPath'").exec()
                if (verifyResult.isSuccess) {
                    targetPath
                } else {
                    null
                }
            } else {
                null
            }
        } catch (e: IOException) {
            e.printStackTrace()
            null
        }
    }

    /**
     * 创建开机自启动脚本
     */
    @SuppressLint("SdCardPath")
    private suspend fun createStartupScript(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val unameValue = getUnameValue(context)
            val buildTimeValue = getBuildTimeValue(context)
            val susPaths = getSusPaths(context)
            val susMounts = getSusMounts(context)
            val tryUmounts = getTryUmounts(context)
            val androidDataPath = getAndroidDataPath(context)
            val sdcardPath = getSdcardPath(context)
            val enableLog = getEnableLogState(context)
            val targetPath = getSuSFSTargetPath()

            val scriptContent = buildString {
                appendLine("#!/system/bin/sh")
                appendLine("# SuSFS 开机自启动脚本")
                appendLine("# 由 KernelSU Manager 自动生成")
                appendLine()
                appendLine("# 等待系统完全启动")
                appendLine("sleep 60")
                appendLine()
                appendLine("# 检查二进制文件是否存在")
                appendLine("if [ -f \"$targetPath\" ]; then")
                appendLine("    # 创建日志目录")
                appendLine("    mkdir -p /data/adb/ksu/log")
                appendLine()

                // 设置日志启用状态
                appendLine("    # 设置日志启用状态")
                val logValue = if (enableLog) 1 else 0
                appendLine("    $targetPath enable_log $logValue")
                appendLine("    echo \"\\$(date): 日志功能设置为: ${if (enableLog) "启用" else "禁用"}\" >> /data/adb/ksu/log/susfs_startup.log")

                // 设置Android Data路径
                if (androidDataPath != "/sdcard/Android/data") {
                    appendLine("    # 设置Android Data路径")
                    appendLine("    $targetPath set_android_data_root_path '$androidDataPath'")
                    appendLine("    echo \"\\$(date): Android Data路径设置为: $androidDataPath\" >> /data/adb/ksu/log/susfs_startup.log")
                }

                // 设置SD卡路径
                if (sdcardPath != "/sdcard") {
                    appendLine("    # 设置SD卡路径")
                    appendLine("    $targetPath set_sdcard_root_path '$sdcardPath'")
                    appendLine("    echo \"\\$(date): SD卡路径设置为: $sdcardPath\" >> /data/adb/ksu/log/susfs_startup.log")
                }

                // 添加SUS路径
                susPaths.forEach { path ->
                    appendLine("    # 添加SUS路径: $path")
                    appendLine("    $targetPath add_sus_path '$path'")
                    appendLine("    echo \"\\$(date): 添加SUS路径: $path\" >> /data/adb/ksu/log/susfs_startup.log")
                }

                // 添加SUS挂载
                susMounts.forEach { mount ->
                    appendLine("    # 添加SUS挂载: $mount")
                    appendLine("    $targetPath add_sus_mount '$mount'")
                    appendLine("    echo \"\\$(date): 添加SUS挂载: $mount\" >> /data/adb/ksu/log/susfs_startup.log")
                }

                // 添加尝试卸载
                tryUmounts.forEach { umount ->
                    val parts = umount.split("|")
                    if (parts.size == 2) {
                        val path = parts[0]
                        val mode = parts[1]
                        appendLine("    # 添加尝试卸载: $path (模式: $mode)")
                        appendLine("    $targetPath add_try_umount '$path' $mode")
                        appendLine("    echo \"\\$(date): 添加尝试卸载: $path (模式: $mode)\" >> /data/adb/ksu/log/susfs_startup.log")
                    }
                }

                // 设置uname和构建时间
                if (unameValue != DEFAULT_UNAME || buildTimeValue != DEFAULT_BUILD_TIME) {
                    appendLine("    # 设置uname和构建时间")
                    appendLine("    $targetPath set_uname '$unameValue' '$buildTimeValue'")
                    appendLine("    echo \"\\$(date): 设置uname为: $unameValue, 构建时间为: $buildTimeValue\" >> /data/adb/ksu/log/susfs_startup.log")
                }

                appendLine("else")
                appendLine("    echo \"\\$(date): SuSFS二进制文件未找到: $targetPath\" >> /data/adb/ksu/log/susfs_startup.log")
                appendLine("fi")
            }

            val shell = getRootShell()
            val commands = arrayOf(
                "mkdir -p /data/adb/service.d",
                "cat > $STARTUP_SCRIPT_PATH << 'EOF'\n$scriptContent\nEOF",
                "chmod 755 $STARTUP_SCRIPT_PATH"
            )

            var success = true
            for (command in commands) {
                val result = shell.newJob().add(command).exec()
                if (!result.isSuccess) {
                    success = false
                    break
                }
            }

            success
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    /**
     * 删除开机自启动脚本
     */
    private suspend fun removeStartupScript(): Boolean = withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()
            val result = shell.newJob().add("rm -f $STARTUP_SCRIPT_PATH").exec()
            result.isSuccess
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    /**
     * 执行SuSFS命令
     */
    private suspend fun executeSusfsCommand(context: Context, command: String): Boolean = withContext(Dispatchers.IO) {
        try {
            // 确保二进制文件存在
            val binaryPath = copyBinaryFromAssets(context)
            if (binaryPath == null) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        context,
                        context.getString(R.string.susfs_binary_not_found),
                        Toast.LENGTH_SHORT
                    ).show()
                }
                return@withContext false
            }

            // 执行命令
            val fullCommand = "$binaryPath $command"
            val result = getRootShell().newJob().add(fullCommand).exec()

            if (!result.isSuccess) {
                withContext(Dispatchers.Main) {
                    val errorOutput = result.out.joinToString("\n") + "\n" + result.err.joinToString("\n")
                    Toast.makeText(
                        context,
                        context.getString(R.string.susfs_command_failed) + "\n$errorOutput",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }

            result.isSuccess
        } catch (e: Exception) {
            e.printStackTrace()
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    context,
                    context.getString(R.string.susfs_command_error, e.message ?: "Unknown error"),
                    Toast.LENGTH_SHORT
                ).show()
            }
            false
        }
    }

    /**
     * 启用或禁用日志功能
     */
    suspend fun setEnableLog(context: Context, enabled: Boolean): Boolean {
        val value = if (enabled) 1 else 0
        val success = executeSusfsCommand(context, "enable_log $value")
        if (success) {
            saveEnableLogState(context, enabled)

            // 如果开启了开机自启动，更新启动脚本
            if (isAutoStartEnabled(context)) {
                createStartupScript(context)
            }

            withContext(Dispatchers.Main) {
                Toast.makeText(
                    context,
                    if (enabled) context.getString(R.string.susfs_log_enabled) else context.getString(R.string.susfs_log_disabled),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
        return success
    }

    /**
     * 获取功能配置映射表
     */
    private fun getFeatureMappings(): List<FeatureMapping> {
        return listOf(
            FeatureMapping("status_sus_path", "CONFIG_KSU_SUSFS_SUS_PATH"),
            FeatureMapping("status_sus_mount", "CONFIG_KSU_SUSFS_SUS_MOUNT"),
            FeatureMapping("status_auto_default_mount", "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT"),
            FeatureMapping("status_auto_bind_mount", "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT"),
            FeatureMapping("status_sus_kstat", "CONFIG_KSU_SUSFS_SUS_KSTAT"),
            FeatureMapping("status_try_umount", "CONFIG_KSU_SUSFS_TRY_UMOUNT"),
            FeatureMapping("status_auto_try_umount_bind", "CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT"),
            FeatureMapping("status_spoof_uname", "CONFIG_KSU_SUSFS_SPOOF_UNAME"),
            FeatureMapping("status_enable_log", "CONFIG_KSU_SUSFS_ENABLE_LOG"),
            FeatureMapping("status_hide_symbols", "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS"),
            FeatureMapping("status_spoof_cmdline", "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG"),
            FeatureMapping("status_open_redirect", "CONFIG_KSU_SUSFS_OPEN_REDIRECT"),
            FeatureMapping("status_magic_mount", "CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT"),
            FeatureMapping("status_overlayfs_auto_kstat", "CONFIG_KSU_SUSFS_SUS_OVERLAYFS")
        )
    }

    /**
     * 获取启用功能状态
     */
    suspend fun getEnabledFeatures(context: Context): List<EnabledFeature> = withContext(Dispatchers.IO) {
        try {
            // 每次都重新执行命令获取最新状态
            val shell = getRootShell()
            val targetPath = getSuSFSTargetPath()

            // 首先检查二进制文件是否存在于目标位置
            val checkResult = shell.newJob().add("test -f '$targetPath'").exec()

            val binaryPath = if (checkResult.isSuccess) {
                // 如果目标位置存在，直接使用
                targetPath
            } else {
                // 如果不存在，尝试从assets复制
                copyBinaryFromAssets(context)
            }

            if (binaryPath == null) {
                return@withContext emptyList()
            }

            // 使用runCmd执行show enabled_features命令获取实时状态
            val command = "$binaryPath show enabled_features"
            val output = runCmd(shell, command)

            if (output.isNotEmpty()) {
                parseEnabledFeatures(context, output)
            } else {
                // 如果命令输出为空，返回空列表
                emptyList()
            }
        } catch (e: Exception) {
            e.printStackTrace()
            emptyList()
        }
    }

    /**
     * 解析启用功能状态输出
     */
    private fun parseEnabledFeatures(context: Context, output: String): List<EnabledFeature> {
        val features = mutableListOf<EnabledFeature>()

        // 将输出按行分割并保存到集合中进行快速查找
        val outputLines = output.lines().map { it.trim() }.filter { it.isNotEmpty() }.toSet()

        // 获取功能配置映射表
        val featureMappings = getFeatureMappings()

        // 定义功能名称映射（id到显示名称）
        val featureNameMap = mapOf(
            "status_sus_path" to context.getString(R.string.sus_path_feature_label),
            "status_sus_mount" to context.getString(R.string.sus_mount_feature_label),
            "status_try_umount" to context.getString(R.string.try_umount_feature_label),
            "status_spoof_uname" to context.getString(R.string.spoof_uname_feature_label),
            "status_spoof_cmdline" to context.getString(R.string.spoof_cmdline_feature_label),
            "status_open_redirect" to context.getString(R.string.open_redirect_feature_label),
            "status_enable_log" to context.getString(R.string.enable_log_feature_label),
            "status_auto_default_mount" to context.getString(R.string.auto_default_mount_feature_label),
            "status_auto_bind_mount" to context.getString(R.string.auto_bind_mount_feature_label),
            "status_auto_try_umount_bind" to context.getString(R.string.auto_try_umount_bind_feature_label),
            "status_hide_symbols" to context.getString(R.string.hide_symbols_feature_label),
            "status_sus_kstat" to context.getString(R.string.sus_kstat_feature_label),
            "status_magic_mount" to context.getString(R.string.magic_mount_feature_label),
            "status_overlayfs_auto_kstat" to context.getString(R.string.overlayfs_auto_kstat_feature_label)
        )

        // 根据映射表检查每个功能的启用状态
        featureMappings.forEach { mapping ->
            val displayName = featureNameMap[mapping.id] ?: mapping.id
            val isEnabled = outputLines.contains(mapping.config)
            val statusText = if (isEnabled) context.getString(R.string.susfs_feature_enabled) else context.getString(R.string.susfs_feature_disabled)
            // 只有 enable_log 功能可以配置
            val canConfigure = mapping.id == "status_enable_log"
            features.add(EnabledFeature(displayName, isEnabled, statusText, canConfigure))
        }

        return features.sortedBy { it.name }
    }

    /**
     * 添加SUS路径
     */
    suspend fun addSusPath(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "add_sus_path '$path'")
        if (success) {
            val currentPaths = getSusPaths(context).toMutableSet()
            currentPaths.add(path)
            saveSusPaths(context, currentPaths)

            // 如果开启了开机自启动，更新启动脚本
            if (isAutoStartEnabled(context)) {
                createStartupScript(context)
            }
        }
        return success
    }

    /**
     * 移除SUS路径
     */
    suspend fun removeSusPath(context: Context, path: String): Boolean {
        val currentPaths = getSusPaths(context).toMutableSet()
        currentPaths.remove(path)
        saveSusPaths(context, currentPaths)

        // 如果开启了开机自启动，更新启动脚本
        if (isAutoStartEnabled(context)) {
            createStartupScript(context)
        }

        withContext(Dispatchers.Main) {
            Toast.makeText(context, "已移除SUS路径: $path", Toast.LENGTH_SHORT).show()
        }
        return true
    }

    /**
     * 添加SUS挂载
     */
    suspend fun addSusMount(context: Context, mount: String): Boolean {
        val success = executeSusfsCommand(context, "add_sus_mount '$mount'")
        if (success) {
            val currentMounts = getSusMounts(context).toMutableSet()
            currentMounts.add(mount)
            saveSusMounts(context, currentMounts)

            // 如果开启了开机自启动，更新启动脚本
            if (isAutoStartEnabled(context)) {
                createStartupScript(context)
            }
        }
        return success
    }

    /**
     * 移除SUS挂载
     */
    suspend fun removeSusMount(context: Context, mount: String): Boolean {
        val currentMounts = getSusMounts(context).toMutableSet()
        currentMounts.remove(mount)
        saveSusMounts(context, currentMounts)

        // 如果开启了开机自启动，更新启动脚本
        if (isAutoStartEnabled(context)) {
            createStartupScript(context)
        }

        withContext(Dispatchers.Main) {
            Toast.makeText(context, "已移除SUS挂载: $mount", Toast.LENGTH_SHORT).show()
        }
        return true
    }

    /**
     * 添加尝试卸载
     */
    suspend fun addTryUmount(context: Context, path: String, mode: Int): Boolean {
        val success = executeSusfsCommand(context, "add_try_umount '$path' $mode")
        if (success) {
            val currentUmounts = getTryUmounts(context).toMutableSet()
            currentUmounts.add("$path|$mode")
            saveTryUmounts(context, currentUmounts)

            // 如果开启了开机自启动，更新启动脚本
            if (isAutoStartEnabled(context)) {
                createStartupScript(context)
            }
        }
        return success
    }

    /**
     * 移除尝试卸载
     */
    suspend fun removeTryUmount(context: Context, umountEntry: String): Boolean {
        val currentUmounts = getTryUmounts(context).toMutableSet()
        currentUmounts.remove(umountEntry)
        saveTryUmounts(context, currentUmounts)

        // 如果开启了开机自启动，更新启动脚本
        if (isAutoStartEnabled(context)) {
            createStartupScript(context)
        }

        val parts = umountEntry.split("|")
        val path = if (parts.isNotEmpty()) parts[0] else umountEntry
        withContext(Dispatchers.Main) {
            Toast.makeText(context, "已移除尝试卸载: $path", Toast.LENGTH_SHORT).show()
        }
        return true
    }

    /**
     * 运行尝试卸载
     */
    suspend fun runTryUmount(context: Context): Boolean {
        return executeSusfsCommand(context, "run_try_umount")
    }

    /**
     * 设置Android Data路径
     */
    suspend fun setAndroidDataPath(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "set_android_data_root_path '$path'")
        if (success) {
            saveAndroidDataPath(context, path)

            // 如果开启了开机自启动，更新启动脚本
            if (isAutoStartEnabled(context)) {
                createStartupScript(context)
            }
        }
        return success
    }

    /**
     * 设置SD卡路径
     */
    suspend fun setSdcardPath(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "set_sdcard_root_path '$path'")
        if (success) {
            saveSdcardPath(context, path)

            // 如果开启了开机自启动，更新启动脚本
            if (isAutoStartEnabled(context)) {
                createStartupScript(context)
            }
        }
        return success
    }

    /**
     * 执行SuSFS命令设置uname和构建时间
     */
    suspend fun setUname(context: Context, unameValue: String, buildTimeValue: String): Boolean = withContext(Dispatchers.IO) {
        try {
            // 首先复制二进制文件到/data/adb/ksu/bin/
            val binaryPath = copyBinaryFromAssets(context)
            if (binaryPath == null) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        context,
                        context.getString(R.string.susfs_binary_not_found),
                        Toast.LENGTH_SHORT
                    ).show()
                }
                return@withContext false
            }

            // 构建命令
            val command = "$binaryPath set_uname '$unameValue' '$buildTimeValue'"

            // 执行命令
            val result = getRootShell().newJob().add(command).exec()

            if (result.isSuccess) {
                // 保存配置
                saveUnameValue(context, unameValue)
                saveBuildTimeValue(context, buildTimeValue)
                saveLastAppliedValue(context, unameValue)
                saveLastAppliedBuildTime(context, buildTimeValue)
                setEnabled(context, true)

                // 如果开启了开机自启动，更新启动脚本
                if (isAutoStartEnabled(context)) {
                    createStartupScript(context)
                }

                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        context,
                        context.getString(R.string.susfs_uname_set_success, unameValue, buildTimeValue),
                        Toast.LENGTH_SHORT
                    ).show()
                }
                true
            } else {
                withContext(Dispatchers.Main) {
                    val errorOutput = result.out.joinToString("\n") + "\n" + result.err.joinToString("\n")
                    Toast.makeText(
                        context,
                        context.getString(R.string.susfs_command_failed) + "\n$errorOutput",
                        Toast.LENGTH_LONG
                    ).show()
                }
                false
            }
        } catch (e: Exception) {
            e.printStackTrace()
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    context,
                    context.getString(R.string.susfs_command_error, e.message ?: "Unknown error"),
                    Toast.LENGTH_SHORT
                ).show()
            }
            false
        }
    }

    /**
     * 检查是否有任何配置可以启用开机自启动
     */
    fun hasConfigurationForAutoStart(context: Context): Boolean {
        val unameValue = getUnameValue(context)
        val buildTimeValue = getBuildTimeValue(context)
        val susPaths = getSusPaths(context)
        val susMounts = getSusMounts(context)
        val tryUmounts = getTryUmounts(context)
        val enabledFeatures = runBlocking {
            getEnabledFeatures(context)
        }

        return (unameValue != DEFAULT_UNAME) ||
                (buildTimeValue != DEFAULT_BUILD_TIME) ||
                susPaths.isNotEmpty() ||
                susMounts.isNotEmpty() ||
                tryUmounts.isNotEmpty() ||
                enabledFeatures.any { it.isEnabled }
    }

    /**
     * 配置开机自启动
     */
    suspend fun configureAutoStart(context: Context, enabled: Boolean): Boolean = withContext(Dispatchers.IO) {
        try {
            if (enabled) {
                // 启用开机自启动
                if (!hasConfigurationForAutoStart(context)) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.susfs_no_config_to_autostart),
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                    return@withContext false
                }

                // 确保二进制文件存在于目标位置
                val shell = getRootShell()
                val targetPath = getSuSFSTargetPath()
                val checkResult = shell.newJob().add("test -f '$targetPath'").exec()

                if (!checkResult.isSuccess) {
                    // 如果不存在，尝试复制
                    val binaryPath = copyBinaryFromAssets(context)
                    if (binaryPath == null) {
                        withContext(Dispatchers.Main) {
                            Toast.makeText(
                                context,
                                context.getString(R.string.susfs_binary_not_found),
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                        return@withContext false
                    }
                }

                val success = createStartupScript(context)
                if (success) {
                    setAutoStartEnabled(context, true)
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.susfs_autostart_enabled),
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.susfs_autostart_enable_failed),
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
                success
            } else {
                // 禁用开机自启动
                val success = removeStartupScript()
                if (success) {
                    setAutoStartEnabled(context, false)
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.susfs_autostart_disabled),
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.susfs_autostart_disable_failed),
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
                success
            }
        } catch (e: Exception) {
            e.printStackTrace()
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    context,
                    context.getString(R.string.susfs_autostart_error, e.message ?: "Unknown error"),
                    Toast.LENGTH_SHORT
                ).show()
            }
            false
        }
    }

    /**
     * 重置为默认值
     */
    suspend fun resetToDefault(context: Context): Boolean {
        val success = setUname(context, DEFAULT_UNAME, DEFAULT_BUILD_TIME)
        if (success) {
            // 重置时清除最后应用的值
            saveLastAppliedValue(context, DEFAULT_UNAME)
            saveLastAppliedBuildTime(context, DEFAULT_BUILD_TIME)
            // 如果开启了开机自启动，需要禁用它
            if (isAutoStartEnabled(context)) {
                configureAutoStart(context, false)
            }
        }
        return success
    }

    /**
     * 检查ksu_susfs文件是否存在于assets中
     */
    fun isBinaryAvailable(context: Context): Boolean {
        return try {
            val binaryName = getSuSFSBinaryName()
            context.assets.open(binaryName).use { true }
        } catch (_: IOException) {
            false
        }
    }
}