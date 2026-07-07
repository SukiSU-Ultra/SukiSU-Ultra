package com.sukisu.ultra.ui.screen.susfs.util

import android.annotation.SuppressLint
import com.sukisu.ultra.ui.util.getKsuDaemonPath
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object SuSFSConfig {
    // Config keys (must match Rust susfs_config.rs)
    const val KEY_UNAME_VALUE = "uname_value"
    const val KEY_BUILD_TIME_VALUE = "build_time_value"
    const val KEY_AUTO_START_ENABLED = "auto_start_enabled"
    const val KEY_SUS_PATHS = "sus_paths"
    const val KEY_SUS_LOOP_PATHS = "sus_loop_paths"
    const val KEY_SUS_MAPS = "sus_maps"
    const val KEY_ENABLE_LOG = "enable_log"
    const val KEY_EXECUTE_IN_POST_FS_DATA = "execute_in_post_fs_data"
    const val KEY_KSTAT_CONFIGS = "kstat_configs"
    const val KEY_ADD_KSTAT_PATHS = "add_kstat_paths"
    const val KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS = "hide_sus_mounts_for_all_procs"
    const val KEY_ENABLE_CLEANUP_RESIDUE = "enable_cleanup_residue"
    const val KEY_ENABLE_HIDE_BL = "enable_hide_bl"
    const val KEY_ENABLE_AVC_LOG_SPOOFING = "enable_avc_log_spoofing"

    // Defaults
    const val DEFAULT_UNAME = "default"
    const val DEFAULT_BUILD_TIME = "default"

    @SuppressLint("SdCardPath")
    const val DEFAULT_ANDROID_DATA_PATH = "/sdcard/Android/data"
    const val BACKUP_FILE_EXTENSION = ".susfs_backup"
    const val MEDIA_DATA_PATH = "/data/media/0/Android/data"
    const val CGROUP_BASE_PATH = "/sys/fs/cgroup"

    private suspend fun configGet(key: String): String = withContext(Dispatchers.IO) {
        val shell = Shell.getShell()
        runCmd(shell, "${getKsuDaemonPath()} susfs config get $key").trim()
    }

    suspend fun get(key: String): String = configGet(key)

    suspend fun configSet(key: String, value: String): Boolean = withContext(Dispatchers.IO) {
        val shell = Shell.getShell()
        shell.newJob().add("${getKsuDaemonPath()} susfs config set $key ${shellQuote(value)}").exec().isSuccess
    }

    suspend fun set(key: String, value: String): Boolean = configSet(key, value)

    suspend fun configSetMulti(key: String, values: Set<String>, separator: String): Boolean = withContext(Dispatchers.IO) {
        val shell = Shell.getShell()
        val raw = values.joinToString(separator)
        shell.newJob().add("${getKsuDaemonPath()} susfs config set $key ${shellQuote(raw)}").exec().isSuccess
    }

    suspend fun setMulti(key: String, values: Set<String>, separator: String): Boolean =
        configSetMulti(key, values, separator)

    private suspend fun configGetMulti(key: String, separator: String = ";"): Set<String> = withContext(Dispatchers.IO) {
        val shell = Shell.getShell()
        val raw = runCmd(shell, "${getKsuDaemonPath()} susfs config get $key")
        if (raw.isBlank()) emptySet() else raw.split(separator).filter { it.isNotBlank() }.toSet()
    }

    suspend fun getMulti(key: String, separator: String = ";"): Set<String> = configGetMulti(key, separator)

    fun shellQuote(value: String): String = "'${value.replace("'", "'\\''")}'"

    fun isDefaultSpoofValue(value: String): Boolean = value.isBlank() || value == DEFAULT_UNAME

    private fun runCmd(shell: Shell, cmd: String): String {
        return shell.newJob().add(cmd).to(mutableListOf<String>(), null).exec().out.joinToString("\n")
    }
}
