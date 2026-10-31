package com.sukisu.ultra.ai.host

import com.sukisu.ultra.ai.api.*

import android.net.Uri
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSBackupManager
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSCommands
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSConfig
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSPathManager
import com.sukisu.ultra.ui.util.getSuSFSStatus
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

/**
 * Full SuSFS configuration surface, matching the eight tabs and the backup /
 * restore flow of the SuSFS screen. Every write is mirrored in the saved
 * module config and, when auto-start is enabled, the boot module is refreshed.
 */
object AiSusfsController {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    suspend fun read(): String = withContext(Dispatchers.IO) {
        ensureAvailable()
        val config = SuSFSManager.getCurrentModuleConfig()
        val enabledFeatures = runCatching { SuSFSManager.getEnabledFeatures(ksuApp) }.getOrElse { emptyList() }
        val slots = runCatching { SuSFSManager.getCurrentSlotInfo() }.getOrElse { emptyList() }
        buildJsonObject {
            put("uname", config.unameValue)
            put("build_time", config.buildTimeValue)
            put("execute_in_post_fs_data", config.executeInPostFsData)
            put("auto_start", config.autoStartEnabled)
            put("sus_paths", buildJsonArray { config.susPaths.sorted().forEach { add(it) } })
            put("sus_loop_paths", buildJsonArray { config.susLoopPaths.sorted().forEach { add(it) } })
            put("sus_maps", buildJsonArray { config.susMaps.sorted().forEach { add(it) } })
            put("priority_uid_filter", config.priorityUidFilter.sorted().joinToString(","))
            put("kstat_configs", buildJsonArray { config.kstatConfigs.sorted().forEach { add(it) } })
            put("add_kstat_paths", buildJsonArray { config.addKstatPaths.sorted().forEach { add(it) } })
            put("hide_sus_mounts_for_all", config.hideSusMountsForAllProcs)
            put("enable_hide_bl", config.enableHideBl)
            put("enable_cleanup_residue", config.enableCleanupResidue)
            put("enable_avc_log_spoofing", config.enableAvcLogSpoofing)
            put("enable_log", config.enableLog)
            put("cmdline_or_bootconfig_path", config.cmdlineOrBootconfigPath)
            put("runtime", buildJsonObject {
                put("version", runCatching { com.sukisu.ultra.ui.util.getSuSFSVersion() }.getOrDefault(""))
                put("variant", runCatching { com.sukisu.ultra.ui.util.getSuSFSVariant() }.getOrDefault(""))
                put(
                    "implementation",
                    runCatching { com.sukisu.ultra.ui.util.getSuSFSImplementation() }.getOrDefault(""),
                )
                put("active_slot", runCatching { SuSFSManager.getCurrentActiveSlot() }.getOrDefault(""))
            })
            put("enabled_features", buildJsonArray {
                enabledFeatures.forEach { feature ->
                    add(buildJsonObject {
                        put("name", feature.name)
                        put("enabled", feature.isEnabled)
                    })
                }
            })
            put("slots", buildJsonArray {
                slots.forEach { slot ->
                    add(buildJsonObject {
                        put("name", slot.slotName)
                        put("uname", slot.uname)
                        put("build_time", slot.buildTime)
                    })
                }
            })
        }.toString()
    }

    suspend fun set(
        action: String,
        enabled: Boolean? = null,
        uname: String? = null,
        buildTime: String? = null,
        path: String? = null,
        newPath: String? = null,
        packageName: String? = null,
        oldConfig: String? = null,
        configFields: String? = null,
        packages: List<String> = emptyList(),
        fileUri: Uri? = null,
    ): String = withContext(Dispatchers.IO) {
        ensureAvailable()
        when (val normalized = action.trim().lowercase().replace('-', '_')) {
            "enable_log", "avc_log_spoofing", "hide_sus_mounts_for_all", "hide_bl", "cleanup_residue" ->
                AiExtensionsController.susfs(normalized, enabled)

            "set_uname" -> {
                val current = SuSFSManager.getCurrentModuleConfig()
                val newUname = uname?.trim()?.takeIf { it.isNotEmpty() } ?: current.unameValue
                val newBuildTime = buildTime?.trim()?.takeIf { it.isNotEmpty() } ?: current.buildTimeValue
                require(newUname.length <= 254 && '\u0000' !in newUname) { "uname is too long or contains NUL" }
                require(newBuildTime.length <= 254 && '\u0000' !in newBuildTime) {
                    "build_time is too long or contains NUL"
                }
                check(SuSFSManager.setUname(ksuApp, newUname, newBuildTime)) {
                    "SuSFS rejected the uname/build-time change."
                }
                "SuSFS uname set to '$newUname' with build time '$newBuildTime'." + autoStartNote()
            }

            "set_execute_in_post_fs_data" -> {
                val value = requireEnabled(enabled)
                SuSFSManager.saveExecuteInPostFsData(value)
                "SuSFS post-fs-data execution ${onOff(value)}." + autoStartNote()
            }

            "set_auto_start" -> {
                val value = requireEnabled(enabled)
                check(SuSFSManager.configureAutoStart(ksuApp, value)) {
                    "Could not update the SuSFS auto-start module."
                }
                "SuSFS auto-start ${onOff(value)}."
            }

            "apply_basic" -> {
                val current = SuSFSManager.getCurrentModuleConfig()
                val newUname = uname?.trim()?.takeIf { it.isNotEmpty() } ?: current.unameValue
                val newBuildTime = buildTime?.trim()?.takeIf { it.isNotEmpty() } ?: current.buildTimeValue
                check(SuSFSManager.setUname(ksuApp, newUname, newBuildTime)) {
                    "SuSFS rejected the uname/build-time change."
                }
                SuSFSManager.saveExecuteInPostFsData(current.executeInPostFsData)
                "SuSFS basic settings applied." + autoStartNote()
            }

            "reset_all" -> {
                check(SuSFSManager.resetToDefault(ksuApp)) { "SuSFS rejected the reset." }
                "SuSFS configuration reset to defaults."
            }

            "add_sus_path" -> {
                val target = requireAbsolutePath(path)
                check(SuSFSManager.addSusPath(ksuApp, target)) { "SuSFS rejected $target." }
                "Added SUS path $target." + autoStartNote()
            }

            "remove_sus_path" -> {
                val target = requireAbsolutePath(path)
                check(SuSFSManager.removeSusPath(target)) { "Failed to remove $target." }
                "Removed SUS path $target." + autoStartNote()
            }

            "edit_sus_path" -> {
                val old = requireAbsolutePath(path)
                val new = requireAbsolutePath(newPath)
                check(SuSFSManager.editSusPath(ksuApp, old, new)) { "Failed to edit $old." }
                "Renamed SUS path $old to $new." + autoStartNote()
            }

            "add_sus_loop_path" -> {
                val target = requireAbsolutePath(path)
                check(SuSFSManager.addSusLoopPath(ksuApp, target)) { "SuSFS rejected $target." }
                "Added SUS loop path $target." + autoStartNote()
            }

            "remove_sus_loop_path" -> {
                val target = requireAbsolutePath(path)
                check(SuSFSManager.removeSusLoopPath(target)) { "Failed to remove $target." }
                "Removed SUS loop path $target." + autoStartNote()
            }

            "edit_sus_loop_path" -> {
                val old = requireAbsolutePath(path)
                val new = requireAbsolutePath(newPath)
                check(SuSFSManager.editSusLoopPath(ksuApp, old, new)) { "Failed to edit $old." }
                "Renamed SUS loop path $old to $new." + autoStartNote()
            }

            "add_sus_map" -> {
                val target = requireMap(path)
                check(SuSFSManager.addSusMap(ksuApp, target)) { "SuSFS rejected $target." }
                "Added SUS map $target." + autoStartNote()
            }

            "remove_sus_map" -> {
                val target = requireMap(path)
                check(SuSFSManager.removeSusMap(target)) { "Failed to remove $target." }
                "Removed SUS map $target." + autoStartNote()
            }

            "edit_sus_map" -> {
                val old = requireMap(path)
                val new = requireMap(newPath)
                check(SuSFSManager.editSusMap(ksuApp, old, new)) { "Failed to edit $old." }
                "Renamed SUS map $old to $new." + autoStartNote()
            }

            "add_app_paths" -> {
                val pkg = requirePackage(packageName)
                check(SuSFSManager.addAppPaths(ksuApp, pkg)) { "Failed to add paths for $pkg." }
                "Added all path rules for $pkg." + autoStartNote()
            }

            "reset_sus_paths" -> {
                SuSFSManager.saveSusPaths(emptySet())
                "Cleared all SUS paths." + autoStartNote()
            }

            "reset_sus_loop_paths" -> {
                SuSFSManager.saveSusLoopPaths(emptySet())
                "Cleared all SUS loop paths." + autoStartNote()
            }

            "reset_sus_maps" -> {
                SuSFSManager.saveSusMaps(emptySet())
                "Cleared all SUS maps." + autoStartNote()
            }

            "add_kstat" -> {
                val target = requireAbsolutePath(path)
                check(SuSFSManager.addKstat(ksuApp, target)) { "Failed to add kstat for $target." }
                "Added dynamic kstat for $target." + autoStartNote()
            }

            "remove_add_kstat" -> {
                val target = requireAbsolutePath(path)
                check(SuSFSManager.removeAddKstat(target)) { "Failed to remove kstat for $target." }
                "Removed dynamic kstat for $target." + autoStartNote()
            }

            "edit_add_kstat" -> {
                val old = requireAbsolutePath(path)
                val new = requireAbsolutePath(newPath)
                check(SuSFSManager.editAddKstat(ksuApp, old, new)) { "Failed to edit kstat for $old." }
                "Updated dynamic kstat $old to $new." + autoStartNote()
            }

            "update_kstat" -> {
                val target = requireAbsolutePath(path)
                check(SuSFSManager.updateKstat(ksuApp, target)) { "Failed to update kstat for $target." }
                "Updated kstat values for $target." + autoStartNote()
            }

            "update_kstat_full_clone" -> {
                val target = requireAbsolutePath(path)
                check(SuSFSManager.updateKstatFullClone(ksuApp, target)) {
                    "Failed to full-clone kstat for $target."
                }
                "Full-cloned kstat values for $target." + autoStartNote()
            }

            "add_kstat_static" -> {
                val fields = parseFields(configFields)
                val target = requireAbsolutePath(fields["path"])
                val required = listOf(
                    "ino", "dev", "nlink", "size", "atime", "atime_nsec", "mtime",
                    "mtime_nsec", "ctime", "ctime_nsec", "blocks", "blksize",
                )
                required.forEach { key ->
                    require(fields[key]?.isNotBlank() == true) { "kstat field '$key' is required" }
                }
                check(
                    SuSFSManager.addKstatStatically(
                        context = ksuApp,
                        path = target,
                        ino = fields.getValue("ino"),
                        dev = fields.getValue("dev"),
                        nlink = fields.getValue("nlink"),
                        size = fields.getValue("size"),
                        atime = fields.getValue("atime"),
                        atimeNsec = fields.getValue("atime_nsec"),
                        mtime = fields.getValue("mtime"),
                        mtimeNsec = fields.getValue("mtime_nsec"),
                        ctime = fields.getValue("ctime"),
                        ctimeNsec = fields.getValue("ctime_nsec"),
                        blocks = fields.getValue("blocks"),
                        blksize = fields.getValue("blksize"),
                    )
                ) { "Failed to add static kstat for $target." }
                "Added static kstat for $target." + autoStartNote()
            }

            "remove_kstat_config" -> {
                val config = oldConfig?.trim().orEmpty()
                require(config.isNotEmpty()) { "old_config is required" }
                check(SuSFSManager.removeKstatConfig(config)) { "Failed to remove kstat config." }
                "Removed kstat config." + autoStartNote()
            }

            "edit_kstat_config" -> {
                val old = oldConfig?.trim().orEmpty()
                require(old.isNotEmpty()) { "old_config is required" }
                val fields = parseFields(configFields)
                val target = requireAbsolutePath(fields["path"])
                check(
                    SuSFSManager.editKstatConfig(
                        context = ksuApp,
                        oldConfig = old,
                        path = target,
                        ino = fields["ino"].orEmpty(),
                        dev = fields["dev"].orEmpty(),
                        nlink = fields["nlink"].orEmpty(),
                        size = fields["size"].orEmpty(),
                        atime = fields["atime"].orEmpty(),
                        atimeNsec = fields["atime_nsec"].orEmpty(),
                        mtime = fields["mtime"].orEmpty(),
                        mtimeNsec = fields["mtime_nsec"].orEmpty(),
                        ctime = fields["ctime"].orEmpty(),
                        ctimeNsec = fields["ctime_nsec"].orEmpty(),
                        blocks = fields["blocks"].orEmpty(),
                        blksize = fields["blksize"].orEmpty(),
                    )
                ) { "Failed to edit kstat config." }
                "Updated kstat config." + autoStartNote()
            }

            "reset_kstat" -> {
                SuSFSManager.saveKstatConfigs(emptySet())
                SuSFSManager.saveAddKstatPaths(emptySet())
                "Cleared all kstat configurations." + autoStartNote()
            }

            "set_priority_uid_filter" -> {
                val value = packages.map { requirePackage(it) }.distinct().sorted().joinToString(",")
                val result = SuSFSCommands.executeSusfsCommandWithOutput(
                    "set-priority-uid-filter ${SuSFSConfig.shellQuote(value.ifEmpty { "," })}"
                )
                check(result.isSuccess) {
                    result.errorOutput.ifBlank { result.output }.ifBlank { "SuSFS rejected the filter." }
                }
                check(SuSFSConfig.set(SuSFSConfig.KEY_PRIORITY_UID_FILTER, value)) {
                    "Filter applied but the configuration could not be saved."
                }
                "Priority UID filter set to: ${value.ifEmpty { "(empty)" }}." + autoStartNote()
            }

            "set_cmdline_or_bootconfig" -> {
                val uri = fileUri ?: throw IllegalArgumentException("file_uri is required")
                check(SuSFSManager.setCmdlineOrBootconfigFile(ksuApp, uri.toString())) {
                    "Failed to apply the cmdline/bootconfig file."
                }
                "Cmdline/bootconfig file applied."
            }

            "backup" -> {
                val uri = fileUri ?: throw IllegalArgumentException("file_uri is required")
                backupTo(uri)
            }

            "restore" -> {
                val uri = fileUri ?: throw IllegalArgumentException("file_uri is required")
                restoreFrom(uri)
            }

            else -> throw IllegalArgumentException(
                "Unknown SuSFS action '$action'. Use one of: enable_log, avc_log_spoofing, " +
                    "hide_sus_mounts_for_all, hide_bl, cleanup_residue, set_uname, " +
                    "set_execute_in_post_fs_data, set_auto_start, apply_basic, reset_all, " +
                    "add_sus_path, remove_sus_path, edit_sus_path, add_sus_loop_path, " +
                    "remove_sus_loop_path, edit_sus_loop_path, add_sus_map, remove_sus_map, " +
                    "edit_sus_map, add_app_paths, reset_sus_paths, reset_sus_loop_paths, " +
                    "reset_sus_maps, add_kstat, remove_add_kstat, edit_add_kstat, update_kstat, " +
                    "update_kstat_full_clone, add_kstat_static, remove_kstat_config, " +
                    "edit_kstat_config, reset_kstat, set_priority_uid_filter, " +
                    "set_cmdline_or_bootconfig, backup, restore"
            )
        }
    }

    private suspend fun ensureAvailable() {
        check(getSuSFSStatus().equals("true", ignoreCase = true)) {
            "SuSFS is not supported by this kernel."
        }
    }

    private suspend fun autoStartNote(): String =
        if (SuSFSManager.isAutoStartEnabled()) {
            if (SuSFSManager.configureAutoStart(ksuApp, true)) {
                " Auto-start module refreshed."
            } else {
                " The change was saved, but the auto-start module could not be refreshed."
            }
        } else {
            ""
        }

    private suspend fun backupTo(uri: Uri): String {
        val temp = File.createTempFile("susfs-backup-", ".susfs_backup", ksuApp.cacheDir)
        try {
            check(SuSFSManager.createBackup(ksuApp, temp.absolutePath)) { "Backup creation failed." }
            val output = ksuApp.contentResolver.openOutputStream(uri)
                ?: throw IllegalStateException("Cannot open the selected destination.")
            output.use { stream -> temp.inputStream().use { it.copyTo(stream) } }
            return "SuSFS backup exported."
        } finally {
            temp.delete()
        }
    }

    private suspend fun restoreFrom(uri: Uri): String {
        val temp = File.createTempFile("susfs-restore-", ".susfs_backup", ksuApp.cacheDir)
        try {
            val input = ksuApp.contentResolver.openInputStream(uri)
                ?: throw IllegalStateException("Cannot open the selected backup.")
            input.use { stream -> temp.outputStream().use { stream.copyTo(it) } }
            check(SuSFSManager.validateBackupFile(temp.absolutePath) != null) {
                "The selected file is not a valid SuSFS backup."
            }
            check(SuSFSManager.restoreFromBackup(ksuApp, temp.absolutePath)) { "Restore failed." }
            return "SuSFS configuration restored from the selected backup."
        } finally {
            temp.delete()
        }
    }

    private fun parseFields(raw: String?): Map<String, String> {
        val text = raw?.trim().orEmpty()
        require(text.isNotEmpty()) { "config_fields must be a JSON object" }
        val obj = runCatching { json.parseToJsonElement(text) as? JsonObject }.getOrNull()
            ?: throw IllegalArgumentException("config_fields must be a JSON object")
        return obj.entries.mapNotNull { (key, value) ->
            ((value as? JsonPrimitive)?.contentOrNull)?.let { key to it }
        }.toMap()
    }

    private fun requireEnabled(enabled: Boolean?): Boolean =
        enabled ?: throw IllegalArgumentException("enabled is required")

    private fun requireAbsolutePath(path: String?): String {
        val trimmed = path?.trim().orEmpty()
        require(trimmed.startsWith("/")) { "path must be absolute" }
        require(trimmed.length <= 4096) { "path is too long" }
        require(trimmed.none { it == '\n' || it == '\r' || it == '\u0000' || it == '\'' }) {
            "path contains characters that are not allowed"
        }
        return trimmed
    }

    private fun requireMap(path: String?): String {
        val trimmed = path?.trim().orEmpty()
        require(trimmed.isNotEmpty()) { "path is required" }
        require(trimmed.length <= 4096) { "path is too long" }
        require(trimmed.none { it == '\n' || it == '\r' || it == '\u0000' || it == '\'' }) {
            "path contains characters that are not allowed"
        }
        return trimmed
    }

    private fun requirePackage(packageName: String?): String {
        val trimmed = packageName?.trim().orEmpty()
        require(PACKAGE_PATTERN.matches(trimmed)) { "Invalid package name '$trimmed'" }
        return trimmed
    }

    private fun onOff(value: Boolean): String = if (value) "enabled" else "disabled"

    private val PACKAGE_PATTERN = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")
}
