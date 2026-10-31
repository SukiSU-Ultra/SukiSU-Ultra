package com.sukisu.ultra.ai.host

import com.sukisu.ultra.ai.api.*

import android.content.Context
import android.net.Uri
import com.sukisu.ultra.data.repository.ExtensionRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.screen.extensions.ExtensionCatalog
import com.sukisu.ultra.ui.screen.extensions.ExtensionEntry
import com.sukisu.ultra.ui.screen.extensions.VersionSpoofRepository
import com.sukisu.ultra.ui.screen.kpm.KpmOperations
import com.sukisu.ultra.ui.screen.kpm.extractModuleName
import com.sukisu.ultra.ui.screen.kpm.isSafeKpmModuleId
import com.sukisu.ultra.ui.screen.kpm.isValidKpmFile
import com.sukisu.ultra.ui.screen.settings.tools.readCurrentCpuIdentity
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.util.addDynamicManager
import com.sukisu.ultra.ui.util.addUmountPath
import com.sukisu.ultra.ui.util.applyUmountConfigToKernel
import com.sukisu.ultra.ui.util.clearCustomUmountPaths
import com.sukisu.ultra.ui.util.controlKpmModule
import com.sukisu.ultra.ui.util.getDynamicManagerSignature
import com.sukisu.ultra.ui.util.getDynamicManagers
import com.sukisu.ultra.ui.util.getKpmModuleCount
import com.sukisu.ultra.ui.util.getKpmModuleInfo
import com.sukisu.ultra.ui.util.getKpmVersion
import com.sukisu.ultra.ui.util.getSuSFSFeatures
import com.sukisu.ultra.ui.util.getSuSFSImplementation
import com.sukisu.ultra.ui.util.getSuSFSStatus
import com.sukisu.ultra.ui.util.getSuSFSVariant
import com.sukisu.ultra.ui.util.getSuSFSVersion
import com.sukisu.ultra.ui.util.listKpmModules
import com.sukisu.ultra.ui.util.listUmountPaths
import com.sukisu.ultra.ui.util.loadKpmModule
import com.sukisu.ultra.ui.util.removeDynamicManager
import com.sukisu.ultra.ui.util.removeUmountPath
import com.sukisu.ultra.ui.util.saveUmountConfig
import com.sukisu.ultra.ui.util.setDynamicManagersEnabled
import com.sukisu.ultra.ui.util.spoofCpu
import com.sukisu.ultra.ui.util.unloadKpmModule
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.json.JSONObject

/**
 * Extension-screen operations exposed to the assistant. Only features that are
 * already reachable from the Extensions screen are modelled here; general
 * settings, superuser rules, installation/flashing and arbitrary shell commands
 * are not part of this surface.
 */
object AiExtensionsController : AiExtensionsService {

    override suspend fun readOverview(): String = withContext(Dispatchers.IO) {
        val extensions = runCatching { ExtensionRepositoryImpl().probeAll() }.getOrElse { emptyList() }
        val kpmVersion = runCatching { getKpmVersion() }.getOrDefault("")
        val kpmAvailable = kpmVersion.isNotBlank() &&
            !kpmVersion.contains("error", true) &&
            !kpmVersion.contains("unsupported", true)
        val kpmCount = if (kpmAvailable) {
            runCatching { getKpmModuleCount() }.getOrDefault(0)
        } else {
            0
        }
        val kpmModules = if (kpmAvailable) {
            runCatching { listKpmModules() }.getOrDefault("")
        } else {
            ""
        }
        val susfsStatus = runCatching { getSuSFSStatus() }.getOrDefault("")
        val susfsAvailable = susfsStatus.equals("true", ignoreCase = true)
        val susfsConfig = if (susfsAvailable) {
            runCatching { SuSFSManager.getCurrentModuleConfig() }.getOrNull()
        } else {
            null
        }
        val susfsFeatures = if (susfsAvailable) {
            runCatching { getSuSFSFeatures() }.getOrDefault("")
        } else {
            ""
        }
        val versionSpoof = runCatching {
            val current = JSONObject(VersionSpoofRepository.command("get"))
            val probe = VersionSpoofRepository.probeWarning()
            buildJsonObject {
                put("supported", probe.supported)
                put("warning_hidden", probe.warningHidden)
                put("is_spoofed", probe.isSpoofed)
                put("version", current.optLong("version").toString())
                put("full", current.optString("full"))
                put("uapi", current.optLong("uapi").toString())
                put("default_version", current.optLong("defaultVersion").toString())
                put("default_full", current.optString("defaultFull"))
                put("default_uapi", current.optLong("defaultUapi").toString())
            }
        }.getOrNull()
        val cpuInfo = runCatching { readCurrentCpuIdentity() }.getOrNull()
        val umountPaths = runCatching { listUmountPaths() }.getOrNull()
        val dynamicManagers = runCatching { getDynamicManagers() }.getOrNull()

        buildJsonObject {
            put("extensions", buildJsonArray {
                extensions.forEach { state ->
                    add(buildJsonObject {
                        put("name", state.wireName)
                        put("id", state.id)
                        put("supported", state.supported)
                        put("enabled", state.enabled)
                        put("value", state.value)
                        put("sticky", state.sticky)
                        put("persistent", state.persistent)
                        put("forced", state.forced)
                        put("managed", state.managed)
                        put("needs_reboot", state.needsReboot)
                        put("user_toggleable", state.userToggleable)
                        put(
                            "generic_toggle",
                            ExtensionCatalog.descriptorFor(state.wireName, state.id).entry is ExtensionEntry.Generic,
                        )
                    })
                }
            })
            if (cpuInfo != null) {
                put("cpu_spoof", buildJsonObject {
                    put("available", true)
                    put("current_midr", cpuInfo.midrHex)
                    put("current_bogomips", cpuInfo.bogomips)
                    put("current_hwcap", cpuInfo.hwcap)
                    put("current_hwcap2", cpuInfo.hwcap2)
                    put("core_count", cpuInfo.coreCount)
                })
            } else {
                put("cpu_spoof", buildJsonObject {
                    put("available", false)
                    put("reason", "Could not read /proc/cpuinfo")
                })
            }
            put("umount_paths", buildJsonObject {
                if (umountPaths != null) {
                    put("available", true)
                    put("list", umountPaths)
                } else {
                    put("available", false)
                    put("reason", "The umount extension is unavailable.")
                }
            })
            put("dynamic_managers", buildJsonObject {
                if (dynamicManagers != null) {
                    put("available", true)
                    put("enabled", dynamicManagers.enabled)
                    putJsonArray("entries") {
                        dynamicManagers.entries.forEach { entry ->
                            add(buildJsonObject {
                                put("package", entry.packageName)
                                put("uid", entry.uid)
                                put("cert_size", entry.certSize)
                                put("hash", entry.hash.take(16))
                            })
                        }
                    }
                } else {
                    put("available", false)
                    put("reason", "The dynamic manager extension is unavailable.")
                }
            })
            put("version_spoof", versionSpoof ?: buildJsonObject {
                put("supported", false)
                put("reason", "The version spoof extension is unavailable.")
            })
            put("kpm", buildJsonObject {
                put("version", kpmVersion)
                put("loaded_count", kpmCount)
                put("available", kpmAvailable)
                if (kpmModules.isNotBlank()) put("modules", kpmModules)
            })
            put("susfs", buildJsonObject {
                put("status", susfsStatus)
                put("available", susfsAvailable)
                if (susfsAvailable) {
                    put("version", runCatching { getSuSFSVersion() }.getOrDefault(""))
                    put("variant", runCatching { getSuSFSVariant() }.getOrDefault(""))
                    put("implementation", runCatching { getSuSFSImplementation() }.getOrDefault(""))
                    put("features", susfsFeatures)
                    put(
                        "auto_start",
                        runCatching { SuSFSManager.isAutoStartEnabled() }.getOrDefault(false),
                    )
                    put(
                        "slot",
                        runCatching { SuSFSManager.getCurrentActiveSlot() }.getOrDefault(""),
                    )
                    susfsConfig?.let { config ->
                        putJsonObject("config") {
                            put("uname", config.unameValue)
                            put("build_time", config.buildTimeValue)
                            put("execute_in_post_fs_data", config.executeInPostFsData)
                            put("auto_start_enabled", config.autoStartEnabled)
                            put("sus_paths", config.susPaths.joinToString("\n"))
                            put("sus_loop_paths", config.susLoopPaths.joinToString("\n"))
                            put("sus_maps", config.susMaps.joinToString("\n"))
                            put("priority_uid_filter", config.priorityUidFilter.joinToString(","))
                            put("kstat_configs", config.kstatConfigs.joinToString("\n"))
                            put("add_kstat_paths", config.addKstatPaths.joinToString("\n"))
                            put("hide_sus_mounts_for_all", config.hideSusMountsForAllProcs)
                            put("enable_hide_bl", config.enableHideBl)
                            put("enable_cleanup_residue", config.enableCleanupResidue)
                            put("enable_avc_log_spoofing", config.enableAvcLogSpoofing)
                            put("enable_log", config.enableLog)
                            put("cmdline_or_bootconfig_path", config.cmdlineOrBootconfigPath)
                        }
                    }
                }
            })
        }.toString()
    }

    /**
     * Declares which extension commands are currently available. The model is
     * instructed to consult this before acting so unsupported features fail
     * with a clear reason instead of a raw shell error.
     */
    override suspend fun capabilities(): String = withContext(Dispatchers.IO) {
        val extensions = runCatching { ExtensionRepositoryImpl().probeAll() }.getOrElse { emptyList() }
        val kpmVersion = runCatching { getKpmVersion() }.getOrDefault("")
        val kpmAvailable = kpmVersion.isNotBlank() &&
            !kpmVersion.contains("error", true) &&
            !kpmVersion.contains("unsupported", true)
        val dynamicAvailable = runCatching { getDynamicManagers() }.isSuccess
        val susfsAvailable = runCatching { getSuSFSStatus() }.getOrDefault("")
            .equals("true", ignoreCase = true)
        val versionSpoofAvailable = runCatching { VersionSpoofRepository.probeWarning() }
            .getOrNull()?.supported == true
        val cpuAvailable = runCatching { readCurrentCpuIdentity() }.getOrNull() != null

        buildJsonObject {
            putJsonArray("features") {
                fun feature(id: String, available: Boolean, reason: String = "") {
                    add(buildJsonObject {
                        put("id", id)
                        put("available", available)
                        if (!available) put("reason", reason.ifBlank { "Not supported on this kernel." })
                    })
                }
                feature("sticky_toggles", extensions.any { it.userToggleable })
                feature("kpm", kpmAvailable, "KPM is not supported by this kernel.")
                feature("version_spoof", versionSpoofAvailable)
                feature("cpu_spoof", cpuAvailable)
                feature("umount_paths", extensions.any { it.wireName == "umount_paths" && it.supported })
                feature("dynamic_manager", dynamicAvailable)
                feature("susfs_runtime", susfsAvailable, "SuSFS is not supported by this kernel.")
                feature("susfs_config", susfsAvailable, "SuSFS is not supported by this kernel.")
            }
            putJsonArray("commands") {
                listOf(
                    "extension_set", "version_spoof_set", "cpu_spoof_set", "umount_action",
                    "dynamic_manager_action", "kpm_action", "susfs_set", "susfs_config_set",
                ).forEach { add(it) }
            }
            put("kpm_version", kpmVersion)
        }.toString()
    }

    override suspend fun toggleExtension(name: String, enabled: Boolean): String = withContext(Dispatchers.IO) {
        val states = ExtensionRepositoryImpl().probeAll()
        val state = states.firstOrNull {
            it.wireName.equals(name, ignoreCase = true) || it.id.toString() == name.trim()
        } ?: throw IllegalArgumentException(
            "Unknown extension '$name'. Available: ${states.joinToString { it.wireName }}"
        )
        require(ExtensionCatalog.descriptorFor(state.wireName, state.id).entry is ExtensionEntry.Generic) {
            "Extension '${state.wireName}' has a dedicated screen and cannot be toggled as a generic sticky extension."
        }
        require(state.supported) { "Extension '${state.wireName}' is not supported by this kernel" }
        require(state.userToggleable) {
            "Extension '${state.wireName}' is ${if (state.forced) "forced" else if (state.managed) "managed" else "not toggleable"} by the user"
        }
        ExtensionRepositoryImpl().setEnabled(state.id, enabled).getOrThrow()
        val updated = ExtensionRepositoryImpl().probeAll().firstOrNull { it.id == state.id }
        "Extension '${state.wireName}' is now ${if (updated?.enabled == true) "enabled" else "disabled"}." +
            if (state.needsReboot) " A reboot is required." else ""
    }

    override suspend fun setVersionSpoof(
        version: String?,
        full: String?,
        uapi: String?,
        hideWarning: Boolean?,
        reset: Boolean,
    ): String = withContext(Dispatchers.IO) {
        check(VersionSpoofRepository.probeWarning().supported) {
            "Version spoof is not supported by this kernel."
        }
        if (reset) {
            VersionSpoofRepository.command("reset")
        } else {
            val current = JSONObject(VersionSpoofRepository.command("get"))
            val newVersion = version?.trim()?.takeIf { it.isNotEmpty() }
                ?: current.optLong("version").toString()
            val newFull = full?.trim()?.takeIf { it.isNotEmpty() }
                ?: current.optString("full")
            val newUapi = uapi?.trim()?.takeIf { it.isNotEmpty() }
                ?: current.optLong("uapi").toString()

            require(validVersionNumber(newVersion)) {
                "version must be a number between 0 and 4294967295"
            }
            require(validVersionNumber(newUapi)) {
                "uapi must be a number between 0 and 4294967295"
            }
            require(newFull.toByteArray(Charsets.UTF_8).size <= 254 && '\u0000' !in newFull) {
                "full must be at most 254 UTF-8 bytes and contain no NUL"
            }

            val args = buildString {
                append("set --acknowledge-compatibility")
                append(" --version ${VersionSpoofRepository.quote(newVersion)}")
                append(" --uapi ${VersionSpoofRepository.quote(newUapi)}")
                if (full != null) append(" --full=${VersionSpoofRepository.quote(newFull)}")
            }
            VersionSpoofRepository.command(args)
        }
        if (hideWarning != null) VersionSpoofRepository.setWarningHidden(hideWarning)
        "Version spoof updated: ${VersionSpoofRepository.command("get")}"
    }

    override suspend fun setCpuSpoof(
        cpus: List<Int>,
        midr: String,
        bogomips: Int,
        hwcap: String,
        hwcap2: String,
    ): String = withContext(Dispatchers.IO) {
        ensureExtensionSupported("cpu_spoof")
        val targets = cpus.distinct().sorted()
        require(targets.isNotEmpty()) { "At least one CPU index is required" }
        require(targets.all { it in 0..63 }) { "cpu indices must be between 0 and 63" }
        require(midr.isNotBlank()) { "midr must not be empty" }
        require(HEX_PATTERN.matches(midr)) { "midr must be a hexadecimal value such as 0x410fd034" }
        require(hwcap.isBlank() || HEX_PATTERN.matches(hwcap)) { "hwcap must be hexadecimal" }
        require(hwcap2.isBlank() || HEX_PATTERN.matches(hwcap2)) { "hwcap2 must be hexadecimal" }
        val failed = targets.filterNot { spoofCpu(it, midr, bogomips, hwcap, hwcap2) }
        when {
            failed.isEmpty() -> "CPU ${targets.joinToString()} spoofed successfully."
            failed.size == targets.size -> throw IllegalStateException(
                "Kernel rejected the CPU spoof for ${targets.joinToString()}."
            )
            else -> "Spoofed ${targets.size - failed.size} of ${targets.size} CPUs; " +
                "the kernel rejected ${failed.joinToString()}."
        }
    }

    override suspend fun umount(action: String, path: String?, flags: Int): String =
        withContext(Dispatchers.IO) {
            ensureExtensionSupported("umount_paths")
            when (action.trim().lowercase().replace('-', '_')) {
                "list" -> listUmountPaths().ifBlank { "No custom umount paths." }
                "add" -> {
                    val target = requirePath(path)
                    check(addUmountPath(target, flags)) { "Failed to add $target" }
                    "Added $target.\n${listUmountPaths()}"
                }

                "remove" -> {
                    val target = requirePath(path)
                    check(removeUmountPath(target)) { "Failed to remove $target" }
                    "Removed $target.\n${listUmountPaths()}"
                }

                "clear", "clear_custom" -> {
                    check(clearCustomUmountPaths()) { "Failed to clear custom umount paths" }
                    "Cleared custom umount paths."
                }

                "save" -> {
                    check(saveUmountConfig()) { "Failed to save umount config" }
                    "Umount configuration saved."
                }

                "apply" -> {
                    check(applyUmountConfigToKernel()) { "Failed to apply umount config" }
                    "Umount configuration applied."
                }

                else -> throw IllegalArgumentException("action must be list, add, remove, clear, save or apply")
            }
        }

    override suspend fun dynamicManager(
        action: String,
        enabled: Boolean?,
        name: String?,
    ): String = withContext(Dispatchers.IO) {
            when (action.trim().lowercase().replace('-', '_')) {
                "list" -> {
                    val state = getDynamicManagers()
                    buildString {
                        appendLine("enabled=${state.enabled}")
                        if (state.entries.isEmpty()) append("no dynamic managers")
                        else state.entries.joinTo(
                            this,
                            separator = "\n",
                            prefix = "",
                        ) { "${it.packageName} uid=${it.uid} hash=${it.hash.take(16)}…" }
                    }
                }

                "set_enabled", "toggle" -> {
                    val value = enabled ?: throw IllegalArgumentException("enabled is required")
                    setDynamicManagersEnabled(value)
                    "Dynamic manager is now ${if (value) "enabled" else "disabled"}."
                }

                "add" -> {
                    val packageName = requirePackageName(name)
                    val sourceDir = runCatching {
                        ksuApp.packageManager.getApplicationInfo(packageName, 0).sourceDir
                    }.getOrElse {
                        throw IllegalArgumentException("Package '$packageName' is not installed.")
                    }
                    val signature = getDynamicManagerSignature(sourceDir)
                    addDynamicManager(packageName, signature)
                    "Added $packageName as a dynamic manager (${signature.hash.take(16)}…)."
                }

                "remove" -> {
                    val packageName = requirePackageName(name)
                    removeDynamicManager(packageName)
                    "Removed $packageName from the dynamic manager list."
                }

                else -> throw IllegalArgumentException(
                    "action must be list, set_enabled, add or remove"
                )
            }
        }

    override suspend fun kpm(
        action: String,
        name: String?,
        path: String?,
        args: String?,
        embed: Boolean,
    ): String = withContext(Dispatchers.IO) {
        ensureKpmAvailable()
        when (action.trim().lowercase().replace('-', '_')) {
            "list" -> listKpmModules().ifBlank { "No KPM modules loaded." }
            "info" -> getKpmModuleInfo(requireModuleName(name))
            "control" -> {
                val code = controlKpmModule(requireModuleName(name), args)
                "KPM control returned $code."
            }

            "unload" -> {
                val module = requireModuleName(name)
                check(unloadKpmModule(module)) { "Failed to unload $module" }
                "Unloaded $module."
            }

            "load" -> {
                val target = requireKpmFile(path)
                val moduleName = extractModuleName(target)
                    ?: throw IllegalArgumentException("Cannot read the module name from ${target.name}")
                require(isSafeKpmModuleId(moduleName)) { "Unsafe module name '$moduleName'" }
                check(loadKpmModule(target.absolutePath, args)) { "Failed to load $moduleName" }
                "Loaded $moduleName."
            }

            "install" -> {
                val target = requireKpmFile(path)
                val moduleName = name?.trim()?.takeIf { it.isNotEmpty() }
                    ?: extractModuleName(target)
                    ?: throw IllegalArgumentException("Cannot read the module name from ${target.name}")
                KpmOperations.install(ksuApp, target, moduleName, embed).getOrThrow()
                "Installed and loaded $moduleName" + if (embed) " (kept in /data/adb/kpm)." else "."
            }

            "uninstall" -> {
                val moduleName = requireModuleName(name)
                KpmOperations.uninstall(ksuApp, moduleName).getOrThrow()
                "Unloaded $moduleName and removed its boot-time copy."
            }

            else -> throw IllegalArgumentException(
                "action must be list, info, control, load, install or uninstall"
            )
        }
    }

    override suspend fun susfs(action: String, enabled: Boolean?): String = withContext(Dispatchers.IO) {
        check(getSuSFSStatus().equals("true", ignoreCase = true)) {
            "SuSFS is not supported by this kernel."
        }
        val toggle = enabled ?: throw IllegalArgumentException("enabled is required")
        val (ok, label, reboot) = when (action.trim().lowercase().replace('-', '_')) {
            "enable_log" -> Triple(SuSFSManager.setEnableLog(ksuApp, toggle), "SuSFS log", false)
            "avc_log_spoofing" -> Triple(
                SuSFSManager.setEnableAvcLogSpoofing(ksuApp, toggle),
                "AVC log spoofing",
                false,
            )

            "hide_sus_mounts_for_all" -> Triple(
                SuSFSManager.setHideSusMountsForAllProcs(ksuApp, toggle),
                "hide sus mounts for non-su processes",
                false,
            )

            "hide_bl" -> {
                val ok = runCatching { SuSFSManager.saveEnableHideBl(toggle) }.isSuccess
                Triple(ok, "hide bootloader status", true)
            }

            "cleanup_residue" -> {
                val ok = runCatching { SuSFSManager.saveEnableCleanupResidue(toggle) }.isSuccess
                Triple(ok, "cleanup residue", true)
            }

            else -> throw IllegalArgumentException(
                "action must be enable_log, avc_log_spoofing, hide_sus_mounts_for_all, hide_bl or cleanup_residue"
            )
        }
        check(ok) { "SuSFS rejected the change" }
        val autoStart = runCatching { SuSFSManager.isAutoStartEnabled() }.getOrDefault(false)
        val scheduled = if (autoStart) {
            runCatching { SuSFSManager.configureAutoStart(ksuApp, true) }.getOrDefault(false)
        } else {
            false
        }
        buildString {
            append(label).append(' ').append(if (toggle) "enabled" else "disabled").append('.')
            when {
                !reboot -> if (autoStart && !scheduled) {
                    append(" The change was applied, but the auto-start module could not be refreshed.")
                } else if (!autoStart) {
                    append(" Auto-start is not enabled, so the change will not persist after a reboot.")
                } else {
                    append(" Auto-start module refreshed.")
                }

                autoStart && scheduled -> append(" A reboot is required.")
                autoStart && !scheduled ->
                    append(" Saved, but the auto-start module could not be refreshed; a reboot may not apply it.")

                else -> append(" Auto-start is not enabled, so this boot-time option will not apply after a reboot.")
            }
        }
    }

    override suspend fun susfsConfigRead(): String = AiSusfsController.read()

    override suspend fun susfsConfigSet(
        action: String,
        enabled: Boolean?,
        uname: String?,
        buildTime: String?,
        path: String?,
        newPath: String?,
        packageName: String?,
        oldConfig: String?,
        configFields: String?,
        packages: List<String>,
        fileUri: Uri?,
    ): String = AiSusfsController.set(
        action = action,
        enabled = enabled,
        uname = uname,
        buildTime = buildTime,
        path = path,
        newPath = newPath,
        packageName = packageName,
        oldConfig = oldConfig,
        configFields = configFields,
        packages = packages,
        fileUri = fileUri,
    )

    private suspend fun ensureExtensionSupported(wireName: String) {
        val states = runCatching { ExtensionRepositoryImpl().probeAll() }.getOrElse { emptyList() }
        val state = states.firstOrNull { it.wireName == wireName }
        check(state != null && state.supported) {
            "Extension '$wireName' is not supported by this kernel."
        }
    }

    private suspend fun ensureKpmAvailable() {
        val version = runCatching { getKpmVersion() }.getOrDefault("")
        check(
            version.isNotBlank() &&
                !version.contains("unsupported", true) &&
                !version.contains("error", true)
        ) { "KPM is not supported by this kernel." }
    }

    private fun requirePackageName(name: String?): String {
        val trimmed = name?.trim().orEmpty()
        require(trimmed.isNotEmpty()) { "package name is required" }
        require(PACKAGE_PATTERN.matches(trimmed)) { "Invalid package name '$trimmed'" }
        return trimmed
    }

    /**
     * KPM files may only come from the app cache (user-picked/staged) or the
     * boot-time KPM directory. This prevents the model from loading arbitrary
     * ELF files by path.
     */
    private fun requireKpmFile(path: String?): File {
        val raw = path?.trim().orEmpty()
        require(raw.isNotEmpty()) { "path is required" }
        val target = File(raw).canonicalFile
        require(target.isFile) { "KPM file not found: ${target.path}" }
        val allowed = listOf(
            ksuApp.cacheDir.canonicalFile,
            File("/data/adb/kpm").canonicalFile,
        ).any { root ->
            target.path == root.path || target.path.startsWith(root.path + File.separator)
        }
        require(allowed) {
            "KPM files must be selected through the file picker or stored in /data/adb/kpm."
        }
        require(isValidKpmFile(target)) { "Not a valid KPM/ELF file" }
        return target
    }

    private fun requirePath(path: String?): String {
        val trimmed = path?.trim().orEmpty()
        require(trimmed.startsWith("/")) { "path must be absolute" }
        require(trimmed.length <= 4096) { "path is too long" }
        require(trimmed.none { it == '\n' || it == '\r' || it == '\u0000' }) { "path contains invalid characters" }
        return trimmed
    }

    private fun requireModuleName(name: String?): String {
        val trimmed = name?.trim().orEmpty()
        require(isSafeKpmModuleId(trimmed)) { "A safe KPM module name is required" }
        return trimmed
    }

    private fun validVersionNumber(value: String): Boolean =
        value.isEmpty() || (value.all { it in '0'..'9' } &&
            value.toULongOrNull()?.let { it <= 4_294_967_295UL } == true)

    private val HEX_PATTERN = Regex("^(0[xX])?[0-9a-fA-F]{1,16}$")
    private val PACKAGE_PATTERN = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")
}
