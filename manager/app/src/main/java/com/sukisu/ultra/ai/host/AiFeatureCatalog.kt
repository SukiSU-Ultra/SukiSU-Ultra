package com.sukisu.ultra.ai.host

import com.sukisu.ultra.ai.api.*

import android.os.SystemClock
import com.sukisu.ultra.Natives
import com.sukisu.ultra.data.model.RepoModule
import com.sukisu.ultra.data.repository.ModuleRepoRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.component.bottombar.BottomBarDestination
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.screen.modulerepo.AuthorArg
import com.sukisu.ultra.ui.screen.modulerepo.RepoModuleArg
import com.sukisu.ultra.ui.screen.settings.SettingsSection
import com.sukisu.ultra.ui.util.getKpmVersion
import com.sukisu.ultra.ui.util.getSuSFSStatus
import com.sukisu.ultra.ui.util.isNetworkAvailable
import com.sukisu.ultra.ui.util.rootAvailable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Host-specific destinations understood by the manager navigator. The library
 * only sees the [AiNavigationTarget] marker and hands the object back untouched.
 */
sealed interface ManagerAiTarget : AiNavigationTarget {
    data class Tab(
        val destination: BottomBarDestination,
        val section: String? = null,
    ) : ManagerAiTarget {
        /** Concrete page index used by the main pager. */
        val pageIndex: Int get() = destination.ordinal
    }

    data class Push(val route: Route) : ManagerAiTarget
}

data class AiFeatureAvailability(
    val isManager: Boolean,
    val rootAvailable: Boolean,
    val isPreviewMode: Boolean,
    val lkmMode: Boolean?,
    val safeMode: Boolean,
    val lateLoadMode: Boolean,
    val networkAvailable: Boolean,
    val kpmAvailable: Boolean,
    val susfsAvailable: Boolean,
    val rootProbeAllowed: Boolean = true,
    val extensionReadAllowed: Boolean = true,
)

data class AiFeatureEntry(
    val id: String,
    val title: String,
    val summary: String,
    val supported: Boolean,
    val openable: Boolean,
    val reason: String = "",
    val solution: String = "",
    val target: AiNavigationTarget? = null,
    /** Call arguments required by open_app_page, e.g. package_name/uid/module_id. */
    val requires: List<String> = emptyList(),
)

/**
 * The catalogue behind the assistant's app knowledge. It covers every manager
 * page and section so the model can answer feature questions and either offer a
 * precise navigation button or explain exactly what is missing and how to fix it.
 */
object AiFeatureCatalog : AiFeatureService {

    private var cachedAt = 0L
    private var cached: AiFeatureAvailability? = null
    private var cachedRootProbe = true
    private var cachedExtensionRead = true
    private const val CACHE_MS = 15_000L

    suspend fun availability(
        allowRootProbe: Boolean = true,
        extensionReadAllowed: Boolean = true,
        force: Boolean = false,
    ): AiFeatureAvailability = withContext(Dispatchers.IO) {
        val now = SystemClock.elapsedRealtime()
        cached?.let {
            if (!force &&
                cachedRootProbe == allowRootProbe &&
                cachedExtensionRead == extensionReadAllowed &&
                now - cachedAt < CACHE_MS
            ) {
                return@withContext it
            }
        }

        val manager = runCatching { Natives.isManager }.getOrDefault(false)
        val root = allowRootProbe && runCatching { rootAvailable() }.getOrDefault(false)
        val lkm = runCatching { Natives.isLkmMode }.getOrNull()
        val safe = runCatching { Natives.isSafeMode }.getOrDefault(false)
        val late = runCatching { Natives.isLateLoadMode }.getOrDefault(false)
        val network = runCatching { isNetworkAvailable(ksuApp) }.getOrDefault(false)
        val extensionProbe = allowRootProbe && extensionReadAllowed && manager && root
        val kpm = extensionProbe && runCatching {
            val version = getKpmVersion()
            version.isNotBlank() &&
                !version.contains("unsupported", true) &&
                !version.contains("error", true)
        }.getOrDefault(false)
        val susfs = extensionProbe && runCatching {
            getSuSFSStatus().equals("true", ignoreCase = true)
        }.getOrDefault(false)

        AiFeatureAvailability(
            isManager = manager,
            rootAvailable = root,
            isPreviewMode = root && !manager,
            lkmMode = lkm,
            safeMode = safe,
            lateLoadMode = late,
            networkAvailable = network,
            kpmAvailable = kpm,
            susfsAvailable = susfs,
            rootProbeAllowed = allowRootProbe,
            extensionReadAllowed = extensionReadAllowed,
        ).also {
            cached = it
            cachedAt = now
            cachedRootProbe = allowRootProbe
            cachedExtensionRead = extensionReadAllowed
        }
    }

    override suspend fun entriesJson(
        rootProbeAllowed: Boolean,
        extensionReadAllowed: Boolean,
    ): String {
        val availability = availability(rootProbeAllowed, extensionReadAllowed)
        return buildJsonObject {
            put("runtime", buildJsonObject {
                put("manager", availability.isManager)
                put("root", availability.rootAvailable)
                put("preview_mode", availability.isPreviewMode)
                put("lkm_mode", availability.lkmMode?.toString() ?: "")
                put("safe_mode", availability.safeMode)
                put("late_load", availability.lateLoadMode)
                put("network", availability.networkAvailable)
                put("kpm", availability.kpmAvailable)
                put("susfs", availability.susfsAvailable)
                put("extension_read_allowed", availability.extensionReadAllowed)
            })
            put("pages", buildJsonArray {
                entries(availability).forEach { entry ->
                    add(buildJsonObject {
                        put("id", entry.id)
                        put("title", entry.title)
                        put("summary", entry.summary)
                        put("supported", entry.supported)
                        put("openable", entry.openable)
                        if (entry.reason.isNotEmpty()) put("reason", entry.reason)
                        if (entry.solution.isNotEmpty()) put("solution", entry.solution)
                        if (entry.requires.isNotEmpty()) {
                            put("requires", buildJsonArray { entry.requires.forEach { add(it) } })
                        }
                        (entry.target as? ManagerAiTarget)?.takeIf { entry.supported }?.let { put("destination", it.describe()) }
                    })
                }
            })
        }.toString()
    }

    override suspend fun openPage(
        id: String,
        rootProbeAllowed: Boolean,
        extensionReadAllowed: Boolean,
        allowSuperuserRead: Boolean,
        packageName: String?,
        uid: Int?,
        moduleId: String?,
        section: String?,
        tab: String?,
    ): AiOpenPageResult {
        val availability = availability(rootProbeAllowed, extensionReadAllowed)
        val normalized = id.trim().lowercase().replace('-', '_')

        if (normalized == "app_profile" || normalized == "superuser_app_detail") {
            if (!allowSuperuserRead) {
                return AiOpenPageResult(
                    "Permission required for superuser data. Enable 'Allow superuser data' in the " +
                        "assistant settings, then retry."
                )
            }
            if (!availability.isManager) {
                return AiOpenPageResult(
                    "NOT SUPPORTED: App root profiles need a SukiSU kernel. ${KERNEL_SOLUTION}"
                )
            }
            if (packageName == ksuApp.packageName) {
                return AiOpenPageResult(
                    "The manager's own root profile is excluded from the app list."
                )
            }
            val resolvedUid = uid ?: packageName?.let { name ->
                runCatching {
                    ksuApp.packageManager.getApplicationInfo(name, 0).uid
                }.getOrNull()
            } ?: return AiOpenPageResult(
                "MISSING ARGUMENT: pass package_name or uid to open an app root profile."
            )
            if (resolvedUid <= 0) {
                return AiOpenPageResult("Invalid UID $resolvedUid; pass an installed app's uid.")
            }
            if (ksuApp.packageManager.getNameForUid(resolvedUid) == ksuApp.packageName) {
                return AiOpenPageResult(
                    "The manager's own root profile is excluded from the app list."
                )
            }
            val label = runCatching {
                ksuApp.packageManager.getApplicationInfo(
                    packageName ?: ksuApp.packageManager.getNameForUid(resolvedUid).orEmpty(),
                    0,
                ).loadLabel(ksuApp.packageManager).toString()
            }.getOrNull()?.takeIf { it.isNotBlank() }
                ?: packageName
                ?: "uid $resolvedUid"
            return AiOpenPageResult(
                text = "A navigation button for the app profile '$label' is shown below. " +
                    "The user can tap it to open its root/temporary-root controls.",
                target = ManagerAiTarget.Push(Route.AppProfile(resolvedUid)),
                title = label,
            )
        }

        if (normalized == "module_repo_detail") {
            if (!availability.networkAvailable) {
                return AiOpenPageResult("NOT SUPPORTED: ${NETWORK_REASON} ${NETWORK_SOLUTION}")
            }
            val targetModuleId = moduleId?.trim()?.takeIf { it.isNotEmpty() }
                ?: return AiOpenPageResult(
                    "MISSING ARGUMENT: pass module_id from module_search to open a registry module detail."
                )
            val detail = runCatching {
                ModuleRepoRepositoryImpl().fetchDetail(targetModuleId).getOrThrow()
            }.getOrElse { error ->
                if (error is kotlinx.coroutines.CancellationException) throw error
                return AiOpenPageResult(
                    "Cannot open module '$targetModuleId': ${error.message ?: "not found in the registry"}."
                )
            }
            val arg = detail.module.toRepoModuleArg()
            return AiOpenPageResult(
                text = "A navigation button for '${arg.moduleName}' is shown below. " +
                    "The user can tap it to open the registry module detail.",
                target = ManagerAiTarget.Push(Route.ModuleRepoDetail(arg)),
                title = arg.moduleName,
            )
        }

        val entry = entries(availability).firstOrNull { it.id.equals(normalized, true) }
            ?: return AiOpenPageResult(
                "Unknown page '$id'. Known ids: ${entries(availability).joinToString { it.id }}"
            )

        // Optional precise section/tab overrides for generic ids.
        if (normalized == "settings" && !section.isNullOrBlank()) {
            val anchor = section.trim().lowercase().replace('-', '_')
            if (anchor !in SettingsSection.ALL) {
                return AiOpenPageResult(
                    "Unknown Settings section '$section'. Use one of: " +
                        SettingsSection.ALL.joinToString() + "."
                )
            }
            return AiOpenPageResult(
                text = "A navigation button for Settings > $anchor is shown below.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, anchor),
                title = "Settings · $anchor",
            )
        }
        if (normalized == "appearance" && !section.isNullOrBlank()) {
            val appearanceSection = section.trim().lowercase().replace('-', '_')
            if (appearanceSection !in APPEARANCE_SECTIONS) {
                return AiOpenPageResult(
                    "Unknown Appearance section '$section'. Use one of: " +
                        APPEARANCE_SECTIONS.joinToString() + "."
                )
            }
            return AiOpenPageResult(
                text = "A navigation button for Appearance > $appearanceSection is shown below.",
                target = ManagerAiTarget.Push(Route.ColorPalette(appearanceSection)),
                title = "Appearance · $appearanceSection",
            )
        }
        if (normalized == "susfs" && !tab.isNullOrBlank()) {
            val suSfsTab = tab.trim().lowercase().replace('-', '_')
            if (suSfsTab !in SU_SFS_TABS) {
                return AiOpenPageResult(
                    "Unknown SuSFS tab '$tab'. Use one of: ${SU_SFS_TABS.joinToString()}."
                )
            }
            return AiOpenPageResult(
                text = "A navigation button for SuSFS > $suSfsTab is shown below.",
                target = ManagerAiTarget.Push(Route.SuSFS(suSfsTab)),
                title = "SuSFS · $suSfsTab",
            )
        }

        if (!entry.supported) {
            return AiOpenPageResult(
                "NOT SUPPORTED: ${entry.title} is unavailable. ${entry.reason} " +
                    "SOLUTION: ${entry.solution}"
            )
        }
        if (entry.requires.isNotEmpty() && entry.target == null) {
            return AiOpenPageResult(
                "MISSING ARGUMENT: ${entry.title} needs ${entry.requires.joinToString("/")}. " +
                    entry.solution
            )
        }
        val target = entry.target
        if (!entry.openable || target == null) {
            return AiOpenPageResult(
                "CANNOT OPEN DIRECTLY: ${entry.title}. ${entry.solution}"
            )
        }
        return AiOpenPageResult(
            text = "A navigation button for '${entry.title}' is shown below. The user can tap it to go there.",
            target = target,
            title = entry.title,
        )
    }

    private fun entries(a: AiFeatureAvailability): List<AiFeatureEntry> {
        val manager = a.isManager
        val root = a.rootAvailable
        val kernelReady = manager && root
        return listOf(
            entry(
                id = "home",
                title = "Home",
                summary = "Dashboard: KernelSU/SukiSU status, version warnings, stats, AI assistant card and support links.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Home),
            ),
            entry(
                id = "superuser",
                title = "Superuser",
                summary = "Root permission manager: app list, grant/deny root, per-app profiles, temporary root and multi-user apps.",
                target = ManagerAiTarget.Tab(BottomBarDestination.SuperUser),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "app_profile",
                title = "App root profile",
                summary = "Per-app root profile, permanent/temporary root, mount/SELinux/capability settings.",
                supported = kernelReady,
                openable = false,
                requires = listOf("package_name or uid"),
                reason = rootReason(a, manager),
                solution = "Call open_app_page with package_name or uid to open the exact app profile.",
            ),
            entry(
                id = "modules",
                title = "Modules",
                summary = "Installed modules: enable/disable, uninstall or undo, action scripts, WebUI, update checks and zygisk/metamodule flags.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Module),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "module_detail",
                title = "Module actions",
                summary = "Run a module action script, open its WebUI or uninstall it.",
                supported = kernelReady,
                openable = false,
                reason = rootReason(a, manager),
                solution = "Open Modules, find the module and use its action/WebUI/uninstall controls.",
            ),
            entry(
                id = "module_repo",
                title = "Module repository",
                summary = "Browse the KernelSU module registry, search/sort modules, install verified releases and check updates.",
                target = ManagerAiTarget.Push(Route.ModuleRepo),
                supported = a.networkAvailable,
                reason = NETWORK_REASON,
                solution = NETWORK_SOLUTION,
            ),
            entry(
                id = "module_repo_detail",
                title = "Repository module detail",
                summary = "Release notes, screenshots and version selection for a registry module.",
                supported = a.networkAvailable,
                openable = false,
                requires = listOf("module_id"),
                reason = NETWORK_REASON,
                solution = "Call open_app_page with module_id from module_search to open the exact module detail.",
            ),
            entry(
                id = "install",
                title = "Install / update",
                summary = "Install or update SukiSU, LKM, patch boot/init_boot images, and configure optional KPM or shell policy.",
                target = ManagerAiTarget.Push(Route.Install()),
            ),
            entry(
                id = "flash",
                title = "Flash image",
                summary = "Flash a kernel or boot image, optionally applying KPM patches.",
                supported = root,
                openable = false,
                reason = ROOT_REASON,
                solution = "Open Install, choose a boot image, or share/open a ZIP/IMG file with the manager and follow the flash screen.",
            ),
            entry(
                id = "extensions",
                title = "Extensions",
                summary = "Extension overview: KPM, CPU spoof, umount paths, dynamic manager, SuSFS and version spoof.",
                target = ManagerAiTarget.Push(Route.Extensions),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "kpm",
                title = "KPM",
                summary = "Kernel module manager: list/load/unload modules, read module info and run control commands.",
                target = ManagerAiTarget.Push(Route.Kpm),
                supported = kernelReady && a.kpmAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else kpmReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else kpmSolution(a),
            ),
            entry(
                id = "cpu_spoof",
                title = "CPU spoof",
                summary = "Spoof per-core CPU identity: MIDR, bogomips, hwcap and hwcap2.",
                target = ManagerAiTarget.Push(Route.CpuSpoof),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "umount_manager",
                title = "Umount paths",
                summary = "Manage paths hidden from selected apps' mount namespace.",
                target = ManagerAiTarget.Push(Route.UmountManager),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "dynamic_managers",
                title = "Dynamic manager",
                summary = "Allow additional manager packages/signatures to use the kernel interface.",
                target = ManagerAiTarget.Push(Route.DynamicManagers),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "susfs",
                title = "SuSFS",
                summary = "Kernel-level hiding/spoofing: paths, maps, kstat, uname, logs and auto-start configuration.",
                target = ManagerAiTarget.Push(Route.SuSFS()),
                supported = kernelReady && a.susfsAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else susfsReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else susfsSolution(a),
            ),
            entry(
                id = "susfs_basic",
                title = "SuSFS basic settings",
                summary = "Uname, build time, post-fs-data execution, cmdline/bootconfig and slot info.",
                target = ManagerAiTarget.Push(Route.SuSFS("basic")),
                supported = kernelReady && a.susfsAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else susfsReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else susfsSolution(a),
            ),
            entry(
                id = "susfs_features",
                title = "SuSFS feature toggles",
                summary = "Enable log, AVC log spoofing, hide SUS mounts, hide bootloader status, cleanup residue and auto-start.",
                target = ManagerAiTarget.Push(Route.SuSFS("features")),
                supported = kernelReady && a.susfsAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else susfsReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else susfsSolution(a),
            ),
            entry(
                id = "susfs_sus_paths",
                title = "SuSFS paths",
                summary = "Manage paths hidden by SuSFS, including paths for an installed app.",
                target = ManagerAiTarget.Push(Route.SuSFS("sus_paths")),
                supported = kernelReady && a.susfsAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else susfsReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else susfsSolution(a),
            ),
            entry(
                id = "susfs_sus_loop_paths",
                title = "SuSFS loop paths",
                summary = "Manage loop-device paths hidden by SuSFS.",
                target = ManagerAiTarget.Push(Route.SuSFS("sus_loop_paths")),
                supported = kernelReady && a.susfsAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else susfsReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else susfsSolution(a),
            ),
            entry(
                id = "susfs_sus_maps",
                title = "SuSFS maps",
                summary = "Manage memory maps hidden by SuSFS.",
                target = ManagerAiTarget.Push(Route.SuSFS("sus_maps")),
                supported = kernelReady && a.susfsAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else susfsReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else susfsSolution(a),
            ),
            entry(
                id = "susfs_kstat",
                title = "SuSFS kstat",
                summary = "Static and dynamic kstat spoofing configurations.",
                target = ManagerAiTarget.Push(Route.SuSFS("kstat")),
                supported = kernelReady && a.susfsAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else susfsReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else susfsSolution(a),
            ),
            entry(
                id = "susfs_priority_uid",
                title = "SuSFS priority UID filter",
                summary = "Select apps whose UIDs are filtered by SuSFS.",
                target = ManagerAiTarget.Push(Route.SuSFS("priority_uid")),
                supported = kernelReady && a.susfsAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else susfsReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else susfsSolution(a),
            ),
            entry(
                id = "susfs_enabled_features",
                title = "SuSFS enabled features",
                summary = "Read-only list of SuSFS features enabled by the running kernel.",
                target = ManagerAiTarget.Push(Route.SuSFS("enabled_features")),
                supported = kernelReady && a.susfsAvailable,
                reason = if (!kernelReady) rootReason(a, manager) else susfsReason(a),
                solution = if (!kernelReady) rootSolution(a, manager) else susfsSolution(a),
            ),
            entry(
                id = "version_spoof",
                title = "Version spoof",
                summary = "Override the kernel-reported version, full version and UAPI.",
                target = ManagerAiTarget.Push(Route.VersionSpoof),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "kernel_modules",
                title = "Kernel module blocklist",
                summary = "Read the active block_modules list, boot config, loaded modules and dependency chains.",
                target = ManagerAiTarget.Push(Route.KernelModules),
                supported = root,
                reason = ROOT_REASON,
                solution = ROOT_SOLUTION,
            ),
            entry(
                id = "tools",
                title = "Tools",
                summary = "Root utilities: CPU information, CPU spoof presets, device and kernel diagnostics.",
                target = ManagerAiTarget.Push(Route.Tool),
                supported = root,
                reason = ROOT_REASON,
                solution = ROOT_SOLUTION,
            ),
            entry(
                id = "sulog",
                title = "SU log",
                summary = "Review and filter superuser grant/deny events.",
                target = ManagerAiTarget.Push(Route.Sulog),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "app_profile_template",
                title = "Profile templates",
                summary = "Create, edit and reuse app profile templates.",
                target = ManagerAiTarget.Push(Route.AppProfileTemplate),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "template_editor",
                title = "Template editor",
                summary = "Edit a specific profile template.",
                supported = kernelReady,
                openable = false,
                reason = rootReason(a, manager),
                solution = "Open Profile templates and select or create a template.",
            ),
            entry(
                id = "script_run",
                title = "Script runner",
                summary = "Run a registry one-shot script with parameters.",
                supported = root,
                openable = false,
                reason = ROOT_REASON,
                solution = "Open Module Repository, search for the script and select Run.",
            ),
            entry(
                id = "about",
                title = "About",
                summary = "Version information, contributors and project links.",
                target = ManagerAiTarget.Push(Route.About),
            ),
            entry(
                id = "settings",
                title = "Settings",
                summary = "UI mode, language, theme, updates, security features, superuser/module sorting and tools.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting),
            ),
            entry(
                id = "settings_general",
                title = "Settings · General",
                summary = "UI mode, language and the appearance entry.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "general"),
            ),
            entry(
                id = "settings_security",
                title = "Settings · Security",
                summary = "SU compatibility, kernel umount, SELinux/AVC/mount hiding, SU log, ADB root and shell su policy.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "security"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_su_compat",
                title = "Settings · SU compatibility",
                summary = "Enable su by default, disable until reboot, or disable always.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "su_compat"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_kernel_umount",
                title = "Settings · Kernel umount",
                summary = "Enable or disable kernel umount.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "kernel_umount"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_selinux_hide",
                title = "Settings · SELinux hide",
                summary = "Hide the manager's SELinux modifications.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "selinux_hide"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_avc_spoof",
                title = "Settings · AVC log spoofing",
                summary = "Spoof AVC denial logs.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "avc_spoof"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_mount_hide",
                title = "Settings · Mount hide",
                summary = "Hide mount information from selected processes.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "mount_hide"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_sulog",
                title = "Settings · SU log",
                summary = "Enable superuser grant/deny logging.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "sulog"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_adb_root",
                title = "Settings · ADB root",
                summary = "Allow adb root.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "adb_root"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_shell_su_adb_only",
                title = "Settings · Shell su ADB only",
                summary = "Restrict shell su to ADB.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "shell_su_adb_only"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_soft_reboot",
                title = "Settings · Soft reboot",
                summary = "Use a soft reboot for late-load changes.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "soft_reboot"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_default_umount_modules",
                title = "Settings · Default umount modules",
                summary = "Apply umount modules to apps by default.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "default_umount_modules"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_auto_delete_module_zip",
                title = "Settings · Auto-delete module ZIP",
                summary = "Delete the module ZIP after installation.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "auto_delete_module_zip"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_web_debugging",
                title = "Settings · Web debugging",
                summary = "Enable WebView debugging.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "web_debugging"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_auto_jailbreak",
                title = "Settings · Auto jailbreak",
                summary = "Automatically apply late-load jailbreak.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "auto_jailbreak"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_temporary_root",
                title = "Settings · Temporary root default",
                summary = "Default duration used when granting temporary root.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "temporary_root"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_module_behaviour",
                title = "Settings · Module behaviour",
                summary = "Default umount modules, auto-delete module ZIP, web debugging and auto-jailbreak.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "module_behaviour"),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_uninstall",
                title = "Settings · Uninstall",
                summary = "Uninstall the LKM installation.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "uninstall"),
                supported = kernelReady && a.lkmMode == true,
                reason = if (!kernelReady) rootReason(a, manager) else "This is not an LKM installation.",
                solution = if (!kernelReady) rootSolution(a, manager) else "Uninstall is only shown for LKM installs.",
            ),
            entry(
                id = "settings_diagnostics",
                title = "Settings · Diagnostics",
                summary = "Send log and About entry.",
                target = ManagerAiTarget.Tab(BottomBarDestination.Setting, "diagnostics"),
            ),
            entry(
                id = "settings_profile_templates",
                title = "Profile templates",
                summary = "Create, edit and reuse app profile templates.",
                target = ManagerAiTarget.Push(Route.AppProfileTemplate),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_extensions",
                title = "Extensions",
                summary = "Extension overview and sub-pages.",
                target = ManagerAiTarget.Push(Route.Extensions),
                supported = kernelReady,
                reason = rootReason(a, manager),
                solution = rootSolution(a, manager),
            ),
            entry(
                id = "settings_tools",
                title = "Tools",
                summary = "CPU information, spoof presets and diagnostics.",
                target = ManagerAiTarget.Push(Route.Tool),
                supported = root,
                reason = ROOT_REASON,
                solution = ROOT_SOLUTION,
            ),
            entry(
                id = "appearance",
                title = "Appearance",
                summary = "Theme mode, key color, palette style/spec, background image, blur/scrim, card opacity, custom texts, app icon, and theme package import/export.",
                target = ManagerAiTarget.Push(Route.ColorPalette()),
            ),
            entry(
                id = "appearance_background",
                title = "Appearance · Background",
                summary = "System wallpaper, custom background image, crop, alpha, blur and scrim.",
                target = ManagerAiTarget.Push(Route.ColorPalette("background")),
            ),
            entry(
                id = "appearance_colors",
                title = "Appearance · Colors",
                summary = "Key color, theme mode, palette style and color spec.",
                target = ManagerAiTarget.Push(Route.ColorPalette("colors")),
            ),
            entry(
                id = "appearance_theme_package",
                title = "Appearance · Theme package",
                summary = "Export, import and reset theme packages.",
                target = ManagerAiTarget.Push(Route.ColorPalette("theme_package")),
            ),
            entry(
                id = "appearance_behavior",
                title = "Appearance · Behavior",
                summary = "Swipe dismiss, pager gesture mode, page scale and module description lines.",
                target = ManagerAiTarget.Push(Route.ColorPalette("behavior")),
            ),
            entry(
                id = "color_palette",
                title = "Color palette",
                summary = "Pick the key color, Material palette style, color spec and preview the result.",
                target = ManagerAiTarget.Push(Route.ColorPalette()),
            ),
            entry(
                id = "custom_texts",
                title = "Custom texts",
                summary = "Override labels and messages across the home and feature pages.",
                target = ManagerAiTarget.Push(Route.CustomTexts),
            ),
            entry(
                id = "app_icon",
                title = "App icon",
                summary = "Choose a built-in launcher icon, dynamic color or icon pack. Arbitrary image replacement is not supported; custom pack icons can be pinned as shortcuts.",
                target = ManagerAiTarget.Push(Route.AppIcon),
            ),
            entry(
                id = "background",
                title = "Background",
                summary = "Custom background image, crop, blur, scrim, system wallpaper and color extraction. AI image import/generation and share/export use the same slot.",
                target = ManagerAiTarget.Push(Route.ColorPalette("background")),
            ),
            entry(
                id = "ai_assistant",
                title = "AI assistant",
                summary = "Chat, inspect the manager environment, and use scoped theme/extension/module/superuser tools.",
                target = ManagerAiTarget.Push(Route.AiAssistant),
            ),
            entry(
                id = "ai_settings",
                title = "Assistant settings",
                summary = "Connection, read/write scopes, superuser control and behaviour.",
                target = ManagerAiTarget.Push(Route.AiSettings),
            ),
        )
    }

    private fun entry(
        id: String,
        title: String,
        summary: String,
        target: AiNavigationTarget? = null,
        supported: Boolean = true,
        openable: Boolean = target != null,
        reason: String = "",
        solution: String = "",
        requires: List<String> = emptyList(),
    ): AiFeatureEntry {
        val effectiveOpenable = supported && openable && target != null
        return AiFeatureEntry(
            id = id,
            title = title,
            summary = summary,
            supported = supported,
            openable = effectiveOpenable,
            reason = if (supported) "" else reason.ifBlank { GENERIC_REASON },
            solution = if (effectiveOpenable) "" else solution,
            target = if (effectiveOpenable) target else null,
            requires = requires,
        )
    }

    private fun ManagerAiTarget.describe(): String = when (this) {
        is ManagerAiTarget.Tab -> buildString {
            append("tab:").append(destination.name.lowercase())
            section?.let { append('#').append(it) }
        }

        is ManagerAiTarget.Push -> when (val route = route) {
            is Route.ColorPalette -> "route:ColorPalette#${route.section.orEmpty()}"
            is Route.SuSFS -> "route:SuSFS#${route.tab.orEmpty()}"
            is Route.AppProfile -> "route:AppProfile#uid=${route.uid}"
            else -> "route:${route::class.simpleName}"
        }
    }

    private fun kpmReason(a: AiFeatureAvailability): String =
        if (!a.extensionReadAllowed) EXTENSION_READ_REASON else KPM_REASON

    private fun kpmSolution(a: AiFeatureAvailability): String =
        if (!a.extensionReadAllowed) EXTENSION_READ_SOLUTION else KPM_SOLUTION

    private fun susfsReason(a: AiFeatureAvailability): String =
        if (!a.extensionReadAllowed) EXTENSION_READ_REASON else SUSFS_REASON

    private fun susfsSolution(a: AiFeatureAvailability): String =
        if (!a.extensionReadAllowed) EXTENSION_READ_SOLUTION else SUSFS_SOLUTION

    private fun rootReason(a: AiFeatureAvailability, manager: Boolean): String = when {
        !manager -> KERNEL_REASON
        !a.rootProbeAllowed -> AI_ROOT_REASON
        else -> ROOT_REASON
    }

    private fun rootSolution(a: AiFeatureAvailability, manager: Boolean): String = when {
        !manager -> KERNEL_SOLUTION
        !a.rootProbeAllowed -> AI_ROOT_SOLUTION
        else -> ROOT_SOLUTION
    }

    private fun RepoModule.toRepoModuleArg(): RepoModuleArg = RepoModuleArg(
        moduleId = moduleId,
        moduleName = moduleName,
        authors = authors,
        authorsList = authorList.map { AuthorArg(it.name, it.link) },
        latestVersion = latestVersion,
        latestVersionCode = latestVersionCode,
        latestReleaseTime = latestReleaseTime,
        metamodule = metamodule,
        script = isScript,
    )

    private val APPEARANCE_SECTIONS = listOf(
        "preview", "background", "theme_package", "appearance", "colors", "color_mode",
        "palette", "chrome", "behavior", "gestures", "predictive_back", "scale",
        "module_description",
    )

    private val SU_SFS_TABS = listOf(
        "basic", "features", "sus_paths", "sus_loop_paths", "sus_maps", "kstat",
        "priority_uid", "enabled_features",
    )

    private const val KERNEL_REASON = "No SukiSU kernel is active (preview mode)."
    private const val KERNEL_SOLUTION =
        "Install the SukiSU kernel or LKM from the Install page, reboot, then reopen the manager."
    private const val ROOT_REASON = "Root access is not available to the manager."
    private const val ROOT_SOLUTION =
        "Grant root to the manager in Superuser. If root is still unavailable, install or repair SukiSU from the Install page and reboot."
    private const val AI_ROOT_REASON = "Root access for the AI assistant is disabled in assistant settings."
    private const val AI_ROOT_SOLUTION =
        "Enable 'Allow root access' in the AI assistant settings, or use 'Allow for this request' on the permission card in the chat."
    private const val NETWORK_REASON = "No validated network connection."
    private const val NETWORK_SOLUTION = "Connect to Wi-Fi or mobile data and retry."
    private const val KPM_REASON = "This kernel does not report KPM support."
    private const val KPM_SOLUTION =
        "Use a kernel built with KPM support (the built-in SukiSU kernel) or load a compatible LKM; check Extensions for support."
    private const val SUSFS_REASON = "This kernel does not report SuSFS support."
    private const val SUSFS_SOLUTION =
        "Flash a SuSFS-enabled kernel or a supported LKM, reboot, then check Extensions."
    private const val EXTENSION_READ_REASON =
        "Extension read access is disabled in the assistant settings."
    private const val EXTENSION_READ_SOLUTION =
        "Enable 'Allow extension data' in the assistant settings so the assistant can check whether this feature is supported."
    private const val GENERIC_REASON = "This feature is unavailable on the current device."
}
