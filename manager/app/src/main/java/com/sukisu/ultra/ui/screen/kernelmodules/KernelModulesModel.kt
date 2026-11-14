package com.sukisu.ultra.ui.screen.kernelmodules

import androidx.compose.runtime.Immutable

/**
 * Maximum length of the comma-separated `block_modules=` value. ksud enforces
 * the same limit; the kernel copies the value into a 256-byte buffer and
 * silently truncates anything longer.
 */
internal const val MAX_BLOCK_MODULES_LEN = 255


enum class KernelModuleStatus {
    
    Blocked,

    
    BlockedLoaded,

    
    ConfigPending,

    
    DeviceBlocklist,

    
    NotFound,
}


@Immutable
data class KernelModuleDependent(
    val name: String,
    val loaded: Boolean,
    
    val boot: Boolean,
    
    val blocked: Boolean,
)


@Immutable
data class KernelModuleEntry(
    val name: String,
    val status: KernelModuleStatus,
    val configured: Boolean,
    val active: Boolean,
    val loaded: Boolean,
    val knownAntiRoot: Boolean,
    val deviceBlocklist: Boolean,
    
    val path: String?,
    
    val dependents: List<KernelModuleDependent>,
)


enum class KernelModulesParamsSource {
    Config,
    Suggested,
    Active,
    None,
}


enum class KernelModulesActiveSource {
    Sysfs,
    Cmdline,
    None,
}

@Immutable
data class KernelModulesSnapshot(
    val entries: List<KernelModuleEntry>,
    val configuredNames: List<String>,
    val activeNames: List<String>,
    val suggestedNames: List<String>,
    val deviceBlocklistNames: List<String>,
    /**
     * Device blocklist entries that are neither in modules.dep nor loaded, so
     * they have no row to show. Kept as a count instead of thousands of cards.
     */
    val hiddenDeviceBlocklistCount: Int,
    val paramsNames: List<String>,
    val paramsSource: KernelModulesParamsSource,
    val paramsConfigLine: String,
    val paramsCliLine: String,
    val paramsTooLong: Boolean,
    
    val activeAvailable: Boolean,
    
    val configAvailable: Boolean,
    
    val dependencyDataAvailable: Boolean,
    val activeSource: KernelModulesActiveSource,
    val currentlyLoadedCount: Int,
    
    val affectedBootModules: Int,
)


internal data class KernelModulesRaw(
    val active: String?,
    val activeReadable: Boolean,
    val config: String?,
    val configReadable: Boolean,
    val cmdline: String?,
    val procModules: String?,
    val modulesDep: String?,
    val modulesLoad: String?,
    val modulesBlocklist: String?,
    val modulesDir: String?,
)

internal data class LoadedModule(
    val name: String,
    val usedBy: List<String>,
)

internal data class ModuleDep(
    val name: String,
    val path: String,
    val dependencies: Set<String>,
)

/**
 * Parsing and classification for the kernel module page. Everything here is
 * pure so the interesting decisions can be unit tested without a device.
 */
internal object KernelModulesParser {

    /**
     * libmodprobe and /proc/modules use the same canonical form: no directory,
     * no `.ko` suffix, dashes replaced by underscores.
     */
    fun canonicalName(raw: String): String? {
        val trimmed = raw.trim().trim('"', '\'')
        if (trimmed.isEmpty() || trimmed == "(null)" || trimmed.startsWith("#")) {
            return null
        }
        val base = trimmed.substringAfterLast('/').removeSuffix(".ko")
        if (base.isEmpty()) return null
        return base.replace('-', '_')
    }

    
    fun isSafeConfigName(name: String): Boolean =
        name.length in 1..64 &&
            name.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' }

    fun parseCommaNames(raw: String?): List<String> =
        raw.orEmpty()
            .split(',')
            .mapNotNull(::canonicalName)
            .distinct()

    fun parseConfigBlockModules(raw: String?): List<String> =
        raw.orEmpty()
            .split(Regex("\\s+"))
            .filter { it.startsWith("block_modules=") }
            .flatMap { token -> token.substringAfter('=').trim('"', '\'').split(',') }
            .map { it.trim() }
            .filter(::isSafeConfigName)
            .distinct()

    /**
     * The kernel's own list is compared verbatim against module names, so keep
     * it canonical only for matching against /proc/modules. Unlike
     * block_modules=, a native entry is not limited by ksud's name validator.
     */
    fun parseCmdlineModuleBlacklist(raw: String?): List<String> =
        raw.orEmpty()
            .split(Regex("\\s+"))
            .filter { it.startsWith("module_blacklist=") }
            .flatMap { token -> token.substringAfter('=').split(',') }
            .mapNotNull(::canonicalName)
            .distinct()

    fun parseCmdlineBlockModules(raw: String?): List<String> =
        raw.orEmpty()
            .split(Regex("\\s+"))
            .filter { it.startsWith("block_modules=") }
            .flatMap { token -> token.substringAfter('=').trim('"', '\'').split(',') }
            .map { it.trim() }
            .filter(::isSafeConfigName)
            .distinct()

    
    fun parseProcModules(raw: String?): Map<String, LoadedModule> {
        val result = LinkedHashMap<String, LoadedModule>()
        raw.orEmpty().lineSequence().forEach { line ->
            val fields = line.trim().split(Regex("\\s+"))
            if (fields.size < 4) return@forEach
            val name = canonicalName(fields[0]) ?: return@forEach
            val usedBy = if (fields[3] == "-") {
                emptyList()
            } else {
                fields[3].split(',').mapNotNull(::canonicalName)
            }
            result[name] = LoadedModule(name, usedBy)
        }
        return result
    }

    
    fun parseModulesDep(raw: String?): Map<String, ModuleDep> {
        val result = LinkedHashMap<String, ModuleDep>()
        raw.orEmpty().lineSequence().forEach { line ->
            val colon = line.indexOf(':')
            if (colon <= 0) return@forEach
            val path = line.substring(0, colon).trim()
            val name = canonicalName(path) ?: return@forEach
            val dependencies = line.substring(colon + 1)
                .trim()
                .split(Regex("\\s+"))
                .mapNotNull(::canonicalName)
                .toSet()
            result[name] = ModuleDep(name, path, dependencies)
        }
        return result
    }

    
    fun parseModuleList(raw: String?): Set<String> =
        raw.orEmpty().lineSequence()
            .map { it.substringBefore('#').trim() }
            .filter { it.isNotEmpty() }
            .mapNotNull(::canonicalName)
            .toSet()

    fun parseModulesBlocklist(raw: String?): Set<String> =
        raw.orEmpty().lineSequence()
            .map { it.substringBefore('#').trim() }
            .filter { it.startsWith("blocklist ") }
            .mapNotNull { canonicalName(it.removePrefix("blocklist ")) }
            .toSet()

    /**
     * Reverse the dependency graph and take the transitive closure. A module
     * can depend on itself through a cycle in a broken depmod output; the seen
     * set keeps that finite and the self entry is dropped.
     */
    fun buildDependents(deps: Map<String, ModuleDep>): Map<String, List<String>> {
        val reverse = LinkedHashMap<String, MutableSet<String>>()
        deps.values.forEach { module ->
            module.dependencies.forEach { required ->
                reverse.getOrPut(required) { linkedSetOf() }.add(module.name)
            }
        }

        val result = HashMap<String, List<String>>()
        val names = LinkedHashSet<String>().apply {
            addAll(deps.keys)
            addAll(reverse.keys)
        }
        for (name in names) {
            val seen = linkedSetOf<String>()
            val queue = ArrayDeque<String>()
            queue.addAll(reverse[name].orEmpty())
            while (queue.isNotEmpty()) {
                val current = queue.removeFirst()
                if (current == name || !seen.add(current)) continue
                queue.addAll(reverse[current].orEmpty())
            }
            if (seen.isNotEmpty()) {
                result[name] = seen.toList()
            }
        }
        return result
    }

    fun buildSnapshot(
        raw: KernelModulesRaw,
        knownAntiRoot: Set<String>,
    ): KernelModulesSnapshot {
        val loaded = parseProcModules(raw.procModules)
        val deps = parseModulesDep(raw.modulesDep)
        val bootModules = parseModuleList(raw.modulesLoad)
        val deviceBlocklist = parseModulesBlocklist(raw.modulesBlocklist)
        val dependents = buildDependents(deps)

        val activeFromSysfs =
            if (raw.activeReadable) parseCommaNames(raw.active) else emptyList()
        val activeFromCmdline = parseCmdlineModuleBlacklist(raw.cmdline)
        val activeNames = activeFromSysfs.ifEmpty { activeFromCmdline }
        val activeSource = when {
            activeFromSysfs.isNotEmpty() -> KernelModulesActiveSource.Sysfs
            activeFromCmdline.isNotEmpty() -> KernelModulesActiveSource.Cmdline
            else -> KernelModulesActiveSource.None
        }

        val configFromRamdisk =
            if (raw.configReadable) parseConfigBlockModules(raw.config) else emptyList()
        val configFromCmdline = parseCmdlineBlockModules(raw.cmdline)
        val configuredNames = configFromRamdisk.ifEmpty { configFromCmdline }

        val configuredSet = configuredNames.toSet()
        val activeSet = activeNames.toSet()
        val deviceSet = deviceBlocklist

        // Vendor modules.blocklist files are generic and often name modules
        // this build does not ship. Only keep entries that have a real row
        // (modules.dep) or are actually loaded; the rest are counted, not
        // rendered as hundreds of "missing dependency data" cards.
        val visibleDeviceBlocklist = deviceBlocklist.filter { it in deps || it in loaded }
        val hiddenDeviceBlocklist = deviceBlocklist.filter {
            it !in deps && it !in loaded && it !in activeSet && it !in configuredSet
        }

        val suggestions = if (configuredNames.isEmpty() && activeNames.isEmpty()) {
            loaded.values
                .filter { it.name in knownAntiRoot && it.usedBy.isEmpty() }
                .map { it.name }
                .filter { it !in configuredSet && it !in deviceSet }
                .filter { name -> dependents[name].orEmpty().all { it in deviceSet } }
                .sorted()
        } else {
            emptyList()
        }

        val allNames = LinkedHashSet<String>()
        allNames.addAll(configuredNames)
        allNames.addAll(activeNames)
        allNames.addAll(visibleDeviceBlocklist)

        val affected = LinkedHashSet<String>()
        val entries = allNames.map { name ->
            val active = name in activeSet
            val configured = name in configuredSet
            val isLoaded = name in loaded
            val device = name in deviceSet
            val status = when {
                active && isLoaded -> KernelModuleStatus.BlockedLoaded
                active -> KernelModuleStatus.Blocked
                configured -> KernelModuleStatus.ConfigPending
                device -> KernelModuleStatus.DeviceBlocklist
                else -> KernelModuleStatus.NotFound
            }
            val moduleDependents = dependents[name].orEmpty()
                .filter { it != name }
                .map { dependent ->
                    KernelModuleDependent(
                        name = dependent,
                        loaded = dependent in loaded,
                        boot = dependent in bootModules,
                        blocked = dependent in activeSet ||
                            dependent in configuredSet ||
                            dependent in deviceSet,
                    )
                }
                .sortedWith(compareBy({ it.loaded }, { !it.boot }, { it.name }))

            if (active || configured) {
                moduleDependents
                    .filter { it.boot && !it.loaded && !it.blocked }
                    .forEach { affected.add(it.name) }
            }

            KernelModuleEntry(
                name = name,
                status = status,
                configured = configured,
                active = active,
                loaded = isLoaded,
                knownAntiRoot = name in knownAntiRoot,
                deviceBlocklist = device,
                path = deps[name]?.path,
                dependents = moduleDependents,
            )
        }.sortedWith(
            compareBy(
                {
                    when (it.status) {
                        KernelModuleStatus.Blocked -> 0
                        KernelModuleStatus.BlockedLoaded -> 1
                        KernelModuleStatus.ConfigPending -> 2
                        KernelModuleStatus.DeviceBlocklist -> 3
                        KernelModuleStatus.NotFound -> 4
                    }
                },
                { it.name },
            ),
        )

        val paramsSource = when {
            configuredNames.isNotEmpty() -> KernelModulesParamsSource.Config
            suggestions.isNotEmpty() -> KernelModulesParamsSource.Suggested
            activeNames.isNotEmpty() -> KernelModulesParamsSource.Active
            else -> KernelModulesParamsSource.None
        }
        val paramsNames = when (paramsSource) {
            KernelModulesParamsSource.Config -> configuredNames
            KernelModulesParamsSource.Suggested -> suggestions
            KernelModulesParamsSource.Active -> activeNames
            KernelModulesParamsSource.None -> emptyList()
        }.filter(::isSafeConfigName).distinct()
        val paramsValue = paramsNames.joinToString(",")

        return KernelModulesSnapshot(
            entries = entries,
            configuredNames = configuredNames,
            activeNames = activeNames,
            suggestedNames = suggestions,
            deviceBlocklistNames = visibleDeviceBlocklist,
            hiddenDeviceBlocklistCount = hiddenDeviceBlocklist.size,
            paramsNames = paramsNames,
            paramsSource = paramsSource,
            paramsConfigLine = if (paramsNames.isEmpty()) "" else "block_modules=$paramsValue",
            paramsCliLine = if (paramsNames.isEmpty()) "" else "--block-module $paramsValue",
            paramsTooLong = paramsValue.length > MAX_BLOCK_MODULES_LEN,
            activeAvailable = raw.activeReadable || activeFromCmdline.isNotEmpty(),
            configAvailable = raw.configReadable || configFromCmdline.isNotEmpty(),
            dependencyDataAvailable = deps.isNotEmpty(),
            activeSource = activeSource,
            currentlyLoadedCount = entries.count {
                it.loaded && (it.active || it.configured || it.deviceBlocklist)
            },
            affectedBootModules = affected.size,
        )
    }

    /**
     * The repository prints one section at a time around files that may not
     * exist, so empty and unreadable are distinguishable.
     */
    fun parseShellOutput(lines: List<String>): KernelModulesRaw {
        var section = ""
        var activeReadable = false
        var configReadable = false
        var depReadable = false
        var modulesDir: String? = null
        val buffers = HashMap<String, StringBuilder>()

        lines.forEach { rawLine ->
            val line = rawLine.trimEnd('\r')
            when {
                line.startsWith(SECTION_MARKER) -> {
                    section = line.removePrefix(SECTION_MARKER).trim()
                }

                line.startsWith(FLAG_MARKER) -> {
                    val flag = line.removePrefix(FLAG_MARKER).trim()
                    val key = flag.substringBefore('=')
                    val value = flag.substringAfter('=', "")
                    when (key) {
                        "active" -> activeReadable = value == "1"
                        "config" -> configReadable = value == "1"
                        "dep" -> depReadable = value == "1"
                        "dir" -> modulesDir = value.ifBlank { null }
                    }
                }

                section.isNotEmpty() -> {
                    buffers.getOrPut(section) { StringBuilder() }.appendLine(line)
                }
            }
        }

        return KernelModulesRaw(
            active = buffers["active"]?.toString(),
            activeReadable = activeReadable,
            config = buffers["config"]?.toString(),
            configReadable = configReadable,
            cmdline = buffers["cmdline"]?.toString(),
            procModules = buffers["proc"]?.toString(),
            modulesDep = if (depReadable) buffers["dep"]?.toString() else null,
            modulesLoad = if (depReadable) buffers["load"]?.toString() else null,
            modulesBlocklist = if (depReadable) buffers["blocklist"]?.toString() else null,
            modulesDir = modulesDir,
        )
    }

    private const val SECTION_MARKER = "__KSU_SECTION__"
    private const val FLAG_MARKER = "__KSU_FLAG__"
}
