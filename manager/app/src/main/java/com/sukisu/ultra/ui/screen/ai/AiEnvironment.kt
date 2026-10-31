package com.sukisu.ultra.ui.screen.ai

import android.os.Build
import android.os.SystemClock
import android.system.Os
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.screen.home.getManagerVersion
import com.sukisu.ultra.ui.util.getKpmModuleCount
import com.sukisu.ultra.ui.util.getKpmVersion
import com.sukisu.ultra.ui.util.getSELinuxStatusRaw
import com.sukisu.ultra.ui.util.getSuSFSStatus
import com.sukisu.ultra.ui.util.getSuSFSVersion
import com.sukisu.ultra.ui.util.getSuperuserCount
import com.sukisu.ultra.ui.util.listModules
import com.sukisu.ultra.ui.util.resolveDeviceName
import com.sukisu.ultra.ui.util.rootAvailable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.json.JSONArray

/**
 * Snapshot attached to the system prompt (and returned by the read-only
 * `get_environment` tool). Scopes that the user disabled are omitted entirely
 * and their root probes are not executed.
 */
object AiEnvironment {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private var cachedAt = 0L
    private var cached = ""
    private var cachedKey = ""
    private const val CACHE_MS = 15_000L

    suspend fun snapshot(config: AiConfig, force: Boolean = false): String =
        withContext(Dispatchers.IO) {
            val key = scopeKey(config)
            val now = SystemClock.elapsedRealtime()
            if (!force && key == cachedKey && cached.isNotEmpty() && now - cachedAt < CACHE_MS) {
                return@withContext cached
            }
            val value = buildSnapshot(config)
            cached = value
            cachedAt = now
            cachedKey = key
            value
        }

    private fun scopeKey(config: AiConfig): String = listOf(
        config.allowRootAccess,
        config.allowSuperuserAccess,
        config.allowModuleAccess,
        config.allowExtensionAccess,
        config.allowWebAccess,
        config.allowThemeRead,
        config.includeContext,
    ).joinToString("|")

    private suspend fun buildSnapshot(config: AiConfig): String {
        val manager = runCatching { getManagerVersion(ksuApp) }.getOrNull()
        val root = config.allowRootAccess && runCatching { rootAvailable() }.getOrDefault(false)
        val modules = if (root && config.allowModuleAccess) {
            runCatching { listModules() }.getOrNull()
        } else {
            null
        }
        val moduleArray = runCatching { JSONArray(modules ?: "[]") }.getOrNull()
        val superuserCount = if (root && config.allowSuperuserAccess) {
            runCatching { getSuperuserCount() }.getOrNull()
        } else {
            null
        }
        val extensions = if (root && config.allowExtensionAccess) {
            runCatching { AiExtensionsController.readOverview() }.getOrNull()
        } else {
            null
        }

        return buildJsonObject {
            put("access", buildJsonObject {
                put("root", config.allowRootAccess)
                put("superuser", config.allowSuperuserAccess)
                put("modules", config.allowModuleAccess)
                put("extensions", config.allowExtensionAccess)
                put("theme", config.allowThemeRead)
                put("web", config.allowWebAccess)
                put("superuser_root_control", config.allowSuperuserRootControl)
                put("superuser_temporary_root", config.allowSuperuserTemporaryRoot)
                put("superuser_switch", config.allowSuperuserSwitch)
            })
            put("manager", buildJsonObject {
                put("name", ksuApp.applicationInfo.loadLabel(ksuApp.packageManager).toString())
                put("package", ksuApp.packageName)
                put("version_name", manager?.versionName ?: "unknown")
                put("version_code", manager?.versionCode?.toString() ?: "0")
                put("manager_available", runCatching { Natives.isManager }.getOrDefault(false))
                put("ksu_version", runCatching { Natives.version }.getOrNull()?.toString() ?: "")
                put("manager_uapi", runCatching { Natives.managerUAPIVersion }.getOrDefault(0))
                put("kernel_uapi", runCatching { Natives.kernelUAPIVersion }.getOrNull()?.toString() ?: "")
                put("lkm_mode", runCatching { Natives.isLkmMode }.getOrNull()?.toString() ?: "")
                put("lkm_bundled", runCatching { Natives.isLkmBundled }.getOrNull()?.toString() ?: "")
                put("late_load", runCatching { Natives.isLateLoadMode }.getOrDefault(false))
                put("safe_mode", runCatching { Natives.isSafeMode }.getOrDefault(false))
                put("pr_build", runCatching { Natives.isPrBuild }.getOrDefault(false))
            })
            put("device", buildJsonObject {
                put("model", runCatching { resolveDeviceName() }.getOrDefault(Build.MODEL))
                put("manufacturer", Build.MANUFACTURER)
                put("brand", Build.BRAND)
                put("android_release", Build.VERSION.RELEASE)
                put("sdk", Build.VERSION.SDK_INT)
                put("abi", Build.SUPPORTED_ABIS.joinToString(", "))
                put("fingerprint", Build.FINGERPRINT)
                put("kernel", runCatching { Os.uname().release }.getOrDefault("unknown"))
                put("selinux", runCatching { getSELinuxStatusRaw() }.getOrDefault("unknown"))
                if (config.allowRootAccess) put("root_available", root)
                if (superuserCount != null) put("superuser_count", superuserCount)
            })
            if (config.allowModuleAccess && root) {
                put("installed_modules", buildJsonArray {
                    if (moduleArray != null) {
                        for (index in 0 until minOf(moduleArray.length(), 30)) {
                            val module = moduleArray.optJSONObject(index) ?: continue
                            add(buildJsonObject {
                                put("id", module.optString("id"))
                                put("name", module.optString("name"))
                                put("version", module.optString("version"))
                                put("enabled", module.optBoolean("enabled"))
                                put("update", module.optBoolean("update"))
                            })
                        }
                    }
                })
            }
            if (extensions != null) {
                put("extensions", runCatching { json.parseToJsonElement(extensions) }
                    .getOrDefault(buildJsonObject { }))
            }
            if (config.allowThemeRead) {
                put("appearance", runCatching {
                    json.parseToJsonElement(AiThemeController.summaryJson())
                }.getOrDefault(buildJsonObject { }))
            }
            if (config.allowExtensionAccess && root) {
                put("susfs", buildJsonObject {
                    put("status", runCatching { getSuSFSStatus() }.getOrDefault(""))
                    put("version", runCatching { getSuSFSVersion() }.getOrDefault(""))
                })
                put("kpm", buildJsonObject {
                    put("version", runCatching { getKpmVersion() }.getOrDefault(""))
                    put("loaded_count", runCatching { getKpmModuleCount() }.getOrDefault(0))
                })
            }
        }.toString()
    }
}
