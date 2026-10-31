package com.sukisu.ultra.ai.host

import com.sukisu.ultra.ai.api.*

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
object AiEnvironment : AiEnvironmentService {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private var cachedAt = 0L
    private var cached = ""
    private var cachedKey = ""
    private const val CACHE_MS = 15_000L

    override suspend fun snapshot(scopes: AiEnvironmentScopes, force: Boolean): String =
        withContext(Dispatchers.IO) {
            val key = scopeKey(scopes)
            val now = SystemClock.elapsedRealtime()
            if (!force && key == cachedKey && cached.isNotEmpty() && now - cachedAt < CACHE_MS) {
                return@withContext cached
            }
            val value = buildSnapshot(scopes)
            cached = value
            cachedAt = now
            cachedKey = key
            value
        }

    private fun scopeKey(scopes: AiEnvironmentScopes): String = listOf(
        scopes.root,
        scopes.superuser,
        scopes.modules,
        scopes.extensions,
        scopes.web,
        scopes.theme,
        scopes.includeContext,
    ).joinToString("|")

    private suspend fun buildSnapshot(scopes: AiEnvironmentScopes): String {
        val manager = runCatching { getManagerVersion(ksuApp) }.getOrNull()
        val root = scopes.root && runCatching { rootAvailable() }.getOrDefault(false)
        val modules = if (root && scopes.modules) {
            runCatching { listModules() }.getOrNull()
        } else {
            null
        }
        val moduleArray = runCatching { JSONArray(modules ?: "[]") }.getOrNull()
        val superuserCount = if (root && scopes.superuser) {
            runCatching { getSuperuserCount() }.getOrNull()
        } else {
            null
        }
        val extensions = if (root && scopes.extensions) {
            runCatching { AiExtensionsController.readOverview() }.getOrNull()
        } else {
            null
        }

        return buildJsonObject {
            put("access", buildJsonObject {
                put("root", scopes.root)
                put("superuser", scopes.superuser)
                put("modules", scopes.modules)
                put("extensions", scopes.extensions)
                put("theme", scopes.theme)
                put("web", scopes.web)
                put("superuser_root_control", scopes.superuserRootControl)
                put("superuser_temporary_root", scopes.superuserTemporaryRoot)
                put("superuser_switch", scopes.superuserSwitch)
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
                if (scopes.root) put("root_available", root)
                if (superuserCount != null) put("superuser_count", superuserCount)
            })
            if (scopes.modules && root) {
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
            if (scopes.theme) {
                put("appearance", runCatching {
                    json.parseToJsonElement(AiThemeController.summaryJson())
                }.getOrDefault(buildJsonObject { }))
            }
            if (scopes.extensions && root) {
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
