package com.sukisu.ultra.ui.screen.home

import android.content.Context
import android.os.Build
import android.system.Os
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.pm.PackageInfoCompat
import com.sukisu.ultra.Natives
import com.sukisu.ultra.Natives.isManager
import com.sukisu.ultra.ui.util.getSuSFSStatus
import com.sukisu.ultra.ui.util.getSuSFSVersion

data class ManagerVersion(
    val versionName: String,
    val versionCode: Long
)

data class SystemInfo(
    val kernelVersion: String,
    val managerVersion: String,
    val deviceModel: String,
    val kernelFullVersion: String?,
    val fingerprint: String,
    val selinuxStatus: String,
    val seccompStatus: Int,
    val zygiskImplementation: String? = null,
)

fun getZygiskImplementation(
    notInstalledText: String,
    disabledText: String,
    rebootRequiredText: String,
): String {
    return runCatching {
        val modulesJson = com.sukisu.ultra.ui.util.listModules()
        val array = org.json.JSONArray(modulesJson)
        val providers = mutableListOf<org.json.JSONObject>()
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            val isProvider = (obj.optInt("zygisk_provider") != 0) || obj.optBoolean("zygisk_provider")
            if (isProvider) {
                providers.add(obj)
            }
        }

        if (providers.isEmpty()) {
            return notInstalledText
        }

        // 1. Check if any provider's daemon is actively running
        val runningProvider = providers.firstOrNull {
            (it.optInt("zygisk_running") != 0) || it.optBoolean("zygisk_running")
        }
        if (runningProvider != null) {
            val name = runningProvider.optString("name").takeIf { it.isNotBlank() }
                ?: runningProvider.getString("id")
            val version = runningProvider.optString("version").takeIf { it.isNotBlank() }
            return listOfNotNull(name, version).joinToString(" ")
        }

        // 2. If none is running, check enabled status
        val enabledProviders = providers.filter {
            it.optBoolean("enabled", false) && !it.optBoolean("remove", false)
        }
        if (enabledProviders.isNotEmpty()) {
            val names = enabledProviders.joinToString(", ") {
                it.optString("name").takeIf { name -> name.isNotBlank() } ?: it.getString("id")
            }
            return "$names ($rebootRequiredText)"
        }

        // 3. All installed providers are disabled
        val names = providers.joinToString(", ") {
            it.optString("name").takeIf { name -> name.isNotBlank() } ?: it.getString("id")
        }
        return "$names ($disabledText)"
    }.getOrDefault(notInstalledText)
}


fun getManagerVersion(context: Context): ManagerVersion {
    val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)!!
    val versionCode = PackageInfoCompat.getLongVersionCode(packageInfo)
    return ManagerVersion(
        versionName = packageInfo.versionName!!,
        versionCode = versionCode
    )
}

enum class SusfsStatus {
    Idle, Supported, Unsupported, Error
}

data class SusfsInfoState(
    val status: SusfsStatus = SusfsStatus.Idle,
    val detail: String = "",
)

@Composable
fun rememberSusfsInfo(
    manualHookLabel: String,
    inlineHookLabel: String,
): SusfsInfoState {
    return remember(manualHookLabel, inlineHookLabel) {
        runCatching {
            val supported = getSuSFSStatus().equals("true", ignoreCase = true)
            if (supported) {
                val version = getSuSFSVersion().trim()
                val hookLabel = when (val type = Natives.getHookType()) {
                    "Manual" -> manualHookLabel
                    "Inline" -> inlineHookLabel
                    else -> type
                }.takeIf { it.isNotBlank() }?.let { "($it)" }.orEmpty()
                SusfsInfoState(
                    status = SusfsStatus.Supported,
                    detail = listOf(version, hookLabel)
                        .filter { it.isNotBlank() }
                        .joinToString(" ")
                )
            } else {
                SusfsInfoState(
                    status = SusfsStatus.Unsupported,
                    detail = ""
                )
            }
        }.getOrElse {
            SusfsInfoState(status = SusfsStatus.Error)
        }
    }
}

@Composable
fun rememberHookTypeLabel(
    manualHookText: String,
    inlineHookText: String,
    tracepointHookText: String,
    unknownHookText: String,
): String? {
    return remember(manualHookText, inlineHookText, tracepointHookText, unknownHookText) {
        if (!isManager) return@remember null
        val rawType = runCatching { Natives.getHookType() }.getOrNull() ?: return@remember null
        when (rawType) {
            "Manual" -> manualHookText
            "Tracepoint" -> tracepointHookText
            else -> rawType.ifBlank { unknownHookText }
        }
    }
}
