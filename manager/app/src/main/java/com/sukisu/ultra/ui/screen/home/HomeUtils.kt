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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

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
    modulesJson: String,
    notInstalledText: String,
    disabledText: String,
    rebootRequiredText: String,
): String {
    return runCatching {
        val providers = Json.parseToJsonElement(modulesJson).jsonArray
            .map { it.jsonObject }
            .filter { it.zygiskFlag("zygisk_provider") }

        if (providers.isEmpty()) {
            return notInstalledText
        }

        // Running takes priority even when a provider was disabled/removed pending reboot.
        val runningProvider = providers.firstOrNull { it.zygiskFlag("zygisk_running") }
        if (runningProvider != null) {
            val version = runningProvider.stringValue("version").takeIf { it.isNotBlank() }
            return listOfNotNull(runningProvider.providerName(), version).joinToString(" ")
        }

        val enabledProviders = providers.filter {
            it.booleanValue("enabled") && !it.booleanValue("remove")
        }
        if (enabledProviders.isNotEmpty()) {
            val names = enabledProviders.joinToString(", ") { it.providerName() }
            return "$names ($rebootRequiredText)"
        }

        val names = providers.joinToString(", ") { it.providerName() }
        "$names ($disabledText)"
    }.getOrDefault(notInstalledText)
}

fun getHomeModuleCount(modulesJson: String): Int =
    runCatching { Json.parseToJsonElement(modulesJson).jsonArray.size }.getOrDefault(0)

private fun JsonObject.stringValue(key: String): String = when (val value = this[key]) {
    null -> ""
    is JsonPrimitive -> value.content
    else -> value.toString()
}

private fun JsonObject.booleanValue(key: String): Boolean =
    stringValue(key).equals("true", ignoreCase = true)

private fun JsonObject.zygiskFlag(key: String): Boolean {
    // Match the old optInt/optBoolean coercion, including numeric and boolean strings.
    val number = stringValue(key).toDoubleOrNull()?.toInt() ?: 0
    return number != 0 || booleanValue(key)
}

private fun JsonObject.providerName(): String =
    stringValue("name").takeIf { it.isNotBlank() }
        ?: stringValue("id").also { require(containsKey("id")) }


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
