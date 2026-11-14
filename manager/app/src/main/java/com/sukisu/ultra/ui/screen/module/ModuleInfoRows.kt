package com.sukisu.ultra.ui.screen.module

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.Resources
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.compose.runtime.Immutable
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.Module
import com.sukisu.ultra.data.model.ModuleUpdateInfo

/**
 * One label/value pair in the long-press module information dialog. [key] is only used as a
 * stable list key; every non-empty value can be copied on its own.
 */
@Immutable
data class ModuleInfoRow(
    val key: String,
    val label: String,
    val value: String,
    val monospace: Boolean = false,
) {
    val copyable: Boolean get() = value.isNotBlank()
}

fun moduleInfoRows(
    resources: Resources,
    module: Module,
    updateInfo: ModuleUpdateInfo?,
): List<ModuleInfoRow> {
    val rows = mutableListOf<ModuleInfoRow>()
    val none = resources.getString(R.string.module_info_none)

    fun add(key: String, @StringRes label: Int, value: String, monospace: Boolean = false) {
        rows += ModuleInfoRow(
            key = key,
            label = resources.getString(label),
            value = value.ifBlank { none },
            monospace = monospace,
        )
    }

    add("name", R.string.module_info_name, module.name)
    add("id", R.string.module_info_id, module.id, monospace = true)
    add("author", R.string.module_info_author, module.author)
    add("version", R.string.module_info_version, module.version)
    add("versionCode", R.string.module_info_version_code, module.versionCode.toString(), monospace = true)
    add("description", R.string.module_info_description, module.description)

    val status = buildList {
        add(
            resources.getString(
                if (module.enabled) R.string.module_info_status_enabled else R.string.module_info_status_disabled
            )
        )
        if (module.update) add(resources.getString(R.string.module_info_status_pending_update))
        if (module.remove) add(resources.getString(R.string.module_info_status_pending_removal))
    }.joinToString(" · ")
    add("status", R.string.module_info_status, status)

    val features = buildList {
        if (module.hasWebUi) add("WebUI")
        if (module.hasActionScript) add("Action")
        if (module.metamodule) add("MetaModule")
        if (module.zygisk) add("Zygisk")
    }.joinToString(", ")
    add("features", R.string.module_info_features, features)

    if (module.preinit.isNotEmpty()) {
        val preinit = if (module.preinit == "ok") {
            resources.getString(R.string.module_info_preinit_ok)
        } else {
            module.preinitWarning()?.let { resources.getString(it) } ?: module.preinit
        }
        add("preinit", R.string.module_info_preinit, preinit)
    }

    add("updateUrl", R.string.module_info_update_url, module.updateJson, monospace = true)
    updateInfo?.version?.takeIf { it.isNotBlank() }?.let { version ->
        add("latestVersion", R.string.module_info_latest_version, version)
    }
    updateInfo?.downloadUrl?.takeIf { it.isNotBlank() }?.let { downloadUrl ->
        add("downloadUrl", R.string.module_info_download_url, downloadUrl, monospace = true)
    }
    updateInfo?.changelog?.takeIf { it.isNotBlank() }?.let { changelog ->
        add("changelog", R.string.module_info_changelog, changelog)
    }

    add("directory", R.string.module_info_directory, "/data/adb/modules/${module.id}", monospace = true)
    add("banner", R.string.module_info_banner_path, module.bannerPath.orEmpty(), monospace = true)

    return rows
}

fun moduleInfoText(rows: List<ModuleInfoRow>): String =
    rows.joinToString("\n") { row -> "${row.label}: ${row.value}" }

@Suppress("UsePropertyAccessSyntax")
fun copyModuleInfo(context: Context, value: String, feedback: String) {
    if (value.isBlank()) return
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("SukiSU module info", value))
    Toast.makeText(context, feedback, Toast.LENGTH_SHORT).show()
}
