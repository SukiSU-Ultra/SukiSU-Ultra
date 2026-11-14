package com.sukisu.ultra.ui.component

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import top.yukonga.miuix.kmp.basic.Text as MiuixText


enum class ConfigRuntimeStatus(val labelRes: Int) {
    APPLIED(R.string.config_status_applied),
    REBOOT_REQUIRED(R.string.config_status_reboot),
    UNSUPPORTED(R.string.config_status_unsupported),
    FAILED(R.string.config_status_failed),
    MISMATCH(R.string.config_status_mismatch),
    UNVERIFIED(R.string.config_status_unverified),
}

data class ConfigResult(
    val name: String,
    val saved: Boolean?,
    val runtime: ConfigRuntimeStatus,
    val reason: String? = null,
) {
    fun description(context: Context): String = buildString {
        append(context.getString(when (saved) {
            true -> R.string.config_saved
            false -> R.string.config_not_saved
            null -> R.string.config_save_unknown
        }))
        if (runtime == ConfigRuntimeStatus.REBOOT_REQUIRED && saved == true) {
            clear()
        } else append(" | ")
        append(context.getString(runtime.labelRes))
        reason?.takeIf { it.isNotBlank() }?.let { append(": "); append(it) }
    }
}

@Composable
fun ConfigResults(results: List<ConfigResult>) {
    if (results.isEmpty()) return
    val context = LocalContext.current
    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        results.forEach { result ->
            val text = result.name + "\n" + result.description(context)
            if (LocalUiMode.current == UiMode.Miuix) MiuixText(text)
            else Text(text, style = MaterialTheme.typography.bodyMedium)
        }
    }
}


fun resolveRuntimeStatus(supported: Boolean?, expected: Boolean, actual: Boolean?): ConfigRuntimeStatus = when {
    supported == false -> ConfigRuntimeStatus.UNSUPPORTED
    actual == null -> ConfigRuntimeStatus.UNVERIFIED
    actual == expected -> ConfigRuntimeStatus.APPLIED
    else -> ConfigRuntimeStatus.MISMATCH
}

@Composable
fun ConfigStatusNote(text: String) {
    if (LocalUiMode.current == UiMode.Miuix) MiuixText(text, Modifier.padding(16.dp))
    else Text(text, Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium)
}
