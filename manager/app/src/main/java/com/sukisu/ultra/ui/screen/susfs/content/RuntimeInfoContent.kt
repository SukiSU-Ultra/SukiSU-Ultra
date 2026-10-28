package com.sukisu.ultra.ui.screen.susfs.content

import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.screen.susfs.SuSFSRuntimeInfo
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun RuntimeInfoContent(info: SuSFSRuntimeInfo?) {
    val miuix = LocalUiMode.current == UiMode.Miuix
    val unknown = stringResource(R.string.susfs_runtime_unknown)
    val variant = when (info?.variant?.trim()?.lowercase()?.replace("_", "-")?.removeSuffix("-lkm")) {
        "gki" -> "GKI"
        "non-gki", "nongki", "nogki" -> "Non-GKI"
        else -> info?.variant?.takeUnless { it.equals("unsupport", true) } ?: unknown
    }
    val rows = listOf(
        stringResource(R.string.susfs_runtime_version) to (info?.version ?: unknown),
        stringResource(R.string.susfs_runtime_variant) to variant,
        stringResource(R.string.susfs_runtime_implementation) to (info?.implementation ?: unknown),
    )
    val body: @Composable () -> Unit = {
        Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (miuix) MiuixText("SuSFS", style = MiuixTheme.textStyles.title3)
            else Text("SuSFS", style = MaterialTheme.typography.titleLarge)
            rows.forEach { (label, value) ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    if (miuix) {
                        MiuixText(label, Modifier.weight(1f), color = MiuixTheme.colorScheme.onSurfaceVariantSummary)
                        MiuixText(value, Modifier.weight(1f))
                    } else {
                        Text(label, Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(value, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
    }
    if (miuix) AppCard(Modifier.fillMaxWidth()) { body() }
    else Surface(
        shape = MaterialTheme.shapes.extraLarge,
        color = backgroundAwareColor(MaterialTheme.colorScheme.surfaceContainerLow),
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) { body() }
}
