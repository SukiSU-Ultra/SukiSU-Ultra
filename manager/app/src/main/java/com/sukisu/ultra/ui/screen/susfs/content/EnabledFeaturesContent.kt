package com.sukisu.ultra.ui.screen.susfs.content

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.screen.susfs.util.EnabledFeature
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun EnabledFeaturesContent(
    enabledFeatures: List<EnabledFeature>,
    onRefresh: () -> Unit,
    isLoading: Boolean = false,
) {
    val miuix = LocalUiMode.current == UiMode.Miuix
    val enabledCount = enabledFeatures.count { it.isEnabled }
    val summary = stringResource(R.string.susfs_features_summary, enabledCount, enabledFeatures.size)
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        val overview: @Composable () -> Unit = {
            Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (miuix) {
                    MiuixText(summary, style = MiuixTheme.textStyles.title3)
                    MiuixText(stringResource(R.string.susfs_enabled_features_description), style = MiuixTheme.textStyles.body2, color = MiuixTheme.colorScheme.onSurfaceVariantSummary)
                } else {
                    Text(summary, style = MaterialTheme.typography.headlineSmall)
                    Text(stringResource(R.string.susfs_enabled_features_description), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSecondaryContainer)
                }
            }
        }
        if (miuix) AppCard(Modifier.fillMaxWidth()) { overview() }
        else Surface(
            shape = MaterialTheme.shapes.extraLarge,
            color = backgroundAwareColor(MaterialTheme.colorScheme.secondaryContainer),
            contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        ) { overview() }

        if (enabledFeatures.isEmpty() && !isLoading) {
            FeatureLabel(stringResource(R.string.susfs_no_features_found), miuix)
        }
        listOf(true, false).forEach { enabled ->
            val features = enabledFeatures.filter { it.isEnabled == enabled }
            if (features.isNotEmpty()) {
                val label = stringResource(if (enabled) R.string.susfs_feature_enabled else R.string.susfs_feature_disabled)
                FeatureLabel("$label (${features.size})", miuix)
                if (miuix) {
                    AppCard(Modifier.fillMaxWidth()) {
                        features.forEach { feature ->
                                Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                    MiuixText(feature.name, modifier = Modifier.weight(1f))
                                    MiuixText(feature.statusText, style = MiuixTheme.textStyles.body2,
                                        color = if (enabled) MiuixTheme.colorScheme.primary else MiuixTheme.colorScheme.onSurfaceVariantSummary)
                                }
                        }
                    }
                } else {
                    SegmentedColumn(content = features.map { feature ->
                        {
                                SegmentedListItem(
                                    headlineContent = { Text(feature.name) },
                                    trailingContent = {
                                        Text(feature.statusText, style = MaterialTheme.typography.labelMedium,
                                            color = if (enabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                                    },
                                )
                        }
                    })
                }
            }
        }
        if (miuix) {
            MiuixTextButton(stringResource(R.string.refresh), onClick = onRefresh, enabled = !isLoading, modifier = Modifier.fillMaxWidth())
        } else {
            FilledTonalButton(
                onClick = onRefresh,
                enabled = !isLoading,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                colors = ButtonDefaults.filledTonalButtonColors(
                    containerColor = backgroundAwareColor(MaterialTheme.colorScheme.secondaryContainer),
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                ),
            ) {
                Text(stringResource(R.string.refresh))
            }
        }
    }
}

@Composable
private fun FeatureLabel(text: String, miuix: Boolean) {
    if (miuix) MiuixText(text, modifier = Modifier.padding(horizontal = 12.dp), style = MiuixTheme.textStyles.body2, color = MiuixTheme.colorScheme.onSurfaceVariantSummary)
    else Text(text, modifier = Modifier.padding(horizontal = 12.dp), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}
