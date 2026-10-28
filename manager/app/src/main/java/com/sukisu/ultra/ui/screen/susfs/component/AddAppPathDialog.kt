package com.sukisu.ultra.ui.screen.susfs.component

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.AppIconImage
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.screen.susfs.util.AppInfo
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextField as MiuixTextField
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.basic.Checkbox as MiuixCheckbox
import top.yukonga.miuix.kmp.basic.ButtonDefaults as MiuixButtonDefaults
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.window.WindowDialog

@Composable
fun AddAppPathDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (List<String>) -> Unit,
    isLoading: Boolean,
    apps: List<AppInfo> = emptyList(),
    isLoadingApps: Boolean = false,
    onLoadApps: () -> Unit,
    existingSusPaths: Set<String> = emptySet(),
) {
    if (!showDialog) return
    val miuix = LocalUiMode.current == UiMode.Miuix
    var query by remember { mutableStateOf("") }
    var selected by remember { mutableStateOf(emptySet<String>()) }
    val existing = remember(existingSusPaths) {
        existingSusPaths.mapNotNull { Regex("/Android/data/([^/]+)").find(it)?.groupValues?.get(1) }.toSet()
    }
    val available = remember(apps, existing) { apps.filter { it.packageName !in existing }.distinctBy { it.packageName } }
    val filtered = remember(available, query) {
        available.filter { it.appName.contains(query.trim(), true) || it.packageName.contains(query.trim(), true) }
    }
    val selectedPackages = available.filter { it.packageName in selected }.map { it.packageName }
    val enabled = !isLoading && !isLoadingApps
    LaunchedEffect(Unit) { onLoadApps() }

    val body: @Composable () -> Unit = {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (miuix) {
                MiuixTextField(
                    value = query, onValueChange = { query = it },
                    label = stringResource(R.string.search_apps), useLabelAsPlaceholder = true,
                    singleLine = true, modifier = Modifier.fillMaxWidth(),
                )
            } else {
                OutlinedTextField(
                    value = query, onValueChange = { query = it },
                    placeholder = { Text(stringResource(R.string.search_apps)) },
                    singleLine = true, shape = RoundedCornerShape(24.dp), modifier = Modifier.fillMaxWidth(),
                )
            }
            if (isLoadingApps) {
                if (miuix) top.yukonga.miuix.kmp.basic.LinearProgressIndicator(Modifier.fillMaxWidth())
                else LinearWavyProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            LazyColumn(
                modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp, max = 360.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                if (!isLoadingApps && filtered.isEmpty()) {
                    item {
                        val message = stringResource(R.string.no_apps_found)
                        if (miuix) MiuixText(message, Modifier.padding(16.dp))
                        else Text(message, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                items(filtered, key = { it.packageName }) { app ->
                    val checked = app.packageName in selected
                    val toggle = { selected = if (checked) selected - app.packageName else selected + app.packageName }
                    val row: @Composable () -> Unit = {
                        Row(
                            Modifier.fillMaxWidth().toggleable(checked, enabled = enabled, role = Role.Checkbox, onValueChange = { toggle() }).padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            AppIconImage(packageInfo = app.packageInfo, label = app.appName, modifier = Modifier.size(44.dp).clip(RoundedCornerShape(12.dp)))
                            Column(Modifier.weight(1f)) {
                                if (miuix) {
                                    MiuixText(app.appName, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    MiuixText(app.packageName, style = MiuixTheme.textStyles.body2, color = MiuixTheme.colorScheme.onSurfaceVariantSummary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                } else {
                                    Text(app.appName, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                            }
                            if (miuix) MiuixCheckbox(state = androidx.compose.ui.state.ToggleableState(checked), onClick = null, enabled = enabled)
                            else Checkbox(checked = checked, onCheckedChange = null, enabled = enabled)
                        }
                    }
                    if (miuix) {
                        AppCard(
                            colors = top.yukonga.miuix.kmp.basic.CardDefaults.defaultColors(color = if (checked) MiuixTheme.colorScheme.secondaryContainer else backgroundAwareColor(MiuixTheme.colorScheme.surfaceContainer)),
                        ) { row() }
                    } else {
                        Surface(shape = RoundedCornerShape(20.dp), color = if (checked) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceContainerLow) { row() }
                    }
                }
            }
        }
    }
    val confirmText = stringResource(R.string.add) + if (selectedPackages.isNotEmpty()) " (${selectedPackages.size})" else ""
    if (miuix) {
        WindowDialog(show = true, title = stringResource(R.string.susfs_add_app_path), onDismissRequest = { if (!isLoading) onDismiss() }) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                body()
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    MiuixTextButton(stringResource(R.string.cancel), onClick = onDismiss, enabled = !isLoading, modifier = Modifier.weight(1f))
                    MiuixTextButton(confirmText, onClick = { onConfirm(selectedPackages) }, enabled = enabled && selectedPackages.isNotEmpty(), modifier = Modifier.weight(1f), colors = MiuixButtonDefaults.textButtonColorsPrimary())
                }
            }
        }
    } else {
        AlertDialog(
            onDismissRequest = { if (!isLoading) onDismiss() },
            title = { Text(stringResource(R.string.susfs_add_app_path)) },
            text = body,
            confirmButton = { TextButton(onClick = { onConfirm(selectedPackages) }, enabled = enabled && selectedPackages.isNotEmpty()) { Text(confirmText) } },
            dismissButton = { TextButton(onClick = onDismiss, enabled = !isLoading) { Text(stringResource(R.string.cancel)) } },
        )
    }
}
