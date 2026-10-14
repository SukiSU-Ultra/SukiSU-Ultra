package com.sukisu.ultra.ui.screen.dynamicmanagers

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun DynamicManagersMiuix(
    state: DynamicManagerState?, apps: List<InstalledApp>, busy: Boolean, error: String?, actions: DynamicManagersActions
) {
    Scaffold(topBar = {
        TopAppBar(
            title = stringResource(R.string.dynamic_manager_title),
            navigationIcon = { IconButton(onClick = actions.onBack) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = null) } },
            actions = { IconButton(onClick = actions.onRefresh) { Icon(Icons.Rounded.Refresh, contentDescription = null) } }
        )
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            state?.let { current ->
                SwitchPreference(
                    title = stringResource(R.string.dynamic_manager_enabled),
                    checked = current.enabled,
                    onCheckedChange = actions.onSetEnabled,
                )
            }
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            error?.let { Text(it, Modifier.padding(16.dp), color = MiuixTheme.colorScheme.error) }
            ArrowPreference(
                title = stringResource(R.string.dynamic_manager_add),
                startAction = { Icon(Icons.Rounded.Add, contentDescription = null, tint = MiuixTheme.colorScheme.onBackground) },
                onClick = actions.onLoadApps,
                enabled = !busy,
            )
            LazyColumn(Modifier.fillMaxSize()) {
                items(state?.entries.orEmpty(), key = { it.packageName }) { entry ->
                    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(entry.packageName)
                            Text("${entry.certSize} bytes · ${entry.hash}")
                        }
                        IconButton(onClick = { actions.onRemove(entry.packageName) }) {
                            Icon(Icons.Rounded.Delete, contentDescription = stringResource(R.string.dynamic_manager_remove))
                        }
                    }
                }
                if (apps.isNotEmpty()) {
                    item { Text(stringResource(R.string.dynamic_manager_select_app), Modifier.padding(16.dp)) }
                    items(apps.filterNot { app -> state?.entries?.any { it.packageName == app.packageName } == true }, key = { it.packageName }) { app ->
                        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                            Column(Modifier.weight(1f)) {
                                Text(app.label)
                                Text(app.packageName)
                            }
                            IconButton(onClick = { actions.onAdd(app) }) {
                                Icon(Icons.Rounded.Add, contentDescription = stringResource(R.string.dynamic_manager_authorize, app.label))
                            }
                        }
                    }
                }
            }
        }
    }
}
