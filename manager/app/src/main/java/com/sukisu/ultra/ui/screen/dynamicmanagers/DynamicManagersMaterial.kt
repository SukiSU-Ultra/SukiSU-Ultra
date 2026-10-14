package com.sukisu.ultra.ui.screen.dynamicmanagers

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R

@Composable
internal fun DynamicManagersMaterial(
    state: DynamicManagerState?, apps: List<InstalledApp>, busy: Boolean, error: String?, actions: DynamicManagersActions
) {
    Scaffold(topBar = {
        TopAppBar(
            title = { Text(stringResource(R.string.dynamic_manager_title)) },
            navigationIcon = { IconButton(onClick = actions.onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null) } },
            actions = { IconButton(onClick = actions.onRefresh) { Icon(Icons.Filled.Refresh, contentDescription = null) } }
        )
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            state?.let { current ->
                Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.dynamic_manager_enabled))
                    Switch(checked = current.enabled, onCheckedChange = actions.onSetEnabled)
                }
            }
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp), horizontalArrangement = Arrangement.End) {
                OutlinedButton(onClick = actions.onLoadApps, enabled = !busy) {
                    Icon(Icons.Filled.Add, contentDescription = null)
                    Text(stringResource(R.string.dynamic_manager_add))
                }
            }
            error?.let { Text(it, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.error) }
            LazyColumn {
                items(state?.entries.orEmpty(), key = { it.packageName }) { entry ->
                    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(entry.packageName)
                            Text("${entry.certSize} bytes · ${entry.hash}", style = MaterialTheme.typography.bodySmall)
                        }
                        IconButton(onClick = { actions.onRemove(entry.packageName) }) {
                            Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.dynamic_manager_remove))
                        }
                    }
                }
                if (apps.isNotEmpty()) {
                    item { Text(stringResource(R.string.dynamic_manager_select_app), Modifier.padding(16.dp), style = MaterialTheme.typography.titleSmall) }
                    items(apps.filterNot { app -> state?.entries?.any { it.packageName == app.packageName } == true }, key = { it.packageName }) { app ->
                        ListItem(
                            modifier = Modifier.fillMaxWidth().clickable { actions.onAdd(app) },
                            supportingContent = { Text(app.packageName) },
                            trailingContent = { Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.dynamic_manager_authorize, app.label)) },
                        ) {
                            Text(app.label)
                        }
                    }
                }
            }
        }
    }
}
