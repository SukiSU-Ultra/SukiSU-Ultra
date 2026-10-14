package com.sukisu.ultra.ui.screen.dynamicmanagers

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.surfaceColorAtElevation
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.AppIconImage
import com.sukisu.ultra.ui.component.material.SearchAppBar
import com.sukisu.ultra.ui.util.DynamicManagerEntry
import com.sukisu.ultra.ui.util.DynamicManagerState

@Composable
internal fun DynamicManagersMaterial(
    state: DynamicManagerState?,
    currentManager: InstalledApp?,
    apps: List<InstalledApp>,
    searchText: String,
    busy: Boolean,
    error: String?,
    actions: DynamicManagersActions,
) {
    Scaffold(
        topBar = {
            SearchAppBar(
                snackbarHostState = remember { SnackbarHostState() },
                title = { Text(stringResource(R.string.dynamic_manager_title)) },
                searchText = searchText,
                onSearchTextChange = actions.onSearchTextChange,
                onClearClick = { actions.onSearchTextChange("") },
                navigationIcon = { IconButton(onClick = actions.onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) } },
                actions = { IconButton(onClick = actions.onRefresh) { Icon(Icons.Filled.Refresh, null) } },
                defaultContent = { _, _ -> },
                searchContent = { _, _ ->
                    ManagerEntries(state?.entries.orEmpty(), currentManager, apps, searchText, actions)
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            verticalArrangement = Arrangement.spacedBy(2.dp),
            contentPadding = PaddingValues(bottom = 24.dp),
        ) {
            item {
                state?.let { current ->
                    ListItem(
                        content = { Text(stringResource(R.string.dynamic_manager_enabled)) },
                        supportingContent = { Text(stringResource(R.string.dynamic_manager_summary)) },
                        trailingContent = { Switch(checked = current.enabled, onCheckedChange = actions.onSetEnabled) },
                    )
                }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                error?.let { Text(it, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.error) }
                HorizontalDivider(Modifier.padding(top = 8.dp))
            }
            currentManager?.let { app ->
                item { SectionTitle(stringResource(R.string.dynamic_manager_current)) }
                item { ManagerItem(app, app.packageName, app.uid, null, true, null) }
            }
            if (state?.entries.orEmpty().isNotEmpty()) {
                item { SectionTitle(stringResource(R.string.dynamic_manager_authorized)) }
                items(state?.entries.orEmpty(), key = { it.packageName }) { entry ->
                    val app = (listOfNotNull(currentManager) + apps).firstOrNull { it.packageName == entry.packageName }
                    ManagerItem(app, entry.packageName, entry.uid, "${entry.certSize} bytes · ${entry.hash}", false) {
                        actions.onRemove(entry.packageName)
                    }
                }
            }
            item {
                OutlinedButton(
                    onClick = actions.onLoadApps,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                ) {
                    Icon(Icons.Filled.Add, null)
                    Text(stringResource(R.string.dynamic_manager_add), Modifier.padding(start = 8.dp))
                }
            }
            if (apps.isNotEmpty()) {
                item { SectionTitle(stringResource(R.string.dynamic_manager_select_app)) }
                items(
                    apps.filterNot { app -> state?.entries?.any { it.packageName == app.packageName } == true },
                    key = { it.packageName },
                ) { app ->
                    ListItem(
                        modifier = Modifier.padding(horizontal = 8.dp),
                        content = { Text(app.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        supportingContent = { Text(app.packageName, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        leadingContent = { AppIconImage(Modifier.size(48.dp), app.packageInfo, app.label) },
                        trailingContent = { IconButton(onClick = { actions.onAdd(app) }) { Icon(Icons.Filled.Add, stringResource(R.string.dynamic_manager_authorize, app.label)) } },
                        colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceColorAtElevation(2.dp)),
                    )
                }
            }
        }
    }
}

@Composable
private fun ManagerEntries(
    entries: List<DynamicManagerEntry>,
    currentManager: InstalledApp?,
    apps: List<InstalledApp>,
    searchText: String,
    actions: DynamicManagersActions,
) {
    val query = searchText.trim()
    val appByPackage = (listOfNotNull(currentManager) + apps).associateBy { it.packageName }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 24.dp)) {
        items(entries.filter { entry ->
            val app = appByPackage[entry.packageName]
            query.isEmpty() || entry.packageName.contains(query, true) || app?.label?.contains(query, true) == true
        }, key = { it.packageName }) { entry ->
            ManagerItem(appByPackage[entry.packageName], entry.packageName, entry.uid, "${entry.certSize} bytes · ${entry.hash}", false) {
                actions.onRemove(entry.packageName)
            }
        }
    }
}

@Composable
private fun SectionTitle(title: String) {
    Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(start = 20.dp, top = 16.dp, bottom = 6.dp))
}

@Composable
private fun ManagerItem(
    app: InstalledApp?,
    packageName: String,
    uid: Int,
    detail: String?,
    current: Boolean,
    onRemove: (() -> Unit)?,
) {
    var expanded by remember(packageName) { mutableStateOf(false) }
    val colors = MaterialTheme.colorScheme
    ListItem(
        modifier = Modifier.clickable { expanded = !expanded },
        content = {
            Text(app?.label ?: packageName, color = if (current) colors.onSurfaceVariant else colors.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis)
        },
        supportingContent = {
            if (expanded) {
                Column {
                    if (current) Text(stringResource(R.string.dynamic_manager_default), color = colors.onSurfaceVariant)
                    if (detail != null) Text(detail, color = colors.onSurfaceVariant)
                    if (app != null) Text(packageName, color = colors.onSurfaceVariant)
                }
            }
        },
        leadingContent = {
            if (app != null) AppIconImage(Modifier.size(48.dp), app.packageInfo, app.label)
            else Icon(Icons.Filled.CheckCircle, null, tint = if (current) colors.outline else colors.primary)
        },
        trailingContent = {
            Column(horizontalAlignment = Alignment.End) {
                Text("UID $uid", color = colors.onSurfaceVariant)
                onRemove?.let { IconButton(onClick = it) { Icon(Icons.Filled.Delete, stringResource(R.string.dynamic_manager_remove)) } }
            }
        },
        colors = ListItemDefaults.colors(
            containerColor = if (current) colors.surfaceVariant.copy(alpha = 0.55f) else colors.surfaceColorAtElevation(2.dp),
            leadingIconColor = colors.onSurfaceVariant,
        ),
    )
}
