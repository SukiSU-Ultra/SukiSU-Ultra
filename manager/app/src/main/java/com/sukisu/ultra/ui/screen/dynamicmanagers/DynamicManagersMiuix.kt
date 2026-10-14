package com.sukisu.ultra.ui.screen.dynamicmanagers

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.AppIconImage
import com.sukisu.ultra.ui.component.SearchStatus
import com.sukisu.ultra.ui.component.miuix.SearchPager
import com.sukisu.ultra.ui.util.DynamicManagerEntry
import com.sukisu.ultra.ui.util.DynamicManagerState
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Refresh
import com.sukisu.ultra.ui.component.miuix.SearchBar

@Composable
internal fun DynamicManagersMiuix(
    state: DynamicManagerState?,
    currentManager: InstalledApp?,
    apps: List<InstalledApp>,
    searchText: String,
    busy: Boolean,
    error: String?,
    actions: DynamicManagersActions,
) {
    val searchLabel = stringResource(R.string.dynamic_manager_title)
    var searchStatus by remember(searchLabel) { mutableStateOf(SearchStatus(searchLabel, searchText)) }
    androidx.compose.runtime.LaunchedEffect(searchText) {
        if (searchStatus.searchText != searchText) searchStatus = searchStatus.copy(searchText = searchText)
    }
    Scaffold(topBar = {
        TopAppBar(
            title = stringResource(R.string.dynamic_manager_title),
            navigationIcon = { IconButton(onClick = actions.onBack) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, null) } },
            actions = { IconButton(onClick = actions.onRefresh) { Icon(Icons.Rounded.Refresh, null) } },
        )
    }) { padding ->
        searchStatus.SearchPager(
            onSearchStatusChange = { next ->
                searchStatus = next
                actions.onSearchTextChange(next.searchText)
            },
            searchBarTopPadding = padding.calculateTopPadding(),
            defaultResult = {
                DynamicManagerContent(state, currentManager, apps, busy, error, actions, padding)
            },
            expandBar = { status, onStatusChange, topPadding ->
                SearchBar(status, onStatusChange, topPadding)
            },
            result = {
                ManagerEntries(state?.entries.orEmpty(), currentManager, apps, searchStatus.searchText, actions)
            },
        )
    }
}

@Composable
private fun DynamicManagerContent(
    state: DynamicManagerState?,
    currentManager: InstalledApp?,
    apps: List<InstalledApp>,
    busy: Boolean,
    error: String?,
    actions: DynamicManagersActions,
    padding: PaddingValues,
) {
    LazyColumn(Modifier.fillMaxSize().padding(padding), verticalArrangement = Arrangement.spacedBy(2.dp), contentPadding = PaddingValues(bottom = 24.dp)) {
        item {
            state?.let { current ->
                SwitchPreference(
                    title = stringResource(R.string.dynamic_manager_enabled),
                    summary = stringResource(R.string.dynamic_manager_summary),
                    checked = current.enabled,
                    onCheckedChange = actions.onSetEnabled,
                )
            }
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            error?.let { Text(it, Modifier.padding(16.dp), color = MiuixTheme.colorScheme.error) }
        }
        currentManager?.let { app ->
            item { SectionTitle(stringResource(R.string.dynamic_manager_current)) }
            item { ManagerItem(app, app.packageName, app.uid, null, true, null) }
        }
        if (state?.entries.orEmpty().isNotEmpty()) {
            item { SectionTitle(stringResource(R.string.dynamic_manager_authorized)) }
            items(state?.entries.orEmpty(), key = { it.packageName }) { entry ->
                ManagerItem((listOfNotNull(currentManager) + apps).firstOrNull { it.packageName == entry.packageName }, entry.packageName, entry.uid, "${entry.certSize} bytes · ${entry.hash}", false) {
                    actions.onRemove(entry.packageName)
                }
            }
        }
        item {
            ArrowPreference(
                title = stringResource(R.string.dynamic_manager_add),
                startAction = { Icon(Icons.Rounded.Add, null, tint = MiuixTheme.colorScheme.onBackground) },
                onClick = actions.onLoadApps,
                enabled = !busy,
            )
        }
        if (apps.isNotEmpty()) {
            item { SectionTitle(stringResource(R.string.dynamic_manager_select_app)) }
            items(apps.filterNot { app -> state?.entries?.any { it.packageName == app.packageName } == true }, key = { it.packageName }) { app ->
                Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    AppIconImage(Modifier.size(48.dp), app.packageInfo, app.label)
                    Column(Modifier.weight(1f).padding(start = 12.dp)) {
                        Text(app.label)
                        Text(app.packageName, color = MiuixTheme.colorScheme.onBackground)
                    }
                    IconButton(onClick = { actions.onAdd(app) }) { Icon(Icons.Rounded.Add, stringResource(R.string.dynamic_manager_authorize, app.label)) }
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
    queryText: String,
    actions: DynamicManagersActions,
) {
    val query = queryText.trim()
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
    Text(title, modifier = Modifier.padding(start = 20.dp, top = 16.dp, bottom = 6.dp), color = MiuixTheme.colorScheme.onBackground)
}

@Composable
private fun ManagerItem(app: InstalledApp?, packageName: String, uid: Int, detail: String?, current: Boolean, onRemove: (() -> Unit)?) {
    var expanded by remember(packageName) { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().clickable { expanded = !expanded }.padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (app != null) AppIconImage(Modifier.size(48.dp), app.packageInfo, app.label)
        else Icon(Icons.Rounded.CheckCircle, null, tint = MiuixTheme.colorScheme.primary)
        Column(Modifier.weight(1f).padding(start = 12.dp)) {
            Text(app?.label ?: packageName, color = if (current) MiuixTheme.colorScheme.onBackground else MiuixTheme.colorScheme.primary, maxLines = 1)
            AnimatedVisibility(visible = expanded) {
                Column {
                    if (current) Text(stringResource(R.string.dynamic_manager_default), color = MiuixTheme.colorScheme.onBackground)
                    if (detail != null) Text(detail, color = MiuixTheme.colorScheme.onBackground)
                    if (app != null) Text(packageName, color = MiuixTheme.colorScheme.onBackground)
                }
            }
        }
        Text("UID $uid", color = MiuixTheme.colorScheme.onBackground)
        onRemove?.let { IconButton(onClick = it) { Icon(Icons.Rounded.Delete, stringResource(R.string.dynamic_manager_remove)) } }
    }
}
