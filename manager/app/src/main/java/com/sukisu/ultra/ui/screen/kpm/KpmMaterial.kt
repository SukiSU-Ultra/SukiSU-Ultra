package com.sukisu.ultra.ui.screen.kpm

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.content.edit
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.ConfigResults
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TonalCard
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import com.sukisu.ultra.ui.viewmodel.KpmViewModel

@Composable
fun KpmMaterial(viewModel: KpmViewModel, actions: KpmActions, bottomInnerPadding: Dp = 0.dp) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val navigator = LocalNavigator.current
    val listState = rememberLazyListState()
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    var expandInstallFab by remember { mutableStateOf(true) }
    val fabScrollThreshold = with(LocalDensity.current) { 100.dp.toPx() }
    val fabScrollConnection = remember(listState, fabScrollThreshold) {
        object : NestedScrollConnection {
            private var scrollDistance = 0f

            override fun onPostScroll(consumed: Offset, available: Offset, source: NestedScrollSource): Offset {
                if (!listState.canScrollBackward) {
                    expandInstallFab = true
                    scrollDistance = 0f
                } else if (consumed.y != 0f) {
                    // Keep the current size when scrolling stops; ignore small direction changes.
                    val delta = -consumed.y
                    if ((delta > 0 && scrollDistance < 0) || (delta < 0 && scrollDistance > 0)) {
                        scrollDistance = 0f
                    }
                    scrollDistance = (scrollDistance + delta).coerceIn(-fabScrollThreshold, fabScrollThreshold)
                    if (scrollDistance >= fabScrollThreshold) {
                        expandInstallFab = false
                        scrollDistance = 0f
                    } else if (scrollDistance <= -fabScrollThreshold) {
                        expandInstallFab = true
                        scrollDistance = 0f
                    }
                }
                // Observe list movement without consuming it or interfering with the app bar.
                return Offset.Zero
            }
        }
    }
    val fabExpanded by remember { derivedStateOf { !listState.canScrollBackward || expandInstallFab } }
    val preferences = LocalContext.current.getSharedPreferences("app_preferences", Context.MODE_PRIVATE)
    var noticeClosed by remember { mutableStateOf(preferences.getBoolean("is_notice_closed", false)) }
    val modules = remember(state.moduleList, state.searchQuery) { state.visibleModules }

    ExpressiveScaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(stringResource(R.string.kpm_title)) },
                navigationIcon = {
                    TopBarBackButton(onClick = { navigator.pop() })
                },
                actions = {
                    IconButton(onClick = actions.onRefresh, enabled = !state.isRefreshing && !state.isBusy) {
                        Icon(Icons.Rounded.Refresh, stringResource(R.string.refresh))
                    }
                },
                scrollBehavior = scrollBehavior,
                colors = expressiveTopAppBarColors()
            )
        },
        floatingActionButton = {
            SmallExtendedFloatingActionButton(
                onClick = { if (!state.isBusy) actions.onRequestInstall() },
                modifier = Modifier.padding(bottom = bottomInnerPadding)
                    .semantics { if (state.isBusy) disabled() },
                expanded = fabExpanded,
                icon = { Icon(Icons.Rounded.Add, stringResource(R.string.kpm_install_mode)) },
                text = { Text(stringResource(R.string.kpm_install_mode)) },
                containerColor = if (state.isBusy) MaterialTheme.colorScheme.surfaceContainerHighest
                    else MaterialTheme.colorScheme.primaryContainer,
                contentColor = if (state.isBusy) MaterialTheme.colorScheme.onSurfaceVariant
                    else MaterialTheme.colorScheme.onPrimaryContainer
            )
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = state.isRefreshing,
            onRefresh = actions.onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding)
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize().nestedScroll(fabScrollConnection),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = bottomInnerPadding + 104.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item(key = "overview") {
                    TonalCard(containerColor = MaterialTheme.colorScheme.primaryContainer, shape = MaterialTheme.shapes.extraLarge) {
                        Row(Modifier.fillMaxWidth().padding(24.dp), verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                            Surface(shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.primary) {
                                Icon(Icons.Rounded.Extension, null, Modifier.padding(16.dp).size(28.dp))
                            }
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(stringResource(R.string.kpm_modules_title), style = MaterialTheme.typography.titleLarge)
                                Text(if (state.hasLoaded) stringResource(R.string.kpm_loaded_count, state.moduleList.size)
                                    else stringResource(R.string.kpm_overview_description), style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                }
                item(key = "search") {
                    OutlinedTextField(
                        value = state.searchQuery, onValueChange = actions.onSearchTextChange,
                        modifier = Modifier.fillMaxWidth(), singleLine = true,
                        shape = MaterialTheme.shapes.extraLarge,
                        label = { Text(stringResource(R.string.kpm_search)) },
                        leadingIcon = { Icon(Icons.Rounded.Search, null) },
                        trailingIcon = {
                            if (state.searchQuery.isNotEmpty()) IconButton(onClick = { actions.onSearchTextChange("") }) {
                                Icon(Icons.Rounded.Close, stringResource(R.string.kpm_clear_search))
                            }
                        }
                    )
                }
                if (state.isBusy) item(key = "busy") {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                        Text(stringResource(R.string.kpm_working), style = MaterialTheme.typography.bodySmall)
                    }
                }
                if (state.operationResults.isNotEmpty()) item(key = "results") {
                    TonalCard { ConfigResults(state.operationResults) }
                }
                state.error?.let { error ->
                    item(key = "error") {
                        TonalCard(containerColor = MaterialTheme.colorScheme.errorContainer) {
                            Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(stringResource(R.string.kpm_refresh_failed), style = MaterialTheme.typography.titleMedium)
                                Text(error.localizedMessage.orEmpty(), style = MaterialTheme.typography.bodyMedium)
                                TextButton(onClick = actions.onRefresh, enabled = !state.isRefreshing && !state.isBusy) {
                                    Text(stringResource(R.string.kpm_retry))
                                }
                            }
                        }
                    }
                }
                if (!noticeClosed) item(key = "notice") {
                    TonalCard {
                        Row(Modifier.fillMaxWidth().padding(start = 16.dp, top = 8.dp, bottom = 8.dp, end = 4.dp),
                            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Icon(Icons.Rounded.Info, null, tint = MaterialTheme.colorScheme.primary)
                            Text(stringResource(R.string.kernel_module_notice), Modifier.weight(1f),
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            IconButton(onClick = {
                                noticeClosed = true
                                preferences.edit { putBoolean("is_notice_closed", true) }
                            }) { Icon(Icons.Rounded.Close, stringResource(R.string.close_notice)) }
                        }
                    }
                }
                if (modules.isEmpty()) item(key = "empty") {
                    Column(Modifier.fillMaxWidth().padding(vertical = 32.dp, horizontal = 24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        if (!state.hasLoaded && state.error == null) {
                            LoadingIndicator()
                            Text(stringResource(R.string.refresh_refresh))
                        } else if (state.error == null || state.hasLoaded) {
                            Icon(if (state.searchQuery.isBlank()) Icons.Rounded.Extension else Icons.Rounded.SearchOff, null,
                                Modifier.size(56.dp), tint = MaterialTheme.colorScheme.primary)
                            Text(stringResource(if (state.searchQuery.isBlank()) R.string.kpm_empty else R.string.kpm_search_empty),
                                textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge)
                            if (state.searchQuery.isNotBlank()) {
                                FilledTonalButton(onClick = { actions.onSearchTextChange("") }) {
                                    Text(stringResource(R.string.kpm_clear_search))
                                }
                            }
                        }
                    }
                }
                items(modules, key = { "module:${it.id}" }, contentType = { "module" }) { module ->
                    KpmMaterialModule(module, state.isBusy, actions, Modifier.animateItem())
                }
            }
        }
    }
    KpmMaterialDialogs(state, actions)
}

@Composable
private fun KpmMaterialModule(module: KpmViewModel.ModuleInfo, busy: Boolean, actions: KpmActions, modifier: Modifier) {
    TonalCard(modifier = modifier.fillMaxWidth(), shape = MaterialTheme.shapes.extraLarge) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Surface(shape = MaterialTheme.shapes.medium, color = MaterialTheme.colorScheme.secondaryContainer) {
                    Icon(Icons.Rounded.Extension, null, Modifier.padding(12.dp).size(24.dp))
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(module.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    val metadata = listOf(module.version, module.author).filter { it.isNotBlank() }.joinToString(" · ")
                    if (metadata.isNotBlank()) Text(metadata, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (module.description.isNotBlank()) Text(module.description, maxLines = 4, overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (module.args.isNotBlank()) Surface(
                shape = MaterialTheme.shapes.medium,
                color = backgroundAwareColor(MaterialTheme.colorScheme.surfaceContainer),
                contentColor = MaterialTheme.colorScheme.onSurface,
            ) {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.kpm_args), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(module.args, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, maxLines = 3, overflow = TextOverflow.Ellipsis)
                }
            }
            // A flow layout keeps translated actions usable with large fonts and narrow windows.
            FlowRow(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (module.hasAction) FilledTonalButton(onClick = { actions.onShowInputDialog(module.id) }, enabled = !busy) {
                    Icon(Icons.Rounded.Terminal, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.kpm_control))
                }
                OutlinedButton(onClick = { actions.onRequestUninstall(module.id) }, enabled = !busy,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) {
                    Icon(Icons.Rounded.DeleteOutline, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.kpm_uninstall))
                }
            }
        }
    }
}

@Composable
private fun KpmMaterialDialogs(state: KpmUiState, actions: KpmActions) {
    if (state.showInstallModeDialog) AlertDialog(
        onDismissRequest = actions.onDismissInstallDialog,
        icon = { Icon(Icons.Rounded.Extension, null) },
        title = { Text(stringResource(R.string.kpm_install_mode)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(state.tempModuleName.orEmpty(), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.kpm_load_description))
                FilledTonalButton(onClick = { actions.onConfirmInstall(false) }, enabled = !state.isBusy, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.kpm_install_mode_load))
                }
                Text(stringResource(R.string.kpm_embed_description))
                Button(onClick = { actions.onConfirmInstall(true) }, enabled = !state.isBusy, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.kpm_install_mode_embed))
                }
                if (state.isBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = actions.onDismissInstallDialog, enabled = !state.isBusy) { Text(stringResource(R.string.cancel)) } }
    )
    val input = state.inputDialogState
    if (input.visible) {
        // Keep IME composition local; commit to the ViewModel only when executing.
        var args by rememberSaveable(input.moduleId) { mutableStateOf(input.args) }
        AlertDialog(
            onDismissRequest = actions.onHideInputDialog,
            title = { Text(stringResource(R.string.kpm_control)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(input.moduleId.orEmpty(), style = MaterialTheme.typography.bodyMedium)
                    OutlinedTextField(value = args, onValueChange = { args = it }, enabled = !state.isBusy,
                        label = { Text(stringResource(R.string.kpm_args)) }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                    if (state.isBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
                }
            },
            confirmButton = {
                Button(enabled = !state.isBusy, onClick = { actions.onInputArgsChange(args); actions.onExecuteControl() }) {
                    Text(stringResource(R.string.confirm))
                }
            },
            dismissButton = { TextButton(onClick = actions.onHideInputDialog, enabled = !state.isBusy) { Text(stringResource(R.string.cancel)) } }
        )
    }
}
