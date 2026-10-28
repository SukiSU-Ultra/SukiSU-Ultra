package com.sukisu.ultra.ui.screen.kpm

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.edit
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.ConfigResults
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import com.sukisu.ultra.ui.viewmodel.KpmViewModel
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun KpmMiuix(viewModel: KpmViewModel, actions: KpmActions, bottomInnerPadding: Dp = 0.dp) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    val scrollBehavior = MiuixScrollBehavior()
    val backdrop = rememberBlurBackdrop(LocalEnableBlur.current)
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val layoutDirection = LocalLayoutDirection.current
    val preferences = LocalContext.current.getSharedPreferences("app_preferences", Context.MODE_PRIVATE)
    var noticeClosed by remember { mutableStateOf(preferences.getBoolean("is_notice_closed", false)) }
    val modules = remember(state.moduleList, state.searchQuery) { state.visibleModules }

    AppScaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    title = stringResource(R.string.kpm_title),
                    color = if (backdrop != null || hasCustomBackground) Color.Transparent else colorScheme.surface,
                    scrollBehavior = scrollBehavior,
                    actions = {
                        IconButton(onClick = actions.onRefresh, enabled = !state.isRefreshing && !state.isBusy) {
                            Icon(Icons.Rounded.Refresh, stringResource(R.string.refresh), tint = colorScheme.onSurface)
                        }
                    }
                )
            }
        },
        floatingActionButton = {
            FloatingActionButton(
                modifier = Modifier.padding(bottom = bottomInnerPadding + 20.dp, end = 20.dp)
                    .semantics { if (state.isBusy) disabled() },
                shape = RoundedCornerShape(20.dp),
                containerColor = if (state.isBusy) colorScheme.secondaryContainer else colorScheme.primary,
                shadowElevation = 0.dp,
                onClick = { if (!state.isBusy) actions.onRequestInstall() }
            ) {
                Row(Modifier.padding(horizontal = 20.dp), verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    val contentColor = if (state.isBusy) colorScheme.onSurfaceVariantSummary else colorScheme.onPrimary
                    Icon(Icons.Rounded.Add, stringResource(R.string.kpm_install_mode), tint = contentColor)
                    Text(stringResource(R.string.kpm_install_mode), color = contentColor, fontWeight = FontWeight.Medium)
                }
            }
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { padding ->
        val contentPadding = PaddingValues(
            top = padding.calculateTopPadding() + 8.dp,
            start = padding.calculateStartPadding(layoutDirection) + 16.dp,
            end = padding.calculateEndPadding(layoutDirection) + 16.dp,
            bottom = bottomInnerPadding + 112.dp
        )
        PullToRefresh(
            isRefreshing = state.isRefreshing, onRefresh = actions.onRefresh,
            refreshTexts = listOf(stringResource(R.string.refresh_pulling), stringResource(R.string.refresh_release),
                stringResource(R.string.refresh_refresh), stringResource(R.string.refresh_complete)),
            contentPadding = PaddingValues(top = padding.calculateTopPadding())
        ) {
            Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize().scrollEndHaptic().overScrollVertical()
                        .nestedScroll(scrollBehavior.nestedScrollConnection),
                    contentPadding = contentPadding, verticalArrangement = Arrangement.spacedBy(12.dp),
                    overscrollEffect = null
                ) {
                    item(key = "overview") {
                        AppCard(insideMargin = PaddingValues(20.dp)) {
                            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                Box(Modifier.clip(RoundedCornerShape(18.dp)).background(colorScheme.primaryContainer).padding(16.dp)) {
                                    Icon(Icons.Rounded.Extension, null, Modifier.size(28.dp), tint = colorScheme.onPrimaryContainer)
                                }
                                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Text(stringResource(R.string.kpm_modules_title), fontSize = 20.sp, fontWeight = FontWeight.SemiBold, color = colorScheme.onSurface)
                                    Text(if (state.hasLoaded) stringResource(R.string.kpm_loaded_count, state.moduleList.size)
                                        else stringResource(R.string.kpm_overview_description), fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary)
                                }
                            }
                        }
                    }
                    item(key = "search") {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            TextField(value = state.searchQuery, onValueChange = actions.onSearchTextChange,
                                label = stringResource(R.string.kpm_search), modifier = Modifier.weight(1f),
                                singleLine = true, useLabelAsPlaceholder = state.searchQuery.isEmpty())
                            if (state.searchQuery.isNotEmpty()) IconButton(onClick = { actions.onSearchTextChange("") }) {
                                Icon(Icons.Rounded.Close, stringResource(R.string.kpm_clear_search), tint = colorScheme.onSurface)
                            }
                        }
                    }
                    if (state.isBusy) item(key = "busy") {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            LinearProgressIndicator(Modifier.fillMaxWidth())
                            Text(stringResource(R.string.kpm_working), fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary)
                        }
                    }
                    if (state.operationResults.isNotEmpty()) item(key = "results") {
                        Card { ConfigResults(state.operationResults) }
                    }
                    state.error?.let { error -> item(key = "error") {
                        AppCard(insideMargin = PaddingValues(20.dp)) {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(stringResource(R.string.kpm_refresh_failed), fontWeight = FontWeight.SemiBold, color = colorScheme.onSurface)
                                Text(error.localizedMessage.orEmpty(), color = colorScheme.onSurfaceVariantSummary)
                                TextButton(text = stringResource(R.string.kpm_retry), enabled = !state.isRefreshing && !state.isBusy, onClick = actions.onRefresh)
                            }
                        }
                    } }
                    if (!noticeClosed) item(key = "notice") {
                        AppCard(insideMargin = PaddingValues(start = 16.dp, top = 8.dp, bottom = 8.dp, end = 4.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                Icon(Icons.Rounded.Info, null, tint = colorScheme.primary)
                                Text(stringResource(R.string.kernel_module_notice), modifier = Modifier.weight(1f), fontSize = 13.sp, color = colorScheme.onSurfaceVariantSummary)
                                IconButton(onClick = {
                                    noticeClosed = true
                                    preferences.edit { putBoolean("is_notice_closed", true) }
                                }) { Icon(Icons.Rounded.Close, stringResource(R.string.close_notice), tint = colorScheme.onSurface) }
                            }
                        }
                    }
                    if (modules.isEmpty()) item(key = "empty") {
                        Column(Modifier.fillMaxWidth().padding(vertical = 32.dp, horizontal = 24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
                            if (!state.hasLoaded && state.error == null) {
                                CircularProgressIndicator()
                                Text(stringResource(R.string.refresh_refresh), color = colorScheme.onSurfaceVariantSummary)
                            } else if (state.error == null || state.hasLoaded) {
                                Icon(if (state.searchQuery.isBlank()) Icons.Rounded.Extension else Icons.Rounded.SearchOff, null,
                                    Modifier.size(56.dp), tint = colorScheme.primary)
                                Text(stringResource(if (state.searchQuery.isBlank()) R.string.kpm_empty else R.string.kpm_search_empty),
                                    textAlign = TextAlign.Center, color = colorScheme.onSurfaceVariantSummary)
                                if (state.searchQuery.isNotBlank()) {
                                    TextButton(text = stringResource(R.string.kpm_clear_search),
                                        onClick = { actions.onSearchTextChange("") },
                                        colors = ButtonDefaults.textButtonColorsPrimary())
                                }
                            }
                        }
                    }
                    items(modules, key = { "module:${it.id}" }, contentType = { "module" }) { module ->
                        KpmMiuixModule(module, state.isBusy, actions, Modifier.animateItem())
                    }
                }
            }
        }
    }
    KpmMiuixDialogs(state, actions)
}

@Composable
private fun KpmMiuixModule(module: KpmViewModel.ModuleInfo, busy: Boolean, actions: KpmActions, modifier: Modifier) {
    AppCard(modifier = modifier.fillMaxWidth(), insideMargin = PaddingValues(20.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Box(Modifier.clip(RoundedCornerShape(14.dp)).background(colorScheme.secondaryContainer).padding(12.dp)) {
                    Icon(Icons.Rounded.Extension, null, Modifier.size(24.dp), tint = colorScheme.onSurface)
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(module.name, fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = colorScheme.onSurface)
                    val metadata = listOf(module.version, module.author).filter { it.isNotBlank() }.joinToString(" · ")
                    if (metadata.isNotBlank()) Text(metadata, fontSize = 13.sp, color = colorScheme.onSurfaceVariantSummary)
                }
            }
            if (module.description.isNotBlank()) Text(module.description, fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary,
                maxLines = 4, overflow = TextOverflow.Ellipsis)
            if (module.args.isNotBlank()) Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
                .background(colorScheme.surfaceContainerHigh).padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.kpm_args), fontSize = 12.sp, color = colorScheme.onSurfaceVariantSummary)
                Text(module.args, fontSize = 13.sp, fontFamily = FontFamily.Monospace, color = colorScheme.onSurface, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            HorizontalDivider(color = colorScheme.outline.copy(alpha = 0.25f))
            FlowRow(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (module.hasAction) TextButton(text = stringResource(R.string.kpm_control), onClick = { actions.onShowInputDialog(module.id) },
                    enabled = !busy, colors = ButtonDefaults.textButtonColorsPrimary())
                TextButton(text = stringResource(R.string.kpm_uninstall), onClick = { actions.onRequestUninstall(module.id) }, enabled = !busy)
            }
        }
    }
}

@Composable
private fun KpmMiuixDialogs(state: KpmUiState, actions: KpmActions) {
    if (state.showInstallModeDialog) OverlayDialog(
        show = true, title = stringResource(R.string.kpm_install_mode), onDismissRequest = actions.onDismissInstallDialog,
        content = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(state.tempModuleName.orEmpty(), fontWeight = FontWeight.SemiBold, color = colorScheme.onSurface)
                Text(stringResource(R.string.kpm_load_description), color = colorScheme.onSurfaceVariantSummary)
                TextButton(text = stringResource(R.string.kpm_install_mode_load), onClick = { actions.onConfirmInstall(false) },
                    enabled = !state.isBusy, modifier = Modifier.fillMaxWidth())
                Text(stringResource(R.string.kpm_embed_description), color = colorScheme.onSurfaceVariantSummary)
                TextButton(text = stringResource(R.string.kpm_install_mode_embed), onClick = { actions.onConfirmInstall(true) },
                    enabled = !state.isBusy, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.textButtonColorsPrimary())
                if (state.isBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
                TextButton(text = stringResource(R.string.cancel), onClick = actions.onDismissInstallDialog,
                    enabled = !state.isBusy, modifier = Modifier.fillMaxWidth())
            }
        }
    )
    val input = state.inputDialogState
    if (input.visible) {
        var args by rememberSaveable(input.moduleId) { mutableStateOf(input.args) }
        OverlayDialog(show = true, title = stringResource(R.string.kpm_control), onDismissRequest = actions.onHideInputDialog, content = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(input.moduleId.orEmpty(), color = colorScheme.onSurfaceVariantSummary)
                TextField(value = args, onValueChange = { args = it }, enabled = !state.isBusy,
                    label = stringResource(R.string.kpm_args), modifier = Modifier.fillMaxWidth(), singleLine = true, useLabelAsPlaceholder = args.isEmpty())
                if (state.isBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    TextButton(text = stringResource(R.string.cancel), onClick = actions.onHideInputDialog, enabled = !state.isBusy, modifier = Modifier.weight(1f))
                    TextButton(text = stringResource(R.string.confirm), onClick = { actions.onInputArgsChange(args); actions.onExecuteControl() },
                        enabled = !state.isBusy, modifier = Modifier.weight(1f), colors = ButtonDefaults.textButtonColorsPrimary())
                }
            }
        })
    }
}
