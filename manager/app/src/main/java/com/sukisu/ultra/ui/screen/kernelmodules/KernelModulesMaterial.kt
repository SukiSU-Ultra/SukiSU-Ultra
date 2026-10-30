package com.sukisu.ultra.ui.screen.kernelmodules

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.util.CustomTextKey
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.TonalCard
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.component.statustag.StatusTag

@Composable
fun KernelModulesMaterial(
    state: KernelModulesUiState,
    actions: KernelModulesActions,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            TopBar(
                scrollBehavior = scrollBehavior,
                loading = state.isLoading,
                onBack = actions.onBack,
                onRefresh = actions.onRefresh,
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { padding ->
        when {
            state.snapshot == null && state.isLoading -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator()
                }
            }

            state.snapshot == null -> {
                ErrorStateMaterial(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding),
                    onRetry = actions.onRefresh,
                )
            }

            else -> {
                val snapshot = state.snapshot
                val isEmpty = snapshot.entries.isEmpty() &&
                    snapshot.suggestedNames.isEmpty() &&
                    snapshot.paramsNames.isEmpty() &&
                    snapshot.hiddenDeviceBlocklistCount == 0
                // An unreadable source must never look like "nothing is blocked".
                if (isEmpty && snapshot.activeAvailable && snapshot.configAvailable) {
                    EmptyStateMaterial(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding),
                    )
                    return@ExpressiveScaffold
                }

                val sourceNotice = kernelModulesSourceNotice(snapshot)

                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .nestedScroll(scrollBehavior.nestedScrollConnection)
                        .padding(horizontal = 16.dp),
                    contentPadding = padding,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item(key = "summary") {
                        SummaryCardMaterial(snapshot)
                    }

                    if (sourceNotice != null) {
                        item(key = "source-notice") {
                            TonalCard(
                                modifier = Modifier.fillMaxWidth(),
                                containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                                contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                                shape = MaterialTheme.shapes.large,
                            ) {
                                Text(
                                    text = sourceNotice,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(16.dp),
                                    style = MaterialTheme.typography.bodyMedium,
                                )
                            }
                        }
                    }

                    if (!snapshot.dependencyDataAvailable) {
                        item(key = "dependency-notice") {
                            TonalCard(
                                modifier = Modifier.fillMaxWidth(),
                                containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                                contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                                shape = MaterialTheme.shapes.large,
                            ) {
                                Text(
                                    text = stringResource(
                                        R.string.kernel_modules_dependency_unavailable,
                                    ),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(16.dp),
                                    style = MaterialTheme.typography.bodyMedium,
                                )
                            }
                        }
                    }

                    if (snapshot.hiddenDeviceBlocklistCount > 0) {
                        item(key = "hidden-device-blocklist") {
                            TonalCard(
                                modifier = Modifier.fillMaxWidth(),
                                containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                                contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                                shape = MaterialTheme.shapes.large,
                            ) {
                                Text(
                                    text = pluralStringResource(
                                        R.plurals.kernel_modules_device_blocklist_hidden,
                                        snapshot.hiddenDeviceBlocklistCount,
                                        snapshot.hiddenDeviceBlocklistCount,
                                    ),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(16.dp),
                                    style = MaterialTheme.typography.bodyMedium,
                                )
                            }
                        }
                    }

                    if (state.failed) {
                        item(key = "error-banner") {
                            TonalCard(
                                modifier = Modifier.fillMaxWidth(),
                                containerColor = MaterialTheme.colorScheme.errorContainer,
                                contentColor = MaterialTheme.colorScheme.onErrorContainer,
                                shape = MaterialTheme.shapes.large,
                            ) {
                                Text(
                                    text = stringResource(R.string.kernel_modules_load_failed),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(16.dp),
                                    style = MaterialTheme.typography.bodyMedium,
                                )
                            }
                        }
                    }

                    if (snapshot.entries.isNotEmpty()) {
                        item(key = "blocked") {
                            SegmentedColumn(
                                title = stringResource(R.string.kernel_modules_section_blocked),
                            ) {
                                snapshot.entries.forEach { entry ->
                                    item(key = entry.name) {
                                        ModuleItemMaterial(
                                            entry = entry,
                                            expanded = entry.name in state.expanded,
                                            activeAvailable = snapshot.activeAvailable,
                                            dependencyDataAvailable = snapshot.dependencyDataAvailable,
                                            onToggle = {
                                                actions.onToggleExpanded(entry.name)
                                            },
                                        )
                                    }
                                }
                            }
                        }
                    }

                    if (snapshot.suggestedNames.isNotEmpty()) {
                        item(key = "suggested") {
                            SegmentedColumn(
                                title = stringResource(R.string.kernel_modules_section_suggested),
                            ) {
                                item(key = "suggested-card") {
                                    SegmentedListItem(
                                        leadingContent = {
                                            IconTile(
                                                icon = Icons.Rounded.Memory,
                                                contentDescription = null,
                                            )
                                        },
                                        supportingContent = {
                                            Text(
                                                text = stringResource(
                                                    R.string.kernel_modules_suggested_summary,
                                                ),
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            )
                                        },
                                        headlineContent = {
                                            Text(
                                                text = snapshot.suggestedNames.joinToString(", "),
                                                style = MaterialTheme.typography.bodyMedium,
                                                fontFamily = FontFamily.Monospace,
                                            )
                                        },
                                    )
                                }
                            }
                        }
                    }

                    item(key = "params") {
                        ParamsSectionMaterial(snapshot, actions.onCopy)
                    }

                    item(key = "bottom-inset") {
                        Spacer(
                            Modifier.height(
                                WindowInsets.navigationBars
                                    .asPaddingValues()
                                    .calculateBottomPadding(),
                            ),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TopBar(
    scrollBehavior: TopAppBarScrollBehavior?,
    loading: Boolean,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
) {
    LargeFlexibleTopAppBar(
        title = { Text(customText(CustomTextKey.PAGE_KERNEL_MODULES)) },
        navigationIcon = {
            TopBarBackButton(onClick = onBack)
        },
        actions = {
            IconButton(onClick = onRefresh, enabled = !loading) {
                Icon(
                    imageVector = Icons.Rounded.Refresh,
                    contentDescription = stringResource(R.string.refresh),
                )
            }
        },
        colors = expressiveTopAppBarColors(),
        windowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
        scrollBehavior = scrollBehavior,
    )
}

@Composable
private fun SummaryCardMaterial(snapshot: KernelModulesSnapshot) {
    val count = if (snapshot.activeAvailable) {
        snapshot.activeNames.size
    } else {
        snapshot.configuredNames.size
    }
    val countText = if (snapshot.activeAvailable) {
        pluralStringResource(R.plurals.kernel_modules_summary_count, count, count)
    } else {
        pluralStringResource(R.plurals.kernel_modules_summary_configured, count, count)
    }
    TonalCard(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 12.dp),
        containerColor = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        shape = MaterialTheme.shapes.extraLarge,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(52.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Memory,
                    contentDescription = null,
                    modifier = Modifier.size(26.dp),
                    tint = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = countText,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = stringResource(
                        R.string.kernel_modules_summary_details,
                        snapshot.configuredNames.size,
                        snapshot.currentlyLoadedCount,
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f),
                )
                if (snapshot.affectedBootModules > 0) {
                    Text(
                        text = pluralStringResource(
                            R.plurals.kernel_modules_summary_affected,
                            snapshot.affectedBootModules,
                            snapshot.affectedBootModules,
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                    )
                }
                val deviceOnlyCount = snapshot.entries.count {
                    it.deviceBlocklist && !it.active && !it.configured
                }
                if (deviceOnlyCount > 0) {
                    Text(
                        text = pluralStringResource(
                            R.plurals.kernel_modules_summary_device,
                            deviceOnlyCount,
                            deviceOnlyCount,
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun ModuleItemMaterial(
    entry: KernelModuleEntry,
    expanded: Boolean,
    activeAvailable: Boolean,
    dependencyDataAvailable: Boolean,
    onToggle: () -> Unit,
) {
    SegmentedListItem(
        onClick = onToggle,
        leadingContent = {
            IconTile(
                icon = Icons.Rounded.Memory,
                contentDescription = null,
            )
        },
        headlineContent = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = entry.name,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                ModuleStatusTag(entry.status, activeAvailable)
            }
        },
        supportingContent = {
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = kernelModuleSummary(entry, activeAvailable),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                AnimatedVisibility(
                    visible = expanded,
                    enter = expandVertically() + fadeIn(),
                    exit = shrinkVertically() + fadeOut(),
                ) {
                    DependencyDetailsMaterial(
                        entry = entry,
                        dependencyDataAvailable = dependencyDataAvailable,
                    )
                }
            }
        },
        trailingContent = {
            Icon(
                imageVector = if (expanded) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                contentDescription = stringResource(
                    if (expanded) {
                        R.string.kernel_modules_collapse
                    } else {
                        R.string.kernel_modules_expand
                    },
                ),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
    )
}

@Composable
private fun DependencyDetailsMaterial(
    entry: KernelModuleEntry,
    dependencyDataAvailable: Boolean,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Text(
            text = stringResource(R.string.kernel_modules_dependents_title),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        when {
            !dependencyDataAvailable -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_unavailable),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            entry.path == null -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_not_in_table),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            entry.dependents.isEmpty() -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_empty),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            else -> {
                entry.dependents.forEach { dependent ->
                    DependentRowMaterial(dependent)
                }
            }
        }
        val impacted = if (entry.active) {
            entry.dependents
                .filter { it.boot && !it.loaded && !it.blocked }
                .map { it.name }
        } else {
            emptyList()
        }
        when {
            impacted.isNotEmpty() -> {
                Text(
                    text = stringResource(
                        R.string.kernel_modules_dependents_impacted,
                        impacted.joinToString(", "),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            entry.active && entry.dependents.any { !it.loaded && !it.blocked } -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            entry.configured && entry.dependents.any { it.boot && !it.loaded && !it.blocked } -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_warning_pending),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
        entry.path?.let { path ->
            Text(
                text = path,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun DependentRowMaterial(dependent: KernelModuleDependent) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = dependent.name,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
        )
        when {
            dependent.loaded -> StatusTag(
                label = stringResource(R.string.kernel_modules_dependents_loaded),
                backgroundColor = MaterialTheme.colorScheme.secondaryContainer,
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
            )

            dependent.blocked -> StatusTag(
                label = stringResource(R.string.kernel_modules_dependents_blocked),
                backgroundColor = MaterialTheme.colorScheme.surfaceVariant,
                contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            dependent.boot -> StatusTag(
                label = stringResource(R.string.kernel_modules_dependents_boot),
                backgroundColor = MaterialTheme.colorScheme.tertiaryContainer,
                contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
            )
        }
    }
}

@Composable
private fun ParamsSectionMaterial(
    snapshot: KernelModulesSnapshot,
    onCopy: (String) -> Unit,
) {
    Column {
        SegmentedColumn(title = stringResource(R.string.kernel_modules_section_params)) {
            if (snapshot.paramsNames.isEmpty()) {
                item(key = "empty") {
                    SegmentedListItem(
                        headlineContent = {
                            Text(
                                text = stringResource(R.string.kernel_modules_params_empty),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        },
                    )
                }
            } else {
                item(key = "config") {
                    ParameterRowMaterial(
                        label = stringResource(R.string.kernel_modules_params_config),
                        value = snapshot.paramsConfigLine,
                        onCopy = onCopy,
                    )
                }
                item(key = "cli") {
                    ParameterRowMaterial(
                        label = stringResource(R.string.kernel_modules_params_cli),
                        value = snapshot.paramsCliLine,
                        onCopy = onCopy,
                    )
                }
            }
        }
        if (snapshot.paramsNames.isNotEmpty()) {
            Text(
                text = stringResource(kernelModulesParamsSourceLabel(snapshot.paramsSource)),
                modifier = Modifier.padding(start = 16.dp, top = 8.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (snapshot.paramsTooLong) {
            Text(
                text = stringResource(R.string.kernel_modules_params_too_long),
                modifier = Modifier.padding(start = 16.dp, top = 8.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        Text(
            text = stringResource(R.string.kernel_modules_params_note),
            modifier = Modifier.padding(start = 16.dp, top = 8.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ParameterRowMaterial(
    label: String,
    value: String,
    onCopy: (String) -> Unit,
) {
    SegmentedListItem(
        overlineContent = {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
            )
        },
        headlineContent = {
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
            )
        },
        trailingContent = {
            IconButton(onClick = { onCopy(value) }) {
                Icon(
                    imageVector = Icons.Filled.ContentCopy,
                    contentDescription = stringResource(R.string.kernel_modules_params_copy),
                    modifier = Modifier.size(20.dp),
                )
            }
        },
    )
}

@Composable
private fun ModuleStatusTag(
    status: KernelModuleStatus,
    activeAvailable: Boolean,
) {
    val (background, content) = statusColorsMaterial(status)
    StatusTag(
        label = kernelModuleStatusText(status, activeAvailable),
        backgroundColor = background,
        contentColor = content,
    )
}

@Composable
private fun statusColorsMaterial(status: KernelModuleStatus): Pair<Color, Color> =
    when (status) {
        KernelModuleStatus.Blocked ->
            MaterialTheme.colorScheme.secondaryContainer to
                MaterialTheme.colorScheme.onSecondaryContainer

        KernelModuleStatus.BlockedLoaded ->
            MaterialTheme.colorScheme.errorContainer to
                MaterialTheme.colorScheme.onErrorContainer

        KernelModuleStatus.ConfigPending ->
            MaterialTheme.colorScheme.tertiaryContainer to
                MaterialTheme.colorScheme.onTertiaryContainer

        KernelModuleStatus.DeviceBlocklist ->
            MaterialTheme.colorScheme.surfaceVariant to
                MaterialTheme.colorScheme.onSurfaceVariant

        KernelModuleStatus.NotFound ->
            MaterialTheme.colorScheme.surfaceContainerHighest to
                MaterialTheme.colorScheme.onSurfaceVariant
    }

@Composable
private fun EmptyStateMaterial(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
    ) {
        Icon(
            imageVector = Icons.Rounded.Memory,
            contentDescription = null,
            modifier = Modifier.size(40.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = stringResource(R.string.kernel_modules_empty_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = stringResource(R.string.kernel_modules_empty_summary),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun ErrorStateMaterial(
    modifier: Modifier = Modifier,
    onRetry: () -> Unit,
) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
    ) {
        Text(
            text = stringResource(R.string.kernel_modules_load_failed),
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center,
        )
        Button(onClick = onRetry) {
            Text(stringResource(R.string.kernel_modules_retry))
        }
    }
}
