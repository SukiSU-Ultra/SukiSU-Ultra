package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.LocalListItemShapes
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.SegmentedSwitchItem
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import com.sukisu.ultra.ui.util.InjectedZygiskModule

@Composable
internal fun BuiltinZygiskMaterial(
    uiState: BuiltinZygiskUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onSwitch: (String, String) -> Unit,
    onToggleInjected: (String) -> Unit,
    onSetOption: (String, String) -> Unit,
    onToggleGroup: () -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()

    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(stringResource(R.string.settings_builtin_zygisk_dashboard)) },
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                scrollBehavior = scrollBehavior,
                colors = expressiveTopAppBarColors(),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
        ) {
            AnimatedVisibility(visible = uiState.isLoading) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                contentPadding = PaddingValues(top = 16.dp, bottom = 32.dp)
            ) {
                item {
                    val status = uiState.status

                    // One card: the live state first, then the modules each daemon is serving.
                    SegmentedColumn(
                        modifier = Modifier.fillMaxWidth(),
                        content = buildList {
                            add {
                                // The card header shares the segmented surface of the rows, so a
                                // custom background image keeps showing through.
                                val shapes = LocalListItemShapes.current
                                    ?: ListItemDefaults.segmentedShapes(0, 1)
                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    color = backgroundAwareColor(MaterialTheme.colorScheme.surfaceBright),
                                    shape = shapes.shape
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(start = 20.dp, end = 8.dp, top = 4.dp, bottom = 4.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = stringResource(R.string.builtin_zygisk_status_title),
                                            style = MaterialTheme.typography.titleMedium,
                                            color = MaterialTheme.colorScheme.primary,
                                            modifier = Modifier.weight(1f)
                                        )
                                        IconButton(onClick = onRefresh) {
                                            Icon(
                                                Icons.Filled.Refresh,
                                                contentDescription = stringResource(R.string.refresh)
                                            )
                                        }
                                    }
                                }
                            }

                            add {
                                StatusRow(
                                    title = stringResource(R.string.builtin_zygisk_monitor_status),
                                    summary = status.monitor?.label
                                        ?: stringResource(R.string.builtin_zygisk_status_stopped),
                                    ok = status.monitorRunning
                                )
                            }

                            // One row per zygote ABI: which zygotes actually carry the loader.
                            status.zygotes.forEach { zygote ->
                                add {
                                    SegmentedListItem(
                                        headlineContent = {
                                            Text(
                                                stringResource(
                                                    R.string.builtin_zygisk_zygote_status,
                                                    zygote.abi
                                                )
                                            )
                                        },
                                        trailingContent = {
                                            StatusChip(
                                                text = stringResource(zygoteStateText(zygote.status)),
                                                ok = zygote.status == "injected"
                                            )
                                        }
                                    )
                                }
                            }

                            add {
                                StatusRow(
                                    title = stringResource(R.string.builtin_zygisk_daemon_status),
                                    summary = status.daemons
                                        .takeIf { it.isNotEmpty() }
                                        ?.joinToString("\n") { it.label }
                                        ?: stringResource(R.string.builtin_zygisk_status_stopped),
                                    ok = status.daemonRunning
                                )
                            }

                            if (uiState.injectedModules.isEmpty()) {
                                add {
                                    SegmentedListItem(
                                        headlineContent = {
                                            Text(
                                                text = stringResource(R.string.builtin_zygisk_injected_empty),
                                                style = MaterialTheme.typography.bodyMedium,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    )
                                }
                            }

                            if (uiState.injectedModules.isNotEmpty()) {
                                add {
                                    GroupRow(
                                        title = stringResource(
                                            R.string.builtin_zygisk_injected_group,
                                            uiState.injectedModules.size
                                        ),
                                        expanded = uiState.injectedGroupExpanded,
                                        onClick = onToggleGroup
                                    )
                                }
                                if (uiState.injectedGroupExpanded) {
                                    uiState.injectedModules.forEach { module ->
                                        val isNext = module.type == "next"
                                        val isExpanded = isNext &&
                                            uiState.expandedInjectedId == module.id
                                        add {
                                            val chevronRotation by animateFloatAsState(
                                                targetValue = if (isExpanded) 180f else 0f,
                                                label = "moduleChevron"
                                            )
                                            SegmentedListItem(
                                                onClick = if (isNext) {
                                                    { onToggleInjected(module.id) }
                                                } else {
                                                    null
                                                },
                                                headlineContent = {
                                                    Text(
                                                        text = module.name,
                                                        fontWeight = FontWeight.SemiBold,
                                                        maxLines = 1,
                                                        overflow = TextOverflow.Ellipsis
                                                    )
                                                },
                                                supportingContent = {
                                                    Column {
                                                        Text(
                                                            text = moduleSummary(module),
                                                            style = MaterialTheme.typography.bodySmall,
                                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                                        )
                                                        if (module.targets.isNotEmpty()) {
                                                            Text(
                                                                text = stringResource(
                                                                    R.string.builtin_zygisk_targets,
                                                                    module.targets.joinToString(", ")
                                                                ),
                                                                style = MaterialTheme.typography.labelSmall,
                                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                                modifier = Modifier.padding(top = 2.dp)
                                                            )
                                                        }
                                                    }
                                                },
                                                trailingContent = {
                                                    Row(
                                                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                                                        verticalAlignment = Alignment.CenterVertically
                                                    ) {
                                                        if (isNext && module.processes.isNotEmpty()) {
                                                            ZygiskBadge(
                                                                text = stringResource(
                                                                    R.string.builtin_zygisk_process_count,
                                                                    module.processes.size
                                                                ),
                                                                container = MaterialTheme.colorScheme.secondaryContainer,
                                                                content = MaterialTheme.colorScheme.onSecondaryContainer
                                                            )
                                                        }
                                                        module.abi.forEach { abi ->
                                                            ZygiskBadge(
                                                                text = abi,
                                                                container = MaterialTheme.colorScheme.surfaceVariant,
                                                                content = MaterialTheme.colorScheme.onSurfaceVariant
                                                            )
                                                        }
                                                        if (isNext) {
                                                            Icon(
                                                                imageVector = Icons.Filled.ExpandMore,
                                                                contentDescription = null,
                                                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                                                modifier = Modifier.rotate(chevronRotation)
                                                            )
                                                        }
                                                    }
                                                }
                                            )
                                        }
                                        if (isExpanded) {
                                            if (module.processes.isEmpty()) {
                                                add {
                                                    SegmentedListItem(
                                                        headlineContent = {
                                                            Text(
                                                                text = stringResource(R.string.builtin_zygisk_no_processes),
                                                                style = MaterialTheme.typography.bodySmall,
                                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                                modifier = Modifier.padding(start = 24.dp)
                                                            )
                                                        }
                                                    )
                                                }
                                            } else {
                                                module.processes.forEach { process ->
                                                    add {
                                                        SegmentedListItem(
                                                            headlineContent = {
                                                                Text(
                                                                    text = process.name,
                                                                    modifier = Modifier.padding(start = 24.dp)
                                                                )
                                                            },
                                                            trailingContent = {
                                                                PidTag(process.pid)
                                                            }
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    )
                }

                item {
                    Text(
                        text = stringResource(R.string.builtin_zygisk_options_title),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(bottom = 4.dp)
                    )
                    Text(
                        text = stringResource(R.string.builtin_zygisk_options_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )

                    SegmentedColumn(
                        modifier = Modifier.fillMaxWidth(),
                        content = listOf(
                            {
                                SegmentedSwitchItem(
                                    title = stringResource(R.string.builtin_zygisk_opt_anonymous_memory),
                                    summary = stringResource(R.string.builtin_zygisk_opt_anonymous_memory_summary),
                                    checked = uiState.config.anonymousMemory,
                                    onCheckedChange = { onSetOption("anonymous_memory", if (it) "1" else "0") }
                                )
                            },
                            {
                                SegmentedSwitchItem(
                                    title = stringResource(R.string.builtin_zygisk_opt_custom_linker),
                                    summary = stringResource(R.string.builtin_zygisk_opt_custom_linker_summary),
                                    checked = uiState.config.customLinker,
                                    onCheckedChange = { onSetOption("custom_linker", if (it) "1" else "0") }
                                )
                            },
                            {
                                SegmentedSwitchItem(
                                    title = stringResource(R.string.builtin_zygisk_opt_lsplt),
                                    summary = stringResource(R.string.builtin_zygisk_opt_lsplt_summary),
                                    checked = uiState.config.pltEngine == "lsplt",
                                    onCheckedChange = { onSetOption("plt_engine", if (it) "lsplt" else "bytehook") }
                                )
                            }
                        )
                    )
                }

                item {
                    Text(
                        text = stringResource(R.string.builtin_zygisk_modules_title),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(bottom = 4.dp)
                    )
                    Text(
                        text = stringResource(R.string.builtin_zygisk_impl_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                }

                if (uiState.zygiskModules.isEmpty()) {
                    item {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = MaterialTheme.colorScheme.surfaceContainer
                        ) {
                            Text(
                                text = stringResource(R.string.builtin_zygisk_no_modules),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(24.dp)
                            )
                        }
                    }
                } else {
                    item {
                        val providers = uiState.implementation.providers
                        val currentId = uiState.implementation.id
                        val itemsList = uiState.zygiskModules.map { module ->
                            val isProvider = providers.contains(module.id)
                            val isCurrent = module.id == currentId &&
                                uiState.implementation.state == "running"
                            @Composable {
                                SegmentedListItem(
                                    onClick = if (isProvider && !isCurrent) {
                                        { onSwitch(module.id, module.name) }
                                    } else {
                                        null
                                    },
                                    headlineContent = {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(
                                                text = module.name,
                                                fontWeight = FontWeight.SemiBold,
                                                modifier = Modifier.weight(1f, fill = false)
                                            )
                                            if (module.suppressedByBuiltin) {
                                                Spacer(Modifier.width(8.dp))
                                                Box(
                                                    modifier = Modifier
                                                        .clip(RoundedCornerShape(4.dp))
                                                        .background(MaterialTheme.colorScheme.errorContainer)
                                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                                ) {
                                                    Text(
                                                        text = stringResource(R.string.module_suppressed_by_builtin),
                                                        style = MaterialTheme.typography.labelSmall,
                                                        color = MaterialTheme.colorScheme.onErrorContainer
                                                    )
                                                }
                                            }
                                        }
                                    },
                                    supportingContent = {
                                        Column {
                                            Text(
                                                text = "${module.version} (${module.author})",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                            if (module.suppressedByBuiltin) {
                                                Text(
                                                    text = stringResource(R.string.builtin_zygisk_suppressed_hint),
                                                    style = MaterialTheme.typography.labelSmall,
                                                    color = MaterialTheme.colorScheme.error,
                                                    modifier = Modifier.padding(top = 4.dp)
                                                )
                                            } else if (module.description.isNotEmpty()) {
                                                Text(
                                                    text = module.description,
                                                    style = MaterialTheme.typography.bodySmall,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    modifier = Modifier.padding(top = 4.dp)
                                                )
                                            }
                                        }
                                    },
                                    leadingContent = {
                                        Icon(
                                            Icons.Filled.Extension,
                                            contentDescription = null,
                                            tint = if (module.suppressedByBuiltin) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                                        )
                                    },
                                    trailingContent = if (isCurrent) {
                                        {
                                            Icon(
                                                Icons.Filled.CheckCircle,
                                                contentDescription = null,
                                                tint = MaterialTheme.colorScheme.primary
                                            )
                                        }
                                    } else {
                                        null
                                    }
                                )
                            }
                        }
                        SegmentedColumn(
                            modifier = Modifier.fillMaxWidth(),
                            content = itemsList
                        )
                    }
                }
            }
        }
    }
}

/// A small label for the module API and its ABIs.
@Composable
private fun ZygiskBadge(
    text: String,
    container: androidx.compose.ui.graphics.Color,
    content: androidx.compose.ui.graphics.Color,
) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(container)
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = content
        )
    }
}

/// A live row of the card: the name on the left, the state as a chip on the right.
@Composable
private fun StatusRow(title: String, summary: String, ok: Boolean) {
    SegmentedListItem(
        headlineContent = { Text(title) },
        supportingContent = {
            Text(
                text = summary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        },
        trailingContent = {
            StatusChip(
                text = stringResource(
                    if (ok) R.string.builtin_zygisk_status_running else R.string.builtin_zygisk_status_stopped
                ),
                ok = ok
            )
        }
    )
}

/// A collapsible group of served modules inside the status card.
@Composable
private fun GroupRow(title: String, expanded: Boolean, onClick: () -> Unit) {
    val rotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        label = "groupChevron"
    )
    SegmentedListItem(
        onClick = onClick,
        headlineContent = { Text(title, fontWeight = FontWeight.SemiBold) },
        trailingContent = {
            Icon(
                imageVector = Icons.Filled.ExpandMore,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.rotate(rotation)
            )
        }
    )
}

/// The version and state line shared by both module groups.
@Composable
private fun moduleSummary(module: InjectedZygiskModule): String =
    listOf(module.version, stringResource(injectedStateText(module.state)))
        .filter { it.isNotEmpty() }
        .joinToString(" · ")

/// The rounded state chip of the live rows.
@Composable
private fun StatusChip(text: String, ok: Boolean) {
    val colors = MaterialTheme.colorScheme
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(if (ok) colors.primaryContainer else colors.errorContainer)
            .padding(horizontal = 10.dp, vertical = 4.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium,
            color = if (ok) colors.onPrimaryContainer else colors.onErrorContainer
        )
    }
}

/// The pill carrying a process id: MD3 expressive tags are fully rounded.
@Composable
private fun PidTag(pid: Int) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.surfaceContainerHighest)
            .padding(horizontal = 10.dp, vertical = 4.dp)
    ) {
        Text(
            text = "PID $pid",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
