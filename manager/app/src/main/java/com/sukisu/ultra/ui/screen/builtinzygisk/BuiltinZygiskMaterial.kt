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
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
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
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.SegmentedSwitchItem
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.util.BUILTIN_ZYGISK_TARGET

@Composable
internal fun BuiltinZygiskMaterial(
    uiState: BuiltinZygiskUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onSwitch: (String, String) -> Unit,
    onToggleProcesses: (String) -> Unit,
    onToggleInjected: (String) -> Unit,
    onSetOption: (String, String) -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()

    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(stringResource(R.string.settings_builtin_zygisk_dashboard)) },
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                actions = {
                    IconButton(onClick = onRefresh) {
                        Icon(Icons.Filled.Refresh, contentDescription = stringResource(R.string.refresh))
                    }
                },
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
            AnimatedVisibility(visible = uiState.isLoading || uiState.isSwitching) {
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
                    Text(
                        text = stringResource(R.string.builtin_zygisk_status_title),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )

                    SegmentedColumn(
                        modifier = Modifier.fillMaxWidth(),
                        content = listOf(
                            {
                                SegmentedListItem(
                                    headlineContent = { Text(stringResource(R.string.builtin_zygisk_daemon_status)) },
                                    supportingContent = {
                                        Text(
                                            uiState.status.daemons
                                                .takeIf { it.isNotEmpty() }
                                                ?.joinToString("\n") { it.label }
                                                ?: stringResource(R.string.builtin_zygisk_status_stopped)
                                        )
                                    },
                                    leadingContent = {
                                        Icon(
                                            if (uiState.status.daemonRunning) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                                            contentDescription = null,
                                            tint = if (uiState.status.daemonRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                                        )
                                    }
                                )
                            },
                            {
                                SegmentedListItem(
                                    headlineContent = { Text(stringResource(R.string.builtin_zygisk_monitor_status)) },
                                    supportingContent = {
                                        Text(
                                            uiState.status.monitor?.label
                                                ?: stringResource(R.string.builtin_zygisk_status_stopped)
                                        )
                                    },
                                    leadingContent = {
                                        Icon(
                                            if (uiState.status.monitorRunning) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                                            contentDescription = null,
                                            tint = if (uiState.status.monitorRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                                        )
                                    }
                                )
                            }
                        )
                    )
                }

                item {
                    Text(
                        text = stringResource(R.string.builtin_zygisk_impl_title),
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

                    val builtinName = stringResource(R.string.builtin_zygisk_impl_builtin)
                    val currentTarget = uiState.implementation.id
                    val choices = listOf(
                        Triple(
                            BUILTIN_ZYGISK_TARGET,
                            builtinName,
                            stringResource(R.string.builtin_zygisk_impl_builtin_summary)
                        )
                    ) + uiState.zygiskModules
                        .filter { it.enabled && !it.remove }
                        .map { Triple(it.id, it.name, "${it.version} (${it.author})") }

                    SegmentedColumn(
                        modifier = Modifier.fillMaxWidth(),
                        content = choices.map { (id, name, summary) ->
                            val isCurrent = id == currentTarget
                            @Composable {
                                SegmentedListItem(
                                    selected = isCurrent,
                                    onClick = {
                                        if (!uiState.isSwitching && !isCurrent) onSwitch(id, name)
                                    },
                                    headlineContent = { Text(name) },
                                    supportingContent = { Text(summary) },
                                    leadingContent = {
                                        Icon(
                                            if (id == BUILTIN_ZYGISK_TARGET) {
                                                Icons.Filled.Memory
                                            } else {
                                                Icons.Filled.Extension
                                            },
                                            contentDescription = null,
                                            tint = if (isCurrent) {
                                                MaterialTheme.colorScheme.primary
                                            } else {
                                                MaterialTheme.colorScheme.onSurfaceVariant
                                            }
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
                        text = stringResource(R.string.builtin_zygisk_injected_title),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 8.dp, bottom = 8.dp)
                    )
                }

                if (uiState.injectedModules.isEmpty()) {
                    item {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            color = MaterialTheme.colorScheme.surfaceContainer
                        ) {
                            Text(
                                text = stringResource(R.string.builtin_zygisk_injected_empty),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(24.dp)
                            )
                        }
                    }
                } else {
                    item {
                        val itemsList = uiState.injectedModules.map { module ->
                            val isExpanded = uiState.expandedInjectedId == module.id
                            @Composable {
                                val chevronRotation by animateFloatAsState(
                                    targetValue = if (isExpanded) 180f else 0f,
                                    label = "injectedChevron"
                                )
                                SegmentedListItem(
                                    onClick = { onToggleInjected(module.id) },
                                    headlineContent = {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(
                                                text = module.name,
                                                fontWeight = FontWeight.SemiBold,
                                                modifier = Modifier.weight(1f, fill = false)
                                            )
                                            Spacer(Modifier.width(8.dp))
                                            ZygiskBadge(
                                                text = stringResource(
                                                    if (module.type == "next") {
                                                        R.string.builtin_zygisk_type_next
                                                    } else {
                                                        R.string.builtin_zygisk_type_zygisk
                                                    }
                                                ),
                                                container = MaterialTheme.colorScheme.secondaryContainer,
                                                content = MaterialTheme.colorScheme.onSecondaryContainer
                                            )
                                            module.abi.forEach { abi ->
                                                Spacer(Modifier.width(4.dp))
                                                ZygiskBadge(
                                                    text = abi,
                                                    container = MaterialTheme.colorScheme.surfaceVariant,
                                                    content = MaterialTheme.colorScheme.onSurfaceVariant
                                                )
                                            }
                                        }
                                    },
                                    supportingContent = {
                                        Column {
                                            val state = stringResource(injectedStateText(module.state))
                                            Text(
                                                text = listOf(module.version, state)
                                                    .filter { it.isNotEmpty() }
                                                    .joinToString(" · "),
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
                                            AnimatedVisibility(visible = isExpanded) {
                                                Column {
                                                    if (module.processes.isEmpty()) {
                                                        Text(
                                                            text = stringResource(R.string.builtin_zygisk_no_processes),
                                                            style = MaterialTheme.typography.labelSmall,
                                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                            modifier = Modifier.padding(top = 6.dp)
                                                        )
                                                    } else {
                                                        Text(
                                                            text = stringResource(
                                                                R.string.builtin_zygisk_process_count,
                                                                module.processes.size
                                                            ),
                                                            style = MaterialTheme.typography.labelSmall,
                                                            color = MaterialTheme.colorScheme.primary,
                                                            modifier = Modifier.padding(top = 6.dp)
                                                        )
                                                        module.processes.forEach { process ->
                                                            Text(
                                                                text = process.label,
                                                                style = MaterialTheme.typography.labelSmall,
                                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                                modifier = Modifier.padding(top = 2.dp)
                                                            )
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    trailingContent = {
                                        Icon(
                                            imageVector = Icons.Filled.ExpandMore,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.rotate(chevronRotation)
                                        )
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

                item {
                    Text(
                        text = stringResource(R.string.builtin_zygisk_modules_title),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 8.dp, bottom = 8.dp)
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
                        val itemsList = uiState.zygiskModules.map { module ->
                            val isActive = module.id == uiState.implementation.id &&
                                uiState.implementation.state == "running"
                            val isExpanded = isActive && uiState.expandedModuleId == module.id
                            @Composable {
                                val chevronRotation by animateFloatAsState(
                                    targetValue = if (isExpanded) 180f else 0f,
                                    label = "moduleChevron"
                                )
                                SegmentedListItem(
                                    onClick = if (isActive) {
                                        { onToggleProcesses(module.id) }
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
                                            AnimatedVisibility(visible = isExpanded) {
                                                val processes = uiState.moduleProcesses
                                                Column {
                                                    if (processes.monitors.isEmpty() && processes.daemons.isEmpty()) {
                                                        Text(
                                                            text = stringResource(R.string.builtin_zygisk_status_stopped),
                                                            style = MaterialTheme.typography.labelSmall,
                                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                            modifier = Modifier.padding(top = 4.dp)
                                                        )
                                                    } else {
                                                        processes.monitors.forEach { process ->
                                                            Text(
                                                                text = "${stringResource(R.string.builtin_zygisk_monitor_status)}: ${process.label}",
                                                                style = MaterialTheme.typography.labelSmall,
                                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                                modifier = Modifier.padding(top = 4.dp)
                                                            )
                                                        }
                                                        processes.daemons.forEach { process ->
                                                            Text(
                                                                text = "${stringResource(R.string.builtin_zygisk_daemon_status)}: ${process.label}",
                                                                style = MaterialTheme.typography.labelSmall,
                                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                                modifier = Modifier.padding(top = 4.dp)
                                                            )
                                                        }
                                                    }
                                                }
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
                                    trailingContent = if (isActive) {
                                        {
                                            Icon(
                                                Icons.Filled.ExpandMore,
                                                contentDescription = null,
                                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                                modifier = Modifier.rotate(chevronRotation)
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

/// A small label for the module API, its ABIs and its process count.
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
