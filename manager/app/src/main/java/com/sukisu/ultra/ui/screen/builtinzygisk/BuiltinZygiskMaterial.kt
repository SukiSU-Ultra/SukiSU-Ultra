package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun BuiltinZygiskMaterial(
    uiState: BuiltinZygiskUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRearm: () -> Unit,
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
            AnimatedVisibility(visible = uiState.isLoading || uiState.isRearming) {
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
                                            if (uiState.status.daemonRunning) {
                                                stringResource(R.string.builtin_zygisk_status_running)
                                            } else {
                                                stringResource(R.string.builtin_zygisk_status_stopped)
                                            }
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
                                            if (uiState.status.monitorRunning) {
                                                stringResource(R.string.builtin_zygisk_status_running)
                                            } else {
                                                stringResource(R.string.builtin_zygisk_status_stopped)
                                            }
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
                            },
                            {
                                SegmentedListItem(
                                    onClick = onRearm,
                                    headlineContent = { Text(stringResource(R.string.builtin_zygisk_rearm)) },
                                    supportingContent = { Text(stringResource(R.string.settings_builtin_zygisk_summary)) },
                                    leadingContent = {
                                        Icon(
                                            Icons.Filled.RestartAlt,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.primary
                                        )
                                    }
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
                            @Composable {
                                SegmentedListItem(
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
