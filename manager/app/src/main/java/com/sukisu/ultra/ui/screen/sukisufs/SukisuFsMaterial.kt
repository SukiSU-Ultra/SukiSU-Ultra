package com.sukisu.ultra.ui.screen.sukisufs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TonalCard
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SukisuFsMaterial(
    mountStatus: SukisuFsMountState?,
    rules: List<SukisuFsRule>,
    busy: Boolean,
    error: String?,
    actions: SukisuFsActions,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    val listState = rememberLazyListState()

    var showMountDialog by rememberSaveable { mutableStateOf(false) }
    var showAddRuleDialog by rememberSaveable { mutableStateOf(false) }

    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sukisufs_title)) },
                navigationIcon = {
                    IconButton(onClick = actions.onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    IconButton(onClick = actions.onRefresh) {
                        Icon(Icons.Outlined.Refresh, contentDescription = null)
                    }
                },
                colors = expressiveTopAppBarColors(),
                scrollBehavior = scrollBehavior,
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
    ) { innerPadding ->
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = 8.dp,
                bottom = 16.dp + 56.dp + 16.dp,
            ),
        ) {
            item("status") {
                MountCard(
                    mountStatus = mountStatus,
                    busy = busy,
                    onMountClick = { showMountDialog = true },
                    onUnmountClick = { actions.onUnmount(it) },
                )
            }
            error?.takeIf { it.isNotEmpty() }?.let { msg ->
                item("error") {
                    Text(
                        text = msg,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(horizontal = 4.dp),
                    )
                }
            }
            item("rules_header") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(R.string.sukisufs_rules_section),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                    TextButton(onClick = actions.onClearRules) {
                        Text(stringResource(R.string.sukisufs_rules_clear))
                    }
                }
            }
            item("add_rule") {
                FilledTonalButton(
                    onClick = { showAddRuleDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.sukisufs_rules_add))
                }
            }
            items(rules, key = { it.path + "_" + it.uidMin + "_" + it.uidMax + "_" + it.view.name }) { rule ->
                RuleCard(
                    rule = rule,
                    onRemove = { actions.onRemoveRule(rule.path) },
                )
            }
        }
    }

    if (showMountDialog) {
        MountDialog(
            onDismiss = { showMountDialog = false },
            onConfirm = { src, tgt ->
                showMountDialog = false
                actions.onMount(src, tgt)
            },
        )
    }
    if (showAddRuleDialog) {
        AddRuleDialog(
            onDismiss = { showAddRuleDialog = false },
            onConfirm = { rule ->
                showAddRuleDialog = false
                actions.onAddRule(rule)
            },
        )
    }
}

@Composable
private fun MountCard(
    mountStatus: SukisuFsMountState?,
    busy: Boolean,
    onMountClick: () -> Unit,
    onUnmountClick: (String) -> Unit,
) {
    TonalCard(modifier = Modifier.fillMaxWidth(), onClick = { }) {
        Column(
            modifier = Modifier.padding(18.dp, 16.dp, 16.dp, 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            val mounted = mountStatus?.mounted == true
            Text(
                text = if (mounted) {
                    stringResource(R.string.sukisufs_mounted)
                } else {
                    stringResource(R.string.sukisufs_not_mounted)
                },
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            mountStatus?.source?.let { src ->
                Text(
                    text = "$src -> ${mountStatus.target ?: "?"}",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                )
            }
            if (busy) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                if (mounted) {
                    FilledTonalButton(
                        onClick = { mountStatus?.target?.let(onUnmountClick) },
                    ) {
                        Text(stringResource(R.string.sukisufs_umount))
                    }
                } else {
                    FilledTonalButton(onClick = onMountClick) {
                        Text(stringResource(R.string.sukisufs_mount))
                    }
                }
            }
        }
    }
}

@Composable
private fun RuleCard(
    rule: SukisuFsRule,
    onRemove: () -> Unit,
) {
    TonalCard(modifier = Modifier.fillMaxWidth(), onClick = { }) {
        Column(
            modifier = Modifier.padding(18.dp, 16.dp, 16.dp, 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = "${rule.view.name} · uid [${rule.uidMin}..${rule.uidMax}]",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = rule.path,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                FilledTonalButton(
                    onClick = onRemove,
                    modifier = Modifier.height(36.dp),
                    contentPadding = ButtonDefaults.TextButtonContentPadding,
                ) {
                    Icon(Icons.Outlined.Delete, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.sukisufs_remove))
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MountDialog(
    onDismiss: () -> Unit,
    onConfirm: (source: String, target: String) -> Unit,
) {
    var source by rememberSaveable { mutableStateOf("/data/adb") }
    var target by rememberSaveable { mutableStateOf("/data/adb/sukisu") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.sukisufs_mount)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = source,
                    onValueChange = { source = it },
                    label = { Text(stringResource(R.string.sukisufs_source)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = target,
                    onValueChange = { target = it },
                    label = { Text(stringResource(R.string.sukisufs_target)) },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(source, target) }) {
                Text(stringResource(android.R.string.ok))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(android.R.string.cancel))
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddRuleDialog(
    onDismiss: () -> Unit,
    onConfirm: (SukisuFsRule) -> Unit,
) {
    var viewText by rememberSaveable { mutableStateOf(SukisuFsView.HIDE.name) }
    var uidMin by rememberSaveable { mutableStateOf("10000") }
    var uidMax by rememberSaveable { mutableStateOf("19999") }
    var path by rememberSaveable { mutableStateOf("/data/adb/secret") }
    var viewMenuOpen by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.sukisufs_rules_add)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ExposedDropdownMenuBox(
                    expanded = viewMenuOpen,
                    onExpandedChange = { viewMenuOpen = !viewMenuOpen },
                ) {
                    OutlinedTextField(
                        value = viewText,
                        onValueChange = { },
                        readOnly = true,
                        label = { Text(stringResource(R.string.sukisufs_view)) },
                        trailingIcon = {
                            ExposedDropdownMenuDefaults.TrailingIcon(expanded = viewMenuOpen)
                        },
                        modifier = Modifier
                            .menuAnchor()
                            .fillMaxWidth(),
                    )
                    ExposedDropdownMenuDefaults
                    DropdownMenu(
                        expanded = viewMenuOpen,
                        onDismissRequest = { viewMenuOpen = false },
                    ) {
                        SukisuFsView.values().forEach { v ->
                            DropdownMenuItem(
                                text = { Text(v.name) },
                                onClick = {
                                    viewText = v.name
                                    viewMenuOpen = false
                                },
                            )
                        }
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = uidMin,
                        onValueChange = { uidMin = it.filter(Char::isDigit) },
                        label = { Text(stringResource(R.string.sukisufs_uid_min)) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedTextField(
                        value = uidMax,
                        onValueChange = { uidMax = it.filter(Char::isDigit) },
                        label = { Text(stringResource(R.string.sukisufs_uid_max)) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                }
                OutlinedTextField(
                    value = path,
                    onValueChange = { path = it },
                    label = { Text(stringResource(R.string.sukisufs_path)) },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onConfirm(
                    SukisuFsRule(
                        view = runCatching { SukisuFsView.valueOf(viewText) }.getOrDefault(SukisuFsView.HIDE),
                        uidMin = uidMin.toIntOrNull() ?: 0,
                        uidMax = uidMax.toIntOrNull() ?: 0,
                        path = path,
                    )
                )
            }) {
                Text(stringResource(android.R.string.ok))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(android.R.string.cancel))
            }
        },
    )
}
