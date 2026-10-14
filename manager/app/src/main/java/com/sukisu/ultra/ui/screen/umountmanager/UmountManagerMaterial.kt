package com.sukisu.ultra.ui.screen.umountmanager

import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import androidx.compose.ui.text.font.FontFamily
import com.sukisu.ultra.ui.component.statustag.StatusTag
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.TonalCard
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R

@Composable
fun UmountManagerMaterial(
    state: UmountManagerUiState,
    actions: UmountManagerActions
) {
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.umount_path_manager)) },
                navigationIcon = {
                    IconButton(onClick = actions.onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = null
                        )
                    }
                },
                actions = {
                    IconButton(onClick = actions.onRefresh) {
                        Icon(
                            imageVector = Icons.Filled.Refresh,
                            contentDescription = null
                        )
                    }
                },
                colors = expressiveTopAppBarColors(),
                scrollBehavior = scrollBehavior
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = actions.onAddClick
            ) {
                Icon(
                    imageVector = Icons.Rounded.Add,
                    contentDescription = null,
                    tint = Color.White
                )
            }
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .padding(paddingValues)
                .fillMaxHeight()
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(SPACING_LARGE)
            ) {
                Row(
                    modifier = Modifier.padding(SPACING_LARGE),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.width(SPACING_MEDIUM))
                    Text(
                        text = stringResource(R.string.umount_path_restart_notice)
                    )
                }
            }

            if (state.isLoading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = SPACING_LARGE, vertical = SPACING_MEDIUM),
                    verticalArrangement = Arrangement.spacedBy(SPACING_MEDIUM)
                ) {
                    items(state.pathList, key = { it.path }) { entry ->
                        UmountPathCardMaterial(
                            entry = entry,
                            onDelete = {
                                actions.onDeletePath(entry)
                            }
                        )
                    }

                    item {
                        Spacer(modifier = Modifier.height(SPACING_LARGE))
                    }

                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = SPACING_LARGE),
                            horizontalArrangement = Arrangement.spacedBy(SPACING_MEDIUM)
                        ) {
                            Button(
                                onClick = actions.onClearCustomPaths,
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(text = stringResource(R.string.clear_custom_paths))
                            }

                            Button(
                                onClick = actions.onApplyConfig,
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(text = stringResource(R.string.apply_config))
                            }
                        }
                    }
                }
            }
        }

        if (state.showAddDialog) {
            AddUmountPathDialogMaterial(
                onDismiss = actions.onDismissAddDialog,
                onConfirm = actions.onAddPath
            )
        }
    }
}

@Composable
fun UmountPathCardMaterial(
    entry: UmountPathEntry,
    onDelete: () -> Unit
) {
    val context = LocalContext.current

    TonalCard(
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, top = 12.dp, end = 8.dp, bottom = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconTile(Icons.Outlined.Folder, null)

            Spacer(modifier = Modifier.width(14.dp))

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = entry.path,
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                )
                StatusTag(
                    label = "${stringResource(R.string.flags)}: ${entry.flags.toUmountFlagName(context)}",
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                    backgroundColor = MaterialTheme.colorScheme.secondaryContainer,
                )
            }

            IconButton(onClick = onDelete) {
                Icon(
                    imageVector = Icons.Filled.Delete,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun AddUmountPathDialogMaterial(
    onDismiss: () -> Unit,
    onConfirm: (String, Int) -> Unit
) {
    var path by rememberSaveable { mutableStateOf("") }
    var flags by rememberSaveable { mutableStateOf("0") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.add_umount_path)) },
        text = {
            Column {
                OutlinedTextField(
                    value = path,
                    onValueChange = { path = it },
                    label = { Text(stringResource(R.string.mount_path)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                Spacer(modifier = Modifier.height(SPACING_MEDIUM))

                OutlinedTextField(
                    value = flags,
                    onValueChange = { flags = it },
                    label = { Text(stringResource(R.string.umount_flags)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                Spacer(modifier = Modifier.height(SPACING_SMALL))

                Text(
                    text = stringResource(R.string.umount_flags_hint),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = SPACING_MEDIUM)
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val flagsInt = flags.toIntOrNull() ?: 0
                    onConfirm(path, flagsInt)
                },
                enabled = path.isNotBlank()
            ) {
                Text(stringResource(android.R.string.ok))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(android.R.string.cancel))
            }
        }
    )
}
