package com.sukisu.ultra.ui.screen.umountmanager

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
import androidx.compose.material.icons.outlined.Block
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
import androidx.compose.material3.Scaffold
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

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = if (state.showExclusionList)
                            stringResource(R.string.umount_exclusion_manager)
                        else
                            stringResource(R.string.umount_path_manager)
                    )
                },
                navigationIcon = {
                    IconButton(onClick = {
                        if (state.showExclusionList) {
                            actions.onBackToPathList()
                        } else {
                            actions.onBack()
                        }
                    }) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = null
                        )
                    }
                },
                actions = {
                    if (state.showExclusionList) {
                        IconButton(onClick = actions.onClearAllExclusions) {
                            Icon(
                                imageVector = Icons.Outlined.Block,
                                contentDescription = stringResource(R.string.clear_all_exclusions)
                            )
                        }
                    }
                    IconButton(onClick = actions.onRefresh) {
                        Icon(
                            imageVector = Icons.Filled.Refresh,
                            contentDescription = null
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                scrollBehavior = scrollBehavior
            )
        },
        floatingActionButton = {
            if (state.showExclusionList) {
                FloatingActionButton(
                    onClick = actions.onAddExclusionClick
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Add,
                        contentDescription = null,
                        tint = Color.White
                    )
                }
            } else {
                FloatingActionButton(
                    onClick = actions.onAddPathClick
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Add,
                        contentDescription = null,
                        tint = Color.White
                    )
                }
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
                        text = if (state.showExclusionList)
                            stringResource(R.string.umount_exclusion_manager_summary)
                        else
                            stringResource(R.string.umount_path_restart_notice)
                    )
                }
            }

            // Toggle button between path list and exclusion list
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = SPACING_LARGE),
                horizontalArrangement = Arrangement.spacedBy(SPACING_MEDIUM)
            ) {
                Button(
                    onClick = { if (!state.showExclusionList) actions.onShowExclusionList() },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Block,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(SPACING_SMALL))
                    Text(stringResource(R.string.umount_exclusion_manager))
                }

                Button(
                    onClick = { if (state.showExclusionList) actions.onBackToPathList() },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Folder,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(SPACING_SMALL))
                    Text(stringResource(R.string.umount_path_manager))
                }
            }

            Spacer(modifier = Modifier.height(SPACING_MEDIUM))

            if (state.isLoading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            } else {
                if (state.showExclusionList) {
                    // Exclusion list
                    if (state.exclusionList.isEmpty()) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = stringResource(R.string.no_umount_exclusions),
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = PaddingValues(horizontal = SPACING_LARGE, vertical = SPACING_MEDIUM),
                            verticalArrangement = Arrangement.spacedBy(SPACING_MEDIUM)
                        ) {
                            items(state.exclusionList, key = { it.pathPrefix }) { entry ->
                                UmountExclusionCardMaterial(
                                    entry = entry,
                                    onDelete = { actions.onDeleteExclusion(entry) }
                                )
                            }

                            item {
                                Spacer(modifier = Modifier.height(SPACING_LARGE))
                            }
                        }
                    }
                } else {
                    // Path list
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(horizontal = SPACING_LARGE, vertical = SPACING_MEDIUM),
                        verticalArrangement = Arrangement.spacedBy(SPACING_MEDIUM)
                    ) {
                        items(state.pathList, key = { it.path }) { entry ->
                            UmountPathCardMaterial(
                                entry = entry,
                                onDelete = { actions.onDeletePath(entry) }
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
        }

        if (state.showAddPathDialog) {
            AddUmountPathDialogMaterial(
                onDismiss = actions.onDismissAddPathDialog,
                onConfirm = actions.onAddPath
            )
        }

        if (state.showAddExclusionDialog) {
            AddUmountExclusionDialogMaterial(
                onDismiss = actions.onDismissAddExclusionDialog,
                onConfirm = actions.onAddExclusion
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

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(SPACING_LARGE),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Outlined.Folder,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp)
            )

            Spacer(modifier = Modifier.width(SPACING_LARGE))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.path
                )
                Spacer(modifier = Modifier.height(SPACING_SMALL))
                Text(
                    text = buildString {
                        append(stringResource(R.string.flags))
                        append(": ")
                        append(entry.flags.toUmountFlagName(context))
                    },
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            IconButton(onClick = onDelete) {
                Icon(
                    imageVector = Icons.Filled.Delete,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
            }
        }
    }
}

@Composable
fun UmountExclusionCardMaterial(
    entry: UmountExclusionEntry,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(SPACING_LARGE),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Outlined.Block,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp)
            )

            Spacer(modifier = Modifier.width(SPACING_LARGE))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.pathPrefix
                )
            }

            IconButton(onClick = onDelete) {
                Icon(
                    imageVector = Icons.Filled.Delete,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
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

@Composable
fun AddUmountExclusionDialogMaterial(
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit
) {
    var pathPrefix by rememberSaveable { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.add_umount_exclusion)) },
        text = {
            Column {
                OutlinedTextField(
                    value = pathPrefix,
                    onValueChange = { pathPrefix = it },
                    label = { Text(stringResource(R.string.umount_exclusion_path_prefix)) },
                    placeholder = { Text(stringResource(R.string.umount_exclusion_path_hint)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onConfirm(pathPrefix)
                },
                enabled = pathPrefix.isNotBlank()
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
