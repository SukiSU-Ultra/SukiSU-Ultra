package com.sukisu.ultra.ui.screen.umountmanager

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.rounded.Add
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.FloatingActionButton
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Delete
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun UmountManagerMiuix(
    state: UmountManagerUiState,
    actions: UmountManagerActions,
) {
    val scrollBehavior = MiuixScrollBehavior()

    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.umount_path_manager),
                navigationIcon = {
                    IconButton(onClick = actions.onBack) {
                        val layoutDirection = LocalLayoutDirection.current
                        Icon(
                            modifier = Modifier.graphicsLayer {
                                if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                            },
                            imageVector = MiuixIcons.Back,
                            contentDescription = null,
                            tint = colorScheme.onBackground
                        )
                    }
                },
                actions = {
                    IconButton(onClick = actions.onRefresh) {
                        Icon(
                            imageVector = MiuixIcons.Refresh,
                            contentDescription = null,
                            tint = colorScheme.onBackground
                        )
                    }
                },
                scrollBehavior = scrollBehavior
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = actions.onAddClick) {
                Icon(
                    imageVector = Icons.Rounded.Add,
                    contentDescription = null,
                    tint = Color.White
                )
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Info,
                        contentDescription = null,
                        tint = colorScheme.primary
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(
                        text = stringResource(R.string.umount_path_restart_notice),
                        color = colorScheme.onSurface
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
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(state.pathList, key = { it.path }) { entry ->
                        UmountPathCardMiuix(
                            entry = entry,
                            onDelete = {
                                actions.onDeletePath(entry)
                            }
                        )
                    }

                    item {
                        Spacer(modifier = Modifier.height(16.dp))
                    }

                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
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
            AddUmountPathDialogMiuix(
                onDismiss = actions.onDismissAddDialog,
                onConfirm = actions.onAddPath
            )
        }
    }
}

@Composable
private fun UmountPathCardMiuix(
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
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Outlined.Folder,
                contentDescription = null,
                tint = colorScheme.primary,
                modifier = Modifier.size(24.dp)
            )

            Spacer(modifier = Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.path,
                    color = colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = buildString {
                        append(stringResource(R.string.flags))
                        append(": ")
                        append(entry.flags.toUmountFlagName(context))
                    },
                    color = colorScheme.onSurfaceVariantSummary
                )
            }

            IconButton(onClick = onDelete) {
                Icon(
                    imageVector = MiuixIcons.Delete,
                    contentDescription = null,
                    tint = colorScheme.primary
                )
            }
        }
    }
}

@Composable
private fun AddUmountPathDialogMiuix(
    onDismiss: () -> Unit,
    onConfirm: (String, Int) -> Unit
) {
    var path by rememberSaveable { mutableStateOf("") }
    var flags by rememberSaveable { mutableStateOf("0") }
    val showDialog = remember { mutableStateOf(true) }

    OverlayDialog(
        show = showDialog.value,
        title = stringResource(R.string.add_umount_path),
        onDismissRequest = {
            showDialog.value = false
            onDismiss()
        },
        content = {
            Column {
                TextField(
                    value = path,
                    onValueChange = { path = it },
                    label = stringResource(R.string.mount_path),
                    modifier = Modifier.fillMaxWidth(),
                    useLabelAsPlaceholder = true
                )

                Spacer(modifier = Modifier.height(12.dp))

                TextField(
                    value = flags,
                    onValueChange = { flags = it },
                    label = stringResource(R.string.umount_flags),
                    modifier = Modifier.fillMaxWidth(),
                    useLabelAsPlaceholder = true
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = stringResource(R.string.umount_flags_hint),
                    color = colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(start = 12.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    TextButton(
                        text = stringResource(android.R.string.cancel),
                        onClick = {
                            showDialog.value = false
                            onDismiss()
                        },
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(
                        text = stringResource(android.R.string.ok),
                        onClick = {
                            val flagsInt = flags.toIntOrNull() ?: 0
                            showDialog.value = false
                            onConfirm(path, flagsInt)
                        },
                        enabled = path.isNotBlank(),
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    )
}
