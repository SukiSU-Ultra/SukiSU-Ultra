package com.sukisu.ultra.ui.screen

import android.content.Context
import android.widget.Toast
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
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.component.ConfirmResult
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.util.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.FloatingActionButton
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.extra.SuperDialog
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Delete
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

private val SPACING_SMALL = 3.dp
private val SPACING_MEDIUM = 8.dp
private val SPACING_LARGE = 16.dp

data class UmountPathEntry(
    val path: String,
    val flags: Int
)

@Composable
fun UmountManagerScreen() {
    val navigator = LocalNavigator.current
    val scrollBehavior = MiuixScrollBehavior()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val confirmDialog = rememberConfirmDialog()

    var pathList by remember { mutableStateOf<List<UmountPathEntry>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var showAddDialog by remember { mutableStateOf(false) }

    val confirmActionText = stringResource(R.string.confirm_action)
    val umountPathRemovedText = stringResource(R.string.umount_path_removed)
    val confirmClearCustomPathsText = stringResource(R.string.confirm_clear_custom_paths)
    val customPathsClearedText = stringResource(R.string.custom_paths_cleared)
    val operationFailedText = stringResource(R.string.operation_failed)
    val configAppliedText = stringResource(R.string.config_applied)
    val umountPathAddedText = stringResource(R.string.umount_path_added)

    fun loadPaths() {
        scope.launch(Dispatchers.IO) {
            isLoading = true
            val result = listUmountPaths()
            val entries = parseUmountPaths(result)
            withContext(Dispatchers.Main) {
                pathList = entries
                isLoading = false
            }
        }
    }

    LaunchedEffect(Unit) {
        loadPaths()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.umount_path_manager),
                navigationIcon = {
                    IconButton(onClick = { navigator.pop() }) {
                        val layoutDirection = LocalLayoutDirection.current
                        Icon(
                            modifier = Modifier.graphicsLayer {
                                if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                            },
                            imageVector = MiuixIcons.Back,
                            contentDescription = null
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { loadPaths() }) {
                        Icon(
                            imageVector = MiuixIcons.Refresh,
                            contentDescription = null
                        )
                    }
                },
                color = Color.Transparent,
                scrollBehavior = scrollBehavior
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { }
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
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
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
                        tint = colorScheme.primary
                    )
                    Spacer(modifier = Modifier.width(SPACING_MEDIUM))
                    Text(
                        text = stringResource(R.string.umount_path_restart_notice)
                    )
                }
            }

            if (isLoading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    top.yukonga.miuix.kmp.basic.CircularProgressIndicator()
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = SPACING_LARGE, vertical = SPACING_MEDIUM),
                    verticalArrangement = Arrangement.spacedBy(SPACING_MEDIUM)
                ) {
                    items(pathList, key = { it.path }) { entry ->
                        UmountPathCard(
                            entry = entry,
                            onDelete = {
                                scope.launch(Dispatchers.IO) {
                                    val success = removeUmountPath(entry.path)
                                    withContext(Dispatchers.Main) {
                                        if (success) {
                                            Toast.makeText(
                                                context,
                                                umountPathRemovedText,
                                                Toast.LENGTH_SHORT
                                            ).show()
                                            loadPaths()
                                        } else {
                                            Toast.makeText(
                                                context,
                                                operationFailedText,
                                                Toast.LENGTH_SHORT
                                            ).show()
                                        }
                                    }
                                }
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
                                onClick = {
                                    scope.launch {
                                        if (confirmDialog.awaitConfirm(
                                                title = confirmActionText,
                                                content = confirmClearCustomPathsText
                                            ) == ConfirmResult.Confirmed) {
                                            withContext(Dispatchers.IO) {
                                                val success = clearCustomUmountPaths()
                                                withContext(Dispatchers.Main) {
                                                    if (success) {
                                                        Toast.makeText(
                                                            context,
                                                            customPathsClearedText,
                                                            Toast.LENGTH_SHORT
                                                        ).show()
                                                        loadPaths()
                                                    } else {
                                                        Toast.makeText(
                                                            context,
                                                            operationFailedText,
                                                            Toast.LENGTH_SHORT
                                                        ).show()
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(text = stringResource(R.string.clear_custom_paths))
                            }

                            Button(
                                onClick = {
                                    scope.launch(Dispatchers.IO) {
                                        val success = applyUmountConfigToKernel()
                                        withContext(Dispatchers.Main) {
                                            if (success) {
                                                Toast.makeText(
                                                    context,
                                                    configAppliedText,
                                                    Toast.LENGTH_SHORT
                                                ).show()
                                            } else {
                                                Toast.makeText(
                                                    context,
                                                    operationFailedText,
                                                    Toast.LENGTH_SHORT
                                                ).show()
                                            }
                                        }
                                    }
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(text = stringResource(R.string.apply_config))
                            }
                        }
                    }
                }
            }
        }

        if (showAddDialog) {
            AddUmountPathDialog(
                onDismiss = { showAddDialog = false },
                onConfirm = { path, flags ->
                    showAddDialog = false

                    scope.launch(Dispatchers.IO) {
                        val success = addUmountPath(path, flags)
                        withContext(Dispatchers.Main) {
                            if (success) {
                                saveUmountConfig()
                                Toast.makeText(
                                    context,
                                    umountPathAddedText,
                                    Toast.LENGTH_SHORT
                                ).show()
                                loadPaths()
                            } else {
                                Toast.makeText(
                                    context,
                                    operationFailedText,
                                    Toast.LENGTH_SHORT
                                ).show()
                            }
                        }
                    }
                }
            )
        }
    }
}

@Composable
fun UmountPathCard(
    entry: UmountPathEntry,
    onDelete: () -> Unit
) {
    val confirmDialog = rememberConfirmDialog()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    val confirmDeleteText = stringResource(R.string.confirm_delete)
    val confirmDeleteUmountPathText = stringResource(R.string.confirm_delete_umount_path, entry.path)

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
                tint = colorScheme.primary,
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
                    color = colorScheme.onSurfaceVariantSummary
                )
            }

            IconButton(
                onClick = {
                    scope.launch {
                        if (confirmDialog.awaitConfirm(
                                title = confirmDeleteText,
                                content = confirmDeleteUmountPathText
                            ) == ConfirmResult.Confirmed) {
                            onDelete()
                        }
                    }
                }
            ) {
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
fun AddUmountPathDialog(
    onDismiss: () -> Unit,
    onConfirm: (String, Int) -> Unit
) {
    var path by rememberSaveable { mutableStateOf("") }
    var flags by rememberSaveable { mutableStateOf("0") }
    val showDialog = remember { mutableStateOf(true) }

    SuperDialog(
        show = showDialog,
        title = stringResource(R.string.add_umount_path),
        onDismissRequest = {
            showDialog.value = false
            onDismiss()
        }
    ) {
        TextField(
            value = path,
            onValueChange = { path = it },
            label = stringResource(R.string.mount_path),
            modifier = Modifier.fillMaxWidth(),
            singleLine = true
        )

        Spacer(modifier = Modifier.height(SPACING_MEDIUM))

        TextField(
            value = flags,
            onValueChange = { flags = it },
            label = stringResource(R.string.umount_flags),
            modifier = Modifier.fillMaxWidth(),
            singleLine = true
        )

        Spacer(modifier = Modifier.height(SPACING_SMALL))

        Text(
            text = stringResource(R.string.umount_flags_hint),
            color = colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.padding(start = SPACING_MEDIUM)
        )

        Spacer(modifier = Modifier.height(SPACING_MEDIUM))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            TextButton(
                text = stringResource(android.R.string.cancel),
                onClick = {
                    showDialog.value = false
                    onDismiss()
                },
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(20.dp))
            TextButton(
                text = stringResource(android.R.string.ok),
                onClick = {
                    val flagsInt = flags.toIntOrNull() ?: 0
                    showDialog.value = false
                    onConfirm(path, flagsInt)
                },
                modifier = Modifier.weight(1f),
                enabled = path.isNotBlank()
            )
        }
    }
}

private fun parseUmountPaths(output: String): List<UmountPathEntry> {
    val lines = output.lines().filter { it.isNotBlank() }
    if (lines.size < 2) return emptyList()

    return lines.drop(2).mapNotNull { line ->
        val parts = line.trim().split(Regex("\\s+"))
        if (parts.size >= 2) {
            UmountPathEntry(
                path = parts[0],
                flags = parts[1].toIntOrNull() ?: 0
            )
        } else null
    }
}

private fun Int.toUmountFlagName(context: Context): String {
    return when (this) {
        2 -> context.getString(R.string.mnt_detach)
        else -> this.toString()
    }
}
