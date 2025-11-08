package com.sukisu.ultra.ui.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.component.ConfirmResult
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.theme.getCardElevation
import com.sukisu.ultra.ui.util.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val SPACING_SMALL = 3.dp
private val SPACING_MEDIUM = 8.dp
private val SPACING_LARGE = 16.dp

data class UmountPathEntry(
    val path: String,
    val checkMnt: Boolean,
    val flags: Int,
    val isDefault: Boolean
)

@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun UmountManagerScreen(navigator: DestinationsNavigator) {
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val snackBarHost = LocalSnackbarHost.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val confirmDialog = rememberConfirmDialog()

    var pathList by remember { mutableStateOf<List<UmountPathEntry>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var showAddDialog by remember { mutableStateOf(false) }

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
                title = { Text(stringResource(R.string.umount_path_manager)) },
                navigationIcon = {
                    IconButton(onClick = { navigator.navigateUp() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    IconButton(onClick = { loadPaths() }) {
                        Icon(Icons.Filled.Refresh, contentDescription = null)
                    }
                },
                scrollBehavior = scrollBehavior,
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(
                        alpha = CardConfig.cardAlpha
                    )
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showAddDialog = true }
            ) {
                Icon(Icons.Filled.Add, contentDescription = null)
            }
        },
        snackbarHost = { SnackbarHost(snackBarHost) }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .padding(paddingValues)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(SPACING_LARGE),
                colors = getCardColors(MaterialTheme.colorScheme.primaryContainer),
                elevation = getCardElevation()
            ) {
                Column(
                    modifier = Modifier.padding(SPACING_LARGE)
                ) {
                    Icon(
                        imageVector = Icons.Filled.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                    Spacer(modifier = Modifier.height(SPACING_MEDIUM))
                    Text(
                        text = stringResource(R.string.umount_path_restart_notice),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            }

            if (isLoading) {
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
                    items(pathList, key = { it.path }) { entry ->
                        UmountPathCard(
                            entry = entry,
                            onDelete = {
                                scope.launch(Dispatchers.IO) {
                                    val success = removeUmountPath(entry.path)
                                    withContext(Dispatchers.Main) {
                                        if (success) {
                                            snackBarHost.showSnackbar(
                                                context.getString(R.string.umount_path_removed)
                                            )
                                            loadPaths()
                                        } else {
                                            snackBarHost.showSnackbar(
                                                context.getString(R.string.operation_failed)
                                            )
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
                                                title = context.getString(R.string.confirm_action),
                                                content = context.getString(R.string.confirm_clear_custom_paths)
                                            ) == ConfirmResult.Confirmed) {
                                            withContext(Dispatchers.IO) {
                                                val success = clearCustomUmountPaths()
                                                withContext(Dispatchers.Main) {
                                                    if (success) {
                                                        snackBarHost.showSnackbar(
                                                            context.getString(R.string.custom_paths_cleared)
                                                        )
                                                        loadPaths()
                                                    } else {
                                                        snackBarHost.showSnackbar(
                                                            context.getString(R.string.operation_failed)
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Filled.DeleteForever, contentDescription = null)
                                Spacer(modifier = Modifier.width(SPACING_MEDIUM))
                                Text(stringResource(R.string.clear_custom_paths))
                            }

                            Button(
                                onClick = {
                                    scope.launch(Dispatchers.IO) {
                                        val success = applyUmountConfigToKernel()
                                        withContext(Dispatchers.Main) {
                                            if (success) {
                                                snackBarHost.showSnackbar(
                                                    context.getString(R.string.config_applied)
                                                )
                                            } else {
                                                snackBarHost.showSnackbar(
                                                    context.getString(R.string.operation_failed)
                                                )
                                            }
                                        }
                                    }
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Filled.Check, contentDescription = null)
                                Spacer(modifier = Modifier.width(SPACING_MEDIUM))
                                Text(stringResource(R.string.apply_config))
                            }
                        }
                    }
                }
            }
        }

        if (showAddDialog) {
            AddUmountPathDialog(
                onDismiss = { showAddDialog = false },
                onConfirm = { path, checkMnt, flags ->
                    showAddDialog = false

                    scope.launch(Dispatchers.IO) {
                        val success = addUmountPath(path, checkMnt, flags)
                        withContext(Dispatchers.Main) {
                            if (success) {
                                saveUmountConfig()
                                snackBarHost.showSnackbar(
                                    context.getString(R.string.umount_path_added)
                                )
                                loadPaths()
                            } else {
                                snackBarHost.showSnackbar(
                                    context.getString(R.string.operation_failed)
                                )
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

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerLow),
        elevation = getCardElevation()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(SPACING_LARGE),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Filled.Folder,
                contentDescription = null,
                tint = if (entry.isDefault)
                    MaterialTheme.colorScheme.primary
                else
                    MaterialTheme.colorScheme.secondary,
                modifier = Modifier.size(24.dp)
            )

            Spacer(modifier = Modifier.width(SPACING_LARGE))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.path,
                    style = MaterialTheme.typography.titleMedium
                )
                Spacer(modifier = Modifier.height(SPACING_SMALL))
                Text(
                    text = buildString {
                        append(context.getString(R.string.check_mount_type))
                        append(": ")
                        append(if (entry.checkMnt) context.getString(R.string.yes) else context.getString(R.string.no))
                        append(" | ")
                        append(context.getString(R.string.flags))
                        append(": ")
                        append(entry.flags.toUmountFlagName(context))
                        if (entry.isDefault) {
                            append(" | ")
                            append(context.getString(R.string.default_entry))
                        }
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (!entry.isDefault) {
                IconButton(
                    onClick = {
                        scope.launch {
                            if (confirmDialog.awaitConfirm(
                                    title = context.getString(R.string.confirm_delete),
                                    content = context.getString(R.string.confirm_delete_umount_path, entry.path)
                                ) == ConfirmResult.Confirmed) {
                                onDelete()
                            }
                        }
                    }
                ) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

@Composable
fun AddUmountPathDialog(
    onDismiss: () -> Unit,
    onConfirm: (String, Boolean, Int) -> Unit
) {
    var path by rememberSaveable { mutableStateOf("") }
    var checkMnt by rememberSaveable { mutableStateOf(false) }
    var flags by rememberSaveable { mutableStateOf("-1") }

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

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(
                        checked = checkMnt,
                        onCheckedChange = { checkMnt = it }
                    )
                    Spacer(modifier = Modifier.width(SPACING_SMALL))
                    Text(stringResource(R.string.check_mount_type_overlay))
                }

                Spacer(modifier = Modifier.height(SPACING_MEDIUM))

                OutlinedTextField(
                    value = flags,
                    onValueChange = { flags = it },
                    label = { Text(stringResource(R.string.umount_flags)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    supportingText = { Text(stringResource(R.string.umount_flags_hint)) }
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val flagsInt = flags.toIntOrNull() ?: -1
                    onConfirm(path, checkMnt, flagsInt)
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

private fun parseUmountPaths(output: String): List<UmountPathEntry> {
    val lines = output.lines().filter { it.isNotBlank() }
    if (lines.size < 2) return emptyList()

    return lines.drop(2).mapNotNull { line ->
        val parts = line.trim().split(Regex("\\s+"))
        if (parts.size >= 4) {
            UmountPathEntry(
                path = parts[0],
                checkMnt = parts[1].equals("true", ignoreCase = true),
                flags = parts[2].toIntOrNull() ?: -1,
                isDefault = parts[3].equals("Yes", ignoreCase = true)
            )
        } else null
    }
}

private fun Int.toUmountFlagName(context: android.content.Context): String {
    return when (this) {
        -1 -> context.getString(R.string.mnt_detach)
        else -> this.toString()
    }
}
