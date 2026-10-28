package com.sukisu.ultra.ui.screen.susfs.component.miuix

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.screen.susfs.util.BackupData
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.CancellationException
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.window.WindowDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import java.io.File
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.ui.platform.LocalLocale
import kotlin.time.Duration.Companion.milliseconds

@Composable
fun BackupRestoreComponentMiuix(
    isLoading: Boolean,
    onLoadingChange: (Boolean) -> Unit,
    onConfigReload: () -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    var internalLoading by remember { mutableStateOf(false) }
    val actualLoading = isLoading || internalLoading

    var showBackupDialog by remember { mutableStateOf(false) }
    var showRestoreDialog by remember { mutableStateOf(false) }
    var showRestoreConfirmDialog by remember { mutableStateOf(false) }
    var selectedBackupFile by remember { mutableStateOf<String?>(null) }
    var backupInfo by remember { mutableStateOf<BackupData?>(null) }

    DisposableEffect(selectedBackupFile) {
        val path = selectedBackupFile
        onDispose {
            if (path != null) {
                // Use an independent IO task: leaving this composable cancels its UI scope.
                kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch { File(path).delete() }
            }
        }
    }


    val backupFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        uri?.let { fileUri ->
            coroutineScope.launch {
                try {
                    internalLoading = true
                    onLoadingChange(true)
                    withContext(Dispatchers.IO) {
                        val tempFile = File.createTempFile("susfs_backup_", ".json", context.cacheDir)
                        try {
                            if (SuSFSManager.createBackup(context, tempFile.absolutePath)) {
                                val output = context.contentResolver.openOutputStream(fileUri)
                                    ?: throw java.io.IOException("Unable to open backup destination")
                                output.use { stream -> tempFile.inputStream().use { it.copyTo(stream) } }
                            }
                        } finally {
                            tempFile.delete()
                        }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    e.printStackTrace()
                } finally {
                    internalLoading = false
                    onLoadingChange(false)
                    showBackupDialog = false
                }
            }
        }
    }

    val restoreFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { fileUri ->
            coroutineScope.launch {
                try {
                    internalLoading = true
                    onLoadingChange(true)
                    val prepared = withContext(Dispatchers.IO) {
                        val tempFile = File.createTempFile("susfs_restore_", ".json", context.cacheDir)
                        try {
                            val input = context.contentResolver.openInputStream(fileUri)
                                ?: throw java.io.IOException("Unable to open backup file")
                            input.use { stream -> tempFile.outputStream().use { stream.copyTo(it) } }
                            val backup = SuSFSManager.validateBackupFile(tempFile.absolutePath)
                            if (backup == null) {
                                tempFile.delete()
                                null
                            } else tempFile.absolutePath to backup
                        } catch (e: Exception) {
                            tempFile.delete()
                            throw e
                        }
                    }
                    if (prepared != null) {
                        selectedBackupFile = prepared.first
                        backupInfo = prepared.second
                        showRestoreConfirmDialog = true
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    e.printStackTrace()
                } finally {
                    internalLoading = false
                    onLoadingChange(false)
                    showRestoreDialog = false
                }
            }
        }
    }

    BackupDialogMiuix(
        showDialog = showBackupDialog,
        onDismiss = { showBackupDialog = false },
        isLoading = actualLoading,
        onBackup = {
            val dateFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
            val timestamp = dateFormat.format(Date())
            backupFileLauncher.launch("SuSFS_Config_$timestamp.susfs_backup")
        }
    )

    RestoreDialogMiuix(
        showDialog = showRestoreDialog,
        onDismiss = { showRestoreDialog = false },
        isLoading = actualLoading,
        onSelectFile = {
            restoreFileLauncher.launch(arrayOf("application/json", "*/*"))
        }
    )

    RestoreConfirmDialogMiuix(
        showDialog = showRestoreConfirmDialog,
        onDismiss = {
            if (!actualLoading) {
            showRestoreConfirmDialog = false
            selectedBackupFile = null
            backupInfo = null
            }
        },
        backupInfo = backupInfo,
        isLoading = actualLoading,
        onConfirm = {
            selectedBackupFile?.let { filePath ->
                coroutineScope.launch {
                    try {
                        internalLoading = true
                        onLoadingChange(true)
                        val success = SuSFSManager.restoreFromBackup(context, filePath)
                        if (success) {
                            onConfigReload()
                        }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        e.printStackTrace()
                    } finally {
                        internalLoading = false
                        onLoadingChange(false)
                        showRestoreConfirmDialog = false
                        selectedBackupFile = null
                        backupInfo = null
                    }
                }
            }
        }
    )

    AppCard(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = { showBackupDialog = true },
                enabled = !actualLoading,
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = 48.dp),
                cornerRadius = 8.dp
            ) {
                Text(
                    text = stringResource(R.string.susfs_backup_title)
                )
            }
            Button(
                onClick = { showRestoreDialog = true },
                enabled = !actualLoading,
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = 48.dp),
                cornerRadius = 8.dp
            ) {
                Text(
                    text = stringResource(R.string.susfs_restore_title)
                )
            }
        }
    }
}

@Composable
private fun BackupDialogMiuix(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    isLoading: Boolean,
    onBackup: () -> Unit
) {
    val showDialogState = remember { mutableStateOf(showDialog) }

    LaunchedEffect(showDialog) {
        showDialogState.value = showDialog
    }

    if (showDialogState.value) {
        WindowDialog(
            show = showDialogState.value,
            title = stringResource(R.string.susfs_backup_title),
            onDismissRequest = onDismiss,
            content = {
                Column(
                    modifier = Modifier.padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(stringResource(R.string.susfs_backup_description))
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = onDismiss,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                        Button(
                            onClick = onBackup,
                            enabled = !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                        ) {
                            Text(stringResource(R.string.susfs_backup_create))
                        }
                    }
                }
            }
        )
    }
}

@Composable
private fun RestoreDialogMiuix(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    isLoading: Boolean,
    onSelectFile: () -> Unit
) {
    val showDialogState = remember { mutableStateOf(showDialog) }

    LaunchedEffect(showDialog) {
        showDialogState.value = showDialog
    }

    if (showDialogState.value) {
        WindowDialog(
            show = showDialogState.value,
            title = stringResource(R.string.susfs_restore_title),
            onDismissRequest = onDismiss,
            content = {
                Column(
                    modifier = Modifier.padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(stringResource(R.string.susfs_restore_description))
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = onDismiss,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                        Button(
                            onClick = onSelectFile,
                            enabled = !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                        ) {
                            Text(stringResource(R.string.susfs_restore_select_file))
                        }
                    }
                }
            }
        )
    }
}

@Composable
private fun RestoreConfirmDialogMiuix(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    backupInfo: BackupData?,
    isLoading: Boolean,
    onConfirm: () -> Unit
) {
    val showDialogState = remember { mutableStateOf(showDialog && backupInfo != null) }

    LaunchedEffect(showDialog, backupInfo) {
        showDialogState.value = showDialog && backupInfo != null
    }

    if (showDialogState.value && backupInfo != null) {
        WindowDialog(
            show = showDialogState.value,
            title = stringResource(R.string.susfs_restore_confirm_title),
            onDismissRequest = onDismiss,
            content = {
                Column(
                    modifier = Modifier.padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(stringResource(R.string.susfs_restore_confirm_description))

                    AppCard(
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", LocalLocale.current.platformLocale)
                            Text(
                                text = stringResource(
                                    R.string.susfs_backup_info_date,
                                    dateFormat.format(Date(backupInfo.timestamp))
                                ),
                                fontSize = MiuixTheme.textStyles.body2.fontSize
                            )
                            Text(
                                text = stringResource(R.string.susfs_backup_info_device, backupInfo.deviceInfo),
                                fontSize = MiuixTheme.textStyles.body2.fontSize
                            )
                            Text(
                                text = stringResource(R.string.susfs_backup_info_version, backupInfo.version),
                                fontSize = MiuixTheme.textStyles.body2.fontSize
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = onDismiss,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                        Button(
                            onClick = onConfirm,
                            enabled = !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                        ) {
                            Text(stringResource(R.string.susfs_restore_confirm))
                        }
                    }
                }
            }
        )
    }
}
