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
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import java.io.File
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.ui.platform.LocalLocale

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
    var backupInfo by remember { mutableStateOf<SuSFSManager.BackupData?>(null) }

    val backupFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        uri?.let { fileUri ->
            coroutineScope.launch {
                try {
                    internalLoading = true
                    onLoadingChange(true)
                    val fileName = SuSFSManager.getDefaultBackupFileName()
                    val tempFile = File(context.cacheDir, fileName)

                    val success = SuSFSManager.createBackup(context, tempFile.absolutePath)
                    if (success) {
                        try {
                            context.contentResolver.openOutputStream(fileUri)?.use { outputStream ->
                                tempFile.inputStream().use { inputStream ->
                                    inputStream.copyTo(outputStream)
                                }
                            }
                        } catch (e: Exception) {
                            e.printStackTrace()
                        } finally {
                            tempFile.delete()
                        }
                    }
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
                    val tempFile = File(context.cacheDir, "temp_restore.susfs_backup")
                    context.contentResolver.openInputStream(fileUri)?.use { inputStream ->
                        tempFile.outputStream().use { outputStream ->
                            inputStream.copyTo(outputStream)
                        }
                    }

                    val backup = SuSFSManager.validateBackupFile(tempFile.absolutePath)
                    if (backup != null) {
                        selectedBackupFile = tempFile.absolutePath
                        backupInfo = backup
                        showRestoreConfirmDialog = true
                    } else {
                        tempFile.delete()
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                } finally {
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
            showRestoreConfirmDialog = false
            selectedBackupFile = null
            backupInfo = null
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
                    } catch (e: Exception) {
                        e.printStackTrace()
                    } finally {
                        internalLoading = false
                        onLoadingChange(false)
                        showRestoreConfirmDialog = false
                        kotlinx.coroutines.delay(100)
                        selectedBackupFile = null
                        backupInfo = null
                    }
                }
            }
        }
    )

    Card(
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
        OverlayDialog(
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
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                        Button(
                            onClick = onBackup,
                            enabled = !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
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
        OverlayDialog(
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
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                        Button(
                            onClick = onSelectFile,
                            enabled = !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
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
    backupInfo: SuSFSManager.BackupData?,
    isLoading: Boolean,
    onConfirm: () -> Unit
) {
    val showDialogState = remember { mutableStateOf(showDialog && backupInfo != null) }

    LaunchedEffect(showDialog, backupInfo) {
        showDialogState.value = showDialog && backupInfo != null
    }

    if (showDialogState.value && backupInfo != null) {
        OverlayDialog(
            show = showDialogState.value,
            title = stringResource(R.string.susfs_restore_confirm_title),
            onDismissRequest = onDismiss,
            content = {
                Column(
                    modifier = Modifier.padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(stringResource(R.string.susfs_restore_confirm_description))

                    Card(
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
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                        Button(
                            onClick = onConfirm,
                            enabled = !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(stringResource(R.string.susfs_restore_confirm))
                        }
                    }
                }
            }
        )
    }
}
