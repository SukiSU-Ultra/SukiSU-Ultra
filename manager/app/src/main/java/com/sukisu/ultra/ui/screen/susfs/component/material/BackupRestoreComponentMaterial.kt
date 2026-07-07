package com.sukisu.ultra.ui.screen.susfs.component.material

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.ui.platform.LocalLocale
import com.sukisu.ultra.ui.screen.susfs.util.BackupData
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds

@Composable
fun BackupRestoreComponentMaterial(
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

    // 备份文件选择器
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

    // 还原文件选择器
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

    // 备份对话框
    if (showBackupDialog) {
        AlertDialog(
            onDismissRequest = { showBackupDialog = false },
            title = { Text(stringResource(R.string.susfs_backup_title)) },
            text = { Text(stringResource(R.string.susfs_backup_description)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        val dateFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
                        val timestamp = dateFormat.format(Date())
                        backupFileLauncher.launch("SuSFS_Config_$timestamp.susfs_backup")
                    },
                    enabled = !actualLoading
                ) {
                    Text(stringResource(R.string.susfs_backup_create))
                }
            },
            dismissButton = {
                TextButton(onClick = { showBackupDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    // 还原对话框
    if (showRestoreDialog) {
        AlertDialog(
            onDismissRequest = { showRestoreDialog = false },
            title = { Text(stringResource(R.string.susfs_restore_title)) },
            text = { Text(stringResource(R.string.susfs_restore_description)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        restoreFileLauncher.launch(arrayOf("application/json", "*/*"))
                    },
                    enabled = !actualLoading
                ) {
                    Text(stringResource(R.string.susfs_restore_select_file))
                }
            },
            dismissButton = {
                TextButton(onClick = { showRestoreDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    // 还原确认对话框
    if (showRestoreConfirmDialog && backupInfo != null) {
        AlertDialog(
            onDismissRequest = {
                showRestoreConfirmDialog = false
                selectedBackupFile = null
                backupInfo = null
            },
            title = { Text(stringResource(R.string.susfs_restore_confirm_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.susfs_restore_confirm_description))
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", LocalLocale.current.platformLocale)
                            Text(
                                text = stringResource(
                                    R.string.susfs_backup_info_date,
                                    dateFormat.format(Date(backupInfo!!.timestamp))
                                ),
                                style = MaterialTheme.typography.bodySmall
                            )
                            Text(
                                text = stringResource(R.string.susfs_backup_info_device, backupInfo!!.deviceInfo),
                                style = MaterialTheme.typography.bodySmall
                            )
                            Text(
                                text = stringResource(R.string.susfs_backup_info_version, backupInfo!!.version),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
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
                                    delay(100.milliseconds)
                                    selectedBackupFile = null
                                    backupInfo = null
                                }
                            }
                        }
                    },
                    enabled = !actualLoading
                ) {
                    Text(stringResource(R.string.susfs_restore_confirm))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showRestoreConfirmDialog = false
                        selectedBackupFile = null
                        backupInfo = null
                    }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    // 按钮行
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
            OutlinedButton(
                onClick = { showBackupDialog = true },
                enabled = !actualLoading,
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Default.Backup, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text(stringResource(R.string.susfs_backup_title))
            }
            OutlinedButton(
                onClick = { showRestoreDialog = true },
                enabled = !actualLoading,
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Default.Restore, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text(stringResource(R.string.susfs_restore_title))
            }
        }
    }
}
