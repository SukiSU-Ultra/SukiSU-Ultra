package com.sukisu.ultra.ui.util

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import com.sukisu.ultra.R
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.*

object ModuleModify {
    @Composable
    fun RestoreConfirmationDialog(
        showDialog: Boolean,
        onConfirm: () -> Unit,
        onDismiss: () -> Unit
    ) {
        val context = LocalContext.current

        if (showDialog) {
            AlertDialog(
                onDismissRequest = onDismiss,
                title = {
                    Text(
                        text = context.getString(R.string.restore_confirm_title),
                        style = MaterialTheme.typography.headlineSmall
                    )
                },
                text = {
                    Text(
                        text = context.getString(R.string.restore_confirm_message),
                        style = MaterialTheme.typography.bodyMedium
                    )
                },
                confirmButton = {
                    TextButton(onClick = onConfirm) {
                        Text(context.getString(R.string.confirm))
                    }
                },
                dismissButton = {
                    TextButton(onClick = onDismiss) {
                        Text(context.getString(R.string.cancel))
                    }
                }
            )
        }
    }

    @Composable
    fun AllowlistRestoreConfirmationDialog(
        showDialog: Boolean,
        onConfirm: () -> Unit,
        onDismiss: () -> Unit
    ) {
        val context = LocalContext.current

        if (showDialog) {
            AlertDialog(
                onDismissRequest = onDismiss,
                title = {
                    Text(
                        text = context.getString(R.string.allowlist_restore_confirm_title),
                        style = MaterialTheme.typography.headlineSmall
                    )
                },
                text = {
                    Text(
                        text = context.getString(R.string.allowlist_restore_confirm_message),
                        style = MaterialTheme.typography.bodyMedium
                    )
                },
                confirmButton = {
                    TextButton(onClick = onConfirm) {
                        Text(context.getString(R.string.confirm))
                    }
                },
                dismissButton = {
                    TextButton(onClick = onDismiss) {
                        Text(context.getString(R.string.cancel))
                    }
                }
            )
        }
    }

    suspend fun backupModules(context: Context, snackBarHost: SnackbarHostState, uri: Uri) {
        withContext(Dispatchers.IO) {
            try {
                val busyboxPath = "/data/adb/ksu/bin/busybox"
                val moduleDir = "/data/adb/modules"

                // 直接将tar输出重定向到用户选择的文件
                val command = """
                    cd "$moduleDir" &&
                    $busyboxPath tar -cz ./* > /proc/self/fd/1
                """.trimIndent()

                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))

                // 直接将tar输出写入到用户选择的文件
                context.contentResolver.openOutputStream(uri)?.use { output ->
                    process.inputStream.copyTo(output)
                }

                val error = BufferedReader(InputStreamReader(process.errorStream)).readText()
                if (process.exitValue() != 0) {
                    throw IOException(context.getString(R.string.command_execution_failed, error))
                }

                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.backup_success),
                        duration = SnackbarDuration.Long
                    )
                }

            } catch (e: Exception) {
                Log.e("Backup", context.getString(R.string.backup_failed, ""), e)
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.backup_failed, e.message),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    suspend fun restoreModules(
        context: Context,
        snackBarHost: SnackbarHostState,
        uri: Uri,
        showConfirmDialog: (Boolean) -> Unit,
        confirmResult: CompletableDeferred<Boolean>
    ) {
        // 显示确认对话框
        withContext(Dispatchers.Main) {
            showConfirmDialog(true)
        }

        val userConfirmed = confirmResult.await()
        if (!userConfirmed) return

        withContext(Dispatchers.IO) {
            try {
                val busyboxPath = "/data/adb/ksu/bin/busybox"
                val moduleDir = "/data/adb/modules"

                // 直接从用户选择的文件读取并解压
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "$busyboxPath tar -xz -C $moduleDir"))

                context.contentResolver.openInputStream(uri)?.use { input ->
                    input.copyTo(process.outputStream)
                }
                process.outputStream.close()

                process.waitFor()

                val error = BufferedReader(InputStreamReader(process.errorStream)).readText()
                if (process.exitValue() != 0) {
                    throw IOException(context.getString(R.string.command_execution_failed, error))
                }

                withContext(Dispatchers.Main) {
                    val snackbarResult = snackBarHost.showSnackbar(
                        message = context.getString(R.string.restore_success),
                        actionLabel = context.getString(R.string.restart_now),
                        duration = SnackbarDuration.Long
                    )
                    if (snackbarResult == SnackbarResult.ActionPerformed) {
                        reboot()
                    }
                }

            } catch (e: Exception) {
                Log.e("Restore", context.getString(R.string.restore_failed, ""), e)
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        message = context.getString(
                            R.string.restore_failed,
                            e.message ?: context.getString(R.string.unknown_error)
                        ),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    suspend fun backupAllowlist(context: Context, snackBarHost: SnackbarHostState, uri: Uri) {
        withContext(Dispatchers.IO) {
            try {
                val allowlistPath = "/data/adb/ksu/.allowlist"

                // 直接复制文件到用户选择的位置
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "cat $allowlistPath"))

                context.contentResolver.openOutputStream(uri)?.use { output ->
                    process.inputStream.copyTo(output)
                }

                val error = BufferedReader(InputStreamReader(process.errorStream)).readText()
                if (process.exitValue() != 0) {
                    throw IOException(context.getString(R.string.command_execution_failed, error))
                }

                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_backup_success),
                        duration = SnackbarDuration.Long
                    )
                }

            } catch (e: Exception) {
                Log.e("AllowlistBackup", context.getString(R.string.allowlist_backup_failed, ""), e)
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_backup_failed, e.message),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    suspend fun restoreAllowlist(
        context: Context,
        snackBarHost: SnackbarHostState,
        uri: Uri,
        showConfirmDialog: (Boolean) -> Unit,
        confirmResult: CompletableDeferred<Boolean>
    ) {
        // 显示确认对话框
        withContext(Dispatchers.Main) {
            showConfirmDialog(true)
        }

        val userConfirmed = confirmResult.await()
        if (!userConfirmed) return

        withContext(Dispatchers.IO) {
            try {
                val allowlistPath = "/data/adb/ksu/.allowlist"

                // 直接从用户选择的文件读取并写入到目标位置
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "cat > $allowlistPath"))

                context.contentResolver.openInputStream(uri)?.use { input ->
                    input.copyTo(process.outputStream)
                }
                process.outputStream.close()

                process.waitFor()

                val error = BufferedReader(InputStreamReader(process.errorStream)).readText()
                if (process.exitValue() != 0) {
                    throw IOException(context.getString(R.string.command_execution_failed, error))
                }

                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_restore_success),
                        duration = SnackbarDuration.Long
                    )
                }

            } catch (e: Exception) {
                Log.e("AllowlistRestore", context.getString(R.string.allowlist_restore_failed, ""), e)
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_restore_failed, e.message),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    @Composable
    fun rememberModuleBackupLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: kotlinx.coroutines.CoroutineScope = rememberCoroutineScope()
    ) = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                scope.launch {
                    backupModules(context, snackBarHost, uri)
                }
            }
        }
    }

    @Composable
    fun rememberModuleRestoreLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: kotlinx.coroutines.CoroutineScope = rememberCoroutineScope()
    ): androidx.activity.result.ActivityResultLauncher<Intent> {
        var showRestoreDialog by remember { mutableStateOf(false) }
        var restoreConfirmResult by remember { mutableStateOf<CompletableDeferred<Boolean>?>(null) }

        // 显示恢复确认对话框
        RestoreConfirmationDialog(
            showDialog = showRestoreDialog,
            onConfirm = {
                showRestoreDialog = false
                restoreConfirmResult?.complete(true)
            },
            onDismiss = {
                showRestoreDialog = false
                restoreConfirmResult?.complete(false)
            }
        )

        return rememberLauncherForActivityResult(
            contract = ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == android.app.Activity.RESULT_OK) {
                result.data?.data?.let { uri ->
                    scope.launch {
                        val confirmResult = CompletableDeferred<Boolean>()
                        restoreConfirmResult = confirmResult

                        restoreModules(
                            context = context,
                            snackBarHost = snackBarHost,
                            uri = uri,
                            showConfirmDialog = { show -> showRestoreDialog = show },
                            confirmResult = confirmResult
                        )
                    }
                }
            }
        }
    }

    @Composable
    fun rememberAllowlistBackupLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: kotlinx.coroutines.CoroutineScope = rememberCoroutineScope()
    ) = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                scope.launch {
                    backupAllowlist(context, snackBarHost, uri)
                }
            }
        }
    }

    @Composable
    fun rememberAllowlistRestoreLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: kotlinx.coroutines.CoroutineScope = rememberCoroutineScope()
    ): androidx.activity.result.ActivityResultLauncher<Intent> {
        var showAllowlistRestoreDialog by remember { mutableStateOf(false) }
        var allowlistRestoreConfirmResult by remember { mutableStateOf<CompletableDeferred<Boolean>?>(null) }

        // 显示允许列表恢复确认对话框
        AllowlistRestoreConfirmationDialog(
            showDialog = showAllowlistRestoreDialog,
            onConfirm = {
                showAllowlistRestoreDialog = false
                allowlistRestoreConfirmResult?.complete(true)
            },
            onDismiss = {
                showAllowlistRestoreDialog = false
                allowlistRestoreConfirmResult?.complete(false)
            }
        )

        return rememberLauncherForActivityResult(
            contract = ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == android.app.Activity.RESULT_OK) {
                result.data?.data?.let { uri ->
                    scope.launch {
                        val confirmResult = CompletableDeferred<Boolean>()
                        allowlistRestoreConfirmResult = confirmResult

                        restoreAllowlist(
                            context = context,
                            snackBarHost = snackBarHost,
                            uri = uri,
                            showConfirmDialog = { show -> showAllowlistRestoreDialog = show },
                            confirmResult = confirmResult
                        )
                    }
                }
            }
        }
    }

    fun createBackupIntent(): Intent {
        return Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/zip"
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
            putExtra(Intent.EXTRA_TITLE, "modules_backup_$timestamp.zip")
        }
    }

    fun createRestoreIntent(): Intent {
        return Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/zip"
        }
    }

    fun createAllowlistBackupIntent(): Intent {
        return Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
            putExtra(Intent.EXTRA_TITLE, "ksu_allowlist_backup_$timestamp.dat")
        }
    }

    fun createAllowlistRestoreIntent(): Intent {
        return Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
        }
    }
}