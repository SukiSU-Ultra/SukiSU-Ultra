package com.sukisu.nova.ui.screen.kpm

import android.annotation.SuppressLint
import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.nova.R
import com.sukisu.nova.ui.LocalUiMode
import com.sukisu.nova.ui.UiMode
import com.sukisu.nova.ui.component.ConfigResult
import com.sukisu.nova.ui.component.ConfigRuntimeStatus
import com.sukisu.nova.ui.component.dialog.ConfirmResult
import com.sukisu.nova.ui.component.dialog.rememberConfirmDialog
import com.sukisu.nova.ui.component.resolveRuntimeStatus
import com.sukisu.nova.ui.screen.susfs.util.SuSFSConfig
import com.sukisu.nova.ui.util.getRootShell
import com.sukisu.nova.ui.util.listKpmModules
import com.sukisu.nova.ui.util.loadKpmModule
import com.sukisu.nova.ui.util.unloadKpmModule
import com.sukisu.nova.ui.viewmodel.KpmViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.time.Duration.Companion.milliseconds

@SuppressLint("LocalContextGetResourceValueCall")
@Composable
fun KpmScreen(bottomInnerPadding: Dp = 0.dp) {
    val context = LocalContext.current
    val appContext = context.applicationContext
    val scope = rememberCoroutineScope()
    val viewModel = viewModel<KpmViewModel>()
    val lifecycleOwner = LocalLifecycleOwner.current
    val confirmDialog = rememberConfirmDialog()
    var pickingFile by remember { mutableStateOf(false) }
    var confirmingUninstall by remember { mutableStateOf(false) }

    val showToast: suspend (String) -> Unit = { message ->
        withContext(Dispatchers.Main) {
            Toast.makeText(appContext, message, Toast.LENGTH_SHORT).show()
        }
    }

    val selectPatchLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        pickingFile = false
        if (uri != null) viewModel.runOperation {
            var stagedFile: File? = null
            try {
                val (file, name) = withContext(Dispatchers.IO) {
                    val file = File.createTempFile("kpm-", ".kpm", appContext.cacheDir)
                    stagedFile = file
                    val input = requireNotNull(appContext.contentResolver.openInputStream(uri))
                    input.use { source -> file.outputStream().use { source.copyTo(it) } }
                    require(isValidKpmFile(file)) { appContext.getString(R.string.invalid_file_type) }
                    val name = requireNotNull(extractModuleName(file)) {
                        appContext.getString(R.string.kpm_install_failed)
                    }
                    require(isSafeKpmModuleId(name)) { appContext.getString(R.string.invalid_file_type) }
                    file to name
                }
                // Store the file before publishing a dialog that can confirm installation.
                viewModel.prepareInstall(file, name)
                stagedFile = null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                showToast(e.localizedMessage ?: appContext.getString(R.string.kpm_install_failed))
            } finally {
                stagedFile?.delete()
            }
        }
    }

    LaunchedEffect(lifecycleOwner, viewModel) {
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (true) {
                viewModel.fetchModuleList(silent = true)
                delay(5000.milliseconds)
            }
        }
    }

    val actions = KpmActions(
        onRefresh = { viewModel.fetchModuleList() },
        onSearchTextChange = viewModel::updateSearchText,
        onRequestInstall = {
            if (!pickingFile && !viewModel.uiState.value.isBusy) {
                pickingFile = true
                try {
                    // Providers do not consistently label .kpm files as octet-stream.
                    selectPatchLauncher.launch("*/*")
                } catch (e: Exception) {
                    pickingFile = false
                    Toast.makeText(context, e.localizedMessage, Toast.LENGTH_SHORT).show()
                }
            }
        },
        onConfirmInstall = { isEmbed ->
            val file = viewModel.getTempFile()
            val moduleId = viewModel.uiState.value.tempModuleName
            if (file != null && moduleId != null) viewModel.runOperation {
                try {
                    handleModuleInstall(appContext, file, moduleId, isEmbed, viewModel, showToast)
                } finally {
                    viewModel.dismissInstallDialog()
                    viewModel.clearTempFile()
                }
            }
        },
        onDismissInstallDialog = {
            if (!viewModel.uiState.value.isBusy) {
                viewModel.dismissInstallDialog()
                viewModel.clearTempFile()
            }
        },
        onRequestUninstall = { moduleId ->
            if (!confirmingUninstall && !viewModel.uiState.value.isBusy) {
                confirmingUninstall = true
                scope.launch {
                    try {
                        val result = confirmDialog.awaitConfirm(
                            title = context.getString(R.string.confirm_uninstall_title_with_filename),
                            content = context.getString(R.string.confirm_uninstall_content, moduleId),
                            confirm = context.getString(R.string.uninstall),
                            dismiss = context.getString(R.string.cancel)
                        )
                        if (result == ConfirmResult.Confirmed) viewModel.runOperation {
                            handleModuleUninstall(appContext, moduleId, showToast, viewModel)
                        }
                    } finally {
                        confirmingUninstall = false
                    }
                }
            }
        },
        onShowInputDialog = viewModel::showInputDialog,
        onHideInputDialog = viewModel::hideInputDialog,
        onInputArgsChange = viewModel::updateInputArgs,
        onExecuteControl = {
            viewModel.runOperation {
                val result = viewModel.executeControl()
                showToast(if (result == 0) appContext.getString(R.string.kpm_control_success)
                    else appContext.getString(R.string.config_exit_code, result))
            }
        }
    )
    when (LocalUiMode.current) {
        UiMode.Miuix -> KpmMiuix(viewModel, actions, bottomInnerPadding)
        UiMode.Material -> KpmMaterial(viewModel, actions, bottomInnerPadding)
    }
}

private suspend fun handleModuleInstall(
    context: Context,
    tempFile: File,
    moduleId: String,
    isEmbed: Boolean,
    viewModel: KpmViewModel,
    showToast: suspend (String) -> Unit
) {
    var saved = false
    try {
        val result = withContext(Dispatchers.IO) {
            require(isSafeKpmModuleId(moduleId))
            if (isEmbed) {
                val targetPath = "/data/adb/kpm/$moduleId.kpm"
                val copy = getRootShell().newJob().add(
                    "mkdir -p /data/adb/kpm && cp ${SuSFSConfig.shellQuote(tempFile.absolutePath)} ${SuSFSConfig.shellQuote(targetPath)}"
                ).to(ArrayList(), ArrayList()).exec()
                check(copy.isSuccess) {
                    copy.err.joinToString("\n").ifBlank { context.getString(R.string.config_exit_code, copy.code) }
                }
                saved = true
            }
            check(loadKpmModule(tempFile.absolutePath)) { context.getString(R.string.config_command_rejected) }
            val runtime = resolveRuntimeStatus(null, true, probeKpmModule(moduleId))
            ConfigResult(moduleId, saved, runtime)
        }
        viewModel.setOperationResult(result)
        showToast(result.description(context))
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val result = ConfigResult(moduleId, saved, ConfigRuntimeStatus.FAILED,
            e.localizedMessage ?: context.getString(R.string.config_command_rejected))
        viewModel.setOperationResult(result)
        showToast(result.description(context))
    }
}

private suspend fun handleModuleUninstall(
    context: Context,
    moduleId: String,
    showToast: suspend (String) -> Unit,
    viewModel: KpmViewModel
) {
    try {
        val result = withContext(Dispatchers.IO) {
            require(isSafeKpmModuleId(moduleId))
            check(unloadKpmModule(moduleId)) { context.getString(R.string.config_command_rejected) }
            // ksud can exit successfully even when the kernel rejects unloading.
            // Confirm removal before deleting the boot-time copy.
            val loaded = probeKpmModule(moduleId)
            check(loaded == false) { context.getString(R.string.config_command_rejected) }
            val removal = getRootShell().newJob().add(
                "rm -f -- ${SuSFSConfig.shellQuote("/data/adb/kpm/$moduleId.kpm")}"
            ).to(ArrayList(), ArrayList()).exec()
            ConfigResult(moduleId, if (removal.isSuccess) false else null,
                ConfigRuntimeStatus.APPLIED,
                if (removal.isSuccess) null else removal.err.joinToString("\n").ifBlank {
                    context.getString(R.string.config_exit_code, removal.code)
                })
        }
        viewModel.setOperationResult(result)
        showToast(result.description(context))
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val result = ConfigResult(moduleId, null, ConfigRuntimeStatus.FAILED,
            e.localizedMessage ?: context.getString(R.string.config_command_rejected))
        viewModel.setOperationResult(result)
        showToast(result.description(context))
    }
}

private fun probeKpmModule(moduleId: String): Boolean? = try {
    listKpmModules().lineSequence().any { it.trim() == moduleId }
} catch (e: CancellationException) {
    throw e
} catch (_: Exception) {
    null
}
