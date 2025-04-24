package com.sukisu.ultra.ui.screen

import android.app.Activity.RESULT_OK
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import com.sukisu.ultra.ui.component.*
import com.sukisu.ultra.ui.theme.*
import com.sukisu.ultra.ui.viewmodel.KpmViewModel
import com.sukisu.ultra.ui.util.*
import java.io.File
import androidx.core.content.edit
import com.sukisu.ultra.R
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.InputStreamReader
import java.net.*

/**
 * KPM 管理界面
 * 以下内核模块功能由KernelPatch开发，经过修改后加入SukiSU Ultra的内核模块功能
 * 开发者：ShirkNeko, Liaokong
 */
@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun KpmScreen(
    navigator: DestinationsNavigator,
    viewModel: KpmViewModel = viewModel()
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackBarHost = remember { SnackbarHostState() }
    val confirmDialog = rememberConfirmDialog()
    val cardColor = if (!ThemeConfig.useDynamicColor) {
        ThemeConfig.currentTheme.ButtonContrast
    } else {
        MaterialTheme.colorScheme.secondaryContainer
    }

    val moduleConfirmContentMap = viewModel.moduleList.associate { module ->
        val moduleFileName = module.id
        module.id to stringResource(R.string.confirm_uninstall_content, moduleFileName)
    }

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    val kpmInstallSuccess = stringResource(R.string.kpm_install_success)
    val kpmInstallFailed = stringResource(R.string.kpm_install_failed)
    val cancel = stringResource(R.string.cancel)
    val uninstall = stringResource(R.string.uninstall)
    val failedToCheckModuleFile = stringResource(R.string.snackbar_failed_to_check_module_file)
    val kpmUninstallSuccess = stringResource(R.string.kpm_uninstall_success)
    val kpmUninstallFailed = stringResource(R.string.kpm_uninstall_failed)
    val kpmInstallMode = stringResource(R.string.kpm_install_mode)
    val kpmInstallModeLoad = stringResource(R.string.kpm_install_mode_load)
    val kpmInstallModeEmbed = stringResource(R.string.kpm_install_mode_embed)
    val invalidFileTypeMessage = stringResource(R.string.invalid_file_type)
    val confirmTitle = stringResource(R.string.confirm_uninstall_title_with_filename)

    var tempFileForInstall by remember { mutableStateOf<File?>(null) }
    val installModeDialog = rememberCustomDialog { dismiss ->
        var moduleName by remember { mutableStateOf<String?>(null) }

        LaunchedEffect(tempFileForInstall) {
            tempFileForInstall?.let { tempFile ->
                try {
                    val command = arrayOf("su", "-c", "strings ${tempFile.absolutePath} | grep 'name='")
                    val process = Runtime.getRuntime().exec(command)
                    val inputStream = process.inputStream
                    val reader = BufferedReader(InputStreamReader(inputStream))
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        if (line!!.startsWith("name=")) {
                            moduleName = line.substringAfter("name=").trim()
                            break
                        }
                    }
                    process.waitFor()
                } catch (e: Exception) {
                    Log.e("KsuCli", "Failed to get module name: ${e.message}", e)
                }
            }
        }
        AlertDialog(
            onDismissRequest = {
                dismiss()
                tempFileForInstall?.delete()
                tempFileForInstall = null
            },
            title = { Text(kpmInstallMode) },
            text = { moduleName?.let { Text(stringResource(R.string.kpm_install_mode_description, it)) } },
            confirmButton = {
                Column {
                    Button(
                        onClick = {
                            scope.launch {
                                dismiss()
                                tempFileForInstall?.let { tempFile ->
                                    handleModuleInstall(
                                        tempFile = tempFile,
                                        isEmbed = false,
                                        viewModel = viewModel,
                                        snackBarHost = snackBarHost,
                                        kpmInstallSuccess = kpmInstallSuccess,
                                        kpmInstallFailed = kpmInstallFailed
                                    )
                                }
                                tempFileForInstall = null
                            }
                        }
                    ) {
                        Text(kpmInstallModeLoad)
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = {
                            scope.launch {
                                dismiss()
                                tempFileForInstall?.let { tempFile ->
                                    handleModuleInstall(
                                        tempFile = tempFile,
                                        isEmbed = true,
                                        viewModel = viewModel,
                                        snackBarHost = snackBarHost,
                                        kpmInstallSuccess = kpmInstallSuccess,
                                        kpmInstallFailed = kpmInstallFailed
                                    )
                                }
                                tempFileForInstall = null
                            }
                        }
                    ) {
                        Text(kpmInstallModeEmbed)
                    }
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        dismiss()
                        tempFileForInstall?.delete()
                        tempFileForInstall = null
                    }
                ) {
                    Text(cancel)
                }
            }
        )
    }

    val selectPatchLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode != RESULT_OK) return@rememberLauncherForActivityResult

        val uri = result.data?.data ?: return@rememberLauncherForActivityResult

        scope.launch {
            val fileName = uri.lastPathSegment ?: "unknown.kpm"
            val encodedFileName = URLEncoder.encode(fileName, "UTF-8")
            val tempFile = File(context.cacheDir, encodedFileName)

            context.contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }

            val mimeType = context.contentResolver.getType(uri)
            val isCorrectMimeType = mimeType == null || mimeType.contains("application/octet-stream")

            if (!isCorrectMimeType) {
                var shouldShowSnackbar = true
                try {
                    val matchCount = checkStringsCommand(tempFile)
                    val isElf = isElfFile(tempFile)

                    if (matchCount >= 1 || isElf) {
                        shouldShowSnackbar = false
                    }
                } catch (e: Exception) {
                    Log.e("KsuCli", "Failed to execute checks: ${e.message}", e)
                }
                if (shouldShowSnackbar) {
                    snackBarHost.showSnackbar(
                        message = invalidFileTypeMessage,
                        duration = SnackbarDuration.Short
                    )
                }
                tempFile.delete()
                return@launch
            }
            tempFileForInstall = tempFile
            installModeDialog.show()
        }
    }

    LaunchedEffect(Unit) {
        while(true) {
            viewModel.fetchModuleList()
            delay(5000)
        }
    }

    val sharedPreferences = context.getSharedPreferences("app_preferences", Context.MODE_PRIVATE)
    var isNoticeClosed by remember { mutableStateOf(sharedPreferences.getBoolean("is_notice_closed", false)) }

    Scaffold(
        topBar = {
            SearchAppBar(
                title = { Text(stringResource(R.string.kpm_title)) },
                searchText = viewModel.search,
                onSearchTextChange = { viewModel.search = it },
                onClearClick = { viewModel.search = "" },
                scrollBehavior = scrollBehavior,
                dropdownContent = {
                    IconButton(onClick = { viewModel.fetchModuleList() }) {
                        Icon(
                            imageVector = Icons.Outlined.Refresh,
                            contentDescription = stringResource(R.string.refresh)
                        )
                    }
                }
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = {
                    selectPatchLauncher.launch(
                        Intent(Intent.ACTION_GET_CONTENT).apply {
                            type = "application/octet-stream"
                        }
                    )
                },
                icon = {
                    Icon(
                        imageVector = Icons.Outlined.Add,
                        contentDescription = stringResource(R.string.kpm_install)
                    )
                },
                text = { Text(stringResource(R.string.kpm_install)) },
                containerColor = cardColor.copy(alpha = 1f),
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer
            )
        },
        snackbarHost = { SnackbarHost(snackBarHost) }
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            if (!isNoticeClosed) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.kernel_module_notice),
                        modifier = Modifier.weight(1f),
                        textAlign = TextAlign.Center
                    )
                    IconButton(onClick = {
                        isNoticeClosed = true
                        sharedPreferences.edit { putBoolean("is_notice_closed", true) }
                    }) {
                        Icon(
                            imageVector = Icons.Outlined.Close,
                            contentDescription = stringResource(R.string.close_notice)
                        )
                    }
                }
            }

            if (viewModel.moduleList.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        stringResource(R.string.kpm_empty),
                        textAlign = TextAlign.Center
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    items(viewModel.moduleList) { module ->
                        KpmModuleItem(
                            module = module,
                            onUninstall = {
                                scope.launch {
                                    val confirmContent = moduleConfirmContentMap[module.id] ?: ""
                                    handleModuleUninstall(
                                        module = module,
                                        viewModel = viewModel,
                                        snackBarHost = snackBarHost,
                                        kpmUninstallSuccess = kpmUninstallSuccess,
                                        kpmUninstallFailed = kpmUninstallFailed,
                                        failedToCheckModuleFile = failedToCheckModuleFile,
                                        uninstall = uninstall,
                                        cancel = cancel,
                                        confirmDialog = confirmDialog,
                                        confirmTitle = confirmTitle,
                                        confirmContent = confirmContent
                                    )
                                }
                            },
                            onControl = {
                                viewModel.loadModuleDetail(module.id)
                            }
                        )
                    }
                }
            }
        }
    }
}

private suspend fun handleModuleInstall(
    tempFile: File,
    isEmbed: Boolean,
    viewModel: KpmViewModel,
    snackBarHost: SnackbarHostState,
    kpmInstallSuccess: String,
    kpmInstallFailed: String
) {
    var moduleId: String? = null
    try {
        val command = arrayOf("su", "-c", "strings ${tempFile.absolutePath} | grep 'name='")
        val process = Runtime.getRuntime().exec(command)
        val inputStream = process.inputStream
        val reader = BufferedReader(InputStreamReader(inputStream))
        var line: String?
        while (reader.readLine().also { line = it } != null) {
            if (line!!.startsWith("name=")) {
                moduleId = line.substringAfter("name=").trim()
                break
            }
        }
        process.waitFor()
    } catch (e: Exception) {
        Log.e("KsuCli", "Failed to get module ID from strings command: ${e.message}", e)
    }

    if (moduleId == null || moduleId.isEmpty()) {
        Log.e("KsuCli", "Failed to extract module ID from file: ${tempFile.name}")
        snackBarHost.showSnackbar(
            message = kpmInstallFailed,
            duration = SnackbarDuration.Short
        )
        tempFile.delete()
        return
    }

    val targetPath = "/data/adb/kpm/$moduleId.kpm"

    try {
        if (isEmbed) {
            Runtime.getRuntime().exec(arrayOf("su", "-c", "mkdir -p /data/adb/kpm")).waitFor()
            Runtime.getRuntime().exec(arrayOf("su", "-c", "cp ${tempFile.absolutePath} $targetPath")).waitFor()
        }

        val loadResult = loadKpmModule(tempFile.absolutePath)
        if (loadResult.startsWith("Error")) {
            Log.e("KsuCli", "Failed to load KPM module: $loadResult")
            snackBarHost.showSnackbar(
                message = kpmInstallFailed,
                duration = SnackbarDuration.Short
            )
        } else {
            viewModel.fetchModuleList()
            snackBarHost.showSnackbar(
                message = kpmInstallSuccess,
                duration = SnackbarDuration.Short
            )
        }
    } catch (e: Exception) {
        Log.e("KsuCli", "Failed to load KPM module: ${e.message}", e)
        snackBarHost.showSnackbar(
            message = kpmInstallFailed,
            duration = SnackbarDuration.Short
        )
    }
    tempFile.delete()
}

private suspend fun handleModuleUninstall(
    module: KpmViewModel.ModuleInfo,
    viewModel: KpmViewModel,
    snackBarHost: SnackbarHostState,
    kpmUninstallSuccess: String,
    kpmUninstallFailed: String,
    failedToCheckModuleFile: String,
    uninstall: String,
    cancel: String,
    confirmTitle : String,
    confirmContent : String,
    confirmDialog: ConfirmDialogHandle
) {
    val moduleFileName = "${module.id}.kpm"
    val moduleFilePath = "/data/adb/kpm/$moduleFileName"

    val fileExists = try {
        val result = Runtime.getRuntime().exec(arrayOf("su", "-c", "ls /data/adb/kpm/$moduleFileName")).waitFor() == 0
        result
    } catch (e: Exception) {
        Log.e("KsuCli", "Failed to check module file existence: ${e.message}", e)
        snackBarHost.showSnackbar(
            message = failedToCheckModuleFile,
            duration = SnackbarDuration.Short
        )
        false
    }
    val confirmResult = confirmDialog.awaitConfirm(
        title = confirmTitle,
        content = confirmContent,
        confirm = uninstall,
        dismiss = cancel
    )

    if (confirmResult == ConfirmResult.Confirmed) {
        try {
            val unloadResult = unloadKpmModule(module.id)
            if (unloadResult.startsWith("Error")) {
                Log.e("KsuCli", "Failed to unload KPM module: $unloadResult")
                snackBarHost.showSnackbar(
                    message = kpmUninstallFailed,
                    duration = SnackbarDuration.Short
                )
                return
            }

            if (fileExists) {
                Runtime.getRuntime().exec(arrayOf("su", "-c", "rm $moduleFilePath")).waitFor()
            }

            viewModel.fetchModuleList()
            snackBarHost.showSnackbar(
                message = kpmUninstallSuccess,
                duration = SnackbarDuration.Short
            )
        } catch (e: Exception) {
            Log.e("KsuCli", "Failed to unload KPM module: ${e.message}", e)
            snackBarHost.showSnackbar(
                message = kpmUninstallFailed,
                duration = SnackbarDuration.Short
            )
        }
    }
}

@Composable
private fun KpmModuleItem(
    module: KpmViewModel.ModuleInfo,
    onUninstall: () -> Unit,
    onControl: () -> Unit
) {
    val viewModel: KpmViewModel = viewModel()
    val scope = rememberCoroutineScope()
    val snackBarHost = remember { SnackbarHostState() }
    val successMessage = stringResource(R.string.kpm_control_success)
    val failureMessage = stringResource(R.string.kpm_control_failed)

    if (viewModel.showInputDialog && viewModel.selectedModuleId == module.id) {
        AlertDialog(
            onDismissRequest = { viewModel.hideInputDialog() },
            title = { Text(stringResource(R.string.kpm_control)) },
            text = {
                OutlinedTextField(
                    value = viewModel.inputArgs,
                    onValueChange = { viewModel.updateInputArgs(it) },
                    label = { Text(stringResource(R.string.kpm_args)) },
                    placeholder = { Text(module.args) }
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        scope.launch {
                            val result = viewModel.executeControl()
                            val message = when (result) {
                                0 -> successMessage
                                else -> failureMessage
                            }
                            snackBarHost.showSnackbar(message)
                            onControl()
                        }
                    }
                ) {
                    Text(stringResource(R.string.confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.hideInputDialog() }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.secondaryContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = getCardElevation())
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = module.name,
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = "${stringResource(R.string.kpm_version)}: ${module.version}",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = "${stringResource(R.string.kpm_author)}: ${module.author}",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = "${stringResource(R.string.kpm_args)}: ${module.args}",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = module.description,
                style = MaterialTheme.typography.bodyMedium
            )

            Spacer(modifier = Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilledTonalButton(
                    onClick = { viewModel.showInputDialog(module.id) },
                    enabled = module.hasAction
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Settings,
                        contentDescription = null
                    )
                    Text(stringResource(R.string.kpm_control))
                }

                FilledTonalButton(
                    onClick = onUninstall
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Delete,
                        contentDescription = null
                    )
                    Text(stringResource(R.string.kpm_uninstall))
                }
            }
        }
    }
}

private fun checkStringsCommand(tempFile: File): Int {
    val command = arrayOf("su", "-c", "strings ${tempFile.absolutePath} | grep -E 'name=|version=|license=|author='")
    val process = Runtime.getRuntime().exec(command)
    val inputStream = process.inputStream
    val reader = BufferedReader(InputStreamReader(inputStream))
    var line: String?
    var matchCount = 0
    val keywords = listOf("name=", "version=", "license=", "author=")
    var nameExists = false

    while (reader.readLine().also { line = it } != null) {
        if (!nameExists && line!!.startsWith("name=")) {
            nameExists = true
            matchCount++
        } else if (nameExists) {
            for (keyword in keywords) {
                if (line!!.startsWith(keyword)) {
                    matchCount++
                    break
                }
            }
        }
    }
    process.waitFor()

    return if (nameExists) matchCount else 0
}

private fun isElfFile(tempFile: File): Boolean {
    val elfMagic = byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
    val fileBytes = ByteArray(4)
    FileInputStream(tempFile).use { input ->
        input.read(fileBytes)
    }
    return fileBytes.contentEquals(elfMagic)
}