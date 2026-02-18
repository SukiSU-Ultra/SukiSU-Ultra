package com.sukisu.ultra.ui

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.LocalActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import kotlinx.coroutines.launch
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.ConfirmResult
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.kernelFlash.KpmPatchOption
import com.sukisu.ultra.ui.kernelFlash.KpmPatchSelectionDialog
import com.sukisu.ultra.ui.kernelFlash.component.SlotSelectionDialog
import com.sukisu.ultra.ui.screen.FlashIt
import com.sukisu.ultra.ui.util.getFileName
import com.sukisu.ultra.ui.util.isAbDevice
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import kotlinx.coroutines.flow.MutableStateFlow

private sealed class DialogState {
    data object None : DialogState()
    data class SlotSelection(val kernelUri: Uri) : DialogState()
    data class KpmSelection(val kernelUri: Uri, val slot: String?) : DialogState()
}

@SuppressLint("StringFormatInvalid")
@Composable
fun HandleZipFileIntent(
    intentState: MutableStateFlow<Int>,
) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val confirmDialog = rememberConfirmDialog()
    val scope = rememberCoroutineScope()
    var processed by remember { mutableStateOf(false) }
    
    var dialogState by remember { mutableStateOf<DialogState>(DialogState.None) }
    var kpmPatchOption by remember { mutableStateOf(KpmPatchOption.FOLLOW_KERNEL) }
    val isSafeMode = Natives.isSafeMode

    val isSafeModeString = stringResource(R.string.safe_mode_module_disabled)
    val zipTypeModuleString = stringResource(R.string.zip_type_module)
    val zipTypeKernelString = stringResource(R.string.zip_type_kernel)
    val zipFileUnknownString = stringResource(R.string.zip_file_unknown)
    val mixedInstallPromptWithName = stringResource(R.string.mixed_install_prompt_with_name)
    val kernelInstallPromptWithName = stringResource(R.string.kernel_install_prompt_with_name)
    val moduleInstallPromptWithName = stringResource(R.string.module_install_prompt_with_name)
    val horizonKernelString = stringResource(R.string.horizon_kernel)
    val moduleString = stringResource(R.string.module)

    val intentStateValue by intentState.collectAsState()
    val activity = LocalActivity.current ?: return
    
    LaunchedEffect(intentStateValue) {
        if (processed) return@LaunchedEffect
        val zipUris = mutableSetOf<Uri>()
        val intent = activity.intent
        
        fun isModuleFile(uri: Uri?): Boolean {
            if (uri == null) return false
            val uriString = uri.toString()
            return uriString.endsWith(".zip", ignoreCase = true) || 
                   uriString.endsWith(".apk", ignoreCase = true)
        }
        
        when (intent.action) {
            Intent.ACTION_VIEW, Intent.ACTION_SEND -> {
                val data = intent.data
                val stream = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                }
                
                when {
                    isModuleFile(data) -> {
                        zipUris.add(data!!)
                    }
                    isModuleFile(stream) -> {
                        zipUris.add(stream!!)
                    }
                }
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val streamList = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
                }
                streamList?.forEach { uri ->
                    if (isModuleFile(uri)) {
                        zipUris.add(uri)
                    }
                }
            }
        }
        
        intent.clipData?.let { clipData ->
            for (i in 0 until clipData.itemCount) {
                clipData.getItemAt(i)?.uri?.let { uri ->
                    if (isModuleFile(uri)) {
                        zipUris.add(uri)
                    }
                }
            }
        }
        
        if (zipUris.isNotEmpty()) {
            processed = true
            
            val zipUrisList = zipUris.toList()
            
            // 检测 zip 文件类型
            val zipTypes = withContext(Dispatchers.IO) {
                zipUrisList.map { uri -> detectZipType(context, uri) }
            }
            
            val moduleUris = zipUrisList.filterIndexed { index, _ -> zipTypes[index] == ZipType.MODULE }
            val kernelUris = zipUrisList.filterIndexed { index, _ -> zipTypes[index] == ZipType.KERNEL }
            val unknownUris = zipUrisList.filterIndexed { index, _ -> zipTypes[index] == ZipType.UNKNOWN }

            val finalModuleUris = moduleUris + unknownUris
            
            val fileNames = zipUrisList.mapIndexed { index, uri -> 
                val fileName = uri.getFileName(context) ?: zipFileUnknownString
                val type = when (zipTypes[index]) {
                    ZipType.MODULE -> zipTypeModuleString
                    ZipType.KERNEL -> zipTypeKernelString
                    ZipType.UNKNOWN -> zipFileUnknownString
                }
                "\n${index + 1}. $fileName$type"
            }.joinToString("")
            
            val confirmContent = when {
                moduleUris.isNotEmpty() && kernelUris.isNotEmpty() -> {
                    mixedInstallPromptWithName.format(fileNames)
                }
                kernelUris.isNotEmpty() -> {
                    kernelInstallPromptWithName.format(fileNames)
                }
                else -> {
                    moduleInstallPromptWithName.format(fileNames)
                }
            }
            
            val confirmTitle = if (kernelUris.isNotEmpty() && moduleUris.isEmpty()) {
                horizonKernelString
            } else {
                moduleString
            }
            
            val result = confirmDialog.awaitConfirm(
                title = confirmTitle,
                content = confirmContent
            )
            
            if (result == ConfirmResult.Confirmed) {
                if (finalModuleUris.isNotEmpty()) {
                    // 如果处于安全模式，禁止安装模块
                    if (isSafeMode) {
                        Toast.makeText(context, isSafeModeString, Toast.LENGTH_SHORT).show()
                    } else {
                        navigator.push(Route.Flash((FlashIt.FlashModules(finalModuleUris))))
                    }
                }
                
                // 处理内核安装
                if (kernelUris.isNotEmpty()) {
                    val kernelUri = kernelUris.first()
                    val isAbDeviceValue = withContext(Dispatchers.IO) { isAbDevice() }
                    dialogState = if (isAbDeviceValue) {
                        // AB设备：先选择槽位
                        DialogState.SlotSelection(kernelUri)
                    } else {
                        // 非AB设备：直接选择KPM
                        DialogState.KpmSelection(kernelUri, null)
                    }
                }
            }
        }
    }
    
    // 槽位选择
    when (val state = dialogState) {
        is DialogState.SlotSelection -> {
            SlotSelectionDialog(
                show = true,
                onDismiss = { },
                onSlotSelected = { _ ->
                    scope.launch {
                        delay(300)
                    }
                }
            )
        }
        is DialogState.KpmSelection -> {
            KpmPatchSelectionDialog(
                show = true,
                currentOption = kpmPatchOption,
                onDismiss = { },
                onOptionSelected = { option ->

                    navigator.push(
                        Route.KernelFlash(
                            kernelUri = state.kernelUri,
                            selectedSlot = state.slot,
                            kpmPatchEnabled = option == KpmPatchOption.PATCH_KPM,
                            kpmUndoPatch = option == KpmPatchOption.UNDO_PATCH_KPM
                        )
                    )
                }
            )
        }
        is DialogState.None -> {
        }
    }
}

enum class ZipType {
    MODULE,
    KERNEL,
    UNKNOWN
}

fun detectZipType(context: Context, uri: Uri): ZipType {
    // 首先检查文件扩展名，APK 文件可能是模块
    val uriString = uri.toString().lowercase()
    val isApk = uriString.endsWith(".apk", ignoreCase = true)
    
    return try {
        context.contentResolver.openInputStream(uri)?.use { inputStream ->
            java.util.zip.ZipInputStream(inputStream).use { zipStream ->
                var hasModuleProp = false
                var hasToolsFolder = false
                var hasAnykernelSh = false

                var entry = zipStream.nextEntry
                while (entry != null) {
                    val entryName = entry.name.lowercase()

                    when {
                        entryName == "module.prop" || entryName.endsWith("/module.prop") -> {
                            hasModuleProp = true
                        }
                        entryName.startsWith("tools/") || entryName == "tools" -> {
                            hasToolsFolder = true
                        }
                        entryName == "anykernel.sh" || entryName.endsWith("/anykernel.sh") -> {
                            hasAnykernelSh = true
                        }
                    }

                    zipStream.closeEntry()
                    entry = zipStream.nextEntry
                }

                when {
                    hasModuleProp -> ZipType.MODULE
                    hasToolsFolder && hasAnykernelSh -> ZipType.KERNEL
                    // APK 文件如果没有检测到其他类型，默认当作模块处理
                    isApk -> ZipType.MODULE
                    else -> ZipType.UNKNOWN
                }
            }
        } ?: run {
            // 如果无法打开文件流，APK 文件默认当作模块处理
            if (isApk) ZipType.MODULE else ZipType.UNKNOWN
        }
    } catch (e: java.io.IOException) {
        e.printStackTrace()
        // 如果是 APK 文件但读取失败，仍然当作模块处理
        if (isApk) ZipType.MODULE else ZipType.UNKNOWN
    }
}
