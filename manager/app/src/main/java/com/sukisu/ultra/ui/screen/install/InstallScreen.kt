package com.sukisu.ultra.ui.screen.install

import android.app.Activity
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.dropUnlessResumed
import com.sukisu.ultra.R
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.choosekmidialog.ChooseKmiDialog
import com.sukisu.ultra.ui.kernelFlash.KpmPatchOption
import com.sukisu.ultra.ui.kernelFlash.KpmPatchSelectionDialog
import com.sukisu.ultra.ui.kernelFlash.component.SlotSelectionDialog
import com.sukisu.ultra.ui.kernelFlash.rememberAnyKernel3State
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.screen.flash.FlashIt
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.util.LkmSelection
import com.sukisu.ultra.ui.util.getAvailablePartitions
import com.sukisu.ultra.ui.util.getCurrentKmi
import com.sukisu.ultra.ui.util.getDefaultPartition
import com.sukisu.ultra.ui.util.getSlotSuffix
import com.sukisu.ultra.ui.util.isAbDevice
import android.net.Uri
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalResources
import com.sukisu.ultra.ui.util.*
import kotlinx.coroutines.launch

@Composable
fun InstallScreen(
    preselectedKernelUri: Uri? = null
) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val snackbarHost = remember { SnackbarHostState() }
    val uiMode = LocalUiMode.current
    val scope = rememberCoroutineScope()
    val resources = LocalResources.current

    var installMethod by rememberSaveable { mutableStateOf<InstallMethod?>(null) }
    var lkmSelection by rememberSaveable { mutableStateOf<LkmSelection>(LkmSelection.KmiNone) }
    var partitionSelectionIndex by rememberSaveable { mutableIntStateOf(0) }
    var hasCustomSelected by rememberSaveable { mutableStateOf(false) }
    val showChooseKmiDialog = rememberSaveable { mutableStateOf(false) }
    var advancedOptionsShown by rememberSaveable { mutableStateOf(false) }
    var allowShell by rememberSaveable { mutableStateOf(false) }
    var enableAdb by rememberSaveable { mutableStateOf(false) }
    var forceBackup by rememberSaveable { mutableStateOf(false) }

    // Read the configuration from the boot image ksu_config
    val bootConfig by produceState(initialValue = BootConfig()) { value = getBootConfig() }
    var spoofRelease by rememberSaveable { mutableStateOf(SuSFSManager.getKernelSpoofRelease()) }
    var spoofVersion by rememberSaveable { mutableStateOf(SuSFSManager.getKernelSpoofVersion()) }

    LaunchedEffect(bootConfig) {
        spoofRelease = bootConfig.spoofRelease.ifEmpty { spoofRelease }
        spoofVersion = bootConfig.spoofVersion.ifEmpty { spoofVersion }
    }

    val currentKmi by produceState(initialValue = "") { value = getCurrentKmi() }
    val partitions by produceState(initialValue = emptyList()) { value = getAvailablePartitions() }
    val defaultPartition by produceState(initialValue = "") { value = getDefaultPartition() }
    val rootAvailable by produceState(initialValue = false) { value = rootAvailable() }
    val isAbDevice by produceState(initialValue = false) { value = isAbDevice() }
    val isGkiDevice by produceState(initialValue = false) { value = getKernelVersion().isGKI() }

    val selectFileTip = stringResource(id = R.string.select_file_tip, defaultPartition)
    val selectFileTipNoGki = stringResource(id = R.string.select_file_tip_nogki)
    val horizonKernelSummary = stringResource(R.string.horizon_kernel_summary)
    val installMethodOptions = remember(rootAvailable, isAbDevice, isGkiDevice, selectFileTip, selectFileTipNoGki, horizonKernelSummary) {
        buildList {
            add(InstallMethod.SelectFile(summary = if (isGkiDevice) selectFileTip else selectFileTipNoGki))
            if (rootAvailable && isGkiDevice) {
                add(InstallMethod.DirectInstall)
                if (isAbDevice) add(InstallMethod.DirectInstallToInactiveSlot)
                add(InstallMethod.HorizonKernel(summary = horizonKernelSummary))
            }
        }
    }

    val installMethodState = remember { mutableStateOf<InstallMethod?>(null) }

    // AnyKernel3 状态
    val anyKernel3State = rememberAnyKernel3State(
        installMethodState = installMethodState,
        preselectedKernelUri = preselectedKernelUri?.toString(),
        horizonKernelSummary = horizonKernelSummary,
        isAbDevice = isAbDevice
    )

    // 同步 installMethod 和 anyKernel3State
    LaunchedEffect(installMethod) {
        installMethodState.value = installMethod
    }

    val kpmPatchOption = anyKernel3State.kpmPatchOption
    val showSlotSelectionDialog = anyKernel3State.showSlotSelectionDialog && isAbDevice
    val showKpmPatchDialog = anyKernel3State.showKpmPatchDialog

    // 槽位选择对话框
    if (showSlotSelectionDialog) {
        SlotSelectionDialog(
            show = true,
            onDismiss = { anyKernel3State.onDismissSlotDialog() },
            onSlotSelected = { slot ->
                anyKernel3State.onSlotSelected(slot)
            }
        )
    }

    // KPM补丁选择对话框
    if (showKpmPatchDialog) {
        KpmPatchSelectionDialog(
            show = true,
            currentOption = kpmPatchOption,
            onDismiss = { anyKernel3State.onDismissPatchDialog() },
            onOptionSelected = { option ->
                anyKernel3State.onOptionSelected(option)
            }
        )
    }

    val isOta = installMethod is InstallMethod.DirectInstallToInactiveSlot
    val slotSuffix by produceState(initialValue = "", isOta) { value = getSlotSuffix(isOta) }
    val defaultIndex = remember(partitions, defaultPartition) {
        partitions.indexOf(defaultPartition).coerceAtLeast(0)
    }

    LaunchedEffect(partitions, defaultIndex, hasCustomSelected) {
        if (partitions.isEmpty()) return@LaunchedEffect
        if (!hasCustomSelected) {
            partitionSelectionIndex = defaultIndex.coerceIn(0, partitions.lastIndex)
        } else if (partitionSelectionIndex > partitions.lastIndex) {
            partitionSelectionIndex = partitions.lastIndex
        }
    }

    val displayPartitions = remember(partitions, defaultPartition) {
        partitions.map { name -> if (defaultPartition == name) "$name (default)" else name }
    }

    fun showMessage(message: String) {
        scope.launch {
            if (uiMode == UiMode.Material) {
                snackbarHost.showSnackbar(message)
            } else {
                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    val onInstall = {
        installMethod?.let { method ->
            when (method) {
                is InstallMethod.HorizonKernel -> {
                    method.uri?.let { uri ->
                        navigator.push(
                            Route.KernelFlash(
                                kernelUri = uri,
                                selectedSlot = method.slot,
                                kpmPatchEnabled = kpmPatchOption == KpmPatchOption.PATCH_KPM,
                                kpmUndoPatch = kpmPatchOption == KpmPatchOption.UNDO_PATCH_KPM
                            )
                        )
                    }
                }
                else -> {
                    val isOta = method is InstallMethod.DirectInstallToInactiveSlot
                    navigator.push(
                        Route.Flash(
                            FlashIt.FlashBoot(
                                boot = if (method is InstallMethod.SelectFile) method.uri else null,
                                lkm = lkmSelection,
                                ota = isOta,
                                partition = partitions.getOrNull(partitionSelectionIndex),
                                allowShell = allowShell,
                                enableAdb = enableAdb,
                                backup = method is InstallMethod.SelectFile && forceBackup,
                                spoofRelease = spoofRelease.trim(),
                                spoofVersion = spoofVersion.trim(),
                            )
                        )
                    )
                }
            }
        }
    }

    ChooseKmiDialog(
        show = showChooseKmiDialog.value,
        onDismissRequest = { showChooseKmiDialog.value = false },
        onSelected = { kmi ->
            kmi?.let {
                lkmSelection = LkmSelection.KmiString(it)
                onInstall()
            }
        }
    )

    val selectLkmLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == Activity.RESULT_OK) {
            it.data?.data?.let { uri ->
                if (isKoFile(context, uri)) {
                    lkmSelection = LkmSelection.LkmUri(uri)
                } else {
                    lkmSelection = LkmSelection.KmiNone
                    showMessage(resources.getString(R.string.install_only_support_ko_file))
                }
            }
        }
    }
    val selectImageLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == Activity.RESULT_OK) {
            it.data?.data?.let { uri ->
                val option = when (installMethod) {
                    is InstallMethod.SelectFile -> InstallMethod.SelectFile(uri, summary = selectFileTip)
                    is InstallMethod.HorizonKernel -> InstallMethod.HorizonKernel(uri, summary = horizonKernelSummary)
                    else -> null
                }
                option?.let { opt ->
                    installMethod = opt
                    // 对于 HorizonKernel，需要触发 AnyKernel3 流程（槽位选择和KPM修补）
                    if (opt is InstallMethod.HorizonKernel) {
                        anyKernel3State.onHorizonKernelSelected(opt)
                    }
                }
            }
        }
    }

    val state = InstallUiState(
        installMethod = installMethod,
        lkmSelection = lkmSelection,
        partitionSelectionIndex = partitionSelectionIndex,
        displayPartitions = displayPartitions,
        currentKmi = currentKmi,
        slotSuffix = slotSuffix,
        installMethodOptions = installMethodOptions,
        canSelectPartition = installMethod is InstallMethod.DirectInstall || installMethod is InstallMethod.DirectInstallToInactiveSlot,
        advancedOptionsShown = advancedOptionsShown,
        allowShell = allowShell,
        enableAdb = enableAdb,
        forceBackup = forceBackup,
        canForceBackup = installMethod is InstallMethod.SelectFile,
        spoofRelease = spoofRelease,
        spoofVersion = spoofVersion,
        anyKernel3State = anyKernel3State,
        kpmPatchOption = kpmPatchOption,
        showSlotSelectionDialog = showSlotSelectionDialog,
        showKpmPatchDialog = showKpmPatchDialog,
    )
    val actions = InstallScreenActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onSelectMethod = { method ->
            if (method is InstallMethod.HorizonKernel && method.uri != null) {
                anyKernel3State.onHorizonKernelSelected(method)
            } else {
                installMethod = method
            }
        },
        onSelectBootImage = { method ->
            // 在打开文件选择器之前，先设置 installMethod
            installMethod = method
            selectImageLauncher.launch(Intent(Intent.ACTION_GET_CONTENT).apply {
                type = "application/*"
                putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("application/octet-stream", "application/zip"))
            })
        },
        onUploadLkm = {
            selectLkmLauncher.launch(Intent(Intent.ACTION_GET_CONTENT).apply { type = "application/octet-stream" })
        },
        onClearLkm = { lkmSelection = LkmSelection.KmiNone },
        onSelectPartition = { index ->
            hasCustomSelected = true
            partitionSelectionIndex = index
        },
        onNext = {
            val isLkmSelected = lkmSelection != LkmSelection.KmiNone
            val isKmiUnknown = currentKmi.isBlank()
            val isSelectFileMode = installMethod is InstallMethod.SelectFile
            if (isGkiDevice && !isLkmSelected && (isKmiUnknown || isSelectFileMode) && installMethod !is InstallMethod.HorizonKernel) {
                showChooseKmiDialog.value = true
            } else {
                onInstall()
            }
        },
        onAdvancedOptionsClicked = {
            advancedOptionsShown = !advancedOptionsShown
        },
        onSelectAllowShell = {
            allowShell = it
        },
        onSelectEnableAdb = {
            enableAdb = it
        },
        onSelectForceBackup = {
            forceBackup = it
        },
        onSpoofReleaseChange = {
            spoofRelease = it
            scope.launch {
                SuSFSManager.saveUnameValue(it.trim().ifBlank { "default" })
            }
        },
        onSpoofVersionChange = {
            spoofVersion = it
            scope.launch {
                SuSFSManager.saveBuildTimeValue(it.trim().ifBlank { "default" })
            }
        },
        onHorizonKernelSelected = { method ->
            anyKernel3State.onHorizonKernelSelected(method)
        },
        onReopenSlotDialog = { method ->
            anyKernel3State.onReopenSlotDialog(method)
        },
        onReopenKpmDialog = { method ->
            anyKernel3State.onReopenKpmDialog(method)
        }
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> InstallScreenMiuix(state, actions)
        UiMode.Material -> InstallScreenMaterial(state, actions, snackbarHost)
    }
}
