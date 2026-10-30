package com.sukisu.ultra.ui.screen.install

import android.app.Activity
import android.content.Intent
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import com.sukisu.ultra.R
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.choosekmidialog.ChooseKmiDialog
import com.sukisu.ultra.ui.kernelFlash.KpmPatchOption
import com.sukisu.ultra.ui.kernelFlash.component.SlotSelectionDialog
import com.sukisu.ultra.ui.component.dialog.rememberLoadingDialog
import com.sukisu.ultra.ui.kernelFlash.rememberAnyKernel3State
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.screen.flash.FlashIt
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.util.LkmSelection
import com.sukisu.ultra.ui.util.getAvailablePartitions
import com.sukisu.ultra.ui.util.getCurrentKmi
import com.sukisu.ultra.ui.util.getDefaultPartition
import com.sukisu.ultra.ui.util.getLoadedBlockableModules
import com.sukisu.ultra.ui.util.isBlockModulesValid
import com.sukisu.ultra.ui.util.getSlotSuffix
import com.sukisu.ultra.ui.util.isAbDevice
import android.net.Uri
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalResources
import com.sukisu.ultra.ui.component.dialog.DownloadDialog
import com.sukisu.ultra.ui.util.*
import top.yukonga.miuix.kmp.basic.SnackbarHostState as MiuixSnackbarHostState

@Composable
fun InstallScreen(
    preselectedKernelUri: Uri? = null
) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val snackbarHost = remember { SnackbarHostState() }
    val miuixSnackbarHost = remember { MiuixSnackbarHostState() }
    val uiMode = LocalUiMode.current
    val scope = rememberCoroutineScope()
    val resources = LocalResources.current
    var probeJob by remember { mutableStateOf<Job?>(null) }
    val loadingDialog = rememberLoadingDialog()

    val installMethodState = rememberSaveable { mutableStateOf<InstallMethod?>(null) }
    var installMethod by installMethodState
    var downloadDialogShown by rememberSaveable { mutableStateOf(false) }
    var remotePartitions by rememberSaveable { mutableStateOf(emptyList<String>()) }
    var remotePartitionSelectionIndex by rememberSaveable { mutableIntStateOf(0) }
    var lkmSelection by rememberSaveable { mutableStateOf<LkmSelection>(LkmSelection.KmiNone) }
    var partitionSelectionIndex by rememberSaveable { mutableIntStateOf(0) }
    var hasCustomSelected by rememberSaveable { mutableStateOf(false) }
    val showChooseKmiDialog = rememberSaveable { mutableStateOf(false) }
    var advancedOptionsShown by rememberSaveable { mutableStateOf(false) }
    var allowShell by rememberSaveable { mutableStateOf(false) }
    var enableAdb by rememberSaveable { mutableStateOf(false) }
    var forceBackup by rememberSaveable { mutableStateOf(false) }
    var kpmPatchOption by rememberSaveable { mutableStateOf(KpmPatchOption.FOLLOW_KERNEL) }
    val kpmEnabled = kpmPatchOption.enabled
    val kpmUndo = kpmPatchOption.undo
    val canPatchKpm = android.os.Build.SUPPORTED_ABIS.contains("arm64-v8a")
    val isStandaloneKpm = installMethod == null && canPatchKpm && kpmEnabled
    var kpmBootExpanded by rememberSaveable { mutableStateOf(false) }
    var kpmBootUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    var blockModulesEnabled by rememberSaveable { mutableStateOf(false) }
    var blockModules by rememberSaveable { mutableStateOf("") }
    var blockModulesPrefilled by rememberSaveable { mutableStateOf(false) }
    // Blocking a module the device needs can bootloop it, so nothing is
    // blocked unless the user explicitly opts in.
    val effectiveBlockModules = if (blockModulesEnabled) blockModules else ""

    // Pre-fill the block list with the known anti-root modules actually loaded
    // on this device, once. It only takes effect once the user opts in.
    LaunchedEffect(Unit) {
        if (!blockModulesPrefilled) {
            blockModulesPrefilled = true
            val detected = getLoadedBlockableModules()
            if (detected.isNotEmpty() && blockModules.isBlank()) {
                blockModules = detected.joinToString(",")
            }
        }
    }

    // Read the configuration from the boot image ksu_config
    val bootConfig by produceState(initialValue = BootConfig()) { value = getBootConfig() }
    var spoofEnabled by rememberSaveable { mutableStateOf(false) }
    var spoofRelease by rememberSaveable { mutableStateOf(SuSFSManager.getKernelSpoofRelease()) }
    var spoofVersion by rememberSaveable { mutableStateOf(SuSFSManager.getKernelSpoofVersion()) }

    val effectiveSpoofRelease = if (spoofEnabled) spoofRelease else ""
    val effectiveSpoofVersion = if (spoofEnabled) spoofVersion else ""

    LaunchedEffect(bootConfig) {
        // boot 镜像里已有伪装配置时，默认打开开关，避免静默覆盖
        if (bootConfig.spoofRelease.isNotEmpty() || bootConfig.spoofVersion.isNotEmpty()) {
            spoofEnabled = true
        }
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

    val downloadFileMsg = stringResource(id = R.string.download_dialog_msg)

    val horizonKernelSummary = stringResource(R.string.horizon_kernel_summary)
    val installMethodOptions = remember(rootAvailable, isAbDevice, isGkiDevice, selectFileTip, selectFileTipNoGki, downloadFileMsg, horizonKernelSummary) {
        buildList {
            add(InstallMethod.SelectFile(summary = if (isGkiDevice) selectFileTip else selectFileTipNoGki))
            add(InstallMethod.DownloadFile(summary = downloadFileMsg))
            if (rootAvailable && isGkiDevice) {
                add(InstallMethod.DirectInstall)
                if (isAbDevice) add(InstallMethod.DirectInstallToInactiveSlot)
                add(InstallMethod.HorizonKernel(summary = horizonKernelSummary))
            }
        }
    }

    // AnyKernel3 状�?
    val anyKernel3State = rememberAnyKernel3State(
        installMethodState = installMethodState,
        preselectedKernelUri = preselectedKernelUri?.toString(),
        horizonKernelSummary = horizonKernelSummary,
        isAbDevice = isAbDevice
    )

    val showSlotSelectionDialog = anyKernel3State.showSlotSelectionDialog && isAbDevice

    // 槽位选择对话�?
    if (showSlotSelectionDialog) {
        SlotSelectionDialog(
            show = true,
            onDismiss = { anyKernel3State.onDismissSlotDialog() },
            onSlotSelected = { slot ->
                anyKernel3State.onSlotSelected(slot)
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
    val remoteDisplayPartitions = remember(remotePartitions, defaultPartition) {
        remotePartitions.map { name -> if (defaultPartition == name) "$name (default)" else name }
    }

    fun showMessage(message: String) {
        scope.launch {
            if (uiMode == UiMode.Material) {
                snackbarHost.showSnackbar(message)
            } else {
                miuixSnackbarHost.showSnackbar(message)
            }
        }
    }

    val blockModulesInvalidMessage = stringResource(R.string.install_block_modules_invalid)
    val onInstall = {
        if (isStandaloneKpm) {
            navigator.push(Route.Flash(FlashIt.PatchKpmBoot(boot = kpmBootUri, undo = kpmUndo)))
        } else if (!isBlockModulesValid(effectiveBlockModules)) {
            showMessage(blockModulesInvalidMessage)
        } else installMethod?.let { method ->
            if (kpmEnabled && method is InstallMethod.DirectInstallToInactiveSlot) {
                showMessage(resources.getString(R.string.install_kpm_inactive_unsupported))
                return@let
            }
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
                            when (method) {
                                is InstallMethod.DownloadFile -> FlashIt.DownloadBoot(
                                    url = method.url ?: return@let,
                                    partition = method.partition ?: return@let,
                                    kpmEnabled = kpmEnabled,
                                    kpmUndo = kpmUndo,
                                    kpmBoot = kpmBootUri,
                                    lkm = lkmSelection,
                                    allowShell = allowShell,
                                    enableAdb = enableAdb,
                                    backup = forceBackup,
                                    blockModules = effectiveBlockModules,
                                    spoofRelease = effectiveSpoofRelease.trim(),
                                    spoofVersion = effectiveSpoofVersion.trim(),
                                )
                                else -> FlashIt.FlashBoot(
                                    boot = if (method is InstallMethod.SelectFile) method.uri else null,
                                    kpmEnabled = kpmEnabled,
                                    kpmUndo = kpmUndo,
                                    kpmBoot = kpmBootUri,
                                    lkm = lkmSelection,
                                    ota = isOta,
                                    partition = partitions.getOrNull(partitionSelectionIndex),
                                    allowShell = allowShell,
                                    enableAdb = enableAdb,
                                    backup = method is InstallMethod.SelectFile && forceBackup,
                                    blockModules = effectiveBlockModules,
                                    spoofRelease = effectiveSpoofRelease.trim(),
                                    spoofVersion = effectiveSpoofVersion.trim(),
                                )
                            }
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

    DownloadDialog(
        show = downloadDialogShown,
        onConfirm = { url ->
            downloadDialogShown = false
            probeJob?.cancel()
            probeJob = scope.launch {
                try {
                    loadingDialog.showLoading()
                    val result = probeRemoteBootPartitions(url)
                    if (result.partitions.isEmpty()) {
                        showMessage(resources.getString(R.string.download_no_boot_partition))
                    } else {
                        val defaultIdx = result.partitions.indexOf(defaultPartition).coerceAtLeast(0)
                        remotePartitions = result.partitions
                        remotePartitionSelectionIndex = defaultIdx
                        installMethod = InstallMethod.DownloadFile(
                            url = url,
                            partition = result.partitions[defaultIdx],
                            summary = downloadFileMsg,
                        )
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    showMessage(
                        resources.getString(R.string.download_probe_failed, e.message ?: "")
                    )
                } finally {
                    loadingDialog.hide()
                }
            }
        },
        onDismiss = { downloadDialogShown = false }
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
        val uri = it.data?.data
        if (it.resultCode != Activity.RESULT_OK || uri == null) {
            installMethod = null
            return@rememberLauncherForActivityResult
        }
        val option = when (installMethod) {
            is InstallMethod.SelectFile -> InstallMethod.SelectFile(uri, summary = selectFileTip)
            is InstallMethod.HorizonKernel -> InstallMethod.HorizonKernel(uri, summary = horizonKernelSummary)
            else -> null
        }
        option?.let { opt ->
            installMethod = opt
            // 对于 HorizonKernel，需要触�?AnyKernel3 流程（槽位选择和KPM修补�?
            if (opt is InstallMethod.HorizonKernel) {
                anyKernel3State.onHorizonKernelSelected(opt)
            }
        }
    }

    val selectKpmBootLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                kpmBootUri = uri
            }
        }
    }

    val state = InstallUiState(
        installMethod = installMethod,
        lkmSelection = lkmSelection,
        partitionSelectionIndex = partitionSelectionIndex,
        displayPartitions = displayPartitions,
        remoteDisplayPartitions = remoteDisplayPartitions,
        remotePartitionSelectionIndex = remotePartitionSelectionIndex,
        currentKmi = currentKmi,
        slotSuffix = slotSuffix,
        installMethodOptions = installMethodOptions,
        canSelectPartition = installMethod is InstallMethod.DirectInstall ||
            installMethod is InstallMethod.DirectInstallToInactiveSlot ||
            installMethod is InstallMethod.DownloadFile,
        advancedOptionsShown = advancedOptionsShown,
        allowShell = allowShell,
        enableAdb = enableAdb,
        forceBackup = forceBackup,
        canForceBackup = installMethod is InstallMethod.SelectFile,
        kpmPatchOption = kpmPatchOption,
        kpmBootExpanded = kpmBootExpanded,
        kpmBootUri = kpmBootUri,
        canPatchKpm = canPatchKpm,
        blockModulesEnabled = blockModulesEnabled,
        blockModules = blockModules,
        blockModulesValid = isBlockModulesValid(effectiveBlockModules),
        spoofEnabled = spoofEnabled,
        spoofRelease = spoofRelease,
        spoofVersion = spoofVersion,
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
        onDownloadFile = { downloadDialogShown = true },
        onSelectBootImage = { method ->
            // 在打开文件选择器之前，先设�?installMethod
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
            val method = installMethod
            if (method is InstallMethod.DownloadFile) {
                remotePartitionSelectionIndex = index
                installMethod = method.copy(partition = remotePartitions.getOrNull(index))
            } else {
                partitionSelectionIndex = index
            }
        },
        onNext = {
            val isLkmSelected = lkmSelection != LkmSelection.KmiNone
            val isKmiUnknown = currentKmi.isBlank()
            val isKmiUnresolved = when (installMethod) {
                // The download flow extracts the KMI itself; no manual
                // selection needed.
                is InstallMethod.DownloadFile -> false
                is InstallMethod.SelectFile -> true
                else -> isKmiUnknown
            }
            if (!isStandaloneKpm && isGkiDevice && !isLkmSelected && isKmiUnresolved && installMethod !is InstallMethod.HorizonKernel) {
                showChooseKmiDialog.value = true
            } else {
                onInstall()
            }
        },
        onAdvancedOptionsClicked = {
            advancedOptionsShown = !advancedOptionsShown
        },
        onPatchKpmFile = {
            selectKpmBootLauncher.launch(Intent(Intent.ACTION_GET_CONTENT).apply {
                type = "*/*"
                putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("application/octet-stream", "application/x-boot-img"))
            })
        },
        onKpmOptionChange = { kpmPatchOption = it },
        onToggleKpmBoot = { kpmBootExpanded = !kpmBootExpanded },
        onClearKpmBoot = { kpmBootUri = null },
        onSelectAllowShell = {
            allowShell = it
        },
        onSelectEnableAdb = {
            enableAdb = it
        },
        onSelectForceBackup = {
            forceBackup = it
        },
        onSpoofEnabledChange = {
            spoofEnabled = it
            if (!it) {
                // 关闭开关时清空已填写的�?
                spoofRelease = ""
                spoofVersion = ""
                scope.launch {
                    SuSFSManager.saveUnameValue("default")
                    SuSFSManager.saveBuildTimeValue("default")
                }
            }
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
        onSelectBlockModules = {
            blockModulesEnabled = it
        },
        onBlockModulesChange = {
            blockModules = it
        }
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> InstallScreenMiuix(state, actions, miuixSnackbarHost)
        UiMode.Material -> InstallScreenMaterial(state, actions, snackbarHost)
    }
}
