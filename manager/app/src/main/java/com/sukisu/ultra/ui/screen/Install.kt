package com.sukisu.ultra.ui.screen

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.captionBar
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.selection.toggleable
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.SdStorage
import androidx.compose.material.icons.filled.Security
import androidx.lifecycle.compose.dropUnlessResumed
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.HazeStyle
import dev.chrisbanes.haze.HazeTint
import dev.chrisbanes.haze.hazeEffect
import dev.chrisbanes.haze.hazeSource
import com.sukisu.ultra.R
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ui.component.ChooseKmiDialog
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.kernelFlash.KpmPatchOption
import com.sukisu.ultra.ui.kernelFlash.KpmPatchSelectionDialog
import com.sukisu.ultra.ui.kernelFlash.component.SlotSelectionDialog
import com.sukisu.ultra.ui.kernelFlash.rememberAnyKernel3State
import com.sukisu.ultra.ui.util.LkmSelection
import com.sukisu.ultra.ui.util.getAvailablePartitions
import com.sukisu.ultra.ui.util.getCurrentKmi
import com.sukisu.ultra.ui.util.getDefaultPartition
import com.sukisu.ultra.ui.util.getSlotSuffix
import com.sukisu.ultra.ui.util.isAbDevice
import com.sukisu.ultra.ui.util.rootAvailable
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.extra.SuperArrow
import top.yukonga.miuix.kmp.extra.SuperCheckbox
import top.yukonga.miuix.kmp.extra.SuperDropdown
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.ConvertFile
import top.yukonga.miuix.kmp.icon.extended.MoveFile
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * @author weishu
 * @date 2024/3/12.
 */
@SuppressLint("LocalContextGetResourceValueCall")
@Composable
fun InstallScreen(preselectedKernelUri: String? = null) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val enableBlur = LocalEnableBlur.current
    val installMethodState = remember {
        mutableStateOf<InstallMethod?>(null)
    }
    var installMethod by installMethodState

    var lkmSelection by remember {
        mutableStateOf<LkmSelection>(LkmSelection.KmiNone)
    }

    val kernelVersion = getKernelVersion()
    val isGKI = kernelVersion.isGKI()
    val isAbDevice = produceState(initialValue = false) {
        value = isAbDevice()
    }.value

    var partitionSelectionIndex by remember { mutableIntStateOf(0) }
    var partitionsState by remember { mutableStateOf<List<String>>(emptyList()) }
    var hasCustomSelected by remember { mutableStateOf(false) }
    val horizonKernelSummary = stringResource(R.string.horizon_kernel_summary)
    // AnyKernel3 刷写状态
    val anyKernel3State = rememberAnyKernel3State(
        installMethodState = installMethodState,
        preselectedKernelUri = preselectedKernelUri,
        horizonKernelSummary = horizonKernelSummary,
        isAbDevice = isAbDevice
    )
    val kpmPatchOption = anyKernel3State.kpmPatchOption

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
                    val partitionSelection = partitionsState.getOrNull(partitionSelectionIndex)
                    val flashIt = FlashIt.FlashBoot(
                        boot = if (method is InstallMethod.SelectFile) method.uri else null,
                        lkm = lkmSelection,
                        ota = isOta,
                        partition = partitionSelection
                    )
                    navigator.push(Route.Flash(flashIt))
                }
            }
        }
    }

    // 槽位选择对话框
    if (anyKernel3State.showSlotSelectionDialog && isAbDevice) {
        SlotSelectionDialog(
            show = true,
            onDismiss = { anyKernel3State.onDismissSlotDialog() },
            onSlotSelected = { slot ->
                anyKernel3State.onSlotSelected(slot)
            }
        )
    }

    // KPM补丁选择对话框
    if (anyKernel3State.showKpmPatchDialog) {
        KpmPatchSelectionDialog(
            show = true,
            currentOption = anyKernel3State.kpmPatchOption,
            onDismiss = { anyKernel3State.onDismissPatchDialog() },
            onOptionSelected = { option ->
                anyKernel3State.onOptionSelected(option)
            }
        )
    }

    val currentKmi by produceState(initialValue = "") { value = getCurrentKmi() }

    val showChooseKmiDialog = rememberSaveable { mutableStateOf(false) }
    val chooseKmiDialog = ChooseKmiDialog(showChooseKmiDialog) { kmi ->
        kmi?.let {
            lkmSelection = LkmSelection.KmiString(it)
            onInstall()
        }
    }

    val onClickNext = {
        val isLkmSelected = lkmSelection != LkmSelection.KmiNone
        val isKmiUnknown = currentKmi.isBlank()
        val isSelectFileMode = installMethod is InstallMethod.SelectFile
        if (isGKI && !isLkmSelected && (isKmiUnknown || isSelectFileMode) && installMethod !is InstallMethod.HorizonKernel) {
            // no lkm file selected and cannot get current kmi or select file mode
            showChooseKmiDialog.value = true
            chooseKmiDialog
        } else {
            onInstall()
        }
    }

    val selectLkmLauncher =
        rememberLauncherForActivityResult(contract = ActivityResultContracts.StartActivityForResult()) {
            if (it.resultCode == Activity.RESULT_OK) {
                it.data?.data?.let { uri ->
                    val isKo = isKoFile(context, uri)
                    if (isKo) {
                        lkmSelection = LkmSelection.LkmUri(uri)
                    } else {
                        lkmSelection = LkmSelection.KmiNone
                        Toast.makeText(
                            context,
                            context.getString(R.string.install_only_support_ko_file),
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        }

    val onLkmUpload = {
        selectLkmLauncher.launch(Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "application/octet-stream"
        })
    }

    val scrollBehavior = MiuixScrollBehavior()
    val hazeState = remember { HazeState() }
    val hazeStyle = if (enableBlur) {
        HazeStyle(
            backgroundColor = colorScheme.surface,
            tint = HazeTint(colorScheme.surface.copy(0.8f))
        )
    } else {
        HazeStyle.Unspecified
    }

    Scaffold(
        topBar = {
            TopBar(
                onBack = dropUnlessResumed { navigator.pop() },
                scrollBehavior = scrollBehavior,
                hazeState = hazeState,
                hazeStyle = hazeStyle,
                enableBlur = enableBlur,
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .let { if (enableBlur) it.hazeSource(state = hazeState) else it }
                .padding(top = 12.dp)
                .padding(horizontal = 16.dp),
            contentPadding = innerPadding,
            overscrollEffect = null,
        ) {
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth(),
                ) {
                    SelectInstallMethod(
                        onSelected = { method ->
                            if (method is InstallMethod.HorizonKernel && method.uri != null) {
                                anyKernel3State.onHorizonKernelSelected(method)
                            } else {
                                installMethod = method
                            }
                        },
                        isAbDevice = isAbDevice
                    )
                }
                AnimatedVisibility(
                    visible = installMethod is InstallMethod.DirectInstall || installMethod is InstallMethod.DirectInstallToInactiveSlot,
                    enter = expandVertically(),
                    exit = shrinkVertically()
                ) {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                    ) {
                        val isOta = installMethod is InstallMethod.DirectInstallToInactiveSlot
                        val suffix = produceState(initialValue = "", isOta) {
                            value = getSlotSuffix(isOta)
                        }.value
                        val partitions = produceState(initialValue = emptyList()) {
                            value = getAvailablePartitions()
                        }.value
                        val defaultPartition = produceState(initialValue = "") {
                            value = getDefaultPartition()
                        }.value
                        partitionsState = partitions
                        val displayPartitions = partitions.map { name ->
                            if (defaultPartition == name) "$name (default)" else name
                        }
                        val defaultIndex = partitions.indexOf(defaultPartition).takeIf { it >= 0 } ?: 0
                        if (!hasCustomSelected) partitionSelectionIndex = defaultIndex
                        SuperDropdown(
                            items = displayPartitions,
                            selectedIndex = partitionSelectionIndex,
                            title = "${stringResource(R.string.install_select_partition)} (${suffix})",
                            onSelectedIndexChange = { index ->
                                hasCustomSelected = true
                                partitionSelectionIndex = index
                            },
                            startAction = {
                                Icon(
                                    MiuixIcons.ConvertFile,
                                    tint = colorScheme.onSurface,
                                    modifier = Modifier.padding(end = 16.dp),
                                    contentDescription = null
                                )
                            }
                        )
                    }
                }
                // LKM 上传（仅 GKI）
                if (isGKI) {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                    ) {
                        SuperArrow(
                            title = stringResource(id = R.string.install_upload_lkm_file),
                            summary = (lkmSelection as? LkmSelection.LkmUri)?.let {
                                stringResource(
                                    id = R.string.selected_lkm,
                                    it.uri.lastPathSegment ?: "(file)"
                                )
                            },
                            onClick = onLkmUpload,
                            startAction = {
                                Icon(
                                    MiuixIcons.MoveFile,
                                    tint = colorScheme.onSurface,
                                    modifier = Modifier.padding(end = 16.dp),
                                    contentDescription = null
                                )
                            }
                        )
                    }
                }
                
                // AnyKernel3 刷写
                (installMethod as? InstallMethod.HorizonKernel)?.let { method ->
                    if (isAbDevice && method.slot != null) {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                        ) {
                            SuperArrow(
                                title = stringResource(
                                    id = R.string.selected_slot,
                                    if (method.slot == "a") stringResource(id = R.string.slot_a)
                                    else stringResource(id = R.string.slot_b)
                                ),
                                onClick = {
                                    anyKernel3State.onReopenSlotDialog(method)
                                },
                                startAction = {
                                    Icon(
                                        Icons.Filled.SdStorage,
                                        tint = colorScheme.primary,
                                        modifier = Modifier.padding(end = 16.dp),
                                        contentDescription = null
                                    )
                                }
                            )
                        }
                    }
                    
                    // KPM 状态显示
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                    ) {
                        SuperArrow(
                            title = when (kpmPatchOption) {
                                KpmPatchOption.PATCH_KPM -> stringResource(R.string.kpm_patch_enabled)
                                KpmPatchOption.UNDO_PATCH_KPM -> stringResource(R.string.kpm_undo_patch_enabled)
                                KpmPatchOption.FOLLOW_KERNEL -> stringResource(R.string.kpm_follow_kernel_file)
                            },
                            onClick = {
                                anyKernel3State.onReopenKpmDialog(method)
                            },
                            startAction = {
                                Icon(
                                    Icons.Filled.Security,
                                    tint = when (kpmPatchOption) {
                                        KpmPatchOption.PATCH_KPM -> colorScheme.primary
                                        KpmPatchOption.UNDO_PATCH_KPM -> colorScheme.secondary
                                        KpmPatchOption.FOLLOW_KERNEL -> colorScheme.onSurfaceVariantSummary
                                    },
                                    modifier = Modifier.padding(end = 16.dp),
                                    contentDescription = null
                                )
                            }
                        )
                    }
                }
                TextButton(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                    text = stringResource(id = R.string.install_next),
                    enabled = installMethod != null,
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                    onClick = { onClickNext() }
                )
                Spacer(
                    Modifier.height(
                        WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() +
                                WindowInsets.captionBar.asPaddingValues().calculateBottomPadding()
                    )
                )
            }
        }
    }
}

sealed class InstallMethod {
    data class SelectFile(
        val uri: Uri? = null,
        @get:StringRes override val label: Int = R.string.select_file,
        override val summary: String?
    ) : InstallMethod()

    data object DirectInstall : InstallMethod() {
        override val label: Int
            get() = R.string.direct_install
    }

    data object DirectInstallToInactiveSlot : InstallMethod() {
        override val label: Int
            get() = R.string.install_inactive_slot
    }

    data class HorizonKernel(
        val uri: Uri? = null,
        val slot: String? = null,
        @get:StringRes override val label: Int = R.string.horizon_kernel,
        override val summary: String? = null
    ) : InstallMethod()

    abstract val label: Int
    open val summary: String? = null
}

@Composable
private fun SelectInstallMethod(
    onSelected: (InstallMethod) -> Unit = {},
    isAbDevice: Boolean = false
) {
    val rootAvailable = rootAvailable()
    val defaultPartitionName = produceState(initialValue = "boot") {
        value = getDefaultPartition()
    }.value
    val isGkiDevice = produceState(initialValue = false) {
        value = getKernelVersion().isGKI()
    }.value
    val horizonKernelSummary = stringResource(R.string.horizon_kernel_summary)
    val selectFileTip = stringResource(
        id = R.string.select_file_tip, defaultPartitionName
    )
    val selectFileTipNoGKI = stringResource(id = R.string.select_file_tip_nogki)
    val radioOptions = mutableListOf<InstallMethod>(InstallMethod.SelectFile(summary = if (isGkiDevice) selectFileTip else selectFileTipNoGKI))
    if (rootAvailable && isGkiDevice) {
        radioOptions.add(InstallMethod.DirectInstall)

        if (isAbDevice) {
            radioOptions.add(InstallMethod.DirectInstallToInactiveSlot)
        }
        radioOptions.add(InstallMethod.HorizonKernel(summary = horizonKernelSummary))
    }

    var selectedOption by remember { mutableStateOf<InstallMethod?>(null) }
    var currentSelectingMethod by remember { mutableStateOf<InstallMethod?>(null) }

    val selectImageLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == Activity.RESULT_OK) {
            it.data?.data?.let { uri ->
                val option = when (currentSelectingMethod) {
                    is InstallMethod.SelectFile -> InstallMethod.SelectFile(uri, summary = selectFileTip)
                    is InstallMethod.HorizonKernel -> InstallMethod.HorizonKernel(uri, summary = horizonKernelSummary)
                    else -> null
                }
                option?.let { opt ->
                    selectedOption = opt
                    onSelected(opt)
                }
            }
        }
    }

    val confirmDialog = rememberConfirmDialog(
        onConfirm = {
            selectedOption = InstallMethod.DirectInstallToInactiveSlot
            onSelected(InstallMethod.DirectInstallToInactiveSlot)
        }
    )
    val dialogTitle = stringResource(id = android.R.string.dialog_alert_title)
    val dialogContent = stringResource(id = R.string.install_inactive_slot_warning)

    val onClick = { option: InstallMethod ->
        currentSelectingMethod = option
        when (option) {
            is InstallMethod.SelectFile, is InstallMethod.HorizonKernel -> {
                selectImageLauncher.launch(Intent(Intent.ACTION_GET_CONTENT).apply {
                    type = "application/*"
                    putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("application/octet-stream", "application/zip"))
                })
            }

            is InstallMethod.DirectInstall -> {
                selectedOption = option
                onSelected(option)
            }

            is InstallMethod.DirectInstallToInactiveSlot -> {
                confirmDialog.showConfirm(dialogTitle, dialogContent)
            }
        }
    }

    Column {
        radioOptions.forEach { option ->
            val interactionSource = remember { MutableInteractionSource() }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .toggleable(
                        value = option.javaClass == selectedOption?.javaClass,
                        onValueChange = {
                            onClick(option)
                        },
                        role = Role.RadioButton,
                        indication = LocalIndication.current,
                        interactionSource = interactionSource
                    )
            ) {
                SuperCheckbox(
                    title = stringResource(id = option.label),
                    summary = option.summary,
                    checked = option.javaClass == selectedOption?.javaClass,
                    onCheckedChange = {
                        onClick(option)
                    },
                )
            }
        }
    }
}

@Composable
private fun TopBar(
    onBack: () -> Unit = {},
    scrollBehavior: ScrollBehavior,
    hazeState: HazeState,
    hazeStyle: HazeStyle,
    enableBlur: Boolean
) {
    TopAppBar(
        modifier = if (enableBlur) {
            Modifier.hazeEffect(hazeState) {
                style = hazeStyle
                blurRadius = 30.dp
                noiseFactor = 0f
            }
        } else {
            Modifier
        },
        color = if (enableBlur) Color.Transparent else colorScheme.surface,
        title = stringResource(R.string.install),
        navigationIcon = {
            IconButton(
                modifier = Modifier.padding(start = 16.dp),
                onClick = onBack
            ) {
                val layoutDirection = LocalLayoutDirection.current
                Icon(
                    modifier = Modifier.graphicsLayer {
                        if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                    },
                    imageVector = MiuixIcons.Back,
                    tint = colorScheme.onSurface,
                    contentDescription = null,
                )
            }
        },
        scrollBehavior = scrollBehavior
    )
}

private fun isKoFile(context: Context, uri: Uri): Boolean {
    val seg = uri.lastPathSegment ?: ""
    if (seg.endsWith(".ko", ignoreCase = true)) return true

    return try {
        context.contentResolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null
        )?.use { cursor ->
            val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx != -1 && cursor.moveToFirst()) {
                val name = cursor.getString(idx)
                name?.endsWith(".ko", ignoreCase = true) == true
            } else {
                false
            }
        } ?: false
    } catch (_: Throwable) {
        false
    }
}