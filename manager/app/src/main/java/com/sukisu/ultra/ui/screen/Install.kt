package com.sukisu.ultra.ui.screen

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.compose.animation.*
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Input
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import com.maxkeppeker.sheets.core.models.base.Header
import com.maxkeppeker.sheets.core.models.base.rememberUseCaseState
import com.maxkeppeler.sheets.list.ListDialog
import com.maxkeppeler.sheets.list.models.ListOption
import com.maxkeppeler.sheets.list.models.ListSelection
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.FlashScreenDestination
import com.ramcosta.composedestinations.generated.destinations.KernelFlashScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.navigation.EmptyDestinationsNavigator
import com.sukisu.ultra.R
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ui.component.DialogHandle
import zako.zako.zako.zakoui.screen.kernelFlash.component.SlotSelectionDialog
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.component.rememberCustomDialog
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.CardConfig.cardAlpha
import com.sukisu.ultra.ui.theme.CardConfig.cardElevation
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.theme.getCardElevation
import com.sukisu.ultra.ui.util.*

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */

enum class KpmPatchOption {
    FOLLOW_KERNEL,
    PATCH_KPM,
    UNDO_PATCH_KPM
}

@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun InstallScreen(
    navigator: DestinationsNavigator,
    preselectedKernelUri: String? = null
) {
    val context = LocalContext.current
    var installMethod by remember { mutableStateOf<InstallMethod?>(null) }
    var lkmSelection by remember { mutableStateOf<LkmSelection>(LkmSelection.KmiNone) }
    var kpmPatchOption by remember { mutableStateOf(KpmPatchOption.FOLLOW_KERNEL) }
    var showRebootDialog by remember { mutableStateOf(false) }
    var showSlotSelectionDialog by remember { mutableStateOf(false) }
    var showKpmPatchDialog by remember { mutableStateOf(false) }
    var tempKernelUri by remember { mutableStateOf<Uri?>(null) }
    val kernelVersion = getKernelVersion()
    val isGKI = kernelVersion.isGKI()
    val isAbDevice = isAbDevice()
    val summary = stringResource(R.string.horizon_kernel_summary)

    // 处理预选的内核文件
    LaunchedEffect(preselectedKernelUri) {
        preselectedKernelUri?.let { uriString ->
            try {
                val preselectedUri = uriString.toUri()
                val horizonMethod = InstallMethod.HorizonKernel(
                    uri = preselectedUri,
                    summary = summary
                )
                installMethod = horizonMethod
                tempKernelUri = preselectedUri
                if (isAbDevice) {
                    showSlotSelectionDialog = true
                } else {
                    showKpmPatchDialog = true
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    if (showRebootDialog) {
        RebootDialog(
            show = true,
            onDismiss = { showRebootDialog = false },
            onConfirm = {
                showRebootDialog = false
                try {
                    val process = Runtime.getRuntime().exec("su")
                    process.outputStream.bufferedWriter().use { writer ->
                        writer.write("svc power reboot\n")
                        writer.write("exit\n")
                    }
                } catch (_: Exception) {
                    Toast.makeText(context, R.string.failed_reboot, Toast.LENGTH_SHORT).show()
                }
            }
        )
    }

    val onInstall = {
        installMethod?.let { method ->
            when (method) {
                is InstallMethod.HorizonKernel -> {
                    method.uri?.let { uri ->
                        navigator.navigate(
                            KernelFlashScreenDestination(
                                kernelUri = uri,
                                selectedSlot = method.slot,
                                kpmPatchEnabled = kpmPatchOption == KpmPatchOption.PATCH_KPM,
                                kpmUndoPatch = kpmPatchOption == KpmPatchOption.UNDO_PATCH_KPM
                            )
                        )
                    }
                }
                else -> {
                    val flashIt = FlashIt.FlashBoot(
                        boot = if (method is InstallMethod.SelectFile) method.uri else null,
                        lkm = lkmSelection,
                        ota = method is InstallMethod.DirectInstallToInactiveSlot
                    )
                    navigator.navigate(FlashScreenDestination(flashIt))
                }
            }
        }
        Unit
    }

    // 槽位选择
    SlotSelectionDialog(
        show = showSlotSelectionDialog && isAbDevice,
        onDismiss = { showSlotSelectionDialog = false },
        onSlotSelected = { slot ->
            showSlotSelectionDialog = false
            val horizonMethod = InstallMethod.HorizonKernel(
                uri = tempKernelUri,
                slot = slot,
                summary = summary
            )
            installMethod = horizonMethod
            if (preselectedKernelUri != null) {
                showKpmPatchDialog = true
            }
        }
    )

    KpmPatchSelectionDialog(
        show = showKpmPatchDialog,
        currentOption = kpmPatchOption,
        onDismiss = { showKpmPatchDialog = false },
        onOptionSelected = { option ->
            kpmPatchOption = option
            showKpmPatchDialog = false
        }
    )

    val currentKmi by produceState(initialValue = "") {
        value = getCurrentKmi()
    }

    val selectKmiDialog = rememberSelectKmiDialog { kmi ->
        kmi?.let {
            lkmSelection = LkmSelection.KmiString(it)
            onInstall()
        }
    }

    val onClickNext = {
        if (isGKI && lkmSelection == LkmSelection.KmiNone && currentKmi.isBlank() && installMethod !is InstallMethod.HorizonKernel) {
            selectKmiDialog.show()
        } else {
            onInstall()
        }
    }

    val selectLkmLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == Activity.RESULT_OK) {
            it.data?.data?.let { uri ->
                lkmSelection = LkmSelection.LkmUri(uri)
            }
        }
    }

    val onLkmUpload = {
        selectLkmLauncher.launch(Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "application/octet-stream"
        })
    }

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    Scaffold(
        topBar = {
            TopBar(
                onBack = { navigator.popBackStack() },
                onLkmUpload = onLkmUpload,
                scrollBehavior = scrollBehavior
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        )
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
                .padding(top = 12.dp)
        ) {
            SelectInstallMethod(
                isGKI = isGKI,
                onSelected = { method ->
                    if (method is InstallMethod.HorizonKernel && method.uri != null) {
                        if (isAbDevice) {
                            tempKernelUri = method.uri
                            showSlotSelectionDialog = true
                        } else {
                            installMethod = method
                            showKpmPatchDialog = true
                        }
                    } else {
                        installMethod = method
                    }
                },
                kpmPatchOption = kpmPatchOption,
                onKpmPatchOptionChanged = { kpmPatchOption = it },
                selectedMethod = installMethod
            )

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                (lkmSelection as? LkmSelection.LkmUri)?.let {
                    ElevatedCard(
                        colors = getCardColors(MaterialTheme.colorScheme.surfaceVariant),
                        elevation = getCardElevation(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 12.dp)
                            .clip(MaterialTheme.shapes.medium)
                            .shadow(
                                elevation = cardElevation,
                                shape = MaterialTheme.shapes.medium,
                                spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                            )
                    ) {
                        Text(
                            text = stringResource(
                                id = R.string.selected_lkm,
                                it.uri.lastPathSegment ?: "(file)"
                            ),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                }

                (installMethod as? InstallMethod.HorizonKernel)?.let { method ->
                    if (method.slot != null) {
                        ElevatedCard(
                            colors = getCardColors(MaterialTheme.colorScheme.surfaceVariant),
                            elevation = getCardElevation(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 12.dp)
                                .clip(MaterialTheme.shapes.medium)
                                .shadow(
                                    elevation = cardElevation,
                                    shape = MaterialTheme.shapes.medium,
                                    spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                                )
                        ) {
                            Text(
                                text = stringResource(
                                    id = R.string.selected_slot,
                                    if (method.slot == "a") stringResource(id = R.string.slot_a)
                                    else stringResource(id = R.string.slot_b)
                                ),
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.padding(16.dp)
                            )
                        }
                    }

                    // KPM 状态显示卡片
                    if (kpmPatchOption != KpmPatchOption.FOLLOW_KERNEL) {
                        ElevatedCard(
                            colors = getCardColors(MaterialTheme.colorScheme.surfaceVariant),
                            elevation = getCardElevation(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 12.dp)
                                .clip(MaterialTheme.shapes.medium)
                                .shadow(
                                    elevation = cardElevation,
                                    shape = MaterialTheme.shapes.medium,
                                    spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                                )
                        ) {
                            Text(
                                text = when (kpmPatchOption) {
                                    KpmPatchOption.PATCH_KPM -> stringResource(R.string.kpm_patch_enabled)
                                    KpmPatchOption.UNDO_PATCH_KPM -> stringResource(R.string.kpm_undo_patch_enabled)
                                    else -> ""
                                },
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.padding(16.dp),
                                color = when (kpmPatchOption) {
                                    KpmPatchOption.PATCH_KPM -> MaterialTheme.colorScheme.primary
                                    KpmPatchOption.UNDO_PATCH_KPM -> MaterialTheme.colorScheme.tertiary
                                    else -> MaterialTheme.colorScheme.onSurface
                                }
                            )
                        }
                    }
                }

                Button(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = installMethod != null,
                    onClick = onClickNext,
                    shape = MaterialTheme.shapes.medium,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                        disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                    )
                ) {
                    Text(
                        stringResource(id = R.string.install_next),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }
    }
}

@Composable
private fun KpmPatchSelectionDialog(
    show: Boolean,
    currentOption: KpmPatchOption,
    onDismiss: () -> Unit,
    onOptionSelected: (KpmPatchOption) -> Unit
) {
    if (show) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.kpm_patch_options)) },
            text = {
                Column {
                    Text(
                        text = stringResource(R.string.kpm_patch_description),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(bottom = 16.dp)
                    )

                    KpmPatchOptionGroup(
                        selectedOption = currentOption,
                        onOptionChanged = onOptionSelected
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { onOptionSelected(currentOption) }
                ) {
                    Text(stringResource(android.R.string.ok))
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(android.R.string.cancel))
                }
            }
        )
    }
}

@Composable
private fun RebootDialog(
    show: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    if (show) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(id = R.string.reboot_complete_title)) },
            text = { Text(stringResource(id = R.string.reboot_complete_msg)) },
            confirmButton = {
                TextButton(onClick = onConfirm) {
                    Text(stringResource(id = R.string.yes))
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(id = R.string.no))
                }
            }
        )
    }
}

sealed class InstallMethod {
    data class SelectFile(
        val uri: Uri? = null,
        @param:StringRes override val label: Int = R.string.select_file,
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
        @param:StringRes override val label: Int = R.string.horizon_kernel,
        override val summary: String? = null
    ) : InstallMethod()

    abstract val label: Int
    open val summary: String? = null
}

@Composable
private fun SelectInstallMethod(
    isGKI: Boolean = false,
    onSelected: (InstallMethod) -> Unit = {},
    kpmPatchOption: KpmPatchOption = KpmPatchOption.FOLLOW_KERNEL,
    onKpmPatchOptionChanged: (KpmPatchOption) -> Unit = {},
    selectedMethod: InstallMethod? = null
) {
    val rootAvailable = rootAvailable()
    val isAbDevice = isAbDevice()
    val horizonKernelSummary = stringResource(R.string.horizon_kernel_summary)
    val selectFileTip = stringResource(
        id = R.string.select_file_tip,
        if (isInitBoot()) {
            "init_boot / vendor_boot ${stringResource(R.string.select_file_tip_vendor)}"
        } else {
            "boot"
        }
    )

    val radioOptions = mutableListOf<InstallMethod>(
        InstallMethod.SelectFile(summary = selectFileTip)
    )

    if (rootAvailable) {
        radioOptions.add(InstallMethod.DirectInstall)
        if (isAbDevice) {
            radioOptions.add(InstallMethod.DirectInstallToInactiveSlot)
        }
        radioOptions.add(InstallMethod.HorizonKernel(summary = horizonKernelSummary))
    }

    var selectedOption by remember { mutableStateOf<InstallMethod?>(null) }
    var currentSelectingMethod by remember { mutableStateOf<InstallMethod?>(null) }

    LaunchedEffect(selectedMethod) {
        selectedOption = selectedMethod
    }

    val selectImageLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == Activity.RESULT_OK) {
            it.data?.data?.let { uri ->
                val option = when (currentSelectingMethod) {
                    is InstallMethod.SelectFile -> InstallMethod.SelectFile(
                        uri,
                        summary = selectFileTip
                    )

                    is InstallMethod.HorizonKernel -> InstallMethod.HorizonKernel(
                        uri,
                        summary = horizonKernelSummary
                    )

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
        },
        onDismiss = null
    )

    val dialogTitle = stringResource(id = android.R.string.dialog_alert_title)
    val dialogContent = stringResource(id = R.string.install_inactive_slot_warning)

    val onClick = { option: InstallMethod ->
        currentSelectingMethod = option
        when (option) {
            is InstallMethod.SelectFile, is InstallMethod.HorizonKernel -> {
                selectImageLauncher.launch(Intent(Intent.ACTION_GET_CONTENT).apply {
                    type = "application/*"
                    putExtra(
                        Intent.EXTRA_MIME_TYPES,
                        arrayOf("application/octet-stream", "application/zip")
                    )
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

    var lkmExpanded by remember { mutableStateOf(false) }
    var gkiExpanded by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.padding(horizontal = 16.dp)
    ) {
        // LKM 安装/修补
        if (isGKI) {
            ElevatedCard(
                colors = getCardColors(MaterialTheme.colorScheme.surfaceVariant),
                elevation = getCardElevation(),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp)
                    .clip(MaterialTheme.shapes.large)
            ) {
                MaterialTheme(
                    colorScheme = MaterialTheme.colorScheme.copy(
                        surface = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    ListItem(
                        leadingContent = {
                            Icon(
                                Icons.Filled.AutoFixHigh,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary
                            )
                        },
                        headlineContent = {
                            Text(
                                stringResource(R.string.Lkm_install_methods),
                                style = MaterialTheme.typography.titleMedium
                            )
                        },
                        modifier = Modifier.clickable {
                            lkmExpanded = !lkmExpanded
                        }
                    )
                }

                AnimatedVisibility(
                    visible = lkmExpanded,
                    enter = fadeIn() + expandVertically(),
                    exit = shrinkVertically() + fadeOut()
                ) {
                    Column(
                        modifier = Modifier.padding(
                            start = 16.dp,
                            end = 16.dp,
                            bottom = 16.dp
                        )
                    ) {
                        radioOptions.take(3).forEach { option ->
                            val interactionSource = remember { MutableInteractionSource() }
                            Surface(
                                color = if (option.javaClass == selectedOption?.javaClass)
                                    MaterialTheme.colorScheme.secondaryContainer.copy(alpha = cardAlpha)
                                else
                                    MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = cardAlpha),
                                shape = MaterialTheme.shapes.medium,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                                    .clip(MaterialTheme.shapes.medium)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .selectable(
                                            selected = option.javaClass == selectedOption?.javaClass,
                                            onClick = { onClick(option) },
                                            role = Role.RadioButton,
                                            indication = LocalIndication.current,
                                            interactionSource = interactionSource
                                        )
                                        .padding(vertical = 8.dp, horizontal = 12.dp)
                                ) {
                                    RadioButton(
                                        selected = option.javaClass == selectedOption?.javaClass,
                                        onClick = null,
                                        interactionSource = interactionSource,
                                        colors = RadioButtonDefaults.colors(
                                            selectedColor = MaterialTheme.colorScheme.primary,
                                            unselectedColor = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    )
                                    Column(
                                        modifier = Modifier
                                            .padding(start = 10.dp)
                                            .weight(1f)
                                    ) {
                                        Text(
                                            text = stringResource(id = option.label),
                                            style = MaterialTheme.typography.bodyLarge
                                        )
                                        option.summary?.let {
                                            Text(
                                                text = it,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // anykernel3 刷写
        if (rootAvailable) {
            ElevatedCard(
                colors = getCardColors(MaterialTheme.colorScheme.surfaceVariant),
                elevation = getCardElevation(),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                    .clip(MaterialTheme.shapes.large)
            ) {
                MaterialTheme(
                    colorScheme = MaterialTheme.colorScheme.copy(
                        surface = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    ListItem(
                        leadingContent = {
                            Icon(
                                Icons.Filled.FileUpload,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary
                            )
                        },
                        headlineContent = {
                            Text(
                                stringResource(R.string.GKI_install_methods),
                                style = MaterialTheme.typography.titleMedium
                            )
                        },
                        modifier = Modifier.clickable {
                            gkiExpanded = !gkiExpanded
                        }
                    )
                }

                AnimatedVisibility(
                    visible = gkiExpanded,
                    enter = fadeIn() + expandVertically(),
                    exit = shrinkVertically() + fadeOut()
                ) {
                    Column(
                        modifier = Modifier.padding(
                            start = 16.dp,
                            end = 16.dp,
                            bottom = 16.dp
                        )
                    ) {
                        radioOptions.filterIsInstance<InstallMethod.HorizonKernel>().forEach { option ->
                            val interactionSource = remember { MutableInteractionSource() }
                            Surface(
                                color = if (option.javaClass == selectedOption?.javaClass)
                                    MaterialTheme.colorScheme.secondaryContainer.copy(alpha = cardAlpha)
                                else
                                    MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = cardAlpha),
                                shape = MaterialTheme.shapes.medium,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                                    .clip(MaterialTheme.shapes.medium)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .selectable(
                                            selected = option.javaClass == selectedOption?.javaClass,
                                            onClick = { onClick(option) },
                                            role = Role.RadioButton,
                                            indication = LocalIndication.current,
                                            interactionSource = interactionSource
                                        )
                                        .padding(vertical = 8.dp, horizontal = 12.dp)
                                ) {
                                    RadioButton(
                                        selected = option.javaClass == selectedOption?.javaClass,
                                        onClick = null,
                                        interactionSource = interactionSource,
                                        colors = RadioButtonDefaults.colors(
                                            selectedColor = MaterialTheme.colorScheme.primary,
                                            unselectedColor = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    )
                                    Column(
                                        modifier = Modifier
                                            .padding(start = 10.dp)
                                            .weight(1f)
                                    ) {
                                        Text(
                                            text = stringResource(id = option.label),
                                            style = MaterialTheme.typography.bodyLarge
                                        )
                                        option.summary?.let {
                                            Text(
                                                text = it,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        // KPM修补
                        if (selectedMethod is InstallMethod.HorizonKernel && selectedMethod.uri != null) {
                            Spacer(modifier = Modifier.height(16.dp))
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 8.dp)
                            ) {
                                Icon(
                                    Icons.Filled.Security,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.tertiary,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    stringResource(R.string.kpm_patch_options),
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.tertiary
                                )
                            }

                            Text(
                                stringResource(R.string.kpm_patch_description),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(bottom = 12.dp)
                            )

                            KpmPatchOptionGroup(
                                selectedOption = kpmPatchOption,
                                onOptionChanged = onKpmPatchOptionChanged
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun KpmPatchOptionGroup(
    selectedOption: KpmPatchOption,
    onOptionChanged: (KpmPatchOption) -> Unit
) {
    val options = listOf(
        KpmPatchOption.FOLLOW_KERNEL to stringResource(R.string.kpm_follow_kernel_file),
        KpmPatchOption.PATCH_KPM to stringResource(R.string.enable_kpm_patch),
        KpmPatchOption.UNDO_PATCH_KPM to stringResource(R.string.enable_kpm_undo_patch)
    )

    val descriptions = mapOf(
        KpmPatchOption.FOLLOW_KERNEL to stringResource(R.string.kpm_follow_kernel_description),
        KpmPatchOption.PATCH_KPM to stringResource(R.string.kpm_patch_switch_description),
        KpmPatchOption.UNDO_PATCH_KPM to stringResource(R.string.kpm_undo_patch_switch_description)
    )

    Column {
        options.forEach { (option, label) ->
            val interactionSource = remember { MutableInteractionSource() }
            Surface(
                color = if (option == selectedOption)
                    MaterialTheme.colorScheme.primaryContainer.copy(alpha = cardAlpha)
                else
                    MaterialTheme.colorScheme.surfaceContainer.copy(alpha = cardAlpha),
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 2.dp)
                    .clip(MaterialTheme.shapes.medium)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = option == selectedOption,
                            onClick = { onOptionChanged(option) },
                            role = Role.RadioButton,
                            indication = LocalIndication.current,
                            interactionSource = interactionSource
                        )
                        .padding(vertical = 12.dp, horizontal = 12.dp)
                ) {
                    RadioButton(
                        selected = option == selectedOption,
                        onClick = null,
                        interactionSource = interactionSource,
                        colors = RadioButtonDefaults.colors(
                            selectedColor = when (option) {
                                KpmPatchOption.FOLLOW_KERNEL -> MaterialTheme.colorScheme.primary
                                KpmPatchOption.PATCH_KPM -> MaterialTheme.colorScheme.primary
                                KpmPatchOption.UNDO_PATCH_KPM -> MaterialTheme.colorScheme.tertiary
                            },
                            unselectedColor = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.bodyLarge,
                            color = if (option == selectedOption)
                                MaterialTheme.colorScheme.onPrimaryContainer
                            else
                                MaterialTheme.colorScheme.onSurface
                        )
                        descriptions[option]?.let { description ->
                            Text(
                                text = description,
                                style = MaterialTheme.typography.bodySmall,
                                color = if (option == selectedOption)
                                    MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                                else
                                    MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun rememberSelectKmiDialog(onSelected: (String?) -> Unit): DialogHandle {
    return rememberCustomDialog { dismiss ->
        val supportedKmi by produceState(initialValue = emptyList()) {
            value = getSupportedKmis()
        }
        val options = supportedKmi.map { value ->
            ListOption(
                titleText = value
            )
        }

        var selection by remember { mutableStateOf<String?>(null) }

        MaterialTheme(
            colorScheme = MaterialTheme.colorScheme.copy(
                surface = MaterialTheme.colorScheme.surfaceContainerHigh
            )
        ) {
            ListDialog(state = rememberUseCaseState(visible = true, onFinishedRequest = {
                onSelected(selection)
            }, onCloseRequest = {
                dismiss()
            }), header = Header.Default(
                title = stringResource(R.string.select_kmi),
            ), selection = ListSelection.Single(
                showRadioButtons = true,
                options = options,
            ) { _, option ->
                selection = option.titleText
            })
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar(
    onBack: () -> Unit = {},
    onLkmUpload: () -> Unit = {},
    scrollBehavior: TopAppBarScrollBehavior? = null
) {
    val colorScheme = MaterialTheme.colorScheme
    val cardColor = if (CardConfig.isCustomBackgroundEnabled) {
        colorScheme.surfaceContainerLow
    } else {
        colorScheme.background
    }
    val cardAlpha = cardAlpha

    TopAppBar(
        title = {
            Text(
                stringResource(R.string.install),
                style = MaterialTheme.typography.titleLarge
            )
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = cardColor.copy(alpha = cardAlpha),
            scrolledContainerColor = cardColor.copy(alpha = cardAlpha)
        ),
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.back)
                )
            }
        },
        windowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        ),
        actions = {
            IconButton(
                modifier = Modifier.padding(end = 16.dp),
                onClick = onLkmUpload
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Input,
                    contentDescription = null
                )
            }
        },
        scrollBehavior = scrollBehavior
    )
}

@Preview
@Composable
fun SelectInstallPreview() {
    InstallScreen(EmptyDestinationsNavigator)
}