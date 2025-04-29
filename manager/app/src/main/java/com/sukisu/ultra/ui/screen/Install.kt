package com.sukisu.ultra.ui.screen

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.maxkeppeler.sheets.list.models.ListOption
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.FlashScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.navigation.EmptyDestinationsNavigator
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.DialogHandle
import com.sukisu.ultra.ui.component.SlotSelectionDialog
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.component.rememberCustomDialog
import com.sukisu.ultra.flash.HorizonKernelFlashProgress
import com.sukisu.ultra.flash.HorizonKernelState
import com.sukisu.ultra.flash.HorizonKernelWorker
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.ThemeConfig
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.util.*

/**
 * @author weishu
 * @date 2024/3/12.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun InstallScreen(navigator: DestinationsNavigator) {
    var installMethod by remember { mutableStateOf<InstallMethod?>(null) }
    var lkmSelection by remember { mutableStateOf<LkmSelection>(LkmSelection.KmiNone) }
    val context = LocalContext.current
    var showRebootDialog by remember { mutableStateOf(false) }
    var showSlotSelectionDialog by remember { mutableStateOf(false) }
    var tempKernelUri by remember { mutableStateOf<Uri?>(null) }
    val horizonKernelState = remember { HorizonKernelState() }
    val flashState by horizonKernelState.state.collectAsState()
    val summary = stringResource(R.string.horizon_kernel_summary)

    val onFlashComplete = {
        showRebootDialog = true
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
                        val worker = HorizonKernelWorker(
                            context = context,
                            state = horizonKernelState,
                            slot = method.slot
                        )
                        worker.uri = uri
                        worker.setOnFlashCompleteListener(onFlashComplete)
                        worker.start()
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
        show = showSlotSelectionDialog,
        onDismiss = { showSlotSelectionDialog = false },
        onSlotSelected = { slot ->
            showSlotSelectionDialog = false
            val horizonMethod = InstallMethod.HorizonKernel(
                uri = tempKernelUri,
                slot = slot,
                summary = summary
            )
            installMethod = horizonMethod
            onInstall()
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
        if (lkmSelection == LkmSelection.KmiNone && currentKmi.isBlank()) {
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
        ) {
            SelectInstallMethod(
                onSelected = { method ->
                    if (method is InstallMethod.HorizonKernel && method.uri != null && method.slot == null) {
                        tempKernelUri = method.uri
                        showSlotSelectionDialog = true
                    } else {
                        installMethod = method
                    }
                    horizonKernelState.reset()
                }
            )

            AnimatedVisibility(
                visible = flashState.isFlashing && installMethod is InstallMethod.HorizonKernel,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                HorizonKernelFlashProgress(flashState)
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                (lkmSelection as? LkmSelection.LkmUri)?.let {
                    Text(
                        stringResource(
                            id = R.string.selected_lkm,
                            it.uri.lastPathSegment ?: "(file)"
                        )
                    )
                }
                (installMethod as? InstallMethod.HorizonKernel)?.let { method ->
                    if (method.slot != null) {
                        Text(
                            stringResource(
                                id = R.string.selected_slot,
                                if (method.slot == "a") stringResource(id = R.string.slot_a)
                                else stringResource(id = R.string.slot_b)
                            )
                        )
                    }
                }
                Button(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = installMethod != null && !flashState.isFlashing,
                    onClick = onClickNext
                ) {
                    Text(
                        stringResource(id = R.string.install_next),
                        fontSize = MaterialTheme.typography.bodyMedium.fontSize
                    )
                }
            }
        }
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
        @StringRes override val label: Int = R.string.select_file,
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
        @StringRes override val label: Int = R.string.horizon_kernel,
        override val summary: String? = null
    ) : InstallMethod()

    abstract val label: Int
    open val summary: String? = null
}

@Composable
private fun SelectInstallMethod(onSelected: (InstallMethod) -> Unit = {}) {
    val rootAvailable = rootAvailable()
    val isAbDevice = isAbDevice()
    val horizonKernelSummary = stringResource(R.string.horizon_kernel_summary)
    val selectFileTip = stringResource(
        id = R.string.select_file_tip,
        if (isInitBoot()) "init_boot" else "boot"
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
                option?.let {
                    selectedOption = it
                    onSelected(it)
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

    var LKMExpanded by remember { mutableStateOf(false) }
    var GKIExpanded by remember { mutableStateOf(false) }

    Column {
        ListItem(
            leadingContent = { Icon(Icons.Filled.AutoFixHigh, null) },
            headlineContent = { Text(stringResource(R.string.Lkm_install_methods)) },
            modifier = Modifier.clickable {
                LKMExpanded = !LKMExpanded
            }
        )
        radioOptions.take(3).forEach { option ->
            AnimatedVisibility(
                visible = LKMExpanded,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
            ) {
                Column {
                    val interactionSource = remember { MutableInteractionSource() }
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .toggleable(
                                value = option.javaClass == selectedOption?.javaClass,
                                onValueChange = { onClick(option) },
                                role = Role.RadioButton,
                                indication = LocalIndication.current,
                                interactionSource = interactionSource
                            )
                    ) {
                        RadioButton(
                            selected = option.javaClass == selectedOption?.javaClass,
                            onClick = { onClick(option) },
                            interactionSource = interactionSource
                        )
                        Column(
                            modifier = Modifier.padding(vertical = 12.dp)
                        ) {
                            Text(
                                text = stringResource(id = option.label),
                                fontSize = MaterialTheme.typography.titleMedium.fontSize,
                                fontFamily = MaterialTheme.typography.titleMedium.fontFamily,
                                fontStyle = MaterialTheme.typography.titleMedium.fontStyle
                            )
                            option.summary?.let {
                                Text(
                                    text = it,
                                    fontSize = MaterialTheme.typography.bodySmall.fontSize,
                                    fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                                    fontStyle = MaterialTheme.typography.bodySmall.fontStyle
                                )
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }
        }
    }
    Column {
        ListItem(
            leadingContent = { Icon(Icons.Filled.FileUpload, null) },
            headlineContent = { Text(stringResource(R.string.GKI_install_methods)) },
            modifier = Modifier.clickable {
                GKIExpanded = !GKIExpanded
            }
        )
        AnimatedVisibility(
            visible = GKIExpanded,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
        ) {
            Column {
                radioOptions.drop(3).forEach { option ->
                    val interactionSource = remember { MutableInteractionSource() }
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .toggleable(
                                value = option.javaClass == selectedOption?.javaClass,
                                onValueChange = { onClick(option) },
                                role = Role.RadioButton,
                                indication = LocalIndication.current,
                                interactionSource = interactionSource
                            )
                    ) {
                        RadioButton(
                            selected = option.javaClass == selectedOption?.javaClass,
                            onClick = { onClick(option) },
                            interactionSource = interactionSource
                        )
                        Column(
                            modifier = Modifier.padding(vertical = 12.dp)
                        ) {
                            Text(
                                text = stringResource(id = option.label),
                                fontSize = MaterialTheme.typography.titleMedium.fontSize,
                                fontFamily = MaterialTheme.typography.titleMedium.fontFamily,
                                fontStyle = MaterialTheme.typography.titleMedium.fontStyle
                            )
                            option.summary?.let {
                                Text(
                                    text = it,
                                    fontSize = MaterialTheme.typography.bodySmall.fontSize,
                                    fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                                    fontStyle = MaterialTheme.typography.bodySmall.fontStyle
                                )
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun rememberSelectKmiDialog(onSelected: (String?) -> Unit): DialogHandle {
    return rememberCustomDialog { dismiss ->
        val supportedKmi by produceState(initialValue = emptyList<String>()) {
            value = getSupportedKmis()
        }
        val listOptions = supportedKmi.map { value ->
            ListOption(
                titleText = value,
                subtitleText = null,
                icon = null
            )
        }

        var selection: String? = null
        val cardColor = if (!ThemeConfig.useDynamicColor) {
            ThemeConfig.currentTheme.ButtonContrast
        } else {
            MaterialTheme.colorScheme.secondaryContainer
        }

        AlertDialog(
            onDismissRequest = {
                dismiss()
            },
            title = {
                Text(text = stringResource(R.string.select_kmi))
            },
            text = {
                Column {
                    listOptions.forEachIndexed { index, option ->
                        Row(
                            modifier = Modifier
                                .clickable {
                                    selection = supportedKmi[index]
                                }
                                .padding(vertical = 8.dp)
                        ) {
                            Column {
                                Text(text = option.titleText)
                                option.subtitleText?.let {
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
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (selection != null) {
                            onSelected(selection)
                        }
                        dismiss()
                    }
                ) {
                    Text(text = stringResource(android.R.string.ok))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        dismiss()
                    }
                ) {
                    Text(text = stringResource(android.R.string.cancel))
                }
            },
            containerColor = getCardColors(cardColor.copy(alpha = 0.9f)).containerColor.copy(alpha = 0.9f),
            shape = MaterialTheme.shapes.medium,
            tonalElevation = 0.dp
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar(
    onBack: () -> Unit = {},
    onLkmUpload: () -> Unit = {},
    scrollBehavior: TopAppBarScrollBehavior? = null
) {
    val cardColor = MaterialTheme.colorScheme.secondaryContainer
    val cardAlpha = CardConfig.cardAlpha

    TopAppBar(
        title = { Text(stringResource(R.string.install)) },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = cardColor.copy(alpha = cardAlpha),
            scrolledContainerColor = cardColor.copy(alpha = cardAlpha)
        ),
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
            }
        },
        windowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        ),
        scrollBehavior = scrollBehavior
    )
}

@Preview
@Composable
fun SelectInstallPreview() {
    InstallScreen(EmptyDestinationsNavigator)
}