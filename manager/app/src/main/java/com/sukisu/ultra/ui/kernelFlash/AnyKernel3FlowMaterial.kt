package com.sukisu.ultra.ui.kernelFlash

import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.install.InstallMethod

@Composable
fun rememberAnyKernel3StateMaterial(
    installMethodState: MutableState<InstallMethod?>,
    preselectedKernelUri: String?,
    horizonKernelSummary: String,
    isAbDevice: Boolean
): AnyKernel3State {
    var kpmPatchOption by remember { mutableStateOf(KpmPatchOption.FOLLOW_KERNEL) }
    var showSlotSelectionDialog by remember { mutableStateOf(false) }
    var showKpmPatchDialog by remember { mutableStateOf(false) }
    var tempKernelUri by remember { mutableStateOf<Uri?>(null) }

    val onHorizonKernelSelected: (InstallMethod.HorizonKernel) -> Unit = { method ->
        val uri = method.uri
        if (uri != null) {
            if (isAbDevice && method.slot == null) {
                tempKernelUri = uri
                showSlotSelectionDialog = true
            } else {
                installMethodState.value = method
                showKpmPatchDialog = true
            }
        }
    }

    val onReopenSlotDialog: (InstallMethod.HorizonKernel) -> Unit = { method ->
        val uri = method.uri
        if (uri != null && isAbDevice) {
            tempKernelUri = uri
            showSlotSelectionDialog = true
        }
    }

    val onReopenKpmDialog: (InstallMethod.HorizonKernel) -> Unit = { method ->
        installMethodState.value = method
        showKpmPatchDialog = true
    }

    val onSlotSelected: (String) -> Unit = { slot ->
        val uri = tempKernelUri ?: (installMethodState.value as? InstallMethod.HorizonKernel)?.uri
        if (uri != null) {
            installMethodState.value = InstallMethod.HorizonKernel(
                uri = uri,
                slot = slot,
                summary = horizonKernelSummary
            )
            tempKernelUri = null
            showSlotSelectionDialog = false
            showKpmPatchDialog = true
        }
    }

    val onDismissSlotDialog = {
        showSlotSelectionDialog = false
    }

    val onOptionSelected: (KpmPatchOption) -> Unit = { option ->
        kpmPatchOption = option
        showKpmPatchDialog = false
    }

    val onDismissPatchDialog = {
        showKpmPatchDialog = false
    }

    LaunchedEffect(preselectedKernelUri, isAbDevice, horizonKernelSummary) {
        preselectedKernelUri?.let { uriString ->
            runCatching { uriString.toUri() }
                .getOrNull()
                ?.let { preselectedUri ->
                    val method = InstallMethod.HorizonKernel(
                        uri = preselectedUri,
                        summary = horizonKernelSummary
                    )
                    if (isAbDevice) {
                        tempKernelUri = preselectedUri
                        showSlotSelectionDialog = true
                    } else {
                        installMethodState.value = method
                        showKpmPatchDialog = true
                    }
                }
        }
    }

    return AnyKernel3State(
        kpmPatchOption = kpmPatchOption,
        showSlotSelectionDialog = showSlotSelectionDialog,
        showKpmPatchDialog = showKpmPatchDialog,
        onHorizonKernelSelected = onHorizonKernelSelected,
        onSlotSelected = onSlotSelected,
        onDismissSlotDialog = onDismissSlotDialog,
        onOptionSelected = onOptionSelected,
        onDismissPatchDialog = onDismissPatchDialog,
        onReopenSlotDialog = onReopenSlotDialog,
        onReopenKpmDialog = onReopenKpmDialog
    )
}

@Composable
fun KpmPatchSelectionDialogMaterial(
    show: Boolean,
    currentOption: KpmPatchOption,
    onDismiss: () -> Unit,
    onOptionSelected: (KpmPatchOption) -> Unit
) {
    var selectedOption by remember { mutableStateOf(currentOption) }
    val showDialog = remember { mutableStateOf(show) }

    LaunchedEffect(show) {
        showDialog.value = show
        if (show) {
            selectedOption = currentOption
        }
    }

    if (showDialog.value) {
        AlertDialog(
            onDismissRequest = {
                showDialog.value = false
                onDismiss()
            },
            title = {
                Text(
                    text = stringResource(id = R.string.kpm_patch_options),
                    fontWeight = FontWeight.Medium,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = stringResource(id = R.string.kpm_patch_description),
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 16.dp)
                    )

                    val options = listOf(
                        KpmPatchOption.FOLLOW_KERNEL to stringResource(R.string.kpm_follow_kernel_file),
                        KpmPatchOption.PATCH_KPM to stringResource(R.string.enable_kpm_patch),
                        KpmPatchOption.UNDO_PATCH_KPM to stringResource(R.string.enable_kpm_undo_patch)
                    )

                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        options.forEach { (option, title) ->
                            val selected = selectedOption == option
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .selectable(
                                        selected = selected,
                                        onClick = { selectedOption = option },
                                        role = Role.RadioButton
                                    ),
                                shape = MaterialTheme.shapes.medium,
                                color = if (selected) MaterialTheme.colorScheme.secondaryContainer
                                else MaterialTheme.colorScheme.surfaceContainerHighest,
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    RadioButton(
                                        selected = selected,
                                        onClick = null
                                    )
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Text(
                                        text = title,
                                        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
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
                        showDialog.value = false
                        onOptionSelected(selectedOption)
                        onDismiss()
                    }
                ) {
                    Text(stringResource(android.R.string.ok))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showDialog.value = false
                        onDismiss()
                    }
                ) {
                    Text(stringResource(android.R.string.cancel))
                }
            }
        )
    }
}
