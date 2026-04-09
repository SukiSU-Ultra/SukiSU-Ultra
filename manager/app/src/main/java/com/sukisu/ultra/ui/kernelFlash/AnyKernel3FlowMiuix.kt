package com.sukisu.ultra.ui.kernelFlash

import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.install.InstallMethod
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
fun rememberAnyKernel3StateMiuix(
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
fun KpmPatchSelectionDialogMiuix(
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

    OverlayDialog(
        show = showDialog.value,
        insideMargin = DpSize(0.dp, 0.dp),
        onDismissRequest = {
            showDialog.value = false
            onDismiss()
        },
        content = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 24.dp)
            ) {
                Text(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 12.dp),
                    text = stringResource(id = R.string.kpm_patch_options),
                    fontSize = MiuixTheme.textStyles.title4.fontSize,
                    fontWeight = FontWeight.Medium,
                    textAlign = TextAlign.Center,
                    color = colorScheme.onSurface
                )

                Text(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 8.dp),
                    text = stringResource(id = R.string.kpm_patch_description),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = colorScheme.onSurfaceVariantSummary,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(12.dp))

                val options = listOf(
                    KpmPatchOption.FOLLOW_KERNEL to stringResource(R.string.kpm_follow_kernel_file),
                    KpmPatchOption.PATCH_KPM to stringResource(R.string.enable_kpm_patch),
                    KpmPatchOption.UNDO_PATCH_KPM to stringResource(R.string.enable_kpm_undo_patch)
                )

                options.forEach { (option, title) ->
                    ArrowPreference(
                        title = title,
                        onClick = {
                            selectedOption = option
                        },
                        startAction = {
                            Icon(
                                imageVector = Icons.Filled.Security,
                                contentDescription = null,
                                tint = if (selectedOption == option) {
                                    colorScheme.primary
                                } else {
                                    colorScheme.onSurfaceVariantSummary
                                }
                            )
                        },
                        insideMargin = PaddingValues(horizontal = 24.dp, vertical = 12.dp)
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    TextButton(
                        text = stringResource(android.R.string.cancel),
                        onClick = {
                            showDialog.value = false
                            onDismiss()
                        },
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(
                        text = stringResource(android.R.string.ok),
                        onClick = {
                            onOptionSelected(selectedOption)
                            showDialog.value = false
                            onDismiss()
                        },
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    )
}

