package com.sukisu.nova.ui.kernelFlash

import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.core.net.toUri
import com.sukisu.nova.ui.LocalUiMode
import com.sukisu.nova.ui.UiMode
import com.sukisu.nova.ui.screen.install.InstallMethod

@Composable
fun rememberAnyKernel3State(
    installMethodState: MutableState<InstallMethod?>,
    preselectedKernelUri: String?,
    horizonKernelSummary: String,
    isAbDevice: Boolean
): AnyKernel3State {
    var showSlotSelectionDialog by rememberSaveable { mutableStateOf(false) }
    var tempKernelUri by rememberSaveable { mutableStateOf<Uri?>(null) }

    val onHorizonKernelSelected: (InstallMethod.HorizonKernel) -> Unit = { method ->
        method.uri?.let { uri ->
            if (isAbDevice && method.slot == null) {
                tempKernelUri = uri
                showSlotSelectionDialog = true
            } else {
                installMethodState.value = method
            }
        }
    }
    val onReopenSlotDialog: (InstallMethod.HorizonKernel) -> Unit = { method ->
        method.uri?.takeIf { isAbDevice }?.let { uri ->
            tempKernelUri = uri
            showSlotSelectionDialog = true
        }
    }
    val onSlotSelected: (String) -> Unit = { slot ->
        val uri = tempKernelUri ?: (installMethodState.value as? InstallMethod.HorizonKernel)?.uri
        uri?.let {
            installMethodState.value = InstallMethod.HorizonKernel(
                uri = it,
                slot = slot,
                summary = horizonKernelSummary
            )
            tempKernelUri = null
            showSlotSelectionDialog = false
        }
    }
    val onDismissSlotDialog = { showSlotSelectionDialog = false }

    LaunchedEffect(preselectedKernelUri, isAbDevice, horizonKernelSummary) {
        preselectedKernelUri?.let { uriString ->
            runCatching { uriString.toUri() }.getOrNull()?.let { uri ->
                val method = InstallMethod.HorizonKernel(uri = uri, summary = horizonKernelSummary)
                if (isAbDevice) {
                    tempKernelUri = uri
                    showSlotSelectionDialog = true
                } else {
                    installMethodState.value = method
                }
            }
        }
    }

    return AnyKernel3State(
        showSlotSelectionDialog = showSlotSelectionDialog,
        onHorizonKernelSelected = onHorizonKernelSelected,
        onSlotSelected = onSlotSelected,
        onDismissSlotDialog = onDismissSlotDialog,
        onReopenSlotDialog = onReopenSlotDialog
    )
}

@Composable
fun KpmPatchSelectionDialog(
    show: Boolean,
    currentOption: KpmPatchOption,
    onDismiss: () -> Unit,
    onOptionSelected: (KpmPatchOption) -> Unit
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> KpmPatchSelectionDialogMiuix(
            show = show,
            currentOption = currentOption,
            onDismiss = onDismiss,
            onOptionSelected = onOptionSelected
        )
        UiMode.Material -> KpmPatchSelectionDialogMaterial(
            show = show,
            currentOption = currentOption,
            onDismiss = onDismiss,
            onOptionSelected = onOptionSelected
        )
    }
}


