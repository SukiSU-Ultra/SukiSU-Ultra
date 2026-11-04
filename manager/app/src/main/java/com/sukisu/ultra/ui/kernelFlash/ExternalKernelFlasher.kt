package com.sukisu.ultra.ui.kernelFlash

import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import com.sukisu.ultra.ui.kernelFlash.component.SlotSelectionDialog
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.util.isAbDevice
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext


@Composable
fun rememberExternalKernelFlasher(): suspend (Uri) -> Unit {
    val navigator = LocalNavigator.current
    var kernelUri by remember { mutableStateOf<Uri?>(null) }
    var selectedSlot by remember { mutableStateOf<String?>(null) }
    var showSlotDialog by remember { mutableStateOf(false) }
    var showKpmDialog by remember { mutableStateOf(false) }

    SlotSelectionDialog(
        show = showSlotDialog,
        onDismiss = {
            showSlotDialog = false
            kernelUri = null
        },
        onSlotSelected = {
            selectedSlot = it
            showSlotDialog = false
            showKpmDialog = true
        },
    )
    KpmPatchSelectionDialog(
        show = showKpmDialog,
        currentOption = KpmPatchOption.FOLLOW_KERNEL,
        onDismiss = {
            showKpmDialog = false
            kernelUri = null
        },
        onOptionSelected = { option ->
            val uri = kernelUri
            showKpmDialog = false
            kernelUri = null
            if (uri != null) {
                navigator.push(
                    Route.KernelFlash(
                        kernelUri = uri,
                        selectedSlot = selectedSlot,
                        kpmPatchEnabled = option == KpmPatchOption.PATCH_KPM,
                        kpmUndoPatch = option == KpmPatchOption.UNDO_PATCH_KPM,
                    )
                )
            }
        },
    )

    val startFlash by rememberUpdatedState<suspend (Uri) -> Unit>({ uri ->
        val abDevice = withContext(Dispatchers.IO) { isAbDevice() }
        kernelUri = uri
        selectedSlot = null
        showSlotDialog = abDevice
        showKpmDialog = !abDevice
    })
    return remember { { uri -> startFlash(uri) } }
}
