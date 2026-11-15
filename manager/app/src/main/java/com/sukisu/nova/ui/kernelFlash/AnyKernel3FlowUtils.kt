package com.sukisu.nova.ui.kernelFlash

import androidx.compose.runtime.Stable
import com.sukisu.nova.ui.screen.install.InstallMethod

enum class KpmPatchOption {
    FOLLOW_KERNEL,
    PATCH_KPM,
    UNDO_PATCH_KPM;

    val enabled: Boolean get() = this != FOLLOW_KERNEL
    val undo: Boolean get() = this == UNDO_PATCH_KPM
}

@Stable
data class AnyKernel3State(
    val showSlotSelectionDialog: Boolean,
    val onHorizonKernelSelected: (InstallMethod.HorizonKernel) -> Unit,
    val onSlotSelected: (String) -> Unit,
    val onDismissSlotDialog: () -> Unit,
    val onReopenSlotDialog: (InstallMethod.HorizonKernel) -> Unit
)
