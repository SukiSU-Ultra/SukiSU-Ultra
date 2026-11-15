package com.sukisu.nova.ui.screen.susfs.component

import androidx.compose.runtime.Composable
import com.sukisu.nova.ui.LocalUiMode
import com.sukisu.nova.ui.UiMode
import com.sukisu.nova.ui.screen.susfs.component.miuix.ConfirmDialogMiuix
import com.sukisu.nova.ui.screen.susfs.component.material.ConfirmDialogMaterial

@Composable
fun ConfirmDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    titleRes: Int,
    messageRes: Int,
    isLoading: Boolean = false
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> ConfirmDialogMiuix(
            showDialog = showDialog,
            onDismiss = onDismiss,
            onConfirm = onConfirm,
            titleRes = titleRes,
            messageRes = messageRes,
            isLoading = isLoading
        )
        UiMode.Material -> ConfirmDialogMaterial(
            showDialog = showDialog,
            onDismiss = onDismiss,
            onConfirm = onConfirm,
            titleRes = titleRes,
            messageRes = messageRes,
            isLoading = isLoading
        )
    }
}
