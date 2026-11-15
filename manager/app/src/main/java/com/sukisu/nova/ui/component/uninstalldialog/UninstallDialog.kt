package com.sukisu.nova.ui.component.uninstalldialog

import androidx.compose.runtime.Composable
import com.sukisu.nova.ui.LocalUiMode
import com.sukisu.nova.ui.UiMode

@Composable
fun UninstallDialog(
    show: Boolean,
    onDismissRequest: () -> Unit
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> UninstallDialogMiuix(show, onDismissRequest)
        UiMode.Material -> UninstallDialogMaterial(show, onDismissRequest)
    }
}
