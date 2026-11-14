package com.sukisu.ultra.ui.screen.susfs.component.material

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R

sealed class DialogFieldMaterial {
    data class TextField(
        val value: String,
        val onValueChange: (String) -> Unit,
        val labelRes: Int,
        val enabled: Boolean = true,
        val modifier: Modifier = Modifier.fillMaxWidth()
    ) : DialogFieldMaterial()

}

@Composable
fun ConfirmDialogMaterial(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    titleRes: Int,
    messageRes: Int,
    isLoading: Boolean = false
) {
    if (showDialog) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(titleRes)) },
            text = {
                Text(stringResource(messageRes))
            },
            confirmButton = {
                Button(
                    onClick = onConfirm,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                    enabled = !isLoading
                ) {
                    Text(stringResource(R.string.confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}
