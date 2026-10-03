package com.sukisu.ultra.ui.screen.modulerepo

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.data.repository.RepoSource
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog

private val MaxSourcesDialogHeight = 460.dp

@Composable
fun ManageSourcesDialogMaterial(
    show: Boolean,
    onDismissRequest: () -> Unit,
    state: ModuleRepoUiState,
    actions: ModuleRepoActions,
) {
    var urlInput by rememberSaveable { mutableStateOf("") }
    var pendingDelete by remember { mutableStateOf<RepoSource?>(null) }
    var editingSource by remember { mutableStateOf<RepoSource?>(null) }
    // Clear the add-field once a source actually landed (success), keep it on failure.
    LaunchedEffect(state.sources.size) {
        urlInput = ""
    }
    val deleteConfirmTitle = stringResource(R.string.module_repo_source_delete_confirm)
    val deleteDialog = rememberConfirmDialog(onConfirm = {
        pendingDelete?.let { actions.onRemoveSource(it.id) }
        pendingDelete = null
    })

    if (!show) return

    AlertDialog(
        onDismissRequest = onDismissRequest,
        title = { Text(stringResource(R.string.module_repo_manage_sources)) },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = MaxSourcesDialogHeight)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (state.sources.isEmpty()) {
                    Text(
                        text = stringResource(R.string.module_repo_sources_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                state.sources.forEach { source ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .clickable { editingSource = source },
                        ) {
                            Text(
                                text = source.name,
                                style = MaterialTheme.typography.titleSmall,
                            )
                            Text(
                                text = source.url,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        Switch(
                            checked = source.enabled,
                            onCheckedChange = { actions.onSetSourceEnabled(source.id, it) },
                            modifier = Modifier.padding(start = 8.dp),
                        )
                        IconButton(onClick = {
                            pendingDelete = source
                            deleteDialog.showConfirm(title = deleteConfirmTitle, content = source.name)
                        }) {
                            Icon(
                                imageVector = Icons.Outlined.Delete,
                                contentDescription = stringResource(R.string.delete),
                            )
                        }
                    }
                    HorizontalDivider(thickness = 0.5.dp)
                }

                OutlinedTextField(
                    value = urlInput,
                    onValueChange = { urlInput = it },
                    label = { Text(stringResource(R.string.module_repo_source_url_label)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    actions.onAddSource(urlInput)
                    urlInput = ""
                },
                enabled = urlInput.isNotBlank() && !state.isAddingSource,
            ) {
                Text(
                    if (state.isAddingSource) {
                        stringResource(R.string.module_repo_source_adding)
                    } else {
                        stringResource(R.string.module_repo_add_source)
                    }
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismissRequest) {
                Text(stringResource(android.R.string.cancel))
            }
        },
    )

    editingSource?.let { source ->
        RenameSourceDialogMaterial(
            source = source,
            onDismissRequest = { editingSource = null },
            onConfirm = { name ->
                actions.onRenameSource(source.id, name)
                editingSource = null
            },
        )
    }
}

@Composable
private fun RenameSourceDialogMaterial(
    source: RepoSource,
    onDismissRequest: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var nameInput by rememberSaveable { mutableStateOf(source.name) }
    AlertDialog(
        onDismissRequest = onDismissRequest,
        title = { Text(stringResource(R.string.module_repo_rename_source)) },
        text = {
            OutlinedTextField(
                value = nameInput,
                onValueChange = { nameInput = it },
                label = { Text(stringResource(R.string.module_repo_source_name)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(nameInput) },
                enabled = nameInput.isNotBlank(),
            ) {
                Text(stringResource(android.R.string.ok))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismissRequest) {
                Text(stringResource(android.R.string.cancel))
            }
        },
    )
}
