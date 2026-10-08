package com.sukisu.ultra.ui.screen.modulerepo

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.data.repository.RepoSource
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Delete
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

private val MaxSourcesDialogHeight = 460.dp

@Composable
fun ManageSourcesDialogMiuix(
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

    OverlayDialog(
        show = show,
        title = stringResource(R.string.module_repo_manage_sources),
        onDismissRequest = onDismissRequest,
        content = {
            Column(
                modifier = Modifier
                    .heightIn(max = MaxSourcesDialogHeight)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (state.sources.isEmpty()) {
                    Text(
                        text = stringResource(R.string.module_repo_sources_empty),
                        fontSize = 13.sp,
                        color = colorScheme.onSurfaceVariantSummary,
                    )
                }
                state.sources.forEach { source ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { editingSource = source },
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = source.name,
                                fontSize = 15.sp,
                                fontWeight = FontWeight(550),
                                color = colorScheme.onSurface,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f),
                            )
                            Switch(
                                checked = source.enabled,
                                onCheckedChange = { actions.onSetSourceEnabled(source.id, it) },
                                modifier = Modifier.padding(start = 8.dp),
                            )
                            IconButton(
                                onClick = {
                                    pendingDelete = source
                                    deleteDialog.showConfirm(title = deleteConfirmTitle, content = source.name)
                                },
                                modifier = Modifier.padding(start = 4.dp),
                            ) {
                                Icon(
                                    imageVector = MiuixIcons.Delete,
                                    contentDescription = stringResource(R.string.delete),
                                    tint = colorScheme.onSurface,
                                    modifier = Modifier.size(20.dp),
                                )
                            }
                        }
                        // The address takes the full width below the name and may wrap, so a long
                        // index path stays readable instead of being cut off right after the host.
                        Text(
                            text = source.url,
                            fontSize = 12.sp,
                            color = colorScheme.onSurfaceVariantSummary,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(end = 8.dp),
                        )
                    }
                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 6.dp),
                        thickness = 0.5.dp,
                        color = colorScheme.outline.copy(alpha = 0.5f),
                    )
                }

                if (state.candidates.isNotEmpty()) {
                    Text(
                        text = stringResource(R.string.module_repo_candidates),
                        fontSize = 15.sp,
                        fontWeight = FontWeight(550),
                        color = colorScheme.onSurface,
                    )
                    state.candidates.forEach { candidate ->
                        val addable = !candidate.isAdded && !state.isAddingSource
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable(enabled = addable) {
                                    actions.onAddSource(candidate.url, candidate.name)
                                },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = candidate.name,
                                    fontSize = 15.sp,
                                    color = colorScheme.onSurface,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    text = stringResource(
                                        R.string.module_repo_candidate_modules,
                                        candidate.moduleCount,
                                    ),
                                    fontSize = 12.sp,
                                    color = colorScheme.onSurfaceVariantSummary,
                                )
                            }
                            Text(
                                text = if (candidate.isAdded) {
                                    stringResource(R.string.module_repo_candidate_added)
                                } else {
                                    stringResource(R.string.module_repo_candidate_add)
                                },
                                fontSize = 14.sp,
                                color = if (addable) colorScheme.primary else colorScheme.onSurfaceVariantSummary,
                            )
                        }
                    }
                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 6.dp),
                        thickness = 0.5.dp,
                        color = colorScheme.outline.copy(alpha = 0.5f),
                    )
                }

                TextField(
                    value = urlInput,
                    onValueChange = { urlInput = it },
                    label = stringResource(R.string.module_repo_source_url_label),
                )
                TextButton(
                    text = if (state.isAddingSource) {
                        stringResource(R.string.module_repo_source_adding)
                    } else {
                        stringResource(R.string.module_repo_add_source)
                    },
                    onClick = {
                        actions.onAddSource(urlInput, null)
                        urlInput = ""
                    },
                    enabled = urlInput.isNotBlank() && !state.isAddingSource,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        }
    )

    editingSource?.let { source ->
        RenameSourceDialogMiuix(
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
private fun RenameSourceDialogMiuix(
    source: RepoSource,
    onDismissRequest: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var nameInput by rememberSaveable { mutableStateOf(source.name) }
    OverlayDialog(
        show = true,
        title = stringResource(R.string.module_repo_rename_source),
        onDismissRequest = onDismissRequest,
        content = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                TextField(
                    value = nameInput,
                    onValueChange = { nameInput = it },
                    label = stringResource(R.string.module_repo_source_name),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    TextButton(
                        text = stringResource(android.R.string.cancel),
                        onClick = onDismissRequest,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        text = stringResource(android.R.string.ok),
                        onClick = { onConfirm(nameInput) },
                        enabled = nameInput.isNotBlank(),
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                    )
                }
            }
        }
    )
}
