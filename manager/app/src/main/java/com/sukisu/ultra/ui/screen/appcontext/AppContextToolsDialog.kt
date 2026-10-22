package com.sukisu.ultra.ui.screen.appcontext

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.viewmodel.AppContextToolsViewModel

/** Shared diagnostic panel for both App Context themes. */
@Composable
fun AppContextToolsDialog(onDismiss: () -> Unit) {
    val model: AppContextToolsViewModel = viewModel()
    val state by model.state.collectAsStateWithLifecycle()
    var uid by rememberSaveable { mutableStateOf("199999") }
    var profile by rememberSaveable { mutableStateOf("42") }
    var tags by rememberSaveable { mutableStateOf("0x8000000000000001") }
    var consent by rememberSaveable { mutableStateOf(false) }
    val active = state.sessionUid != null
    val validUid = uid.toLongOrNull()?.let { it in 1..0xffffffffL } == true

    AlertDialog(
        onDismissRequest = { if (!state.busy && !active) onDismiss() },
        properties = DialogProperties(dismissOnBackPress = !state.busy && !active,
            dismissOnClickOutside = !state.busy && !active),
        title = { Text(stringResource(R.string.app_context_tools)) },
        text = {
            Column(
                modifier = Modifier.heightIn(max = 560.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(stringResource(R.string.app_context_tools_warning))
                OutlinedTextField(
                    value = uid, onValueChange = { uid = it; consent = false },
                    label = { Text(stringResource(R.string.app_context_test_uid)) },
                    enabled = !state.busy && !active, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row {
                    Checkbox(checked = consent, onCheckedChange = { consent = it },
                        enabled = !state.busy && !active)
                    Text(stringResource(R.string.app_context_test_consent))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { model.autoTest(uid) },
                        enabled = validUid && consent && !active && !state.busy) {
                        Text(stringResource(R.string.app_context_run_tests))
                    }
                    TextButton(onClick = { model.start(uid) },
                        enabled = validUid && consent && !active && !state.busy) {
                        Text(stringResource(R.string.app_context_start_session))
                    }
                }
                if (active) {
                    Text(stringResource(R.string.app_context_active_uid, state.sessionUid.toString()))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = { model.update("set-fg", "true") }, enabled = !state.busy) {
                            Text(stringResource(R.string.app_context_debug_fg))
                        }
                        TextButton(onClick = { model.update("set-fg", "false") }, enabled = !state.busy) {
                            Text(stringResource(R.string.app_context_debug_bg))
                        }
                    }
                    OutlinedTextField(value = profile, onValueChange = { profile = it },
                        label = { Text(stringResource(R.string.app_context_profile)) },
                        singleLine = true, enabled = !state.busy, modifier = Modifier.fillMaxWidth())
                    TextButton(onClick = { model.update("set-profile", profile) }, enabled = !state.busy) {
                        Text(stringResource(R.string.app_context_apply_profile))
                    }
                    OutlinedTextField(value = tags, onValueChange = { tags = it },
                        label = { Text(stringResource(R.string.app_context_debug_mask)) },
                        singleLine = true, enabled = !state.busy, modifier = Modifier.fillMaxWidth())
                    Row {
                        TextButton(onClick = { model.update("set-tag", tags) }, enabled = !state.busy) {
                            Text(stringResource(R.string.app_context_set_bits))
                        }
                        TextButton(onClick = { model.update("clear-tag", tags) }, enabled = !state.busy) {
                            Text(stringResource(R.string.app_context_clear_bits))
                        }
                    }
                    Row {
                        TextButton(onClick = model::query, enabled = !state.busy) {
                            Text(stringResource(R.string.app_context_query_test))
                        }
                        TextButton(onClick = model::end, enabled = !state.busy) {
                            Text(stringResource(R.string.app_context_end_session))
                        }
                    }
                }
                if (active) {
                    TextButton(onClick = model::detach, enabled = !state.busy) {
                        Text(stringResource(R.string.app_context_detach_session))
                    }
                }
                if (state.busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                Text(stringResource(R.string.app_context_test_log))
                SelectionContainer {
                    Text(state.log.joinToString("\n"), fontFamily = FontFamily.Monospace)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss, enabled = !state.busy && !active) {
                Text(stringResource(R.string.app_context_tools_close))
            }
        },
    )
}
