package com.sukisu.ultra.ui.screen.appcontext

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.ui.state.ToggleableState
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.basic.TextField as MiuixTextField
import top.yukonga.miuix.kmp.basic.Checkbox as MiuixCheckbox
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator as MiuixProgress
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
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

    val miuix = LocalUiMode.current == UiMode.Miuix
    val dismiss = { if (!state.busy && !active) onDismiss() }
    val content: @Composable () -> Unit = {

        Column(
            modifier = Modifier.heightIn(max = 560.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            ToolText(stringResource(R.string.app_context_tools_warning))
            ToolField(value = uid, onValueChange = { uid = it; consent = false },
                label = stringResource(R.string.app_context_test_uid), enabled = !state.busy && !active)
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (miuix) {
                    MiuixCheckbox(state = ToggleableState(consent), onClick = { consent = !consent },
                        enabled = !state.busy && !active)
                } else {
                    Checkbox(checked = consent, onCheckedChange = { consent = it },
                        enabled = !state.busy && !active)
                }
                ToolText(stringResource(R.string.app_context_test_consent))
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                ToolButton(onClick = { model.autoTest(uid) },
                    enabled = validUid && consent && !active && !state.busy) {
                    ToolText(stringResource(R.string.app_context_run_tests))
                }
                ToolButton(onClick = { model.start(uid) },
                    enabled = validUid && consent && !active && !state.busy) {
                    ToolText(stringResource(R.string.app_context_start_session))
                }
            }
            if (active) {
                ToolText(stringResource(R.string.app_context_active_uid, state.sessionUid.toString()))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    ToolButton(onClick = { model.update("set-fg", "true") }, enabled = !state.busy) {
                        ToolText(stringResource(R.string.app_context_debug_fg))
                    }
                    ToolButton(onClick = { model.update("set-fg", "false") }, enabled = !state.busy) {
                        ToolText(stringResource(R.string.app_context_debug_bg))
                    }
                }
                ToolField(value = profile, onValueChange = { profile = it },
                    label = stringResource(R.string.app_context_profile), enabled = !state.busy)
                ToolButton(onClick = { model.update("set-profile", profile) }, enabled = !state.busy) {
                    ToolText(stringResource(R.string.app_context_apply_profile))
                }
                ToolField(value = tags, onValueChange = { tags = it },
                    label = stringResource(R.string.app_context_debug_mask), enabled = !state.busy)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ToolButton(onClick = { model.update("set-tag", tags) }, enabled = !state.busy) {
                        ToolText(stringResource(R.string.app_context_set_bits))
                    }
                    ToolButton(onClick = { model.update("clear-tag", tags) }, enabled = !state.busy) {
                        ToolText(stringResource(R.string.app_context_clear_bits))
                    }
                }
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ToolButton(onClick = model::query, enabled = !state.busy) {
                        ToolText(stringResource(R.string.app_context_query_test))
                    }
                    ToolButton(onClick = model::end, enabled = !state.busy) {
                        ToolText(stringResource(R.string.app_context_end_session))
                    }
                }
            }
            if (active) {
                ToolButton(onClick = model::detach, enabled = !state.busy) {
                    ToolText(stringResource(R.string.app_context_detach_session))
                }
            }
            if (state.busy) {
                if (miuix) MiuixProgress()
                else LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            ToolText(stringResource(R.string.app_context_test_log))
            SelectionContainer {
                ToolText(state.log.joinToString("\n"), fontFamily = FontFamily.Monospace)
            }
        }
    }
    if (miuix) {
        OverlayDialog(
            show = true,
            title = stringResource(R.string.app_context_tools),
            onDismissRequest = dismiss,
            content = {
                content()
                MiuixTextButton(
                    text = stringResource(R.string.app_context_tools_close),
                    onClick = onDismiss,
                    enabled = !state.busy && !active,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
        )
    } else {
        AlertDialog(
            onDismissRequest = dismiss,
            properties = DialogProperties(dismissOnBackPress = !state.busy && !active,
                dismissOnClickOutside = !state.busy && !active),
            title = { Text(stringResource(R.string.app_context_tools)) },
            text = content,
            confirmButton = {
                TextButton(onClick = onDismiss, enabled = !state.busy && !active) {
                    Text(stringResource(R.string.app_context_tools_close))
                }
            },
        )
    }
}

@Composable
private fun ToolText(text: String, fontFamily: FontFamily? = null) {
    if (LocalUiMode.current == UiMode.Miuix) {
        MiuixText(text = text, fontFamily = fontFamily)
    } else Text(text = text, fontFamily = fontFamily)
}

@Composable
private fun ToolButton(onClick: () -> Unit, enabled: Boolean, content: @Composable () -> Unit) {
    if (LocalUiMode.current == UiMode.Miuix) {
        top.yukonga.miuix.kmp.basic.Button(onClick = onClick, enabled = enabled) { content() }
    } else TextButton(onClick = onClick, enabled = enabled) { content() }
}

@Composable
private fun ToolField(value: String, onValueChange: (String) -> Unit, label: String, enabled: Boolean) {
    if (LocalUiMode.current == UiMode.Miuix) {
        MiuixTextField(value = value, onValueChange = onValueChange, label = label,
            enabled = enabled, singleLine = true, modifier = Modifier.fillMaxWidth())
    } else {
        OutlinedTextField(value = value, onValueChange = onValueChange, label = { Text(label) },
            enabled = enabled, singleLine = true, modifier = Modifier.fillMaxWidth())
    }
}
