package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.preference.CheckboxPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun VersionSpoofMiuix(s: VersionSpoofState, a: VersionSpoofActions, version: String, uapi: String) {
    val scroll = MiuixScrollBehavior()
    Scaffold(topBar = {
        TopAppBar(title = stringResource(R.string.extension_version_spoof_title), scrollBehavior = scroll,
            navigationIcon = { IconButton(onClick = a.onBack) {
                Icon(Icons.AutoMirrored.Rounded.ArrowBack, stringResource(R.string.version_spoof_back))
            } })
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).nestedScroll(scroll.nestedScrollConnection)
            .verticalScroll(rememberScrollState()).imePadding().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            if (s.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            MiuixVersionSection(R.string.version_spoof_section_info) {
                Text(stringResource(R.string.version_spoof_warning), color = MiuixTheme.colorScheme.error)
                Text(stringResource(R.string.version_spoof_compiled_target, version, uapi), style = MiuixTheme.textStyles.body2)
            }
            MiuixVersionSection(R.string.version_spoof_section_fields) {
                MiuixVersionField(s.version, a.onVersion, R.string.version_spoof_code, s.originalVersion, !s.busy && s.loaded)
                MiuixVersionField(s.full, a.onFull, R.string.version_spoof_full, s.originalFull, !s.busy && s.loaded)
                MiuixVersionField(s.uapi, a.onUapi, R.string.version_spoof_uapi, s.originalUapi, !s.busy && s.loaded)
                Text(stringResource(R.string.version_spoof_hint), style = MiuixTheme.textStyles.body2)
                CheckboxPreference(title = stringResource(R.string.version_spoof_ack), checked = s.acknowledged,
                    onCheckedChange = a.onAcknowledge, enabled = !s.busy)
                TextButton(stringResource(R.string.susfs_save), a.onSave, enabled = s.canSave,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp), colors = ButtonDefaults.textButtonColorsPrimary())
                TextButton(stringResource(R.string.version_spoof_reset), a.onReset,
                    enabled = !s.busy && !s.warningBusy, modifier = Modifier.fillMaxWidth())
            }
            MiuixVersionSection(R.string.version_spoof_section_recovery) {
                SwitchPreference(title = stringResource(R.string.version_spoof_hide_warning),
                    summary = stringResource(R.string.version_spoof_hide_warning_summary),
                    checked = s.hideWarning, onCheckedChange = a.onHideWarning, enabled = !s.busy && !s.warningBusy)
                SelectionContainer { Text(stringResource(R.string.version_spoof_recovery), style = MiuixTheme.textStyles.body2) }
            }
            s.error?.let { Text(it, color = MiuixTheme.colorScheme.error) }
            if (s.success) Text(stringResource(R.string.version_spoof_success), color = MiuixTheme.colorScheme.primary)
            if (!s.loaded && !s.busy) TextButton(stringResource(R.string.refresh), a.onReload)
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun MiuixVersionSection(title: Int, content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text(stringResource(title), style = MiuixTheme.textStyles.title4, color = MiuixTheme.colorScheme.primary)
            content()
        }
    }
}

@Composable
private fun MiuixVersionField(value: String, change: (String) -> Unit, label: Int, original: String, enabled: Boolean) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        TextField(value, change, label = stringResource(label), enabled = enabled, singleLine = true, modifier = Modifier.fillMaxWidth())
        SelectionContainer { Text(stringResource(R.string.version_spoof_original_value, original),
            style = MiuixTheme.textStyles.body2, color = MiuixTheme.colorScheme.onSurfaceVariantSummary) }
    }
}
