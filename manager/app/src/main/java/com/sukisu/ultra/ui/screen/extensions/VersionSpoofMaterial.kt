package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors

@Composable
internal fun VersionSpoofMaterial(s: VersionSpoofState, a: VersionSpoofActions, version: String, uapi: String) {
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    ExpressiveScaffold(topBar = {
        LargeFlexibleTopAppBar(
            title = { Text(stringResource(R.string.extension_version_spoof_title)) },
            navigationIcon = { TopBarBackButton(onClick = a.onBack) },
            colors = expressiveTopAppBarColors(), scrollBehavior = scroll,
        )
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).nestedScroll(scroll.nestedScrollConnection)
            .verticalScroll(rememberScrollState()).imePadding().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            if (s.busy) LinearWavyProgressIndicator(Modifier.fillMaxWidth())
            MaterialVersionSection(R.string.version_spoof_section_info) {
                Text(stringResource(R.string.version_spoof_warning), color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.version_spoof_compiled_target, version, uapi), style = MaterialTheme.typography.bodySmall)
            }
            MaterialVersionSection(R.string.version_spoof_section_fields) {
                VersionField(s.version, a.onVersion, R.string.version_spoof_code, s.originalVersion, !s.busy && s.loaded, !validVersionNumber(s.version))
                VersionField(s.full, a.onFull, R.string.version_spoof_full, s.originalFull, !s.busy && s.loaded,
                    s.full.toByteArray(Charsets.UTF_8).size > 254 || '\u0000' in s.full)
                VersionField(s.uapi, a.onUapi, R.string.version_spoof_uapi, s.originalUapi, !s.busy && s.loaded, !validVersionNumber(s.uapi))
                Text(stringResource(R.string.version_spoof_hint), style = MaterialTheme.typography.bodySmall)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(s.acknowledged, a.onAcknowledge, enabled = !s.busy)
                    Text(stringResource(R.string.version_spoof_ack), style = MaterialTheme.typography.bodyMedium)
                }
                Button(a.onSave, enabled = s.canSave, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
                    Text(stringResource(R.string.susfs_save))
                }
                OutlinedButton(a.onReset, enabled = !s.busy && !s.warningBusy, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.version_spoof_reset))
                }
            }
            MaterialVersionSection(R.string.version_spoof_section_recovery) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.version_spoof_hide_warning), style = MaterialTheme.typography.titleSmall)
                        Text(stringResource(R.string.version_spoof_hide_warning_summary), style = MaterialTheme.typography.bodySmall)
                    }
                    Switch(s.hideWarning, a.onHideWarning, enabled = !s.busy && !s.warningBusy)
                }
                SelectionContainer { Text(stringResource(R.string.version_spoof_recovery), style = MaterialTheme.typography.bodySmall) }
            }
            s.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (s.success) Text(stringResource(R.string.version_spoof_success), color = MaterialTheme.colorScheme.primary)
            if (!s.loaded && !s.busy) TextButton(a.onReload) { Text(stringResource(R.string.refresh)) }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun MaterialVersionSection(title: Int, content: @Composable ColumnScope.() -> Unit) {
    Surface(shape = MaterialTheme.shapes.extraLarge, color = MaterialTheme.colorScheme.surfaceContainerLow) {
        Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text(stringResource(title), style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
            content()
        }
    }
}

@Composable
private fun VersionField(value: String, change: (String) -> Unit, label: Int, original: String, enabled: Boolean, invalid: Boolean) {
    OutlinedTextField(value, change, label = { Text(stringResource(label)) },
        supportingText = { SelectionContainer { Text(stringResource(R.string.version_spoof_original_value, original)) } },
        enabled = enabled, isError = invalid, singleLine = true,
        shape = MaterialTheme.shapes.large, modifier = Modifier.fillMaxWidth())
}
