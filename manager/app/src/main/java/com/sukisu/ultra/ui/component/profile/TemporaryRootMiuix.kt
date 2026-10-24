package com.sukisu.ultra.ui.component.profile

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Timer
import top.yukonga.miuix.kmp.basic.TextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.CheckboxPreference
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun TemporaryRootPreferencesMiuix(labels: List<String>, selectedIndex: Int, onSelect: (Int) -> Unit) {
    // Settings' LazyColumn already supplies the 12 dp horizontal page inset.
    Column(Modifier.padding(top = 12.dp)) {
        Card(Modifier.fillMaxWidth()) {
            OverlayDropdownPreference(
                title = stringResource(R.string.temporary_root_duration_title),
                summary = stringResource(R.string.temporary_root_duration_summary),
                items = labels,
                selectedIndex = selectedIndex,
                onSelectedIndexChange = onSelect,
                startAction = { TemporaryRootIconMiuix() },
            )
        }
    }
}

@Composable
internal fun TemporaryRootControlsMiuix(
    enabled: Boolean,
    granted: Boolean,
    options: List<RootGrantOption>,
    onEnabledChange: (Boolean) -> Unit,
    onChoose: (Long?) -> Unit,
) {
    Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
        Card(Modifier.fillMaxWidth()) {
            SwitchPreference(
                title = stringResource(R.string.temporary_root_title),
                summary = stringResource(R.string.temporary_root_switch_summary),
                checked = enabled,
                onCheckedChange = onEnabledChange,
                startAction = { TemporaryRootIconMiuix() },
            )
            AnimatedVisibility(visible = enabled && !granted) {
                Column {
                    options.forEach { option ->
                        ArrowPreference(
                            title = option.label,
                            onClick = { onChoose(option.seconds) },
                        )
                    }
                }
            }
        }
        TemporaryRootNoticeMiuix()
    }
}

@Composable
private fun TemporaryRootIconMiuix() {
    Icon(
        imageVector = Icons.Outlined.Timer,
        contentDescription = null,
        modifier = Modifier.padding(end = 6.dp),
        tint = MiuixTheme.colorScheme.onSurface,
    )
}

@Composable
private fun TemporaryRootNoticeMiuix(text: String = stringResource(R.string.temporary_root_warning_short)) {
    Text(
        text = text,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
        fontSize = MiuixTheme.textStyles.footnote1.fontSize,
        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
    )
}

@Composable
internal fun TemporaryRootGrantDialogMiuix(options: List<RootGrantOption>, onDismiss: () -> Unit, onChoose: (Long?) -> Unit) {
    var selectedIndex by remember(options) { mutableIntStateOf(options.indexOfLast { it.seconds != null && it.seconds != 0L }.coerceAtLeast(0)) }
    OverlayDialog(
        show = true,
        title = stringResource(R.string.temporary_root_grant_title),
        onDismissRequest = onDismiss,
        insideMargin = DpSize(0.dp, 24.dp),
    ) {
        Column(Modifier.heightIn(max = 520.dp)) {
            // Keep actions outside the scrollable content for large text / landscape.
            Column(Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState())) {
                TemporaryRootNoticeMiuix(stringResource(R.string.temporary_root_warning))
                options.forEachIndexed { index, option ->
                    CheckboxPreference(
                        title = option.label,
                        checked = selectedIndex == index,
                        holdDownState = selectedIndex == index,
                        onCheckedChange = { selectedIndex = index },
                        insideMargin = PaddingValues(horizontal = 24.dp, vertical = 12.dp),
                    )
                }
            }
            Row(Modifier.fillMaxWidth().padding(start = 24.dp, end = 24.dp, top = 16.dp)) {
                TextButton(
                    text = stringResource(android.R.string.cancel),
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(16.dp))
                TextButton(
                    text = stringResource(R.string.confirm),
                    onClick = { onChoose(options[selectedIndex].seconds) },
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
internal fun TemporaryRootCustomDurationMiuix(
    input: TextFieldValue,
    valid: Boolean,
    onInput: (TextFieldValue) -> Unit,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    OverlayDialog(
        show = true,
        title = stringResource(R.string.temporary_root_custom_duration),
        summary = stringResource(R.string.temporary_root_custom_range),
        onDismissRequest = onDismiss,
    ) {
        TextField(
            value = input,
            onValueChange = onInput,
            label = stringResource(R.string.temporary_root_custom_minutes),
            singleLine = true,
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Number,
            ),
        )
        Row(Modifier.fillMaxWidth().padding(top = 16.dp)) {
            TextButton(
                text = stringResource(android.R.string.cancel),
                onClick = onDismiss,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(16.dp))
            TextButton(
                text = stringResource(R.string.confirm),
                onClick = onConfirm,
                enabled = valid,
                colors = ButtonDefaults.textButtonColorsPrimary(),
                modifier = Modifier.weight(1f),
            )
        }
    }
}
