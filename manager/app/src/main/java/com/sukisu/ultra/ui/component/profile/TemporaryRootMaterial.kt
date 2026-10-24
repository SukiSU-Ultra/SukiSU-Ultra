package com.sukisu.ultra.ui.component.profile

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Timer
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveDialog
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedDropdownItem
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.SegmentedSwitchItem

@Composable
internal fun TemporaryRootPreferencesMaterial(labels: List<String>, selectedIndex: Int, onSelect: (Int) -> Unit) {
    Column(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 13.dp)) {
        SegmentedColumn(content = listOf {
            SegmentedDropdownItem(
                icon = Icons.Outlined.Timer,
                title = stringResource(R.string.temporary_root_duration_title),
                summary = stringResource(R.string.temporary_root_duration_summary),
                items = labels,
                selectedIndex = selectedIndex,
                onItemSelected = onSelect,
            )
        })
    }
}

@Composable
internal fun TemporaryRootControlsMaterial(
    enabled: Boolean,
    granted: Boolean,
    options: List<RootGrantOption>,
    onEnabledChange: (Boolean) -> Unit,
    onChoose: (Long?) -> Unit,
) {
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        SegmentedColumn(content = listOf {
            SegmentedSwitchItem(
                icon = Icons.Outlined.Timer,
                title = stringResource(R.string.temporary_root_title),
                summary = stringResource(R.string.temporary_root_switch_summary),
                checked = enabled,
                onCheckedChange = onEnabledChange,
            )
        })
        AnimatedVisibility(visible = enabled && !granted) {
            Column(Modifier.padding(top = 8.dp)) {
                SegmentedColumn(content = options.map { option ->
                    {
                        SegmentedListItem(
                            onClick = { onChoose(option.seconds) },
                            headlineContent = { Text(option.label) },
                            leadingContent = { IconTile(Icons.Outlined.Timer, null) },
                        )
                    }
                })
            }
        }
        TemporaryRootNoticeMaterial()
    }
}

@Composable
private fun TemporaryRootNoticeMaterial() {
    Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Icon(Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            text = stringResource(R.string.temporary_root_warning_short),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
internal fun TemporaryRootGrantDialogMaterial(options: List<RootGrantOption>, onDismiss: () -> Unit, onChoose: (Long?) -> Unit) {
    // Default to a finite lease, never silently preselect permanent access.
    var selectedIndex by remember(options) { mutableIntStateOf(options.indexOfLast { it.seconds != null && it.seconds != 0L }.coerceAtLeast(0)) }
    ExpressiveDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.Timer, contentDescription = null) },
        title = { Text(stringResource(R.string.temporary_root_grant_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.temporary_root_warning), style = MaterialTheme.typography.bodySmall)
                SegmentedColumn(content = options.mapIndexed { index, option ->
                    {
                        SegmentedListItem(
                            selected = selectedIndex == index,
                            onClick = { selectedIndex = index },
                            headlineContent = { Text(option.label) },
                            leadingContent = { RadioButton(selected = selectedIndex == index, onClick = null) },
                        )
                    }
                })
            }
        },
        confirmButton = { TextButton(onClick = { onChoose(options[selectedIndex].seconds) }) { Text(stringResource(R.string.confirm)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(android.R.string.cancel)) } },
    )
}

@Composable
internal fun TemporaryRootCustomDurationMaterial(
    input: TextFieldValue,
    valid: Boolean,
    onInput: (TextFieldValue) -> Unit,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    ExpressiveDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.temporary_root_custom_duration)) },
        text = {
            OutlinedTextField(
                value = input,
                onValueChange = onInput,
                singleLine = true,
                label = { Text(stringResource(R.string.temporary_root_custom_minutes)) },
                supportingText = { Text(stringResource(R.string.temporary_root_custom_range)) },
                isError = !valid,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Number,
                ),
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm, enabled = valid) { Text(stringResource(R.string.confirm)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(android.R.string.cancel)) }
        },
    )
}
