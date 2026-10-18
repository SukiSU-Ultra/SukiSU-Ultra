package com.sukisu.ultra.ui.screen.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.ExtensionId
import com.sukisu.ultra.ui.util.ExtensionState

/**
 * One row in the extension list. Shows status (enabled/disabled/not supported).
 * The whole card is clickable if the extension is supported; unsupported
 * extensions display a non-interactive status and no navigation arrow.
 */
@Composable
fun ExtensionCard(
    title: String,
    summary: String,
    state: ExtensionState?,
    onOpenDetails: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val supported = state?.supported == true

    Card(
        modifier = modifier
            .fillMaxWidth()
            .then(
                if (supported && onOpenDetails != null) {
                    Modifier.clickable(onClick = onOpenDetails)
                } else {
                    Modifier
                }
            ),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = Icons.Rounded.Memory,
                contentDescription = null,
                modifier = Modifier.padding(end = 12.dp)
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                StatusLine(state = state)
            }
            if (supported && onOpenDetails != null) {
                Icon(
                    imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                    contentDescription = stringResource(
                        R.string.extension_open_details
                    ),
                )
            }
        }
    }
}

@Composable
private fun StatusLine(state: ExtensionState?) {
    // Extensions without a runtime sticky bit (KPM, CPU spoof, umount
    // paths) report value=0 even when their subsystem is healthy.
    // Forcing a neutral "Supported" label here avoids showing a
    // misleading "Disabled" pill in the overview, since the only
    // place to actually operate them is their sub-screen.
    if (state != null && !state.id.hasStickyBit && state.supported) {
        Text(
            text = stringResource(R.string.extension_status_supported),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary,
        )
        return
    }
    val (label, color) = when {
        state == null -> return
        !state.supported ->
            stringResource(R.string.extension_status_unsupported) to
                MaterialTheme.colorScheme.error
        state.forced ->
            stringResource(R.string.extension_status_forced) to
                MaterialTheme.colorScheme.tertiary
        state.managed ->
            stringResource(R.string.extension_status_managed) to
                MaterialTheme.colorScheme.tertiary
        state.value != 0L ->
            stringResource(R.string.extension_status_enabled) to
                MaterialTheme.colorScheme.primary
        else ->
            stringResource(R.string.extension_status_disabled) to
                MaterialTheme.colorScheme.onSurfaceVariant
    }
    Text(
        text = label,
        style = MaterialTheme.typography.labelSmall,
        color = color,
    )
}

@Composable
fun ExtensionCard(
    id: ExtensionId,
    state: ExtensionState?,
    onOpenDetails: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    ExtensionCard(
        title = stringResource(id.displayRes),
        summary = stringResource(
            when (id) {
                ExtensionId.Kpm -> R.string.extension_kpm_summary
                ExtensionId.CpuSpoof -> R.string.extension_cpu_spoof_summary
                ExtensionId.UmountPaths -> R.string.extension_umount_paths_summary
                ExtensionId.DynamicManager -> R.string.extension_dynamic_manager_summary
            }
        ),
        state = state,
        onOpenDetails = onOpenDetails,
        modifier = modifier,
    )
}
