package com.sukisu.nova.ui.screen.susfs.content.miuix

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.nova.R
import com.sukisu.nova.ui.screen.susfs.component.miuix.BottomActionButtonsMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.DescriptionCardMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.EmptyStateCardMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.PathItemCardMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.ResetButtonMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.SectionHeaderMiuix

@Composable
fun SusMapsContentMiuix(
    susMaps: Set<String>,
    isLoading: Boolean,
    onAddSusMap: () -> Unit,
    onRemoveSusMap: (String) -> Unit,
    onEditSusMap: ((String) -> Unit)? = null,
    onReset: (() -> Unit)? = null
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 说明卡片
        DescriptionCardMiuix(
            title = stringResource(R.string.sus_maps_description_title),
            description = stringResource(R.string.sus_maps_description_text),
            warning = stringResource(R.string.sus_maps_warning),
            additionalInfo = stringResource(R.string.sus_maps_debug_info)
        )

        if (susMaps.isEmpty()) {
            EmptyStateCardMiuix(
                message = stringResource(R.string.susfs_no_sus_maps_configured)
            )
        } else {
            SectionHeaderMiuix(
                title = stringResource(R.string.sus_maps_section),
                subtitle = null,
                icon = Icons.Default.Security,
                count = susMaps.size
            )

            susMaps.sorted().forEach { map ->
                PathItemCardMiuix(
                    path = map,
                    icon = Icons.Default.Security,
                    onDelete = { onRemoveSusMap(map) },
                    onEdit = if (onEditSusMap != null) {
                        { onEditSusMap(map) }
                    } else null,
                    isLoading = isLoading
                )
            }
        }
    }

    BottomActionButtonsMiuix(
        primaryButtonText = stringResource(R.string.add),
        onPrimaryClick = onAddSusMap,
        isLoading = isLoading
    )

    if (onReset != null && susMaps.isNotEmpty()) {
        ResetButtonMiuix(
            title = stringResource(R.string.susfs_reset_sus_maps_title),
            onClick = onReset,
            enabled = !isLoading
        )
    }
}
