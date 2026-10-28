package com.sukisu.ultra.ui.screen.susfs.content.material

import androidx.compose.foundation.layout.*
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.component.material.BottomActionButtonsMaterial
import com.sukisu.ultra.ui.screen.susfs.component.material.DescriptionCardMaterial
import com.sukisu.ultra.ui.screen.susfs.component.material.EmptyStateCardMaterial
import com.sukisu.ultra.ui.screen.susfs.component.material.ResetButtonMaterial
import com.sukisu.ultra.ui.screen.susfs.component.material.SectionHeaderMaterial
import com.sukisu.ultra.ui.theme.backgroundAwareColor

@Composable
fun PriorityUidFilterContentMaterial(
    packages: Set<String>,
    isLoading: Boolean,
    onSelectApps: () -> Unit,
    onApply: () -> Unit,
    onClear: () -> Unit,
) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        DescriptionCardMaterial(
            title = stringResource(R.string.susfs_priority_uid_filter),
            description = stringResource(R.string.susfs_priority_uid_filter_description),
            warning = stringResource(R.string.susfs_priority_uid_filter_warning),
        )
        SectionHeaderMaterial(
            title = stringResource(R.string.susfs_priority_uid_filter_apps),
            subtitle = null,
            icon = Icons.Default.Security,
            count = packages.size,
        )
        if (packages.isEmpty()) {
            EmptyStateCardMaterial(message = stringResource(R.string.susfs_priority_uid_filter_empty))
        } else {
            packages.sorted().forEach { name ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = backgroundAwareColor(MaterialTheme.colorScheme.surfaceContainerLow),
                        contentColor = MaterialTheme.colorScheme.onSurface,
                    ),
                ) {
                    Text(name, Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
    BottomActionButtonsMaterial(
        primaryButtonText = stringResource(R.string.susfs_priority_uid_filter_select),
        onPrimaryClick = onSelectApps,
        secondaryButtonText = stringResource(R.string.confirm),
        onSecondaryClick = onApply,
        isLoading = isLoading,
    )
    if (packages.isNotEmpty()) {
        ResetButtonMaterial(
            title = stringResource(R.string.susfs_priority_uid_filter_clear),
            onClick = onClear,
            enabled = !isLoading,
        )
    }
}
