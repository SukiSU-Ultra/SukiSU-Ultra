package com.sukisu.ultra.ui.screen.susfs.content.miuix

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.screen.susfs.component.miuix.BottomActionButtonsMiuix
import com.sukisu.ultra.ui.screen.susfs.component.miuix.DescriptionCardMiuix
import com.sukisu.ultra.ui.screen.susfs.component.miuix.EmptyStateCardMiuix
import com.sukisu.ultra.ui.screen.susfs.component.miuix.ResetButtonMiuix
import com.sukisu.ultra.ui.screen.susfs.component.miuix.SectionHeaderMiuix

@Composable
fun PriorityUidFilterContentMiuix(
    packages: Set<String>,
    isLoading: Boolean,
    onSelectApps: () -> Unit,
    onApply: () -> Unit,
    onClear: () -> Unit,
) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        DescriptionCardMiuix(
            title = stringResource(R.string.susfs_priority_uid_filter),
            description = stringResource(R.string.susfs_priority_uid_filter_description),
            warning = stringResource(R.string.susfs_priority_uid_filter_warning),
        )
        SectionHeaderMiuix(
            title = stringResource(R.string.susfs_priority_uid_filter_apps),
            subtitle = null,
            icon = Icons.Default.Security,
            count = packages.size,
        )
        if (packages.isEmpty()) {
            EmptyStateCardMiuix(message = stringResource(R.string.susfs_priority_uid_filter_empty))
        } else {
            packages.sorted().forEach { name ->
                AppCard(
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(name, modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        style = MiuixTheme.textStyles.body2)
                }
            }
        }
    }
    BottomActionButtonsMiuix(
        primaryButtonText = stringResource(R.string.susfs_priority_uid_filter_select),
        onPrimaryClick = onSelectApps,
        secondaryButtonText = stringResource(R.string.confirm),
        onSecondaryClick = onApply,
        isLoading = isLoading,
    )
    if (packages.isNotEmpty()) {
        ResetButtonMiuix(
            title = stringResource(R.string.susfs_priority_uid_filter_clear),
            onClick = onClear,
            enabled = !isLoading,
        )
    }
}
