package com.sukisu.nova.ui.screen.susfs.content.miuix

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Loop
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
fun SusLoopPathsContentMiuix(
    susLoopPaths: Set<String>,
    isLoading: Boolean,
    onAddLoopPath: () -> Unit,
    onRemoveLoopPath: (String) -> Unit,
    onEditLoopPath: ((String) -> Unit)? = null,
    onReset: (() -> Unit)? = null
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 说明卡片
        DescriptionCardMiuix(
            title = stringResource(R.string.sus_loop_paths_description_title),
            description = stringResource(R.string.sus_loop_paths_description_text),
            warning = stringResource(R.string.susfs_loop_path_restriction_warning)
        )

        if (susLoopPaths.isEmpty()) {
            EmptyStateCardMiuix(
                message = stringResource(R.string.susfs_no_loop_paths_configured)
            )
        } else {
            SectionHeaderMiuix(
                title = stringResource(R.string.loop_paths_section),
                subtitle = null,
                icon = Icons.Default.Loop,
                count = susLoopPaths.size
            )

            susLoopPaths.sorted().forEach { path ->
                PathItemCardMiuix(
                    path = path,
                    icon = Icons.Default.Loop,
                    onDelete = { onRemoveLoopPath(path) },
                    onEdit = if (onEditLoopPath != null) {
                        { onEditLoopPath(path) }
                    } else null,
                    isLoading = isLoading
                )
            }
        }
    }

    BottomActionButtonsMiuix(
        primaryButtonText = stringResource(R.string.add_loop_path),
        onPrimaryClick = onAddLoopPath,
        isLoading = isLoading
    )

    if (onReset != null && susLoopPaths.isNotEmpty()) {
        ResetButtonMiuix(
            title = stringResource(R.string.susfs_reset_loop_paths_title),
            onClick = onReset,
            enabled = !isLoading
        )
    }
}
