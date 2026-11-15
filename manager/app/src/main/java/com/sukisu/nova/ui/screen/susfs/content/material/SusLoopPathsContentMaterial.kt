package com.sukisu.nova.ui.screen.susfs.content.material

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.nova.R
import com.sukisu.nova.ui.screen.susfs.component.material.BottomActionButtonsMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.DescriptionCardMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.EmptyStateCardMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.PathItemCardMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.ResetButtonMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.SectionHeaderMaterial

@Composable
fun SusLoopPathsContentMaterial(
    susLoopPaths: Set<String>,
    isLoading: Boolean,
    onAddLoopPath: () -> Unit,
    onRemoveLoopPath: (String) -> Unit,
    onEditLoopPath: (String) -> Unit,
    onReset: () -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        DescriptionCardMaterial(
            title = stringResource(R.string.sus_loop_paths_description_title),
            description = stringResource(R.string.sus_loop_paths_description_text),
            warning = stringResource(R.string.susfs_loop_path_restriction_warning)
        )

        if (susLoopPaths.isEmpty()) {
            EmptyStateCardMaterial(message = stringResource(R.string.susfs_no_loop_paths_configured))
        } else {
            SectionHeaderMaterial(
                title = stringResource(R.string.loop_paths_section),
                subtitle = null,
                icon = Icons.Default.Loop,
                count = susLoopPaths.size
            )
            susLoopPaths.sorted().forEach { path ->
                PathItemCardMaterial(
                    path = path,
                    icon = Icons.Default.Loop,
                    onDelete = { onRemoveLoopPath(path) },
                    onEdit = { onEditLoopPath(path) },
                    isLoading = isLoading
                )
            }
        }
    }

    BottomActionButtonsMaterial(
        primaryButtonText = stringResource(R.string.add_loop_path),
        onPrimaryClick = onAddLoopPath,
        isLoading = isLoading
    )

    if (susLoopPaths.isNotEmpty()) {
        ResetButtonMaterial(
            title = stringResource(R.string.susfs_reset_loop_paths_title),
            onClick = onReset,
            enabled = !isLoading
        )
    }
}
