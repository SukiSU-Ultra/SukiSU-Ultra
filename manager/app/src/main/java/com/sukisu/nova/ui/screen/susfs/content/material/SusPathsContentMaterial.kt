package com.sukisu.nova.ui.screen.susfs.content.material

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.nova.R
import com.sukisu.nova.ui.screen.susfs.component.material.AppPathGroupCardMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.BottomActionButtonsMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.EmptyStateCardMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.PathItemCardMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.ResetButtonMaterial
import com.sukisu.nova.ui.screen.susfs.component.material.SectionHeaderMaterial

@Composable
fun SusPathsContentMaterial(
    susPaths: Set<String>,
    isLoading: Boolean,
    onAddPath: () -> Unit,
    onAddAppPath: () -> Unit,
    onRemovePath: (String) -> Unit,
    onEditPath: (String) -> Unit,
    onReset: () -> Unit
) {
    val (appPathGroups, otherPaths) = remember(susPaths) {
        val appPathRegex = Regex(".*/Android/data/([^/]+)/?.*")
        val appPathMap = mutableMapOf<String, MutableList<String>>()
        val others = mutableListOf<String>()
        susPaths.forEach { path ->
            val appDataMatch = appPathRegex.find(path)
            when {
                appDataMatch != null -> {
                    val packageName = appDataMatch.groupValues[1]
                    appPathMap.getOrPut(packageName) { mutableListOf() }.add(path)
                }
                else -> others.add(path)
            }
        }
        Pair(appPathMap.toList().sortedBy { it.first }, others.sorted())
    }

    Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        // 应用路径分组
        if (appPathGroups.isNotEmpty()) {
            SectionHeaderMaterial(
                title = stringResource(R.string.app_paths_section),
                subtitle = null,
                icon = Icons.Default.Apps,
                count = appPathGroups.size
            )
            appPathGroups.forEach { (packageName, paths) ->
                AppPathGroupCardMaterial(
                    packageName = packageName,
                    paths = paths,
                    onDeleteGroup = { paths.forEach { path -> onRemovePath(path) } },
                    onEditGroup = { onEditPath(paths.first()) },
                    isLoading = isLoading
                )
            }
        }

        // 其他路径
        if (otherPaths.isNotEmpty()) {
            SectionHeaderMaterial(
                title = stringResource(R.string.other_paths_section),
                subtitle = null,
                icon = Icons.Default.Folder,
                count = otherPaths.size
            )
            otherPaths.forEach { path ->
                PathItemCardMaterial(
                    path = path,
                    icon = Icons.Default.Folder,
                    onDelete = { onRemovePath(path) },
                    onEdit = { onEditPath(path) },
                    isLoading = isLoading
                )
            }
        }

        if (susPaths.isEmpty()) {
            EmptyStateCardMaterial(message = stringResource(R.string.susfs_no_paths_configured))
        }
    }

    // 底部按钮
    BottomActionButtonsMaterial(
        primaryButtonText = stringResource(R.string.add_custom_path),
        onPrimaryClick = onAddPath,
        secondaryButtonText = stringResource(R.string.susfs_apply),
        onSecondaryClick = onAddAppPath,
        isLoading = isLoading
    )

    if (susPaths.isNotEmpty()) {
        ResetButtonMaterial(
            title = stringResource(R.string.susfs_reset_paths_title),
            onClick = onReset,
            enabled = !isLoading
        )
    }
}
