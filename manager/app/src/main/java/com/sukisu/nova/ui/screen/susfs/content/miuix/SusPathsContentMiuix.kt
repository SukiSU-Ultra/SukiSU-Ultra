package com.sukisu.nova.ui.screen.susfs.content.miuix

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.nova.R
import com.sukisu.nova.ui.screen.susfs.component.miuix.AppPathGroupCardMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.BottomActionButtonsMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.EmptyStateCardMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.PathItemCardMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.ResetButtonMiuix
import com.sukisu.nova.ui.screen.susfs.component.miuix.SectionHeaderMiuix
import com.sukisu.nova.ui.screen.susfs.util.AppInfoCache
import com.sukisu.nova.ui.viewmodel.SuperUserViewModel

@Composable
fun SusPathsContentMiuix(
    susPaths: Set<String>,
    isLoading: Boolean,
    onAddPath: () -> Unit,
    onAddAppPath: () -> Unit,
    onRemovePath: (String) -> Unit,
    onEditPath: ((String) -> Unit)? = null,
    forceRefreshApps: Boolean = false,
    onReset: (() -> Unit)? = null
) {
    var superUserApps by remember { mutableStateOf(SuperUserViewModel.getAppsSafely()) }

    LaunchedEffect(Unit) {
        snapshotFlow { SuperUserViewModel.apps }
            .distinctUntilChanged()
            .collect { _ ->
                superUserApps = SuperUserViewModel.getAppsSafely()
                if (superUserApps.isNotEmpty()) {
                    try {
                        AppInfoCache.clearCache()
                    } catch (_: Exception) {
                    }
                }
            }
    }

    LaunchedEffect(forceRefreshApps) {
        if (forceRefreshApps) {
            try {
                AppInfoCache.clearCache()
            } catch (_: Exception) {
                // Ignore cache clear errors
            }
        }
    }

    val (appPathGroups, otherPaths) = remember(susPaths, superUserApps) {
        val appPathRegex = Regex(".*/Android/data/([^/]+)/?.*")
        val uidPathRegex = Regex("/sys/fs/cgroup(?:/[^/]+)*/uid_([0-9]+)")
        val appPathMap = mutableMapOf<String, MutableList<String>>()
        val uidToPackageMap = mutableMapOf<String, String>()
        val others = mutableListOf<String>()

        // 构建UID到包名的映射
        try {
            superUserApps.forEach { app: SuperUserViewModel.AppInfo ->
                try {
                    val uid = app.packageInfo.applicationInfo?.uid
                    if (uid != null) {
                        uidToPackageMap[uid.toString()] = app.packageName
                    }
                } catch (_: Exception) {
                    // Ignore individual app errors
                }
            }
        } catch (_: Exception) {
            // Ignore mapping errors
        }

        susPaths.forEach { path ->
            val appDataMatch = appPathRegex.find(path)
            val uidMatch = uidPathRegex.find(path)

            when {
                appDataMatch != null -> {
                    val packageName = appDataMatch.groupValues[1]
                    appPathMap.getOrPut(packageName) { mutableListOf() }.add(path)
                }
                uidMatch != null -> {
                    val uid = uidMatch.groupValues[1]
                    val packageName = uidToPackageMap[uid]
                    if (packageName != null) {
                        appPathMap.getOrPut(packageName) { mutableListOf() }.add(path)
                    } else {
                        others.add(path)
                    }
                }
                else -> {
                    others.add(path)
                }
            }
        }

        val sortedAppGroups = appPathMap.toList()
            .sortedBy { it.first }
            .map { (packageName, paths) -> packageName to paths.sorted() }

        Pair(sortedAppGroups, others.sorted())
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 应用路径分组
        if (appPathGroups.isNotEmpty()) {
            SectionHeaderMiuix(
                title = stringResource(R.string.app_paths_section),
                subtitle = null,
                icon = Icons.Default.Apps,
                count = appPathGroups.size
            )

            appPathGroups.forEach { (packageName, paths) ->
                AppPathGroupCardMiuix(
                    packageName = packageName,
                    paths = paths,
                    onDeleteGroup = {
                        paths.forEach { path -> onRemovePath(path) }
                    },
                    onEditGroup = if (onEditPath != null) {
                        {
                            onEditPath(paths.first())
                        }
                    } else null,
                    isLoading = isLoading
                )
            }
        }

        // 其他路径
        if (otherPaths.isNotEmpty()) {
            SectionHeaderMiuix(
                title = stringResource(R.string.other_paths_section),
                subtitle = null,
                icon = Icons.Default.Folder,
                count = otherPaths.size
            )

            otherPaths.forEach { path ->
                PathItemCardMiuix(
                    path = path,
                    icon = Icons.Default.Folder,
                    onDelete = { onRemovePath(path) },
                    onEdit = if (onEditPath != null) {
                        { onEditPath(path) }
                    } else null,
                    isLoading = isLoading
                )
            }
        }

        if (susPaths.isEmpty()) {
            EmptyStateCardMiuix(
                message = stringResource(R.string.susfs_no_paths_configured)
            )
        }
    }

    BottomActionButtonsMiuix(
        primaryButtonText = stringResource(R.string.add_custom_path),
        onPrimaryClick = onAddPath,
        secondaryButtonText = stringResource(R.string.susfs_apply),
        onSecondaryClick = onAddAppPath,
        isLoading = isLoading
    )

    if (onReset != null && susPaths.isNotEmpty()) {
        ResetButtonMiuix(
            title = stringResource(R.string.susfs_reset_paths_title),
            onClick = onReset,
            enabled = !isLoading
        )
    }
}
