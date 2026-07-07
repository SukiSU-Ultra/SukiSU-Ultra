package com.sukisu.ultra.ui.screen.settings.tools

import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Backup
import androidx.compose.material.icons.rounded.FolderDelete
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.KsuIsValid
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.util.getSELinuxStatusRaw

@Composable
fun ToolsMaterial(
    state: ToolsUiState,
    actions: ToolsActions,
) {
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tools)) },
                navigationIcon = {
                    TopBarBackButton(onClick = actions.onBack)
                },
                scrollBehavior = scrollBehavior,
                colors = expressiveTopAppBarColors(),
            )
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(horizontal = 16.dp),
            contentPadding = innerPadding,
        ) {
            item {
                KsuIsValid {
                    SelinuxToggleSectionMaterial(
                        selinuxEnforcing = state.selinuxEnforcing,
                        selinuxLoading = state.selinuxLoading,
                        onSelinuxToggle = actions.onSelinuxToggle
                    )

                    SegmentedColumn(
                        modifier = Modifier.padding(top = 12.dp),
                        content = listOf({
                            val umountManager = stringResource(id = R.string.umount_path_manager)
                            SegmentedListItem(
                                onClick = actions.onNavigateToUmountManager,
                                headlineContent = { Text(umountManager) },
                                leadingContent = {
                                    Icon(
                                        Icons.Rounded.FolderDelete,
                                        umountManager,
                                        tint = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            )
                        })
                    )

                    AllowlistBackupSectionMaterial(
                        onBackup = actions.onBackupAllowlist,
                        onRestore = actions.onRestoreAllowlist
                    )
                }
            }
        }
    }
}

@Composable
private fun SelinuxToggleSectionMaterial(
    selinuxEnforcing: Boolean,
    selinuxLoading: Boolean,
    onSelinuxToggle: (Boolean) -> Unit
) {
    SegmentedColumn(
        modifier = Modifier.padding(top = 12.dp),
        content = listOf({
            val statusLabel = getSELinuxStatusRaw()
            SegmentedListItem(
                headlineContent = { Text(stringResource(R.string.tools_selinux_toggle)) },
                supportingContent = { Text(stringResource(R.string.tools_selinux_summary, statusLabel)) },
                leadingContent = {
                    Icon(
                        imageVector = Icons.Rounded.Security,
                        contentDescription = stringResource(id = R.string.tools_selinux_toggle),
                        tint = MaterialTheme.colorScheme.onSurface
                    )
                },
                trailingContent = {
                    Switch(
                        checked = selinuxEnforcing,
                        enabled = !selinuxLoading,
                        onCheckedChange = onSelinuxToggle
                    )
                }
            )
        })
    )
}

@Composable
private fun AllowlistBackupSectionMaterial(
    onBackup: () -> Unit,
    onRestore: () -> Unit
) {
    SegmentedColumn(
        modifier = Modifier.padding(vertical = 12.dp),
        content = listOf(
            {
                SegmentedListItem(
                    headlineContent = { Text(stringResource(R.string.allowlist_backup_title)) },
                    supportingContent = { Text(stringResource(R.string.allowlist_backup_summary_picker)) },
                    leadingContent = {
                        Icon(
                            imageVector = Icons.Rounded.Backup,
                            contentDescription = stringResource(R.string.allowlist_backup_title),
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    },
                    onClick = onBackup
                )
            },
            {
                SegmentedListItem(
                    headlineContent = { Text(stringResource(R.string.allowlist_restore_title)) },
                    supportingContent = { Text(stringResource(R.string.allowlist_restore_summary_picker)) },
                    leadingContent = {
                        Icon(
                            imageVector = Icons.Rounded.Restore,
                            contentDescription = stringResource(R.string.allowlist_restore_title),
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    },
                    onClick = onRestore
                )
            }
        )
    )
}
