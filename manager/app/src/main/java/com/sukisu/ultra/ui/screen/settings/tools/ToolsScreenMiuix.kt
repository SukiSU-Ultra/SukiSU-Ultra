package com.sukisu.ultra.ui.screen.settings.tools

import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Backup
import androidx.compose.material.icons.rounded.FolderDelete
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.Security
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.KsuIsValid
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.getSELinuxStatusRaw
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun ToolsMiuix(
    state: ToolsUiState,
    actions: ToolsActions
) {
    val scrollBehavior = MiuixScrollBehavior()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive) Color.Transparent else colorScheme.surface

    Scaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    color = barColor,
                    title = stringResource(R.string.tools),
                    scrollBehavior = scrollBehavior,
                    navigationIcon = {
                        IconButton(onClick = { /* handled in navigator */ }) {
                            val layoutDirection = LocalLayoutDirection.current
                            Icon(
                                modifier = Modifier.graphicsLayer {
                                    if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                                },
                                imageVector = MiuixIcons.Back,
                                contentDescription = null
                            )
                        }
                    }
                )
            }
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(horizontal = 12.dp),
            contentPadding = innerPadding,
            overscrollEffect = null,
        ) {
            item {
                KsuIsValid {
                    SelinuxToggleSectionMiuix(
                        selinuxEnforcing = state.selinuxEnforcing,
                        selinuxLoading = state.selinuxLoading,
                        onSelinuxToggle = actions.onSelinuxToggle
                    )

                    Card(
                        modifier = Modifier
                            .padding(top = 12.dp)
                            .fillMaxWidth(),
                    ) {
                        val umountManager = stringResource(id = R.string.umount_path_manager)
                        ArrowPreference(
                            title = umountManager,
                            startAction = {
                                Icon(
                                    Icons.Rounded.FolderDelete,
                                    modifier = Modifier.padding(end = 6.dp),
                                    contentDescription = umountManager,
                                    tint = colorScheme.onBackground
                                )
                            },
                            onClick = actions.onNavigateToUmountManager
                        )
                    }

                    AllowlistBackupSectionMiuix(
                        onBackup = actions.onBackupAllowlist,
                        onRestore = actions.onRestoreAllowlist
                    )
                }
            }
        }
    }
}

@Composable
private fun SelinuxToggleSectionMiuix(
    selinuxEnforcing: Boolean,
    selinuxLoading: Boolean,
    onSelinuxToggle: (Boolean) -> Unit
) {
    Card(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        val statusLabel = getSELinuxStatusRaw()
        SwitchPreference(
            title = stringResource(R.string.tools_selinux_toggle),
            summary = stringResource(R.string.tools_selinux_summary, statusLabel),
            startAction = {
                Icon(
                    imageVector = Icons.Rounded.Security,
                    modifier = Modifier.padding(end = 6.dp),
                    contentDescription = stringResource(id = R.string.tools_selinux_toggle),
                    tint = colorScheme.onBackground
                )
            },
            checked = selinuxEnforcing,
            enabled = !selinuxLoading,
            onCheckedChange = onSelinuxToggle
        )
    }
}

@Composable
private fun AllowlistBackupSectionMiuix(
    onBackup: () -> Unit,
    onRestore: () -> Unit
) {
    Card(
        modifier = Modifier
            .padding(vertical = 12.dp)
            .fillMaxWidth(),
    ) {
        ArrowPreference(
            title = stringResource(R.string.allowlist_backup_title),
            summary = stringResource(R.string.allowlist_backup_summary_picker),
            startAction = {
                Icon(
                    imageVector = Icons.Rounded.Backup,
                    modifier = Modifier.padding(end = 6.dp),
                    contentDescription = stringResource(R.string.allowlist_backup_title),
                    tint = colorScheme.onBackground
                )
            },
            onClick = onBackup
        )

        ArrowPreference(
            title = stringResource(R.string.allowlist_restore_title),
            summary = stringResource(R.string.allowlist_restore_summary_picker),
            startAction = {
                Icon(
                    imageVector = Icons.Rounded.Restore,
                    modifier = Modifier.padding(end = 6.dp),
                    contentDescription = stringResource(R.string.allowlist_restore_title),
                    tint = colorScheme.onBackground
                )
            },
            onClick = onRestore
        )
    }
}
