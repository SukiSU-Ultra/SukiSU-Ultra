package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.util.ExtensionId
import com.sukisu.ultra.ui.util.ExtensionState
import com.sukisu.ultra.ui.viewmodel.ExtensionsUiState

@Composable
fun ExtensionsScreenMaterial(
    state: ExtensionsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpenDetails: (ExtensionId) -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            TopBar(
                onBack = onBack,
                onRefresh = onRefresh,
                scrollBehavior = scrollBehavior,
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
    ) { padding ->
        if (state.states.isEmpty() && !state.loading) {
            EmptyExtensionsHint(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            )
            return@ExpressiveScaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SegmentedColumn(
                modifier = Modifier.padding(bottom = 13.dp),
                content = ExtensionId.ALL.map { ext ->
                    val extState = state.states[ext]
                    val onOpen = if (extState?.supported == true) {
                        { onOpenDetails(ext) }
                    } else null
                    {
                        ExtensionCardMaterial(
                            id = ext,
                            state = extState,
                            onOpenDetails = onOpen,
                        )
                    }
                },
            )
        }
    }
}

@Composable
private fun TopBar(
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    scrollBehavior: TopAppBarScrollBehavior? = null,
) {
    LargeFlexibleTopAppBar(
        title = { Text(stringResource(R.string.extension_section_title)) },
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                    contentDescription = null,
                )
            }
        },
        actions = {
            IconButton(onClick = onRefresh) {
                Icon(
                    imageVector = Icons.Rounded.Refresh,
                    contentDescription = null,
                )
            }
        },
        colors = expressiveTopAppBarColors(),
        windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        scrollBehavior = scrollBehavior,
    )
}

@Composable
private fun ExtensionCardMaterial(
    id: ExtensionId,
    state: ExtensionState?,
    onOpenDetails: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    val title = stringResource(id.displayRes)
    val featureSummary = stringResource(
        when (id) {
            ExtensionId.Kpm -> R.string.extension_kpm_summary
            ExtensionId.CpuSpoof -> R.string.extension_cpu_spoof_summary
            ExtensionId.UmountPaths -> R.string.extension_umount_paths_summary
            ExtensionId.DynamicManager -> R.string.extension_dynamic_manager_summary
            ExtensionId.SuSFS -> R.string.extension_susfs_summary
            ExtensionId.VersionSpoof -> R.string.extension_version_spoof_summary
        }
    )
    val statusSummary: String? = if (state == null) {
        null
    } else {
        when (pillFor(state).pill) {
            ExtensionPill.Unsupported -> stringResource(R.string.config_status_unsupported)
            ExtensionPill.Forced -> stringResource(R.string.extension_status_forced)
            ExtensionPill.Managed -> stringResource(R.string.extension_status_managed)
            ExtensionPill.Supported -> stringResource(R.string.extension_status_supported)
            ExtensionPill.Enabled -> stringResource(R.string.config_status_applied)
            ExtensionPill.Disabled -> stringResource(R.string.extension_status_disabled)
        }
    }
    val supportingText = statusSummary ?: featureSummary
    val canOpen = onOpenDetails != null

    SegmentedListItem(
        modifier = modifier,
        onClick = onOpenDetails,
        enabled = canOpen,
        leadingContent = {
            IconTile(
                icon = Icons.Rounded.Memory,
                contentDescription = title,
            )
        },
        headlineContent = {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
        },
        supportingContent = {
            Text(
                text = supportingText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        trailingContent = if (canOpen) {
            {
                Icon(
                    imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                    contentDescription = stringResource(R.string.extension_open_details),
                )
            }
        } else null,
    )
}

@Composable
private fun EmptyExtensionsHint(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
    ) {
        Text(
            text = stringResource(R.string.extension_empty_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = stringResource(R.string.extension_empty_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}