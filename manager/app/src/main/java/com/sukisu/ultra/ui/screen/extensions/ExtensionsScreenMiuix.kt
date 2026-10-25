package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.ExtensionId
import com.sukisu.ultra.ui.util.ExtensionState
import com.sukisu.ultra.ui.viewmodel.ExtensionsUiState
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.textStyles
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun ExtensionsScreenMiuix(
    state: ExtensionsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpenDetails: (ExtensionId) -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior()

    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.extension_section_title),
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
            )
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
    ) { padding ->
        if (state.states.isEmpty() && !state.loading) {
            Column(
                modifier = Modifier
                    .fillMaxHeight()
                    .padding(padding)
                    .padding(32.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
            ) {
                Text(
                    text = stringResource(R.string.extension_empty_title),
                    style = textStyles.title3,
                )
                Text(
                    text = stringResource(R.string.extension_empty_subtitle),
                    style = textStyles.body2,
                    color = colorScheme.onBackground.copy(alpha = 0.75f),
                )
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(padding),
            contentPadding = PaddingValues(
                horizontal = 12.dp,
                vertical = 4.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            items(ExtensionId.ALL, key = { it.id }) { ext ->
                val extState = state.states[ext]
                val onOpen = if (extState?.supported == true) {
                    { onOpenDetails(ext) }
                } else null
                ExtensionCardMiuix(
                    id = ext,
                    state = extState,
                    onOpenDetails = onOpen,
                )
            }
        }
    }
}

@Composable
private fun ExtensionCardMiuix(
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
    val labels = ExtensionStatusLabels(
        unsupported = stringResource(R.string.config_status_unsupported),
        forced = stringResource(R.string.extension_status_forced),
        managed = stringResource(R.string.extension_status_managed),
        supported = stringResource(R.string.extension_status_supported),
        enabled = stringResource(R.string.config_status_applied),
        disabled = stringResource(R.string.extension_status_disabled),
    )
    val supported = onOpenDetails != null
    val iconTint = if (supported) {
        colorScheme.onBackground
    } else {
        colorScheme.disabledOnSecondaryVariant
    }

    val statusLabel: String = if (state == null) {
        // State hasn't been observed yet (first frame, refresh in
        // flight). Keep the feature description so the row still
        // tells the user what the extension does.
        featureSummary
    } else labels.forPill(pillFor(state).pill)

    Card(
        modifier = modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        if (supported) {
            ArrowPreference(
                title = title,
                summary = statusLabel,
                startAction = {
                    Icon(
                        imageVector = Icons.Rounded.Memory,
                        contentDescription = null,
                        modifier = Modifier.padding(end = 6.dp),
                        tint = iconTint,
                    )
                },
                onClick = onOpenDetails,
            )
        } else {
            BasicComponent(
                title = title,
                summary = statusLabel,
                enabled = false,
                startAction = {
                    Icon(
                        imageVector = Icons.Rounded.Memory,
                        contentDescription = null,
                        modifier = Modifier.padding(end = 6.dp),
                        tint = iconTint,
                    )
                },
                onClick = null,
            )
        }
    }
}