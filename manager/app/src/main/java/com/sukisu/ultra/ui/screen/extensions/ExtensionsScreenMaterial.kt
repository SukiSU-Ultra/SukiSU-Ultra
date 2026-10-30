package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
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
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.util.CustomTextKey
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.ExpressiveSwitch
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.viewmodel.ExtensionItem
import com.sukisu.ultra.ui.viewmodel.ExtensionsUiState

@Composable
fun ExtensionsScreenMaterial(
    state: ExtensionsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpenDetails: (ExtensionItem) -> Unit,
    onToggle: (ExtensionItem, Boolean) -> Unit,
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
        // Match HomePagerMaterial: keep the system bottom inset out of the
        // scroll viewport and add a trailing spacer instead, so the last card
        // can scroll clear of the navigation bar.
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { padding ->
        if (state.items.isEmpty() && !state.loading) {
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
                content = state.items.map { item ->
                    val extState = item.state
                    val canOpen = extState.supported && item.descriptor.entry !is ExtensionEntry.Generic
                    val onOpen = if (canOpen) {
                        { onOpenDetails(item) }
                    } else null
                    {
                        ExtensionCardMaterial(
                            item = item,
                            busy = item.wireName in state.busy,
                            onOpenDetails = onOpen,
                            onToggle = { enabled -> onToggle(item, enabled) },
                        )
                    }
                },
            )
            Spacer(
                Modifier.height(
                    WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding(),
                ),
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
        title = { Text(customText(CustomTextKey.PAGE_EXTENSIONS)) },
        navigationIcon = {
            TopBarBackButton(onClick = onBack)
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
    item: ExtensionItem,
    busy: Boolean,
    onOpenDetails: (() -> Unit)?,
    onToggle: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val extState = item.state
    val descriptor = item.descriptor
    val title = extensionTitle(item)
    val canToggle = descriptor.entry == ExtensionEntry.Generic && extState.userToggleable

    SegmentedListItem(
        modifier = modifier,
        onClick = onOpenDetails,
        enabled = extState.supported,
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
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                ExtensionStatusRow(item)
                Text(
                    text = extensionDescription(item),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        },
        trailingContent = when {
            canToggle -> {
                {
                    ExpressiveSwitch(
                        checked = extState.value != 0L,
                        onCheckedChange = onToggle,
                        enabled = !busy,
                    )
                }
            }
            onOpenDetails != null -> {
                {
                    Icon(
                        imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                        contentDescription = stringResource(R.string.extension_open_details),
                    )
                }
            }
            else -> null
        },
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
