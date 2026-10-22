package com.sukisu.ultra.ui.screen.appcontext

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors

@Composable
fun AppContextScreenMaterial(
    state: AppContextUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onTools: () -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    ExpressiveScaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(stringResource(R.string.extension_app_context_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Rounded.ArrowBack, stringResource(R.string.app_context_back))
                    }
                },
                actions = {
                    IconButton(onClick = onTools) {
                        Icon(Icons.Rounded.Build, stringResource(R.string.app_context_tools))
                    }
                    IconButton(onClick = onRefresh, enabled = !state.isLoading) {
                        Icon(Icons.Rounded.Refresh, stringResource(R.string.refresh))
                    }
                },
                colors = expressiveTopAppBarColors(),
                scrollBehavior = scrollBehavior,
                windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = state.isLoading,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                item(key = "description") {
                    Text(
                        text = stringResource(R.string.extension_app_context_summary),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 8.dp),
                    )
                }
                if (state.error != null) {
                    item(key = "error") {
                        Surface(
                            shape = MaterialTheme.shapes.extraLarge,
                            color = MaterialTheme.colorScheme.errorContainer,
                            contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        ) {
                            Column(Modifier.fillMaxWidth().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                                Text(stringResource(state.error), style = MaterialTheme.typography.bodyLarge)
                                FilledTonalButton(onClick = onRefresh, enabled = !state.isLoading) {
                                    Text(stringResource(R.string.refresh))
                                }
                            }
                        }
                    }
                } else if (!state.isLoading && state.contexts.isEmpty()) {
                    item(key = "empty") {
                        Surface(shape = MaterialTheme.shapes.extraLarge, color = MaterialTheme.colorScheme.surfaceContainerLow) {
                            Column(
                                modifier = Modifier.fillMaxWidth().padding(32.dp),
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.spacedBy(16.dp),
                            ) {
                                IconTile(Icons.Rounded.Apps, null)
                                Text(stringResource(R.string.app_context_empty), style = MaterialTheme.typography.titleMedium)
                            }
                        }
                    }
                }
                items(state.contexts, key = { it.uid }) { entry ->
                    AppContextCard(entry)
                }
            }
        }
    }
}

@Composable
private fun AppContextCard(entry: AppContextEntry) {
    SegmentedColumn {
        item(key = "identity") {
            SegmentedListItem(
                leadingContent = { IconTile(Icons.Rounded.Apps, null) },
                headlineContent = {
                    Text(
                        entry.packageName ?: stringResource(R.string.app_context_uid_title, entry.uid),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                },
                supportingContent = {
                    Text(stringResource(R.string.app_context_uid, entry.uid), style = MaterialTheme.typography.bodySmall)
                },
            )
        }
        item(key = "foreground") {
            SegmentedListItem(
                headlineContent = { Text(stringResource(R.string.app_context_foreground)) },
                trailingContent = {
                    Surface(
                        shape = MaterialTheme.shapes.large,
                        color = if (entry.foreground) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerHighest,
                    ) {
                        Text(
                            stringResource(if (entry.foreground) R.string.app_context_yes else R.string.app_context_no),
                            style = MaterialTheme.typography.labelLarge,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        )
                    }
                },
            )
        }
        item(key = "profile") {
            SegmentedListItem(
                headlineContent = { Text(stringResource(R.string.app_context_profile)) },
                supportingContent = { Text(entry.profileId.toString(), style = MaterialTheme.typography.bodyLarge) },
            )
        }
        item(key = "updated") {
            SegmentedListItem(
                headlineContent = { Text(stringResource(R.string.app_context_updated)) },
                supportingContent = { Text(stringResource(R.string.app_context_update_ns, entry.lastUpdateNs)) },
            )
        }
        item(key = "tags") {
            SegmentedListItem(
                headlineContent = { Text(stringResource(R.string.app_context_tags)) },
                supportingContent = {
                    Text(
                        "0x" + entry.tags.toULong().toString(16).padStart(16, '0'),
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = FontFamily.Monospace,
                    )
                },
            )
        }
    }
}
