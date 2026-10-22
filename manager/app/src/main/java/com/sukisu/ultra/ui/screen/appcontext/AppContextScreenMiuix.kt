package com.sukisu.ultra.ui.screen.appcontext

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import top.yukonga.miuix.kmp.basic.PullToRefresh
import top.yukonga.miuix.kmp.basic.rememberPullToRefreshState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import com.sukisu.ultra.R
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.CardDefaults
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Build
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun AppContextScreenMiuix(
    state: AppContextUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onTools: () -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior()

    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.extension_app_context_title),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(imageVector = Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = stringResource(R.string.app_context_back))
                    }
                },
                actions = {
                    // Miuix actions is a Box slot, unlike Material's RowScope.
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = onTools) {
                            Icon(Icons.Rounded.Build, stringResource(R.string.app_context_tools))
                        }
                        IconButton(onClick = onRefresh, enabled = !state.isLoading) {
                            Icon(Icons.Rounded.Refresh, stringResource(R.string.refresh))
                        }
                    }
                }
            )
        }
    ) { paddingValues ->
        PullToRefresh(
            isRefreshing = state.isLoading,
            pullToRefreshState = rememberPullToRefreshState(),
            onRefresh = onRefresh,
            refreshTexts = listOf(
                stringResource(R.string.refresh_pulling),
                stringResource(R.string.refresh_release),
                stringResource(R.string.refresh_refresh),
                stringResource(R.string.refresh_complete),
            ),
            contentPadding = paddingValues,
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(paddingValues)
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                item(key = "description") {
                    Text(
                        stringResource(R.string.extension_app_context_summary),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    )
                }
                if (state.error != null) {
                    item(key = "error") {
                        Text(stringResource(state.error), color = MiuixTheme.colorScheme.error)
                    }
                } else if (!state.isLoading && state.contexts.isEmpty()) {
                    item(key = "empty") {
                        Text(stringResource(R.string.app_context_empty))
                    }
                }
                items(state.contexts, key = { it.uid }) { entry ->
                    AppContextCardMiuix(entry)
                }
            }
        }
    }
}

@Composable
fun AppContextCardMiuix(entry: AppContextEntry) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        insideMargin = PaddingValues(0.dp),
        colors = CardDefaults.defaultColors(
            color = if (entry.foreground) {
                MiuixTheme.colorScheme.primaryContainer
            } else {
                MiuixTheme.colorScheme.surfaceVariant
            },
        )
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = entry.packageName ?: stringResource(R.string.app_context_uid_title, entry.uid),
                    style = MiuixTheme.textStyles.title3,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = stringResource(R.string.app_context_uid, entry.uid),
                    style = MiuixTheme.textStyles.body2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            AppContextFieldMiuix(
                label = stringResource(R.string.app_context_foreground),
                value = stringResource(if (entry.foreground) R.string.app_context_yes else R.string.app_context_no),
            )
            AppContextFieldMiuix(
                label = stringResource(R.string.app_context_profile),
                value = entry.profileId.toString(),
            )
            AppContextFieldMiuix(
                label = stringResource(R.string.app_context_updated),
                value = stringResource(R.string.app_context_update_ns, entry.lastUpdateNs),
            )
            AppContextFieldMiuix(
                label = stringResource(R.string.app_context_tags),
                value = "0x" + entry.tags.toULong().toString(16).padStart(16, '0'),
                monospace = true,
            )
        }
    }
}

@Composable
private fun AppContextFieldMiuix(label: String, value: String, monospace: Boolean = false) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = label,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        Text(
            text = value,
            style = MiuixTheme.textStyles.body1,
            fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
        )
    }
}
