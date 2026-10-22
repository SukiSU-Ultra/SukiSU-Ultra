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
                    IconButton(onClick = onTools) {
                        Icon(Icons.Rounded.Build, stringResource(R.string.app_context_tools))
                    }
                    IconButton(onClick = onRefresh, enabled = !state.isLoading) {
                        Icon(imageVector = Icons.Rounded.Refresh, contentDescription = stringResource(R.string.refresh))
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
                    Text(stringResource(R.string.extension_app_context_summary))
                }
                if (state.isLoading && state.contexts.isEmpty()) {
                    item(key = "loading") {
                        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                            top.yukonga.miuix.kmp.basic.CircularProgressIndicator()
                        }
                    }
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
        colors = CardDefaults.defaultColors(
            color = if (entry.foreground) {
                MiuixTheme.colorScheme.primaryContainer
            } else {
                MiuixTheme.colorScheme.surfaceVariant
            },
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Text(
                text = entry.packageName ?: stringResource(R.string.app_context_uid_title, entry.uid),
                style = MiuixTheme.textStyles.title3
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.app_context_uid, entry.uid),
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurfaceVariantActions
            )
            Text(
                text = stringResource(R.string.app_context_updated) + ": " +
                    stringResource(R.string.app_context_update_ns, entry.lastUpdateNs),
                style = MiuixTheme.textStyles.body2,
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text(
                        text = stringResource(R.string.app_context_foreground),
                        style = MiuixTheme.textStyles.body2
                    )
                    Text(
                        text = stringResource(if (entry.foreground) R.string.app_context_yes else R.string.app_context_no),
                        style = MiuixTheme.textStyles.body1
                    )
                }
                Column {
                    Text(
                        text = stringResource(R.string.app_context_profile),
                        style = MiuixTheme.textStyles.body2
                    )
                    Text(
                        text = entry.profileId.toString(),
                        style = MiuixTheme.textStyles.body1
                    )
                }
                Column {
                    Text(
                        text = stringResource(R.string.app_context_tags),
                        style = MiuixTheme.textStyles.body2
                    )
                    Text(
                        text = "0x" + entry.tags.toULong().toString(16).padStart(16, '0'),
                        style = MiuixTheme.textStyles.body1
                    )
                }
            }
        }
    }
}
