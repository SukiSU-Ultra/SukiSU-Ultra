package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.rememberAsyncImagePainter
import com.sukisu.ultra.R
import com.sukisu.ultra.data.repository.ThemeStoreHistoryEntry
import com.sukisu.ultra.data.repository.ThemeStoreHistoryKind
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.ExpressiveTabRow
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
internal fun ThemeStoreHistoryScreen(
    viewedHistory: List<ThemeStoreHistoryEntry>,
    downloadedHistory: List<ThemeStoreHistoryEntry>,
    sources: List<ThemeStoreSource>,
    loading: Boolean,
    error: String?,
    loginRequired: Boolean,
    onBack: () -> Unit,
    onOpen: (ThemeStoreHistoryEntry) -> Unit,
    onClear: (ThemeStoreHistoryKind) -> Unit,
    onDelete: (ThemeStoreHistoryKind, Set<String>) -> Unit,
    onLogin: () -> Unit,
    onRefresh: () -> Unit,
) {
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var selecting by rememberSaveable { mutableStateOf(false) }
    var selected by rememberSaveable(
        stateSaver = listSaver(
            save = { it.toList() },
            restore = { it.toSet() },
        ),
    ) { mutableStateOf(emptySet<String>()) }
    var confirmClear by remember { mutableStateOf(false) }
    val kind = if (tab == 0) ThemeStoreHistoryKind.VIEWED else ThemeStoreHistoryKind.DOWNLOADED
    val current = if (tab == 0) viewedHistory else downloadedHistory
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    LaunchedEffect(tab) {
        selecting = false
        selected = emptySet()
    }
    LaunchedEffect(current) {
        val available = current.map { it.key }.toSet()
        if (!available.containsAll(selected)) selected = selected.intersect(available)
    }

    ExpressiveScaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(stringResource(R.string.theme_store_history_title)) },
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                actions = {
                    IconButton(
                        onClick = onRefresh,
                        enabled = !loading,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Refresh,
                            contentDescription = stringResource(R.string.theme_store_upload_refresh),
                        )
                    }
                    IconButton(
                        onClick = {
                            selecting = !selecting
                            if (!selecting) selected = emptySet()
                        },
                        enabled = !loginRequired,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        Icon(
                            imageVector = if (selecting) Icons.Rounded.Close else Icons.Rounded.Check,
                            contentDescription = stringResource(
                                if (selecting) R.string.theme_store_history_cancel_selection
                                else R.string.theme_store_history_select,
                            ),
                        )
                    }
                    IconButton(
                        onClick = { confirmClear = true },
                        enabled = current.isNotEmpty(),
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.DeleteSweep,
                            contentDescription = stringResource(R.string.theme_store_history_clear_all),
                        )
                    }
                },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
                scrollBehavior = scrollBehavior,
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
        ) {
            ExpressiveTabRow(
                selectedTabIndex = tab,
                tabs = listOf(
                    stringResource(R.string.theme_store_history_viewed),
                    stringResource(R.string.theme_store_history_downloaded),
                ),
                onTabClick = { tab = it },
            )
            if (selecting && !loginRequired) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    TextButton(
                        onClick = {
                            selected = if (selected.size == current.size) {
                                emptySet()
                            } else {
                                current.map { it.key }.toSet()
                            }
                        },
                        shapes = ButtonDefaults.shapes(),
                    ) {
                        Text(
                            stringResource(
                                if (current.isNotEmpty() && selected.size == current.size) {
                                    R.string.theme_store_history_select_none
                                } else {
                                    R.string.theme_store_history_select_all
                                },
                            ),
                        )
                    }
                    Spacer(Modifier.weight(1f))
                    FilledTonalButton(
                        onClick = {
                            onDelete(kind, selected)
                            selected = emptySet()
                            selecting = false
                        },
                        enabled = selected.isNotEmpty(),
                        shapes = ButtonDefaults.shapes(),
                    ) {
                        Text(stringResource(R.string.theme_store_history_delete_selected, selected.size))
                    }
                }
            }
            when {
                loginRequired -> HistoryLogin(Modifier.weight(1f), onLogin = onLogin)

                loading && current.isEmpty() -> Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularWavyProgressIndicator(modifier = Modifier.size(24.dp))
                }

                current.isEmpty() -> Column(modifier = Modifier.weight(1f)) {
                    HistoryError(error)
                    HistoryEmpty(kind, Modifier.weight(1f))
                }

                else -> Column(modifier = Modifier.weight(1f)) {
                    HistoryError(error)
                    LazyColumn(
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(
                            start = 20.dp,
                            end = 20.dp,
                            top = 8.dp,
                            bottom = 36.dp,
                        ),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(current, key = { it.key }) { entry ->
                            HistoryCard(
                                entry = entry,
                                source = sources.firstOrNull {
                                    it.id == entry.sourceId || it.baseUrl == entry.baseUrl
                                },
                                selecting = selecting,
                                checked = entry.key in selected,
                                onToggle = {
                                    selected = if (entry.key in selected) {
                                        selected - entry.key
                                    } else {
                                        selected + entry.key
                                    }
                                },
                                onClick = {
                                    if (selecting) {
                                        selected = if (entry.key in selected) {
                                            selected - entry.key
                                        } else {
                                            selected + entry.key
                                        }
                                    } else {
                                        onOpen(entry)
                                    }
                                },
                            )
                        }
                    }
                }
            }
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            shape = MaterialTheme.shapes.extraLarge,
            title = { Text(stringResource(R.string.theme_store_history_clear_title)) },
            text = {
                Text(
                    stringResource(
                        if (kind == ThemeStoreHistoryKind.VIEWED) {
                            R.string.theme_store_history_clear_viewed_message
                        } else {
                            R.string.theme_store_history_clear_downloaded_message
                        },
                    ),
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmClear = false
                        onClear(kind)
                        selected = emptySet()
                        selecting = false
                    },
                    shapes = ButtonDefaults.shapes(),
                ) {
                    Text(stringResource(R.string.theme_store_history_clear_all))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { confirmClear = false },
                    shapes = ButtonDefaults.shapes(),
                ) {
                    Text(stringResource(R.string.theme_store_upload_cancel))
                }
            },
        )
    }
}

@Composable
private fun HistoryCard(
    entry: ThemeStoreHistoryEntry,
    source: ThemeStoreSource?,
    selecting: Boolean,
    checked: Boolean,
    onToggle: () -> Unit,
    onClick: () -> Unit,
) {
    val context = LocalContext.current
    val imageUrl = source
        ?.takeIf { entry.previewPath.isNotBlank() }
        ?.let { ThemeStoreRepository.assetUrl(it.baseUrl, entry.previewPath) }
    val painter = if (imageUrl != null) {
        rememberAsyncImagePainter(
            themeImageRequest(context, imageUrl, source.token),
        )
    } else {
        null
    }
    val date = remember(entry.createdAt) {
        SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(entry.createdAt))
    }
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(
            containerColor = themeStoreCardColor(),
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = androidx.compose.foundation.BorderStroke(
            1.dp,
            themeStoreCardBorderColor(),
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (selecting) {
                Checkbox(
                    checked = checked,
                    onCheckedChange = { onToggle() },
                )
            }
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .clip(MaterialTheme.shapes.medium),
                contentAlignment = Alignment.Center,
            ) {
                if (painter != null) {
                    androidx.compose.foundation.Image(
                        painter = painter,
                        contentDescription = null,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.fillMaxSize(),
                    )
                } else {
                    Icon(
                        imageVector = Icons.Rounded.History,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.name.ifBlank { entry.themeId },
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    text = listOf(entry.author, date)
                        .filter { it.isNotBlank() }
                        .joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (entry.r18) {
                ThemeR18Badge()
            }
        }
    }
}

@Composable
private fun HistoryError(error: String?) {
    error?.takeIf { it.isNotBlank() }?.let { message ->
        Text(
            text = message,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp),
        )
    }
}

@Composable
private fun HistoryLogin(modifier: Modifier = Modifier, onLogin: () -> Unit) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.surfaceContainerLow,
            contentColor = MaterialTheme.colorScheme.onSurface,
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.History,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(40.dp),
                )
                Text(
                    text = stringResource(R.string.theme_store_history_login_required),
                    style = MaterialTheme.typography.titleMedium,
                )
                Button(
                    onClick = onLogin,
                    modifier = Modifier.fillMaxWidth(),
                    shapes = ButtonDefaults.shapes(),
                ) {
                    Text(stringResource(R.string.account_login))
                }
            }
        }
    }
}

@Composable
private fun HistoryEmpty(kind: ThemeStoreHistoryKind, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            imageVector = Icons.Rounded.History,
            contentDescription = null,
            modifier = Modifier.size(44.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(
                if (kind == ThemeStoreHistoryKind.VIEWED) {
                    R.string.theme_store_history_empty_viewed
                } else {
                    R.string.theme_store_history_empty_downloaded
                },
            ),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
