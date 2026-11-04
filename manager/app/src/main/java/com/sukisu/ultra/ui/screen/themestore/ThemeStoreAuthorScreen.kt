package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.ViewCarousel
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.sukisu.ultra.R
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors

/**
 * Shows every catalog theme from one author, aggregated across configured sources.
 */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
internal fun ThemeStoreAuthorScreen(
    author: String,
    items: List<ThemeStoreItem>,
    state: ThemeStoreUiState,
    gridLayout: Boolean,
    onToggleLayout: () -> Unit,
    landscapePreviewKeys: MutableMap<String, Boolean>,
    onBack: () -> Unit,
    onSelect: (ThemeStoreItem) -> Unit,
    onDownload: (ThemeStoreItem) -> Unit,
    onRefresh: () -> Unit,
    onOpenSettings: () -> Unit,
    followedAuthorKeys: Set<String> = emptySet(),
    onToggleFollow: (ThemeStoreItem) -> Unit = {},
) {
    val context = LocalContext.current
    var menuExpanded by remember { mutableStateOf(false) }
    val avatarItem = remember(items) {
        items.firstOrNull { it.entry.avatarPath.isNotBlank() }
    }
    // Only annotate cards when the same author name was aggregated from multiple mirrors.
    val multipleSources = remember(items) {
        items.map { it.source.baseUrl }.distinct().size > 1
    }
    // Following is per mirror and author identity; hide the action when this page mixes mirrors.
    val followItem = remember(items, multipleSources) {
        if (multipleSources) null else items.firstOrNull { it.entry.authorHash.isNotBlank() }
    }
    val following = followItem != null && followItem.followKey() in followedAuthorKeys
    val avatarUrl = remember(avatarItem) {
        avatarItem?.let { item ->
            ThemeStoreRepository.assetUrl(item.source.baseUrl, item.entry.avatarPath)
        }
    }
    val avatarToken = avatarItem?.source?.token.orEmpty()
    val pageContainer = MaterialTheme.colorScheme.surface

    ExpressiveScaffold(
        containerColor = pageContainer,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = author,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                subtitle = {
                    Text(stringResource(R.string.theme_store_author_themes, items.size))
                },
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                actions = {
                    IconButton(
                        onClick = onToggleLayout,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        Icon(
                            imageVector = if (gridLayout) Icons.Rounded.ViewCarousel else Icons.Rounded.Apps,
                            contentDescription = stringResource(
                                if (gridLayout) {
                                    R.string.theme_store_layout_switch_to_list
                                } else {
                                    R.string.theme_store_layout_switch_to_grid
                                },
                            ),
                        )
                    }
                    Box {
                        IconButton(
                            onClick = { menuExpanded = true },
                            colors = themeStoreTopBarIconColors(),
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.MoreVert,
                                contentDescription = stringResource(R.string.theme_store_more),
                            )
                        }
                        DropdownMenu(
                            expanded = menuExpanded,
                            onDismissRequest = { menuExpanded = false },
                            shape = MaterialTheme.shapes.large,
                            containerColor = MaterialTheme.colorScheme.surfaceContainer,
                            tonalElevation = 0.dp,
                            shadowElevation = 3.dp,
                            border = BorderStroke(
                                1.dp,
                                MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                            ),
                        ) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.theme_store_refresh)) },
                                leadingIcon = {
                                    Icon(
                                        imageVector = Icons.Rounded.Refresh,
                                        contentDescription = null,
                                    )
                                },
                                enabled = !state.loading && !state.refreshing,
                                onClick = {
                                    menuExpanded = false
                                    onRefresh()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.theme_store_sources)) },
                                leadingIcon = {
                                    Icon(
                                        imageVector = Icons.Rounded.Settings,
                                        contentDescription = null,
                                    )
                                },
                                onClick = {
                                    menuExpanded = false
                                    onOpenSettings()
                                },
                            )
                        }
                    }
                },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { paddingValues ->
        LazyVerticalGrid(
            columns = GridCells.Fixed(if (gridLayout) 2 else 1),
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 13.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "author-header", span = { GridItemSpan(maxLineSpan) }) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                    ),
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(56.dp)
                                .clip(CircleShape)
                                .background(MaterialTheme.colorScheme.surfaceContainerHigh),
                            contentAlignment = Alignment.Center,
                        ) {
                            androidx.compose.material3.Icon(
                                imageVector = Icons.Rounded.Person,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(30.dp),
                            )
                            if (avatarUrl != null) {
                                AsyncImage(
                                    model = themeImageRequest(context, avatarUrl, avatarToken),
                                    contentDescription = author,
                                    contentScale = ContentScale.Crop,
                                    modifier = Modifier.fillMaxSize(),
                                )
                            }
                        }
                        Spacer(Modifier.width(14.dp))
                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Text(
                                text = author,
                                style = MaterialTheme.typography.titleLarge,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(R.string.theme_store_author_themes, items.size),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        followItem?.let { item ->
                            if (following) {
                                OutlinedButton(
                                    onClick = { onToggleFollow(item) },
                                    shapes = ButtonDefaults.shapes(),
                                ) {
                                    Text(stringResource(R.string.theme_store_following))
                                }
                            } else {
                                FilledTonalButton(
                                    onClick = { onToggleFollow(item) },
                                    shapes = ButtonDefaults.shapes(),
                                ) {
                                    Text(stringResource(R.string.theme_store_follow))
                                }
                            }
                        }
                    }
                }
            }
            if (items.isEmpty()) {
                item(key = "empty", span = { GridItemSpan(maxLineSpan) }) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 40.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = stringResource(R.string.theme_store_author_empty),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            } else {
                items(
                    items = items,
                    key = { it.key },
                    span = { item ->
                        if (gridLayout && landscapePreviewKeys[item.key] == true) {
                            GridItemSpan(maxLineSpan)
                        } else {
                            GridItemSpan(1)
                        }
                    },
                ) { item ->
                    val cardModifier = Modifier.animateItem(
                        fadeInSpec = MaterialTheme.motionScheme.defaultEffectsSpec(),
                        placementSpec = MaterialTheme.motionScheme.defaultSpatialSpec(),
                        fadeOutSpec = MaterialTheme.motionScheme.fastEffectsSpec(),
                    )
                    val sourceLabel = if (multipleSources) item.source.displayName() else null
                    if (gridLayout) {
                        ThemeGridCardMaterial(
                            item = item,
                            state = state,
                            onSelect = onSelect,
                            onDownload = onDownload,
                            sourceLabel = sourceLabel,
                            modifier = cardModifier,
                            onLandscapePreviewChange = { isLandscape ->
                                if (landscapePreviewKeys[item.key] != isLandscape) {
                                    landscapePreviewKeys[item.key] = isLandscape
                                }
                            },
                        )
                    } else {
                        ThemeCardMaterial(
                            item = item,
                            state = state,
                            onSelect = onSelect,
                            onDownload = onDownload,
                            sourceLabel = sourceLabel,
                            modifier = cardModifier,
                        )
                    }
                }
            }
            item(key = "bottom-inset", span = { GridItemSpan(maxLineSpan) }) {
                Spacer(
                    Modifier.height(
                        WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 24.dp,
                    ),
                )
            }
        }
    }
}
