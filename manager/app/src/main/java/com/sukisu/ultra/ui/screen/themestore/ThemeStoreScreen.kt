package com.sukisu.ultra.ui.screen.themestore

import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.IconButton as MaterialIconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.material3.TopAppBar as MaterialTopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.component.themeimport.ThemeImportDialog
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.util.CustomTextKey
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import java.util.Locale
import kotlin.math.roundToInt

private enum class ThemeStoreSort {
    DEFAULT,
    NEWEST,
    NAME,
    SIZE,
}

private fun List<ThemeStoreItem>.sortedFor(mode: ThemeStoreSort): List<ThemeStoreItem> = when (mode) {
    ThemeStoreSort.DEFAULT -> this
    ThemeStoreSort.NEWEST -> sortedWith(
        compareByDescending<ThemeStoreItem> { it.entry.updatedAt }
            .thenBy { it.entry.name.lowercase(Locale.ROOT) },
    )
    ThemeStoreSort.NAME -> sortedWith(compareBy { it.entry.name.lowercase(Locale.ROOT) })
    ThemeStoreSort.SIZE -> sortedWith(compareByDescending { it.entry.size })
}

@Composable
fun ThemeStoreScreen(
    viewModel: ThemeStoreViewModel = viewModel(),
) {
    val context = LocalContext.current
    val navigator = LocalNavigator.current
    val settingsViewModel = viewModel<SettingsViewModel>()
    val settingsUiState by settingsViewModel.uiState.collectAsStateWithLifecycle()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var showUpload by rememberSaveable { mutableStateOf(false) }
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var sortMode by rememberSaveable { mutableStateOf(ThemeStoreSort.DEFAULT) }
    var selectedItemKey by rememberSaveable { mutableStateOf<String?>(null) }
    val visibleItems = remember(state.items, searchQuery, sortMode) {
        state.items
            .filter { it.matchesSearch(searchQuery) }
            .sortedFor(sortMode)
    }
    val uploadSource = state.sources.firstOrNull { it.isDefault } ?: state.sources.firstOrNull()

    BackHandler(enabled = selectedItemKey != null && state.items.any { it.key == selectedItemKey }) {
        selectedItemKey = null
    }

    LaunchedEffect(state.uploadSubmitted) {
        if (state.uploadSubmitted) {
            Toast.makeText(
                context,
                if (state.uploadAutoApproved) R.string.theme_store_upload_auto_approved
                else R.string.theme_store_upload_success,
                Toast.LENGTH_SHORT,
            ).show()
            showUpload = false
            viewModel.consumeUploadSubmitted()
        }
    }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.load()
    }

    LaunchedEffect(Unit) {
        navigator.observeResult<Boolean>(THEME_SOURCES_RESULT_KEY).collect {
            viewModel.load()
        }
    }

    LaunchedEffect(
        settingsUiState.themeStoreBaseUrl,
        settingsUiState.themeStoreToken,
        settingsUiState.themeStoreAdminUrl,
        settingsUiState.themeStoreExtraSources,
    ) {
        viewModel.load()
    }

    LaunchedEffect(state.downloaded) {
        state.downloaded?.let { downloaded ->
            settingsViewModel.importThemeFile(context, downloaded.file)
            viewModel.consumeDownloaded()
        }
    }

    LaunchedEffect(state.downloadFailed) {
        if (state.downloadFailed) {
            Toast.makeText(context, R.string.theme_store_download_failed, Toast.LENGTH_SHORT).show()
            viewModel.clearDownloadError()
        }
    }

    ThemeImportDialog(
        show = settingsUiState.showThemeImportDialog,
        theme = settingsUiState.pendingImportTheme,
        onDismissRequest = settingsViewModel::dismissImportThemeDialog,
        onConfirm = { options -> settingsViewModel.confirmImportTheme(context, options) },
        forceMaterial = true,
    )

    val detailItem = selectedItemKey?.let { key -> state.items.firstOrNull { it.key == key } }

    BackHandler(enabled = showUpload && detailItem == null) {
        if (!state.submitting) {
            showUpload = false
            viewModel.clearUploadState()
        }
    }

    when {
        detailItem != null -> ThemeStoreDetailScreen(
            item = detailItem,
            state = state,
            onBack = { selectedItemKey = null },
            onDownload = viewModel::download,
            onRefresh = { viewModel.load() },
        )

        showUpload && uploadSource != null -> ThemeStoreUploadScreen(
            source = uploadSource,
            initialAuthor = settingsUiState.themeStoreAuthorName,
            initialAuthorId = settingsUiState.themeStoreAuthorId,
            submitting = state.submitting,
            errorText = state.uploadError,
            onBack = {
                if (!state.submitting) {
                    showUpload = false
                    viewModel.clearUploadState()
                }
            },
            onSubmit = { input ->
                settingsViewModel.setThemeStoreAuthorName(input.author)
                settingsViewModel.setThemeStoreAuthorId(input.authorId)
                viewModel.submit(input, uploadSource)
            },
            onExportCurrentPreset = { settingsViewModel.createCurrentThemePackage(context).getOrNull() },
        )

        else -> ThemeStoreMaterial(
            state = state,
            visibleItems = visibleItems,
            searchQuery = searchQuery,
            onSearchQueryChange = { searchQuery = it },
            sortMode = sortMode,
            onSortChange = { sortMode = it },
            onBack = { navigator.pop() },
            onRefresh = { viewModel.load() },
            onOpenSettings = { navigator.navigateForResult(Route.ThemeStoreSources, THEME_SOURCES_RESULT_KEY) },
            onOpenUpload = {
                viewModel.clearUploadState()
                showUpload = true
            },
            onSelect = { selectedItemKey = it.key },
            onDownload = viewModel::download,
        )
    }
}

@Composable
private fun ThemeStoreSearchMaterial(
    query: String,
    onQueryChange: (String) -> Unit,
) {
    val shape = RoundedCornerShape(28.dp)
    val hasBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val searchContainer = themeStoreSearchColor()
    TextField(
        value = query,
        onValueChange = onQueryChange,
        modifier = Modifier
            .fillMaxWidth()
            .height(58.dp),
        singleLine = true,
        shape = shape,
        textStyle = MaterialTheme.typography.bodyLarge,
        placeholder = {
            MaterialText(
                text = stringResource(R.string.theme_store_search),
                style = MaterialTheme.typography.bodyLarge,
            )
        },
        leadingIcon = {
            MaterialIcon(
                imageVector = Icons.Rounded.Search,
                contentDescription = null,
            )
        },
        trailingIcon = {
            if (query.isNotEmpty()) {
                MaterialIconButton(onClick = { onQueryChange("") }) {
                    MaterialIcon(
                        imageVector = Icons.Rounded.Close,
                        contentDescription = stringResource(R.string.theme_store_clear_search),
                    )
                }
            }
        },
        colors = TextFieldDefaults.colors(
            focusedContainerColor = searchContainer,
            unfocusedContainerColor = searchContainer,
            disabledContainerColor = if (hasBackground) searchContainer.copy(alpha = 0.38f) else searchContainer,
            focusedIndicatorColor = Color.Transparent,
            unfocusedIndicatorColor = Color.Transparent,
            disabledIndicatorColor = Color.Transparent,
            cursorColor = MaterialTheme.colorScheme.primary,
        ),
    )
}

@Composable
private fun ThemeStoreSortRow(
    selected: ThemeStoreSort,
    onSelect: (ThemeStoreSort) -> Unit,
) {
    val options = listOf(
        ThemeStoreSort.DEFAULT to R.string.theme_store_sort_default,
        ThemeStoreSort.NEWEST to R.string.theme_store_sort_newest,
        ThemeStoreSort.NAME to R.string.theme_store_sort_name,
        ThemeStoreSort.SIZE to R.string.theme_store_sort_size,
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        options.forEach { (mode, label) ->
            ThemeSortChip(
                selected = selected == mode,
                onClick = { onSelect(mode) },
                label = stringResource(label),
            )
        }
    }
}

/**
 * Flat, fully opaque sort pill. Deliberately not a Material FilterChip: its translucent
 * container and interaction layers made the label look like it had a shadow over a custom
 * background image.
 */
@Composable
private fun ThemeSortChip(
    selected: Boolean,
    onClick: () -> Unit,
    label: String,
) {
    Surface(
        selected = selected,
        onClick = onClick,
        shape = RoundedCornerShape(50),
        color = if (selected) {
            MaterialTheme.colorScheme.primary
        } else {
            MaterialTheme.colorScheme.surfaceContainerHigh
        },
        contentColor = if (selected) {
            MaterialTheme.colorScheme.onPrimary
        } else {
            MaterialTheme.colorScheme.onSurface
        },
        border = BorderStroke(
            1.dp,
            if (selected) Color.Transparent else MaterialTheme.colorScheme.outlineVariant,
        ),
        shadowElevation = 0.dp,
    ) {
        MaterialText(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
    }
}

@Composable
private fun ThemeStoreSearchEmptyMaterial() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        MaterialText(
            text = stringResource(R.string.theme_store_search_empty),
            style = MaterialTheme.typography.titleMedium,
        )
    }
}

@Composable
private fun ThemeStoreMaterial(
    state: ThemeStoreUiState,
    visibleItems: List<ThemeStoreItem>,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    sortMode: ThemeStoreSort,
    onSortChange: (ThemeStoreSort) -> Unit,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenUpload: () -> Unit,
    onSelect: (ThemeStoreItem) -> Unit,
    onDownload: (ThemeStoreItem) -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                title = { MaterialText(customText(CustomTextKey.PAGE_THEME_STORE)) },
                actions = {
                    MaterialIconButton(
                        onClick = onOpenUpload,
                        enabled = !state.needsConfig && state.sources.isNotEmpty() && !state.submitting,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.FileUpload,
                            contentDescription = stringResource(R.string.theme_store_upload),
                        )
                    }
                    MaterialIconButton(
                        onClick = onOpenSettings,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.Settings,
                            contentDescription = stringResource(R.string.theme_store_settings),
                        )
                    }
                    MaterialIconButton(
                        onClick = onRefresh,
                        enabled = !state.needsConfig && !state.refreshing && !state.loading,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.Refresh,
                            contentDescription = stringResource(R.string.theme_store_refresh),
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
        when {
            state.needsConfig -> ThemeStoreConfigRequiredMaterial(
                onOpenSettings = onOpenSettings,
                modifier = Modifier.padding(paddingValues),
            )

            !state.loaded && !state.needsConfig && !state.error -> Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator()
            }

            state.items.isEmpty() && state.error -> ThemeStoreErrorMaterial(
                unauthorized = state.unauthorized,
                onRetry = onRefresh,
                onOpenSettings = onOpenSettings,
                modifier = Modifier.padding(paddingValues),
            )

            else -> LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 13.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item(key = "search") {
                    ThemeStoreSearchMaterial(
                        query = searchQuery,
                        onQueryChange = onSearchQueryChange,
                    )
                }
                item(key = "sort") {
                    ThemeStoreSortRow(
                        selected = sortMode,
                        onSelect = onSortChange,
                    )
                }
                if (state.refreshing) {
                    item(key = "refreshing") {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                }
                if (state.fromCache) {
                    item(key = "offline") {
                        MaterialText(
                            text = stringResource(R.string.theme_store_offline),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                if (state.failedSources > 0 && state.items.isNotEmpty()) {
                    item(key = "partial-failure") {
                        MaterialText(
                            text = stringResource(R.string.theme_store_partial_failure),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                if (visibleItems.isEmpty()) {
                    item(key = "empty") {
                        if (searchQuery.isBlank()) {
                            ThemeStoreEmptyMaterial(onRefresh = onRefresh, onUpload = onOpenUpload)
                        } else {
                            ThemeStoreSearchEmptyMaterial()
                        }
                    }
                } else {
                    items(visibleItems, key = { it.key }) { item ->
                        ThemeCardMaterial(
                            item = item,
                            state = state,
                            onSelect = onSelect,
                            onDownload = onDownload,
                        )
                    }
                }
                item(key = "bottom-inset") {
                    Spacer(
                        Modifier.height(
                            WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 16.dp,
                        ),
                    )
                }
            }
        }
    }
}

@Composable
private fun ThemeCardMaterial(
    item: ThemeStoreItem,
    state: ThemeStoreUiState,
    onSelect: (ThemeStoreItem) -> Unit,
    onDownload: (ThemeStoreItem) -> Unit,
) {
    val entry = item.entry
    val downloading = state.downloadingKey == item.key
    val date = entry.updatedAt.substringBefore('T').replace('-', '/')
    val byline = buildString {
        if (entry.author.isNotBlank()) {
            append(entry.author)
        }
        if (date.isNotBlank()) {
            if (isNotEmpty()) append(" · ")
            append(date)
        }
    }
    val textShadow = Shadow(
        color = Color.Black.copy(alpha = 0.6f),
        blurRadius = 10f,
    )

    Card(
        onClick = { onSelect(item) },
        modifier = Modifier
            .fillMaxWidth()
            .height(200.dp),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = themeStoreCardColor(),
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 0.dp,
            pressedElevation = 0.dp,
            focusedElevation = 0.dp,
            hoveredElevation = 0.dp,
            draggedElevation = 0.dp,
            disabledElevation = 0.dp,
        ),
        border = BorderStroke(
            1.dp,
            themeStoreCardBorderColor(),
        ),
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            ThemeBannerImage(
                entry = entry,
                baseUrl = item.source.baseUrl,
                token = item.source.token,
                modifier = Modifier.fillMaxSize(),
            )
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        Brush.verticalGradient(
                            0.38f to Color.Transparent,
                            0.7f to Color.Black.copy(alpha = 0.34f),
                            1f to Color.Black.copy(alpha = 0.82f),
                        ),
                    ),
            )
            Row(
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .fillMaxWidth()
                    .padding(start = 16.dp, top = 10.dp, end = 12.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                MaterialText(
                    text = entry.name,
                    style = MaterialTheme.typography.titleMedium.copy(shadow = textShadow),
                    color = Color.White,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (byline.isNotBlank()) {
                    MaterialText(
                        text = byline,
                        style = MaterialTheme.typography.labelSmall.copy(shadow = textShadow),
                        color = Color.White.copy(alpha = 0.9f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.widthIn(max = 140.dp),
                    )
                }
                Button(
                    onClick = { onDownload(item) },
                    enabled = state.downloadingKey == null,
                    shape = RoundedCornerShape(99.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.White.copy(alpha = 0.22f),
                        contentColor = Color.White,
                        disabledContainerColor = Color.White.copy(alpha = 0.12f),
                        disabledContentColor = Color.White.copy(alpha = 0.5f),
                    ),
                    border = BorderStroke(1.dp, Color.White.copy(alpha = 0.32f)),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 0.dp),
                    modifier = Modifier.height(40.dp),
                ) {
                    if (downloading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = Color.White,
                        )
                        Spacer(Modifier.size(6.dp))
                        MaterialText(stringResource(R.string.theme_store_downloading_short))
                    } else {
                        MaterialIcon(
                            imageVector = Icons.Rounded.FileDownload,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.size(6.dp))
                        MaterialText(stringResource(R.string.theme_store_download))
                    }
                }
            }
        }
    }
}

@Composable
private fun ThemeStoreEmptyMaterial(onRefresh: () -> Unit, onUpload: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        MaterialIcon(
            imageVector = Icons.Rounded.Palette,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(40.dp),
        )
        MaterialText(
            text = stringResource(R.string.theme_store_empty_title),
            style = MaterialTheme.typography.titleMedium,
        )
        MaterialText(
            text = stringResource(R.string.theme_store_empty_summary),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(onClick = onUpload) {
            MaterialText(stringResource(R.string.theme_store_upload))
        }
        MaterialTextButton(onClick = onRefresh) {
            MaterialText(stringResource(R.string.theme_store_refresh))
        }
    }
}

@Composable
private fun ThemeStoreConfigRequiredMaterial(
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        MaterialIcon(
            imageVector = Icons.Rounded.Settings,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(40.dp),
        )
        Spacer(Modifier.height(8.dp))
        MaterialText(
            text = stringResource(R.string.theme_store_config_required),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.height(4.dp))
        MaterialText(
            text = stringResource(R.string.theme_store_config_required_summary),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        MaterialTextButton(onClick = onOpenSettings) {
            MaterialText(stringResource(R.string.theme_store_settings))
        }
    }
}

@Composable
private fun ThemeStoreErrorMaterial(
    unauthorized: Boolean,
    onRetry: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        MaterialText(
            text = stringResource(
                if (unauthorized) R.string.theme_store_unauthorized
                else R.string.theme_store_load_failed,
            ),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.height(8.dp))
        MaterialTextButton(onClick = onOpenSettings) {
            MaterialText(stringResource(R.string.theme_store_settings))
        }
        MaterialTextButton(onClick = onRetry) {
            MaterialText(stringResource(R.string.theme_store_retry))
        }
    }
}
