package com.sukisu.ultra.ui.screen.themestore

import android.annotation.SuppressLint
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountCircle
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.InstallMobile
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.ContainedLoadingIndicator
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SmallExtendedFloatingActionButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.PullToRefreshDefaults
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
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
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
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
import com.sukisu.ultra.ui.util.ThemePackageStorage
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import java.util.Locale
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.IconButton as MaterialIconButton
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton

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

@SuppressLint("LocalContextGetResourceValueCall")
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
    var showSubmissions by rememberSaveable { mutableStateOf(false) }
    var showAccountPicker by rememberSaveable { mutableStateOf(false) }
    var selectedUploadBaseUrl by rememberSaveable { mutableStateOf<String?>(null) }
    var editingThemeId by rememberSaveable { mutableStateOf<String?>(null) }
    var editingThemeBaseUrl by rememberSaveable { mutableStateOf<String?>(null) }
    var returnToSubmissions by rememberSaveable { mutableStateOf(false) }
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var sortMode by rememberSaveable { mutableStateOf(ThemeStoreSort.DEFAULT) }
    var selectedItemKey by rememberSaveable { mutableStateOf<String?>(null) }
    val visibleItems = remember(state.items, searchQuery, sortMode) {
        state.items
            .filter { it.matchesSearch(searchQuery) }
            .sortedFor(sortMode)
    }
    val uploadAccount = state.accounts.firstOrNull {
        it.source.baseUrl == selectedUploadBaseUrl
    }
    val uploadSource = uploadAccount?.source
    val editingTheme = editingThemeId?.let { id ->
        state.userThemes.firstOrNull {
            it.theme.id == id && it.account.source.baseUrl == editingThemeBaseUrl
        }?.theme
    }
    val installPackagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri?.let { settingsViewModel.importTheme(context, it) }
    }

    fun openUpload(account: ThemeStoreAccount) {
        showSubmissions = false
        editingThemeId = null
        editingThemeBaseUrl = null
        selectedUploadBaseUrl = account.source.baseUrl
        returnToSubmissions = false
        viewModel.clearUploadState()
        showUpload = true
    }

    BackHandler(enabled = selectedItemKey != null && state.items.any { it.key == selectedItemKey }) {
        selectedItemKey = null
    }

    LaunchedEffect(showUpload, selectedUploadBaseUrl) {
        val baseUrl = selectedUploadBaseUrl
        if (showUpload && baseUrl != null) viewModel.loadUploadOptions(baseUrl)
    }

    LaunchedEffect(showSubmissions) {
        if (showSubmissions) viewModel.loadUserContent()
    }

    LaunchedEffect(state.uploadSubmitted) {
        if (state.uploadSubmitted) {
            val message = state.uploadedThemeId?.let {
                context.getString(R.string.theme_store_upload_submitted_id, it)
            } ?: if (state.uploadAutoApproved) {
                context.getString(R.string.theme_store_upload_auto_approved)
            } else {
                context.getString(R.string.theme_store_upload_success)
            }
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            viewModel.consumeUploadSubmitted()
        }
    }

    LaunchedEffect(Unit) {
        navigator.observeResult<Boolean>(THEME_SOURCES_RESULT_KEY).collect {
            viewModel.load()
        }
    }

    LaunchedEffect(state.downloaded) {
        state.downloaded?.let { downloaded ->
            // Consume first: the trial now runs in the settings view model, so a rotation
            // must not replay this effect with an already-deleted package file.
            viewModel.consumeDownloaded()
            if (downloaded.trial) {
                settingsViewModel.startThemeTrial(context, downloaded.file)
            } else {
                settingsViewModel.importThemeFile(context, downloaded.file)
            }
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

    if (showAccountPicker) {
        AlertDialog(
            onDismissRequest = { showAccountPicker = false },
            shape = MaterialTheme.shapes.extraLarge,
            title = {
                MaterialText(stringResource(R.string.theme_store_upload_select_account))
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    MaterialText(
                        stringResource(R.string.theme_store_upload_select_account_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    state.accounts.forEach { account ->
                        MaterialTextButton(
                            onClick = {
                                showAccountPicker = false
                                viewModel.setUploadSourcePreference(account.source.baseUrl)
                                openUpload(account)
                            },
                            modifier = Modifier.fillMaxWidth(),
                            shapes = ButtonDefaults.shapes(),
                        ) {
                            Column(
                                modifier = Modifier.weight(1f),
                                horizontalAlignment = Alignment.Start,
                            ) {
                                MaterialText(
                                    account.source.displayName(),
                                    style = MaterialTheme.typography.bodyLarge,
                                )
                                MaterialText(
                                    "@${account.session.user.username}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                MaterialTextButton(
                    onClick = {
                        showAccountPicker = false
                        navigator.navigateTo(Route.ThemeAccount())
                    },
                    shapes = ButtonDefaults.shapes(),
                ) {
                    MaterialText(stringResource(R.string.theme_store_upload_manage_accounts))
                }
            },
            dismissButton = {
                MaterialTextButton(
                    onClick = { showAccountPicker = false },
                    shapes = ButtonDefaults.shapes(),
                ) {
                    MaterialText(stringResource(R.string.theme_store_upload_cancel))
                }
            },
        )
    }

    val detailItem = selectedItemKey?.let { key -> state.items.firstOrNull { it.key == key } }

    BackHandler(enabled = showUpload && detailItem == null) {
        if (!state.submitting) {
            showUpload = false
            editingThemeId = null
            showSubmissions = returnToSubmissions
            returnToSubmissions = false
            viewModel.clearUploadState()
        }
    }

    BackHandler(enabled = showSubmissions && detailItem == null) {
        showSubmissions = false
    }

    when {
        detailItem != null -> ThemeStoreDetailScreen(
            item = detailItem,
            state = state,
            onBack = { selectedItemKey = null },
            onDownload = viewModel::download,
            onTrial = { viewModel.download(it, trial = true) },
            onRefresh = { viewModel.load() },
        )

        showUpload && state.uploadResult != null -> ThemeStoreUploadResultScreen(
            result = state.uploadResult!!,
            onDone = {
                showUpload = false
                editingThemeId = null
                editingThemeBaseUrl = null
                showSubmissions = returnToSubmissions
                returnToSubmissions = false
                viewModel.clearUploadState()
            },
        )

        showUpload && uploadSource != null -> ThemeStoreUploadScreen(
            source = uploadSource,
            accountSession = uploadAccount.session,
            autoThemeId = state.uploadThemeId,
            editingTheme = editingTheme,
            optionsLoading = state.uploadOptionsLoading,
            optionsError = state.uploadOptionsError,
            uploadPhase = state.uploadPhase,
            uploadProgress = state.uploadProgress,
            submitting = state.submitting,
            errorText = state.uploadError,
            onBack = {
                if (!state.submitting) {
                    showUpload = false
                    editingThemeId = null
                    editingThemeBaseUrl = null
                    showSubmissions = returnToSubmissions
                    returnToSubmissions = false
                    viewModel.clearUploadState()
                }
            },
            onLogin = {
                showUpload = false
                editingThemeId = null
                editingThemeBaseUrl = null
                returnToSubmissions = false
                viewModel.clearUploadState()
                navigator.navigateTo(Route.ThemeAccount())
            },
            onSubmit = { input -> viewModel.submit(input, uploadSource) },
            onExportCurrentPreset = { settingsViewModel.createCurrentThemePackage(context).getOrNull() },
        )

        showSubmissions -> ThemeStoreSubmissionsScreen(
            accounts = state.accounts,
            themes = state.userThemes,
            submissions = state.submissions,
            submissionsLoading = state.submissionsLoading,
            submissionsError = state.submissionsError,
            withdrawnThemes = state.withdrawnThemes,
            withdrawingThemeKey = state.withdrawingThemeKey,
            withdrawError = state.withdrawError,
            restoringThemeKey = state.restoringThemeKey,
            restoreError = state.restoreError,
            onRefresh = { viewModel.loadUserContent(force = true) },
            onEditTheme = { theme ->
                viewModel.clearUploadState()
                showSubmissions = false
                selectedUploadBaseUrl = theme.account.source.baseUrl
                editingThemeId = theme.theme.id
                editingThemeBaseUrl = theme.account.source.baseUrl
                returnToSubmissions = true
                showUpload = true
            },
            onWithdrawTheme = viewModel::withdrawTheme,
            onRestoreTheme = viewModel::restoreTheme,
            onBack = { showSubmissions = false },
            onLogin = {
                showSubmissions = false
                navigator.navigateTo(Route.ThemeAccount())
            },
            onOpenWeb = { account ->
                viewModel.accountUrl(account.source.baseUrl)?.let { url ->
                    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, url.toUri())) }
                }
            },
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
            onOpenAccount = { navigator.navigateTo(Route.ThemeAccount()) },
            onOpenSubmissions = {
                showUpload = false
                editingThemeId = null
                editingThemeBaseUrl = null
                returnToSubmissions = false
                viewModel.clearUploadState()
                showSubmissions = true
            },
            onOpenUpload = {
                val preferred = viewModel.preferredUploadAccount()
                val accounts = viewModel.uiState.value.accounts
                when {
                    accounts.isEmpty() -> navigator.navigateTo(Route.ThemeAccount())
                    preferred != null -> openUpload(preferred)
                    accounts.size == 1 -> {
                        viewModel.setUploadSourcePreference(accounts.single().source.baseUrl)
                        openUpload(accounts.single())
                    }

                    else -> showAccountPicker = true
                }
            },
            onInstallLocal = {
                installPackagePicker.launch(
                    arrayOf(
                        ThemePackageStorage.THEME_MIME_TYPE,
                        "application/octet-stream",
                        "application/zip",
                        "application/x-zip-compressed",
                        "*/*",
                    ),
                )
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
    val shape = MaterialTheme.shapes.extraLarge
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
 * MD3E filter chip with fully opaque containers so the label stays readable over a custom
 * background image.
 */
@Composable
private fun ThemeSortChip(
    selected: Boolean,
    onClick: () -> Unit,
    label: String,
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = {
            MaterialText(
                text = label,
                style = MaterialTheme.typography.labelLarge,
            )
        },
        shapes = FilterChipDefaults.shapes(),
        colors = FilterChipDefaults.filterChipColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            labelColor = MaterialTheme.colorScheme.onSurface,
            selectedContainerColor = MaterialTheme.colorScheme.primary,
            selectedLabelColor = MaterialTheme.colorScheme.onPrimary,
        ),
        border = FilterChipDefaults.filterChipBorder(
            enabled = true,
            selected = selected,
        ),
    )
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

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
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
    onOpenAccount: () -> Unit,
    onOpenSubmissions: () -> Unit,
    onOpenUpload: () -> Unit,
    onInstallLocal: () -> Unit,
    onSelect: (ThemeStoreItem) -> Unit,
    onDownload: (ThemeStoreItem) -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    val pullToRefreshState = rememberPullToRefreshState()
    val refreshing = state.refreshing || (state.loading && state.loaded)
    val listState = rememberLazyListState()
    val fabThreshold = with(LocalDensity.current) { 100.dp.toPx() }
    val fabExpanded by remember {
        var lastIndex = 0
        var lastOffset = 0
        var scrollDelta = 0f
        var expanded = true
        derivedStateOf {
            val currentIndex = listState.firstVisibleItemIndex
            val currentOffset = listState.firstVisibleItemScrollOffset
            val delta = if (currentIndex == lastIndex) {
                (currentOffset - lastOffset).toFloat()
            } else if (currentIndex > lastIndex) {
                100f
            } else {
                -100f
            }
            scrollDelta = (scrollDelta + delta).coerceIn(-fabThreshold, fabThreshold)
            lastIndex = currentIndex
            lastOffset = currentOffset
            if (currentIndex == 0) {
                expanded = true
                scrollDelta = 0f
            } else if (expanded && scrollDelta >= fabThreshold) {
                expanded = false
                scrollDelta = 0f
            } else if (!expanded && scrollDelta <= -fabThreshold) {
                expanded = true
                scrollDelta = 0f
            }
            expanded
        }
    }

    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                title = { MaterialText(customText(CustomTextKey.PAGE_THEME_STORE)) },
                actions = {
                    MaterialIconButton(
                        onClick = onOpenAccount,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.AccountCircle,
                            contentDescription = stringResource(R.string.theme_store_account),
                        )
                    }
                    MaterialIconButton(
                        onClick = onOpenSubmissions,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.History,
                            contentDescription = stringResource(R.string.theme_store_my_content_title),
                        )
                    }
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
        floatingActionButton = {
            SmallExtendedFloatingActionButton(
                onClick = onInstallLocal,
                expanded = fabExpanded,
                icon = {
                    MaterialIcon(
                        imageVector = Icons.Rounded.InstallMobile,
                        contentDescription = null,
                    )
                },
                text = {
                    MaterialText(stringResource(R.string.theme_store_install_local))
                },
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
                ContainedLoadingIndicator()
            }

            state.items.isEmpty() && state.error -> ThemeStoreErrorMaterial(
                unauthorized = state.unauthorized,
                onRetry = onRefresh,
                onOpenSettings = onOpenSettings,
                modifier = Modifier.padding(paddingValues),
            )

            else -> PullToRefreshBox(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
                isRefreshing = refreshing,
                onRefresh = onRefresh,
                state = pullToRefreshState,
                indicator = {
                    PullToRefreshDefaults.LoadingIndicator(
                        state = pullToRefreshState,
                        isRefreshing = refreshing,
                        modifier = Modifier.align(Alignment.TopCenter),
                    )
                },
            ) {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .nestedScroll(scrollBehavior.nestedScrollConnection),
                    state = listState,
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
                    if (state.fromCache) {
                        item(key = "offline") {
                            ThemeStoreInlineNotice(
                                text = stringResource(R.string.theme_store_offline),
                            )
                        }
                    }
                    if (state.failedSources > 0 && state.items.isNotEmpty()) {
                        item(key = "partial-failure") {
                            ThemeStoreInlineNotice(
                                text = stringResource(R.string.theme_store_partial_failure),
                                isError = true,
                                icon = Icons.Rounded.Warning,
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
                                modifier = Modifier.animateItem(
                                    fadeInSpec = MaterialTheme.motionScheme.defaultEffectsSpec(),
                                    placementSpec = MaterialTheme.motionScheme.defaultSpatialSpec(),
                                    fadeOutSpec = MaterialTheme.motionScheme.fastEffectsSpec(),
                                ),
                            )
                        }
                    }
                    item(key = "bottom-inset") {
                        Spacer(
                            Modifier.height(
                                WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 88.dp,
                            ),
                        )
                    }
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
    modifier: Modifier = Modifier,
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
        modifier = modifier
            .fillMaxWidth()
            .height(200.dp),
        shape = MaterialTheme.shapes.large,
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
                    shapes = ButtonDefaults.shapes(),
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
                        CircularWavyProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            color = Color.White,
                            trackColor = Color.Transparent,
                            stroke = Stroke(width = 2f),
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
        Button(
            onClick = onUpload,
            shapes = ButtonDefaults.shapes(),
        ) {
            MaterialText(stringResource(R.string.theme_store_upload))
        }
        MaterialTextButton(
            onClick = onRefresh,
            shapes = ButtonDefaults.shapes(),
        ) {
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
        MaterialTextButton(
            onClick = onOpenSettings,
            shapes = ButtonDefaults.shapes(),
        ) {
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
        MaterialTextButton(
            onClick = onOpenSettings,
            shapes = ButtonDefaults.shapes(),
        ) {
            MaterialText(stringResource(R.string.theme_store_settings))
        }
        MaterialTextButton(
            onClick = onRetry,
            shapes = ButtonDefaults.shapes(),
        ) {
            MaterialText(stringResource(R.string.theme_store_retry))
        }
    }
}
