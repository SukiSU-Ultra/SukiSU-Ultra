package com.sukisu.ultra.ui.screen.themestore

import android.annotation.SuppressLint
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountCircle
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.FlashOn
import androidx.compose.material.icons.automirrored.rounded.Chat
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.InstallMobile
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.automirrored.rounded.Sort
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Tag
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.ViewCarousel
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.ContainedLoadingIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SmallExtendedFloatingActionButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.PullToRefreshDefaults
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import coil.compose.rememberAsyncImagePainter
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.data.repository.ThemeStoreRepository
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
    HOT,
    DOWNLOADS,
    NEWEST,
    NAME,
    SIZE,
}

private fun List<ThemeStoreItem>.sortedFor(mode: ThemeStoreSort): List<ThemeStoreItem> = when (mode) {
    ThemeStoreSort.DEFAULT -> this
    ThemeStoreSort.HOT -> sortedWith(
        compareByDescending<ThemeStoreItem> { it.entry.heat }
            .thenByDescending { it.entry.downloads }
            .thenBy { it.entry.name.lowercase(Locale.ROOT) },
    )
    ThemeStoreSort.DOWNLOADS -> sortedWith(
        compareByDescending<ThemeStoreItem> { it.entry.downloads }
            .thenByDescending { it.entry.heat }
            .thenBy { it.entry.name.lowercase(Locale.ROOT) },
    )
    ThemeStoreSort.NEWEST -> sortedWith(
        compareByDescending<ThemeStoreItem> { it.entry.updatedAt }
            .thenBy { it.entry.name.lowercase(Locale.ROOT) },
    )
    ThemeStoreSort.NAME -> sortedWith(compareBy { it.entry.name.lowercase(Locale.ROOT) })
    ThemeStoreSort.SIZE -> sortedWith(compareByDescending { it.entry.size })
}


internal fun formatStoreCount(value: Long): String {
    val count = value.coerceAtLeast(0)
    return when {
        count >= 999_500 -> String.format(Locale.ROOT, "%.1fM", count / 1_000_000.0)
        count >= 10_000 -> String.format(Locale.ROOT, "%.0fk", count / 1_000.0)
        count >= 1_000 -> String.format(Locale.ROOT, "%.1fk", count / 1_000.0)
        else -> count.toString()
    }
}

@SuppressLint("LocalContextGetResourceValueCall")
@Composable
fun ThemeStoreScreen(
    viewModel: ThemeStoreViewModel = viewModel(),
    startAdaptiveUpload: Boolean = false,
    startCurrentUpload: Boolean = false,
    initialThemeId: String? = null,
    initialSourceBaseUrl: String? = null,
) {
    val context = LocalContext.current
    val navigator = LocalNavigator.current
    val settingsViewModel = viewModel<SettingsViewModel>()
    val settingsUiState by settingsViewModel.uiState.collectAsStateWithLifecycle()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var showUpload by rememberSaveable { mutableStateOf(false) }
    var showSubmissions by rememberSaveable { mutableStateOf(false) }
    var showMessages by rememberSaveable { mutableStateOf(false) }
    var showHistory by rememberSaveable { mutableStateOf(false) }
    var showPreferences by rememberSaveable { mutableStateOf(false) }
    var showConsentDialog by rememberSaveable { mutableStateOf(false) }
    var showAccountPicker by rememberSaveable { mutableStateOf(false) }
    var pendingAdaptiveTheme by rememberSaveable { mutableStateOf(false) }
    var pendingCurrentTheme by rememberSaveable { mutableStateOf(false) }
    var adaptiveUploadHandled by rememberSaveable(startAdaptiveUpload) { mutableStateOf(false) }
    var adaptiveAccountRedirected by rememberSaveable(startAdaptiveUpload) { mutableStateOf(false) }
    var currentUploadHandled by rememberSaveable(startCurrentUpload) { mutableStateOf(false) }
    var currentAccountRedirected by rememberSaveable(startCurrentUpload) { mutableStateOf(false) }
    var selectedUploadBaseUrl by rememberSaveable { mutableStateOf<String?>(null) }
    var editingThemeId by rememberSaveable { mutableStateOf<String?>(null) }
    var editingThemeBaseUrl by rememberSaveable { mutableStateOf<String?>(null) }
    var returnToSubmissions by rememberSaveable { mutableStateOf(false) }
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var sortMode by rememberSaveable { mutableStateOf(ThemeStoreSort.DEFAULT) }
    var selectedItemKey by rememberSaveable { mutableStateOf<String?>(null) }
    val themeGridState = rememberLazyGridState()
    var selectedAuthor by rememberSaveable { mutableStateOf<String?>(null) }
    var authorReturnItemKey by rememberSaveable { mutableStateOf<String?>(null) }
    var detailReturnAuthor by rememberSaveable { mutableStateOf<String?>(null) }
    var selectedTags by rememberSaveable(
        stateSaver = listSaver(
            save = { it.toList() },
            restore = { it.toSet() },
        ),
    ) { mutableStateOf(emptySet<String>()) }
    // Adult themes are hidden from search, tags and author pages until the user opts in.
    val catalogItems = remember(state.items, state.showR18) {
        if (state.showR18) state.items else state.items.filterNot { it.isR18Theme() }
    }
    var deepLinkHandled by rememberSaveable(initialThemeId, initialSourceBaseUrl) { mutableStateOf(false) }
    LaunchedEffect(initialThemeId, initialSourceBaseUrl, catalogItems, state.loaded, state.loading) {
        if (initialThemeId.isNullOrBlank() || deepLinkHandled || !state.loaded || state.loading) return@LaunchedEffect
        searchQuery = initialThemeId
        val item = catalogItems.firstOrNull { candidate ->
            candidate.entry.id == initialThemeId &&
                (initialSourceBaseUrl == null || candidate.source.baseUrl.trimEnd('/') == initialSourceBaseUrl.trimEnd('/'))
        }
        if (item != null) {
            viewModel.recordView(item)
            selectedItemKey = item.key
        }
        deepLinkHandled = true
    }
    val allTags = remember(catalogItems) { catalogItems.popularThemeTags(Int.MAX_VALUE) }
    // Hoisted above the store/author switch so orientation survives detail navigation instead
    // of re-measuring every preview when the grid comes back.
    val landscapePreviewKeys = remember { mutableStateMapOf<String, Boolean>() }
    LaunchedEffect(allTags) {
        // Keep restored filters until the first catalog load actually provides a tag set.
        if (allTags.isEmpty()) return@LaunchedEffect
        if (selectedTags.isNotEmpty()) {
            val canonical = allTags.associateBy { canonicalThemeTag(it) }
            val pruned = selectedTags
                .mapNotNull { canonical[canonicalThemeTag(it)] }
                .toSet()
            if (pruned != selectedTags) selectedTags = pruned
        }
    }
    val adaptiveSearchLabel = stringResource(R.string.theme_adaptive_tag)
    val visibleItems = remember(
        catalogItems,
        searchQuery,
        sortMode,
        selectedTags,
        adaptiveSearchLabel,
        state.followedAuthorKeys,
    ) {
        catalogItems
            .filter { it.matchesSearch(searchQuery, adaptiveSearchLabel) }
            .filterByThemeTags(selectedTags)
            .sortedFor(sortMode)
            .followedFirst(state.followedAuthorKeys)
    }
    val authorItems = remember(catalogItems, selectedAuthor) {
        selectedAuthor?.let { author ->
            catalogItems
                .forThemeAuthor(author)
                .sortedWith(compareByDescending { it.entry.updatedAt })
        }.orEmpty()
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
        viewModel.clearEditPrefill()
        showUpload = true
    }

    // Entered from the adaptive theme builder: pick an account and open the upload form with the
    // adaptive package generated on demand instead of asking for a file again.
    LaunchedEffect(startAdaptiveUpload, state.loaded, state.accounts) {
        if (!startAdaptiveUpload || adaptiveUploadHandled) return@LaunchedEffect
        if (!state.loaded) return@LaunchedEffect
        if (state.needsConfig) return@LaunchedEffect
        if (!settingsViewModel.hasAdaptiveThemeForUpload()) return@LaunchedEffect
        val accounts = state.accounts
        if (accounts.isEmpty()) {
            if (!adaptiveAccountRedirected) {
                adaptiveAccountRedirected = true
                navigator.navigateTo(Route.ThemeAccount())
            }
            return@LaunchedEffect
        }
        pendingAdaptiveTheme = true
        adaptiveUploadHandled = true
        // Returning from the account page after login should land directly on the upload form.
        if (navigator.current() is Route.ThemeAccount) navigator.pop()
        if (accounts.size == 1) {
            openUpload(accounts.single())
        } else {
            showAccountPicker = true
        }
    }

    // Entered from the theme settings export dialog: open the upload form straight away and let
    // the form generate a package from the options the user just picked.
    LaunchedEffect(startCurrentUpload, state.loaded, state.accounts) {
        if (!startCurrentUpload || currentUploadHandled) return@LaunchedEffect
        if (!state.loaded) return@LaunchedEffect
        if (state.needsConfig) return@LaunchedEffect
        val accounts = state.accounts
        if (accounts.isEmpty()) {
            if (!currentAccountRedirected) {
                currentAccountRedirected = true
                navigator.navigateTo(Route.ThemeAccount())
            }
            return@LaunchedEffect
        }
        pendingCurrentTheme = true
        currentUploadHandled = true
        if (navigator.current() is Route.ThemeAccount) navigator.pop()
        if (accounts.size == 1) {
            openUpload(accounts.single())
        } else {
            showAccountPicker = true
        }
    }

    fun openAuthor(item: ThemeStoreItem) {
        val author = item.entry.author.trim()
        if (author.isEmpty()) return
        authorReturnItemKey = selectedItemKey
        detailReturnAuthor = null
        selectedAuthor = author
        selectedItemKey = null
    }

    fun closeAuthorPage() {
        val returnKey = authorReturnItemKey
        authorReturnItemKey = null
        selectedAuthor = null
        if (returnKey != null) {
            detailReturnAuthor = null
            selectedItemKey = returnKey
        }
    }

    fun closeDetail() {
        val returnToAuthor = detailReturnAuthor != null && selectedAuthor != null
        selectedItemKey = null
        detailReturnAuthor = null
        if (!returnToAuthor) selectedAuthor = null
    }

    LaunchedEffect(showUpload, selectedUploadBaseUrl) {
        val baseUrl = selectedUploadBaseUrl
        if (showUpload && baseUrl != null) viewModel.loadUploadOptions(baseUrl)
    }

    LaunchedEffect(showUpload) {
        if (!showUpload) viewModel.clearEditPrefill()
    }

    // The account page can log in, log out or switch the active author while the store entry
    // stays alive in the back stack, so re-read its sessions whenever the store is resumed.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.refreshAccounts()
    }

    LaunchedEffect(showSubmissions) {
        if (showSubmissions) viewModel.loadUserContent()
    }

    LaunchedEffect(showHistory) {
        if (showHistory) viewModel.refreshHistory()
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

    LaunchedEffect(state.followError) {
        state.followError?.let { message ->
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            viewModel.clearFollowError()
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
                        if (startAdaptiveUpload) adaptiveUploadHandled = false
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
    val currentAuthor = selectedAuthor

    LaunchedEffect(state.needsConsent, showPreferences) {
        // First entry shows the agreement automatically; the settings page stays available so
        // the user can read the agreement again and reconnect.
        if (state.needsConsent && !showPreferences) {
            showConsentDialog = true
        }
    }

    BackHandler(enabled = showPreferences) {
        showPreferences = false
    }

    BackHandler(enabled = detailItem != null) {
        closeDetail()
    }

    BackHandler(enabled = detailItem == null && currentAuthor != null) {
        closeAuthorPage()
    }

    BackHandler(enabled = showUpload && detailItem == null && currentAuthor == null) {
        if (!state.submitting) {
            showUpload = false
            editingThemeId = null
            showSubmissions = returnToSubmissions
            returnToSubmissions = false
            viewModel.clearUploadState()
        }
    }

    BackHandler(enabled = showSubmissions && detailItem == null && currentAuthor == null) {
        showSubmissions = false
    }

    BackHandler(enabled = showMessages && detailItem == null && currentAuthor == null) {
        showMessages = false
    }

    BackHandler(enabled = showHistory && detailItem == null && currentAuthor == null) {
        showHistory = false
    }

    when {
        showPreferences -> ThemeStorePreferencesScreen(
            consentAccepted = !state.needsConsent,
            showR18 = state.showR18,
            onToggleShowR18 = viewModel::setShowR18,
            onRequestConsent = { showConsentDialog = true },
            onRevokeConsent = viewModel::revokeConsent,
            onBack = { showPreferences = false },
        )

        detailItem != null -> ThemeStoreDetailScreen(
            item = detailItem,
            state = state,
            onBack = ::closeDetail,
            onDownload = viewModel::download,
            onTrial = { viewModel.download(it, trial = true) },
            onRefresh = { viewModel.load() },
            onAuthorClick = ::openAuthor,
            onOpenSettings = {
                navigator.navigateForResult(Route.ThemeStoreSources, THEME_SOURCES_RESULT_KEY)
            },
            onLoadComments = { viewModel.loadComments(detailItem) },
            onCommentsLogin = { navigator.navigateTo(Route.ThemeAccount()) },
            onCommentsRefresh = { viewModel.loadComments(detailItem, force = true) },
            onSendComment = { content -> viewModel.sendComment(detailItem, content) },
            onDeleteComment = { comment -> viewModel.deleteComment(detailItem, comment) },
            onCommentReplyTargetChange = viewModel::setCommentReplyTarget,
            onCommentVisibilityChange = viewModel::setCommentVisibility,
            onSearchMentions = { query -> viewModel.searchMentionUsers(detailItem.source, query) },
            onClearMentionSearch = viewModel::clearMentionSearch,
            followVisible = detailItem.entry.authorHash.isNotBlank(),
            following = detailItem.followKey() in state.followedAuthorKeys,
            onToggleFollow = {
                if (viewModel.hasAccountFor(detailItem.source.baseUrl)) {
                    viewModel.toggleFollow(detailItem)
                } else {
                    navigator.navigateTo(Route.ThemeAccount())
                }
            },
        )

        currentAuthor != null -> ThemeStoreAuthorScreen(
            author = currentAuthor,
            items = authorItems,
            state = state,
            gridLayout = state.gridLayout,
            onToggleLayout = { viewModel.setGridLayout(!state.gridLayout) },
            landscapePreviewKeys = landscapePreviewKeys,
            onBack = ::closeAuthorPage,
            onSelect = { item ->
                detailReturnAuthor = currentAuthor
                viewModel.recordView(item)
                selectedItemKey = item.key
            },
            onDownload = viewModel::download,
            onRefresh = { viewModel.load() },
            onOpenSettings = {
                navigator.navigateForResult(Route.ThemeStoreSources, THEME_SOURCES_RESULT_KEY)
            },
            followedAuthorKeys = state.followedAuthorKeys,
            onToggleFollow = { item ->
                if (viewModel.hasAccountFor(item.source.baseUrl)) {
                    viewModel.toggleFollow(item)
                } else {
                    navigator.navigateTo(Route.ThemeAccount())
                }
            },
        )

        showUpload && state.uploadResult != null -> ThemeStoreUploadResultScreen(
            result = state.uploadResult!!,
            onDone = {
                showUpload = false
                pendingAdaptiveTheme = false
                pendingCurrentTheme = false
                settingsViewModel.clearPendingThemeUploadOptions()
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
            editPrefill = state.editPrefill,
            initialAdaptiveTheme = pendingAdaptiveTheme,
            initialCurrentTheme = pendingCurrentTheme,
            optionsLoading = state.uploadOptionsLoading,
            optionsError = state.uploadOptionsError,
            uploadPhase = state.uploadPhase,
            uploadProgress = state.uploadProgress,
            uploadTransferredBytes = state.uploadTransferredBytes,
            uploadTotalBytes = state.uploadTotalBytes,
            uploadSpeedBytesPerSecond = state.uploadSpeedBytesPerSecond,
            uploadEtaSeconds = state.uploadEtaSeconds,
            submitting = state.submitting,
            errorText = state.uploadError,
            onBack = {
                if (!state.submitting) {
                    showUpload = false
                    pendingAdaptiveTheme = false
                    pendingCurrentTheme = false
                    settingsViewModel.clearPendingThemeUploadOptions()
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
            onLoadAdaptiveTheme = { settingsViewModel.createAdaptiveThemePackage(context).getOrNull() },
        )

        showHistory -> ThemeStoreHistoryScreen(
            viewedHistory = if (state.showR18) state.viewedHistory
                else state.viewedHistory.filterNot { it.r18 },
            downloadedHistory = if (state.showR18) state.downloadedHistory
                else state.downloadedHistory.filterNot { it.r18 },
            sources = state.sources,
            loading = state.historyLoading,
            error = state.historyError,
            loginRequired = state.historyLoginRequired,
            onBack = { showHistory = false },
            onOpen = { entry ->
                val item = state.items.firstOrNull { it.key == entry.key }
                    ?: state.items.firstOrNull {
                        it.entry.id == entry.themeId && it.source.baseUrl == entry.baseUrl
                    }
                if (item != null) {
                    viewModel.recordView(item)
                    selectedAuthor = null
                    detailReturnAuthor = null
                    authorReturnItemKey = null
                    selectedItemKey = item.key
                } else {
                    Toast.makeText(
                        context,
                        context.getString(R.string.theme_store_history_missing),
                        Toast.LENGTH_SHORT,
                    ).show()
                }
            },
            onClear = viewModel::clearHistory,
            onDelete = viewModel::removeHistory,
            onLogin = {
                showHistory = false
                navigator.navigateTo(Route.ThemeAccount())
            },
            onRefresh = viewModel::refreshHistory,
        )

        showMessages -> ThemeStoreMessagesScreen(
            state = state,
            onBack = { showMessages = false },
            onRefresh = { viewModel.loadMessages(force = true) },
            onLogin = {
                showMessages = false
                navigator.navigateTo(Route.ThemeAccount())
            },
            onReply = { conversation, content, parentId ->
                viewModel.sendMessageReply(conversation, content, parentId)
            },
            onDelete = viewModel::deleteMessage,
            mentionUsers = state.mentionUsers,
            mentionLoading = state.mentionLoading,
            mentionError = state.mentionError,
            onSearchMentions = { conversation, query ->
                viewModel.searchMentionUsers(conversation.account.source, query)
            },
            onClearMentionSearch = viewModel::clearMentionSearch,
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
                viewModel.loadEditPrefill(theme.theme, theme.account.source.baseUrl)
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
            listState = themeGridState,
            visibleItems = visibleItems,
            searchQuery = searchQuery,
            onSearchQueryChange = { searchQuery = it },
            availableTags = allTags,
            selectedTags = selectedTags,
            onToggleTag = { tag ->
                selectedTags = if (tag in selectedTags) selectedTags - tag else selectedTags + tag
            },
            onClearTags = { selectedTags = emptySet() },
            sortMode = sortMode,
            onSortChange = { sortMode = it },
            gridLayout = state.gridLayout,
            onToggleLayout = { viewModel.setGridLayout(!state.gridLayout) },
            landscapePreviewKeys = landscapePreviewKeys,
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
                showMessages = false
                showSubmissions = true
            },
            onOpenMessages = {
                showUpload = false
                showSubmissions = false
                editingThemeId = null
                editingThemeBaseUrl = null
                returnToSubmissions = false
                viewModel.clearUploadState()
                showMessages = true
            },
            onOpenHistory = {
                viewModel.refreshHistory()
                showUpload = false
                showSubmissions = false
                showMessages = false
                editingThemeId = null
                editingThemeBaseUrl = null
                returnToSubmissions = false
                viewModel.clearUploadState()
                showHistory = true
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
            onSelect = { item ->
                selectedAuthor = null
                detailReturnAuthor = null
                authorReturnItemKey = null
                viewModel.recordView(item)
                selectedItemKey = item.key
            },
            onAuthorClick = ::openAuthor,
            onDownload = viewModel::download,
            needsConsent = state.needsConsent,
            onRequestConsent = { showConsentDialog = true },
            onOpenPreferences = { showPreferences = true },
        )
    }

    if (showConsentDialog) {
        ThemeStoreConsentDialog(
            alreadyAccepted = !state.needsConsent,
            onAccept = {
                showConsentDialog = false
                if (state.needsConsent) viewModel.acceptConsent()
            },
            onDismiss = {
                showConsentDialog = false
                if (state.needsConsent) navigator.pop()
            },
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

/**
 * Compact single-row toolbar: tag and sort filters open anchored menus, while the view switch
 * stays directly reachable. This keeps the chip rows off the scrolling content.
 */
@Composable
private fun ThemeStoreFilterRow(
    tags: List<String>,
    selectedTags: Set<String>,
    onToggleTag: (String) -> Unit,
    onClearTags: () -> Unit,
    sortMode: ThemeStoreSort,
    onSortChange: (ThemeStoreSort) -> Unit,
    gridLayout: Boolean,
    onToggleLayout: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier
                .weight(1f)
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (tags.isNotEmpty() || selectedTags.isNotEmpty()) {
                ThemeTagMenuButton(
                    tags = tags,
                    selected = selectedTags,
                    onToggle = onToggleTag,
                    onClear = onClearTags,
                )
            }
            ThemeSortMenuButton(
                selected = sortMode,
                onSelect = onSortChange,
            )
        }
        FilledTonalIconButton(
            onClick = onToggleLayout,
            shapes = IconButtonDefaults.shapes(),
        ) {
            MaterialIcon(
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
    }
}

@Composable
private fun ThemeTagMenuButton(
    tags: List<String>,
    selected: Set<String>,
    onToggle: (String) -> Unit,
    onClear: () -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val summary = when {
        selected.isEmpty() -> stringResource(R.string.theme_store_tags)
        selected.size == 1 -> themeTagLabel(selected.first())
        else -> themeTagLabel(selected.first()) + " +${selected.size - 1}"
    }
    Box {
        ThemeStoreMenuButton(
            text = summary,
            icon = Icons.Rounded.Tag,
            active = selected.isNotEmpty(),
            onClick = { expanded = true },
        )
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            // Long catalogs would otherwise push the popup to the window edge and cover the
            // top bar; cap the menu height and let it scroll internally.
            modifier = Modifier.heightIn(max = 320.dp),
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
                text = { MaterialText(stringResource(R.string.theme_store_tag_all)) },
                leadingIcon = if (selected.isEmpty()) {
                    { MaterialIcon(Icons.Rounded.Check, contentDescription = null) }
                } else {
                    null
                },
                onClick = {
                    onClear()
                    expanded = false
                },
            )
            tags.forEach { tag ->
                val isSelected = tag in selected
                DropdownMenuItem(
                    text = { MaterialText(themeTagLabel(tag)) },
                    leadingIcon = if (isSelected) {
                        { MaterialIcon(Icons.Rounded.Check, contentDescription = null) }
                    } else {
                        null
                    },
                    // Multi-select filters stay open until the user taps outside the menu.
                    onClick = { onToggle(tag) },
                )
            }
        }
    }
}

@Composable
private fun ThemeSortMenuButton(
    selected: ThemeStoreSort,
    onSelect: (ThemeStoreSort) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val options = listOf(
        ThemeStoreSort.DEFAULT to R.string.theme_store_sort_default,
        ThemeStoreSort.HOT to R.string.theme_store_sort_hot,
        ThemeStoreSort.DOWNLOADS to R.string.theme_store_sort_downloads,
        ThemeStoreSort.NEWEST to R.string.theme_store_sort_newest,
        ThemeStoreSort.NAME to R.string.theme_store_sort_name,
        ThemeStoreSort.SIZE to R.string.theme_store_sort_size,
    )
    val currentLabel = stringResource(
        options.firstOrNull { it.first == selected }?.second
            ?: R.string.theme_store_sort_default,
    )
    Box {
        ThemeStoreMenuButton(
            text = currentLabel,
            icon = Icons.AutoMirrored.Rounded.Sort,
            active = selected != ThemeStoreSort.DEFAULT,
            onClick = { expanded = true },
        )
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            modifier = Modifier.heightIn(max = 320.dp),
            shape = MaterialTheme.shapes.large,
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
            tonalElevation = 0.dp,
            shadowElevation = 3.dp,
            border = BorderStroke(
                1.dp,
                MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
            ),
        ) {
            options.forEach { (mode, label) ->
                DropdownMenuItem(
                    text = { MaterialText(stringResource(label)) },
                    leadingIcon = if (selected == mode) {
                        { MaterialIcon(Icons.Rounded.Check, contentDescription = null) }
                    } else {
                        null
                    },
                    onClick = {
                        onSelect(mode)
                        expanded = false
                    },
                )
            }
        }
    }
}

/**
 * MD3E filled tonal menu trigger; the container switches to the selected colors while a filter
 * is active so the collapsed state is still visible.
 */
@Composable
private fun ThemeStoreMenuButton(
    text: String,
    icon: ImageVector,
    active: Boolean,
    onClick: () -> Unit,
) {
    FilledTonalButton(
        onClick = onClick,
        shapes = ButtonDefaults.shapes(),
        colors = ButtonDefaults.filledTonalButtonColors(
            containerColor = if (active) {
                MaterialTheme.colorScheme.secondaryContainer
            } else {
                MaterialTheme.colorScheme.surfaceContainerHigh
            },
            contentColor = if (active) {
                MaterialTheme.colorScheme.onSecondaryContainer
            } else {
                MaterialTheme.colorScheme.onSurface
            },
        ),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 0.dp),
    ) {
        MaterialIcon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
        )
        Spacer(Modifier.size(6.dp))
        MaterialText(
            text = text,
            style = MaterialTheme.typography.labelLarge,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.size(2.dp))
        MaterialIcon(
            imageVector = Icons.Rounded.ExpandMore,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
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

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun ThemeStoreMaterial(
    state: ThemeStoreUiState,
    listState: androidx.compose.foundation.lazy.grid.LazyGridState,
    visibleItems: List<ThemeStoreItem>,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    availableTags: List<String>,
    selectedTags: Set<String>,
    onToggleTag: (String) -> Unit,
    onClearTags: () -> Unit,
    sortMode: ThemeStoreSort,
    onSortChange: (ThemeStoreSort) -> Unit,
    gridLayout: Boolean,
    onToggleLayout: () -> Unit,
    landscapePreviewKeys: MutableMap<String, Boolean>,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenAccount: () -> Unit,
    onOpenSubmissions: () -> Unit,
    onOpenMessages: () -> Unit,
    onOpenHistory: () -> Unit,
    onOpenUpload: () -> Unit,
    onInstallLocal: () -> Unit,
    onSelect: (ThemeStoreItem) -> Unit,
    onAuthorClick: (ThemeStoreItem) -> Unit,
    onDownload: (ThemeStoreItem) -> Unit,
    needsConsent: Boolean,
    onRequestConsent: () -> Unit,
    onOpenPreferences: () -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    val pullToRefreshState = rememberPullToRefreshState()
    val refreshing = state.refreshing || (state.loading && state.loaded)
    var menuExpanded by remember { mutableStateOf(false) }
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
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeFlexibleTopAppBar(
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                title = { MaterialText(customText(CustomTextKey.PAGE_THEME_STORE)) },
                actions = {
                    MaterialIconButton(
                        onClick = onOpenUpload,
                        enabled = !state.needsConfig && !state.maintenance &&
                            state.sources.isNotEmpty() && !state.submitting,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.FileUpload,
                            contentDescription = stringResource(R.string.theme_store_upload),
                        )
                    }
                    Box {
                        MaterialIconButton(
                            onClick = { menuExpanded = true },
                            colors = themeStoreTopBarIconColors(),
                        ) {
                            MaterialIcon(
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
                                text = { MaterialText(stringResource(R.string.theme_store_account)) },
                                leadingIcon = {
                                    MaterialIcon(
                                        imageVector = Icons.Rounded.AccountCircle,
                                        contentDescription = null,
                                    )
                                },
                                enabled = !state.maintenance,
                                onClick = {
                                    menuExpanded = false
                                    onOpenAccount()
                                },
                            )
                            DropdownMenuItem(
                                text = { MaterialText(stringResource(R.string.theme_store_my_content_title)) },
                                leadingIcon = {
                                    MaterialIcon(
                                        imageVector = Icons.Rounded.Palette,
                                        contentDescription = null,
                                    )
                                },
                                enabled = !state.maintenance,
                                onClick = {
                                    menuExpanded = false
                                    onOpenSubmissions()
                                },
                            )
                            DropdownMenuItem(
                                text = { MaterialText(stringResource(R.string.theme_store_history_title)) },
                                leadingIcon = {
                                    MaterialIcon(
                                        imageVector = Icons.Rounded.History,
                                        contentDescription = null,
                                    )
                                },
                                enabled = !state.maintenance,
                                onClick = {
                                    menuExpanded = false
                                    onOpenHistory()
                                },
                            )
                            DropdownMenuItem(
                                text = { MaterialText(stringResource(R.string.theme_store_messages_title)) },
                                leadingIcon = {
                                    MaterialIcon(
                                        imageVector = Icons.AutoMirrored.Rounded.Chat,
                                        contentDescription = null,
                                    )
                                },
                                enabled = !state.maintenance,
                                onClick = {
                                    menuExpanded = false
                                    onOpenMessages()
                                },
                            )
                            DropdownMenuItem(
                                text = { MaterialText(stringResource(R.string.theme_store_preferences)) },
                                leadingIcon = {
                                    MaterialIcon(
                                        imageVector = Icons.Rounded.Tune,
                                        contentDescription = null,
                                    )
                                },
                                onClick = {
                                    menuExpanded = false
                                    onOpenPreferences()
                                },
                            )
                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                            )
                            DropdownMenuItem(
                                text = { MaterialText(stringResource(R.string.theme_store_refresh)) },
                                leadingIcon = {
                                    MaterialIcon(
                                        imageVector = Icons.Rounded.Refresh,
                                        contentDescription = null,
                                    )
                                },
                                enabled = !state.needsConfig && !state.refreshing && !state.loading,
                                onClick = {
                                    menuExpanded = false
                                    onRefresh()
                                },
                            )
                            DropdownMenuItem(
                                text = { MaterialText(stringResource(R.string.theme_store_sources)) },
                                leadingIcon = {
                                    MaterialIcon(
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
            needsConsent -> ThemeStoreConsentRequiredMaterial(
                onRequestConsent = onRequestConsent,
                onOpenPreferences = onOpenPreferences,
                modifier = Modifier.padding(paddingValues),
            )

            state.needsConfig -> ThemeStoreConfigRequiredMaterial(
                onOpenSettings = onOpenSettings,
                modifier = Modifier.padding(paddingValues),
            )

            state.maintenance -> ThemeStoreMaintenanceMaterial(
                onRetry = onRefresh,
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
                LazyVerticalGrid(
                    columns = GridCells.Fixed(if (gridLayout) 2 else 1),
                    modifier = Modifier.fillMaxSize(),
                    state = listState,
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 13.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item(key = "search", span = { GridItemSpan(maxLineSpan) }) {
                        ThemeStoreSearchMaterial(
                            query = searchQuery,
                            onQueryChange = onSearchQueryChange,
                        )
                    }
                    item(key = "filters", span = { GridItemSpan(maxLineSpan) }) {
                        ThemeStoreFilterRow(
                            tags = availableTags,
                            selectedTags = selectedTags,
                            onToggleTag = onToggleTag,
                            onClearTags = onClearTags,
                            sortMode = sortMode,
                            onSortChange = onSortChange,
                            gridLayout = gridLayout,
                            onToggleLayout = onToggleLayout,
                        )
                    }
                    if (state.fromCache) {
                        item(key = "offline", span = { GridItemSpan(maxLineSpan) }) {
                            ThemeStoreInlineNotice(
                                text = stringResource(R.string.theme_store_offline),
                            )
                        }
                    }
                    if (state.failedSources > 0 && state.items.isNotEmpty()) {
                        item(key = "partial-failure", span = { GridItemSpan(maxLineSpan) }) {
                            ThemeStoreInlineNotice(
                                text = stringResource(R.string.theme_store_partial_failure),
                                isError = true,
                                icon = Icons.Rounded.Warning,
                            )
                        }
                    }
                    if (visibleItems.isEmpty()) {
                        item(key = "empty", span = { GridItemSpan(maxLineSpan) }) {
                            if (searchQuery.isBlank() && selectedTags.isEmpty()) {
                                ThemeStoreEmptyMaterial(onRefresh = onRefresh, onUpload = onOpenUpload)
                            } else {
                                ThemeStoreSearchEmptyMaterial()
                            }
                        }
                    } else {
                        items(
                            items = visibleItems,
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
                            if (gridLayout) {
                                ThemeGridCardMaterial(
                                    item = item,
                                    state = state,
                                    onSelect = onSelect,
                                    onDownload = onDownload,
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
                                    onAuthorClick = onAuthorClick,
                                    onDownload = onDownload,
                                    modifier = cardModifier,
                                )
                            }
                        }
                    }
                    item(key = "bottom-inset", span = { GridItemSpan(maxLineSpan) }) {
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
internal fun ThemeCardMaterial(
    item: ThemeStoreItem,
    state: ThemeStoreUiState,
    onSelect: (ThemeStoreItem) -> Unit,
    onDownload: (ThemeStoreItem) -> Unit,
    modifier: Modifier = Modifier,
    onAuthorClick: ((ThemeStoreItem) -> Unit)? = null,
    sourceLabel: String? = null,
) {
    val entry = item.entry
    val downloading = state.downloadingKey == item.key
    val date = entry.updatedAt.substringBefore('T').replace('-', '/')
    val primaryLabel = sourceLabel ?: entry.author
    val authorClick = onAuthorClick?.takeIf {
        sourceLabel == null && entry.author.isNotBlank()
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
            if (item.isR18Theme() || item.isAdaptiveTheme()) {
                Column(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(10.dp),
                    horizontalAlignment = Alignment.End,
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    if (item.isR18Theme()) {
                        ThemeR18Badge()
                    }
                    if (item.isAdaptiveTheme()) {
                        AdaptiveThemeBadge()
                    }
                }
            }
            Row(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                ThemeStoreStatBadge(
                    icon = Icons.Rounded.FlashOn,
                    value = entry.heat,
                    contentDescription = stringResource(R.string.theme_store_heat),
                )
                ThemeStoreStatBadge(
                    icon = Icons.Rounded.FileDownload,
                    value = entry.downloads,
                    contentDescription = stringResource(R.string.theme_store_downloads),
                )
            }
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
                if (primaryLabel.isNotBlank() || date.isNotBlank()) {
                    Row(
                        modifier = Modifier.widthIn(max = 140.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (primaryLabel.isNotBlank()) {
                            MaterialText(
                                text = primaryLabel,
                                style = MaterialTheme.typography.labelSmall.copy(shadow = textShadow),
                                color = Color.White.copy(alpha = 0.9f),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                textDecoration = if (authorClick != null) {
                                    TextDecoration.Underline
                                } else {
                                    TextDecoration.None
                                },
                                modifier = Modifier
                                    .weight(1f, fill = false)
                                    .then(
                                        if (authorClick != null) {
                                            Modifier
                                                .minimumInteractiveComponentSize()
                                                .clickable { authorClick(item) }
                                        } else {
                                            Modifier
                                        },
                                    ),
                            )
                        }
                        if (date.isNotBlank()) {
                            MaterialText(
                                text = if (primaryLabel.isNotBlank()) " · $date" else date,
                                style = MaterialTheme.typography.labelSmall.copy(shadow = textShadow),
                                color = Color.White.copy(alpha = 0.9f),
                                maxLines = 1,
                            )
                        }
                    }
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

/**
 * Store tile that shows the complete preview image with [ContentScale.Fit], sized to the
 * preview's own aspect ratio so it fills the card instead of being cropped. Landscape previews
 * keep a wide ratio and are reported to the host, which lets them span both grid columns.
 */
@Composable
internal fun ThemeGridCardMaterial(
    item: ThemeStoreItem,
    state: ThemeStoreUiState,
    onSelect: (ThemeStoreItem) -> Unit,
    onDownload: (ThemeStoreItem) -> Unit,
    modifier: Modifier = Modifier,
    sourceLabel: String? = null,
    onLandscapePreviewChange: ((Boolean) -> Unit)? = null,
) {
    val entry = item.entry
    val context = LocalContext.current
    val downloading = state.downloadingKey == item.key
    val date = entry.updatedAt.substringBefore('T').replace('-', '/')
    val primaryLabel = sourceLabel ?: entry.author
    val meta = listOf(primaryLabel, date).filter { it.isNotBlank() }.joinToString(" · ")
    val textShadow = Shadow(
        color = Color.Black.copy(alpha = 0.6f),
        blurRadius = 10f,
    )
    val previewUrl = remember(entry.previewPath, entry.screenshotPaths, item.source.baseUrl) {
        val path = entry.previewPath.ifBlank { entry.screenshotPaths.firstOrNull().orEmpty() }
        ThemeStoreRepository.assetUrl(item.source.baseUrl, path)
    }
    val painter = previewUrl?.let { url ->
        rememberAsyncImagePainter(themeImageRequest(context, url, item.source.token))
    }
    val intrinsic = painter?.intrinsicSize
    val rawAspectRatio = if (intrinsic != null && intrinsic.width > 0f && intrinsic.height > 0f) {
        intrinsic.height / intrinsic.width
    } else {
        null
    }
    LaunchedEffect(rawAspectRatio) {
        if (rawAspectRatio != null) {
            onLandscapePreviewChange?.invoke(rawAspectRatio < 1f)
        }
    }
    val aspectRatio = when {
        rawAspectRatio == null -> 1.5f
        // Landscape previews span both columns, so keep their own wide ratio instead of
        // squeezing them into a portrait tile.
        rawAspectRatio < 1f -> rawAspectRatio.coerceIn(0.5f, 0.95f)
        else -> rawAspectRatio.coerceIn(1.15f, 2.1f)
    }
    // Only pay for the blurred backdrop when the fitted image cannot fill the tile itself.
    val showBackdrop = rawAspectRatio != null &&
        kotlin.math.abs(rawAspectRatio - aspectRatio) > 0.02f

    Card(
        onClick = { onSelect(item) },
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1f / aspectRatio),
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
            if (painter != null) {
                // Square or landscape previews cannot fill a portrait tile on their own, so the
                // same image is repeated as a dimmed, blurred backdrop underneath the full image.
                if (showBackdrop) {
                    Image(
                        painter = painter,
                        contentDescription = null,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier
                            .fillMaxSize()
                            .blur(18.dp),
                    )
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(Color.Black.copy(alpha = 0.38f)),
                    )
                }
                Image(
                    painter = painter,
                    contentDescription = entry.name,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.fillMaxSize(),
                )
            } else {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh),
                    contentAlignment = Alignment.Center,
                ) {
                    MaterialIcon(
                        imageVector = Icons.Rounded.Palette,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(32.dp),
                    )
                }
            }
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        Brush.verticalGradient(
                            0.42f to Color.Transparent,
                            0.72f to Color.Black.copy(alpha = 0.34f),
                            1f to Color.Black.copy(alpha = 0.82f),
                        ),
                    ),
            )
            if (item.isR18Theme() || item.isAdaptiveTheme()) {
                Column(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(8.dp),
                    horizontalAlignment = Alignment.End,
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    if (item.isR18Theme()) {
                        ThemeR18Badge()
                    }
                    if (item.isAdaptiveTheme()) {
                        AdaptiveThemeBadge(compact = true)
                    }
                }
            }
            Column(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                ThemeStoreStatBadge(
                    icon = Icons.Rounded.FlashOn,
                    value = entry.heat,
                    contentDescription = stringResource(R.string.theme_store_heat),
                )
                ThemeStoreStatBadge(
                    icon = Icons.Rounded.FileDownload,
                    value = entry.downloads,
                    contentDescription = stringResource(R.string.theme_store_downloads),
                )
            }
            Column(
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .fillMaxWidth()
                    .padding(start = 10.dp, top = 8.dp, end = 8.dp, bottom = 8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                MaterialText(
                    text = entry.name,
                    style = MaterialTheme.typography.titleSmall.copy(shadow = textShadow),
                    color = Color.White,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    MaterialText(
                        text = meta,
                        style = MaterialTheme.typography.labelSmall.copy(shadow = textShadow),
                        color = Color.White.copy(alpha = 0.9f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    MaterialIconButton(
                        onClick = { onDownload(item) },
                        enabled = state.downloadingKey == null,
                        colors = IconButtonDefaults.iconButtonColors(
                            containerColor = Color.White.copy(alpha = 0.22f),
                            contentColor = Color.White,
                            disabledContainerColor = Color.White.copy(alpha = 0.12f),
                            disabledContentColor = Color.White.copy(alpha = 0.5f),
                        ),
                    ) {
                        if (downloading) {
                            CircularWavyProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                color = Color.White,
                                trackColor = Color.Transparent,
                                stroke = Stroke(width = 2f),
                            )
                        } else {
                            MaterialIcon(
                                imageVector = Icons.Rounded.FileDownload,
                                contentDescription = stringResource(R.string.theme_store_download),
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ThemeStoreStatBadge(
    icon: ImageVector,
    value: Long,
    contentDescription: String,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .background(
                color = Color.Black.copy(alpha = 0.46f),
                shape = MaterialTheme.shapes.small,
            )
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        MaterialIcon(
            imageVector = icon,
            contentDescription = contentDescription,
            tint = Color.White.copy(alpha = 0.86f),
            modifier = Modifier.size(13.dp),
        )
        MaterialText(
            text = formatStoreCount(value),
            style = MaterialTheme.typography.labelSmall,
            color = Color.White,
        )
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
private fun ThemeStoreMaintenanceMaterial(
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
        MaterialIcon(
            imageVector = Icons.Rounded.Warning,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(40.dp),
        )
        Spacer(Modifier.height(12.dp))
        MaterialText(
            text = stringResource(R.string.theme_store_maintenance_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.height(6.dp))
        MaterialText(
            text = stringResource(R.string.theme_store_maintenance_message),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = onRetry,
            shapes = ButtonDefaults.shapes(),
        ) {
            MaterialText(stringResource(R.string.theme_store_retry))
        }
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
