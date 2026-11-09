package com.sukisu.ultra.ui.screen.themestore

import android.app.Application
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import androidx.exifinterface.media.ExifInterface
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.AccountHistoryItem
import com.sukisu.ultra.data.model.AccountMessageConversation
import com.sukisu.ultra.data.model.AccountMessagesResponse
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.model.AccountSubmission
import com.sukisu.ultra.data.model.AccountThemeSummary
import com.sukisu.ultra.data.model.AccountUserSummary
import com.sukisu.ultra.data.model.ThemeComment
import com.sukisu.ultra.data.model.ThemeStoreEntry
import com.sukisu.ultra.data.repository.AccountRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.data.repository.ThemeCatalogLoad
import com.sukisu.ultra.data.repository.ThemeStoreDefaults
import com.sukisu.ultra.data.repository.ThemeStoreHistoryEntry
import com.sukisu.ultra.data.repository.ThemeStoreHistoryKind
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import com.sukisu.ultra.data.repository.ThemeStoreConsentStore
import com.sukisu.ultra.data.repository.ThemeStoreSubmission
import com.sukisu.ultra.data.repository.ThemeStoreUnauthorizedException
import com.sukisu.ultra.ui.util.ThemePackageStorage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.util.Locale
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import androidx.core.graphics.scale
import kotlin.time.Duration.Companion.milliseconds

data class ThemeStoreSource(
    val id: String,
    val name: String,
    val baseUrl: String,
    val token: String,
    val adminUrl: String = "",
    val isDefault: Boolean = false,
)


data class ThemeStoreAccount(
    val source: ThemeStoreSource,
    val session: AccountSession,
) {
    val key: String get() = source.baseUrl
}


data class UserTheme(
    val theme: AccountThemeSummary,
    val account: ThemeStoreAccount,
) {
    val key: String get() = "${account.key}:${theme.id}"
}


data class UserMessageConversation(
    val conversation: AccountMessageConversation,
    val account: ThemeStoreAccount,
) {
    val key: String get() = "${account.key}:${conversation.themeId}"
}


data class UserSubmission(
    val submission: AccountSubmission,
    val account: ThemeStoreAccount,
) {
    val key: String get() = "${account.key}:${submission.submissionId.ifBlank { submission.id }}"
}

data class ThemeStoreItem(
    val entry: ThemeStoreEntry,
    val source: ThemeStoreSource,
) {
    val key: String get() = "${source.id}:${entry.id}"
}

data class DownloadedTheme(
    val item: ThemeStoreItem,
    val file: File,
    val trial: Boolean = false,
)

data class ThemeStoreUploadInput(
    val id: String,
    val version: String,
    val name: String,
    val author: String,
    val authorId: String,
    /** Reason entered when this submission creates the author licence. */
    val authorApplyNote: String = "",
    val description: String,
    val tags: String,
    val license: String,
    val minManagerVersion: String,
    val changelog: String,
    val packageUri: Uri,
    val previewUri: Uri,
    val avatarUri: Uri? = null,
    val screenshotUris: List<Uri> = emptyList(),
)

enum class ThemeStoreUploadPhase {
    IDLE,
    PREPARING,
    UPLOADING,
    VERIFYING,
    PENDING,
    PUBLISHED,
    FAILED,
}

data class ThemeStoreUploadResult(
    val themeId: String,
    val submissionId: String,
    val pending: Boolean,
    val autoApproved: Boolean,
    val sha256: String,
    val message: String,
)

/** Existing files of the theme being edited, downloaded so the form starts complete. */
data class ThemeStoreEditPrefill(
    val themeId: String = "",
    val loading: Boolean = false,
    val error: String? = null,
    val packageUri: Uri? = null,
    val previewUri: Uri? = null,
    val avatarUri: Uri? = null,
    val screenshotUris: List<Uri> = emptyList(),
)

data class ThemeStoreUiState(
    val loaded: Boolean = false,
    val loading: Boolean = false,
    val refreshing: Boolean = false,
    val needsConsent: Boolean = true,
    val showR18: Boolean = false,
    val gridLayout: Boolean = true,
    val followedAuthorKeys: Set<String> = emptySet(),
    val followError: String? = null,
    val items: List<ThemeStoreItem> = emptyList(),
    val sources: List<ThemeStoreSource> = emptyList(),
    val viewedHistory: List<ThemeStoreHistoryEntry> = emptyList(),
    val downloadedHistory: List<ThemeStoreHistoryEntry> = emptyList(),
    val historyLoading: Boolean = false,
    val historyError: String? = null,
    val historyLoginRequired: Boolean = false,
    val fromCache: Boolean = false,
    val maintenance: Boolean = false,
    val failedSources: Int = 0,
    val unauthorized: Boolean = false,
    val error: Boolean = false,
    val needsConfig: Boolean = false,
    val downloadingKey: String? = null,
    val downloadTrial: Boolean = false,
    val downloadProgress: Float = 0f,
    val downloadTransferredBytes: Long = 0L,
    val downloadTotalBytes: Long = 0L,
    val downloadSpeedBytesPerSecond: Long = 0L,
    val downloadEtaSeconds: Long? = null,
    val downloaded: DownloadedTheme? = null,
    val verifiedThemeKey: String? = null,
    val downloadFailed: Boolean = false,
    val submitting: Boolean = false,
    val uploadError: String? = null,
    val uploadSubmitted: Boolean = false,
    val uploadAutoApproved: Boolean = false,
    val uploadedThemeId: String? = null,
    val uploadThemeId: String? = null,
    val uploadOptionsBaseUrl: String? = null,
    val editPrefill: ThemeStoreEditPrefill? = null,
    val accounts: List<ThemeStoreAccount> = emptyList(),
    val uploadOptionsLoading: Boolean = false,
    val uploadOptionsError: String? = null,
    val uploadPhase: ThemeStoreUploadPhase = ThemeStoreUploadPhase.IDLE,
    val uploadProgress: Float = 0f,
    val uploadTransferredBytes: Long = 0L,
    val uploadTotalBytes: Long = 0L,
    val uploadSpeedBytesPerSecond: Long = 0L,
    val uploadEtaSeconds: Long? = null,
    val uploadResult: ThemeStoreUploadResult? = null,
    val userThemes: List<UserTheme> = emptyList(),
    val submissions: List<UserSubmission> = emptyList(),
    val submissionsLoading: Boolean = false,
    val submissionsError: String? = null,
    val withdrawnThemes: List<UserTheme> = emptyList(),
    val withdrawingThemeKey: String? = null,
    val withdrawError: String? = null,
    val restoringThemeKey: String? = null,
    val restoreError: String? = null,
    val commentsThemeKey: String? = null,
    val comments: List<ThemeComment> = emptyList(),
    val commentsLoading: Boolean = false,
    val commentsError: String? = null,
    val commentsSending: Boolean = false,
    val commentsSentCount: Long = 0L,
    val commentReplyTarget: ThemeComment? = null,
    val commentVisibility: String = "public",
    val commentsRetentionDays: Long = 0L,
    val commentsIsThemeAuthor: Boolean = false,
    val commentsIsAdmin: Boolean = false,
    val mentionUsers: List<AccountUserSummary> = emptyList(),
    val mentionLoading: Boolean = false,
    val mentionError: String? = null,
    val mentionQuery: String = "",
    val messages: List<UserMessageConversation> = emptyList(),
    val messagesLoading: Boolean = false,
    val messagesError: String? = null,
    val messagesSending: Boolean = false,
    val messagesRetentionDays: Long = 0L,
)

private data class PreparedThemeUpload(
    val submission: ThemeStoreSubmission,
    val workDir: File,
)

private data class SourceContent(
    val account: ThemeStoreAccount,
    val themes: Result<List<AccountThemeSummary>>,
    val submissions: Result<List<AccountSubmission>>,
)

@Suppress("SpellCheckingInspection")
class ThemeStoreViewModel(application: Application) : AndroidViewModel(application) {
    private companion object {
        const val MAX_IMAGE_INPUT_BYTES = 12L * 1024L * 1024L
        const val MAX_IMAGE_BYTES = 2L * 1024L * 1024L
        const val MAX_SCREENSHOTS = 6
        const val PREVIEW_MAX_EDGE = 1280
        const val AVATAR_MAX_EDGE = 256
        const val SCREENSHOT_MAX_EDGE = 1080
        const val WEBP_QUALITY = 80
        val THEME_ID_PATTERN = Regex("^[a-z0-9][a-z0-9-]{0,63}$")
        val AUTHOR_ID_PATTERN = Regex("^[A-Za-z0-9._~-]{16,128}$")
    }

    private val repository = ThemeStoreRepository(application)
    private val settings = SettingsRepositoryImpl()
    private val account = AccountRepository(application)
    private val consentStore = ThemeStoreConsentStore(application)
    private val initialConsent = consentStore.read()
    private var historyJob: kotlinx.coroutines.Job? = null
    private var editPrefillJob: kotlinx.coroutines.Job? = null
    private var followsJob: kotlinx.coroutines.Job? = null
    private var loadJob: kotlinx.coroutines.Job? = null
    private var preferencesPushJob: kotlinx.coroutines.Job? = null
    private var preferencesPullJob: kotlinx.coroutines.Job? = null
    private var localPreferenceRevision = 0L
    private var preferencesSyncedAccounts: String? = null
    private val preferencesSyncLock = Mutex()
    private var mentionRequestSeq = 0L
    private val _uiState = MutableStateFlow(
        ThemeStoreUiState(
            gridLayout = settings.themeStoreGridLayout,
            needsConsent = initialConsent == null,
            showR18 = initialConsent?.showR18 == true,
        ),
    )
    val uiState: StateFlow<ThemeStoreUiState> = _uiState.asStateFlow()

    init {
        if (initialConsent != null) {
            load()
        }
        viewModelScope.launch {
            while (true) {
                kotlinx.coroutines.delay((10 * 60 * 1000L).milliseconds)
                if (!_uiState.value.needsConsent) {
                    load()
                }
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            repository.cleanupStaleCache()
        }
    }

    fun load() {
        val current = _uiState.value
        if (current.needsConsent) return
        if (current.loading || current.refreshing) return

        account.reload()
        val sources = configuredSources()
        val accounts = accountsFor(sources)
        if (sources.isEmpty()) {
            _uiState.update {
                it.copy(
                    loaded = true,
                    loading = false,
                    refreshing = false,
                    items = emptyList(),
                    sources = emptyList(),
                    accounts = emptyList(),
                    fromCache = false,
                    maintenance = false,
                    failedSources = 0,
                    unauthorized = false,
                    error = false,
                    needsConfig = true,
                    followedAuthorKeys = emptySet(),
                )
            }
            return
        }

        val hasItems = current.items.isNotEmpty()
        _uiState.update {
            it.copy(
                loading = !hasItems,
                refreshing = hasItems,
                error = false,
                unauthorized = false,
                failedSources = 0,
                needsConfig = false,
                sources = sources,
                accounts = accounts,
            )
        }
        refreshFollows(accounts)
        loadJob = viewModelScope.launch {
            // Apply the web R18 choice before the catalog becomes visible, so a stale local
            // choice cannot briefly reveal adult themes after sign-in. A slow mirror must not
            // hold the store hostage; fall back to the local value after a short wait.
            withTimeoutOrNull(5_000.milliseconds) {
                preferencesSyncLock.withLock {
                    syncPreferencesNow(accounts, force = false)
                }
            }
            val results = sources
                .map { source -> async { loadSource(source) } }
                .awaitAll()
            val successes = results.filter { it.second.isSuccess }
            val catalogs = successes.map { (source, result) -> source to result.getOrThrow() }
            val sourceOrder = sources.mapIndexed { index, source -> source.id to index }.toMap()
            val liveCatalogs = catalogs.filterNot { it.second.fromCache }
            val maintenanceCatalogs = liveCatalogs.ifEmpty { catalogs }
            val maintenance = maintenanceCatalogs.isNotEmpty() &&
                maintenanceCatalogs.all { it.second.catalog.maintenance }
            val items = catalogs
                .filterNot { it.second.catalog.maintenance }
                .flatMap { (source, load) ->
                    load.catalog.themes.map { ThemeStoreItem(it, source) }
                }
                .distinctBy { it.key }
                .sortedWith(
                    compareBy(
                        { sourceOrder[it.source.id] ?: Int.MAX_VALUE },
                        { it.entry.name.lowercase() },
                    ),
                )
            val failures = results.size - successes.size
            val unauthorized = successes.isEmpty() &&
                results.any { it.second.exceptionOrNull() is ThemeStoreUnauthorizedException }
            _uiState.update { state ->
                state.copy(
                    loaded = true,
                    loading = false,
                    refreshing = false,
                    items = items,
                    sources = results.map { it.first },
                    accounts = accounts,
                    fromCache = successes.any { it.second.getOrThrow().fromCache },
                    maintenance = maintenance,
                    failedSources = failures,
                    unauthorized = unauthorized,
                    error = successes.isEmpty(),
                    needsConfig = false,
                )
            }
        }
    }

    /**
     * Loads one source, walking the regional mirror chain (primary → secondary →
     * tertiary) until one answers without a cached body. The returned source
     * carries the host that answered, so downloads and uploads stay on it.
     */
    private suspend fun loadSource(
        source: ThemeStoreSource,
    ): Pair<ThemeStoreSource, Result<ThemeCatalogLoad>> {
        val first = fetchSource(source, source.baseUrl)
        if (first.second.getOrNull()?.fromCache == false) {
            ThemeStoreDefaults.reportReachable(source.baseUrl)
            return first
        }
        // An authentication failure is not a connectivity problem; retrying on
        // another mirror would hide the real error.
        if (first.second.exceptionOrNull() is ThemeStoreUnauthorizedException) return first
        var previousBase = source.baseUrl
        var nextBase = ThemeStoreDefaults.fallbackBaseUrl(previousBase)
        var best = first
        while (nextBase != null) {
            // Mark only the mirror that just failed so the next launch starts from
            // the top of the chain again once its cooldown expires.
            ThemeStoreDefaults.reportUnreachable(previousBase)
            val attempt = fetchSource(source, nextBase)
            if (attempt.second.getOrNull()?.fromCache == false) {
                ThemeStoreDefaults.reportReachable(nextBase)
                return attempt
            }
            if (best.second.isSuccess.not() && attempt.second.isSuccess) best = attempt
            previousBase = nextBase
            nextBase = ThemeStoreDefaults.fallbackBaseUrl(nextBase)
        }
        return best
    }

    private suspend fun fetchSource(
        source: ThemeStoreSource,
        baseUrl: String,
    ): Pair<ThemeStoreSource, Result<ThemeCatalogLoad>> {
        val credential = repository.accessToken(baseUrl, source.token)
        val resolved = source.copy(baseUrl = baseUrl, token = credential.getOrNull() ?: source.token)
        return resolved to credential.fold(
            onSuccess = { repository.loadCatalog(baseUrl, it) },
            onFailure = { Result.failure(it) },
        )
    }

    fun setGridLayout(enabled: Boolean) {
        if (_uiState.value.gridLayout == enabled) return
        settings.themeStoreGridLayout = enabled
        _uiState.update { it.copy(gridLayout = enabled) }
    }

    fun acceptConsent() {
        val record = consentStore.accept(showR18 = _uiState.value.showR18)
        _uiState.update { it.copy(needsConsent = false, showR18 = record.showR18) }
        // load() pulls the web choice before showing the catalog, so the agreement is accepted
        // first on every install while an existing web R18 preference still wins afterwards.
        load()
    }

    fun revokeConsent() {
        consentStore.revoke()
        loadJob?.cancel()
        loadJob = null
        followsJob?.cancel()
        followsJob = null
        preferencesPullJob?.cancel()
        preferencesPullJob = null
        preferencesPushJob?.cancel()
        preferencesPushJob = null
        preferencesSyncedAccounts = null
        // Clear the server consent record without overwriting an R18 choice made on the web.
        pushPreferences(showR18 = null, consentVersion = 0L)
        // The next agreement acceptance must pull the web preference again.
        preferencesSyncedAccounts = null
        _uiState.update {
            it.copy(
                needsConsent = true,
                showR18 = false,
                loaded = false,
                loading = false,
                refreshing = false,
                items = emptyList(),
                followedAuthorKeys = emptySet(),
                fromCache = false,
                maintenance = false,
                failedSources = 0,
                unauthorized = false,
                error = false,
                needsConfig = false,
                downloadingKey = null,
                downloadFailed = false,
                downloadTrial = false,
                verifiedThemeKey = null,
            )
        }
    }

    fun setShowR18(enabled: Boolean) {
        val record = consentStore.updateShowR18(enabled) ?: return
        _uiState.update { it.copy(showR18 = enabled) }
        pushPreferences(record.showR18, record.version.toLong())
    }

    /**
     * Uploads the device-local agreement (and an explicit R18 choice) to every signed-in mirror.
     */
    private fun pushPreferences(showR18: Boolean?, consentVersion: Long) {
        if (consentVersion > 0 && _uiState.value.needsConsent) return
        val accounts = _uiState.value.accounts
        if (accounts.isEmpty()) return
        val syncKey = accountsSyncKey(accounts)
        // A local change is authoritative until the next explicit resume sync; otherwise a
        // refresh racing with this upload could read the old server value and undo the toggle.
        preferencesSyncedAccounts = syncKey
        preferencesPullJob?.cancel()
        localPreferenceRevision += 1
        val revision = localPreferenceRevision
        preferencesPushJob?.cancel()
        preferencesPushJob = viewModelScope.launch {
            preferencesSyncLock.withLock {
                if (revision != localPreferenceRevision) return@withLock
                if (consentVersion > 0 && _uiState.value.needsConsent) return@withLock
                if (syncKey != accountsSyncKey(_uiState.value.accounts)) return@withLock
                accounts.forEach { entry ->
                    if (revision != localPreferenceRevision) return@withLock
                    account.savePreferences(entry.source.baseUrl, showR18, consentVersion)
                }
            }
        }
    }

    private fun accountsSyncKey(accounts: List<ThemeStoreAccount>): String =
        accounts.joinToString("|") { "${it.source.baseUrl}:${it.session.user.id}" }

    /**
     * Pulls the web content preference after sign-in. An explicit web R18 choice wins over the
     * local switch; when no account has set one yet, the local value is uploaded so the account
     * starts in sync. Device-local agreement acceptance is still required first, so uninstalling
     * the manager always asks for consent again.
     */
    private fun syncPreferencesFromServer(
        accounts: List<ThemeStoreAccount>,
        force: Boolean,
    ) {
        if (accounts.isEmpty()) {
            preferencesSyncedAccounts = null
            return
        }
        if (!force && accountsSyncKey(accounts) == preferencesSyncedAccounts) return
        preferencesPullJob?.cancel()
        preferencesPullJob = viewModelScope.launch {
            preferencesSyncLock.withLock {
                syncPreferencesNow(accounts, force)
            }
        }
    }

    private suspend fun syncPreferencesNow(
        accounts: List<ThemeStoreAccount>,
        force: Boolean,
    ) {
        if (accounts.isEmpty()) {
            preferencesSyncedAccounts = null
            return
        }
        val syncKey = accountsSyncKey(accounts)
        if (!force && syncKey == preferencesSyncedAccounts) return
        val local = consentStore.read() ?: return
        val revision = localPreferenceRevision
        var remoteShowR18: Boolean? = null
        var reachable = false
        val accountsWithoutPreference = mutableSetOf<String>()
        for (entry in accounts) {
            if (revision != localPreferenceRevision) return
            val response = account.getPreferences(entry.source.baseUrl).getOrNull()
                ?: continue
            reachable = true
            if (response.showR18Set) {
                remoteShowR18 = response.showR18
                break
            }
            accountsWithoutPreference += entry.source.baseUrl
        }
        if (!reachable ||
            revision != localPreferenceRevision ||
            _uiState.value.needsConsent
        ) {
            return
        }
        if (remoteShowR18 != null) {
            val value = remoteShowR18
            if (local.showR18 != value && consentStore.updateShowR18(value) != null) {
                _uiState.update { state ->
                    if (state.needsConsent) state else state.copy(showR18 = value)
                }
            }
        }
        val current = consentStore.read() ?: return
        if (revision != localPreferenceRevision) return
        // Never overwrite an explicit web choice; only upload the local R18 value to servers
        // that have no preference yet. Accounts whose GET failed are left untouched.
        accounts.forEach { entry ->
            if (revision != localPreferenceRevision) return
            val baseUrl = entry.source.baseUrl
            val serverHasNoChoice = baseUrl in accountsWithoutPreference
            if (remoteShowR18 == null && !serverHasNoChoice) return@forEach
            val showR18 = if (remoteShowR18 == null) current.showR18 else null
            account.savePreferences(baseUrl, showR18, current.version.toLong())
        }
        if (revision == localPreferenceRevision) {
            preferencesSyncedAccounts = syncKey
        }
    }

    fun refreshAccounts() {
        account.reload()
        val sources = configuredSources()
        val accounts = accountsFor(sources)
        _uiState.update {
            it.copy(sources = sources, accounts = accounts)
        }
        refreshFollows(accounts)
        // ON_RESUME also runs after returning from the account screen or the web, so re-read the
        // server choice here even when the signed-in account set itself did not change.
        syncPreferencesFromServer(accounts, force = true)
    }

    fun hasAccountFor(baseUrl: String): Boolean =
        _uiState.value.accounts.any { it.source.baseUrl == baseUrl }

    fun toggleFollow(item: ThemeStoreItem) {
        val authorHash = item.entry.authorHash.trim()
        if (authorHash.isEmpty()) return
        val baseUrl = item.source.baseUrl
        val key = themeFollowKey(baseUrl, authorHash)
        if (key.isEmpty()) return
        val currentlyFollowing = key in _uiState.value.followedAuthorKeys
        _uiState.update {
            it.copy(
                followedAuthorKeys = if (currentlyFollowing) {
                    it.followedAuthorKeys - key
                } else {
                    it.followedAuthorKeys + key
                },
                followError = null,
            )
        }
        viewModelScope.launch {
            account.setFollow(baseUrl, authorHash, follow = !currentlyFollowing)
                .onFailure { error ->
                    // Revert the optimistic update and surface the server/network error.
                    _uiState.update {
                        it.copy(
                            followedAuthorKeys = if (currentlyFollowing) {
                                it.followedAuthorKeys + key
                            } else {
                                it.followedAuthorKeys - key
                            },
                            followError = error.message,
                        )
                    }
                }
        }
    }

    fun clearFollowError() {
        _uiState.update { it.copy(followError = null) }
    }

    private fun refreshFollows(accounts: List<ThemeStoreAccount>) {
        if (accounts.isEmpty()) {
            _uiState.update { it.copy(followedAuthorKeys = emptySet()) }
            return
        }
        followsJob?.cancel()
        followsJob = viewModelScope.launch {
            val keys = mutableSetOf<String>()
            for (entry in accounts) {
                account.follows(entry.source.baseUrl).getOrNull()?.authors?.forEach { author ->
                    val key = themeFollowKey(entry.source.baseUrl, author.authorHash)
                    if (key.isNotEmpty()) keys += key
                }
            }
            _uiState.update { it.copy(followedAuthorKeys = keys) }
        }
    }

    
    fun setUploadSourcePreference(baseUrl: String) {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(baseUrl) ?: return
        val defaultBase = configuredSources().firstOrNull { it.isDefault }?.baseUrl
        settings.themeStoreUploadSource = if (normalized == defaultBase) "" else normalized
    }

    /**
     * Resolves the account used without prompting: saved preference first, then the default
     * source, then any logged-in account when the preferred one is unavailable.
     */
    fun preferredUploadAccount(): ThemeStoreAccount? {
        account.reload()
        val sources = configuredSources()
        val accounts = accountsFor(sources)
        _uiState.update {
            it.copy(sources = sources, accounts = accounts)
        }
        val defaultBase = sources.firstOrNull { it.isDefault }?.baseUrl.orEmpty()
        val preferredBase = settings.themeStoreUploadSource.ifBlank { defaultBase }
        return accounts.preferredUploadAccount(preferredBase, defaultBase)
    }

    private fun accountsFor(sources: List<ThemeStoreSource>): List<ThemeStoreAccount> =
        sources.mapNotNull { source ->
            account.sessionFor(source.baseUrl)?.let { session ->
                ThemeStoreAccount(source, session)
            }
        }

    private fun historyEntry(source: ThemeStoreSource, item: AccountHistoryItem): ThemeStoreHistoryEntry =
        ThemeStoreHistoryEntry(
            key = "${source.id}#${item.id}",
            themeId = item.themeId,
            name = item.themeName,
            author = item.themeAuthor,
            sourceId = source.id,
            baseUrl = source.baseUrl,
            previewPath = item.themePreviewPath,
            createdAt = runCatching {
                java.time.Instant.parse(item.createdAt).toEpochMilli()
            }.getOrDefault(0L),
            r18 = item.r18,
            adaptive = item.themeAdaptive,
        )

    /** History lives on the account: record every view/download for the matching source. */
    fun recordView(item: ThemeStoreItem) {
        if (!hasAccountFor(item.source.baseUrl)) return
        viewModelScope.launch {
            account.recordThemeHistory(
                item.source.baseUrl,
                ThemeStoreHistoryKind.VIEWED.apiKind,
                item.entry.id,
            )
        }
    }

    private fun recordDownload(item: ThemeStoreItem) {
        if (!hasAccountFor(item.source.baseUrl)) return
        viewModelScope.launch {
            account.recordThemeHistory(
                item.source.baseUrl,
                ThemeStoreHistoryKind.DOWNLOADED.apiKind,
                item.entry.id,
            )
        }
    }

    fun refreshHistory() {
        historyJob?.cancel()
        historyJob = viewModelScope.launch {
            account.reload()
            val accounts = accountsFor(configuredSources())
            if (accounts.isEmpty()) {
                _uiState.update {
                    it.copy(
                        historyLoading = false,
                        historyError = null,
                        historyLoginRequired = true,
                        viewedHistory = emptyList(),
                        downloadedHistory = emptyList(),
                    )
                }
                return@launch
            }
            _uiState.update {
                it.copy(historyLoading = true, historyError = null, historyLoginRequired = false)
            }
            val viewed = mutableListOf<ThemeStoreHistoryEntry>()
            val downloaded = mutableListOf<ThemeStoreHistoryEntry>()
            var failure: String? = null
            accounts.forEach { entry ->
                val source = entry.source
                account.themeHistory(source.baseUrl, ThemeStoreHistoryKind.VIEWED.apiKind).fold(
                    onSuccess = { items -> viewed += items.map { historyEntry(source, it) } },
                    onFailure = { failure = it.message },
                )
                account.themeHistory(source.baseUrl, ThemeStoreHistoryKind.DOWNLOADED.apiKind).fold(
                    onSuccess = { items -> downloaded += items.map { historyEntry(source, it) } },
                    onFailure = { failure = it.message },
                )
            }
            _uiState.update {
                it.copy(
                    historyLoading = false,
                    historyError = if (viewed.isEmpty() && downloaded.isEmpty()) failure else null,
                    viewedHistory = viewed.sortedByDescending { item -> item.createdAt }.take(100),
                    downloadedHistory = downloaded.sortedByDescending { item -> item.createdAt }.take(100),
                )
            }
        }
    }

    fun clearEditPrefill() {
        editPrefillJob?.cancel()
        _uiState.update { it.copy(editPrefill = null) }
    }

    /**
     * The edit form starts from the theme that is already published: download its
     * package plus every image so the author only changes what they want to change.
     */
    fun loadEditPrefill(theme: AccountThemeSummary, baseUrl: String) {
        editPrefillJob?.cancel()
        _uiState.update {
            it.copy(editPrefill = ThemeStoreEditPrefill(themeId = theme.id, loading = true))
        }
        editPrefillJob = viewModelScope.launch {
            val key = "edit-${theme.id}"
            val packageFile = account.downloadMyThemePackage(baseUrl, theme.id).getOrNull()
            val previewFile = editAsset(baseUrl, theme.previewPath, "preview", key)
            val avatarFile = editAsset(baseUrl, theme.avatarPath.orEmpty(), "avatar", key)
            val screenshots = mutableListOf<File>()
            theme.screenshotPaths.forEachIndexed { index, path ->
                editAsset(baseUrl, path, "screenshot-${index + 1}", key)?.let(screenshots::add)
            }
            _uiState.update {
                it.copy(
                    editPrefill = ThemeStoreEditPrefill(
                        themeId = theme.id,
                        loading = false,
                        error = if (packageFile == null || previewFile == null) {
                            getApplication<Application>().getString(
                                R.string.theme_store_edit_prefill_failed,
                            )
                        } else {
                            null
                        },
                        packageUri = packageFile?.let(Uri::fromFile),
                        previewUri = previewFile?.let(Uri::fromFile),
                        avatarUri = avatarFile?.let(Uri::fromFile),
                        screenshotUris = screenshots.map(Uri::fromFile),
                    ),
                )
            }
        }
    }

    private suspend fun editAsset(
        baseUrl: String,
        path: String,
        baseName: String,
        cacheKey: String,
    ): File? {
        if (path.isBlank()) return null
        val ext = path.substringAfterLast('.', "webp").lowercase()
            .takeIf { suffix -> suffix.length in 2..5 && suffix.all(Char::isLetterOrDigit) }
            ?: "webp"
        return account.downloadAccountAsset(baseUrl, path, "$baseName.$ext", cacheKey).getOrNull()
    }

    fun clearHistory(kind: ThemeStoreHistoryKind) {
        viewModelScope.launch {
            accountsFor(configuredSources()).forEach { entry ->
                account.deleteThemeHistory(entry.source.baseUrl, kind.apiKind, all = true)
            }
            refreshHistory()
        }
    }

    fun removeHistory(kind: ThemeStoreHistoryKind, keys: Set<String>) {
        if (keys.isEmpty()) return
        viewModelScope.launch {
            val sources = configuredSources()
            val grouped = keys.mapNotNull { key ->
                val at = key.lastIndexOf('#')
                val sourceId = if (at > 0) key.substring(0, at) else return@mapNotNull null
                val id = key.substring(at + 1).toLongOrNull() ?: return@mapNotNull null
                sourceId to id
            }.groupBy({ it.first }, { it.second })
            grouped.forEach { (sourceId, ids) ->
                val source = sources.firstOrNull { it.id == sourceId } ?: return@forEach
                account.deleteThemeHistory(source.baseUrl, kind.apiKind, ids = ids)
            }
            refreshHistory()
        }
    }

    fun download(item: ThemeStoreItem, trial: Boolean = false) {
        val current = _uiState.value
        if (current.downloadingKey != null) return
        _uiState.update {
            it.copy(
                downloadingKey = item.key,
                downloadTrial = trial,
                downloadProgress = 0f,
                downloadTransferredBytes = 0L,
                downloadTotalBytes = item.entry.size,
                downloadSpeedBytesPerSecond = 0L,
                downloadEtaSeconds = null,
                downloadFailed = false,
                verifiedThemeKey = null,
            )
        }
        viewModelScope.launch {
            var meter: TransferSpeedMeter? = null
            val telemetryLock = Any()
            var lastTelemetryAt = 0L
            repository.downloadTheme(
                entry = item.entry,
                baseUrl = item.source.baseUrl,
                token = item.source.token,
                onProgress = { progress ->
                    _uiState.update { it.copy(downloadProgress = progress) }
                },
                onTransferred = { transferred, total ->
                    synchronized(telemetryLock) {
                        val now = System.nanoTime()
                        val activeMeter = meter
                        if (activeMeter == null || activeMeter.totalBytes != total) {
                            meter = TransferSpeedMeter(total)
                            lastTelemetryAt = now
                            _uiState.update {
                                it.copy(
                                    downloadTransferredBytes = transferred.coerceIn(0L, total),
                                    downloadTotalBytes = total,
                                    downloadSpeedBytesPerSecond = 0L,
                                    downloadEtaSeconds = null,
                                )
                            }
                        } else if (now - lastTelemetryAt >= 200_000_000L ||
                            (total > 0L && transferred >= total)
                        ) {
                            lastTelemetryAt = now
                            val speed = activeMeter.update(transferred, now)
                            _uiState.update {
                                it.copy(
                                    downloadTransferredBytes = transferred.coerceIn(0L, total),
                                    downloadSpeedBytesPerSecond = speed.bytesPerSecond,
                                    downloadEtaSeconds = speed.etaSeconds,
                                )
                            }
                        }
                    }
                },
            ).fold(
                onSuccess = { file ->
                    _uiState.update {
                        it.copy(
                            downloadingKey = null,
                            downloadProgress = 1f,
                            downloadTransferredBytes = item.entry.size,
                            downloadTotalBytes = item.entry.size,
                            downloadSpeedBytesPerSecond = 0L,
                            downloadEtaSeconds = null,
                            downloaded = DownloadedTheme(item, file, trial),
                            verifiedThemeKey = item.key,
                        )
                    }
                    recordDownload(item)
                },
                onFailure = {
                    _uiState.update {
                        it.copy(
                            downloadingKey = null,
                            downloadTrial = false,
                            downloadProgress = 0f,
                            downloadTransferredBytes = 0L,
                            downloadTotalBytes = 0L,
                            downloadSpeedBytesPerSecond = 0L,
                            downloadEtaSeconds = null,
                            downloadFailed = true,
                        )
                    }
                },
            )
        }
    }

    fun consumeDownloaded() {
        _uiState.update { it.copy(downloaded = null, downloadTrial = false) }
    }

    fun clearDownloadError() {
        _uiState.update { it.copy(downloadFailed = false) }
    }

    fun submit(input: ThemeStoreUploadInput, source: ThemeStoreSource) {
        if (_uiState.value.submitting) return
        account.reload()
        val accountSession = account.sessionFor(source.baseUrl)
        if (accountSession == null) {
            _uiState.update {
                it.copy(uploadError = getApplication<Application>().getString(R.string.theme_store_upload_login_required))
            }
            return
        }
        _uiState.update {
            it.copy(
                submitting = true,
                uploadError = null,
                uploadSubmitted = false,
                uploadAutoApproved = false,
                uploadPhase = ThemeStoreUploadPhase.PREPARING,
                uploadProgress = 0f,
                uploadTransferredBytes = 0L,
                uploadTotalBytes = 0L,
                uploadSpeedBytesPerSecond = 0L,
                uploadEtaSeconds = null,
                uploadResult = null,
            )
        }
        viewModelScope.launch {
            var workDir: File? = null
            var uploadMeter: TransferSpeedMeter? = null
            val telemetryLock = Any()
            var lastTelemetryAt = 0L
            try {
                val prepared = prepareUpload(input, accountMode = true)
                workDir = prepared.workDir
                _uiState.update {
                    it.copy(
                        uploadPhase = ThemeStoreUploadPhase.UPLOADING,
                        uploadProgress = 0f,
                    )
                }
                val response = repository
                    .submitTheme(
                        submission = prepared.submission,
                        baseUrl = source.baseUrl,
                        token = source.token,
                        bearerToken = accountSession.token,
                        onProgress = { progress ->
                            _uiState.update { state ->
                                if (state.uploadPhase == ThemeStoreUploadPhase.PREPARING ||
                                    state.uploadPhase == ThemeStoreUploadPhase.UPLOADING
                                ) {
                                    state.copy(
                                        uploadPhase = if (progress >= 1f) {
                                            ThemeStoreUploadPhase.VERIFYING
                                        } else {
                                            ThemeStoreUploadPhase.UPLOADING
                                        },
                                        uploadProgress = progress.coerceIn(0f, 1f),
                                    )
                                } else {
                                    state
                                }
                            }
                        },
                        onTransferred = { transferred, total ->
                            synchronized(telemetryLock) {
                                val now = System.nanoTime()
                                val meter = uploadMeter
                                if (meter == null || meter.totalBytes != total) {
                                    uploadMeter = TransferSpeedMeter(total)
                                    lastTelemetryAt = now
                                    _uiState.update {
                                        it.copy(
                                            uploadTransferredBytes = transferred.coerceIn(0L, total),
                                            uploadTotalBytes = total,
                                            uploadSpeedBytesPerSecond = 0L,
                                            uploadEtaSeconds = null,
                                        )
                                    }
                                } else if (now - lastTelemetryAt >= 200_000_000L ||
                                    (total > 0L && transferred >= total)
                                ) {
                                    lastTelemetryAt = now
                                    val reading = meter.update(transferred, now)
                                    _uiState.update {
                                        it.copy(
                                            uploadTransferredBytes = transferred.coerceIn(0L, total),
                                            uploadSpeedBytesPerSecond = reading.bytesPerSecond,
                                            uploadEtaSeconds = reading.etaSeconds,
                                        )
                                    }
                                }
                            }
                        },
                    )
                    .getOrThrow()
                if (!response.ok) {
                    throw IllegalStateException(
                        response.error.ifBlank {
                            getApplication<Application>().getString(R.string.theme_store_upload_failed)
                        },
                    )
                }
                val message = response.message.ifBlank {
                    getApplication<Application>().getString(
                        if (response.autoApproved) R.string.theme_store_upload_auto_approved
                        else R.string.theme_store_upload_success,
                    )
                }
                _uiState.update {
                    it.copy(
                        submitting = false,
                        uploadSubmitted = true,
                        uploadAutoApproved = response.autoApproved,
                        uploadedThemeId = response.id,
                        uploadError = null,
                        uploadPhase = if (response.autoApproved) {
                            ThemeStoreUploadPhase.PUBLISHED
                        } else {
                            ThemeStoreUploadPhase.PENDING
                        },
                        uploadProgress = 1f,
                        uploadTransferredBytes = it.uploadTotalBytes,
                        uploadSpeedBytesPerSecond = 0L,
                        uploadEtaSeconds = null,
                        uploadResult = ThemeStoreUploadResult(
                            themeId = response.id,
                            submissionId = response.submissionId,
                            pending = response.pending && !response.autoApproved,
                            autoApproved = response.autoApproved,
                            sha256 = response.sha256,
                            message = message,
                        ),
                    )
                }
                account.refreshProfile(source.baseUrl)
                loadUserContent(force = true)
                if (response.autoApproved) {
                    load()
                }
            } catch (error: CancellationException) {
                throw error
            } catch (_: ThemeStoreUnauthorizedException) {
                _uiState.update {
                    it.copy(
                        submitting = false,
                        uploadPhase = ThemeStoreUploadPhase.FAILED,
                        uploadProgress = 0f,
                        uploadSpeedBytesPerSecond = 0L,
                        uploadEtaSeconds = null,
                        uploadError = getApplication<Application>().getString(R.string.theme_store_unauthorized),
                    )
                }
            } catch (error: Exception) {
                _uiState.update {
                    it.copy(
                        submitting = false,
                        uploadPhase = ThemeStoreUploadPhase.FAILED,
                        uploadProgress = 0f,
                        uploadSpeedBytesPerSecond = 0L,
                        uploadEtaSeconds = null,
                        uploadError = error.message?.takeIf { message -> message.isNotBlank() }
                            ?: getApplication<Application>().getString(R.string.theme_store_upload_failed),
                    )
                }
            } finally {
                workDir?.deleteRecursively()
            }
        }
    }

    fun clearUploadState() {
        _uiState.update {
            it.copy(
                uploadError = null,
                uploadSubmitted = false,
                uploadAutoApproved = false,
                uploadPhase = ThemeStoreUploadPhase.IDLE,
                uploadProgress = 0f,
                uploadTransferredBytes = 0L,
                uploadTotalBytes = 0L,
                uploadSpeedBytesPerSecond = 0L,
                uploadEtaSeconds = null,
                uploadResult = null,
            )
        }
    }

    fun consumeUploadSubmitted() {
        _uiState.update {
            it.copy(
                uploadSubmitted = false,
                uploadAutoApproved = false,
                uploadedThemeId = null,
            )
        }
    }

    fun loadUploadOptions(baseUrl: String) {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(baseUrl) ?: return
        val current = _uiState.value
        if (current.uploadOptionsLoading && current.uploadOptionsBaseUrl == normalized) return
        account.reload()
        if (account.sessionFor(normalized) == null) {
            _uiState.update {
                it.copy(
                    uploadOptionsLoading = false,
                    uploadOptionsBaseUrl = normalized,
                    uploadThemeId = null,
                    uploadOptionsError = getApplication<Application>()
                        .getString(R.string.theme_store_upload_login_required),
                )
            }
            return
        }
        _uiState.update {
            it.copy(
                uploadOptionsBaseUrl = normalized,
                uploadOptionsLoading = true,
                uploadOptionsError = null,
                uploadThemeId = null,
            )
        }
        viewModelScope.launch {
            // Refresh the licence list first: the submit dialog decides from it
            // whether the account needs to apply for an author profile.
            account.refreshProfile(normalized)
            val refreshed = account.sessionFor(normalized)
            if (refreshed != null) {
                _uiState.update { state ->
                    state.copy(
                        accounts = state.accounts.map { accountEntry ->
                            if (accountEntry.source.baseUrl == normalized) {
                                accountEntry.copy(session = refreshed)
                            } else {
                                accountEntry
                            }
                        },
                    )
                }
            }
            val idResult = account.nextThemeId(normalized)
            _uiState.update { state ->
                if (state.uploadOptionsBaseUrl != normalized) {
                    state
                } else {
                    state.copy(
                        uploadOptionsLoading = false,
                        uploadThemeId = idResult.getOrNull()?.id,
                        uploadOptionsError = idResult.exceptionOrNull()?.message,
                    )
                }
            }
        }
    }

    
    fun loadUserContent(force: Boolean = false) {
        if (_uiState.value.submissionsLoading && !force) return
        account.reload()
        val sources = configuredSources()
        val accounts = accountsFor(sources)
        _uiState.update { it.copy(sources = sources, accounts = accounts) }
        if (accounts.isEmpty()) {
            _uiState.update {
                it.copy(
                    submissionsLoading = false,
                    userThemes = emptyList(),
                    submissions = emptyList(),
                    withdrawnThemes = emptyList(),
                    submissionsError = getApplication<Application>()
                        .getString(R.string.theme_store_submissions_login_required),
                )
            }
            return
        }
        _uiState.update {
            it.copy(
                submissionsLoading = true,
                submissionsError = null,
            )
        }
        viewModelScope.launch {
            val accountRepository = account
            val results = coroutineScope {
                accounts.map { sourceAccount ->
                    async {
                        SourceContent(
                            account = sourceAccount,
                            themes = accountRepository.myThemes(sourceAccount.source.baseUrl),
                            submissions = accountRepository.mySubmissions(sourceAccount.source.baseUrl),
                        )
                    }
                }.awaitAll()
            }
            val userThemes = results.flatMap { result ->
                result.themes.getOrDefault(emptyList()).map { UserTheme(it, result.account) }
            }
            val userSubmissions = results.flatMap { result ->
                result.submissions.getOrDefault(emptyList()).map {
                    UserSubmission(it, result.account)
                }
            }
            val errors = results.mapNotNull { result ->
                result.themes.exceptionOrNull()?.message
                    ?: result.submissions.exceptionOrNull()?.message
            }
            val remainingAccounts = accountsFor(configuredSources())
            val remainingKeys = remainingAccounts.mapTo(mutableSetOf()) { it.key }
            val visibleThemes = userThemes.filter { it.account.key in remainingKeys }
            val visibleSubmissions = userSubmissions.filter { it.account.key in remainingKeys }
            _uiState.update { state ->
                state.copy(
                    submissionsLoading = false,
                    accounts = remainingAccounts,
                    userThemes = visibleThemes.filter { it.theme.status != "withdrawn" },
                    withdrawnThemes = visibleThemes.filter { it.theme.status == "withdrawn" },
                    submissions = visibleSubmissions,
                    submissionsError = errors.firstOrNull(),
                )
            }
        }
    }

    fun withdrawTheme(submission: UserSubmission) {
        val themeId = submission.submission.id
        if (themeId.isBlank() || _uiState.value.withdrawingThemeKey != null) return
        val key = submission.key
        _uiState.update { it.copy(withdrawingThemeKey = key, withdrawError = null) }
        viewModelScope.launch {
            account.withdrawTheme(themeId, submission.account.source.baseUrl).fold(
                onSuccess = {
                    _uiState.update { it.copy(withdrawingThemeKey = null, withdrawError = null) }
                    loadUserContent(force = true)
                    load()
                },
                onFailure = { error ->
                    _uiState.update {
                        it.copy(
                            withdrawingThemeKey = null,
                            withdrawError = error.message,
                        )
                    }
                },
            )
        }
    }

    fun restoreTheme(theme: UserTheme) {
        val themeId = theme.theme.id
        if (themeId.isBlank() || _uiState.value.restoringThemeKey != null) return
        val key = theme.key
        _uiState.update { it.copy(restoringThemeKey = key, restoreError = null) }
        viewModelScope.launch {
            account.restoreTheme(themeId, theme.account.source.baseUrl).fold(
                onSuccess = {
                    _uiState.update { it.copy(restoringThemeKey = null, restoreError = null) }
                    loadUserContent(force = true)
                    load()
                },
                onFailure = { error ->
                    _uiState.update {
                        it.copy(
                            restoringThemeKey = null,
                            restoreError = error.message,
                        )
                    }
                },
            )
        }
    }

    
    fun loadComments(item: ThemeStoreItem, force: Boolean = false) {
        val current = _uiState.value
        if (current.commentsLoading && !force) return
        if (!force && current.commentsThemeKey == item.key && current.commentsError == null) return
        account.reload()
        val signedIn = account.sessionFor(item.source.baseUrl) != null
        _uiState.update {
            it.copy(
                commentsThemeKey = item.key,
                commentsLoading = true,
                commentsError = null,
                commentReplyTarget = if (signedIn) it.commentReplyTarget else null,
            )
        }
        viewModelScope.launch {
            account.comments(item.source.baseUrl, item.entry.id).fold(
                onSuccess = { response ->
                    _uiState.update { state ->
                        if (state.commentsThemeKey != item.key) {
                            state
                        } else {
                            state.copy(
                                comments = response.comments,
                                commentsLoading = false,
                                commentsError = null,
                                commentsRetentionDays = response.retentionDays,
                                commentsIsThemeAuthor = response.isThemeAuthor,
                                commentsIsAdmin = response.isAdmin,
                                commentReplyTarget = state.commentReplyTarget?.let { target ->
                                    findComment(response.comments, target.id)
                                },
                            )
                        }
                    }
                },
                onFailure = { error ->
                    account.reload()
                    val accounts = accountsFor(configuredSources())
                    val signedIn = account.sessionFor(item.source.baseUrl) != null
                    _uiState.update { state ->
                        if (state.commentsThemeKey != item.key) {
                            state
                        } else {
                            state.copy(
                                commentsLoading = false,
                                commentsError = error.message,
                                accounts = accounts,
                                commentReplyTarget = if (signedIn) {
                                    state.commentReplyTarget
                                } else {
                                    null
                                },
                            )
                        }
                    }
                },
            )
        }
    }

    private fun findComment(comments: List<ThemeComment>, id: String): ThemeComment? {
        comments.forEach { comment ->
            if (comment.id == id) return comment
            findComment(comment.replies, id)?.let { return it }
        }
        return null
    }

    fun setCommentReplyTarget(comment: ThemeComment?) {
        _uiState.update { it.copy(commentReplyTarget = comment) }
    }

    
    fun searchMentionUsers(source: ThemeStoreSource, query: String) {
        val text = query.trim()
        _uiState.update { it.copy(mentionQuery = text) }
        if (text.isEmpty()) {
            _uiState.update {
                it.copy(
                    mentionUsers = emptyList(),
                    mentionLoading = false,
                    mentionError = null,
                )
            }
            return
        }
        val sequence = ++mentionRequestSeq
        _uiState.update { it.copy(mentionLoading = true, mentionError = null) }
        viewModelScope.launch {
            account.searchUsers(source.baseUrl, text).fold(
                onSuccess = { users ->
                    if (sequence != mentionRequestSeq) return@fold
                    _uiState.update {
                        it.copy(
                            mentionUsers = users,
                            mentionLoading = false,
                            mentionError = null,
                        )
                    }
                },
                onFailure = { error ->
                    if (sequence != mentionRequestSeq) return@fold
                    _uiState.update {
                        it.copy(
                            mentionLoading = false,
                            mentionError = error.message,
                        )
                    }
                },
            )
        }
    }

    fun clearMentionSearch() {
        mentionRequestSeq += 1
        _uiState.update {
            it.copy(
                mentionUsers = emptyList(),
                mentionLoading = false,
                mentionError = null,
                mentionQuery = "",
            )
        }
    }

    fun setCommentVisibility(value: String) {
        val visibility = if (value == "author") "author" else "public"
        _uiState.update { it.copy(commentVisibility = visibility) }
    }

    fun sendComment(item: ThemeStoreItem, content: String) {
        val text = content.trim()
        val state = _uiState.value
        if (text.isEmpty() || state.commentsSending) return
        account.reload()
        if (account.sessionFor(item.source.baseUrl) == null) {
            _uiState.update {
                it.copy(
                    commentsError = getApplication<Application>()
                        .getString(R.string.theme_store_upload_login_required),
                )
            }
            return
        }
        _uiState.update { it.copy(commentsSending = true, commentsError = null) }
        viewModelScope.launch {
            account.postComment(
                baseUrl = item.source.baseUrl,
                themeId = item.entry.id,
                content = text,
                visibility = state.commentVisibility,
                parentId = state.commentReplyTarget?.id,
            ).fold(
                onSuccess = {
                    _uiState.update {
                        it.copy(
                            commentsSending = false,
                            commentsSentCount = it.commentsSentCount + 1,
                            commentReplyTarget = null,
                            commentVisibility = "public",
                        )
                    }
                    loadComments(item, force = true)
                    if (_uiState.value.messages.isNotEmpty()) loadMessages(force = true)
                },
                onFailure = { error ->
                    account.reload()
                    val accounts = accountsFor(configuredSources())
                    val signedIn = account.sessionFor(item.source.baseUrl) != null
                    _uiState.update { state ->
                        state.copy(
                            commentsSending = false,
                            commentsError = error.message,
                            accounts = accounts,
                            commentReplyTarget = if (signedIn) {
                                state.commentReplyTarget
                            } else {
                                null
                            },
                        )
                    }
                },
            )
        }
    }

    fun deleteComment(item: ThemeStoreItem, comment: ThemeComment) {
        viewModelScope.launch {
            account.deleteComment(item.source.baseUrl, comment.id).fold(
                onSuccess = {
                    if (_uiState.value.commentReplyTarget?.id == comment.id) {
                        _uiState.update { it.copy(commentReplyTarget = null) }
                    }
                    loadComments(item, force = true)
                    if (_uiState.value.messages.isNotEmpty()) loadMessages(force = true)
                },
                onFailure = { error ->
                    account.reload()
                    val accounts = accountsFor(configuredSources())
                    val signedIn = account.sessionFor(item.source.baseUrl) != null
                    _uiState.update { state ->
                        state.copy(
                            commentsError = error.message,
                            accounts = accounts,
                            commentReplyTarget = if (signedIn) {
                                state.commentReplyTarget
                            } else {
                                null
                            },
                        )
                    }
                },
            )
        }
    }

    
    fun loadMessages(force: Boolean = false) {
        if (_uiState.value.messagesLoading && !force) return
        account.reload()
        val sources = configuredSources()
        val accounts = accountsFor(sources)
        _uiState.update { it.copy(sources = sources, accounts = accounts) }
        if (accounts.isEmpty()) {
            // The messages screen shows its own login-required notice and sign-in button, so
            // leaving an error here would duplicate the same text.
            _uiState.update {
                it.copy(
                    messagesLoading = false,
                    messages = emptyList(),
                    messagesError = null,
                )
            }
            return
        }
        _uiState.update { it.copy(messagesLoading = true, messagesError = null) }
        viewModelScope.launch {
            val accountRepository = account
            val results = coroutineScope {
                accounts.map { sourceAccount ->
                    async {
                        sourceAccount to accountRepository.messages(sourceAccount.source.baseUrl)
                    }
                }.awaitAll()
            }
            val remaining = accountsFor(configuredSources())
            val remainingKeys = remaining.mapTo(mutableSetOf()) { it.key }
            val conversations = results.flatMap { (sourceAccount, result) ->
                result.getOrDefault(AccountMessagesResponse()).conversations
                    .filter { sourceAccount.key in remainingKeys }
                    .map { UserMessageConversation(it, sourceAccount) }
            }.sortedByDescending { it.conversation.lastAt }
            val retention = results.mapNotNull { (_, result) ->
                result.getOrNull()?.retentionDays?.takeIf { it > 0 }
            }.firstOrNull() ?: 0L
            _uiState.update {
                it.copy(
                    messagesLoading = false,
                    accounts = remaining,
                    messages = conversations,
                    messagesRetentionDays = retention,
                    messagesError = results
                        .mapNotNull { (_, result) -> result.exceptionOrNull()?.message }
                        .firstOrNull(),
                )
            }
        }
    }

    fun sendMessageReply(
        conversation: UserMessageConversation,
        content: String,
        parentId: String?,
    ) {
        val text = content.trim()
        if (text.isEmpty() || _uiState.value.messagesSending) return
        _uiState.update { it.copy(messagesSending = true, messagesError = null) }
        viewModelScope.launch {
            account.postComment(
                baseUrl = conversation.account.source.baseUrl,
                themeId = conversation.conversation.themeId,
                content = text,
                visibility = "public",
                parentId = parentId,
            ).fold(
                onSuccess = {
                    _uiState.update { it.copy(messagesSending = false) }
                    loadMessages(force = true)
                },
                onFailure = { error ->
                    _uiState.update {
                        it.copy(messagesSending = false, messagesError = error.message)
                    }
                },
            )
        }
    }

    fun deleteMessage(conversation: UserMessageConversation, comment: ThemeComment) {
        viewModelScope.launch {
            account.deleteComment(conversation.account.source.baseUrl, comment.id).fold(
                onSuccess = { loadMessages(force = true) },
                onFailure = { error ->
                    _uiState.update { it.copy(messagesError = error.message) }
                },
            )
        }
    }

    fun accountUrl(baseUrl: String): String? = account.accountUrl(baseUrl)

    private suspend fun prepareUpload(
        input: ThemeStoreUploadInput,
        accountMode: Boolean,
    ): PreparedThemeUpload =
        withContext(Dispatchers.IO) {
            val app = getApplication<Application>()
            val themeId = input.id.trim()
            if (themeId.isNotEmpty() && !THEME_ID_PATTERN.matches(themeId)) {
                throw IllegalArgumentException(app.getString(R.string.theme_store_upload_invalid_id))
            }
            val version = input.version.trim().toIntOrNull()
                ?.takeIf { it in 1..1_000_000 }
                ?: throw IllegalArgumentException(app.getString(R.string.theme_store_upload_invalid_version))
            val name = input.name.trim()
            if (name.isBlank()) {
                throw IllegalArgumentException(app.getString(R.string.theme_store_upload_name_required))
            }
            val authorId = input.authorId.trim()
            if (!accountMode && !AUTHOR_ID_PATTERN.matches(authorId)) {
                throw IllegalArgumentException(app.getString(R.string.theme_store_upload_author_id_invalid))
            }
            if (name.length > 100 || input.author.trim().length > 100) {
                throw IllegalArgumentException(app.getString(R.string.theme_store_upload_text_too_long))
            }
            if (input.description.length > 2000 || input.changelog.length > 4000) {
                throw IllegalArgumentException(app.getString(R.string.theme_store_upload_text_too_long))
            }
            if (input.license.trim().length > 100) {
                throw IllegalArgumentException(app.getString(R.string.theme_store_upload_text_too_long))
            }
            val minManagerVersion = input.minManagerVersion.trim().ifBlank { "0" }
                .toLongOrNull()
                ?.takeIf { it >= 0 }
                ?: throw IllegalArgumentException(app.getString(R.string.theme_store_upload_invalid_version))
            val tags = input.tags
                .split(Regex("[,，\\n]"))
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toMutableList()
            if (tags.size > 10 || tags.any { it.length > 24 }) {
                throw IllegalArgumentException(app.getString(R.string.theme_store_upload_tags_invalid))
            }
            if (input.screenshotUris.size > MAX_SCREENSHOTS) {
                throw IllegalArgumentException(app.getString(R.string.theme_store_upload_too_many_screenshots))
            }

            val workDir = File(app.cacheDir, "theme_upload_${System.currentTimeMillis()}")
            if (!workDir.mkdirs()) {
                throw IllegalStateException(app.getString(R.string.theme_store_upload_failed))
            }
            try {
                val imageSemaphore = Semaphore(2)
                suspend fun compress(uri: Uri, baseName: String, maxEdge: Int): File =
                    withContext(Dispatchers.Default) {
                        imageSemaphore.withPermit {
                            compressImage(
                                uri = uri,
                                directory = workDir,
                                baseName = baseName,
                                maxEdge = maxEdge,
                                app = app,
                            )
                        }
                    }
                coroutineScope {
                    // Image encoding is CPU-bound; start it before copying and reading the
                    // package so preparation overlaps instead of running phase by phase.
                    val preview = async { compress(input.previewUri, "preview", PREVIEW_MAX_EDGE) }
                    val shots = input.screenshotUris.mapIndexed { index, uri ->
                        async { compress(uri, "screenshot-${index + 1}", SCREENSHOT_MAX_EDGE) }
                    }
                    val avatar = input.avatarUri?.let { uri ->
                        async { compress(uri, "avatar", AVATAR_MAX_EDGE) }
                    }

                    val packageFile = copyPackageFile(
                        uri = input.packageUri,
                        directory = workDir,
                        app = app,
                    )
                    // Only theme.json is needed here. Extracting every image just repeats
                    // validation the server performs and dominated preparation time for
                    // large packages.
                    val packageData = ThemePackageStorage.inspect(app, Uri.fromFile(packageFile))
                        .getOrElse {
                            throw IllegalArgumentException(
                                app.getString(R.string.theme_store_upload_package_invalid),
                            )
                        }
                    // Adaptive packages are always tagged so store previews and filters can badge them,
                    // even when the author did not type the tag themselves.
                    if (packageData.adaptive == true &&
                        tags.none { canonicalThemeTag(it) == ThemePackageStorage.ADAPTIVE_TAG }
                    ) {
                        if (tags.size >= 10) {
                            tags.removeAt(tags.lastIndex)
                        }
                        tags.add(0, ThemePackageStorage.ADAPTIVE_TAG)
                    } else if (packageData.adaptive != true) {
                        // The tag describes the package, so a plain package must not keep a stale one.
                        tags.removeAll {
                            canonicalThemeTag(it) == ThemePackageStorage.ADAPTIVE_TAG
                        }
                    }
                    PreparedThemeUpload(
                        submission = ThemeStoreSubmission(
                            id = themeId,
                            version = version,
                            formatVersion = packageData.version,
                            name = name,
                            author = input.author.trim(),
                            authorId = if (accountMode) "" else authorId,
                            authorApplyNote = if (accountMode) input.authorApplyNote.trim() else "",
                            description = input.description.trim(),
                            tags = tags.joinToString(", "),
                            license = input.license.trim(),
                            minManagerVersion = minManagerVersion,
                            changelog = input.changelog.trim(),
                            packageFile = packageFile,
                            previewFile = preview.await(),
                            avatarFile = avatar?.await(),
                            screenshotFiles = shots.awaitAll(),
                        ),
                        workDir = workDir,
                    )
                }
            } catch (error: Exception) {
                workDir.deleteRecursively()
                throw error
            }
        }

    @Suppress("DEPRECATION")
    private fun webpFormat(): Bitmap.CompressFormat =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Bitmap.CompressFormat.WEBP_LOSSY
        } else {
            Bitmap.CompressFormat.WEBP
        }

    private fun copyPackageFile(
        uri: Uri,
        directory: File,
        app: Application,
    ): File {
        val displayName = displayName(uri, app)
        val suffix = displayName.substringAfterLast('.', "").lowercase(Locale.ROOT)
        //noinspection SpellCheckingInspection
        if (suffix != "sukisu") {
            throw IllegalArgumentException(app.getString(R.string.theme_store_upload_file_invalid, displayName))
        }
        // Presets and adaptive exports already live in a seekable app-private file. The
        // chunked uploader only reads it, so copying tens of megabytes first is wasted I/O.
        val direct = uri.takeIf { it.scheme == "file" }?.path?.let(::File)
        if (direct != null && direct.isFile) {
            if (direct.length() <= 0L) {
                throw IllegalArgumentException(app.getString(R.string.theme_store_upload_file_empty, displayName))
            }
            if (direct.length() > ThemeStoreRepository.MAX_PACKAGE_BYTES) {
                throw IllegalArgumentException(
                    app.getString(R.string.theme_store_upload_file_too_large, displayName),
                )
            }
            return direct
        }
        val target = File(directory, "package.sukisu")
        val stream = app.contentResolver.openInputStream(uri)
            ?: throw IllegalArgumentException(app.getString(R.string.theme_store_upload_file_invalid, displayName))
        stream.use { input ->
            target.outputStream().use { output ->
                val buffer = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > ThemeStoreRepository.MAX_PACKAGE_BYTES) {
                        throw IllegalArgumentException(
                            app.getString(R.string.theme_store_upload_file_too_large, displayName),
                        )
                    }
                    output.write(buffer, 0, read)
                }
                if (total <= 0) {
                    throw IllegalArgumentException(app.getString(R.string.theme_store_upload_file_empty, displayName))
                }
            }
        }
        return target
    }

    private fun compressImage(
        uri: Uri,
        directory: File,
        baseName: String,
        maxEdge: Int,
        app: Application,
    ): File {
        val invalidMessage = when (baseName) {
            "preview" -> R.string.theme_store_upload_preview_invalid
            "avatar" -> R.string.theme_store_upload_avatar_invalid
            else -> R.string.theme_store_upload_screenshot_invalid
        }
        val source = copyImageToCache(uri, directory, baseName, app, invalidMessage)
        try {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(source.path, bounds)
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
                throw IllegalArgumentException(app.getString(invalidMessage))
            }
            var sampleSize = 1
            while (max(bounds.outWidth, bounds.outHeight) / (sampleSize * 2) >= maxEdge) {
                sampleSize *= 2
            }
            val options = BitmapFactory.Options().apply {
                inSampleSize = sampleSize
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }
            val decoded = BitmapFactory.decodeFile(source.path, options)
                ?: throw IllegalArgumentException(app.getString(invalidMessage))
            val oriented = applyExifOrientation(decoded, readExifOrientation(source))

            val scale = min(1f, maxEdge.toFloat() / max(oriented.width, oriented.height))
            val scaled = if (scale < 1f) {
                oriented.scale(
                    (oriented.width * scale).roundToInt().coerceAtLeast(1),
                    (oriented.height * scale).roundToInt().coerceAtLeast(1),
                )
            } else {
                oriented
            }
            val target = File(directory, "$baseName.webp")
            val format = webpFormat()
            try {
                val written = target.outputStream().use { output ->
                    scaled.compress(format, WEBP_QUALITY, output)
                }
                if (!written || !target.isFile || target.length() <= 0L) {
                    throw IllegalArgumentException(app.getString(invalidMessage))
                }
                if (target.length() > MAX_IMAGE_BYTES) {
                    target.outputStream().use { output ->
                        scaled.compress(format, 60, output)
                    }
                }
                if (target.length() > MAX_IMAGE_BYTES) {
                    throw IllegalArgumentException(
                        app.getString(R.string.theme_store_upload_file_too_large, baseName),
                    )
                }
                return target
            } finally {
                if (scaled !== oriented) scaled.recycle()
                if (oriented !== decoded) oriented.recycle()
                decoded.recycle()
            }
        } finally {
            source.delete()
        }
    }

    private fun copyImageToCache(
        uri: Uri,
        directory: File,
        baseName: String,
        app: Application,
        invalidMessage: Int,
    ): File {
        val target = File(directory, "$baseName.input")
        val stream = app.contentResolver.openInputStream(uri)
            ?: throw IllegalArgumentException(app.getString(invalidMessage))
        stream.use { input ->
            target.outputStream().use { output ->
                val buffer = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > MAX_IMAGE_INPUT_BYTES) {
                        throw IllegalArgumentException(
                            app.getString(R.string.theme_store_upload_file_too_large, baseName),
                        )
                    }
                    output.write(buffer, 0, read)
                }
                if (total <= 0L) {
                    throw IllegalArgumentException(app.getString(invalidMessage))
                }
            }
        }
        return target
    }

    private fun readExifOrientation(file: File): Int = runCatching {
        ExifInterface(file.absolutePath).getAttributeInt(
            ExifInterface.TAG_ORIENTATION,
            ExifInterface.ORIENTATION_NORMAL,
        )
    }.getOrDefault(ExifInterface.ORIENTATION_NORMAL)

    private fun applyExifOrientation(bitmap: Bitmap, orientation: Int): Bitmap {
        if (orientation == ExifInterface.ORIENTATION_NORMAL ||
            orientation == ExifInterface.ORIENTATION_UNDEFINED
        ) {
            return bitmap
        }
        val matrix = Matrix()
        when (orientation) {
            ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> matrix.postScale(-1f, 1f)
            ExifInterface.ORIENTATION_ROTATE_180 -> matrix.postRotate(180f)
            ExifInterface.ORIENTATION_FLIP_VERTICAL -> matrix.postScale(1f, -1f)
            ExifInterface.ORIENTATION_TRANSPOSE -> {
                matrix.postRotate(90f)
                matrix.postScale(-1f, 1f)
            }
            ExifInterface.ORIENTATION_ROTATE_90 -> matrix.postRotate(90f)
            ExifInterface.ORIENTATION_TRANSVERSE -> {
                matrix.postRotate(-90f)
                matrix.postScale(-1f, 1f)
            }
            ExifInterface.ORIENTATION_ROTATE_270 -> matrix.postRotate(-90f)
            else -> return bitmap
        }
        return runCatching {
            Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
        }.getOrDefault(bitmap)
    }

    private fun displayName(uri: Uri, app: Application): String {
        val queried = runCatching {
            app.contentResolver.query(
                uri,
                arrayOf(OpenableColumns.DISPLAY_NAME),
                null,
                null,
                null,
            )?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            }
        }.getOrNull()
        return queried?.takeIf { it.isNotBlank() }
            ?: uri.lastPathSegment?.substringAfterLast('/').orEmpty()
    }

    private fun configuredSources(): List<ThemeStoreSource> {
        val result = mutableListOf<ThemeStoreSource>()
        val builtInBase = ThemeStoreRepository.normalizeBaseUrl(ThemeStoreDefaults.preferredBaseUrl())
        val configuredBase = ThemeStoreDefaults.resolveConfiguredBaseUrl(settings.themeStoreBaseUrl)
        val defaultBase = ThemeStoreRepository.normalizeBaseUrl(configuredBase)
        if (defaultBase != null) {
            val defaultToken = when {
                settings.themeStoreToken.isNotBlank() -> settings.themeStoreToken
                defaultBase == builtInBase -> ""
                else -> ""
            }
            result += ThemeStoreSource(
                id = "default",
                name = "",
                baseUrl = defaultBase,
                token = defaultToken,
                adminUrl = adminUrlFor(defaultBase, settings.themeStoreAdminUrl),
                isDefault = true,
            )
        }
        settings.themeStoreExtraSources.forEach { config ->
            val base = ThemeStoreRepository.normalizeBaseUrl(config.baseUrl) ?: return@forEach
            result += ThemeStoreSource(
                id = config.id.ifBlank { base },
                name = config.name,
                baseUrl = base,
                token = config.token,
                adminUrl = adminUrlFor(base, config.adminUrl),
            )
        }
        return result.distinctBy { it.baseUrl }
    }

    private fun adminUrlFor(base: String, configured: String): String =
        configured.trim().takeIf { it.isNotEmpty() }
            ?.let { ThemeStoreRepository.normalizeBaseUrl(it) }
            ?: (base + "admin/")
}

// Separators inside author handles ("shirk neko", "shirk_neko") and invisible format characters
// pasted from a submission form should not stop a search from matching.
private val SEARCH_SEPARATORS = Regex("[\\p{Cf}\\p{Zs}\\s_.\\-·]+")
private val SEARCH_DIACRITICS = Regex("\\p{Mn}+")

private fun String.searchKey(): String =
    java.text.Normalizer.normalize(this, java.text.Normalizer.Form.NFKD)
        .replace(SEARCH_DIACRITICS, "")
        .replace(SEARCH_SEPARATORS, "")

internal fun ThemeStoreItem.matchesSearch(
    query: String,
    adaptiveLabel: String = ADAPTIVE_TAG,
): Boolean {
    val normalized = query.trim().lowercase(Locale.ROOT)
    if (normalized.isEmpty()) return true
    val haystack = buildString {
        append(entry.id).append(' ')
        append(entry.name).append(' ')
        append(entry.author).append(' ')
        append(entry.description).append(' ')
        append(entry.tags.joinToString(" ")).append(' ')
        if (isAdaptiveTheme()) append(adaptiveLabel).append(" adaptive ")
        append(source.name).append(' ')
        append(source.baseUrl)
    }.lowercase(Locale.ROOT)
    // Authors are displayed and shared as @name, so accept queries written that way too.
    val parts = normalized.split(Regex("\\s+"))
        .map { it.removePrefix("@") }
        .filter { it.isNotEmpty() }
    if (parts.isEmpty()) return true
    if (parts.all { part -> haystack.contains(part) }) return true
    // Fallback: compare compacted text so handles written with spaces, underscores, full-width
    // characters or zero-width joiners still match.
    val compactHaystack = haystack.searchKey()
    return parts.all { part ->
        val key = part.searchKey()
        key.isNotEmpty() && compactHaystack.contains(key)
    }
}

/**
 * Newest submissions first across all mirror sources. Entries without a timestamp keep the
 * server order at the end; the UI only shows the newest [limit] entries.
 */
internal fun List<UserSubmission>.latestUserSubmissions(limit: Int = 20): List<UserSubmission> =
    sortedWith(compareByDescending { it.submission.submittedAt.orEmpty() })
        .take(limit.coerceAtLeast(0))


internal fun List<ThemeStoreAccount>.preferredUploadAccount(
    preferredBaseUrl: String,
    defaultBaseUrl: String,
): ThemeStoreAccount? = firstOrNull { it.source.baseUrl == preferredBaseUrl }
    ?: firstOrNull { it.source.baseUrl == defaultBaseUrl }
