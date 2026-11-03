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
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.model.AccountSubmission
import com.sukisu.ultra.data.model.AccountThemeSummary
import com.sukisu.ultra.data.model.ThemeStoreEntry
import com.sukisu.ultra.data.repository.AccountRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.data.repository.ThemeStoreDefaults
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import com.sukisu.ultra.data.repository.ThemeStoreSubmission
import com.sukisu.ultra.data.repository.ThemeStoreUnauthorizedException
import com.sukisu.ultra.ui.util.ThemePackageStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Locale
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import androidx.core.graphics.scale

data class ThemeStoreSource(
    val id: String,
    val name: String,
    val baseUrl: String,
    val token: String,
    val adminUrl: String = "",
    val isDefault: Boolean = false,
)

/** A logged-in account bound to one configured mirror source. */
data class ThemeStoreAccount(
    val source: ThemeStoreSource,
    val session: AccountSession,
) {
    val key: String get() = source.baseUrl
}

/** A theme owned by one source account. */
data class UserTheme(
    val theme: AccountThemeSummary,
    val account: ThemeStoreAccount,
) {
    val key: String get() = "${account.key}:${theme.id}"
}

/** A submission made on one source account. */
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

data class ThemeStoreUiState(
    val loaded: Boolean = false,
    val loading: Boolean = false,
    val refreshing: Boolean = false,
    val items: List<ThemeStoreItem> = emptyList(),
    val sources: List<ThemeStoreSource> = emptyList(),
    val fromCache: Boolean = false,
    val failedSources: Int = 0,
    val unauthorized: Boolean = false,
    val error: Boolean = false,
    val needsConfig: Boolean = false,
    val downloadingKey: String? = null,
    val downloadTrial: Boolean = false,
    val downloadProgress: Float = 0f,
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
    val accounts: List<ThemeStoreAccount> = emptyList(),
    val uploadOptionsLoading: Boolean = false,
    val uploadOptionsError: String? = null,
    val uploadPhase: ThemeStoreUploadPhase = ThemeStoreUploadPhase.IDLE,
    val uploadProgress: Float = 0f,
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
    private val _uiState = MutableStateFlow(ThemeStoreUiState())
    val uiState: StateFlow<ThemeStoreUiState> = _uiState.asStateFlow()

    init {
        load()
        viewModelScope.launch(Dispatchers.IO) {
            repository.cleanupStaleCache()
        }
    }

    fun load() {
        val current = _uiState.value
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
                    failedSources = 0,
                    unauthorized = false,
                    error = false,
                    needsConfig = true,
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
        viewModelScope.launch {
            val results = sources
                .map { source -> async { source to repository.loadCatalog(source.baseUrl, source.token) } }
                .awaitAll()
            val successes = results.filter { it.second.isSuccess }
            val sourceOrder = sources.mapIndexed { index, source -> source.id to index }.toMap()
            val items = successes
                .flatMap { (source, result) ->
                    result.getOrThrow().catalog.themes.map { ThemeStoreItem(it, source) }
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
                    sources = sources,
                    accounts = accounts,
                    fromCache = successes.any { it.second.getOrThrow().fromCache },
                    failedSources = failures,
                    unauthorized = unauthorized,
                    error = successes.isEmpty(),
                    needsConfig = false,
                )
            }
        }
    }

    /** Re-reads sessions from preferences, e.g. after returning from the account page. */
    fun refreshAccounts() {
        account.reload()
        val sources = configuredSources()
        _uiState.update {
            it.copy(sources = sources, accounts = accountsFor(sources))
        }
    }

    /** Remembers the source used for future uploads; the default source is stored as blank. */
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

    fun download(item: ThemeStoreItem, trial: Boolean = false) {
        val current = _uiState.value
        if (current.downloadingKey != null) return
        _uiState.update {
            it.copy(
                downloadingKey = item.key,
                downloadTrial = trial,
                downloadProgress = 0f,
                downloadFailed = false,
                verifiedThemeKey = null,
            )
        }
        viewModelScope.launch {
            repository.downloadTheme(
                entry = item.entry,
                baseUrl = item.source.baseUrl,
                token = item.source.token,
            ) { progress ->
                _uiState.update { it.copy(downloadProgress = progress) }
            }.fold(
                onSuccess = { file ->
                    _uiState.update {
                        it.copy(
                            downloadingKey = null,
                            downloadProgress = 1f,
                            downloaded = DownloadedTheme(item, file, trial),
                            verifiedThemeKey = item.key,
                        )
                    }
                },
                onFailure = {
                    _uiState.update {
                        it.copy(
                            downloadingKey = null,
                            downloadTrial = false,
                            downloadProgress = 0f,
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
                uploadResult = null,
            )
        }
        viewModelScope.launch {
            var workDir: File? = null
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
                        prepared.submission,
                        source.baseUrl,
                        source.token,
                        accountSession.token,
                    ) { progress ->
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
                    }
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
            } catch (_: ThemeStoreUnauthorizedException) {
                _uiState.update {
                    it.copy(
                        submitting = false,
                        uploadPhase = ThemeStoreUploadPhase.FAILED,
                        uploadProgress = 0f,
                        uploadError = getApplication<Application>().getString(R.string.theme_store_unauthorized),
                    )
                }
            } catch (error: Exception) {
                _uiState.update {
                    it.copy(
                        submitting = false,
                        uploadPhase = ThemeStoreUploadPhase.FAILED,
                        uploadProgress = 0f,
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

    /** Loads themes and submission history for every logged-in mirror source. */
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
                val packageFile = copyPackageFile(
                    uri = input.packageUri,
                    directory = workDir,
                    app = app,
                )
                val packageData = ThemePackageStorage.validate(app, Uri.fromFile(packageFile)).getOrElse {
                    throw IllegalArgumentException(app.getString(R.string.theme_store_upload_package_invalid))
                }
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
                val (previewFile, screenshots, avatarFile) = coroutineScope {
                    val preview = async { compress(input.previewUri, "preview", PREVIEW_MAX_EDGE) }
                    val shots = input.screenshotUris.mapIndexed { index, uri ->
                        async { compress(uri, "screenshot-${index + 1}", SCREENSHOT_MAX_EDGE) }
                    }
                    val avatar = input.avatarUri?.let { uri ->
                        async { compress(uri, "avatar", AVATAR_MAX_EDGE) }
                    }
                    Triple(preview.await(), shots.awaitAll(), avatar?.await())
                }
                PreparedThemeUpload(
                    submission = ThemeStoreSubmission(
                        id = themeId,
                        version = version,
                        formatVersion = packageData.version,
                        name = name,
                        author = input.author.trim(),
                        authorId = if (accountMode) "" else authorId,
                        description = input.description.trim(),
                        tags = tags.joinToString(", "),
                        license = input.license.trim(),
                        minManagerVersion = minManagerVersion,
                        changelog = input.changelog.trim(),
                        packageFile = packageFile,
                        previewFile = previewFile,
                        avatarFile = avatarFile,
                        screenshotFiles = screenshots,
                    ),
                    workDir = workDir,
                )
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
        val builtInBase = ThemeStoreRepository.normalizeBaseUrl(ThemeStoreDefaults.BASE_URL)
        val configuredBase = settings.themeStoreBaseUrl.ifBlank { ThemeStoreDefaults.BASE_URL }
        val defaultBase = ThemeStoreRepository.normalizeBaseUrl(configuredBase)
        if (defaultBase != null) {
            val defaultToken = when {
                settings.themeStoreToken.isNotBlank() -> settings.themeStoreToken
                defaultBase == builtInBase -> ThemeStoreDefaults.TOKEN
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

internal fun ThemeStoreItem.matchesSearch(query: String): Boolean {
    val normalized = query.trim().lowercase(Locale.ROOT)
    if (normalized.isEmpty()) return true
    val haystack = buildString {
        append(entry.id).append(' ')
        append(entry.name).append(' ')
        append(entry.author).append(' ')
        append(entry.description).append(' ')
        append(entry.tags.joinToString(" ")).append(' ')
        append(source.name).append(' ')
        append(source.baseUrl)
    }.lowercase(Locale.ROOT)
    return normalized.split(Regex("\\s+")).all { part -> haystack.contains(part) }
}

/**
 * Newest submissions first across all mirror sources. Entries without a timestamp keep the
 * server order at the end; the UI only shows the newest [limit] entries.
 */
internal fun List<UserSubmission>.latestUserSubmissions(limit: Int = 20): List<UserSubmission> =
    sortedWith(compareByDescending { it.submission.submittedAt.orEmpty() })
        .take(limit.coerceAtLeast(0))

/** Saved upload preference first, then the default source, without prompting the user. */
internal fun List<ThemeStoreAccount>.preferredUploadAccount(
    preferredBaseUrl: String,
    defaultBaseUrl: String,
): ThemeStoreAccount? = firstOrNull { it.source.baseUrl == preferredBaseUrl }
    ?: firstOrNull { it.source.baseUrl == defaultBaseUrl }
