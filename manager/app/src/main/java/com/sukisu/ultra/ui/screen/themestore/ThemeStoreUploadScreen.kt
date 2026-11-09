package com.sukisu.ultra.ui.screen.themestore

import android.annotation.SuppressLint
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Article
import androidx.compose.material.icons.rounded.AutoAwesome
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.Phone
import androidx.compose.material.icons.rounded.PhotoLibrary
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.LinearWavyProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar as MaterialTopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.model.AccountThemeSummary
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import com.sukisu.ultra.ui.component.material.ExpressiveDialog
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.util.ThemePackageStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.math.roundToInt

private val UploadUriSaver = Saver<Uri?, String>(
    save = { it?.toString().orEmpty() },
    restore = { value -> value.takeIf { it.isNotBlank() }?.let(Uri::parse) },
)

private val UploadUriListSaver = listSaver(
    save = { uris -> uris.map(Uri::toString) },
    restore = { values -> values.map(Uri::parse) },
)

/**
 * Full-page theme submission form. Kept inside the theme store screen rather than a navigation
 * destination so the shared view model keeps the submission progress and errors.
 */
@SuppressLint("LocalContextGetResourceValueCall")
@Composable
internal fun ThemeStoreUploadScreen(
    source: ThemeStoreSource,
    accountSession: AccountSession?,
    autoThemeId: String?,
    editingTheme: AccountThemeSummary?,
    editPrefill: ThemeStoreEditPrefill? = null,
    initialAdaptiveTheme: Boolean = false,
    initialCurrentTheme: Boolean = false,
    optionsLoading: Boolean,
    optionsError: String?,
    uploadPhase: ThemeStoreUploadPhase,
    uploadProgress: Float,
    uploadTransferredBytes: Long,
    uploadTotalBytes: Long,
    uploadSpeedBytesPerSecond: Long,
    uploadEtaSeconds: Long?,
    submitting: Boolean,
    errorText: String?,
    onBack: () -> Unit,
    onLogin: () -> Unit,
    onSubmit: (ThemeStoreUploadInput) -> Unit,
    onExportCurrentPreset: suspend () -> File?,
    onLoadAdaptiveTheme: suspend () -> File?,
) {
    val editingId = editingTheme?.id.orEmpty()
    var selectedUpdateId by rememberSaveable(editingId) { mutableStateOf(editingId) }
    var version by rememberSaveable(editingId) {
        mutableStateOf(editingTheme?.version?.plus(1)?.toString() ?: "1")
    }
    var name by rememberSaveable(editingId) { mutableStateOf(editingTheme?.name.orEmpty()) }
    var tags by rememberSaveable(editingId) {
        mutableStateOf(editingTheme?.tags?.joinToString(", ").orEmpty())
    }
    var license by rememberSaveable(editingId) {
        mutableStateOf(editingTheme?.license?.takeIf { it.isNotBlank() } ?: "CC-BY-4.0")
    }
    var minManagerVersion by rememberSaveable(editingId) {
        mutableStateOf(
            editingTheme?.minManagerVersion?.toString() ?: BuildConfig.VERSION_CODE.toString(),
        )
    }
    var description by rememberSaveable(editingId) {
        mutableStateOf(editingTheme?.description.orEmpty())
    }
    var changelog by rememberSaveable(editingId) {
        mutableStateOf(editingTheme?.changelog.orEmpty())
    }
    var presetBusy by remember { mutableStateOf(false) }
    var presetError by remember { mutableStateOf<String?>(null) }
    var adaptiveBusy by remember { mutableStateOf(false) }
    var packageLabel by rememberSaveable(editingId) { mutableStateOf<String?>(null) }
    var packageAdaptive by rememberSaveable { mutableStateOf(false) }
    var initialPackageApplied by rememberSaveable { mutableStateOf(false) }
    var packageUri by rememberSaveable(editingId, stateSaver = UploadUriSaver) {
        mutableStateOf(null)
    }
    var previewUri by rememberSaveable(editingId, stateSaver = UploadUriSaver) {
        mutableStateOf(null)
    }
    var avatarUri by rememberSaveable(editingId, stateSaver = UploadUriSaver) {
        mutableStateOf(null)
    }
    var screenshotUris by rememberSaveable(editingId, stateSaver = UploadUriListSaver) {
        mutableStateOf(emptyList())
    }
    var authorApplyOpen by rememberSaveable { mutableStateOf(false) }
    var authorApplyNote by rememberSaveable { mutableStateOf("") }
    var authorApplyError by remember { mutableStateOf<String?>(null) }

    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val packagePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
        packageUri = it
        packageLabel = null
        presetError = null
    }
    val previewPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
        previewUri = it
    }
    val avatarPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
        avatarUri = it
    }
    val screenshotPicker = rememberLauncherForActivityResult(ActivityResultContracts.GetMultipleContents()) {
        screenshotUris = it.take(6)
    }

    LaunchedEffect(packageUri) {
        val uri = packageUri
        packageAdaptive = false
        if (uri == null) {
            return@LaunchedEffect
        }
        val data = withContext(Dispatchers.IO) {
            ThemePackageStorage.inspect(context, uri).getOrNull()
        } ?: return@LaunchedEffect
        packageAdaptive = data.adaptive == true
        val values = tags.split(Regex("[,，\n]"))
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toMutableList()
        if (packageAdaptive) {
            val hasAdaptive = values.any {
                canonicalThemeTag(it) == ThemePackageStorage.ADAPTIVE_TAG
            }
            if (!hasAdaptive) {
                if (values.size >= 10) values.removeAt(values.lastIndex)
                values.add(0, ThemePackageStorage.ADAPTIVE_TAG)
                tags = values.joinToString(", ")
            }
        } else if (values.any { canonicalThemeTag(it) == ThemePackageStorage.ADAPTIVE_TAG }) {
            // Drop the tag that the previous adaptive package added automatically.
            values.removeAll { canonicalThemeTag(it) == ThemePackageStorage.ADAPTIVE_TAG }
            tags = values.joinToString(", ")
        }
    }

    val noFile = stringResource(R.string.theme_store_upload_no_file)
    val presetName = stringResource(R.string.theme_store_upload_current_preset)
    val adaptivePresetName = stringResource(R.string.theme_store_upload_adaptive_preset)
    LaunchedEffect(initialAdaptiveTheme, initialPackageApplied) {
        if (!initialAdaptiveTheme || initialPackageApplied) return@LaunchedEffect
        adaptiveBusy = true
        val file = runCatching { onLoadAdaptiveTheme() }.getOrNull()
        adaptiveBusy = false
        if (file == null) {
            presetError = context.getString(R.string.theme_store_upload_adaptive_missing)
            return@LaunchedEffect
        }
        initialPackageApplied = true
        packageUri = Uri.fromFile(file)
        packageLabel = adaptivePresetName
    }
    LaunchedEffect(initialCurrentTheme, initialPackageApplied) {
        if (!initialCurrentTheme || initialPackageApplied) return@LaunchedEffect
        presetBusy = true
        val file = runCatching { onExportCurrentPreset() }.getOrNull()
        presetBusy = false
        if (file == null) {
            presetError = context.getString(R.string.theme_store_upload_preset_failed)
            return@LaunchedEffect
        }
        initialPackageApplied = true
        packageUri = Uri.fromFile(file)
        packageLabel = presetName
    }
    // Editing starts from the files that are already published; the pickers only
    // need to be touched when something actually changes.
    LaunchedEffect(editPrefill, editingId) {
        val prefill = editPrefill ?: return@LaunchedEffect
        if (prefill.loading || prefill.themeId != editingId) return@LaunchedEffect
        prefill.packageUri?.let { packageUri = it }
        prefill.previewUri?.let { previewUri = it }
        prefill.avatarUri?.let { avatarUri = it }
        if (prefill.screenshotUris.isNotEmpty()) screenshotUris = prefill.screenshotUris
    }

    val pickedPackageName = remember(packageUri) {
        packageUri?.let { queryDisplayName(context, it) } ?: noFile
    }
    val packageName = packageLabel ?: pickedPackageName
    val previewName = remember(previewUri) { previewUri?.let { queryDisplayName(context, it) } ?: noFile }
    val avatarName = remember(avatarUri) { avatarUri?.let { queryDisplayName(context, it) } ?: noFile }
    val screenshotSummary = if (screenshotUris.isEmpty()) {
        noFile
    } else {
        stringResource(R.string.theme_store_upload_screenshot_count, screenshotUris.size)
    }
    val versionValue = version.trim().toIntOrNull()
    val displayedThemeId = selectedUpdateId.ifBlank { autoThemeId.orEmpty() }
    val authorAvatarUrl = remember(accountSession?.baseUrl, accountSession?.activeAuthor?.avatarPath) {
        val base = accountSession?.baseUrl.orEmpty()
        val path = accountSession?.activeAuthor?.avatarPath.orEmpty()
        if (base.isBlank() || path.isBlank()) {
            null
        } else {
            ThemeStoreRepository.assetUrl(base, path)
        }
    }
    val canSubmit = !submitting && accountSession != null && name.isNotBlank() &&
        packageUri != null && previewUri != null && versionValue != null && versionValue >= 1

    // A submission creates the author licence when the account has none yet.
    // The reason is asked for at submit time (MD3 expressive dialog) instead of
    // applying silently while the user is only previewing the upload form.
    fun needsAuthorApplication(session: AccountSession): Boolean =
        session.authors.none { it.status == "pending" || it.status == "active" } &&
            session.activeAuthor == null

    fun uploadInput(session: AccountSession, applyNote: String): ThemeStoreUploadInput =
        ThemeStoreUploadInput(
            id = selectedUpdateId,
            version = version,
            name = name,
            author = session.user.displayName.ifBlank { session.user.username },
            authorId = "",
            authorApplyNote = applyNote,
            description = description,
            tags = tags,
            license = license,
            minManagerVersion = minManagerVersion,
            changelog = changelog,
            packageUri = requireNotNull(packageUri),
            previewUri = requireNotNull(previewUri),
            avatarUri = avatarUri,
            screenshotUris = screenshotUris,
        )

    fun submit() {
        if (submitting) return
        val session = accountSession ?: return
        if (packageUri == null || previewUri == null) return
        if (needsAuthorApplication(session)) {
            authorApplyError = null
            authorApplyOpen = true
            return
        }
        onSubmit(uploadInput(session, ""))
    }

    fun confirmAuthorApplication() {
        val session = accountSession ?: return
        if (packageUri == null || previewUri == null) return
        val minimum = if (session.authors.any { it.status == "revoked" || it.status == "retired" }) {
            10
        } else {
            5
        }
        val note = authorApplyNote.trim()
        if (note.length < minimum) {
            authorApplyError = context.getString(
                R.string.theme_store_upload_author_apply_required,
                minimum,
            )
            return
        }
        authorApplyError = null
        authorApplyOpen = false
        onSubmit(uploadInput(session, note))
    }

    fun appendMention(mention: String) {
        val spacer = if (description.isBlank() || description.endsWith(" ")) "" else " "
        description += "$spacer$mention "
    }

    fun toggleTag(tag: String) {
        val values = tags.split(Regex("[,，\n]"))
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toMutableList()
        val canonical = canonicalThemeTag(tag)
        val existing = values.indexOfFirst { canonicalThemeTag(it) == canonical }
        if (existing >= 0) {
            values.removeAt(existing)
        } else if (values.size < 10) {
            values.add(tag)
        }
        tags = values.joinToString(", ")
    }

    val tagValues = tags.split(Regex("[,，\n]")).map { it.trim() }.filter { it.isNotEmpty() }

    val pageContainer = MaterialTheme.colorScheme.surface
    ExpressiveScaffold(
        modifier = Modifier.imePadding(),
        containerColor = pageContainer,
        topBar = {
            MaterialTopAppBar(
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                title = {
                    MaterialText(
                        text = stringResource(
                            if (editingTheme != null) R.string.theme_store_edit_title
                            else R.string.theme_store_upload_title,
                        ),
                    )
                },
                subtitle = {
                    MaterialText(
                        text = stringResource(
                            R.string.theme_store_upload_target_source,
                            source.displayName(),
                        ),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = pageContainer,
                    scrolledContainerColor = pageContainer,
                ),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
            )
        },
        bottomBar = {
            UploadSubmitBar(
                submitting = submitting,
                phase = uploadPhase,
                progress = uploadProgress,
                transferredBytes = uploadTransferredBytes,
                totalBytes = uploadTotalBytes,
                speedBytesPerSecond = uploadSpeedBytesPerSecond,
                etaSeconds = uploadEtaSeconds,
                canSubmit = canSubmit,
                errorText = errorText,
                onSubmit = ::submit,
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            item(key = "basic") {
                ThemeStoreSectionCard(
                    title = stringResource(R.string.theme_store_upload_section_basic),
                    icon = Icons.Rounded.Description,
                ) {
                    UploadTextField(
                        value = displayedThemeId,
                        onValueChange = {},
                        label = stringResource(R.string.theme_store_upload_id),
                        enabled = false,
                    )
                    when {
                        editingTheme != null -> {
                            UploadHint(stringResource(R.string.theme_store_edit_id_hint))
                            when {
                                editPrefill?.loading == true -> UploadHint(
                                    stringResource(R.string.theme_store_edit_prefill_loading),
                                )

                                !editPrefill?.error.isNullOrBlank() -> UploadHint(
                                    editPrefill.error,
                                    isError = true,
                                )
                            }
                        }

                        optionsLoading -> UploadHint(
                            stringResource(R.string.theme_store_upload_id_loading),
                        )

                        !optionsError.isNullOrBlank() -> UploadHint(
                            stringResource(R.string.theme_store_upload_id_error, optionsError),
                        )

                        else -> UploadHint(
                            stringResource(
                                if (displayedThemeId.isBlank()) {
                                    R.string.theme_store_upload_id_pending
                                } else {
                                    R.string.theme_store_upload_id_hint
                                },
                            ),
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        UploadTextField(
                            value = version,
                            onValueChange = { version = it },
                            label = stringResource(R.string.theme_store_upload_version),
                            enabled = !submitting,
                            keyboardType = KeyboardType.Number,
                            modifier = Modifier.weight(1f),
                        )
                        UploadTextField(
                            value = minManagerVersion,
                            onValueChange = { minManagerVersion = it },
                            label = stringResource(R.string.theme_store_upload_min_manager),
                            enabled = !submitting,
                            keyboardType = KeyboardType.Number,
                            modifier = Modifier.weight(1f),
                        )
                    }
                    UploadTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = stringResource(R.string.theme_store_upload_name),
                        enabled = !submitting,
                    )
                    UploadTextField(
                        value = tags,
                        onValueChange = { tags = it },
                        label = stringResource(R.string.theme_store_upload_tags),
                        enabled = !submitting,
                    )
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        listOf(
                            ThemePackageStorage.ADAPTIVE_TAG,
                            R18_TAG,
                            "light",
                            "dark",
                            "pink",
                            "cute",
                            "minimal",
                            "gradient",
                            "anime",
                            "blue",
                            "purple",
                            "green",
                        )
                            .forEach { tag ->
                                FilterChip(
                                    selected = tagValues.any {
                                        canonicalThemeTag(it) == canonicalThemeTag(tag)
                                    },
                                    onClick = { toggleTag(tag) },
                                    enabled = !submitting,
                                    label = { MaterialText(themeTagLabel(tag)) },
                                    shapes = FilterChipDefaults.shapes(),
                                )
                            }
                    }
                    MaterialText(
                        stringResource(R.string.theme_store_upload_license),
                        style = MaterialTheme.typography.labelLarge,
                    )
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        listOf(
                            "CC-BY-4.0",
                            "CC-BY-SA-4.0",
                            "CC-BY-NC-4.0",
                            "CC-BY-NC-SA-4.0",
                            "CC0-1.0",
                            "MIT",
                            "Apache-2.0",
                            "GPL-3.0",
                            "All Rights Reserved",
                            "",
                        ).forEach { option ->
                            FilterChip(
                                selected = license == option,
                                onClick = { license = option },
                                enabled = !submitting,
                                label = {
                                    MaterialText(
                                        option.ifBlank {
                                            stringResource(R.string.theme_store_license_unspecified)
                                        },
                                    )
                                },
                                shapes = FilterChipDefaults.shapes(),
                            )
                        }
                    }
                }
            }
            item(key = "author") {
                ThemeStoreSectionCard(
                    title = stringResource(R.string.theme_store_upload_section_author),
                    icon = Icons.Rounded.Person,
                ) {
                    UploadHint(
                        stringResource(R.string.theme_store_upload_source_preference_hint),
                    )
                    if (accountSession == null) {
                        ThemeStoreInlineNotice(
                            text = stringResource(R.string.theme_store_upload_login_required),
                            isError = true,
                        )
                        Button(
                            onClick = onLogin,
                            modifier = Modifier.fillMaxWidth(),
                            shapes = ButtonDefaults.shapes(),
                        ) {
                            MaterialText(stringResource(R.string.theme_store_upload_relogin))
                        }
                    } else {
                        UploadTextField(
                            value = accountSession.user.displayName.ifBlank { accountSession.user.username },
                            onValueChange = {},
                            label = stringResource(R.string.theme_store_upload_author),
                            enabled = false,
                        )
                        val activeAuthor = accountSession.activeAuthor
                        val pendingAuthor = accountSession.authors.any {
                            it.status == "pending"
                        }
                        UploadHint(
                            when {
                                activeAuthor != null -> stringResource(
                                    R.string.theme_store_upload_author_active,
                                    accountSession.user.username,
                                    activeAuthor.displayName ?: accountSession.user.displayName,
                                )

                                pendingAuthor -> stringResource(
                                    R.string.theme_store_upload_author_pending,
                                    accountSession.user.username,
                                )

                                else -> stringResource(
                                    R.string.theme_store_upload_author_new,
                                    accountSession.user.username,
                                )
                            },
                        )
                        if (authorAvatarUrl != null) {
                            UploadAuthorAvatar(url = authorAvatarUrl, token = source.token)
                        } else {
                            UploadPickerRow(
                                icon = Icons.Rounded.Person,
                                label = stringResource(R.string.theme_store_upload_avatar),
                                value = avatarName,
                                enabled = !submitting,
                                thumbnail = avatarUri,
                                thumbnailShape = CircleShape,
                                onClick = { avatarPicker.launch(arrayOf("image/*")) },
                            )
                            UploadHint(stringResource(R.string.theme_store_upload_avatar_hint))
                        }
                    }
                }
            }
            item(key = "about") {
                ThemeStoreSectionCard(
                    title = stringResource(R.string.theme_store_upload_section_about),
                    icon = Icons.AutoMirrored.Rounded.Article,
                ) {
                    UploadTextField(
                        value = description,
                        onValueChange = { description = it },
                        label = stringResource(R.string.theme_store_upload_description),
                        enabled = !submitting,
                        singleLine = false,
                        minLines = 4,
                    )
                    UploadHint(stringResource(R.string.theme_store_upload_markdown_hint))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        listOf(
                            "GitHub" to "yourname@github",
                            "Gitee" to "yourname@gitee",
                            "Bilibili" to "yourname@bilibili",
                            "Coolapk" to "yourname@coolapk",
                            "Telegram" to "yourname@telegram",
                            "Weibo" to "yourname@weibo",
                            "Xiaohongshu" to "yourname@xiaohongshu",
                            "XDA" to "yourname@xda",
                            "YouTube" to "yourname@youtube",
                            "Afdian" to "yourname@afdian",
                        ).forEach { (label, mention) ->
                            AssistChip(
                                onClick = { appendMention(mention) },
                                label = { MaterialText(label) },
                                enabled = !submitting,
                                shape = MaterialTheme.shapes.small,
                            )
                        }
                    }
                    UploadTextField(
                        value = changelog,
                        onValueChange = { changelog = it },
                        label = stringResource(R.string.theme_store_upload_changelog),
                        enabled = !submitting,
                        singleLine = false,
                        minLines = 3,
                    )
                    UploadHint(stringResource(R.string.theme_store_upload_markdown_hint_short))
                }
            }
            item(key = "files") {
                ThemeStoreSectionCard(
                    title = stringResource(R.string.theme_store_upload_section_files),
                    icon = Icons.Rounded.Folder,
                ) {
                    UploadPickerRow(
                        icon = Icons.Rounded.Folder,
                        label = stringResource(R.string.theme_store_upload_package),
                        value = packageName,
                        enabled = !submitting,
                        onClick = { packagePicker.launch(arrayOf("*/*")) },
                    )
                    if (packageAdaptive) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            AdaptiveThemeBadge()
                            MaterialText(
                                text = stringResource(R.string.theme_adaptive_upload_notice),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                    FilledTonalButton(
                        onClick = {
                            scope.launch {
                                presetBusy = true
                                presetError = null
                                val file = runCatching { onExportCurrentPreset() }.getOrNull()
                                if (file != null) {
                                    packageUri = Uri.fromFile(file)
                                    packageLabel = presetName
                                } else {
                                    presetError = context.getString(R.string.theme_store_upload_preset_failed)
                                }
                                presetBusy = false
                            }
                        },
                        enabled = !submitting && !presetBusy && !adaptiveBusy,
                        shapes = ButtonDefaults.shapes(),
                        colors = ButtonDefaults.filledTonalButtonColors(
                            containerColor = MaterialTheme.colorScheme.secondaryContainer,
                            contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.Phone,
                            contentDescription = null,
                        )
                        MaterialText(
                            text = stringResource(
                                if (presetBusy) R.string.theme_store_upload_generating
                                else R.string.theme_store_upload_use_current,
                            ),
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    FilledTonalButton(
                        onClick = {
                            scope.launch {
                                adaptiveBusy = true
                                presetError = null
                                val file = runCatching { onLoadAdaptiveTheme() }.getOrNull()
                                if (file != null) {
                                    packageUri = Uri.fromFile(file)
                                    packageLabel = adaptivePresetName
                                } else {
                                    presetError = context.getString(
                                        R.string.theme_store_upload_adaptive_missing,
                                    )
                                }
                                adaptiveBusy = false
                            }
                        },
                        enabled = !submitting && !adaptiveBusy && !presetBusy,
                        shapes = ButtonDefaults.shapes(),
                        colors = ButtonDefaults.filledTonalButtonColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.AutoAwesome,
                            contentDescription = null,
                        )
                        MaterialText(
                            text = stringResource(
                                if (adaptiveBusy) R.string.theme_store_upload_generating
                                else R.string.theme_store_upload_use_adaptive,
                            ),
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }
                    UploadHint(stringResource(R.string.theme_store_upload_adaptive_hint))
                    UploadHint(stringResource(R.string.theme_store_upload_current_hint))
                    if (presetError != null) {
                        ThemeStoreInlineNotice(
                            text = presetError.orEmpty(),
                            isError = true,
                        )
                    }
                    UploadPickerRow(
                        icon = Icons.Rounded.Image,
                        label = stringResource(R.string.theme_store_upload_preview),
                        value = previewName,
                        enabled = !submitting,
                        thumbnail = previewUri,
                        onClick = { previewPicker.launch(arrayOf("image/*")) },
                    )
                    UploadPickerRow(
                        icon = Icons.Rounded.PhotoLibrary,
                        label = stringResource(R.string.theme_store_upload_screenshots),
                        value = screenshotSummary,
                        enabled = !submitting,
                        onClick = { screenshotPicker.launch("image/*") },
                    )
                    if (packageUri == null || previewUri == null) {
                        ThemeStoreInlineNotice(
                            text = stringResource(R.string.theme_store_upload_files_required),
                            isError = true,
                        )
                    }
                }
            }
        }
    }

    if (authorApplyOpen) {
        val reapply = accountSession?.authors?.any {
            it.status == "revoked" || it.status == "retired"
        } == true
        val minimum = if (reapply) 10 else 5
        ExpressiveDialog(
            onDismissRequest = {
                if (!submitting) {
                    authorApplyOpen = false
                    authorApplyError = null
                }
            },
            icon = {
                MaterialIcon(
                    imageVector = Icons.Rounded.Person,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
            },
            title = {
                MaterialText(stringResource(R.string.theme_store_upload_author_apply_title))
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    MaterialText(
                        text = stringResource(
                            if (reapply) {
                                R.string.theme_store_upload_author_apply_hint_reapply
                            } else {
                                R.string.theme_store_upload_author_apply_hint
                            },
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedTextField(
                        value = authorApplyNote,
                        onValueChange = {
                            authorApplyNote = it.take(500)
                            authorApplyError = null
                        },
                        label = {
                            MaterialText(stringResource(R.string.theme_store_upload_author_apply_note))
                        },
                        placeholder = {
                            MaterialText(
                                stringResource(
                                    R.string.theme_store_upload_author_apply_note_hint,
                                    minimum,
                                ),
                            )
                        },
                        minLines = 3,
                        maxLines = 6,
                        isError = authorApplyError != null,
                        supportingText = if (authorApplyError != null) {
                            { MaterialText(authorApplyError.orEmpty()) }
                        } else {
                            null
                        },
                        enabled = !submitting,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    MaterialText(
                        text = stringResource(
                            R.string.theme_store_upload_author_apply_count,
                            authorApplyNote.length,
                            500,
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        authorApplyOpen = false
                        authorApplyError = null
                    },
                    enabled = !submitting,
                    shapes = ButtonDefaults.shapes(),
                ) {
                    MaterialText(stringResource(R.string.theme_store_upload_author_apply_cancel))
                }
            },
            confirmButton = {
                Button(
                    onClick = ::confirmAuthorApplication,
                    enabled = !submitting,
                    shapes = ButtonDefaults.shapes(),
                ) {
                    if (submitting) {
                        CircularWavyProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            stroke = Stroke(width = 2f),
                        )
                    } else {
                        MaterialText(stringResource(R.string.theme_store_upload_submit))
                    }
                }
            },
        )
    }
}

@Composable
private fun UploadTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    singleLine: Boolean = true,
    minLines: Int = 1,
    keyboardType: KeyboardType = KeyboardType.Text,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { MaterialText(label) },
        modifier = modifier.fillMaxWidth(),
        enabled = enabled,
        singleLine = singleLine,
        minLines = minLines,
        shape = MaterialTheme.shapes.large,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        textStyle = MaterialTheme.typography.bodyLarge,
    )
}

@Composable
private fun UploadAuthorAvatar(url: String, token: String) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            AsyncImage(
                model = themeImageRequest(LocalContext.current, url, token),
                contentDescription = null,
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .size(42.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.surfaceContainerLow),
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                MaterialText(
                    text = stringResource(R.string.theme_store_upload_avatar),
                    style = MaterialTheme.typography.labelLarge,
                )
                MaterialText(
                    text = stringResource(R.string.theme_store_upload_avatar_existing),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun UploadPickerRow(
    icon: ImageVector,
    label: String,
    value: String,
    enabled: Boolean,
    onClick: () -> Unit,
    thumbnail: Uri? = null,
    thumbnailShape: Shape = MaterialTheme.shapes.small,
) {
    Surface(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (thumbnail != null) {
                AsyncImage(
                    model = thumbnail,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .size(42.dp)
                        .clip(thumbnailShape)
                        .background(MaterialTheme.colorScheme.surfaceContainerLow),
                )
            } else {
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .clip(thumbnailShape)
                        .background(MaterialTheme.colorScheme.surfaceContainerLow),
                    contentAlignment = Alignment.Center,
                ) {
                    MaterialIcon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(22.dp),
                    )
                }
            }
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                MaterialText(
                    text = label,
                    style = MaterialTheme.typography.labelLarge,
                )
                MaterialText(
                    text = value,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            MaterialIcon(
                imageVector = Icons.Rounded.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

@Composable
private fun UploadHint(text: String, isError: Boolean = false) {
    MaterialText(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = if (isError) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
    )
}

@Composable
private fun UploadSubmitBar(
    submitting: Boolean,
    phase: ThemeStoreUploadPhase,
    progress: Float,
    transferredBytes: Long,
    totalBytes: Long,
    speedBytesPerSecond: Long,
    etaSeconds: Long?,
    canSubmit: Boolean,
    errorText: String?,
    onSubmit: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface),
    ) {
        HorizontalDivider(
            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
        )
        Column(
            modifier = Modifier
                .navigationBarsPadding()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (submitting) {
                when (phase) {
                    ThemeStoreUploadPhase.PREPARING,
                    ThemeStoreUploadPhase.VERIFYING -> {
                        LinearWavyProgressIndicator(
                            modifier = Modifier.fillMaxWidth(),
                        )
                        UploadHint(
                            stringResource(
                                if (phase == ThemeStoreUploadPhase.PREPARING) {
                                    R.string.theme_store_upload_phase_preparing
                                } else {
                                    R.string.theme_store_upload_phase_verifying
                                },
                            ),
                        )
                    }

                    ThemeStoreUploadPhase.UPLOADING -> {
                        LinearWavyProgressIndicator(
                            progress = { progress.coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            MaterialText(
                                text = stringResource(
                                    R.string.theme_store_upload_phase_uploading,
                                    (progress.coerceIn(0f, 1f) * 100).roundToInt(),
                                ),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            ThemeStoreSpeedBadge(speedBytesPerSecond)
                        }
                        if (totalBytes > 0L) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                MaterialText(
                                    text = stringResource(
                                        R.string.theme_store_transfer_bytes,
                                        formatTransferBytes(transferredBytes),
                                        formatTransferBytes(totalBytes),
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                etaSeconds?.let { eta ->
                                    MaterialText(
                                        text = stringResource(
                                            R.string.theme_store_transfer_eta,
                                            formatTransferEta(eta),
                                        ),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }

                    else -> Unit
                }
            }
            when {
                !errorText.isNullOrBlank() -> ThemeStoreInlineNotice(
                    text = errorText,
                    isError = true,
                )
                !submitting && !canSubmit -> UploadHint(
                    stringResource(R.string.theme_store_upload_incomplete),
                )
            }
            Button(
                onClick = onSubmit,
                enabled = canSubmit || submitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shapes = ButtonDefaults.shapes(),
            ) {
                if (submitting) {
                    CircularWavyProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        trackColor = MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.24f),
                        stroke = Stroke(width = 2f),
                    )
                    Spacer(Modifier.width(8.dp))
                    MaterialText(stringResource(R.string.theme_store_upload_submitting_short))
                } else {
                    MaterialText(stringResource(R.string.theme_store_upload_submit))
                }
            }
        }
    }
}

private fun queryDisplayName(context: Context, uri: Uri): String {
    val queried = runCatching {
        context.contentResolver.query(
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
