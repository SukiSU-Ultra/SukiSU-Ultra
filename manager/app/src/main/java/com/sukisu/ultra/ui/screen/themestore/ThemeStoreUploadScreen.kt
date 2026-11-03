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
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.PhotoLibrary
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.LinearWavyProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.material3.TopAppBar as MaterialTopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
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
import coil.request.ImageRequest
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.model.AccountThemeSummary
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import kotlinx.coroutines.launch
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
    optionsLoading: Boolean,
    optionsError: String?,
    uploadPhase: ThemeStoreUploadPhase,
    uploadProgress: Float,
    submitting: Boolean,
    errorText: String?,
    onBack: () -> Unit,
    onLogin: () -> Unit,
    onSubmit: (ThemeStoreUploadInput) -> Unit,
    onExportCurrentPreset: suspend () -> File?,
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
    var packageLabel by rememberSaveable { mutableStateOf<String?>(null) }
    var packageUri by rememberSaveable(stateSaver = UploadUriSaver) {
        mutableStateOf(null)
    }
    var previewUri by rememberSaveable(stateSaver = UploadUriSaver) {
        mutableStateOf(null)
    }
    var avatarUri by rememberSaveable(stateSaver = UploadUriSaver) {
        mutableStateOf(null)
    }
    var screenshotUris by rememberSaveable(stateSaver = UploadUriListSaver) {
        mutableStateOf(emptyList())
    }

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

    val noFile = stringResource(R.string.theme_store_upload_no_file)
    val presetName = stringResource(R.string.theme_store_upload_current_preset)
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

    fun submit() {
        if (submitting) return
        val session = accountSession ?: return
        val packageFile = packageUri ?: return
        val previewFile = previewUri ?: return
        onSubmit(
            ThemeStoreUploadInput(
                id = selectedUpdateId,
                version = version,
                name = name,
                author = session.user.displayName.ifBlank { session.user.username },
                authorId = "",
                description = description,
                tags = tags,
                license = license,
                minManagerVersion = minManagerVersion,
                changelog = changelog,
                packageUri = packageFile,
                previewUri = previewFile,
                avatarUri = avatarUri,
                screenshotUris = screenshotUris,
            ),
        )
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
        if (!values.remove(tag) && values.size < 10) values.add(tag)
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
                        editingTheme != null -> UploadHint(
                            stringResource(R.string.theme_store_edit_id_hint),
                        )

                        optionsLoading -> UploadHint(
                            stringResource(R.string.theme_store_upload_id_loading),
                        )

                        !optionsError.isNullOrBlank() -> UploadHint(
                            stringResource(R.string.theme_store_upload_id_error, optionsError),
                        )

                        else -> UploadHint(
                            stringResource(R.string.theme_store_upload_id_hint),
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
                        listOf("light", "dark", "pink", "cute", "minimal", "gradient", "anime", "blue", "purple", "green")
                            .forEach { tag ->
                                FilterChip(
                                    selected = tagValues.contains(tag),
                                    onClick = { toggleTag(tag) },
                                    enabled = !submitting,
                                    label = { MaterialText(tag) },
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
                        UploadHint(
                            if (activeAuthor != null) {
                                stringResource(
                                    R.string.theme_store_upload_author_active,
                                    accountSession.user.username,
                                    activeAuthor.displayName ?: accountSession.user.displayName,
                                )
                            } else {
                                stringResource(
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
                    MaterialTextButton(
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
                        enabled = !submitting && !presetBusy,
                        modifier = Modifier.fillMaxWidth(),
                        shapes = ButtonDefaults.shapes(),
                    ) {
                        MaterialText(
                            text = stringResource(
                                if (presetBusy) R.string.theme_store_upload_generating
                                else R.string.theme_store_upload_use_current,
                            ),
                        )
                    }
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
                model = ImageRequest.Builder(LocalContext.current)
                    .data(url)
                    .apply {
                        if (token.isNotBlank()) {
                            addHeader(ThemeStoreRepository.TOKEN_HEADER, token)
                        }
                    }
                    .build(),
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
                    ThemeStoreUploadPhase.VERIFYING -> LinearWavyProgressIndicator(
                        modifier = Modifier.fillMaxWidth(),
                    )
                    ThemeStoreUploadPhase.UPLOADING -> LinearWavyProgressIndicator(
                        progress = { progress.coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    else -> Unit
                }
                UploadHint(
                    when (phase) {
                        ThemeStoreUploadPhase.PREPARING ->
                            stringResource(R.string.theme_store_upload_phase_preparing)
                        ThemeStoreUploadPhase.UPLOADING -> stringResource(
                            R.string.theme_store_upload_phase_uploading,
                            (progress.coerceIn(0f, 1f) * 100).roundToInt(),
                        )
                        ThemeStoreUploadPhase.VERIFYING ->
                            stringResource(R.string.theme_store_upload_phase_verifying)
                        else -> ""
                    },
                )
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
