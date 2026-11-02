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
import androidx.compose.foundation.layout.ColumnScope
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.PhotoLibrary
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon as MaterialIcon
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import kotlinx.coroutines.launch
import java.io.File
import java.security.SecureRandom

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
    initialAuthor: String,
    initialAuthorId: String,
    submitting: Boolean,
    errorText: String?,
    onBack: () -> Unit,
    onSubmit: (ThemeStoreUploadInput) -> Unit,
    onExportCurrentPreset: suspend () -> File?,
) {
    var id by rememberSaveable { mutableStateOf("") }
    var version by rememberSaveable { mutableStateOf("1") }
    var name by rememberSaveable { mutableStateOf("") }
    var author by rememberSaveable(initialAuthor) { mutableStateOf(initialAuthor) }
    var authorId by rememberSaveable(initialAuthorId) { mutableStateOf(initialAuthorId) }
    var tags by rememberSaveable { mutableStateOf("") }
    var license by rememberSaveable { mutableStateOf("") }
    var minManagerVersion by rememberSaveable { mutableStateOf("0") }
    var description by rememberSaveable { mutableStateOf("") }
    var changelog by rememberSaveable { mutableStateOf("") }
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
    val canSubmit = !submitting && id.isNotBlank() && name.isNotBlank() &&
        authorId.trim().length >= 16 && packageUri != null && previewUri != null &&
        versionValue != null && versionValue >= 1

    fun submit() {
        if (submitting) return
        val packageFile = packageUri ?: return
        val previewFile = previewUri ?: return
        onSubmit(
            ThemeStoreUploadInput(
                id = id,
                version = version,
                name = name,
                author = author,
                authorId = authorId,
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

    fun generateAuthorId() {
        val random = SecureRandom()
        val bytes = ByteArray(24)
        random.nextBytes(bytes)
        authorId = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    fun appendMention(mention: String) {
        val spacer = if (description.isBlank() || description.endsWith(" ")) "" else " "
        description += spacer + mention + " "
    }

    val pageContainer = MaterialTheme.colorScheme.surface
    ExpressiveScaffold(
        modifier = Modifier.imePadding(),
        containerColor = pageContainer,
        topBar = {
            MaterialTopAppBar(
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                title = {
                    MaterialText(
                        text = stringResource(R.string.theme_store_upload_title),
                        style = MaterialTheme.typography.titleLarge,
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
            item(key = "intro") {
                UploadIntroCard(source = source)
            }
            item(key = "basic") {
                UploadSectionCard(title = stringResource(R.string.theme_store_upload_section_basic)) {
                    UploadTextField(
                        value = id,
                        onValueChange = { id = it },
                        label = stringResource(R.string.theme_store_upload_id),
                        enabled = !submitting,
                    )
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
                    UploadTextField(
                        value = license,
                        onValueChange = { license = it },
                        label = stringResource(R.string.theme_store_upload_license),
                        enabled = !submitting,
                    )
                }
            }
            item(key = "author") {
                UploadSectionCard(title = stringResource(R.string.theme_store_upload_section_author)) {
                    UploadTextField(
                        value = author,
                        onValueChange = { author = it },
                        label = stringResource(R.string.theme_store_upload_author),
                        enabled = !submitting,
                    )
                    UploadTextField(
                        value = authorId,
                        onValueChange = { authorId = it },
                        label = stringResource(R.string.theme_store_upload_author_id),
                        enabled = !submitting,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                    ) {
                        MaterialTextButton(
                            onClick = ::generateAuthorId,
                            enabled = !submitting,
                        ) {
                            MaterialText(stringResource(R.string.theme_store_generate_author_id))
                        }
                    }
                    UploadHint(stringResource(R.string.theme_store_upload_author_id_hint))
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
            item(key = "about") {
                UploadSectionCard(title = stringResource(R.string.theme_store_upload_section_about)) {
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
                        listOf("@github", "@gitee", "@bilibili", "@coolapk", "@telegram", "@weibo")
                            .forEach { mention ->
                                AssistChip(
                                    onClick = { appendMention(mention) },
                                    label = { MaterialText(mention) },
                                    enabled = !submitting,
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
                UploadSectionCard(title = stringResource(R.string.theme_store_upload_section_files)) {
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
                        UploadHint(presetError.orEmpty(), isError = true)
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
                }
            }
        }
    }
}

@Composable
private fun UploadIntroCard(source: ThemeStoreSource) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
        ),
    ) {
        Row(
            modifier = Modifier.padding(18.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center,
            ) {
                MaterialIcon(
                    imageVector = Icons.Rounded.FileUpload,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onPrimaryContainer,
                    modifier = Modifier.size(22.dp),
                )
            }
            Spacer(Modifier.width(14.dp))
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                MaterialText(
                    text = stringResource(R.string.theme_store_upload_summary),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                MaterialText(
                    text = if (source.isDefault) {
                        stringResource(R.string.theme_store_default_source)
                    } else {
                        source.name.ifBlank { source.baseUrl }
                    },
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
}

@Composable
private fun UploadSectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
        ),
    ) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            MaterialText(
                text = title,
                style = MaterialTheme.typography.titleMedium,
            )
            content()
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
        shape = RoundedCornerShape(16.dp),
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        textStyle = MaterialTheme.typography.bodyLarge,
    )
}

@Composable
private fun UploadPickerRow(
    icon: ImageVector,
    label: String,
    value: String,
    enabled: Boolean,
    onClick: () -> Unit,
    thumbnail: Uri? = null,
    thumbnailShape: Shape = RoundedCornerShape(12.dp),
) {
    Surface(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
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
            when {
                !errorText.isNullOrBlank() -> UploadHint(errorText, isError = true)
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
                shape = RoundedCornerShape(50),
            ) {
                if (submitting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
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
