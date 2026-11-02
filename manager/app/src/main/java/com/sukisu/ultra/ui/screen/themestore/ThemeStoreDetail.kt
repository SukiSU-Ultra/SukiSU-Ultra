package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.PagerState
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.IconButton as MaterialIconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.material3.TopAppBar as MaterialTopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import coil.compose.rememberAsyncImagePainter
import coil.request.ImageRequest
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.ThemeStoreEntry
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.util.ThemePackageStorage
import kotlin.math.roundToInt

@Composable
internal fun ThemeStoreDetailScreen(
    item: ThemeStoreItem,
    state: ThemeStoreUiState,
    onBack: () -> Unit,
    onDownload: (ThemeStoreItem) -> Unit,
    onRefresh: () -> Unit,
) {
    val entry = item.entry
    val compatible = entry.isCompatible()
    val downloading = state.downloadingKey == item.key
    val downloadBusy = state.downloadingKey != null
    val sourceName = if (item.source.isDefault) {
        stringResource(R.string.theme_store_default_source)
    } else {
        item.source.name.ifBlank {
            item.source.baseUrl
                .removePrefix("https://")
                .removePrefix("http://")
                .removeSuffix("/")
        }
    }
    val formatVersion = stringResource(R.string.theme_store_format_version, entry.formatVersion)
    val previewUrl = remember(entry.previewPath, item.source.baseUrl) {
        ThemeStoreRepository.assetUrl(item.source.baseUrl, entry.previewPath)
    }
    val screenshotUrls = remember(entry.screenshotPaths, item.source.baseUrl) {
        entry.screenshotPaths
            .mapNotNull { path -> ThemeStoreRepository.assetUrl(item.source.baseUrl, path) }
            .distinct()
    }
    val avatarUrl = remember(entry.avatarPath, item.source.baseUrl) {
        ThemeStoreRepository.assetUrl(item.source.baseUrl, entry.avatarPath)
    }
    // Keep the cover in the pager so every uploaded image stays browsable, then the screenshots.
    val galleryImages = remember(previewUrl, screenshotUrls) {
        (listOfNotNull(previewUrl) + screenshotUrls).distinct()
    }
    val pagerState = rememberPagerState(pageCount = { galleryImages.size.coerceAtLeast(1) })
    val pageContainer = MaterialTheme.colorScheme.surface

    ExpressiveScaffold(
        containerColor = pageContainer,
        topBar = {
            MaterialTopAppBar(
                title = {},
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                actions = {
                    MaterialIconButton(
                        onClick = onRefresh,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.Refresh,
                            contentDescription = stringResource(R.string.theme_store_refresh),
                        )
                    }
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
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(
                top = 8.dp,
                bottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 32.dp,
            ),
        ) {
            item(key = "gallery") {
                ThemeStoreGallery(
                    images = galleryImages,
                    pagerState = pagerState,
                    token = item.source.token,
                )
            }
            item(key = "header") {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 20.dp, end = 20.dp, top = 18.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        MaterialText(
                            text = entry.name,
                            style = MaterialTheme.typography.headlineSmall,
                            modifier = Modifier.weight(1f),
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (compatible) {
                            Spacer(Modifier.width(12.dp))
                            Button(
                                onClick = { onDownload(item) },
                                enabled = !downloadBusy || downloading,
                                shape = RoundedCornerShape(99.dp),
                                contentPadding = PaddingValues(horizontal = 18.dp),
                                modifier = Modifier.height(44.dp),
                            ) {
                                if (downloading) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        strokeWidth = 2.dp,
                                        color = MaterialTheme.colorScheme.onPrimary,
                                    )
                                    Spacer(Modifier.width(6.dp))
                                    MaterialText(stringResource(R.string.theme_store_downloading_short))
                                } else {
                                    MaterialText(stringResource(R.string.theme_store_download_apply))
                                }
                            }
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    MaterialText(
                        text = buildString {
                            append("v${entry.version}")
                            append(" · ")
                            append(formatVersion)
                            if (entry.size > 0) {
                                append(" · ")
                                append(formatBytes(entry.size))
                            }
                            append(" · ")
                            append(sourceName)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (entry.tags.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        MaterialText(
                            text = entry.tags.joinToString(" · "),
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    if (!compatible) {
                        Spacer(Modifier.height(8.dp))
                        MaterialText(
                            text = stringResource(R.string.theme_store_requires_manager),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    if (downloading) {
                        Spacer(Modifier.height(12.dp))
                        LinearProgressIndicator(
                            progress = { state.downloadProgress.coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(6.dp))
                        MaterialText(
                            text = stringResource(
                                R.string.theme_store_downloading,
                                (state.downloadProgress * 100).roundToInt(),
                            ),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
            if (entry.description.isNotBlank()) {
                item(key = "description") {
                    ExpandableMarkdownText(
                        text = themeStoreMarkdown(entry.description),
                        resetKey = item.key,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 20.dp, end = 20.dp, top = 16.dp),
                    )
                }
            }
            if (entry.changelog.isNotBlank()) {
                item(key = "changelog") {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 20.dp, end = 20.dp, top = 20.dp),
                    ) {
                        MaterialText(
                            text = stringResource(R.string.theme_store_changelog),
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Spacer(Modifier.height(8.dp))
                        MaterialText(
                            text = themeStoreMarkdown(entry.changelog),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
            if (entry.author.isNotBlank()) {
                item(key = "author") {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 20.dp, end = 20.dp, top = 24.dp),
                    ) {
                        MaterialText(
                            text = stringResource(R.string.theme_store_author_section),
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Spacer(Modifier.height(10.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(46.dp)
                                    .clip(CircleShape)
                                    .background(MaterialTheme.colorScheme.surfaceContainerHigh),
                                contentAlignment = Alignment.Center,
                            ) {
                                MaterialIcon(
                                    imageVector = Icons.Rounded.Person,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(26.dp),
                                )
                                if (avatarUrl != null) {
                                    AsyncImage(
                                        model = themeImageRequest(
                                            context = LocalContext.current,
                                            url = avatarUrl,
                                            token = item.source.token,
                                        ),
                                        contentDescription = entry.author,
                                        contentScale = ContentScale.Crop,
                                        modifier = Modifier.fillMaxSize(),
                                    )
                                }
                            }
                            Spacer(Modifier.width(12.dp))
                            MaterialText(
                                text = entry.author,
                                style = MaterialTheme.typography.bodyLarge,
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * Single-image carousel for the preview and every screenshot. Each page fills the width and
 * swipes to the next image; the strip height follows the current image's aspect ratio within
 * sensible limits so the whole image stays visible.
 */
@Composable
private fun ThemeStoreGallery(
    images: List<String>,
    pagerState: PagerState,
    token: String,
) {
    if (images.isEmpty()) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(220.dp)
                .background(MaterialTheme.colorScheme.surfaceContainerHigh),
            contentAlignment = Alignment.Center,
        ) {
            MaterialIcon(
                imageVector = Icons.Rounded.Palette,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(42.dp),
            )
        }
        return
    }
    val context = LocalContext.current
    val currentPainter = rememberAsyncImagePainter(
        model = themeImageRequest(
            context = context,
            url = images[pagerState.settledPage.coerceIn(images.indices)],
            token = token,
        ),
    )
    val intrinsic = currentPainter.intrinsicSize
    val aspect = if (intrinsic.width > 0f && intrinsic.height > 0f) {
        intrinsic.height / intrinsic.width
    } else {
        0.72f
    }
    BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
        val targetHeight = (maxWidth * aspect).coerceIn(200.dp, 420.dp)
        val galleryHeight by animateDpAsState(
            targetValue = targetHeight,
            label = "themeGalleryHeight",
        )
        HorizontalPager(
            state = pagerState,
            modifier = Modifier
                .fillMaxWidth()
                .height(galleryHeight),
        ) { page ->
            AsyncImage(
                model = themeImageRequest(
                    context = context,
                    url = images[page],
                    token = token,
                ),
                contentDescription = null,
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.surfaceContainerHigh),
            )
        }
    }
    if (images.size > 1) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 10.dp),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            repeat(images.size) { index ->
                val selectedDot = pagerState.currentPage == index
                Box(
                    modifier = Modifier
                        .padding(horizontal = 3.dp)
                        .width(if (selectedDot) 18.dp else 6.dp)
                        .height(6.dp)
                        .clip(RoundedCornerShape(99.dp))
                        .background(
                            if (selectedDot) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.outlineVariant,
                        ),
                )
            }
        }
    }
}

@Composable
private fun ExpandableMarkdownText(
    text: AnnotatedString,
    resetKey: Any,
    modifier: Modifier = Modifier,
) {
    var expanded by rememberSaveable(resetKey) { mutableStateOf(false) }
    var overflowed by remember(resetKey) { mutableStateOf(false) }
    Column(modifier = modifier) {
        MaterialText(
            text = text,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = if (expanded) Int.MAX_VALUE else 3,
            overflow = TextOverflow.Ellipsis,
            onTextLayout = { layout ->
                if (!expanded) overflowed = layout.hasVisualOverflow
            },
        )
        if (overflowed || expanded) {
            MaterialTextButton(
                onClick = { expanded = !expanded },
                contentPadding = PaddingValues(0.dp),
            ) {
                MaterialText(
                    text = stringResource(
                        if (expanded) R.string.theme_store_show_less
                        else R.string.theme_store_show_more,
                    ),
                )
            }
        }
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes <= 0) return ""
    val kb = bytes / 1024.0
    return if (kb < 1024.0) {
        String.format(java.util.Locale.getDefault(), "%.0f KB", kb)
    } else {
        String.format(java.util.Locale.getDefault(), "%.1f MB", kb / 1024.0)
    }
}

private fun ThemeStoreEntry.isCompatible(): Boolean {
    if (formatVersion > ThemePackageStorage.CURRENT_VERSION) return false
    return minManagerVersion <= BuildConfig.VERSION_CODE.toLong()
}

@Composable
internal fun ThemeBannerImage(
    entry: ThemeStoreEntry,
    baseUrl: String,
    token: String,
    modifier: Modifier,
) {
    val path = entry.previewPath.ifBlank { entry.screenshotPaths.firstOrNull().orEmpty() }
    val url = ThemeStoreRepository.assetUrl(baseUrl, path)
    if (url == null) {
        Box(
            modifier = modifier.background(MaterialTheme.colorScheme.surfaceContainerHigh),
        )
        return
    }
    AsyncImage(
        model = themeImageRequest(LocalContext.current, url, token),
        contentDescription = entry.name,
        contentScale = ContentScale.Crop,
        modifier = modifier,
    )
}

private fun themeImageRequest(context: android.content.Context, url: String, token: String): ImageRequest =
    ImageRequest.Builder(context)
        .data(url)
        .crossfade(true)
        .apply {
            if (token.isNotBlank()) {
                addHeader(ThemeStoreRepository.TOKEN_HEADER, token)
            }
        }
        .build()
