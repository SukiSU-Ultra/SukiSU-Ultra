package com.sukisu.ultra.ui.screen.colorpalette

import android.annotation.SuppressLint
import androidx.annotation.StringRes
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.MenuBook
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VolunteerActivism
import androidx.compose.material.icons.outlined.Extension
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.rounded.BatteryFull
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.Cottage
import androidx.compose.material.icons.rounded.Extension
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.SignalCellularAlt
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.HorizontalDivider as MaterialDivider
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.material3.Surface as MaterialSurface
import androidx.compose.material3.Text as MaterialText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import coil.request.ImageRequest
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.statustag.StatusTagMaterial
import com.sukisu.ultra.ui.component.statustag.StatusTagMiuix
import com.sukisu.ultra.ui.theme.ColorMode
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalCardBackgroundAlpha
import com.sukisu.ultra.ui.theme.LocalColorMode
import com.sukisu.ultra.ui.theme.Shapes
import com.sukisu.ultra.ui.theme.Typography
import com.sukisu.ultra.ui.theme.backgroundAwareCardColors
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import com.sukisu.ultra.ui.theme.effectiveFor
import com.sukisu.ultra.ui.theme.rememberKernelSUColorScheme
import com.sukisu.ultra.ui.util.BgStorage
import top.yukonga.miuix.kmp.basic.Badge as MiuixBadge
import top.yukonga.miuix.kmp.basic.BadgedBox as MiuixBadgedBox
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon as MiuixIcon
import top.yukonga.miuix.kmp.basic.NavigationBar
import top.yukonga.miuix.kmp.basic.NavigationBarItem
import top.yukonga.miuix.kmp.basic.Surface as MiuixSurface
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.ColorSchemeMode
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.ThemeColorSpec
import top.yukonga.miuix.kmp.theme.ThemeController
import top.yukonga.miuix.kmp.theme.ThemePaletteStyle
import java.io.File

/**
 * Everything the theme preview renders. It is built from the committed settings plus the
 * in-flight slider values, so the preview stays a pure function of the appearance options.
 */
@Immutable
internal data class ThemePreviewSpec(
    val keyColor: Int = 0,
    val isDark: Boolean = false,
    val isAmoled: Boolean = false,
    val miuixMonet: Boolean = false,
    val paletteStyle: PaletteStyle = PaletteStyle.TonalSpot,
    val colorSpec: ColorSpec.SpecVersion = ColorSpec.SpecVersion.SPEC_2025,
    val backgroundPath: String = "",
    val backgroundUpdatedAt: Long = 0L,
    val cardAlpha: Float = 0.6f,
    val backgroundBlurPercent: Int = 50,
    val backgroundScrimPercent: Int = -35,
    val floatingBottomBar: Boolean = false,
    val floatingBottomBarBlur: Boolean = false,
    val navigationBadge: Boolean = true,
    val pageScale: Float = 1f,
    val customHomeTitle: String = "",
)

private const val PreviewDesignWidthDp = 360f
private const val PreviewBadgeCount = "2"
private const val PreviewKernelVersion = "6.1.75"
private val PreviewBezelShape = RoundedCornerShape(34.dp)
private val PreviewScreenShape = RoundedCornerShape(29.dp)
private val PreviewBezelColor = Color(0xFF141417)

private data class MiuixPreviewDestination(
    @StringRes val label: Int,
    val icon: ImageVector,
)

private val MiuixPreviewDestinations = listOf(
    MiuixPreviewDestination(R.string.home, Icons.Rounded.Cottage),
    MiuixPreviewDestination(R.string.superuser, Icons.Rounded.Security),
    MiuixPreviewDestination(R.string.module, Icons.Rounded.Extension),
    MiuixPreviewDestination(R.string.settings, Icons.Rounded.Settings),
)

private data class MaterialPreviewDestination(
    @StringRes val label: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
)

private val MaterialPreviewDestinations = listOf(
    MaterialPreviewDestination(R.string.home, Icons.Filled.Home, Icons.Outlined.Home),
    MaterialPreviewDestination(R.string.superuser, Icons.Filled.Shield, Icons.Outlined.Shield),
    MaterialPreviewDestination(R.string.module, Icons.Filled.Extension, Icons.Outlined.Extension),
    MaterialPreviewDestination(R.string.settings, Icons.Filled.Settings, Icons.Outlined.Settings),
)

/**
 * A Miuix-flavoured home screen inside a device frame.
 *
 * The preview builds a nested [MiuixTheme] so it can show colors that differ from the page it is
 * embedded in (for example a dark preview while the page is light), and it never writes settings
 * or recreates the activity - it only reads [spec].
 */
@Composable
internal fun ThemePreviewMiuix(
    spec: ThemePreviewSpec,
    modifier: Modifier = Modifier,
) {
    val ambientColors = MiuixTheme.colorScheme
    val paletteStyle = remember(spec.paletteStyle) {
        runCatching { ThemePaletteStyle.valueOf(spec.paletteStyle.name) }
            .getOrDefault(ThemePaletteStyle.TonalSpot)
    }
    val colorSpec = remember(spec.colorSpec, spec.paletteStyle) {
        if (spec.colorSpec.effectiveFor(spec.paletteStyle) == ColorSpec.SpecVersion.SPEC_2025) {
            ThemeColorSpec.Spec2025
        } else {
            ThemeColorSpec.Spec2021
        }
    }
    val controller = ThemeController(
        colorSchemeMode = when {
            !spec.miuixMonet && spec.isDark -> ColorSchemeMode.Dark
            !spec.miuixMonet -> ColorSchemeMode.Light
            spec.isDark -> ColorSchemeMode.MonetDark
            else -> ColorSchemeMode.MonetLight
        },
        keyColor = if (spec.miuixMonet && spec.keyColor != 0) Color(spec.keyColor) else null,
        isDark = spec.isDark,
        paletteStyle = paletteStyle,
        colorSpec = colorSpec,
    )

    ThemePreviewLayout(
        modifier = modifier,
        caption = {
            PreviewCaption(
                text = stringResource(R.string.theme_preview_caption_miuix),
                dotColor = ambientColors.primary,
                textColor = ambientColors.onSurfaceVariantSummary,
            )
        },
    ) {
        MiuixTheme(controller = controller) {
            CompositionLocalProvider(
                LocalColorMode provides if (spec.isDark) ColorMode.DARK.value else ColorMode.LIGHT.value,
                LocalBackgroundImagePath provides spec.backgroundPath,
                LocalCardBackgroundAlpha provides spec.cardAlpha,
            ) {
                val colors = MiuixTheme.colorScheme
                PreviewDevice(
                    spec = spec,
                    screenColor = colors.surface,
                    contentColor = colors.onBackground,
                ) { screenModifier ->
                    MiuixPreviewScreen(spec, screenModifier)
                }
            }
        }
    }
}

/**
 * The Material 3 Expressive counterpart of [ThemePreviewMiuix].
 */
@Composable
internal fun ThemePreviewMaterial(
    spec: ThemePreviewSpec,
    modifier: Modifier = Modifier,
) {
    val ambientColors = MaterialTheme.colorScheme
    val colorScheme = rememberKernelSUColorScheme(
        seedColor = if (spec.keyColor == 0) Color.Unspecified else Color(spec.keyColor),
        isDark = spec.isDark,
        isAmoled = spec.isAmoled,
        paletteStyle = spec.paletteStyle,
        colorSpec = spec.colorSpec,
    )
    val hasCustomBackground = spec.backgroundPath.isNotEmpty()
    // Matches MaterialKernelSUTheme: default Card/Surface containers bypass backgroundAwareColor().
    val previewScheme = remember(colorScheme, hasCustomBackground, spec.cardAlpha) {
        if (!hasCustomBackground) {
            colorScheme
        } else {
            colorScheme.copy(
                surfaceBright = colorScheme.surfaceBright.copy(alpha = spec.cardAlpha),
                surfaceContainerLowest = colorScheme.surfaceContainerLowest.copy(alpha = spec.cardAlpha),
                surfaceContainerHighest = colorScheme.surfaceContainerHighest.copy(alpha = spec.cardAlpha),
            )
        }
    }

    MaterialExpressiveTheme(
        colorScheme = previewScheme,
        motionScheme = MotionScheme.expressive(),
        shapes = Shapes,
        typography = Typography,
    ) {
        CompositionLocalProvider(
            LocalColorMode provides if (spec.isDark) ColorMode.DARK.value else ColorMode.LIGHT.value,
            LocalBackgroundImagePath provides spec.backgroundPath,
            LocalCardBackgroundAlpha provides spec.cardAlpha,
        ) {
            ThemePreviewLayout(
                modifier = modifier,
                caption = {
                    PreviewCaption(
                        text = stringResource(R.string.theme_preview_caption_material),
                        dotColor = ambientColors.primary,
                        textColor = ambientColors.onSurfaceVariant,
                    )
                },
            ) {
                val colors = MaterialTheme.colorScheme
                PreviewDevice(
                    spec = spec,
                    screenColor = colors.surfaceContainer,
                    contentColor = colors.onSurface,
                ) { screenModifier ->
                    MaterialPreviewScreen(spec, screenModifier)
                }
            }
        }
    }
}

@SuppressLint("ConfigurationScreenWidthHeight")
@Composable
private fun ThemePreviewLayout(
    modifier: Modifier = Modifier,
    caption: @Composable () -> Unit,
    device: @Composable () -> Unit,
) {
    val configuration = LocalConfiguration.current
    val screenRatio = (configuration.screenWidthDp.toFloat() / configuration.screenHeightDp.toFloat())
        .takeIf { it.isFinite() && it > 0f }
        ?.coerceIn(0.42f, 0.62f)
        ?: 0.46f
    val description = stringResource(R.string.theme_preview_description)

    BoxWithConstraints(
        modifier = modifier.fillMaxWidth(),
        contentAlignment = Alignment.TopCenter,
    ) {
        val frameWidth = minOf(maxWidth * 0.52f, 248.dp)
        val frameHeight = frameWidth / screenRatio
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Box(
                modifier = Modifier
                    .width(frameWidth)
                    .height(frameHeight)
                    .shadow(22.dp, PreviewBezelShape, clip = false)
                    .background(
                        Brush.linearGradient(listOf(Color(0xFF242428), PreviewBezelColor)),
                        PreviewBezelShape,
                    )
                    .border(1.dp, Color.White.copy(alpha = 0.12f), PreviewBezelShape)
                    .padding(5.dp)
                    .clip(PreviewScreenShape)
                    .pointerInput(Unit) { detectTapGestures { } }
                    .clearAndSetSemantics { contentDescription = description },
            ) {
                device()
            }
            Spacer(Modifier.height(10.dp))
            caption()
        }
    }
}

/**
 * Draws the wallpaper (with its blur and scrim) and scales the screen content down to fit the
 * device frame. Scaling through [LocalDensity] keeps text crisp compared to a graphics-layer
 * scale and also previews the page-scale option.
 */
@Composable
private fun PreviewDevice(
    spec: ThemePreviewSpec,
    screenColor: Color,
    contentColor: Color,
    content: @Composable (Modifier) -> Unit,
) {
    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val baseDensity = LocalDensity.current
        val scale = ((maxWidth.value / PreviewDesignWidthDp).coerceIn(0.4f, 1f) * spec.pageScale)
            .coerceIn(0.3f, 1.15f)
        CompositionLocalProvider(
            // Font scale is pinned so an extreme system setting cannot distort this mock.
            LocalDensity provides Density(baseDensity.density * scale, fontScale = 1f),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(screenColor)
            ) {
                PreviewBackgroundImage(spec)
                if (spec.backgroundPath.isNotEmpty()) {
                    // Soft veil behind the transparent top bars, matching TopBarVeil on the real pages.
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(150.dp)
                            .background(
                                Brush.verticalGradient(
                                    listOf(screenColor.copy(alpha = 0.28f), Color.Transparent)
                                )
                            )
                    )
                }
                Column(modifier = Modifier.fillMaxSize()) {
                    PreviewStatusBar(contentColor)
                    content(Modifier.weight(1f))
                }
                PreviewCameraPunch()
            }
        }
    }
}

@Composable
private fun PreviewBackgroundImage(spec: ThemePreviewSpec) {
    if (spec.backgroundPath.isEmpty()) return
    val context = LocalContext.current
    val blurRadius = (BgStorage.BACKGROUND_BLUR_MAX_RADIUS_DP * spec.backgroundBlurPercent / 100f).dp
    val request = remember(spec.backgroundPath, spec.backgroundUpdatedAt) {
        // Same recipe as the real background: the mtime parameter invalidates the cache after a
        // re-crop even though the file path stays the same.
        val file = File(spec.backgroundPath)
        ImageRequest.Builder(context)
            .data(file)
            .setParameter("mtime", file.lastModified(), memoryCacheKey = null)
            .build()
    }

    AsyncImage(
        model = request,
        contentDescription = null,
        contentScale = ContentScale.Crop,
        modifier = Modifier
            .fillMaxSize()
            .then(if (blurRadius > 0.dp) Modifier.blur(blurRadius) else Modifier),
    )

    val scrimPercent = spec.backgroundScrimPercent
    if (scrimPercent != 0) {
        val scrimColor = if (scrimPercent < 0) {
            Color.Black.copy(alpha = -scrimPercent / 100f)
        } else {
            Color.White.copy(alpha = scrimPercent / 100f)
        }
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(scrimColor)
        )
    }
}

@Composable
private fun PreviewStatusBar(contentColor: Color) {
    val textStyle = remember(contentColor) {
        TextStyle(
            color = contentColor,
            fontSize = 9.sp,
            fontWeight = FontWeight.SemiBold,
        )
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(26.dp)
            // Clear of the rounded screen corners; a notched phone keeps its status bar
            // content inset from the edges.
            .padding(start = 20.dp, end = 20.dp, top = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        BasicText(text = "9:41", style = textStyle)
        Spacer(Modifier.weight(1f))
        Image(
            imageVector = Icons.Rounded.SignalCellularAlt,
            contentDescription = null,
            modifier = Modifier.size(8.dp),
            colorFilter = ColorFilter.tint(contentColor),
        )
        Spacer(Modifier.width(3.dp))
        Image(
            imageVector = Icons.Rounded.Wifi,
            contentDescription = null,
            modifier = Modifier.size(8.dp),
            colorFilter = ColorFilter.tint(contentColor),
        )
        Spacer(Modifier.width(3.dp))
        Image(
            imageVector = Icons.Rounded.BatteryFull,
            contentDescription = null,
            modifier = Modifier.size(10.dp),
            colorFilter = ColorFilter.tint(contentColor),
        )
    }
}

@Composable
private fun BoxScope.PreviewCameraPunch() {
    Box(
        modifier = Modifier
            .align(Alignment.TopCenter)
            .padding(top = 6.dp)
            .width(52.dp)
            .height(14.dp)
            .background(Color.Black, CircleShape)
    )
}

@Composable
private fun PreviewCaption(
    text: String,
    dotColor: Color,
    textColor: Color,
) {
    val textStyle = remember(textColor) {
        TextStyle(
            color = textColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
        )
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            modifier = Modifier
                .size(5.dp)
                .background(dotColor, CircleShape)
        )
        BasicText(text = text, style = textStyle)
    }
}

@Composable
private fun MiuixPreviewScreen(spec: ThemePreviewSpec, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth()) {
        MiuixPreviewTopBar(spec)
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clipToBounds()
                .padding(top = 4.dp, start = 10.dp, end = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            MiuixPreviewHeroCard(spec)
            MiuixPreviewStatsRow()
            MiuixPreviewNoticeCard()
            MiuixPreviewLinksCard()
            MiuixPreviewSpecCard()
            Spacer(Modifier.weight(1f))
        }
        MiuixPreviewBottomBar(spec)
    }
}

@Composable
private fun MiuixPreviewTopBar(spec: ThemePreviewSpec) {
    val colors = MiuixTheme.colorScheme
    TopAppBar(
        title = spec.customHomeTitle.ifBlank { stringResource(R.string.app_name) },
        color = Color.Transparent,
        titleColor = colors.onSurface,
        largeTitleColor = colors.onBackground,
        defaultWindowInsetsPadding = false,
        actions = {
            MiuixIcon(
                imageVector = Icons.Rounded.RestartAlt,
                contentDescription = null,
                modifier = Modifier.size(22.dp),
                tint = colors.onBackground,
            )
        },
    )
}

@Composable
private fun MiuixPreviewHeroCard(spec: ThemePreviewSpec) {
    val colors = MiuixTheme.colorScheme
    val heroColor = when {
        spec.miuixMonet -> colors.secondaryContainer
        spec.isDark -> Color(0xFF1A3825)
        else -> Color(0xFFDFFAE4)
    }
    val accentColor = if (spec.miuixMonet) colors.primary else Color(0xFF36D167)
    val accentContentColor = if (spec.miuixMonet) colors.onPrimary else Color.White
    val tagBackground = when {
        spec.miuixMonet -> colors.tertiaryContainer
        spec.isDark -> Color(0xFF315D3E)
        else -> Color(0xFFB8E8C5)
    }
    val tagContent = when {
        spec.miuixMonet -> colors.onTertiaryContainer
        spec.isDark -> Color(0xFFB8E8C5)
        else -> Color(0xFF164A29)
    }

    AppCard(
        modifier = Modifier
            .fillMaxWidth()
            .height(168.dp),
        colors = CardDefaults.defaultColors(
            color = backgroundAwareColor(heroColor),
            contentColor = colors.onSurface,
        ),
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            MiuixIcon(
                imageVector = Icons.Rounded.CheckCircleOutline,
                contentDescription = null,
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .offset(x = 20.dp, y = 22.dp)
                    .size(112.dp),
                tint = accentColor.copy(alpha = if (spec.miuixMonet) 0.8f else 1f),
            )
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(14.dp),
                verticalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    StatusTagMiuix(
                        label = "LKM",
                        backgroundColor = accentColor,
                        contentColor = accentContentColor,
                    )
                    StatusTagMiuix(
                        label = stringResource(R.string.home_lkm_custom),
                        backgroundColor = tagBackground,
                        contentColor = tagContent,
                    )
                }
                Column {
                    MiuixText(
                        text = stringResource(R.string.home_working),
                        fontSize = 30.sp,
                        fontWeight = FontWeight.Bold,
                        color = colors.onSurface,
                    )
                    MiuixText(
                        text = BuildConfig.VERSION_NAME,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = colors.onSurfaceVariantSummary,
                    )
                }
            }
        }
    }
}

@Composable
private fun MiuixPreviewNoticeCard() {
    val colors = MiuixTheme.colorScheme
    AppCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(
            color = backgroundAwareColor(colors.tertiaryContainer),
            contentColor = colors.onTertiaryContainer,
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            MiuixText(
                text = stringResource(R.string.home_lkm_update_available),
                fontSize = 11.sp,
                color = colors.onTertiaryContainer,
                maxLines = 2,
            )
        }
    }
}

@Composable
private fun MiuixPreviewSpecCard() {
    val colors = MiuixTheme.colorScheme
    val rows = listOf(
        stringResource(R.string.home_manager_version) to BuildConfig.VERSION_NAME,
        stringResource(R.string.home_kernel) to PreviewKernelVersion,
        stringResource(R.string.home_selinux_status) to stringResource(R.string.selinux_status_enforcing),
        stringResource(R.string.home_seccomp_status) to stringResource(R.string.seccomp_status_filter),
    )
    AppCard(
        modifier = Modifier.fillMaxWidth(),
        colors = backgroundAwareCardColors(),
    ) {
        Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 2.dp)) {
            rows.forEachIndexed { index, (label, value) ->
                if (index > 0) {
                    HorizontalDivider()
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 38.dp)
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    MiuixText(
                        text = label,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium,
                        color = colors.onSurface,
                    )
                    Spacer(Modifier.weight(1f))
                    MiuixText(
                        text = value,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = colors.onSurfaceVariantSummary,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

@Composable
private fun MiuixPreviewStatsRow() {
    val colors = MiuixTheme.colorScheme
    val tiles = listOf(
        3 to R.string.superuser,
        2 to R.string.module,
        1 to R.string.kpm_title,
    )
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        tiles.forEach { (count, label) ->
            AppCard(
                modifier = Modifier.weight(1f),
                colors = backgroundAwareCardColors(),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(72.dp)
                        .padding(11.dp),
                    verticalArrangement = Arrangement.SpaceBetween,
                ) {
                    MiuixText(
                        text = count.toString(),
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold,
                        color = colors.onSurface,
                    )
                    MiuixText(
                        text = stringResource(label),
                        fontSize = 9.sp,
                        color = colors.onSurfaceVariantSummary,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

@Composable
private fun MiuixPreviewLinksCard() {
    val colors = MiuixTheme.colorScheme
    AppCard(
        modifier = Modifier.fillMaxWidth(),
        colors = backgroundAwareCardColors(),
    ) {
        ArrowPreference(
            title = stringResource(R.string.home_support_title),
            startAction = {
                MiuixIcon(
                    imageVector = Icons.Filled.VolunteerActivism,
                    contentDescription = null,
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colors.onBackground,
                )
            },
        )
        HorizontalDivider()
        ArrowPreference(
            title = stringResource(R.string.home_learn_kernelsu),
            startAction = {
                MiuixIcon(
                    imageVector = Icons.AutoMirrored.Filled.MenuBook,
                    contentDescription = null,
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colors.onBackground,
                )
            },
        )
    }
}

@Composable
private fun MiuixPreviewBottomBar(spec: ThemePreviewSpec) {
    val colors = MiuixTheme.colorScheme
    if (spec.floatingBottomBar) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 10.dp),
            contentAlignment = Alignment.Center,
        ) {
            MiuixSurface(
                modifier = Modifier.fillMaxWidth(),
                shape = CircleShape,
                color = if (spec.floatingBottomBarBlur) {
                    colors.surfaceContainer.copy(alpha = 0.45f)
                } else {
                    colors.surfaceContainer
                },
                contentColor = colors.onSurface,
                border = BorderStroke(0.5.dp, colors.onSurface.copy(alpha = 0.08f)),
                shadowElevation = 6.dp,
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(44.dp)
                        .padding(horizontal = 6.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    MiuixPreviewDestinations.forEachIndexed { index, destination ->
                        val selected = index == 0
                        Row(
                            modifier = Modifier
                                .then(
                                    if (selected) {
                                        Modifier
                                            .clip(CircleShape)
                                            .background(colors.primary)
                                    } else {
                                        Modifier
                                    }
                                )
                                .padding(horizontal = 9.dp, vertical = 5.dp),
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            MiuixPreviewNavIcon(
                                icon = destination.icon,
                                selected = selected,
                                showBadge = spec.navigationBadge && index == 1,
                            )
                            MiuixText(
                                text = stringResource(destination.label),
                                fontSize = 9.sp,
                                color = if (selected) colors.onPrimary else colors.onSurface,
                                maxLines = 1,
                            )
                        }
                    }
                }
            }
        }
    } else {
        NavigationBar(
            color = backgroundAwareColor(colors.surface),
            showDivider = true,
            defaultWindowInsetsPadding = false,
        ) {
            MiuixPreviewDestinations.forEachIndexed { index, destination ->
                NavigationBarItem(
                    selected = index == 0,
                    onClick = {},
                    icon = destination.icon,
                    label = stringResource(destination.label),
                    badge = if (spec.navigationBadge && index == 1) {
                        { MiuixBadge { MiuixText(text = PreviewBadgeCount) } }
                    } else {
                        null
                    },
                )
            }
        }
    }
}

@Composable
private fun MiuixPreviewNavIcon(
    icon: ImageVector,
    selected: Boolean,
    showBadge: Boolean,
) {
    val colors = MiuixTheme.colorScheme
    val tint = if (selected) colors.onPrimary else colors.onSurface
    if (showBadge) {
        MiuixBadgedBox(
            badge = { MiuixBadge { MiuixText(text = PreviewBadgeCount) } },
        ) {
            MiuixIcon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(14.dp),
                tint = tint,
            )
        }
    } else {
        MiuixIcon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(14.dp),
            tint = tint,
        )
    }
}

@Composable
private fun MaterialPreviewScreen(spec: ThemePreviewSpec, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth()) {
        MaterialPreviewTopBar(spec)
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clipToBounds()
                .padding(top = 4.dp, start = 14.dp, end = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            MaterialPreviewHeroCard(spec)
            MaterialPreviewStatsRow()
            MaterialPreviewNoticeCard()
            MaterialPreviewLinksCard()
            MaterialPreviewSpecCard()
            Spacer(Modifier.weight(1f))
        }
        MaterialPreviewBottomBar(spec)
    }
}

@Composable
private fun MaterialPreviewTopBar(spec: ThemePreviewSpec) {
    val colors = MaterialTheme.colorScheme
    LargeFlexibleTopAppBar(
        title = { MaterialText(spec.customHomeTitle.ifBlank { stringResource(R.string.app_name) }) },
        expandedHeight = 104.dp,
        collapsedHeight = 56.dp,
        windowInsets = WindowInsets(0, 0, 0, 0),
        colors = expressiveTopAppBarColors(
            containerColor = Color.Transparent,
            scrolledContainerColor = Color.Transparent,
        ),
        actions = {
            MaterialIcon(
                imageVector = Icons.Rounded.RestartAlt,
                contentDescription = null,
                modifier = Modifier
                    .padding(end = 16.dp)
                    .size(22.dp),
                tint = colors.onSurface,
            )
        },
    )
}

@Composable
private fun MaterialPreviewHeroCard(spec: ThemePreviewSpec) {
    val colors = MaterialTheme.colorScheme
    MaterialSurface(
        modifier = Modifier
            .fillMaxWidth()
            .height(148.dp),
        shape = RoundedCornerShape(26.dp),
        color = backgroundAwareColor(colors.primary),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .drawBehind { drawHeroRings(colors.onPrimary.copy(alpha = 0.16f)) }
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                verticalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    StatusTagMaterial(
                        label = "LKM",
                        backgroundColor = colors.onPrimary,
                        contentColor = colors.primary,
                    )
                    StatusTagMaterial(
                        label = stringResource(R.string.home_lkm_custom),
                        backgroundColor = colors.tertiaryContainer,
                        contentColor = colors.onTertiaryContainer,
                    )
                }
                Column {
                    MaterialText(
                        text = stringResource(R.string.home_working),
                        style = MaterialTheme.typography.displaySmall,
                        fontWeight = FontWeight.Black,
                    )
                    MaterialText(
                        text = BuildConfig.VERSION_NAME,
                        style = MaterialTheme.typography.labelMedium,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }
    }
}

private fun DrawScope.drawHeroRings(color: Color) {
    val center = Offset(size.width - 26.dp.toPx(), 26.dp.toPx())
    val stroke = 1.5.dp.toPx()
    drawCircle(color = color, radius = 84.dp.toPx(), center = center, style = Stroke(stroke))
    drawCircle(
        color = color,
        radius = 60.dp.toPx(),
        center = center,
        style = Stroke(
            stroke,
            pathEffect = PathEffect.dashPathEffect(floatArrayOf(3.dp.toPx(), 6.dp.toPx())),
        ),
    )
    drawCircle(color = color, radius = 36.dp.toPx(), center = center, style = Stroke(stroke))
    drawCircle(color = color, radius = 10.dp.toPx(), center = center)
}

@Composable
private fun MaterialPreviewStatsRow() {
    val colors = MaterialTheme.colorScheme
    val tiles = listOf(
        3 to R.string.superuser,
        2 to R.string.module,
        1 to R.string.kpm_title,
    )
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        tiles.forEach { (count, label) ->
            MaterialSurface(
                modifier = Modifier
                    .weight(1f)
                    .height(72.dp),
                shape = RoundedCornerShape(20.dp),
                color = backgroundAwareColor(colors.surfaceBright),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(11.dp),
                    verticalArrangement = Arrangement.SpaceBetween,
                ) {
                    MaterialText(
                        text = count.toString(),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.ExtraBold,
                    )
                    MaterialText(
                        text = stringResource(label),
                        style = MaterialTheme.typography.labelSmall,
                        color = colors.onSurfaceVariant,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

@Composable
private fun MaterialPreviewNoticeCard() {
    val colors = MaterialTheme.colorScheme
    MaterialSurface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        color = backgroundAwareColor(colors.tertiaryContainer),
        contentColor = colors.onTertiaryContainer,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            MaterialText(
                text = stringResource(R.string.home_lkm_update_available),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
        }
    }
}

@Composable
private fun MaterialPreviewSpecCard() {
    val colors = MaterialTheme.colorScheme
    val rows = listOf(
        stringResource(R.string.home_manager_version) to BuildConfig.VERSION_NAME,
        stringResource(R.string.home_kernel) to PreviewKernelVersion,
        stringResource(R.string.home_selinux_status) to stringResource(R.string.selinux_status_enforcing),
        stringResource(R.string.home_seccomp_status) to stringResource(R.string.seccomp_status_filter),
    )
    MaterialSurface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        color = backgroundAwareColor(colors.surfaceBright),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp)) {
            rows.forEachIndexed { index, (label, value) ->
                if (index > 0) {
                    MaterialDivider()
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 38.dp)
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    MaterialText(
                        text = label,
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                    )
                    Spacer(Modifier.weight(1f))
                    MaterialText(
                        text = value,
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = colors.onSurfaceVariant,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

@Composable
private fun MaterialPreviewLinksCard() {
    SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
        item {
            SegmentedListItem(
                headlineContent = { MaterialText(stringResource(R.string.home_support_title)) },
                leadingContent = {
                    IconTile(Icons.Filled.VolunteerActivism, null)
                },
                trailingContent = {
                    MaterialIcon(
                        imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                        contentDescription = null,
                    )
                },
            )
        }
        item {
            SegmentedListItem(
                headlineContent = { MaterialText(stringResource(R.string.home_learn_kernelsu)) },
                leadingContent = {
                    IconTile(Icons.AutoMirrored.Filled.MenuBook, null)
                },
                trailingContent = {
                    MaterialIcon(
                        imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                        contentDescription = null,
                    )
                },
            )
        }
    }
}

@Composable
private fun MaterialPreviewBottomBar(spec: ThemePreviewSpec) {
    val colors = MaterialTheme.colorScheme
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 10.dp),
        contentAlignment = Alignment.Center,
    ) {
        MaterialSurface(
            modifier = Modifier.fillMaxWidth(),
            shape = CircleShape,
            color = backgroundAwareColor(colors.surfaceContainerHighest),
            shadowElevation = 6.dp,
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
                    .padding(horizontal = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                MaterialPreviewDestinations.forEachIndexed { index, destination ->
                    val selected = index == 0
                    Row(
                        modifier = Modifier
                            .then(
                                if (selected) {
                                    Modifier
                                        .clip(CircleShape)
                                        .background(colors.primary)
                                        .padding(horizontal = 12.dp)
                                } else {
                                    Modifier.padding(horizontal = 10.dp)
                                }
                            )
                            .height(38.dp),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        MaterialPreviewNavIcon(
                            icon = if (selected) destination.selectedIcon else destination.unselectedIcon,
                            selected = selected,
                            showBadge = spec.navigationBadge && index == 1,
                        )
                        if (selected) {
                            MaterialText(
                                text = stringResource(destination.label),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold,
                                color = colors.onPrimary,
                                maxLines = 1,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MaterialPreviewNavIcon(
    icon: ImageVector,
    selected: Boolean,
    showBadge: Boolean,
) {
    val colors = MaterialTheme.colorScheme
    val tint = if (selected) colors.onPrimary else colors.onSurfaceVariant
    val iconContent: @Composable () -> Unit = {
        MaterialIcon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
            tint = tint,
        )
    }
    if (showBadge) {
        BadgedBox(
            badge = { Badge { MaterialText(text = PreviewBadgeCount) } },
        ) {
            iconContent()
        }
    } else {
        iconContent()
    }
}
