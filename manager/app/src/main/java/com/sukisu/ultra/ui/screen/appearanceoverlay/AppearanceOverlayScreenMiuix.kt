package com.sukisu.ultra.ui.screen.appearanceoverlay

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AutoAwesome
import androidx.compose.material.icons.rounded.Colorize
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.appearance.OverlayColorSwatch
import com.sukisu.ultra.ui.component.appearance.OverlayPresets
import com.sukisu.ultra.ui.component.appearance.titleRes
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.screen.settings.SettingsUiState
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.theme.backgroundAwareCardColors
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import com.sukisu.ultra.ui.util.AppearanceColorMode
import com.sukisu.ultra.ui.util.AppearanceColorToken
import com.sukisu.ultra.ui.util.AppearanceEffectKey
import com.sukisu.ultra.ui.util.AppearanceOverlayData
import com.sukisu.ultra.ui.util.AppearanceOverlayStore
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.colorTokenValue
import com.sukisu.ultra.ui.util.effectiveColorToken
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import com.sukisu.ultra.ui.util.withColorToken
import com.sukisu.ultra.ui.util.withImageEffect
import kotlin.math.roundToInt
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.Slider
import top.yukonga.miuix.kmp.basic.TabRowDefaults
import top.yukonga.miuix.kmp.basic.TabRowWithContour
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun AppearanceOverlayScreenMiuix(
    state: SettingsUiState,
    data: AppearanceOverlayData,
    actions: AppearanceOverlayActions,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val barBlurActive = backdrop != null
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val barColor = if (barBlurActive || hasCustomBackground) Color.Transparent else colorScheme.surface
    var modeIndex by rememberSaveable { mutableIntStateOf(AppearanceColorMode.SHARED.ordinal) }
    val mode = AppearanceColorMode.entries[modeIndex]
    val backgroundEffects = data.image?.background
    val backgroundBlurred = state.customBackgroundBlurPercent > 0
    val sharpenSupported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU

    var sharpenDraft by remember { mutableFloatStateOf(backgroundEffects?.sharpen ?: 0f) }
    var saturationDraft by remember { mutableFloatStateOf(backgroundEffects?.saturation ?: 100f) }
    var contrastDraft by remember { mutableFloatStateOf(backgroundEffects?.contrast ?: 100f) }
    var brightnessDraft by remember { mutableFloatStateOf(backgroundEffects?.brightness ?: 0f) }
    LaunchedEffect(backgroundEffects?.sharpen) {
        sharpenDraft = backgroundEffects?.sharpen ?: 0f
    }
    LaunchedEffect(backgroundEffects?.saturation) {
        saturationDraft = backgroundEffects?.saturation ?: 100f
    }
    LaunchedEffect(backgroundEffects?.contrast) {
        contrastDraft = backgroundEffects?.contrast ?: 100f
    }
    LaunchedEffect(backgroundEffects?.brightness) {
        brightnessDraft = backgroundEffects?.brightness ?: 0f
    }

    fun commitEffect(key: AppearanceEffectKey, value: Float, default: Float) {
        actions.onUpdate(
            data.withImageEffect(key, value.takeUnless { it == default })
        )
    }

    AppScaffoldMiuix(
        title = stringResource(R.string.appearance_page_title),
        onBack = actions.onBack,
        onResetAll = actions.onResetAll,
        scrollBehavior = scrollBehavior,
        backdrop = backdrop,
        barColor = barColor,
    ) { innerPadding ->
        Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxHeight()
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection)
                    .padding(horizontal = 12.dp),
                contentPadding = innerPadding,
                overscrollEffect = null,
            ) {
            item {
                Spacer(Modifier.height(16.dp))
                AppCard(colors = backgroundAwareCardColors()) {
                    Text(
                        text = stringResource(R.string.appearance_page_summary),
                        fontSize = 13.sp,
                        color = colorScheme.onSurface,
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 14.dp),
                    )
                }
                Spacer(Modifier.height(12.dp))
                AppCard(colors = backgroundAwareCardColors()) {
                    BasicComponent(
                        title = stringResource(R.string.appearance_color_mode),
                        summary = stringResource(R.string.appearance_color_mode_summary),
                        startAction = {
                            Icon(
                                imageVector = Icons.Rounded.Colorize,
                                modifier = Modifier.padding(end = 6.dp),
                                contentDescription = stringResource(R.string.appearance_color_mode),
                                tint = colorScheme.onBackground,
                            )
                        },
                    )
                    TabRowWithContour(
                        tabs = AppearanceColorMode.entries.map { stringResource(it.titleRes()) },
                        selectedTabIndex = modeIndex,
                        onTabSelected = { modeIndex = it },
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        colors = TabRowDefaults.tabRowColors(
                            backgroundColor = backgroundAwareColor(colorScheme.surfaceContainerHighest),
                            selectedBackgroundColor = backgroundAwareColor(colorScheme.surfaceContainer),
                        ),
                    )
                }
            }

            item {
                Spacer(Modifier.height(12.dp))
                OverlayCard(
                    title = stringResource(R.string.appearance_section_text_colors),
                    summary = stringResource(R.string.appearance_section_text_colors_summary),
                    icon = Icons.Rounded.Colorize,
                ) {
                    listOf(
                        AppearanceColorToken.TEXT_PRIMARY,
                        AppearanceColorToken.TEXT_SECONDARY,
                        AppearanceColorToken.TEXT_DISABLED,
                        AppearanceColorToken.ON_ACCENT,
                    ).forEachIndexed { index, token ->
                        if (index > 0) HorizontalDivider()
                        OverlayColorRow(
                            data = data,
                            mode = mode,
                            token = token,
                            actions = actions,
                        )
                    }
                }
            }

            item {
                Spacer(Modifier.height(12.dp))
                OverlayCard(
                    title = stringResource(R.string.appearance_section_palette),
                    summary = stringResource(R.string.appearance_section_palette_summary),
                    icon = Icons.Rounded.Palette,
                ) {
                    listOf(
                        AppearanceColorToken.ACCENT,
                        AppearanceColorToken.SURFACE,
                        AppearanceColorToken.CARD,
                        AppearanceColorToken.OUTLINE,
                        AppearanceColorToken.ERROR,
                    ).forEachIndexed { index, token ->
                        if (index > 0) HorizontalDivider()
                        OverlayColorRow(
                            data = data,
                            mode = mode,
                            token = token,
                            actions = actions,
                        )
                    }
                }
            }

            item {
                Spacer(Modifier.height(12.dp))
                OverlayCard(
                    title = stringResource(R.string.appearance_section_image_effects),
                    summary = stringResource(R.string.appearance_section_image_effects_summary),
                    icon = Icons.Rounded.Tune,
                ) {
                    OverlaySliderRow(
                        title = stringResource(R.string.appearance_effect_sharpen),
                        summary = stringResource(R.string.appearance_effect_sharpen_summary),
                        value = sharpenDraft,
                        valueRange = 0f..100f,
                        enabled = sharpenSupported,
                        onValueChange = { sharpenDraft = it },
                        onValueChangeFinished = {
                            val rounded = sharpenDraft.roundToInt().toFloat()
                            sharpenDraft = rounded
                            commitEffect(AppearanceEffectKey.SHARPEN, rounded, 0f)
                        },
                        onReset = {
                            sharpenDraft = 0f
                            commitEffect(AppearanceEffectKey.SHARPEN, 0f, 0f)
                        },
                    )
                    if (!sharpenSupported) {
                        Text(
                            text = stringResource(R.string.appearance_overlay_sharpen_api_notice),
                            fontSize = 12.sp,
                            color = colorScheme.primary,
                            modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp),
                        )
                    } else if (backgroundBlurred && sharpenDraft > 0f) {
                        Text(
                            text = stringResource(R.string.appearance_effect_sharpen_blur_notice),
                            fontSize = 12.sp,
                            color = colorScheme.primary,
                            modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp),
                        )
                    }
                    HorizontalDivider()
                    OverlaySliderRow(
                        title = stringResource(R.string.appearance_effect_saturation),
                        summary = stringResource(R.string.appearance_effect_saturation_summary),
                        value = saturationDraft,
                        valueRange = 20f..200f,
                        onValueChange = { saturationDraft = it },
                        onValueChangeFinished = {
                            val rounded = saturationDraft.roundToInt().toFloat()
                            saturationDraft = rounded
                            commitEffect(AppearanceEffectKey.SATURATION, rounded, 100f)
                        },
                        onReset = {
                            saturationDraft = 100f
                            commitEffect(AppearanceEffectKey.SATURATION, 100f, 100f)
                        },
                    )
                    HorizontalDivider()
                    OverlaySliderRow(
                        title = stringResource(R.string.appearance_effect_contrast),
                        summary = stringResource(R.string.appearance_effect_contrast_summary),
                        value = contrastDraft,
                        valueRange = 20f..200f,
                        onValueChange = { contrastDraft = it },
                        onValueChangeFinished = {
                            val rounded = contrastDraft.roundToInt().toFloat()
                            contrastDraft = rounded
                            commitEffect(AppearanceEffectKey.CONTRAST, rounded, 100f)
                        },
                        onReset = {
                            contrastDraft = 100f
                            commitEffect(AppearanceEffectKey.CONTRAST, 100f, 100f)
                        },
                    )
                    HorizontalDivider()
                    OverlaySliderRow(
                        title = stringResource(R.string.appearance_effect_brightness),
                        summary = stringResource(R.string.appearance_effect_brightness_summary),
                        value = brightnessDraft,
                        valueRange = -100f..100f,
                        onValueChange = { brightnessDraft = it },
                        onValueChangeFinished = {
                            val rounded = brightnessDraft.roundToInt().toFloat()
                            brightnessDraft = rounded
                            commitEffect(AppearanceEffectKey.BRIGHTNESS, rounded, 0f)
                        },
                        onReset = {
                            brightnessDraft = 0f
                            commitEffect(AppearanceEffectKey.BRIGHTNESS, 0f, 0f)
                        },
                    )
                }
            }

            item {
                Spacer(Modifier.height(12.dp))
                OverlayCard(
                    title = stringResource(R.string.appearance_section_presets),
                    summary = stringResource(R.string.appearance_section_presets_summary),
                    icon = Icons.Rounded.AutoAwesome,
                ) {
                    OverlayPresets.forEachIndexed { index, preset ->
                        if (index > 0) HorizontalDivider()
                        BasicComponent(
                            title = stringResource(preset.titleRes),
                            summary = stringResource(R.string.appearance_preset_apply_summary),
                            onClick = {
                                actions.onUpdate(preset.data.copy(image = data.image))
                            },
                        )
                    }
                }
            }

            item {
                Spacer(Modifier.height(12.dp))
                AppCard(colors = backgroundAwareCardColors()) {
                    BasicComponent(
                        title = stringResource(R.string.appearance_advanced_json),
                        summary = stringResource(R.string.appearance_advanced_json_summary),
                        startAction = {
                            Icon(
                                imageVector = Icons.Rounded.Description,
                                contentDescription = null,
                                tint = colorScheme.onBackground,
                                modifier = Modifier.padding(end = 6.dp),
                            )
                        },
                        onClick = actions.onOpenJson,
                    )
                    HorizontalDivider()
                    BasicComponent(
                        title = stringResource(R.string.appearance_clear_all),
                        summary = stringResource(R.string.appearance_clear_all_summary),
                        startAction = {
                            Icon(
                                imageVector = Icons.Rounded.Delete,
                                contentDescription = null,
                                tint = colorScheme.error,
                                modifier = Modifier.padding(end = 6.dp),
                            )
                        },
                        onClick = actions.onRequestClear,
                    )
                }
                Spacer(Modifier.height(24.dp))
            }
        }
    }
}
}

@Composable
private fun AppScaffoldMiuix(
    title: String,
    onBack: () -> Unit,
    onResetAll: () -> Unit,
    scrollBehavior: ScrollBehavior,
    backdrop: LayerBackdrop?,
    barColor: Color,
    content: @Composable (androidx.compose.foundation.layout.PaddingValues) -> Unit,
) {
    AppScaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    color = barColor,
                    title = title,
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            val layoutDirection = LocalLayoutDirection.current
                            Icon(
                                modifier = Modifier.graphicsLayer {
                                    if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                                },
                                imageVector = MiuixIcons.Back,
                                contentDescription = null,
                                tint = colorScheme.onBackground,
                            )
                        }
                    },
                    actions = {
                        IconButton(onClick = onResetAll) {
                            Icon(
                                imageVector = Icons.Rounded.Restore,
                                contentDescription = stringResource(R.string.appearance_clear_all),
                                tint = Color(0xFFE53935),
                            )
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars
            .add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
        content = content,
    )
}

@Composable
private fun OverlayCard(
    title: String,
    summary: String,
    icon: ImageVector,
    content: @Composable ColumnScope.() -> Unit,
) {
    AppCard(colors = backgroundAwareCardColors()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = colorScheme.primary,
            )
            Spacer(Modifier.width(10.dp))
            Column {
                Text(
                    text = title,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium,
                    color = colorScheme.onSurface,
                )
                Text(
                    text = summary,
                    fontSize = 13.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                )
            }
        }
        HorizontalDivider()
        Column(content = content)
    }
}

@Composable
private fun OverlayColorRow(
    data: AppearanceOverlayData,
    mode: AppearanceColorMode,
    token: AppearanceColorToken,
    actions: AppearanceOverlayActions,
) {
    val explicit = data.colorTokenValue(mode, token)
    val effective = data.effectiveColorToken(mode, token)
    val summary = when {
        explicit != null -> explicit
        mode != AppearanceColorMode.SHARED && effective != null ->
            stringResource(R.string.appearance_shared_value, effective.second)
        else -> stringResource(R.string.appearance_follow_theme)
    }
    BasicComponent(
        title = stringResource(token.titleRes()),
        summary = summary,
        startAction = {
            OverlayColorSwatch(
                color = effective?.second
                    ?.let(AppearanceOverlayStore::parseColorValue)
                    ?.let(::Color),
                outlineColor = colorScheme.outline,
                emptyColor = colorScheme.surfaceContainerHigh,
                modifier = Modifier.padding(end = 10.dp),
            )
        },
        endActions = if (explicit != null) {
            {
                IconButton(
                    onClick = { actions.onUpdate(data.withColorToken(mode, token, null)) },
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Restore,
                        contentDescription = stringResource(R.string.appearance_override_clear),
                        tint = colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        } else {
            null
        },
        onClick = { actions.onPickColor(OverlayColorTarget(mode, token)) },
    )
}

@Composable
private fun OverlaySliderRow(
    title: String,
    summary: String,
    value: Float,
    valueRange: ClosedFloatingPointRange<Float>,
    onValueChange: (Float) -> Unit,
    onValueChangeFinished: () -> Unit,
    onReset: () -> Unit,
    enabled: Boolean = true,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = 15.sp,
                    color = colorScheme.onSurface,
                )
                Text(
                    text = summary,
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                )
            }
            Text(
                text = value.roundToInt().toString(),
                fontSize = 14.sp,
                color = colorScheme.onSurfaceVariantSummary,
                modifier = Modifier.padding(end = 6.dp),
            )
            IconButton(onClick = onReset) {
                Icon(
                    imageVector = Icons.Rounded.Restore,
                    contentDescription = stringResource(R.string.appearance_effect_reset),
                    tint = colorScheme.onSurfaceVariantSummary,
                )
            }
        }
        Slider(
            value = value,
            onValueChange = onValueChange,
            onValueChangeFinished = onValueChangeFinished,
            valueRange = valueRange,
            enabled = enabled,
        )
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(
                text = valueRange.start.roundToInt().toString(),
                fontSize = 11.sp,
                color = colorScheme.onSurfaceVariantSummary,
            )
            Text(
                text = valueRange.endInclusive.roundToInt().toString(),
                fontSize = 11.sp,
                color = colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}
