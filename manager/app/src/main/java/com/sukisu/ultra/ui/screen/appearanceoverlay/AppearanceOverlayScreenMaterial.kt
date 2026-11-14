package com.sukisu.ultra.ui.screen.appearanceoverlay

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
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
import androidx.compose.material3.ButtonGroupDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberSliderState
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.appearance.OverlayColorSwatch
import com.sukisu.ultra.ui.component.appearance.OverlayPresets
import com.sukisu.ultra.ui.component.appearance.titleRes
import com.sukisu.ultra.ui.component.material.CapsuleSlider
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.ExpressiveToggleButton
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedItemContainer
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.screen.settings.SettingsUiState
import com.sukisu.ultra.ui.util.AppearanceColorMode
import com.sukisu.ultra.ui.util.AppearanceColorToken
import com.sukisu.ultra.ui.util.AppearanceEffectKey
import com.sukisu.ultra.ui.util.AppearanceOverlayData
import com.sukisu.ultra.ui.util.AppearanceOverlayStore
import com.sukisu.ultra.ui.util.colorTokenValue
import com.sukisu.ultra.ui.util.effectiveColorToken
import com.sukisu.ultra.ui.util.withColorToken
import com.sukisu.ultra.ui.util.withImageEffect
import kotlin.math.roundToInt

@Composable
fun AppearanceOverlayScreenMaterial(
    state: SettingsUiState,
    data: AppearanceOverlayData,
    actions: AppearanceOverlayActions,
) {
    val scrollBehavior =
        TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    var modeIndex by rememberSaveable { mutableIntStateOf(AppearanceColorMode.SHARED.ordinal) }
    val mode = AppearanceColorMode.entries[modeIndex]
    val effects = data.image?.background
    val blurActive = state.customBackgroundBlurPercent > 0
    val sharpenSupported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU

    val sharpenState = rememberSliderState(
        value = effects?.sharpen ?: 0f,
        trackRange = 0f..100f,
    )
    val saturationState = rememberSliderState(
        value = effects?.saturation ?: 100f,
        trackRange = 20f..200f,
    )
    val contrastState = rememberSliderState(
        value = effects?.contrast ?: 100f,
        trackRange = 20f..200f,
    )
    val brightnessState = rememberSliderState(
        value = effects?.brightness ?: 0f,
        trackRange = -100f..100f,
    )
    LaunchedEffect(effects?.sharpen) {
        val target = effects?.sharpen ?: 0f
        if (sharpenState.value != target) sharpenState.value = target
    }
    LaunchedEffect(effects?.saturation) {
        val target = effects?.saturation ?: 100f
        if (saturationState.value != target) saturationState.value = target
    }
    LaunchedEffect(effects?.contrast) {
        val target = effects?.contrast ?: 100f
        if (contrastState.value != target) contrastState.value = target
    }
    LaunchedEffect(effects?.brightness) {
        val target = effects?.brightness ?: 0f
        if (brightnessState.value != target) brightnessState.value = target
    }

    fun commit(key: AppearanceEffectKey, value: Float, default: Float) {
        actions.onUpdate(data.withImageEffect(key, value.takeUnless { it == default }))
    }

    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                navigationIcon = { TopBarBackButton(onClick = actions.onBack) },
                title = { Text(stringResource(R.string.appearance_page_title)) },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing
                    .only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
                actions = {
                    IconButton(onClick = actions.onResetAll) {
                        Icon(
                            imageVector = Icons.Rounded.Restore,
                            contentDescription = stringResource(R.string.appearance_clear_all),
                            tint = Color(0xFFE53935),
                        )
                    }
                },
                scrollBehavior = scrollBehavior,
            )
        },
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            verticalArrangement = Arrangement.spacedBy(13.dp),
        ) {
            item {
                SegmentedColumn(modifier = Modifier.padding(horizontal = 16.dp)) {
                    item {
                        SegmentedItemContainer {
                            Text(
                                text = stringResource(R.string.appearance_page_summary),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                            )
                        }
                    }
                }
            }

            item {
                SegmentedColumn(modifier = Modifier.padding(horizontal = 16.dp)) {
                    item {
                        OverlaySectionHeader(
                            title = stringResource(R.string.appearance_color_mode),
                            summary = stringResource(R.string.appearance_color_mode_summary),
                            icon = Icons.Rounded.Colorize,
                        )
                    }
                    item {
                        SegmentedItemContainer {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                                horizontalArrangement = Arrangement.spacedBy(
                                    ButtonGroupDefaults.ConnectedSpaceBetween
                                ),
                            ) {
                                AppearanceColorMode.entries.forEachIndexed { index, entry ->
                                    ExpressiveToggleButton(
                                        checked = modeIndex == index,
                                        onCheckedChange = { if (it) modeIndex = index },
                                        modifier = Modifier
                                            .weight(1f)
                                            .semantics { role = Role.RadioButton },
                                        shapes = when (index) {
                                            0 -> ButtonGroupDefaults.connectedLeadingButtonShapes()
                                            AppearanceColorMode.entries.lastIndex ->
                                                ButtonGroupDefaults.connectedTrailingButtonShapes()
                                            else -> ButtonGroupDefaults.connectedMiddleButtonShapes()
                                        },
                                    ) {
                                        Text(stringResource(entry.titleRes()))
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item {
                SegmentedColumn(modifier = Modifier.padding(horizontal = 16.dp)) {
                    item {
                        OverlaySectionHeader(
                            title = stringResource(R.string.appearance_section_text_colors),
                            summary = stringResource(R.string.appearance_section_text_colors_summary),
                            icon = Icons.Rounded.Colorize,
                        )
                    }
                    listOf(
                        AppearanceColorToken.TEXT_PRIMARY,
                        AppearanceColorToken.TEXT_SECONDARY,
                        AppearanceColorToken.TEXT_DISABLED,
                        AppearanceColorToken.ON_ACCENT,
                    ).forEach { token ->
                        item {
                            OverlayColorRowMaterial(
                                data = data,
                                mode = mode,
                                token = token,
                                actions = actions,
                            )
                        }
                    }
                }
            }

            item {
                SegmentedColumn(modifier = Modifier.padding(horizontal = 16.dp)) {
                    item {
                        OverlaySectionHeader(
                            title = stringResource(R.string.appearance_section_palette),
                            summary = stringResource(R.string.appearance_section_palette_summary),
                            icon = Icons.Rounded.Palette,
                        )
                    }
                    listOf(
                        AppearanceColorToken.ACCENT,
                        AppearanceColorToken.SURFACE,
                        AppearanceColorToken.CARD,
                        AppearanceColorToken.OUTLINE,
                        AppearanceColorToken.ERROR,
                    ).forEach { token ->
                        item {
                            OverlayColorRowMaterial(
                                data = data,
                                mode = mode,
                                token = token,
                                actions = actions,
                            )
                        }
                    }
                }
            }

            item {
                SegmentedColumn(modifier = Modifier.padding(horizontal = 16.dp)) {
                    item {
                        OverlaySectionHeader(
                            title = stringResource(R.string.appearance_section_image_effects),
                            summary = stringResource(R.string.appearance_section_image_effects_summary),
                            icon = Icons.Rounded.Tune,
                        )
                    }
                    item {
                        SegmentedItemContainer {
                            Column {
                                OverlaySliderBlock(
                                    icon = Icons.Rounded.AutoAwesome,
                                    title = stringResource(R.string.appearance_effect_sharpen),
                                    summary = stringResource(R.string.appearance_effect_sharpen_summary),
                                    value = sharpenState.value,
                                    onReset = {
                                        sharpenState.value = 0f
                                        commit(AppearanceEffectKey.SHARPEN, 0f, 0f)
                                    },
                                ) {
                                    CapsuleSlider(
                                        state = sharpenState,
                                        enabled = sharpenSupported,
                                        onValueChangeFinished = {
                                            val rounded = sharpenState.value.roundToInt().toFloat()
                                            sharpenState.value = rounded
                                            commit(
                                                AppearanceEffectKey.SHARPEN,
                                                rounded,
                                                0f,
                                            )
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                }
                                if (!sharpenSupported) {
                                    Text(
                                        text = stringResource(R.string.appearance_overlay_sharpen_api_notice),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.padding(
                                            horizontal = 16.dp,
                                            vertical = 4.dp,
                                        ),
                                    )
                                } else if (blurActive && sharpenState.value > 0f) {
                                    Text(
                                        text = stringResource(R.string.appearance_effect_sharpen_blur_notice),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.padding(
                                            horizontal = 16.dp,
                                            vertical = 4.dp,
                                        ),
                                    )
                                }
                                HorizontalDivider()
                                OverlaySliderBlock(
                                    icon = Icons.Rounded.Colorize,
                                    title = stringResource(R.string.appearance_effect_saturation),
                                    summary = stringResource(R.string.appearance_effect_saturation_summary),
                                    value = saturationState.value,
                                    onReset = {
                                        saturationState.value = 100f
                                        commit(AppearanceEffectKey.SATURATION, 100f, 100f)
                                    },
                                ) {
                                    CapsuleSlider(
                                        state = saturationState,
                                        onValueChangeFinished = {
                                            val rounded = saturationState.value
                                                .roundToInt()
                                                .toFloat()
                                            saturationState.value = rounded
                                            commit(
                                                AppearanceEffectKey.SATURATION,
                                                rounded,
                                                100f,
                                            )
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                }
                                HorizontalDivider()
                                OverlaySliderBlock(
                                    icon = Icons.Rounded.Palette,
                                    title = stringResource(R.string.appearance_effect_contrast),
                                    summary = stringResource(R.string.appearance_effect_contrast_summary),
                                    value = contrastState.value,
                                    onReset = {
                                        contrastState.value = 100f
                                        commit(AppearanceEffectKey.CONTRAST, 100f, 100f)
                                    },
                                ) {
                                    CapsuleSlider(
                                        state = contrastState,
                                        onValueChangeFinished = {
                                            val rounded = contrastState.value
                                                .roundToInt()
                                                .toFloat()
                                            contrastState.value = rounded
                                            commit(
                                                AppearanceEffectKey.CONTRAST,
                                                rounded,
                                                100f,
                                            )
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                }
                                HorizontalDivider()
                                OverlaySliderBlock(
                                    icon = Icons.Rounded.Tune,
                                    title = stringResource(R.string.appearance_effect_brightness),
                                    summary = stringResource(R.string.appearance_effect_brightness_summary),
                                    value = brightnessState.value,
                                    onReset = {
                                        brightnessState.value = 0f
                                        commit(AppearanceEffectKey.BRIGHTNESS, 0f, 0f)
                                    },
                                ) {
                                    CapsuleSlider(
                                        state = brightnessState,
                                        onValueChangeFinished = {
                                            val rounded = brightnessState.value
                                                .roundToInt()
                                                .toFloat()
                                            brightnessState.value = rounded
                                            commit(
                                                AppearanceEffectKey.BRIGHTNESS,
                                                rounded,
                                                0f,
                                            )
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                }
                            }
                        }
                    }
                }
            }

            item {
                SegmentedColumn(modifier = Modifier.padding(horizontal = 16.dp)) {
                    item {
                        OverlaySectionHeader(
                            title = stringResource(R.string.appearance_section_presets),
                            summary = stringResource(R.string.appearance_section_presets_summary),
                            icon = Icons.Rounded.AutoAwesome,
                        )
                    }
                    OverlayPresets.forEach { preset ->
                        item {
                            SegmentedListItem(
                                onClick = {
                                    actions.onUpdate(preset.data.copy(image = data.image))
                                },
                                headlineContent = { Text(stringResource(preset.titleRes)) },
                                supportingContent = {
                                    Text(stringResource(R.string.appearance_preset_apply_summary))
                                },
                                leadingContent = {
                                    IconTile(Icons.Rounded.AutoAwesome, stringResource(preset.titleRes))
                                },
                            )
                        }
                    }
                }
            }

            item {
                SegmentedColumn(modifier = Modifier.padding(horizontal = 16.dp)) {
                    item {
                        SegmentedListItem(
                            onClick = actions.onOpenJson,
                            headlineContent = {
                                Text(stringResource(R.string.appearance_advanced_json))
                            },
                            supportingContent = {
                                Text(stringResource(R.string.appearance_advanced_json_summary))
                            },
                            leadingContent = {
                                IconTile(
                                    Icons.Rounded.Description,
                                    stringResource(R.string.appearance_advanced_json),
                                )
                            },
                        )
                    }
                    item {
                        SegmentedListItem(
                            onClick = actions.onRequestClear,
                            headlineContent = { Text(stringResource(R.string.appearance_clear_all)) },
                            supportingContent = {
                                Text(stringResource(R.string.appearance_clear_all_summary))
                            },
                            leadingContent = {
                                IconTile(
                                    Icons.Rounded.Delete,
                                    stringResource(R.string.appearance_clear_all),
                                )
                            },
                        )
                    }
                }
            }

            item { Spacer(Modifier.height(24.dp)) }
        }
    }
}

@Composable
private fun OverlaySectionHeader(
    title: String,
    summary: String,
    icon: ImageVector,
) {
    SegmentedListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(summary) },
        leadingContent = { IconTile(icon, title) },
    )
}

@Composable
private fun OverlayColorRowMaterial(
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
    SegmentedListItem(
        onClick = { actions.onPickColor(OverlayColorTarget(mode, token)) },
        headlineContent = { Text(stringResource(token.titleRes())) },
        supportingContent = { Text(summary) },
        leadingContent = {
            OverlayColorSwatch(
                color = effective?.second
                    ?.let(AppearanceOverlayStore::parseColorValue)
                    ?.let(::Color),
                outlineColor = MaterialTheme.colorScheme.outline,
                emptyColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            )
        },
        trailingContent = if (explicit != null) {
            {
                IconButton(
                    onClick = { actions.onUpdate(data.withColorToken(mode, token, null)) },
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Restore,
                        contentDescription = stringResource(R.string.appearance_override_clear),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else {
            null
        },
    )
}

@Composable
private fun OverlaySliderBlock(
    icon: ImageVector,
    title: String,
    summary: String,
    value: Float,
    onReset: () -> Unit,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = value.roundToInt().toString(),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(end = 6.dp),
            )
            androidx.compose.material3.TextButton(
                onClick = onReset,
            ) {
                Text(stringResource(R.string.appearance_effect_reset))
            }
        }
        Spacer(Modifier.height(8.dp))
        content()
    }
}
