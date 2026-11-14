package com.sukisu.ultra.ui.screen.colorpalette

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AutoAwesome
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.LightMode
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TopAppBar as MaterialTopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TonalCard
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.screen.settings.ThemePackageOptions
import com.sukisu.ultra.ui.theme.ColorMode
import com.sukisu.ultra.ui.util.AdaptiveThemeDraft
import com.sukisu.ultra.ui.util.AdaptiveThemeVariantState
import com.sukisu.ultra.ui.util.ThemePackageStorage
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel

/**
 * Captures two complete appearances as an adaptive theme. Each capture keeps its own background,
 * card image, stickers and style values; the export writes them as a v3 package.
 */
@Composable
fun AdaptiveThemeBuilderScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val viewModel = viewModel<SettingsViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(ThemePackageStorage.THEME_MIME_TYPE),
    ) { uri ->
        uri?.let { viewModel.exportTheme(context, it, ThemePackageOptions()) }
    }

    fun publishToStore() {
        navigator.push(Route.ThemeStoreAdaptiveUpload)
    }

    LaunchedEffect(Unit) {
        viewModel.refreshAdaptiveAppearance()
    }
    LaunchedEffect(isSystemInDarkTheme()) {
        viewModel.refreshAdaptiveAppearance()
    }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.refreshAdaptiveAppearance()
    }

    val draft: AdaptiveThemeDraft? = remember(
        state.adaptiveDraftRevision,
        state.adaptiveDraftLightCaptured,
        state.adaptiveDraftDarkCaptured,
    ) {
        viewModel.loadAdaptiveDraft()
    }
    val currentMode = ColorMode.fromValue(state.themeMode)
    val effectiveDark = currentMode.isDark ||
        (currentMode.isSystem && isSystemInDarkTheme())
    val nextStep = when {
        state.adaptiveDraftComplete -> R.string.theme_adaptive_draft_ready
        state.adaptiveDraftLightCaptured -> R.string.theme_adaptive_next_dark
        state.adaptiveDraftDarkCaptured -> R.string.theme_adaptive_next_light_missing
        else -> R.string.theme_adaptive_next_light
    }

    val pageContainer = MaterialTheme.colorScheme.surface
    ExpressiveScaffold(
        containerColor = pageContainer,
        topBar = {
            MaterialTopAppBar(
                navigationIcon = { TopBarBackButton(onClick = { navigator.pop() }) },
                title = { MaterialText(stringResource(R.string.theme_adaptive_builder_title)) },
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
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            item(key = "intro") {
                BuilderCard {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.AutoAwesome,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                        )
                        MaterialText(
                            text = stringResource(R.string.theme_adaptive_builder_summary),
                            style = MaterialTheme.typography.titleMedium,
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    MaterialText(
                        text = stringResource(
                            R.string.theme_adaptive_current_mode,
                            stringResource(
                                if (effectiveDark) R.string.theme_adaptive_mode_dark
                                else R.string.theme_adaptive_mode_light,
                            ),
                        ),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Spacer(Modifier.height(6.dp))
                    MaterialText(
                        text = stringResource(nextStep),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    MaterialText(
                        text = stringResource(R.string.theme_adaptive_builder_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(12.dp))
                    FilledTonalButton(
                        onClick = { navigator.pop() },
                        shapes = ButtonDefaults.shapes(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        MaterialText(stringResource(R.string.theme_adaptive_edit_appearance))
                    }
                }
            }
            item(key = "light") {
                VariantCaptureCard(
                    title = stringResource(R.string.theme_adaptive_draft_light),
                    captured = state.adaptiveDraftLightCaptured,
                    variant = draft?.light,
                    dark = false,
                    icon = Icons.Rounded.LightMode,
                    onCapture = {
                        viewModel.captureAdaptiveDraft(context, dark = false)
                    },
                )
            }
            item(key = "dark") {
                VariantCaptureCard(
                    title = stringResource(R.string.theme_adaptive_draft_dark),
                    captured = state.adaptiveDraftDarkCaptured,
                    variant = draft?.dark,
                    dark = true,
                    icon = Icons.Rounded.DarkMode,
                    onCapture = {
                        viewModel.captureAdaptiveDraft(context, dark = true)
                    },
                )
            }
            if (state.adaptiveDraftComplete) {
                item(key = "ready") {
                    BuilderCard {
                        MaterialText(
                            text = stringResource(R.string.theme_adaptive_draft_ready),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Button(
                                onClick = {
                                    exportLauncher.launch(ThemePackageStorage.packageFileName())
                                },
                                shapes = ButtonDefaults.shapes(),
                                modifier = Modifier.weight(1f),
                            ) {
                                MaterialIcon(
                                    imageVector = Icons.Rounded.FileUpload,
                                    contentDescription = null,
                                )
                                Spacer(Modifier.width(8.dp))
                                MaterialText(
                                    text = stringResource(R.string.theme_adaptive_builder_export),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            OutlinedButton(
                                onClick = { viewModel.applyAdaptiveDraft(context) },
                                shapes = ButtonDefaults.shapes(),
                                modifier = Modifier.weight(1f),
                            ) {
                                MaterialIcon(
                                    imageVector = Icons.Rounded.FileDownload,
                                    contentDescription = null,
                                )
                                Spacer(Modifier.width(8.dp))
                                MaterialText(
                                    text = stringResource(R.string.theme_adaptive_builder_apply),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                        Button(
                            onClick = ::publishToStore,
                            shapes = ButtonDefaults.shapes(),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            MaterialIcon(
                                imageVector = Icons.Rounded.FileUpload,
                                contentDescription = null,
                            )
                            Spacer(Modifier.width(8.dp))
                            MaterialText(
                                text = stringResource(R.string.theme_adaptive_builder_publish),
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                        MaterialText(
                            text = stringResource(R.string.theme_adaptive_export_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
            if (state.adaptiveDraftLightCaptured || state.adaptiveDraftDarkCaptured) {
                item(key = "clear") {
                    FilledTonalButton(
                        onClick = { viewModel.clearAdaptiveDraft(context) },
                        shapes = ButtonDefaults.shapes(),
                        colors = ButtonDefaults.filledTonalButtonColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                            contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        MaterialIcon(
                            imageVector = Icons.Rounded.DeleteOutline,
                            contentDescription = null,
                        )
                        MaterialText(
                            text = stringResource(R.string.theme_adaptive_builder_clear),
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun BuilderCard(content: @Composable () -> Unit) {
    TonalCard(
        modifier = Modifier.fillMaxWidth(),
        containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
        shape = MaterialTheme.shapes.large,
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            content()
        }
    }
}

@Composable
private fun VariantCaptureCard(
    title: String,
    captured: Boolean,
    variant: AdaptiveThemeVariantState?,
    dark: Boolean,
    icon: ImageVector,
    onCapture: () -> Unit,
) {
    BuilderCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            MaterialIcon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
            MaterialText(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.weight(1f),
            )
            Surface(
                shape = MaterialTheme.shapes.small,
                color = if (captured) {
                    MaterialTheme.colorScheme.primaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceContainerHighest
                },
                contentColor = if (captured) {
                    MaterialTheme.colorScheme.onPrimaryContainer
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            ) {
                MaterialText(
                    text = stringResource(
                        if (captured) R.string.theme_adaptive_captured
                        else R.string.theme_adaptive_not_captured,
                    ),
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                )
            }
        }
        if (variant != null) {
            Spacer(Modifier.height(10.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Surface(
                    modifier = Modifier.size(22.dp),
                    shape = CircleShape,
                    color = variant.data.keyColor
                        ?.takeIf { it != 0 }
                        ?.let { Color(it) }
                        ?: MaterialTheme.colorScheme.primary,
                ) {}
                MaterialText(
                    text = stringResource(
                        R.string.theme_adaptive_captured_summary,
                        stringResource(
                            if (variant.data.hasBackground == true) {
                                R.string.theme_adaptive_captured
                            } else {
                                R.string.theme_adaptive_not_captured
                            },
                        ),
                        stringResource(
                            if (variant.data.hasCardBackground == true) {
                                R.string.theme_adaptive_captured
                            } else {
                                R.string.theme_adaptive_not_captured
                            },
                        ),
                        variant.stickers.size,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        FilledTonalButton(
            onClick = onCapture,
            shapes = ButtonDefaults.shapes(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            MaterialText(
                text = stringResource(
                    when {
                        captured && dark -> R.string.theme_adaptive_recapture_dark
                        captured -> R.string.theme_adaptive_recapture_light
                        dark -> R.string.theme_adaptive_capture_dark
                        else -> R.string.theme_adaptive_capture_light
                    },
                ),
            )
        }
    }
}
