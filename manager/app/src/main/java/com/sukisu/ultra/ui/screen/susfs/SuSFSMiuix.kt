package com.sukisu.ultra.ui.screen.susfs

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.systemBars
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalCardBackgroundAlpha
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
internal fun SuSFSMiuix(
    uiState: SuSFSUiState,
    onSelectTab: (SuSFSTab) -> Unit,
    onBack: () -> Unit,
    content: @Composable () -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val barColor = if (blurActive || hasCustomBackground) Color.Transparent else colorScheme.surface
    val cardAlpha = LocalCardBackgroundAlpha.current
    val baseColors = colorScheme
    // TextField and secondary Button defaults use these two roles; make them follow the
    // card opacity so SuSFS controls don't render as opaque boxes over a custom background.
    //
    // Do not remember by Colors identity: the theme mutates the same instance, so a remembered
    // copy would keep the palette from before a light/dark or dynamic color change.
    val contentColors = if (hasCustomBackground) {
        baseColors.copy(
            secondaryContainer = baseColors.secondaryContainer.copy(alpha = cardAlpha),
            secondaryVariant = baseColors.secondaryVariant.copy(alpha = cardAlpha),
        )
    } else {
        baseColors
    }

    AppScaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    color = barColor,
                    title = stringResource(R.string.susfs_config_title),
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            val layoutDirection = LocalLayoutDirection.current
                            Icon(
                                modifier = Modifier.graphicsLayer {
                                    if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                                },
                                imageVector = MiuixIcons.Back,
                                contentDescription = stringResource(R.string.log_viewer_back),
                                tint = colorScheme.onBackground
                            )
                        }
                    },
                    scrollBehavior = scrollBehavior
                )
            }
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = (if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier)
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(horizontal = 16.dp),
            contentPadding = innerPadding,
            overscrollEffect = null,
        ) {
            item {
                AppCard(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                    OverlayDropdownPreference(
                        title = stringResource(R.string.susfs_config_title),
                        items = SuSFSTab.entries.map { stringResource(it.displayNameRes) },
                        selectedIndex = uiState.selectedTab.ordinal,
                        onSelectedIndexChange = { onSelectTab(SuSFSTab.entries[it]) },
                    )
                }
                Box(Modifier.fillMaxWidth().height(4.dp)) {
                    if (uiState.isLoading || uiState.isLoadingFeatures && uiState.selectedTab == SuSFSTab.ENABLED_FEATURES) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                }
                uiState.error?.let {
                    AppCard(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                        Text(it.localizedMessage ?: stringResource(R.string.operation_failed), Modifier.padding(16.dp), color = colorScheme.error)
                    }
                }
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    MiuixTheme(colors = contentColors) {
                        content()
                    }
                }
                Spacer(Modifier.height(24.dp))
            }
        }
    }
}
