package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.util.CustomTextKey
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import com.sukisu.ultra.ui.viewmodel.ExtensionItem
import com.sukisu.ultra.ui.viewmodel.ExtensionsUiState
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.textStyles
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun ExtensionsScreenMiuix(
    state: ExtensionsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpenDetails: (ExtensionItem) -> Unit,
    onToggle: (ExtensionItem, Boolean) -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive || hasCustomBackground) Color.Transparent else colorScheme.surface

    AppScaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    title = customText(CustomTextKey.PAGE_EXTENSIONS),
                    color = barColor,
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
                        IconButton(onClick = onRefresh) {
                            Icon(
                                imageVector = MiuixIcons.Refresh,
                                contentDescription = null,
                                tint = colorScheme.onBackground,
                            )
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
    ) { padding ->
        if (state.items.isEmpty() && !state.loading) {
            Column(
                modifier = Modifier
                    .then(if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier)
                    .fillMaxHeight()
                    .padding(padding)
                    .padding(32.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
            ) {
                Text(
                    text = stringResource(R.string.extension_empty_title),
                    style = textStyles.title3,
                )
                Text(
                    text = stringResource(R.string.extension_empty_subtitle),
                    style = textStyles.body2,
                    color = colorScheme.onBackground.copy(alpha = 0.75f),
                )
            }
            return@AppScaffold
        }

        val listState = rememberLazyListState()
        LazyColumn(
            state = listState,
            modifier = Modifier
                .then(if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier)
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(horizontal = 12.dp),
            contentPadding = padding,
            verticalArrangement = Arrangement.spacedBy(12.dp),
            overscrollEffect = null,
        ) {
            // Without a leading item the list settles at a non-zero initial scroll offset on
            // entry, which tucks the first card under the expanded large title until the user
            // scrolls. A zero-height item keeps the entry position at offset 0.
            item(key = "top-inset") {
                Spacer(Modifier.height(0.dp))
            }
            items(state.items, key = { it.wireName }) { item ->
                val extState = item.state
                val canOpen = extState.supported && item.descriptor.entry !is ExtensionEntry.Generic
                val onOpen = if (canOpen) {
                    { onOpenDetails(item) }
                } else null
                ExtensionCardMiuix(
                    item = item,
                    busy = item.wireName in state.busy,
                    onOpenDetails = onOpen,
                    onToggle = { enabled -> onToggle(item, enabled) },
                )
            }
            // Same pattern as HomePagerMiuix: a trailing spacer, not
            // contentPadding, gives the list a real scroll range so the last
            // card can move above the navigation bar.
            item(key = "bottom-inset") {
                Spacer(
                    Modifier.height(
                        WindowInsets.navigationBars
                            .asPaddingValues()
                            .calculateBottomPadding() + 4.dp,
                    ),
                )
            }
        }
    }
}

@Composable
private fun ExtensionCardMiuix(
    item: ExtensionItem,
    busy: Boolean,
    onOpenDetails: (() -> Unit)?,
    onToggle: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val extState = item.state
    val title = extensionTitle(item)
    val canToggle = item.descriptor.entry == ExtensionEntry.Generic && extState.userToggleable
    val titleColor = if (extState.supported) {
        colorScheme.onBackground
    } else {
        colorScheme.disabledOnSecondaryVariant
    }
    val descriptionColor = if (extState.supported) {
        colorScheme.onSurfaceVariantSummary
    } else {
        colorScheme.disabledOnSecondaryVariant
    }

    AppCard(
        modifier = modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        BasicComponent(
            modifier = Modifier.fillMaxWidth(),
            startAction = {
                Icon(
                    imageVector = Icons.Rounded.Memory,
                    contentDescription = null,
                    modifier = Modifier.padding(end = 6.dp),
                    tint = titleColor,
                )
            },
            endActions = when {
                canToggle -> {
                    {
                        Switch(
                            checked = extState.value != 0L,
                            onCheckedChange = onToggle,
                            enabled = !busy,
                        )
                    }
                }
                onOpenDetails != null -> {
                    {
                        Icon(
                            imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                            contentDescription = stringResource(R.string.extension_open_details),
                            tint = colorScheme.onBackground,
                        )
                    }
                }
                else -> null
            },
            insideMargin = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            onClick = onOpenDetails,
            enabled = extState.supported,
        ) {
            Text(
                text = title,
                style = textStyles.title4,
                color = titleColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            ExtensionStatusRow(item, modifier = Modifier.padding(top = 4.dp))
            Text(
                text = extensionDescription(item),
                modifier = Modifier.padding(top = 4.dp),
                style = textStyles.body2,
                color = descriptionColor,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
