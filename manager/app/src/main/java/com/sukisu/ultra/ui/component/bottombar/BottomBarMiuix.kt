package com.sukisu.ultra.ui.component.bottombar

import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cottage
import androidx.compose.material.icons.rounded.Extension
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.LocalMainPagerState
import com.sukisu.ultra.ui.component.FloatingBottomBar
import com.sukisu.ultra.ui.component.FloatingBottomBarItem
import com.sukisu.ultra.ui.theme.LocalEnableFloatingBottomBar
import com.sukisu.ultra.ui.theme.LocalEnableFloatingBottomBarBlur
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.CustomTextKey
import com.sukisu.ultra.ui.util.customText
import top.yukonga.miuix.kmp.basic.Badge
import top.yukonga.miuix.kmp.basic.BadgedBox
import top.yukonga.miuix.kmp.basic.NavigationBar
import top.yukonga.miuix.kmp.basic.NavigationBarDefaults
import top.yukonga.miuix.kmp.basic.NavigationBarItem
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.blur.Backdrop
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.theme.LocalContentColor as MiuixLocalContentColor
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun BottomBarMiuix(
    blurBackdrop: LayerBackdrop?,
    backdrop: Backdrop,
    navigationBadge: NavigationBadgeState,
    modifier: Modifier,
) {
    val fullFeatured = Natives.isFullFeatured()
    if (!fullFeatured) return

    val mainState = LocalMainPagerState.current
    val enableFloatingBottomBar = LocalEnableFloatingBottomBar.current
    val enableFloatingBottomBarBlur = LocalEnableFloatingBottomBarBlur.current

    val bottomBarIcons = rememberBottomBarIconPaths()
    val items = BottomBarDestination.entries.map { destination ->
        Triple(
            destination,
            customText(destination.textKey),
            bottomBarIcons[destination.key],
        )
    }
    if (!enableFloatingBottomBar) {
        BlurredBar(blurBackdrop) {
            NavigationBar(
                modifier = modifier,
                color = if (blurBackdrop != null) Color.Transparent else backgroundAwareColor(MiuixTheme.colorScheme.surface),
                content = {
                    items.forEachIndexed { index, (destination, label, iconPath) ->
                        val selected = mainState.selectedPage == index
                        if (iconPath.isNullOrBlank()) {
                            NavigationBarItem(
                                modifier = Modifier.weight(1f),
                                icon = destination.icon,
                                label = label,
                                selected = selected,
                                onClick = {
                                    mainState.animateToPage(index)
                                },
                                badge = navigationBadgeFor(index, navigationBadge),
                            )
                        } else {
                            MiuixCustomNavigationBarItem(
                                selected = selected,
                                onClick = { mainState.animateToPage(index) },
                                icon = destination.icon,
                                iconPath = iconPath,
                                label = label,
                                badge = navigationBadgeFor(index, navigationBadge),
                            )
                        }
                    }
                }
            )
        }
    } else {
        val bottomPadding = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
            .let { inset -> if (inset != 0.dp) 8.dp + inset else 28.dp }
        FloatingBottomBar(
            modifier = modifier
                .pointerInput(Unit) {
                    detectTapGestures { }
                }
                .padding(start = 28.dp, end = 28.dp, bottom = bottomPadding),
            selectedIndex = mainState.selectedPage,
            onSelected = { mainState.animateToPage(it) },
            backdrop = backdrop,
            tabsCount = items.size,
            isBlurEnabled = enableFloatingBottomBarBlur,
        ) { activateTab ->
            items.forEachIndexed { index, (destination, label, iconPath) ->
                FloatingBottomBarItem(
                    selected = mainState.selectedPage == index,
                    onClick = {
                        activateTab(index)
                    },
                    modifier = Modifier.defaultMinSize(minWidth = 76.dp)
                ) {
                    // Icon and label take LocalContentColor so the FloatingBottomBar backdrop copy
                    // can recolor them to the accent tone inside the indicator pill.
                    val badge = navigationBadgeFor(index, navigationBadge, floating = true)
                    val icon: @Composable () -> Unit = {
                        BottomBarIconContent(
                            icon = destination.icon,
                            iconPath = iconPath,
                            contentDescription = label,
                            tint = MiuixLocalContentColor.current,
                        )
                    }
                    if (badge != null) {
                        BadgedBox(badge = { badge() }) { icon() }
                    } else {
                        icon()
                    }
                    Text(
                        text = label,
                        fontSize = 11.sp,
                        lineHeight = 14.sp,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.MiuixCustomNavigationBarItem(
    selected: Boolean,
    onClick: () -> Unit,
    icon: ImageVector,
    iconPath: String,
    label: String,
    badge: (@Composable () -> Unit)?,
) {
    val tint = MiuixTheme.colorScheme.onSurfaceContainer.copy(
        alpha = if (selected) 1f else NavigationBarDefaults.UnselectedAlpha,
    )
    val interactionSource = remember { MutableInteractionSource() }
    Column(
        modifier = Modifier
            .height(NavigationBarDefaults.ItemHeight)
            .weight(1f)
            .selectable(
                selected = selected,
                interactionSource = interactionSource,
                indication = null,
                role = Role.Tab,
                onClick = onClick,
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top,
    ) {
        Box(modifier = Modifier.padding(top = NavigationBarDefaults.IconTopPadding)) {
            if (badge != null) {
                BadgedBox(badge = { badge() }) {
                    BottomBarIconContent(
                        icon = icon,
                        iconPath = iconPath,
                        contentDescription = null,
                        tint = tint,
                        size = NavigationBarDefaults.IconSize,
                    )
                }
            } else {
                BottomBarIconContent(
                    icon = icon,
                    iconPath = iconPath,
                    contentDescription = null,
                    tint = tint,
                    size = NavigationBarDefaults.IconSize,
                )
            }
        }
        Text(
            text = label,
            color = tint,
            fontSize = NavigationBarDefaults.LabelFontSize,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            modifier = Modifier.padding(bottom = NavigationBarDefaults.BottomPadding),
        )
    }
}

enum class BottomBarDestination(
    val textKey: CustomTextKey,
    val icon: ImageVector,
    val key: String,
) {
    Home(CustomTextKey.PAGE_HOME, Icons.Rounded.Cottage, "home"),
    SuperUser(CustomTextKey.PAGE_SUPERUSER, Icons.Rounded.Security, "superuser"),
    Module(CustomTextKey.PAGE_MODULES, Icons.Rounded.Extension, "module"),
    Setting(CustomTextKey.PAGE_SETTINGS, Icons.Rounded.Settings, "setting")
}

internal fun navigationBadgeFor(
    index: Int,
    state: NavigationBadgeState,
    floating: Boolean = false,
): (@Composable () -> Unit)? {
    val badge = badgeFor(index, state) ?: return null
    return when (badge.tone) {
        BadgeTone.Alert -> {
            {
                Badge {
                    Text(badge.count.toString())
                }
            }
        }

        BadgeTone.Accent -> {
            {
                Badge(
                    containerColor = if (floating) MiuixTheme.colorScheme.primaryContainer else MiuixTheme.colorScheme.primary,
                    contentColor = if (floating) MiuixTheme.colorScheme.onPrimaryContainer else MiuixTheme.colorScheme.onPrimary,
                ) {
                    Text(badge.count.toString())
                }
            }
        }
    }
}
