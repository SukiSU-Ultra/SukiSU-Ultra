package com.sukisu.ultra.ui.component.miuix

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.union
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.sukisu.ultra.ui.component.TopBarVeil
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import top.yukonga.miuix.kmp.basic.FabPosition
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ToolbarPosition
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.MiuixPopupUtils.Companion.MiuixPopupHost

/**
 * A wrapper around miuix [Scaffold] that follows the custom background image.
 *
 * When [containerColor] is left unspecified, the container becomes transparent while a
 * custom background image is active and falls back to [MiuixTheme.colorScheme.surface]
 * otherwise. Passing an explicit [containerColor] always takes precedence.
 *
 * All other parameters are forwarded to [Scaffold] unchanged.
 */
@Composable
fun AppScaffold(
    modifier: Modifier = Modifier,
    topBar: @Composable () -> Unit = {},
    bottomBar: @Composable () -> Unit = {},
    floatingActionButton: @Composable () -> Unit = {},
    floatingActionButtonPosition: FabPosition = FabPosition.End,
    floatingToolbar: @Composable () -> Unit = {},
    floatingToolbarPosition: ToolbarPosition = ToolbarPosition.BottomCenter,
    snackbarHost: @Composable () -> Unit = {},
    popupHost: @Composable () -> Unit = { MiuixPopupHost() },
    containerColor: Color = Color.Unspecified,
    contentWindowInsets: WindowInsets = WindowInsets.systemBars.union(WindowInsets.displayCutout),
    content: @Composable (PaddingValues) -> Unit,
) {
    val resolvedContainerColor = when {
        containerColor != Color.Unspecified -> containerColor
        LocalBackgroundImagePath.current.isNotEmpty() -> Color.Transparent
        else -> MiuixTheme.colorScheme.surface
    }
    Scaffold(
        modifier = modifier,
        topBar = { TopBarVeil(MiuixTheme.colorScheme.surface) { topBar() } },
        bottomBar = bottomBar,
        floatingActionButton = floatingActionButton,
        floatingActionButtonPosition = floatingActionButtonPosition,
        floatingToolbar = floatingToolbar,
        floatingToolbarPosition = floatingToolbarPosition,
        snackbarHost = snackbarHost,
        popupHost = popupHost,
        containerColor = resolvedContainerColor,
        contentWindowInsets = contentWindowInsets,
        content = content,
    )
}
