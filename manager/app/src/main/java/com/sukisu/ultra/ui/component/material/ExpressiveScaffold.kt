package com.sukisu.ultra.ui.component.material

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.FabPosition
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScaffoldDefaults
import androidx.compose.material3.TopAppBarColors
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.contentColorFor
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.sukisu.ultra.ui.component.TopBarVeil
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableProgressiveBlur
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.blur.rememberLayerBackdrop
import top.yukonga.miuix.kmp.shader.isRuntimeShaderSupported

@Composable
fun ExpressiveScaffold(
    modifier: Modifier = Modifier,
    topBar: @Composable () -> Unit = {},
    bottomBar: @Composable () -> Unit = {},
    snackbarHost: @Composable () -> Unit = {},
    floatingActionButton: @Composable () -> Unit = {},
    floatingActionButtonPosition: FabPosition = FabPosition.End,
    containerColor: Color = Color.Unspecified,
    contentColor: Color = Color.Unspecified,
    contentWindowInsets: WindowInsets = ScaffoldDefaults.contentWindowInsets,
    content: @Composable (PaddingValues) -> Unit,
) {
    val resolvedContainerColor = when {
        containerColor != Color.Unspecified -> containerColor
        LocalBackgroundImagePath.current.isNotEmpty() -> Color.Transparent
        else -> MaterialTheme.colorScheme.surfaceContainer
    }
    val containerContentColor = contentColorFor(resolvedContainerColor)
    val resolvedContentColor = when {
        contentColor != Color.Unspecified -> contentColor
        containerContentColor != Color.Unspecified -> containerContentColor
        else -> LocalContentColor.current
    }
    val progressiveBlur = LocalEnableProgressiveBlur.current && isRuntimeShaderSupported()
    // The progressive top bar samples what is drawn behind it. An opaque page container is the
    // only thing there, so paint it into the capture; a transparent one over a custom background
    // lets the wallpaper capture underneath show through instead.
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val captureBaseColor = if (resolvedContainerColor.alpha > 0f || hasCustomBackground) {
        resolvedContainerColor
    } else {
        // A transparent page color over no wallpaper has nothing opaque behind the layer; keep
        // the capture opaque so blurring it cannot bleed black into the bar.
        MaterialTheme.colorScheme.surfaceContainer
    }
    val contentBackdrop = rememberLayerBackdrop {
        if (captureBaseColor.alpha > 0f) {
            drawRect(captureBaseColor)
        }
        drawContent()
    }
    Scaffold(
        modifier = modifier,
        topBar = {
            TopBarVeil(
                // MD3E app bars sit on surfaceContainer; the progressive tint follows the bar.
                color = MaterialTheme.colorScheme.surfaceContainer,
                blurBackdrop = if (progressiveBlur) contentBackdrop else null,
            ) {
                topBar()
            }
        },
        bottomBar = bottomBar,
        snackbarHost = snackbarHost,
        floatingActionButton = floatingActionButton,
        floatingActionButtonPosition = floatingActionButtonPosition,
        containerColor = resolvedContainerColor,
        contentColor = resolvedContentColor,
        contentWindowInsets = contentWindowInsets,
    ) { paddingValues ->
        // Keep the wrapper in place in both modes: swapping the composition structure when the
        // setting is flipped would recreate the page content and drop its remembered state.
        Box(
            modifier = Modifier
                .fillMaxSize()
                .then(if (progressiveBlur) Modifier.layerBackdrop(contentBackdrop) else Modifier)
        ) {
            content(paddingValues)
        }
    }
}

@Composable
fun expressiveTopAppBarColors(
    containerColor: Color = Color.Unspecified,
    scrolledContainerColor: Color = Color.Unspecified,
): TopAppBarColors {
    val resolvedContainerColor = when {
        containerColor != Color.Unspecified -> containerColor
        LocalBackgroundImagePath.current.isNotEmpty() -> Color.Transparent
        else -> MaterialTheme.colorScheme.surfaceContainer
    }
    val resolvedScrolledContainerColor = if (scrolledContainerColor != Color.Unspecified) {
        scrolledContainerColor
    } else {
        resolvedContainerColor
    }
    return TopAppBarDefaults.topAppBarColors(
        containerColor = resolvedContainerColor,
        scrolledContainerColor = resolvedScrolledContainerColor,
    )
}
