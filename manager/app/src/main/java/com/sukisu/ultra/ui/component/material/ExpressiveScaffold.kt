package com.sukisu.ultra.ui.component.material

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
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
    Scaffold(
        modifier = modifier,
        topBar = { TopBarVeil(MaterialTheme.colorScheme.surface) { topBar() } },
        bottomBar = bottomBar,
        snackbarHost = snackbarHost,
        floatingActionButton = floatingActionButton,
        floatingActionButtonPosition = floatingActionButtonPosition,
        containerColor = resolvedContainerColor,
        contentColor = resolvedContentColor,
        contentWindowInsets = contentWindowInsets,
        content = content,
    )
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
