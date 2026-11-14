package com.sukisu.ultra.ui.screen.colorpalette

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.ui.component.FullscreenPagerDialog

/**
 * The theme-settings flavour of [FullscreenPagerDialog].
 *
 * Pages are the Miuix and the Material 3 Expressive renderings of the same live
 * [ThemePreviewSpec], so swiping compares both UI styles; double-tap or the close button exits.
 */
@Composable
internal fun ThemeFullscreenPreviewDialog(
    show: Boolean,
    onDismiss: () -> Unit,
    content: @Composable (Modifier, Int) -> Unit,
) {
    FullscreenPagerDialog(
        show = show,
        pageCount = 2,
        onDismiss = onDismiss,
    ) { modifier, page ->
        Column(
            modifier = modifier
                .verticalScroll(rememberScrollState())
                .padding(start = 16.dp, end = 16.dp, top = 64.dp, bottom = 56.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            content(Modifier.fillMaxWidth(), page)
        }
    }
}
