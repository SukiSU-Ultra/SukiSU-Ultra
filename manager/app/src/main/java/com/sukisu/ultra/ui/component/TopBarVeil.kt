package com.sukisu.ultra.ui.component

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath

/**
 * A soft scrim behind a transparent top bar while a custom background is active.
 *
 * This is intentionally not a blur: it keeps the bar and its icons readable without hiding the
 * background image, and it works the same way in both the Material and Miuix shells.
 */
@Composable
fun TopBarVeil(
    color: Color,
    content: @Composable () -> Unit,
) {
    if (LocalBackgroundImagePath.current.isEmpty()) {
        content()
    } else {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.verticalGradient(
                        0f to color.copy(alpha = 0.28f),
                        0.65f to color.copy(alpha = 0.12f),
                        1f to color.copy(alpha = 0f),
                    )
                )
        ) {
            content()
        }
    }
}
