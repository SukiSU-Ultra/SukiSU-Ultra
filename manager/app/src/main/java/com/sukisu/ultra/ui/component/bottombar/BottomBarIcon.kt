package com.sukisu.ultra.ui.component.bottombar

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import coil.compose.rememberAsyncImagePainter
import java.io.File

/**
 * Draws a custom bottom bar icon image when [iconPath] points at a real file, otherwise falls
 * back to the built-in [icon] vector.
 *
 * Custom images keep their original colours (no tint) as chosen in the appearance settings, so
 * authors can ship multi-colour icons. The built-in vectors still take [tint].
 */
@Composable
fun BottomBarIconContent(
    icon: ImageVector,
    iconPath: String?,
    contentDescription: String?,
    modifier: Modifier = Modifier,
    tint: Color = Color.Unspecified,
    size: Dp = 24.dp,
) {
    val file = iconPath?.takeIf { it.isNotBlank() }?.let(::File)?.takeIf { it.isFile }
    if (file != null) {
        Image(
            painter = rememberAsyncImagePainter(model = file),
            contentDescription = contentDescription,
            modifier = modifier.size(size),
            contentScale = ContentScale.Fit,
        )
    } else {
        Image(
            painter = rememberVectorPainter(icon),
            contentDescription = contentDescription,
            modifier = modifier.size(size),
            colorFilter = tint.takeIf { it != Color.Unspecified }?.let { color ->
                ColorFilter.tint(color)
            },
        )
    }
}
