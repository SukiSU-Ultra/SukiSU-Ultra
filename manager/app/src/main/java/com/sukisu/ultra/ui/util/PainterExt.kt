package com.sukisu.ultra.ui.util

import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.geometry.isSpecified
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.painter.Painter
import kotlin.math.max

/**
 * Fills the modifier's bounds with [painter], cropping the overflow like `ContentScale.Crop`.
 *
 * `Painter.draw(size)` ignores the painter's content scale and stretches the image to the bounds,
 * so a card background with a different aspect ratio than the card comes out squashed instead of
 * cropped.
 */
fun Modifier.drawPainterCover(painter: Painter): Modifier = drawBehind {
    if (size.width <= 0f || size.height <= 0f) return@drawBehind
    val intrinsicSize = painter.intrinsicSize
    val usable = intrinsicSize.isSpecified && !intrinsicSize.isEmpty() &&
        intrinsicSize.width.isFinite() && intrinsicSize.height.isFinite()
    if (!usable) {
        with(painter) { draw(size) }
        return@drawBehind
    }
    val scale = max(size.width / intrinsicSize.width, size.height / intrinsicSize.height)
    val coveredSize = Size(intrinsicSize.width * scale, intrinsicSize.height * scale)
    translate(
        left = (size.width - coveredSize.width) / 2f,
        top = (size.height - coveredSize.height) / 2f,
    ) {
        with(painter) { draw(coveredSize) }
    }
}
