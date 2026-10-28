package com.sukisu.ultra.ui.screen.backgroundcrop

import android.graphics.Bitmap
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.toSize
import kotlin.math.min

@Stable
class CropController {
    var zoom by mutableFloatStateOf(1f)
        private set
    var offset by mutableStateOf(Offset.Zero)
        private set
    var quarterTurns by mutableIntStateOf(0)
        private set
    var viewportSize by mutableStateOf(Size.Zero)
        private set

    val transform: CropTransform
        get() = CropTransform(zoom, offset)

    fun updateViewportSize(size: Size) {
        if (size == viewportSize) return
        viewportSize = size
        resetTransform()
    }

    fun update(next: CropTransform, image: OrientedImageSize) {
        val clamped = clampCropTransform(next, viewportSize, image)
        zoom = clamped.zoom
        offset = clamped.offset
    }

    fun rotate() {
        quarterTurns = (quarterTurns + 1) % 4
        resetTransform()
    }

    fun resetTransform() {
        zoom = 1f
        offset = Offset.Zero
    }

    fun resetAll() {
        quarterTurns = 0
        resetTransform()
    }
}

@Composable
fun rememberCropController(): CropController = remember { CropController() }

@Composable
fun CropViewport(
    bitmap: Bitmap,
    aspectRatio: Float,
    controller: CropController,
    cornerRadius: Dp,
    modifier: Modifier = Modifier,
) {
    val viewportAspect = aspectRatio.takeIf { it.isFinite() && it > 0f } ?: 1f
    val turns = controller.quarterTurns
    val oriented = remember(bitmap, turns) { orientedImageSize(bitmap, turns) }
    val image = remember(bitmap) { bitmap.asImageBitmap() }

    BoxWithConstraints(modifier) {
        val availableWidth = maxWidth
        val availableHeight = maxHeight
        val width: Dp
        val height: Dp
        if (availableWidth / availableHeight > viewportAspect) {
            height = availableHeight
            width = availableHeight * viewportAspect
        } else {
            width = availableWidth
            height = availableWidth / viewportAspect
        }

        Box(
            modifier = Modifier
                .align(Alignment.Center)
                .size(width.coerceAtLeast(1.dp), height.coerceAtLeast(1.dp))
                .clip(RoundedCornerShape(cornerRadius))
                .background(Color.Black)
                .onSizeChanged { controller.updateViewportSize(it.toSize()) }
                .pointerInput(bitmap, oriented) {
                    detectTransformGestures { centroid, pan, zoomChange, _ ->
                        val viewport = controller.viewportSize
                        if (viewport.width <= 0f || viewport.height <= 0f) {
                            return@detectTransformGestures
                        }
                        val previous = controller.transform
                        val nextZoom = (previous.zoom * zoomChange)
                            .coerceIn(1f, CROP_MAX_ZOOM)
                        val zoomRatio = nextZoom / previous.zoom
                        val center = Offset(viewport.width / 2f, viewport.height / 2f)
                        // Keep the point under the fingers stable while pinching.
                        val nextOffset = centroid - center -
                            (centroid - center - previous.offset) * zoomRatio + pan
                        controller.update(
                            CropTransform(zoom = nextZoom, offset = nextOffset),
                            oriented,
                        )
                    }
                }
        ) {
            Canvas(Modifier.fillMaxSize()) {
                val viewport = size
                if (viewport.width <= 0f || viewport.height <= 0f) return@Canvas
                val scale = coverScale(viewport, oriented)
                if (!scale.isFinite() || scale <= 0f) return@Canvas

                withTransform({
                    translate(
                        viewport.width / 2f + controller.offset.x,
                        viewport.height / 2f + controller.offset.y,
                    )
                    rotate(controller.quarterTurns * 90f, pivot = Offset.Zero)
                    scale(scale * controller.zoom, scale * controller.zoom, pivot = Offset.Zero)
                    translate(-bitmap.width / 2f, -bitmap.height / 2f)
                }) {
                    drawImage(
                        image = image,
                        dstSize = IntSize(bitmap.width, bitmap.height),
                        filterQuality = FilterQuality.High,
                    )
                }
                drawCropOverlay()
            }
        }
    }
}

private fun DrawScope.drawCropOverlay() {
    val width = size.width
    val height = size.height
    val gridStroke = 0.8.dp.toPx()

    for (index in 1..2) {
        val x = width * index / 3f
        val y = height * index / 3f
        drawLine(
            color = Color.White.copy(alpha = 0.22f),
            start = Offset(x, 0f),
            end = Offset(x, height),
            strokeWidth = gridStroke,
        )
        drawLine(
            color = Color.White.copy(alpha = 0.22f),
            start = Offset(0f, y),
            end = Offset(width, y),
            strokeWidth = gridStroke,
        )
    }

    drawRect(
        color = Color.White.copy(alpha = 0.24f),
        topLeft = Offset.Zero,
        size = size,
        style = Stroke(width = 1.dp.toPx()),
    )

    val inset = 1.dp.toPx()
    val bracket = min(width, height) * 0.09f
    val shadowWidth = 4.5.dp.toPx()
    val bracketWidth = 3.dp.toPx()

    fun drawBracket(x: Float, y: Float, dx: Float, dy: Float) {
        val endX = x + dx * bracket
        val endY = y + dy * bracket
        val shadow = Color.Black.copy(alpha = 0.35f)
        drawLine(shadow, Offset(x, y), Offset(endX, y), shadowWidth, StrokeCap.Round)
        drawLine(shadow, Offset(x, y), Offset(x, endY), shadowWidth, StrokeCap.Round)
        drawLine(Color.White, Offset(x, y), Offset(endX, y), bracketWidth, StrokeCap.Round)
        drawLine(Color.White, Offset(x, y), Offset(x, endY), bracketWidth, StrokeCap.Round)
    }

    drawBracket(inset, inset, 1f, 1f)
    drawBracket(width - inset, inset, -1f, 1f)
    drawBracket(inset, height - inset, 1f, -1f)
    drawBracket(width - inset, height - inset, -1f, -1f)
}
