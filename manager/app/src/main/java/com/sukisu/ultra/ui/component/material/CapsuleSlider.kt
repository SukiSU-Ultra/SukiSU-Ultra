package com.sukisu.ultra.ui.component.material

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsDraggedAsState
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp

/** Outer capsule track height; the active capsule sits inside it. */
private val TrackHeight = 32.dp

/** How far the outer track extends past the active capsule at both ends. */
private val TrackInset = 6.dp

/** Thumb diameter: 20dp, i.e. 0.72 of the track height like the miuix slider. */
private val ThumbSize = 20.dp

private const val ThumbPressedScale = 0.88f
private const val DisabledAlpha = 0.38f

/**
 * A Material slider drawn in the miuix capsule style.
 *
 * Material3 [Slider] still owns the gestures, semantics and RTL handling; only the track and the
 * thumb are drawn here. Use it when the M3 Expressive split-track slider is not wanted.
 */
@Composable
fun CapsuleSlider(
    state: SliderState,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onValueChangeFinished: (() -> Unit)? = null,
) {
    val interactionSource = remember { MutableInteractionSource() }
    Slider(
        state = state,
        modifier = modifier,
        enabled = enabled,
        onValueChange = null,
        onValueChangeFinished = onValueChangeFinished,
        interactionSource = interactionSource,
        thumb = { CapsuleThumb(interactionSource, enabled) },
        track = { sliderState -> CapsuleTrack(sliderState, enabled) },
    )
}

@Composable
private fun CapsuleThumb(
    interactionSource: MutableInteractionSource,
    enabled: Boolean,
) {
    val pressed by interactionSource.collectIsPressedAsState()
    val dragged by interactionSource.collectIsDraggedAsState()
    val scale by animateFloatAsState(
        targetValue = if (enabled && (pressed || dragged)) ThumbPressedScale else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioNoBouncy,
            stiffness = Spring.StiffnessMediumLow,
        ),
        label = "CapsuleSliderThumbScale",
    )
    val thumbColor = if (enabled) {
        MaterialTheme.colorScheme.onPrimary
    } else {
        MaterialTheme.colorScheme.onSurface.copy(alpha = DisabledAlpha)
    }

    Box(
        modifier = Modifier.size(ThumbSize),
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .size(ThumbSize)
                .graphicsLayer {
                    scaleX = scale
                    scaleY = scale
                }
                .background(thumbColor, CircleShape)
        )
    }
}

@Composable
private fun CapsuleTrack(
    state: SliderState,
    enabled: Boolean,
) {
    val colorScheme = MaterialTheme.colorScheme
    val activeColor = if (enabled) {
        colorScheme.primary
    } else {
        colorScheme.onSurface.copy(alpha = DisabledAlpha)
    }
    // Keep the inactive track translucent so it blends with the translucent cards instead of
    // reading as a solid pastel bar.
    val trackColor = if (enabled) {
        colorScheme.primary.copy(alpha = 0.2f)
    } else {
        colorScheme.onSurface.copy(alpha = 0.12f)
    }
    val isRtl = LocalLayoutDirection.current == LayoutDirection.Rtl

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(TrackHeight)
    ) {
        val heightPx = size.height
        val centerY = heightPx / 2f
        val thumbPx = ThumbSize.toPx()
        val halfThumb = thumbPx / 2f
        val insetPx = TrackInset.toPx()
        // Material3 measures the track slot without the thumb width and offsets it by half a
        // thumb. Extend the drawing by that half on both sides so the capsule still spans the
        // whole slider and the thumb stays inside the track at 0% / 100%.
        val fullLeft = -halfThumb
        val fullRight = size.width + halfThumb
        val activeHeightPx = ThumbSize.toPx()
        val activeTop = (heightPx - activeHeightPx) / 2f
        val activeBottom = activeTop + activeHeightPx

        // Outer track: extends past the active capsule at both ends and is taller than it, so it
        // completely wraps the active capsule (and the thumb) with a visible border.
        val trackPath = Path().apply {
            addRoundRect(
                RoundRect(
                    left = fullLeft - insetPx,
                    top = 0f,
                    right = fullRight + insetPx,
                    bottom = heightPx,
                    cornerRadius = CornerRadius(centerY),
                )
            )
        }
        drawPath(trackPath, trackColor)

        val fraction = state.coercedValueAsFraction.coerceIn(0f, 1f)
        // Track-local coordinates: thumb center is size.width * fraction (no thumb inset).
        val thumbCenterX = if (isRtl) size.width * (1f - fraction) else size.width * fraction
        val startX = if (isRtl) fullRight else fullLeft
        val activeLeft = minOf(startX, thumbCenterX)
        val activeRight = maxOf(startX, thumbCenterX)
        val activeWidth = activeRight - activeLeft
        if (activeWidth > 0.5f) {
            val activeRadius = (activeHeightPx / 2f).coerceAtMost(activeWidth / 2f)
            val activePath = Path().apply {
                addRoundRect(
                    RoundRect(
                        left = activeLeft,
                        top = activeTop,
                        right = activeRight,
                        bottom = activeBottom,
                        cornerRadius = CornerRadius(activeRadius),
                    )
                )
            }
            drawPath(activePath, activeColor)
        }
    }
}
