package com.sukisu.ultra.ui.component.material

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsDraggedAsState
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.requiredSize
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
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp

/** Thickness of the thin rounded track. */
private val TrackHeight = 8.dp

/** Diameter of the floating knob. */
private val ThumbSize = 24.dp

/** Width of the primary ring around the knob. */
private val ThumbBorderWidth = 2.dp

/** Resting shadow of the knob; dropped when the slider is disabled. */
private val ThumbElevation = 2.dp

/** Diameter of the translucent halo shown while the knob is held. */
private val HaloSize = 40.dp

/** Diameter of the step tick dots drawn on the track. */
private val TickSize = 3.dp

private const val ThumbPressedScale = 1.08f
private const val HaloAlpha = 0.14f
private const val InactiveTrackAlpha = 0.2f
private const val DisabledAlpha = 0.38f

/**
 * A Material slider with a thin track and a floating round knob.
 *
 * Material3 [Slider] still owns the gestures, semantics and RTL handling; only the track and the
 * knob are drawn here. Use it when the M3 Expressive split-track slider is not wanted.
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
    val active = enabled && (pressed || dragged)
    val scale by animateFloatAsState(
        targetValue = if (active) ThumbPressedScale else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMedium,
        ),
        label = "CapsuleSliderThumbScale",
    )
    val haloAlpha by animateFloatAsState(
        targetValue = if (active) HaloAlpha else 0f,
        animationSpec = tween(durationMillis = 150),
        label = "CapsuleSliderThumbHalo",
    )
    val colorScheme = MaterialTheme.colorScheme
    val ringColor = if (enabled) colorScheme.primary else colorScheme.onSurface.copy(alpha = DisabledAlpha)
    // The knob body stays opaque so it hides the track and tick dots underneath it.
    val bodyColor = colorScheme.surfaceContainerLowest

    Box(
        modifier = Modifier.size(ThumbSize),
        contentAlignment = Alignment.Center,
    ) {
        if (haloAlpha > 0f) {
            // requiredSize lets the halo grow past the 24dp thumb slot without changing layout.
            Box(
                modifier = Modifier
                    .requiredSize(HaloSize)
                    .background(ringColor.copy(alpha = haloAlpha), CircleShape)
            )
        }
        Box(
            modifier = Modifier
                .size(ThumbSize)
                .graphicsLayer {
                    scaleX = scale
                    scaleY = scale
                }
                .shadow(
                    elevation = if (enabled) ThumbElevation else 0.dp,
                    shape = CircleShape,
                    clip = false,
                )
                .background(bodyColor, CircleShape)
                .border(ThumbBorderWidth, ringColor, CircleShape)
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
    val inactiveColor = if (enabled) {
        colorScheme.primary.copy(alpha = InactiveTrackAlpha)
    } else {
        colorScheme.onSurface.copy(alpha = 0.12f)
    }
    val activeTickColor = if (enabled) {
        colorScheme.onPrimary.copy(alpha = 0.7f)
    } else {
        colorScheme.surface.copy(alpha = 0.6f)
    }
    val inactiveTickColor = activeColor.copy(alpha = activeColor.alpha * 0.6f)
    val isRtl = LocalLayoutDirection.current == LayoutDirection.Rtl

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(TrackHeight)
    ) {
        val heightPx = size.height
        val centerY = heightPx / 2f
        val radius = CornerRadius(centerY)
        val halfThumb = ThumbSize.toPx() / 2f
        // Material3 measures the track slot without the thumb width and offsets it by half a
        // thumb. Extend the drawing by that half on both sides so the track lines up with the
        // slider edges and the knob never sticks out past the track ends.
        val fullLeft = -halfThumb
        val fullRight = size.width + halfThumb

        drawPath(
            Path().apply {
                addRoundRect(RoundRect(fullLeft, 0f, fullRight, heightPx, radius))
            },
            inactiveColor,
        )

        val fraction = state.coercedValueAsFraction.coerceIn(0f, 1f)
        // Track-local coordinates: thumb center is size.width * fraction (no thumb inset).
        val thumbCenterX = if (isRtl) size.width * (1f - fraction) else size.width * fraction
        val startX = if (isRtl) fullRight else fullLeft
        val activeLeft = minOf(startX, thumbCenterX)
        val activeRight = maxOf(startX, thumbCenterX)
        if (activeRight - activeLeft > 0.5f) {
            drawPath(
                Path().apply {
                    addRoundRect(RoundRect(activeLeft, 0f, activeRight, heightPx, radius))
                },
                activeColor,
            )
        }

        // Discrete sliders get a dot per stop; the opaque knob covers the one it sits on.
        val stops = state.steps + 1
        if (state.steps > 0) {
            val tickRadius = TickSize.toPx() / 2f
            for (i in 0..stops) {
                val tickFraction = i.toFloat() / stops
                val x = if (isRtl) size.width * (1f - tickFraction) else size.width * tickFraction
                val onActive = if (isRtl) x >= thumbCenterX else x <= thumbCenterX
                drawCircle(
                    color = if (onActive) activeTickColor else inactiveTickColor,
                    radius = tickRadius,
                    center = Offset(x, centerY),
                )
            }
        }
    }
}
