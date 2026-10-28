package com.sukisu.ultra.ui.component.material

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
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
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp

/** Track thickness from the M3 Expressive slider spec. */
private val TrackHeight = 16.dp

/** Rounded handle size from the M3 Expressive slider spec. */
private val HandleWidth = 4.dp
private val HandleHeight = 44.dp

/** Space between the handle and the split track segments. */
private val HandleGap = 6.dp

/** Corner radius of the track ends that face the handle. */
private val TrackInsideCorner = 2.dp

/** Diameter of the stop indicator dot at the trailing end of the track. */
private val StopIndicatorSize = 4.dp

private const val DisabledAlpha = 0.38f

/**
 * An M3 Expressive slider: a thick split track with a pill handle and a stop indicator.
 *
 * [androidx.compose.material3.Slider] still owns the gestures, semantics and RTL handling; only
 * the track and the handle are drawn here. The slider state updates itself, so the caller reads
 * [SliderState.value] for a live value and persists it from [onValueChangeFinished].
 */
@Composable
fun ExpressiveSlider(
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
        thumb = { ExpressiveSliderThumb(interactionSource, enabled) },
        track = { sliderState -> ExpressiveSliderTrack(sliderState, enabled) },
    )
}

@Composable
private fun ExpressiveSliderThumb(
    interactionSource: MutableInteractionSource,
    enabled: Boolean,
) {
    val pressed by interactionSource.collectIsPressedAsState()
    val dragged by interactionSource.collectIsDraggedAsState()
    val active = enabled && (pressed || dragged)
    // The handle narrows while it is held, matching the pressed handle width of the spec.
    val handleWidth by animateDpAsState(
        targetValue = if (active) HandleWidth / 2 else HandleWidth,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioNoBouncy,
            stiffness = Spring.StiffnessMediumLow,
        ),
        label = "ExpressiveSliderHandleWidth",
    )
    val stateLayerAlpha by animateFloatAsState(
        targetValue = if (active) 0.10f else 0f,
        animationSpec = tween(durationMillis = 120),
        label = "ExpressiveSliderHandleStateLayer",
    )
    val handleColor = if (enabled) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.onSurface.copy(alpha = DisabledAlpha)
    }

    Box(
        modifier = Modifier.size(width = HandleWidth, height = HandleHeight),
        contentAlignment = Alignment.Center,
    ) {
        if (stateLayerAlpha > 0f) {
            Box(
                modifier = Modifier
                    .requiredSize(width = 20.dp, height = 56.dp)
                    .background(handleColor.copy(alpha = stateLayerAlpha), CircleShape)
            )
        }
        Box(
            modifier = Modifier
                .size(width = handleWidth, height = HandleHeight)
                .background(handleColor, CircleShape)
        )
    }
}

@Composable
private fun ExpressiveSliderTrack(
    state: SliderState,
    enabled: Boolean,
) {
    val colorScheme = MaterialTheme.colorScheme
    val activeColor = if (enabled) colorScheme.primary else colorScheme.onSurface.copy(alpha = DisabledAlpha)
    val inactiveColor = if (enabled) {
        colorScheme.secondaryContainer
    } else {
        colorScheme.onSurface.copy(alpha = 0.12f)
    }
    val isRtl = LocalLayoutDirection.current == LayoutDirection.Rtl

    // The track canvas is as tall as the handle so both are vertically centered on each other.
    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(HandleHeight)
    ) {
        val trackHeightPx = TrackHeight.toPx()
        val outerCorner = trackHeightPx / 2f
        val insideCorner = TrackInsideCorner.toPx()
        val gap = HandleGap.toPx() + HandleWidth.toPx() / 2f
        val top = (size.height - trackHeightPx) / 2f
        val bottom = top + trackHeightPx
        val centerY = size.height / 2f
        val fraction = state.coercedValueAsFraction
        // The thumb is placed with placeRelative(), so its physical position mirrors in RTL.
        val thumbX = if (isRtl) size.width * (1f - fraction) else size.width * fraction

        val activeEnd = if (isRtl) thumbX + gap else thumbX - gap
        val inactiveStart = if (isRtl) thumbX - gap else thumbX + gap

        if (isRtl) {
            drawTrackSegment(activeEnd, size.width, activeColor, insideCorner, outerCorner, top, bottom)
            drawTrackSegment(0f, inactiveStart, inactiveColor, outerCorner, insideCorner, top, bottom)
        } else {
            drawTrackSegment(0f, activeEnd, activeColor, outerCorner, insideCorner, top, bottom)
            drawTrackSegment(inactiveStart, size.width, inactiveColor, insideCorner, outerCorner, top, bottom)
        }

        // A dot marks the trailing end of the track while the handle has not reached it yet.
        val inactiveWidth = if (isRtl) inactiveStart else size.width - inactiveStart
        if (inactiveWidth > outerCorner * 2f) {
            val dotX = if (isRtl) outerCorner else size.width - outerCorner
            drawCircle(
                color = activeColor,
                radius = StopIndicatorSize.toPx() / 2f,
                center = Offset(dotX, centerY),
            )
        }
    }
}

private fun DrawScope.drawTrackSegment(
    startX: Float,
    endX: Float,
    color: Color,
    startCorner: Float,
    endCorner: Float,
    top: Float,
    bottom: Float,
) {
    val left = startX.coerceIn(0f, size.width)
    val right = endX.coerceIn(0f, size.width)
    if (right - left <= 0.5f) return
    val path = Path().apply {
        addRoundRect(
            RoundRect(
                left = left,
                top = top,
                right = right,
                bottom = bottom,
                topLeftCornerRadius = CornerRadius(startCorner),
                topRightCornerRadius = CornerRadius(endCorner),
                bottomLeftCornerRadius = CornerRadius(startCorner),
                bottomRightCornerRadius = CornerRadius(endCorner),
            )
        )
    }
    drawPath(path, color)
}
