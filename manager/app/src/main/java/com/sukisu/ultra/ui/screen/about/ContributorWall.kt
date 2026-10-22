/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Adapted from eltavine/Duck-Detector-Refactoring (ContributorWallGeometry / Motion / Canvas).
package com.sukisu.ultra.ui.screen.about

import androidx.compose.animation.core.AnimationState
import androidx.compose.animation.core.DecayAnimationSpec
import androidx.compose.animation.core.animate
import androidx.compose.animation.core.animateDecay
import androidx.compose.animation.core.animateTo
import androidx.compose.animation.core.spring
import androidx.compose.animation.rememberSplineBasedDecay
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculateCentroid
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.util.VelocityTracker
import androidx.compose.ui.input.pointer.util.addPointerInputChange
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sign
import kotlin.math.sqrt
import kotlin.math.tanh

private const val MinWallZoom = 0.6f
private const val MaxWallZoom = 3f
private val WallOffsetSaver = listSaver<Offset, Float>(
    save = { listOf(it.x, it.y) },
    restore = { Offset(it[0], it[1]) },
)

@Composable
fun ContributorWall(
    contributors: List<Contributor>,
    onSelect: (Contributor) -> Unit,
    modifier: Modifier = Modifier,
) {
    var zoom by rememberSaveable { mutableFloatStateOf(1.5f) }
    var offset by rememberSaveable(stateSaver = WallOffsetSaver) { mutableStateOf(Offset.Zero) }
    var motionJob by remember { mutableStateOf<Job?>(null) }
    val scope = rememberCoroutineScope()
    val decay = rememberSplineBasedDecay<Float>()
    val density = LocalDensity.current
    val avatarSize = 56.dp
    val geometry = remember(contributors.size, density) {
        with(density) { contributorWallGeometry(contributors.size, avatarSize.toPx(), 6.dp.toPx()) }
    }

    BoxWithConstraints(modifier.fillMaxWidth()) {
        val canvasHeight = maxWidth.coerceAtMost(380.dp)
        val viewport = with(density) { Size(maxWidth.toPx(), canvasHeight.toPx()) }
        val inset = with(density) { 8.dp.toPx() }
        val available = Size(viewport.width - inset * 2, viewport.height - inset * 2)
        val fitScale = geometry.fitScale(available)
        val center = Offset(viewport.width / 2, viewport.height / 2)

        LaunchedEffect(geometry, viewport) {
            motionJob?.cancel()
            offset = constrainWallOffset(offset, geometry.panLimit(available, fitScale * zoom))
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(canvasHeight)
                .clip(MaterialTheme.shapes.large)
                .wallEdgeFade()
                .pointerInput(geometry, viewport) {
                    val maximumVelocity = 6000.dp.toPx().let { Velocity(it, it) }
                    awaitEachGesture {
                        val down = awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
                        val stoppingMotion = motionJob?.isActive == true
                        motionJob?.cancel()
                        if (stoppingMotion) down.consume()
                        val tracker = VelocityTracker()
                        var trackedPosition = Offset.Zero
                        var pointerCount = 1
                        tracker.addPointerInputChange(down)
                        var rawOffset = unresistWallOffset(
                            offset, geometry.panLimit(available, fitScale * zoom), viewport,
                        )
                        var velocityHandoff: WallVelocityHandoff? = null
                        var releaseTimeMillis = down.uptimeMillis
                        var drag = Offset.Zero
                        var ownsGesture = stoppingMotion
                        do {
                            val event = awaitPointerEvent(PointerEventPass.Initial)
                            val pan = event.calculatePan()
                            val pressedCount = event.changes.count { it.pressed }
                            val previousEventTimeMillis = releaseTimeMillis
                            releaseTimeMillis = event.changes.first().uptimeMillis
                            if (pressedCount > 0 && pressedCount != pointerCount) {
                                velocityHandoff = if (pointerCount > 1 && pressedCount == 1) {
                                    val velocity = tracker.calculateVelocity(maximumVelocity)
                                    WallVelocityHandoff(Offset(velocity.x, velocity.y), previousEventTimeMillis)
                                } else null
                                tracker.resetTracking()
                                trackedPosition = Offset.Zero
                            }
                            if (pressedCount == 1 && pan != Offset.Zero) {
                                velocityHandoff = null
                            }
                            if (pressedCount == 1 || pressedCount == 0 && pointerCount == 1) {
                                val pointer = event.changes.firstOrNull { it.pressed }
                                    ?: event.changes.first { it.previousPressed }
                                tracker.addPointerInputChange(pointer)
                            } else if (pressedCount > 1) {
                                trackedPosition += pan
                                tracker.addPosition(event.changes.first().uptimeMillis, trackedPosition)
                            }
                            pointerCount = pressedCount
                            drag += pan
                            if (pressedCount >= 2 || drag.getDistance() > viewConfiguration.touchSlop) {
                                ownsGesture = true
                            }
                            if (ownsGesture) {
                                val nextZoom = (zoom * event.calculateZoom()).coerceIn(MinWallZoom, MaxWallZoom)
                                val centroid = event.calculateCentroid(useCurrent = false)
                                if (centroid != Offset.Unspecified) {
                                    rawOffset = zoomAround(rawOffset, centroid - center, pan, nextZoom / zoom)
                                }
                                zoom = nextZoom
                                offset = resistWallOffset(
                                    rawOffset,
                                    geometry.panLimit(available, fitScale * zoom),
                                    viewport,
                                )
                                event.changes.forEach { it.consume() }
                            }
                        } while (event.changes.any { it.pressed })
                        if (ownsGesture) {
                            val velocity = tracker.calculateVelocity(maximumVelocity)
                            val releasedVelocity = velocityHandoff?.velocityAtRelease(releaseTimeMillis)
                                ?: Offset(velocity.x, velocity.y)
                            val initialVelocity = releasedVelocity.let {
                                if (it.getDistance() < 50.dp.toPx()) Offset.Zero else it
                            }
                            motionJob = scope.launch {
                                settleContributorWall(
                                    initialOffset = offset,
                                    initialVelocity = initialVelocity,
                                    limit = geometry.panLimit(available, fitScale * zoom),
                                    viewport = viewport,
                                    decay = decay,
                                ) { offset = it }
                            }
                        }
                    }
                },
            contentAlignment = Alignment.Center,
        ) {
            contributors.forEachIndexed { index, contributor ->
                key(contributor.login) {
                    val avatar = rememberContributorAvatar(contributor.login)
                    Box(
                        modifier = Modifier
                            .size(avatarSize)
                            .graphicsLayer {
                                val scale = fitScale * zoom
                                val bubble = wallBubbleTransform(geometry.centers[index] * scale + offset, viewport)
                                scaleX = scale * bubble.scale
                                scaleY = scaleX
                                translationX = bubble.position.x
                                translationY = bubble.position.y
                            }
                            .clip(CircleShape)
                            .background(MaterialTheme.colorScheme.surface)
                            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant), CircleShape)
                            .clickable(role = Role.Button) { onSelect(contributor) }
                            .semantics { contentDescription = contributor.login },
                        contentAlignment = Alignment.Center,
                    ) {
                        if (avatar != null) {
                            Image(
                                bitmap = avatar,
                                contentDescription = null,
                                contentScale = ContentScale.Crop,
                                modifier = Modifier.size(avatarSize),
                            )
                        } else {
                            Text(
                                text = contributor.login.first().uppercase(),
                                style = MaterialTheme.typography.headlineMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.clearAndSetSemantics { },
                            )
                        }
                    }
                }
            }
        }
    }
}

/** Fades all four edges of the wall so avatars dissolve into the card instead of being cut off. */
private fun Modifier.wallEdgeFade(): Modifier = this
    .graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen }
    .drawWithCache {
        val fade = 36.dp.toPx().coerceAtMost(size.minDimension / 4)
        fun stops(fraction: Float) = arrayOf(
            0f to Color.Transparent,
            fraction * 0.4f to Color.Black.copy(alpha = 0.35f),
            fraction to Color.Black,
            1f - fraction to Color.Black,
            1f - fraction * 0.4f to Color.Black.copy(alpha = 0.35f),
            1f to Color.Transparent,
        )
        val horizontal = Brush.horizontalGradient(*stops(fade / size.width))
        val vertical = Brush.verticalGradient(*stops(fade / size.height))
        onDrawWithContent {
            drawContent()
            drawRect(horizontal, blendMode = BlendMode.DstIn)
            drawRect(vertical, blendMode = BlendMode.DstIn)
        }
    }

internal data class ContributorWallGeometry(
    val centers: List<Offset>,
    val contentSize: Size,
) {
    fun fitScale(viewport: Size): Float =
        min(viewport.width / contentSize.width, viewport.height / contentSize.height).coerceAtMost(1f)

    fun panLimit(viewport: Size, scale: Float): Offset = Offset(
        max(0f, (contentSize.width * scale - viewport.width) / 2f),
        max(0f, (contentSize.height * scale - viewport.height) / 2f),
    )
}

internal fun contributorWallGeometry(count: Int, avatarSize: Float, gap: Float): ContributorWallGeometry {
    require(count >= 0 && avatarSize > 0f && gap >= 0f)
    if (count == 0) return ContributorWallGeometry(emptyList(), Size(avatarSize, avatarSize))
    var radius = 0
    while (1 + 3 * radius * (radius + 1) < count) radius++
    val spacing = avatarSize + gap
    val pairs = buildList {
        for (r in -radius..radius) {
            for (q in -radius..radius) {
                if (abs(q + r) <= radius && (r > 0 || r == 0 && q > 0)) {
                    val point = Offset((q + r / 2f) * spacing, r * spacing * sqrt(3f) / 2f)
                    add((q * q + q * r + r * r) to point)
                }
            }
        }
    }.sortedWith(compareBy<Pair<Int, Offset>> { it.first }.thenBy { atan2(it.second.y, it.second.x) })
    // Pick outer positions in opposite pairs so a partial ring does not skew the whole wall to one side.
    val centers = (listOf(Offset.Zero) + pairs.flatMap { listOf(it.second, -it.second) }).take(count)
    val minX = centers.minOf { it.x }
    val maxX = centers.maxOf { it.x }
    val minY = centers.minOf { it.y }
    val maxY = centers.maxOf { it.y }
    val center = Offset((minX + maxX) / 2f, (minY + maxY) / 2f)
    return ContributorWallGeometry(
        centers = centers.map { it - center },
        contentSize = Size(maxX - minX + avatarSize, maxY - minY + avatarSize),
    )
}

internal fun zoomAround(offset: Offset, centroid: Offset, pan: Offset, ratio: Float): Offset =
    (offset - centroid) * ratio + centroid + pan

internal fun constrainWallOffset(offset: Offset, limit: Offset): Offset = Offset(
    if (limit.x == 0f) 0f else offset.x.coerceIn(-limit.x, limit.x),
    if (limit.y == 0f) 0f else offset.y.coerceIn(-limit.y, limit.y),
)

internal fun resistWallOffset(offset: Offset, limit: Offset, viewport: Size): Offset = Offset(
    resistWallAxis(offset.x, limit.x, viewport.width),
    resistWallAxis(offset.y, limit.y, viewport.height),
)

internal fun resistWallAxis(value: Float, bound: Float, extent: Float): Float {
    val overflow = abs(value) - bound
    if (overflow <= 0f) return value
    val travel = extent * 0.18f
    return sign(value) * (bound + travel * overflow / (travel + overflow))
}

internal fun unresistWallOffset(offset: Offset, limit: Offset, viewport: Size): Offset {
    fun restore(value: Float, bound: Float, extent: Float): Float {
        val overflow = abs(value) - bound
        if (overflow <= 0f) return value
        val travel = extent * 0.18f
        val visibleOverflow = overflow.coerceAtMost(travel * 0.999f)
        return sign(value) * (bound + travel * visibleOverflow / (travel - visibleOverflow))
    }
    return Offset(
        restore(offset.x, limit.x, viewport.width),
        restore(offset.y, limit.y, viewport.height),
    )
}

internal data class WallBubbleTransform(val position: Offset, val scale: Float)

internal fun wallBubbleTransform(position: Offset, viewport: Size): WallBubbleTransform {
    val distance = max(abs(position.x) / (viewport.width / 2), abs(position.y) / (viewport.height / 2))
    if (distance <= 0.3f) return WallBubbleTransform(position, 1f)
    val edgeDistance = distance - 0.3f
    val curve = tanh(edgeDistance / 0.42f)
    val compressedDistance = 0.3f + 0.35f * edgeDistance + 0.65f * 0.42f * curve
    // Scale and position compression share one curve so shrunken edge avatars stay tightly packed.
    val scale = 0.35f + 0.65f * (1f - curve * curve)
    return WallBubbleTransform(position * (compressedDistance / distance), scale)
}

internal data class WallVelocityHandoff(val velocity: Offset, val uptimeMillis: Long) {
    // Only carry velocity across the lift-off event that immediately follows; a held finger drops old momentum.
    fun velocityAtRelease(releaseTimeMillis: Long): Offset? =
        velocity.takeIf { releaseTimeMillis - uptimeMillis in 0L..40L }
}

internal suspend fun settleContributorWall(
    initialOffset: Offset,
    initialVelocity: Offset,
    limit: Offset,
    viewport: Size,
    decay: DecayAnimationSpec<Float>,
    onFrame: (Offset) -> Unit,
) = coroutineScope {
    var current = initialOffset
    // Axes decelerate independently so the wall keeps sliding along one edge while pinned on the other.
    launch {
        settleAxis(initialOffset.x, initialVelocity.x, limit.x, viewport.width, decay) {
            current = current.copy(x = it)
            onFrame(current)
        }
    }
    launch {
        settleAxis(initialOffset.y, initialVelocity.y, limit.y, viewport.height, decay) {
            current = current.copy(y = it)
            onFrame(current)
        }
    }
}

private suspend fun settleAxis(
    initial: Float,
    velocity: Float,
    bound: Float,
    extent: Float,
    decay: DecayAnimationSpec<Float>,
    onFrame: (Float) -> Unit,
) {
    val rebound = spring<Float>(dampingRatio = 0.85f, stiffness = 220f)
    if (abs(initial) > bound) {
        animate(initial, initial.coerceIn(-bound, bound), animationSpec = rebound) { value, _ -> onFrame(value) }
        return
    }
    if (velocity == 0f || bound == 0f) return
    val motion = AnimationState(initialValue = initial, initialVelocity = velocity)
    motion.animateDecay(decay) {
        onFrame(resistWallAxis(value, bound, extent))
        if (abs(value) > bound) cancelAnimation()
    }
    if (abs(motion.value) > bound) {
        // Reuse the impact velocity so momentum flows into the edge rebound.
        motion.animateTo(
            targetValue = motion.value.coerceIn(-bound, bound),
            animationSpec = rebound,
            sequentialAnimation = true,
        ) { onFrame(resistWallAxis(value, bound, extent)) }
    }
}
