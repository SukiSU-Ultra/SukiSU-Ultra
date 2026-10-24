package com.sukisu.ultra.ui.component.material

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.contentColorFor
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import com.sukisu.ultra.ui.theme.backgroundAwareColor

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun TonalCard(
    modifier: Modifier = Modifier,
    containerColor: Color = MaterialTheme.colorScheme.surfaceBright,
    contentColor: Color = contentColorFor(containerColor),
    shape: Shape = MaterialTheme.shapes.large,
    enabled: Boolean = true,
    onClick: (() -> Unit)? = null,
    onLongClick: (() -> Unit)? = null,
    interactionSource: MutableInteractionSource = remember { MutableInteractionSource() },
    pressFeedbackEnabled: Boolean = true,
    pressScale: Float = 0.97f,
    pressHapticEnabled: Boolean = true,
    content: @Composable () -> Unit,
) {
    val colors = CardDefaults.cardColors(
        containerColor = backgroundAwareColor(containerColor),
        contentColor = contentColor,
    )
    when {
        onLongClick != null || onClick != null -> {
            val pressed by interactionSource.collectIsPressedAsState()
            val targetScale = when {
                !pressFeedbackEnabled -> 1f
                pressed -> pressScale
                else -> 1f
            }
            val scale by animateFloatAsState(
                targetValue = targetScale,
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioMediumBouncy,
                    stiffness = Spring.StiffnessMediumLow,
                ),
                label = "TonalCardPressScale",
            )
            val haptic = LocalHapticFeedback.current
            LaunchedEffect(pressed) {
                if (pressed && pressFeedbackEnabled && pressHapticEnabled) {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                }
            }
            Card(
                modifier = modifier
                    .scale(scale)
                    .clip(shape)
                    .combinedClickable(
                        enabled = enabled,
                        onClick = onClick ?: {},
                        onLongClick = onLongClick,
                        interactionSource = interactionSource,
                        indication = LocalIndication.current,
                    ),
                colors = colors,
                shape = shape,
            ) { content() }
        }

        else -> Card(
            modifier = modifier,
            colors = colors,
            shape = shape,
        ) { content() }
    }
}
