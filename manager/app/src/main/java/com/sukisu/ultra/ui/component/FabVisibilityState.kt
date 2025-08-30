package com.sukisu.ultra.ui.component

import android.annotation.SuppressLint
import androidx.compose.animation.*
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.unit.dp

@SuppressLint("AutoboxingStateCreation")
@Composable
fun rememberFabVisibilityState(listState: LazyListState): State<Boolean> {
    var previousScrollOffset by remember { mutableStateOf(0) }
    var previousIndex by remember { mutableStateOf(0) }
    val fabVisible = remember { mutableStateOf(true) }

    LaunchedEffect(listState) {
        snapshotFlow { listState.firstVisibleItemIndex to listState.firstVisibleItemScrollOffset }
            .collect { (index, offset) ->
                if (previousIndex == 0 && previousScrollOffset == 0) {
                    fabVisible.value = true
                } else {
                    val isScrollingDown = when {
                        index > previousIndex -> false
                        index < previousIndex -> true
                        else -> offset < previousScrollOffset
                    }

                    fabVisible.value = isScrollingDown
                }

                previousIndex = index
                previousScrollOffset = offset
            }
    }

    return fabVisible
}

@Composable
fun AnimatedFab(
    visible: Boolean,
    content: @Composable () -> Unit
) {
    val scale by animateFloatAsState(
        targetValue = if (visible) 1f else 0f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessLow
        )
    )

    AnimatedVisibility(
        visible = visible,
        enter = fadeIn() + scaleIn(),
        exit = fadeOut() + scaleOut(targetScale = 0.8f)
    ) {
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(16.dp))
                .scale(scale)
                .alpha(scale)
        ) {
            content()
        }
    }
}