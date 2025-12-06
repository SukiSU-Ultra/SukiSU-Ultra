package com.sukisu.ultra.ui.component

import android.annotation.SuppressLint
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow

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

    AnimatedVisibility(
        visible = visible,
        enter = fadeIn() + scaleIn(),
        exit = fadeOut() + scaleOut(targetScale = 0.8f)
    ) {
        content()
    }
}