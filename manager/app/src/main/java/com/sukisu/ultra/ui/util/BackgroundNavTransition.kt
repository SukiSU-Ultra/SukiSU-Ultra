package com.sukisu.ultra.ui.util

import androidx.compose.ui.unit.LayoutDirection
import kotlin.math.roundToInt
import top.yukonga.miuix.kmp.nav.runtime.NavChange
import top.yukonga.miuix.kmp.nav.transition.navGraphicsTransition

/**
 * Navigation transition used while a custom background image is active.
 *
 * Keeps the standard miuix slide/parallax, but fades the covered page out as it gets covered.
 * Since pages render transparently over the global background, this prevents the previous
 * destination from showing through once the transition has settled.
 */
val BackgroundNavTransition = navGraphicsTransition { scope ->
    val width = scope.layoutSize.width.toFloat()
    val depth = scope.relativeDepth
    val rtl = scope.layoutDirection == LayoutDirection.Rtl
    if (depth <= 0f) {
        translationX = ((if (rtl) -1f else 1f) * (-depth).coerceIn(0f, 1f) * width).roundToInt().toFloat()
    } else {
        val progress = depth.coerceIn(0f, 1f)
        translationX = (if (rtl) 1f else -1f) * progress * width * 0.25f
        // On a push the previous page must not linger behind a transparent destination; on a pop
        // (or while a back gesture drives the stack) it fades in as it is revealed.
        val hideForPush = scope.gesture == null &&
            (scope.change is NavChange.Push || scope.change is NavChange.MultiPush)
        alpha = if (hideForPush) 0f else 1f - progress
    }
}
