package zako.zako.zako.zakoui.activity.util

import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.navigation.NavBackStackEntry
import com.ramcosta.composedestinations.animations.NavHostAnimatedDestinationStyle

object NavigationUtils {
    fun defaultTransitions() = object : NavHostAnimatedDestinationStyle() {
        override val enterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition
            get() = { fadeIn(animationSpec = tween(340)) }
        override val exitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition
            get() = { fadeOut(animationSpec = tween(340)) }
    }
}