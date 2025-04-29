package com.sukisu.ultra.ui

import android.database.ContentObserver
import android.os.Build
import android.os.Bundle
import android.os.Handler
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavHostController
import androidx.navigation.compose.rememberNavController
import com.ramcosta.composedestinations.DestinationsNavHost
import com.ramcosta.composedestinations.animations.NavHostAnimatedDestinationStyle
import com.ramcosta.composedestinations.generated.NavGraphs
import com.ramcosta.composedestinations.spec.NavHostGraphSpec
import com.ramcosta.composedestinations.spec.RouteOrDirection
import com.ramcosta.composedestinations.utils.isRouteOnBackStackAsState
import com.ramcosta.composedestinations.utils.rememberDestinationsNavigator
import io.sukisu.ultra.UltraToolInstall
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.screen.BottomBarDestination
import com.sukisu.ultra.ui.theme.*
import com.sukisu.ultra.ui.util.*

class MainActivity : ComponentActivity() {
    private inner class ThemeChangeContentObserver(
        handler: Handler,
        private val onThemeChanged: () -> Unit
    ) : ContentObserver(handler) {
        override fun onChange(selfChange: Boolean) {
            super.onChange(selfChange)
            onThemeChanged()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // 启用边缘到边缘显示
        enableEdgeToEdge()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
        }

        super.onCreate(savedInstanceState)

        // 加载保存的主题设置
        loadCustomBackground()
        loadThemeMode()
        loadThemeColors()
        loadDynamicColorState()
        CardConfig.load(applicationContext)

        val contentObserver = ThemeChangeContentObserver(Handler(mainLooper)) {
            runOnUiThread {
                ThemeConfig.backgroundImageLoaded = false
                loadCustomBackground()
            }
        }

        contentResolver.registerContentObserver(
            android.provider.Settings.System.getUriFor("ui_night_mode"),
            false,
            contentObserver
        )

        val destroyListeners = mutableListOf<() -> Unit>()
        destroyListeners.add {
            contentResolver.unregisterContentObserver(contentObserver)
        }

        val isManager = Natives.becomeManager(ksuApp.packageName)
        if (isManager) {
            install()
            UltraToolInstall.tryToInstall()
        }

        setContent {
            KernelSUTheme {
                val navController = rememberNavController()
                val snackBarHostState = remember { SnackbarHostState() }

                Scaffold(
                    bottomBar = { BottomBar(navController) },
                    contentWindowInsets = WindowInsets(0, 0, 0, 0),
                    snackbarHost = { SnackbarHost(snackBarHostState) }
                ) { innerPadding ->
                    CompositionLocalProvider(
                        LocalSnackbarHost provides snackBarHostState
                    ) {
                        DestinationsNavHost(
                            modifier = Modifier.padding(innerPadding),
                            navGraph = NavGraphs.root as NavHostGraphSpec,
                            navController = navController,
                            defaultTransitions = remember {
                                object : NavHostAnimatedDestinationStyle() {
                                    override val enterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
                                        fadeIn(animationSpec = tween(300)) +
                                                slideIntoContainer(
                                                    towards = AnimatedContentTransitionScope.SlideDirection.Up,
                                                    animationSpec = tween(300)
                                                )
                                    }

                                    override val exitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition = {
                                        fadeOut(animationSpec = tween(300)) +
                                                slideOutOfContainer(
                                                    towards = AnimatedContentTransitionScope.SlideDirection.Down,
                                                    animationSpec = tween(300)
                                                )
                                    }
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    private val destroyListeners = mutableListOf<() -> Unit>()

    override fun onDestroy() {
        destroyListeners.forEach { it() }
        super.onDestroy()
    }
}

@Composable
private fun BottomBar(navController: NavHostController) {
    val navigator = navController.rememberDestinationsNavigator()
    val isManager = Natives.becomeManager(ksuApp.packageName)
    val fullFeatured = isManager && !Natives.requireNewKernel() && rootAvailable()
    val kpmVersion = getKpmVersion()

    val containerColor = MaterialTheme.colorScheme.surfaceContainer
    val selectedColor = MaterialTheme.colorScheme.primary
    val unselectedColor = MaterialTheme.colorScheme.onSurfaceVariant
    val cornerRadius = 18.dp

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .clip(RoundedCornerShape(cornerRadius)),
        color = containerColor.copy(alpha = 0.95f),
        tonalElevation = 0.dp
    ) {
        NavigationBar(
            modifier = Modifier.windowInsetsPadding(
                WindowInsets.navigationBars.only(WindowInsetsSides.Horizontal)
            ),
            containerColor = Color.Transparent,
            tonalElevation = 0.dp
        ) {
            BottomBarDestination.entries.forEach { destination ->
                if (destination == BottomBarDestination.Kpm) {
                    if (kpmVersion.isNotEmpty() && !kpmVersion.startsWith("Error")) {
                        if (!fullFeatured && destination.rootRequired) return@forEach
                        val isCurrentDestOnBackStack by navController.isRouteOnBackStackAsState(destination.direction)
                        NavigationBarItem(
                            selected = isCurrentDestOnBackStack,
                            onClick = {
                                if (!isCurrentDestOnBackStack) {
                                    navigator.navigate(destination.direction) {
                                        popUpTo(NavGraphs.root as RouteOrDirection) {
                                            saveState = true
                                        }
                                        launchSingleTop = true
                                        restoreState = true
                                    }
                                }
                            },
                            icon = {
                                Icon(
                                    imageVector = if (isCurrentDestOnBackStack) {
                                        destination.iconSelected
                                    } else {
                                        destination.iconNotSelected
                                    },
                                    contentDescription = stringResource(destination.label),
                                    tint = if (isCurrentDestOnBackStack) selectedColor else unselectedColor
                                )
                            },
                            label = {
                                Text(
                                    text = stringResource(destination.label),
                                    style = MaterialTheme.typography.labelMedium
                                )
                            },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = selectedColor,
                                unselectedIconColor = unselectedColor,
                                selectedTextColor = selectedColor,
                                unselectedTextColor = unselectedColor,
                                indicatorColor = MaterialTheme.colorScheme.secondaryContainer
                            )
                        )
                    }
                } else {
                    if (!fullFeatured && destination.rootRequired) return@forEach
                    val isCurrentDestOnBackStack by navController.isRouteOnBackStackAsState(destination.direction)
                    NavigationBarItem(
                        selected = isCurrentDestOnBackStack,
                        onClick = {
                            if (!isCurrentDestOnBackStack) {
                                navigator.navigate(destination.direction) {
                                    popUpTo(NavGraphs.root as RouteOrDirection) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            }
                        },
                        icon = {
                            Icon(
                                imageVector = if (isCurrentDestOnBackStack) {
                                    destination.iconSelected
                                } else {
                                    destination.iconNotSelected
                                },
                                contentDescription = stringResource(destination.label),
                                tint = if (isCurrentDestOnBackStack) selectedColor else unselectedColor
                            )
                        },
                        label = {
                            Text(
                                text = stringResource(destination.label),
                                style = MaterialTheme.typography.labelMedium
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = selectedColor,
                            unselectedIconColor = unselectedColor,
                            selectedTextColor = selectedColor,
                            unselectedTextColor = unselectedColor,
                            indicatorColor = MaterialTheme.colorScheme.secondaryContainer
                        )
                    )
                }
            }
        }
    }
}
