package com.sukisu.ultra.ui.activity.component

import android.annotation.SuppressLint
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavHostController
import com.ramcosta.composedestinations.generated.NavGraphs
import com.ramcosta.composedestinations.spec.RouteOrDirection
import com.ramcosta.composedestinations.utils.isRouteOnBackStackAsState
import com.ramcosta.composedestinations.utils.rememberDestinationsNavigator
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.MainActivity
import com.sukisu.ultra.ui.activity.util.*
import com.sukisu.ultra.ui.activity.util.AppData.getKpmVersionUse
import com.sukisu.ultra.ui.screen.BottomBarDestination
import com.sukisu.ultra.ui.theme.CardConfig.cardAlpha
import com.sukisu.ultra.ui.theme.CardConfig.cardElevation
import com.sukisu.ultra.ui.util.*

@SuppressLint("ContextCastToActivity")
@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun BottomBar(navController: NavHostController) {
    val navigator = navController.rememberDestinationsNavigator()
    val isFullFeatured = AppData.isFullFeatured()
    val kpmVersion = getKpmVersionUse()
    val cardColor = MaterialTheme.colorScheme.surfaceContainer
    val activity = LocalContext.current as MainActivity
    val settings by activity.settingsStateFlow.collectAsState()

    // 检查是否隐藏红点
    val isHideOtherInfo = settings.isHideOtherInfo
    val showKpmInfo = settings.showKpmInfo

    // 收集计数数据
    val superuserCount by AppData.DataRefreshManager.superuserCount.collectAsState()
    val moduleCount by AppData.DataRefreshManager.moduleCount.collectAsState()
    val kpmModuleCount by AppData.DataRefreshManager.kpmModuleCount.collectAsState()


    FlexibleBottomAppBar(
        modifier = Modifier.windowInsetsPadding(
            WindowInsets.navigationBars.only(WindowInsetsSides.Horizontal)
        ),
        containerColor = TopAppBarDefaults.topAppBarColors(
            containerColor = cardColor.copy(alpha = cardAlpha),
            scrolledContainerColor = cardColor.copy(alpha = cardAlpha)
        ).containerColor
    ) {
        BottomBarDestination.entries.forEach { destination ->
            val shouldShowButton : Boolean = when (destination) {
                BottomBarDestination.Kpm -> {
                    kpmVersion.isNotEmpty() && !kpmVersion.startsWith("Error") && !showKpmInfo && Natives.version >= Natives.MINIMAL_SUPPORTED_KPM
                }
                else -> true
            }

            val badge : @Composable BoxScope.() -> Unit = {
                when (destination) {
                    BottomBarDestination.Kpm -> {
                        if (kpmModuleCount > 0 && !isHideOtherInfo) {
                            Badge(
                                containerColor = MaterialTheme.colorScheme.secondary
                            ) {
                                Text(
                                    text = kpmModuleCount.toString(),
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                        }
                    }

                    BottomBarDestination.SuperUser -> {
                        if (superuserCount > 0 && !isHideOtherInfo) {
                            Badge(
                                containerColor = MaterialTheme.colorScheme.secondary
                            ) {
                                Text(
                                    text = superuserCount.toString(),
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                        }
                    }

                    BottomBarDestination.Module -> {
                        if (moduleCount > 0 && !isHideOtherInfo) {
                            Badge(
                                containerColor = MaterialTheme.colorScheme.secondary)
                            {
                                Text(
                                    text = moduleCount.toString(),
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                        }
                    }

                    else -> null
                }
            }
            if (!shouldShowButton) return@forEach
            if (!isFullFeatured && destination.rootRequired) return@forEach
            val isCurrentDestOnBackStack by navController.isRouteOnBackStackAsState(destination.direction)

            NavigationBarItem(
                selected = isCurrentDestOnBackStack,
                onClick = {
                    if (isCurrentDestOnBackStack) {
                        navigator.popBackStack(destination.direction, false)
                    }
                    navigator.navigate(destination.direction) {
                        popUpTo(NavGraphs.root) {
                            saveState = true
                        }
                        launchSingleTop = true
                        restoreState = true
                    }
                },
                icon = {
                    BadgedBox(
                        badge = badge
                    ) {
                        if (isCurrentDestOnBackStack) {
                            Icon(destination.iconSelected, stringResource(destination.label))
                        } else {
                            Icon(destination.iconNotSelected, stringResource(destination.label))
                        }
                    }
                },
                label = { Text(stringResource(destination.label),style = MaterialTheme.typography.labelMedium) },
                alwaysShowLabel = false
            )
        }
    }
}