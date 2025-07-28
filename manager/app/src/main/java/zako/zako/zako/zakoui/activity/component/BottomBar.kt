package zako.zako.zako.zakoui.activity.component

import android.annotation.SuppressLint
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavHostController
import com.ramcosta.composedestinations.utils.isRouteOnBackStackAsState
import com.ramcosta.composedestinations.utils.rememberDestinationsNavigator
import com.ramcosta.composedestinations.spec.RouteOrDirection
import com.ramcosta.composedestinations.generated.NavGraphs
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.MainActivity
import zako.zako.zako.zakoui.activity.util.AppData
import zako.zako.zako.zakoui.activity.util.AppData.getKpmVersionUse
import com.sukisu.ultra.ui.screen.BottomBarDestination
import com.sukisu.ultra.ui.theme.CardConfig.cardAlpha
import com.sukisu.ultra.ui.theme.CardConfig.cardElevation
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.navigationBars
import zako.zako.zako.zakoui.activity.util.AppData.DataRefreshManager

@SuppressLint("ContextCastToActivity")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BottomBar(navController: NavHostController) {
    val navigator = navController.rememberDestinationsNavigator()
    val isFullFeatured = AppData.isFullFeatured(ksuApp.packageName)
    val kpmVersion = getKpmVersionUse()
    val cardColor = MaterialTheme.colorScheme.surfaceContainer
    val activity = LocalContext.current as MainActivity
    val settings by activity.settingsStateFlow.collectAsState()

    // 检查是否隐藏红点
    val isHideOtherInfo = settings.isHideOtherInfo
    val showKpmInfo = settings.showKpmInfo

    // 收集计数数据
    val superuserCount by DataRefreshManager.superuserCount.collectAsState()
    val moduleCount by DataRefreshManager.moduleCount.collectAsState()
    val kpmModuleCount by DataRefreshManager.kpmModuleCount.collectAsState()


    NavigationBar(
        modifier = Modifier.windowInsetsPadding(
            WindowInsets.navigationBars.only(WindowInsetsSides.Horizontal)
        ),
        containerColor = TopAppBarDefaults.topAppBarColors(
            containerColor = cardColor.copy(alpha = cardAlpha),
            scrolledContainerColor = cardColor.copy(alpha = cardAlpha)
        ).containerColor,
        tonalElevation = cardElevation
    ) {
        BottomBarDestination.entries.forEach { destination ->
            if (destination == BottomBarDestination.Kpm) {
                if (kpmVersion.isNotEmpty() && !showKpmInfo && Natives.version >= Natives.MINIMAL_SUPPORTED_KPM) {
                    if (!isFullFeatured && destination.rootRequired) return@forEach
                    val isCurrentDestOnBackStack by navController.isRouteOnBackStackAsState(destination.direction)
                    NavigationBarItem(
                        selected = isCurrentDestOnBackStack,
                        onClick = {
                            if (!isCurrentDestOnBackStack) {
                                navigator.popBackStack(destination.direction, false)
                            }
                            navigator.navigate(destination.direction) {
                                popUpTo(NavGraphs.root as RouteOrDirection) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = {
                            BadgedBox(
                                badge = {
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
            } else if (destination == BottomBarDestination.SuperUser) {
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
                            badge = {
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
            } else if (destination == BottomBarDestination.Module) {
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
                            badge = {
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
            } else {
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
                        if (isCurrentDestOnBackStack) {
                            Icon(destination.iconSelected, stringResource(destination.label))
                        } else {
                            Icon(destination.iconNotSelected, stringResource(destination.label))
                        }
                    },
                    label = { Text(stringResource(destination.label),style = MaterialTheme.typography.labelMedium) },
                    alwaysShowLabel = false
                )
            }
        }
    }
}