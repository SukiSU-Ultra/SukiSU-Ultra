package com.sukisu.ultra.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import androidx.navigation.NavBackStackEntry
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.ramcosta.composedestinations.DestinationsNavHost
import com.ramcosta.composedestinations.animations.NavHostAnimatedDestinationStyle
import com.ramcosta.composedestinations.generated.NavGraphs
import com.ramcosta.composedestinations.generated.destinations.ExecuteModuleActionScreenDestination
import com.ramcosta.composedestinations.spec.NavHostGraphSpec
import com.ramcosta.composedestinations.utils.rememberDestinationsNavigator
import zako.zako.zako.zakoui.screen.moreSettings.util.LocaleHelper
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.screen.BottomBarDestination
import com.sukisu.ultra.ui.theme.KernelSUTheme
import com.sukisu.ultra.ui.util.LocalSnackbarHost
import com.sukisu.ultra.ui.util.install
import com.sukisu.ultra.ui.viewmodel.HomeViewModel
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import com.sukisu.ultra.ui.webui.initPlatform
import com.sukisu.ultra.ui.component.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import com.sukisu.ultra.ui.activity.component.BottomBar
import com.sukisu.ultra.ui.activity.util.*

class MainActivity : ComponentActivity() {
    private lateinit var superUserViewModel: SuperUserViewModel
    private lateinit var homeViewModel: HomeViewModel
    internal val settingsStateFlow = MutableStateFlow(SettingsState())

    data class SettingsState(
        val isHideOtherInfo: Boolean = false,
        val showKpmInfo: Boolean = false
    )

    private var showConfirmationDialog = mutableStateOf(false)
    private var pendingZipFiles = mutableStateOf<List<ZipFileInfo>>(emptyList())

    private lateinit var themeChangeObserver: ThemeChangeContentObserver
    private var isInitialized = false

    override fun attachBaseContext(newBase: Context?) {
        super.attachBaseContext(newBase?.let { LocaleHelper.applyLanguage(it) })
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        try {
            // 应用自定义 DPI
            DisplayUtils.applyCustomDpi(this)

            // Enable edge to edge
            enableEdgeToEdge()

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                window.isNavigationBarContrastEnforced = false
            }

            super.onCreate(savedInstanceState)

            val isManager = Natives.becomeManager(packageName)
            if (isManager) {
                install()
            }

            // 使用标记控制初始化流程
            if (!isInitialized) {
                initializeViewModels()
                initializeData()
                isInitialized = true
            }

            // Check if launched with a ZIP file
            val zipUri: ArrayList<Uri>? = when (intent?.action) {
                Intent.ACTION_SEND -> {
                    val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(Intent.EXTRA_STREAM)
                    }
                    uri?.let { arrayListOf(it) }
                }

                Intent.ACTION_SEND_MULTIPLE -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
                    }
                }

                else -> when {
                    intent?.data != null -> arrayListOf(intent.data!!)
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> {
                        intent.getParcelableArrayListExtra("uris", Uri::class.java)
                    }
                    else -> {
                        @Suppress("DEPRECATION")
                        intent.getParcelableArrayListExtra("uris")
                    }
                }
            }

            setContent {
                KernelSUTheme {
                    val navController = rememberNavController()
                    val snackBarHostState = remember { SnackbarHostState() }
                    val currentDestination = navController.currentBackStackEntryAsState().value?.destination

                    val bottomBarRoutes = remember {
                        BottomBarDestination.entries.map { it.direction.route }.toSet()
                    }

                    val navigator = navController.rememberDestinationsNavigator()

                    InstallConfirmationDialog(
                        show = showConfirmationDialog.value,
                        zipFiles = pendingZipFiles.value,
                        onConfirm = { confirmedFiles ->
                            showConfirmationDialog.value = false
                            UltraActivityUtils.navigateToFlashScreen(this, confirmedFiles, navigator)
                        },
                        onDismiss = {
                            showConfirmationDialog.value = false
                            pendingZipFiles.value = emptyList()
                            finish()
                        }
                    )

                    LaunchedEffect(zipUri) {
                        if (!zipUri.isNullOrEmpty()) {
                            // 检测 ZIP 文件类型并显示确认对话框
                            lifecycleScope.launch {
                                UltraActivityUtils.detectZipTypeAndShowConfirmation(this@MainActivity, zipUri) { infos ->
                                    if (infos.isNotEmpty()) {
                                        pendingZipFiles.value = infos
                                        showConfirmationDialog.value = true
                                    } else {
                                        finish()
                                    }
                                }
                            }
                        }
                    }

                    val showBottomBar = when (currentDestination?.route) {
                        ExecuteModuleActionScreenDestination.route -> false
                        else -> true
                    }

                    LaunchedEffect(Unit) {
                        initPlatform()
                    }

                    CompositionLocalProvider(
                        LocalSnackbarHost provides snackBarHostState
                    ) {
                        Scaffold(
                            bottomBar = {
                                AnimatedBottomBar.AnimatedBottomBarWrapper(
                                    showBottomBar = showBottomBar,
                                    content = { BottomBar(navController) }
                                )
                            },
                            contentWindowInsets = WindowInsets(0, 0, 0, 0)
                        ) { innerPadding ->
                            DestinationsNavHost(
                                modifier = Modifier.padding(innerPadding),
                                navGraph = NavGraphs.root as NavHostGraphSpec,
                                navController = navController,
                                defaultTransitions = object : NavHostAnimatedDestinationStyle() {
                                    override val enterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
                                        // If the target is a detail page (not a bottom navigation page), slide in from the right
                                        if (targetState.destination.route !in bottomBarRoutes) {
                                            slideInHorizontally(initialOffsetX = { it })
                                        } else {
                                            // Otherwise (switching between bottom navigation pages), use fade in
                                            fadeIn(animationSpec = tween(340))
                                        }
                                    }

                                    override val exitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition = {
                                        // If navigating from the home page (bottom navigation page) to a detail page, slide out to the left
                                        if (initialState.destination.route in bottomBarRoutes && targetState.destination.route !in bottomBarRoutes) {
                                            slideOutHorizontally(targetOffsetX = { -it / 4 }) + fadeOut()
                                        } else {
                                            // Otherwise (switching between bottom navigation pages), use fade out
                                            fadeOut(animationSpec = tween(340))
                                        }
                                    }

                                    override val popEnterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
                                        // If returning to the home page (bottom navigation page), slide in from the left
                                        if (targetState.destination.route in bottomBarRoutes) {
                                            slideInHorizontally(initialOffsetX = { -it / 4 }) + fadeIn()
                                        } else {
                                            // Otherwise (e.g., returning between multiple detail pages), use default fade in
                                            fadeIn(animationSpec = tween(340))
                                        }
                                    }

                                    override val popExitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition = {
                                        // If returning from a detail page (not a bottom navigation page), scale down and fade out
                                        if (initialState.destination.route !in bottomBarRoutes) {
                                            scaleOut(targetScale = 0.9f) + fadeOut()
                                        } else {
                                            // Otherwise, use default fade out
                                            fadeOut(animationSpec = tween(340))
                                        }
                                    }
                                }
                            )
                        }
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun initializeViewModels() {
        superUserViewModel = SuperUserViewModel()
        homeViewModel = HomeViewModel()

        // 设置主题变化监听器
        themeChangeObserver = ThemeUtils.registerThemeChangeObserver(this)
    }

    private fun initializeData() {
        lifecycleScope.launch {
            try {
                superUserViewModel.fetchAppList()
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

        // 数据刷新协程
        DataRefreshUtils.startDataRefreshCoroutine(lifecycleScope)
        DataRefreshUtils.startSettingsMonitorCoroutine(lifecycleScope, this, settingsStateFlow)

        // 初始化主题相关设置
        ThemeUtils.initializeThemeSettings(this, settingsStateFlow)
    }

    override fun onResume() {
        try {
            super.onResume()
            ThemeUtils.onActivityResume()

            // 仅在需要时刷新数据
            if (isInitialized) {
                refreshData()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun refreshData() {
        lifecycleScope.launch {
            try {
                superUserViewModel.fetchAppList()
                DataRefreshUtils.refreshData(lifecycleScope)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    override fun onPause() {
        try {
            super.onPause()
            ThemeUtils.onActivityPause(this)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun onDestroy() {
        try {
            ThemeUtils.unregisterThemeChangeObserver(this, themeChangeObserver)
            super.onDestroy()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}