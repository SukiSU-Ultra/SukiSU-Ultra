package com.sukisu.ultra.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import androidx.navigation.NavBackStackEntry
import androidx.navigation.compose.rememberNavController
import com.ramcosta.composedestinations.DestinationsNavHost
import com.ramcosta.composedestinations.animations.NavHostAnimatedDestinationStyle
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.NavGraphs
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.spec.NavHostGraphSpec
import com.ramcosta.composedestinations.utils.rememberDestinationsNavigator
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.activity.component.BottomBar
import com.sukisu.ultra.ui.activity.util.DisplayUtils
import com.sukisu.ultra.ui.activity.util.ThemeChangeContentObserver
import com.sukisu.ultra.ui.activity.util.ThemeUtils
import com.sukisu.ultra.ui.activity.util.UltraActivityUtils
import com.sukisu.ultra.ui.component.InstallConfirmationDialog
import com.sukisu.ultra.ui.component.ZipFileInfo
import com.sukisu.ultra.ui.screen.BottomBarDestination
import com.sukisu.ultra.ui.theme.KernelSUTheme
import com.sukisu.ultra.ui.util.LocalHandlePageChange
import com.sukisu.ultra.ui.util.LocalPagerState
import com.sukisu.ultra.ui.util.LocalSelectedPage
import com.sukisu.ultra.ui.util.LocalSnackbarHost
import com.sukisu.ultra.ui.util.install
import com.sukisu.ultra.ui.viewmodel.HomeViewModel
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import com.sukisu.ultra.ui.webui.initPlatform
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import zako.zako.zako.zakoui.screen.moreSettings.util.LocaleHelper

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

            val isManager = Natives.isManager
            if (isManager && !Natives.requireNewKernel()) {
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

                    LaunchedEffect(Unit) {
                        initPlatform()
                    }

                    CompositionLocalProvider(
                        LocalSnackbarHost provides snackBarHostState,
                    ) {
                        Scaffold(
                            contentWindowInsets = WindowInsets(0, 0, 0, 0)
                        ) { innerPadding ->
                            DestinationsNavHost(
                                modifier = Modifier.padding(innerPadding),
                                navGraph = NavGraphs.root as NavHostGraphSpec,
                                navController = navController,
                                defaultTransitions = object : NavHostAnimatedDestinationStyle() {
                                    override val enterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition =
                                        {
                                            slideInHorizontally(
                                                initialOffsetX = { it },
                                                animationSpec = tween(durationMillis = 500, easing = FastOutSlowInEasing)
                                            )
                                        }

                                    override val exitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition =
                                        {
                                            slideOutHorizontally(
                                                targetOffsetX = { -it / 5 },
                                                animationSpec = tween(durationMillis = 500, easing = FastOutSlowInEasing)
                                            )
                                        }

                                    override val popEnterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition =
                                        {
                                            slideInHorizontally(
                                                initialOffsetX = { -it / 5 },
                                                animationSpec = tween(durationMillis = 500, easing = FastOutSlowInEasing)
                                            )
                                        }

                                    override val popExitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition =
                                        {
                                            slideOutHorizontally(
                                                targetOffsetX = { it },
                                                animationSpec = tween(durationMillis = 500, easing = FastOutSlowInEasing)
                                            )
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

        // 初始化主题相关设置
        ThemeUtils.initializeThemeSettings(this, settingsStateFlow)
    }

    override fun onResume() {
        try {
            super.onResume()
            ThemeUtils.onActivityResume()
        } catch (e: Exception) {
            e.printStackTrace()
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

/**
 * @param navigator 页面导航
 * @param pageIndex 初始页面索引
 */
@Destination<RootGraph>(start = true)
@Composable
fun MainScreen(navigator: DestinationsNavigator, pageIndex: Int = 0) {
    // 页面隐藏处理
    val activity = LocalActivity.current as MainActivity
    val pages = BottomBarDestination.getPages(activity.settingsStateFlow.collectAsState().value)

    if (pageIndex < 0 || pageIndex >= pages.size) throw IllegalArgumentException("pageIndex invalid, index: $pageIndex, pages size: ${pages.size}")

    val coroutineScope = rememberCoroutineScope()
    val pagerState = rememberPagerState(initialPage = pageIndex, pageCount = { pages.size })
    var userScrollEnabled by remember { mutableStateOf(true) }
    var animating by remember { mutableStateOf(false) }
    var uiSelectedPage by remember { mutableIntStateOf(pageIndex) }
    var animateJob by remember { mutableStateOf<Job?>(null) }
    var lastRequestedPage by remember { mutableIntStateOf(pagerState.currentPage) }

    val handlePageChange: (Int) -> Unit = remember(pagerState, coroutineScope) {
        { page ->
            uiSelectedPage = page
            if (page == pagerState.currentPage) {
                if (animateJob != null && lastRequestedPage != page) {
                    animateJob?.cancel()
                    animateJob = null
                    animating = false
                    userScrollEnabled = true
                }
                lastRequestedPage = page
            } else {
                if (animateJob != null && lastRequestedPage == page) {
                    // Already animating to the requested page
                } else {
                    animateJob?.cancel()
                    animating = true
                    userScrollEnabled = false
                    val job = coroutineScope.launch {
                        try {
                            pagerState.animateScrollToPage(page)
                        } finally {
                            if (animateJob === this) {
                                userScrollEnabled = true
                                animating = false
                                animateJob = null
                            }
                        }
                    }
                    animateJob = job
                    lastRequestedPage = page
                }
            }
        }
    }

    LaunchedEffect(pagerState) {
        snapshotFlow { pagerState.currentPage }.collect { page ->
            if (!animating) uiSelectedPage = page
        }
    }

    BackHandler {
        if (pagerState.currentPage != 0) {
            handlePageChange(0)
        } else {
            activity.moveTaskToBack(true)
        }
    }

    CompositionLocalProvider(
        LocalPagerState provides pagerState,
        LocalHandlePageChange provides handlePageChange,
        LocalSelectedPage provides uiSelectedPage
    ) {
        Scaffold(
            bottomBar = {
                BottomBar(pages)
            },
        ) { innerPadding ->
            HorizontalPager(
                state = pagerState,
                beyondViewportPageCount = pages.size,
                userScrollEnabled = userScrollEnabled,
            ) {
                val destination = pages[it]
                destination.direction(navigator, innerPadding.calculateBottomPadding())
            }
        }
    }
}