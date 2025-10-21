package com.sukisu.ultra.ui.theme

import android.content.Context
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.annotation.RequiresApi
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.paint
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.zIndex
import androidx.core.content.edit
import androidx.core.net.toUri
import coil.compose.AsyncImagePainter
import coil.compose.rememberAsyncImagePainter
import com.sukisu.ultra.ui.theme.util.BackgroundTransformation
import com.sukisu.ultra.ui.theme.util.saveTransformedBackground
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileOutputStream

@Stable
object ThemeConfig {
    // 主题状态
    var customBackgroundUri by mutableStateOf<Uri?>(null)
    var forceDarkMode by mutableStateOf<Boolean?>(null)
    var currentTheme by mutableStateOf<ThemeColors>(ThemeColors.Default)
    var useDynamicColor by mutableStateOf(false)

    // 背景状态
    var backgroundImageLoaded by mutableStateOf(false)
    var isThemeChanging by mutableStateOf(false)
    var preventBackgroundRefresh by mutableStateOf(false)

    // 主题变化检测
    private var lastDarkModeState: Boolean? = null

    fun detectThemeChange(currentDarkMode: Boolean): Boolean {
        val hasChanged = lastDarkModeState != null && lastDarkModeState != currentDarkMode
        lastDarkModeState = currentDarkMode
        return hasChanged
    }

    fun resetBackgroundState() {
        if (!preventBackgroundRefresh) {
            backgroundImageLoaded = false
        }
        isThemeChanging = true
    }

    fun updateTheme(
        theme: ThemeColors? = null,
        dynamicColor: Boolean? = null,
        darkMode: Boolean? = null
    ) {
        theme?.let { currentTheme = it }
        dynamicColor?.let { useDynamicColor = it }
        darkMode?.let { forceDarkMode = it }
    }

    fun reset() {
        customBackgroundUri = null
        forceDarkMode = null
        currentTheme = ThemeColors.Default
        useDynamicColor = false
        backgroundImageLoaded = false
        isThemeChanging = false
        preventBackgroundRefresh = false
        lastDarkModeState = null
    }
}

object ThemeManager {
    private const val PREFS_NAME = "theme_prefs"

    fun saveThemeMode(context: Context, forceDark: Boolean?) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit {
            putString("theme_mode", when (forceDark) {
                true -> "dark"
                false -> "light"
                null -> "system"
            })
        }
        ThemeConfig.forceDarkMode = forceDark
    }

    fun loadThemeMode(context: Context) {
        val mode = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString("theme_mode", "system")

        ThemeConfig.forceDarkMode = when (mode) {
            "dark" -> true
            "light" -> false
            else -> null
        }
    }

    fun saveThemeColors(context: Context, themeName: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit {
            putString("theme_colors", themeName)
        }
        ThemeConfig.currentTheme = ThemeColors.fromName(themeName)
    }

    fun loadThemeColors(context: Context) {
        val themeName = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString("theme_colors", "default") ?: "default"
        ThemeConfig.currentTheme = ThemeColors.fromName(themeName)
    }

    fun saveDynamicColorState(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit {
            putBoolean("use_dynamic_color", enabled)
        }
        ThemeConfig.useDynamicColor = enabled
    }


    fun loadDynamicColorState(context: Context) {
        val enabled = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean("use_dynamic_color", Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        ThemeConfig.useDynamicColor = enabled
    }
}

object BackgroundManager {
    private const val TAG = "BackgroundManager"

    fun saveAndApplyCustomBackground(
        context: Context,
        uri: Uri,
        transformation: BackgroundTransformation? = null
    ) {
        try {
            val finalUri = if (transformation != null) {
                context.saveTransformedBackground(uri, transformation)
            } else {
                copyImageToInternalStorage(context, uri)
            }

            saveBackgroundUri(context, finalUri)
            ThemeConfig.customBackgroundUri = finalUri
            CardConfig.updateBackground(true)
            resetBackgroundState(context)

        } catch (e: Exception) {
            Log.e(TAG, "保存背景失败: ${e.message}", e)
        }
    }

    fun clearCustomBackground(context: Context) {
        saveBackgroundUri(context, null)
        ThemeConfig.customBackgroundUri = null
        CardConfig.updateBackground(false)
        resetBackgroundState(context)
    }

    fun loadCustomBackground(context: Context) {
        val uriString = context.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
            .getString("custom_background", null)

        val newUri = uriString?.toUri()
        val preventRefresh = context.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
            .getBoolean("prevent_background_refresh", false)

        ThemeConfig.preventBackgroundRefresh = preventRefresh

        if (!preventRefresh || ThemeConfig.customBackgroundUri?.toString() != newUri?.toString()) {
            Log.d(TAG, "加载自定义背景: $uriString")
            ThemeConfig.customBackgroundUri = newUri
            ThemeConfig.backgroundImageLoaded = false
            CardConfig.updateBackground(newUri != null)
        }
    }

    private fun saveBackgroundUri(context: Context, uri: Uri?) {
        context.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE).edit {
            putString("custom_background", uri?.toString())
            putBoolean("prevent_background_refresh", false)
        }
    }

    private fun resetBackgroundState(context: Context) {
        ThemeConfig.backgroundImageLoaded = false
        ThemeConfig.preventBackgroundRefresh = false
        context.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE).edit {
            putBoolean("prevent_background_refresh", false)
        }
    }

    private fun copyImageToInternalStorage(context: Context, uri: Uri): Uri? {
        return try {
            val inputStream = context.contentResolver.openInputStream(uri) ?: return null
            val fileName = "custom_background_${System.currentTimeMillis()}.jpg"
            val file = File(context.filesDir, fileName)

            FileOutputStream(file).use { outputStream ->
                val buffer = ByteArray(8 * 1024)
                var read: Int
                while (inputStream.read(buffer).also { read = it } != -1) {
                    outputStream.write(buffer, 0, read)
                }
                outputStream.flush()
            }
            inputStream.close()

            Uri.fromFile(file)
        } catch (e: Exception) {
            Log.e(TAG, "复制图片失败: ${e.message}", e)
            null
        }
    }
}

@Composable
fun KernelSUTheme(
    darkTheme: Boolean = when(ThemeConfig.forceDarkMode) {
        true -> true
        false -> false
        null -> isSystemInDarkTheme()
    },
    dynamicColor: Boolean = ThemeConfig.useDynamicColor,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val systemIsDark = isSystemInDarkTheme()

    // 初始化主题
    ThemeInitializer(context = context, systemIsDark = systemIsDark)

    // 创建颜色方案
    val colorScheme = createColorScheme(context, darkTheme, dynamicColor)

    // 系统栏样式
    SystemBarController(darkTheme)

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            // 背景层
            BackgroundLayer(darkTheme)
            // 内容层
            Box(modifier = Modifier.fillMaxSize().zIndex(1f)) {
                content()
            }
        }
    }
}

@Composable
private fun ThemeInitializer(context: Context, systemIsDark: Boolean) {
    val themeChanged = ThemeConfig.detectThemeChange(systemIsDark)
    val scope = rememberCoroutineScope()

    // 处理系统主题变化
    LaunchedEffect(systemIsDark, themeChanged) {
        if (ThemeConfig.forceDarkMode == null && themeChanged) {
            Log.d("ThemeSystem", "系统主题变化: $systemIsDark")
            ThemeConfig.resetBackgroundState()

            if (!ThemeConfig.preventBackgroundRefresh) {
                BackgroundManager.loadCustomBackground(context)
            }

            CardConfig.apply {
                load(context)
                setThemeDefaults(systemIsDark)
                save(context)
            }
        }
    }

    // 初始加载配置
    LaunchedEffect(Unit) {
        scope.launch {
            ThemeManager.loadThemeMode(context)
            ThemeManager.loadThemeColors(context)
            ThemeManager.loadDynamicColorState(context)
            CardConfig.load(context)

            if (!ThemeConfig.backgroundImageLoaded && !ThemeConfig.preventBackgroundRefresh) {
                BackgroundManager.loadCustomBackground(context)
            }
        }
    }
}

@Composable
private fun BackgroundLayer(darkTheme: Boolean) {
    val backgroundUri = rememberSaveable { mutableStateOf(ThemeConfig.customBackgroundUri) }

    LaunchedEffect(ThemeConfig.customBackgroundUri) {
        backgroundUri.value = ThemeConfig.customBackgroundUri
    }

    // 默认背景
    Box(
        modifier = Modifier
            .fillMaxSize()
            .zIndex(-2f)
            .background(
                if (CardConfig.isCustomBackgroundEnabled) {
                    MaterialTheme.colorScheme.surfaceContainerLow
                } else {
                    MaterialTheme.colorScheme.background
                }
            )
    )

    // 自定义背景
    backgroundUri.value?.let { uri ->
        CustomBackgroundLayer(uri = uri, darkTheme = darkTheme)
    }
}

@Composable
private fun CustomBackgroundLayer(uri: Uri, darkTheme: Boolean) {
    val painter = rememberAsyncImagePainter(
        model = uri,
        onError = { error ->
            Log.e("ThemeSystem", "背景加载失败: ${error.result.throwable.message}")
            ThemeConfig.customBackgroundUri = null
        },
        onSuccess = {
            Log.d("ThemeSystem", "背景加载成功")
            ThemeConfig.backgroundImageLoaded = true
            ThemeConfig.isThemeChanging = false
        }
    )

    val transition = updateTransition(
        targetState = ThemeConfig.backgroundImageLoaded,
        label = "backgroundTransition"
    )

    val alpha by transition.animateFloat(
        label = "backgroundAlpha",
        transitionSpec = {
            spring(
                dampingRatio = Spring.DampingRatioMediumBouncy,
                stiffness = Spring.StiffnessMedium
            )
        }
    ) { loaded -> if (loaded) 1f else 0f }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .zIndex(-1f)
            .alpha(alpha)
    ) {
        // 背景图片
        Box(
            modifier = Modifier
                .fillMaxSize()
                .paint(painter = painter, contentScale = ContentScale.Crop)
                .graphicsLayer {
                    this.alpha = (painter.state as? AsyncImagePainter.State.Success)?.let { 1f } ?: 0f
                }
        )

        // 遮罩层
        BackgroundOverlay(darkTheme = darkTheme)
    }
}

@Composable
private fun BackgroundOverlay(darkTheme: Boolean) {
    val dimFactor = CardConfig.cardDim

    // 主要遮罩层
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                if (darkTheme) {
                    Color.Black.copy(alpha = 0.3f + dimFactor * 0.4f)
                } else {
                    Color.White.copy(alpha = 0.05f + dimFactor * 0.3f)
                }
            )
    )

    // 边缘渐变遮罩
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors = listOf(
                        Color.Transparent,
                        if (darkTheme) {
                            Color.Black.copy(alpha = 0.2f + dimFactor * 0.2f)
                        } else {
                            Color.Black.copy(alpha = 0.05f + dimFactor * 0.1f)
                        }
                    ),
                    radius = 1000f
                )
            )
    )
}

@Composable
private fun createColorScheme(
    context: Context,
    darkTheme: Boolean,
    dynamicColor: Boolean
): ColorScheme {
    return when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) createDynamicDarkColorScheme(context)
            else createDynamicLightColorScheme(context)
        }
        darkTheme -> createDarkColorScheme()
        else -> createLightColorScheme()
    }
}

@Composable
private fun SystemBarController(darkMode: Boolean) {
    val context = LocalContext.current
    val activity = context as ComponentActivity

    SideEffect {
        activity.enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.auto(
                Color.Transparent.toArgb(),
                Color.Transparent.toArgb(),
            ) { darkMode },
            navigationBarStyle = if (darkMode) {
                SystemBarStyle.dark(Color.Transparent.toArgb())
            } else {
                SystemBarStyle.light(
                    Color.Transparent.toArgb(),
                    Color.Transparent.toArgb()
                )
            }
        )
    }
}

@RequiresApi(Build.VERSION_CODES.S)
@Composable
private fun createDynamicDarkColorScheme(context: Context): ColorScheme {
    val scheme = dynamicDarkColorScheme(context)
    return scheme.copy(
        background = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else scheme.background,
        surface = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else scheme.surface,
        onBackground = scheme.onBackground,
        onSurface = scheme.onSurface
    )
}

@RequiresApi(Build.VERSION_CODES.S)
@Composable
private fun createDynamicLightColorScheme(context: Context): ColorScheme {
    val scheme = dynamicLightColorScheme(context)
    return scheme.copy(
        background = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else scheme.background,
        surface = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else scheme.surface,
        onBackground = scheme.onBackground,
        onSurface = scheme.onSurface
    )
}

@Composable
private fun createDarkColorScheme() = darkColorScheme(
    primary = ThemeConfig.currentTheme.primaryDark,
    onPrimary = ThemeConfig.currentTheme.onPrimaryDark,
    primaryContainer = ThemeConfig.currentTheme.primaryContainerDark,
    onPrimaryContainer = ThemeConfig.currentTheme.onPrimaryContainerDark,
    secondary = ThemeConfig.currentTheme.secondaryDark,
    onSecondary = ThemeConfig.currentTheme.onSecondaryDark,
    secondaryContainer = ThemeConfig.currentTheme.secondaryContainerDark,
    onSecondaryContainer = ThemeConfig.currentTheme.onSecondaryContainerDark,
    tertiary = ThemeConfig.currentTheme.tertiaryDark,
    onTertiary = ThemeConfig.currentTheme.onTertiaryDark,
    tertiaryContainer = ThemeConfig.currentTheme.tertiaryContainerDark,
    onTertiaryContainer = ThemeConfig.currentTheme.onTertiaryContainerDark,
    error = ThemeConfig.currentTheme.errorDark,
    onError = ThemeConfig.currentTheme.onErrorDark,
    errorContainer = ThemeConfig.currentTheme.errorContainerDark,
    onErrorContainer = ThemeConfig.currentTheme.onErrorContainerDark,
    background = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else ThemeConfig.currentTheme.backgroundDark,
    onBackground = ThemeConfig.currentTheme.onBackgroundDark,
    surface = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else ThemeConfig.currentTheme.surfaceDark,
    onSurface = ThemeConfig.currentTheme.onSurfaceDark,
    surfaceVariant = ThemeConfig.currentTheme.surfaceVariantDark,
    onSurfaceVariant = ThemeConfig.currentTheme.onSurfaceVariantDark,
    outline = ThemeConfig.currentTheme.outlineDark,
    outlineVariant = ThemeConfig.currentTheme.outlineVariantDark,
    scrim = ThemeConfig.currentTheme.scrimDark,
    inverseSurface = ThemeConfig.currentTheme.inverseSurfaceDark,
    inverseOnSurface = ThemeConfig.currentTheme.inverseOnSurfaceDark,
    inversePrimary = ThemeConfig.currentTheme.inversePrimaryDark,
    surfaceDim = ThemeConfig.currentTheme.surfaceDimDark,
    surfaceBright = ThemeConfig.currentTheme.surfaceBrightDark,
    surfaceContainerLowest = ThemeConfig.currentTheme.surfaceContainerLowestDark,
    surfaceContainerLow = ThemeConfig.currentTheme.surfaceContainerLowDark,
    surfaceContainer = ThemeConfig.currentTheme.surfaceContainerDark,
    surfaceContainerHigh = ThemeConfig.currentTheme.surfaceContainerHighDark,
    surfaceContainerHighest = ThemeConfig.currentTheme.surfaceContainerHighestDark,
)

@Composable
private fun createLightColorScheme() = lightColorScheme(
    primary = ThemeConfig.currentTheme.primaryLight,
    onPrimary = ThemeConfig.currentTheme.onPrimaryLight,
    primaryContainer = ThemeConfig.currentTheme.primaryContainerLight,
    onPrimaryContainer = ThemeConfig.currentTheme.onPrimaryContainerLight,
    secondary = ThemeConfig.currentTheme.secondaryLight,
    onSecondary = ThemeConfig.currentTheme.onSecondaryLight,
    secondaryContainer = ThemeConfig.currentTheme.secondaryContainerLight,
    onSecondaryContainer = ThemeConfig.currentTheme.onSecondaryContainerLight,
    tertiary = ThemeConfig.currentTheme.tertiaryLight,
    onTertiary = ThemeConfig.currentTheme.onTertiaryLight,
    tertiaryContainer = ThemeConfig.currentTheme.tertiaryContainerLight,
    onTertiaryContainer = ThemeConfig.currentTheme.onTertiaryContainerLight,
    error = ThemeConfig.currentTheme.errorLight,
    onError = ThemeConfig.currentTheme.onErrorLight,
    errorContainer = ThemeConfig.currentTheme.errorContainerLight,
    onErrorContainer = ThemeConfig.currentTheme.onErrorContainerLight,
    background = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else ThemeConfig.currentTheme.backgroundLight,
    onBackground = ThemeConfig.currentTheme.onBackgroundLight,
    surface = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else ThemeConfig.currentTheme.surfaceLight,
    onSurface = ThemeConfig.currentTheme.onSurfaceLight,
    surfaceVariant = ThemeConfig.currentTheme.surfaceVariantLight,
    onSurfaceVariant = ThemeConfig.currentTheme.onSurfaceVariantLight,
    outline = ThemeConfig.currentTheme.outlineLight,
    outlineVariant = ThemeConfig.currentTheme.outlineVariantLight,
    scrim = ThemeConfig.currentTheme.scrimLight,
    inverseSurface = ThemeConfig.currentTheme.inverseSurfaceLight,
    inverseOnSurface = ThemeConfig.currentTheme.inverseOnSurfaceLight,
    inversePrimary = ThemeConfig.currentTheme.inversePrimaryLight,
    surfaceDim = ThemeConfig.currentTheme.surfaceDimLight,
    surfaceBright = ThemeConfig.currentTheme.surfaceBrightLight,
    surfaceContainerLowest = ThemeConfig.currentTheme.surfaceContainerLowestLight,
    surfaceContainerLow = ThemeConfig.currentTheme.surfaceContainerLowLight,
    surfaceContainer = ThemeConfig.currentTheme.surfaceContainerLight,
    surfaceContainerHigh = ThemeConfig.currentTheme.surfaceContainerHighLight,
    surfaceContainerHighest = ThemeConfig.currentTheme.surfaceContainerHighestLight,
)

// 向后兼容
@OptIn(DelicateCoroutinesApi::class)
fun Context.saveAndApplyCustomBackground(uri: Uri, transformation: BackgroundTransformation? = null) {
    kotlinx.coroutines.GlobalScope.launch {
        BackgroundManager.saveAndApplyCustomBackground(this@saveAndApplyCustomBackground, uri, transformation)
    }
}

fun Context.saveCustomBackground(uri: Uri?) {
    if (uri != null) {
        saveAndApplyCustomBackground(uri)
    } else {
        BackgroundManager.clearCustomBackground(this)
    }
}

fun Context.saveThemeMode(forceDark: Boolean?) {
    ThemeManager.saveThemeMode(this, forceDark)
}


fun Context.saveThemeColors(themeName: String) {
    ThemeManager.saveThemeColors(this, themeName)
}


fun Context.saveDynamicColorState(enabled: Boolean) {
    ThemeManager.saveDynamicColorState(this, enabled)
}