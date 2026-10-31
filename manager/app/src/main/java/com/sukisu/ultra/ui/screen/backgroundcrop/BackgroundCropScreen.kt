package com.sukisu.ultra.ui.screen.backgroundcrop

import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.graphics.Bitmap
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.util.ImageStorage
import com.sukisu.ultra.ui.util.ExternalCropper
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

enum class BackgroundCropRatio {
    SCREEN,
    SQUARE,
    PORTRAIT_THREE_FOUR,
    LANDSCAPE_FOUR_THREE,
    PORTRAIT_NINE_SIXTEEN,
    LANDSCAPE_SIXTEEN_NINE,
}

fun BackgroundCropRatio.aspectPair(screenWidth: Int, screenHeight: Int): Pair<Int, Int> = when (this) {
    BackgroundCropRatio.SCREEN -> screenWidth.coerceAtLeast(1) to screenHeight.coerceAtLeast(1)
    BackgroundCropRatio.SQUARE -> 1 to 1
    BackgroundCropRatio.PORTRAIT_THREE_FOUR -> 3 to 4
    BackgroundCropRatio.LANDSCAPE_FOUR_THREE -> 4 to 3
    BackgroundCropRatio.PORTRAIT_NINE_SIXTEEN -> 9 to 16
    BackgroundCropRatio.LANDSCAPE_SIXTEEN_NINE -> 16 to 9
}

@Composable
fun BackgroundCropRatio.label(): String = when (this) {
    BackgroundCropRatio.SCREEN -> stringResource(R.string.background_crop_ratio_screen)
    BackgroundCropRatio.SQUARE -> "1:1"
    BackgroundCropRatio.PORTRAIT_THREE_FOUR -> "3:4"
    BackgroundCropRatio.LANDSCAPE_FOUR_THREE -> "4:3"
    BackgroundCropRatio.PORTRAIT_NINE_SIXTEEN -> "9:16"
    BackgroundCropRatio.LANDSCAPE_SIXTEEN_NINE -> "16:9"
}

data class BackgroundCropUiState(
    val bitmap: Bitmap?,
    val loading: Boolean,
    val saving: Boolean,
    val selectedRatio: BackgroundCropRatio,
    val aspectRatio: Float,
    val galleryCropAvailable: Boolean,
    val isHomeCardCrop: Boolean,
)

/** Matches the minimum height in the home status card. */
private const val HOME_CARD_MIN_HEIGHT_DP = 188f

/** Miuix home page uses 12dp horizontal padding on each side. */
private const val MIUIX_HOME_CARD_HORIZONTAL_MARGIN_DP = 24f

/** Material home page uses 16dp horizontal padding on each side. */
private const val MATERIAL_HOME_CARD_HORIZONTAL_MARGIN_DP = 32f

data class BackgroundCropActions(
    val onClose: () -> Unit,
    val onConfirm: () -> Unit,
    val onUseOriginal: () -> Unit,
    val onCropWithGallery: () -> Unit,
    val onSelectRatio: (BackgroundCropRatio) -> Unit,
    val onRotate: () -> Unit,
    val onReset: () -> Unit,
)

@Composable
fun BackgroundCropScreen(sourcePath: String, forHomeCard: Boolean = false) {
    val context = LocalContext.current
    val navigator = LocalNavigator.current
    val viewModel = viewModel<SettingsViewModel>()
    val scope = rememberCoroutineScope()
    val controller = rememberCropController()
    val windowSize = LocalWindowInfo.current.containerSize
    val configuration = LocalConfiguration.current
    val density = LocalDensity.current
    val uiMode = LocalUiMode.current

    val screenWidth = windowSize.width.takeIf { it > 0 }
        ?: configuration.screenWidthDp.takeIf { it > 0 }
        ?: 9
    val screenHeight = windowSize.height.takeIf { it > 0 }
        ?: configuration.screenHeightDp.takeIf { it > 0 }
        ?: 20

    var bitmap by remember(sourcePath) { mutableStateOf<Bitmap?>(null) }
    var loading by remember(sourcePath) { mutableStateOf(true) }
    var saving by remember { mutableStateOf(false) }
    var ratioName by rememberSaveable(sourcePath) {
        mutableStateOf(BackgroundCropRatio.SCREEN.name)
    }
    var pendingOutputPath by remember { mutableStateOf<String?>(null) }

    val selectedRatio = remember(ratioName) {
        runCatching { BackgroundCropRatio.valueOf(ratioName) }
            .getOrDefault(BackgroundCropRatio.SCREEN)
    }
    val (aspectX, aspectY) = selectedRatio.aspectPair(screenWidth, screenHeight)
    val backgroundAspect = aspectX.toFloat() / aspectY.toFloat()
    val homeCardHorizontalMarginDp = when (uiMode) {
        UiMode.Miuix -> MIUIX_HOME_CARD_HORIZONTAL_MARGIN_DP
        UiMode.Material -> MATERIAL_HOME_CARD_HORIZONTAL_MARGIN_DP
    }
    val homeCardAspect = remember(screenWidth, density.density, homeCardHorizontalMarginDp) {
        val widthDp = screenWidth / density.density
        ((widthDp - homeCardHorizontalMarginDp).coerceAtLeast(1f)) / HOME_CARD_MIN_HEIGHT_DP
    }
    val viewportAspect = if (forHomeCard) homeCardAspect else backgroundAspect
    val galleryCropAvailable = remember(context) { ExternalCropper.isAvailable(context) }
    val lowRam = remember(context) {
        (context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager)?.isLowRamDevice == true
    }

    BackHandler(enabled = saving) {}

    DisposableEffect(sourcePath) {
        onDispose { ImageStorage.discardStaged(sourcePath) }
    }

    LaunchedEffect(sourcePath) {
        val loaded = withContext(Dispatchers.IO) { loadCropSource(File(sourcePath), lowRam) }
        loading = false
        if (loaded == null) {
            Toast.makeText(context, R.string.background_crop_failed, Toast.LENGTH_SHORT).show()
            navigator.pop()
        } else {
            bitmap = loaded
        }
    }

    val applyCrop: suspend (File) -> Boolean = { output ->
        if (forHomeCard) {
            viewModel.finishHomeCardCrop(context, output, sourcePath)
        } else {
            viewModel.finishBackgroundCrop(context, output, sourcePath)
        }
    }

    val galleryLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val outputPath = pendingOutputPath
        pendingOutputPath = null
        if (outputPath == null) return@rememberLauncherForActivityResult

        val output = File(outputPath)
        val emptyOutput = !output.isFile || output.length() == 0L
        if (result.resultCode == Activity.RESULT_CANCELED && emptyOutput) {
            output.delete()
            return@rememberLauncherForActivityResult
        }

        saving = true
        scope.launch {
            val read = withContext(Dispatchers.IO) {
                ExternalCropper.readResult(context, result, output)
            }
            if (!read) {
                output.delete()
                Toast.makeText(
                    context,
                    R.string.background_crop_gallery_failed,
                    Toast.LENGTH_SHORT,
                ).show()
                saving = false
                return@launch
            }
            val applied = applyCrop(output)
            if (applied) {
                navigator.pop()
            } else {
                output.delete()
                Toast.makeText(context, R.string.background_crop_failed, Toast.LENGTH_SHORT).show()
                saving = false
            }
        }
    }

    fun finishWithOutput(output: File) {
        saving = true
        scope.launch {
            val applied = applyCrop(output)
            if (applied) {
                navigator.pop()
            } else {
                output.delete()
                Toast.makeText(context, R.string.background_crop_failed, Toast.LENGTH_SHORT).show()
                saving = false
            }
        }
    }

    val onConfirm: () -> Unit = {
        val current = bitmap
        val viewport = controller.viewportSize
        if (current != null && !saving && viewport.width > 0f && viewport.height > 0f) {
            saving = true
            val turns = controller.quarterTurns
            val transform = controller.transform
            scope.launch {
                val output = withContext(Dispatchers.IO) {
                    val cropped = renderCroppedBitmap(
                        source = current,
                        quarterTurns = turns,
                        transform = transform,
                        viewport = viewport,
                        lowRam = lowRam,
                    ) ?: return@withContext null
                    val file = ImageStorage.newCropOutput(context)
                    val saved = saveCropBitmap(cropped, file)
                    cropped.recycle()
                    if (saved) {
                        file
                    } else {
                        file.delete()
                        null
                    }
                }
                if (output == null) {
                    Toast.makeText(
                        context,
                        R.string.background_crop_failed,
                        Toast.LENGTH_SHORT,
                    ).show()
                    saving = false
                } else {
                    finishWithOutput(output)
                }
            }
        }
    }

    val onUseOriginal: () -> Unit = {
        if (!forHomeCard && !saving) {
            saving = true
            scope.launch {
                val applied = viewModel.applyOriginalBackground(context, sourcePath)
                if (applied) {
                    navigator.pop()
                } else {
                    Toast.makeText(
                        context,
                        R.string.background_crop_failed,
                        Toast.LENGTH_SHORT,
                    ).show()
                    saving = false
                }
            }
        }
    }

    val onCropWithGallery: () -> Unit = {
        if (!forHomeCard && !saving && galleryCropAvailable) {
            val output = ImageStorage.newCropOutput(context)
            val intent = ExternalCropper.createIntent(
                context = context,
                source = File(sourcePath),
                output = output,
                aspectX = aspectX,
                aspectY = aspectY,
            )
            if (intent == null) {
                output.delete()
                Toast.makeText(
                    context,
                    R.string.background_crop_gallery_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            } else {
                pendingOutputPath = output.absolutePath
                val started = runCatching { galleryLauncher.launch(intent) }.isSuccess
                if (!started) {
                    pendingOutputPath = null
                    output.delete()
                    Toast.makeText(
                        context,
                        R.string.background_crop_gallery_failed,
                        Toast.LENGTH_SHORT,
                    ).show()
                }
            }
        }
    }

    val onSelectRatio: (BackgroundCropRatio) -> Unit = { ratio ->
        if (!forHomeCard && !saving && ratio != selectedRatio) {
            ratioName = ratio.name
            controller.resetTransform()
        }
    }

    val state = BackgroundCropUiState(
        bitmap = bitmap,
        loading = loading,
        saving = saving,
        selectedRatio = selectedRatio,
        aspectRatio = viewportAspect,
        galleryCropAvailable = galleryCropAvailable && !forHomeCard,
        isHomeCardCrop = forHomeCard,
    )
    val actions = BackgroundCropActions(
        onClose = { if (!saving) navigator.pop() },
        onConfirm = onConfirm,
        onUseOriginal = onUseOriginal,
        onCropWithGallery = onCropWithGallery,
        onSelectRatio = onSelectRatio,
        onRotate = { if (!saving) controller.rotate() },
        onReset = {
            if (!saving) {
                if (!forHomeCard) {
                    ratioName = BackgroundCropRatio.SCREEN.name
                }
                controller.resetAll()
            }
        },
    )

    when (uiMode) {
        UiMode.Miuix -> BackgroundCropScreenMiuix(state, actions, controller)
        UiMode.Material -> BackgroundCropScreenMaterial(state, actions, controller)
    }
}
