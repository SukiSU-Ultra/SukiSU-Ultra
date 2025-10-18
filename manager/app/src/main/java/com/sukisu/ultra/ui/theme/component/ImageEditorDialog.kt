package com.sukisu.ultra.ui.theme.component

import android.net.Uri
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Fullscreen
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import coil.compose.AsyncImage
import coil.request.ImageRequest
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.theme.util.BackgroundTransformation
import com.sukisu.ultra.ui.theme.util.saveTransformedBackground
import kotlinx.coroutines.launch
import kotlin.math.abs
import kotlin.math.max

@Composable
fun ImageEditorDialog(
    imageUri: Uri,
    onDismiss: () -> Unit,
    onConfirm: (Uri) -> Unit
) {
    // 图像变换状态
    val transformState = remember { ImageTransformState() }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // 尺寸状态
    var imageSize by remember { mutableStateOf(Size.Zero) }
    var screenSize by remember { mutableStateOf(Size.Zero) }

    // 动画状态
    val animationSpec = spring<Float>(
        dampingRatio = Spring.DampingRatioMediumBouncy,
        stiffness = Spring.StiffnessMedium
    )

    val animatedScale by animateFloatAsState(
        targetValue = transformState.scale,
        animationSpec = animationSpec,
        label = "ScaleAnimation"
    )

    val animatedOffsetX by animateFloatAsState(
        targetValue = transformState.offsetX,
        animationSpec = animationSpec,
        label = "OffsetXAnimation"
    )

    val animatedOffsetY by animateFloatAsState(
        targetValue = transformState.offsetY,
        animationSpec = animationSpec,
        label = "OffsetYAnimation"
    )

    // 工具函数
    val scaleToFullScreen = remember {
        {
            if (imageSize.height > 0 && screenSize.height > 0) {
                val newScale = screenSize.height / imageSize.height
                transformState.updateTransform(newScale, 0f, 0f)
            }
        }
    }

    val saveImage: () -> Unit = remember {
        {
            scope.launch {
                try {
                    val transformation = BackgroundTransformation(
                        transformState.scale,
                        transformState.offsetX,
                        transformState.offsetY
                    )
                    val savedUri = context.saveTransformedBackground(imageUri, transformation)
                    savedUri?.let { onConfirm(it) }
                } catch (_: Exception) {
                }
            }
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            dismissOnBackPress = true,
            dismissOnClickOutside = false,
            usePlatformDefaultWidth = false
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            Color.Black.copy(alpha = 0.9f),
                            Color.Black.copy(alpha = 0.95f)
                        ),
                        radius = 800f
                    )
                )
                .onSizeChanged { size ->
                    screenSize = Size(size.width.toFloat(), size.height.toFloat())
                }
        ) {
            // 图像显示区域
            ImageDisplayArea(
                imageUri = imageUri,
                animatedScale = animatedScale,
                animatedOffsetX = animatedOffsetX,
                animatedOffsetY = animatedOffsetY,
                transformState = transformState,
                onImageSizeChanged = { imageSize = it },
                modifier = Modifier.fillMaxSize()
            )

            // 顶部工具栏
            TopToolbar(
                onDismiss = onDismiss,
                onFullscreen = scaleToFullScreen,
                onConfirm = saveImage,
                modifier = Modifier.align(Alignment.TopCenter)
            )

            // 底部提示信息
            BottomHintCard(
                modifier = Modifier.align(Alignment.BottomCenter)
            )
        }
    }
}

/**
 * 图像变换状态管理类
 */
private class ImageTransformState {
    var scale by mutableFloatStateOf(1f)
    var offsetX by mutableFloatStateOf(0f)
    var offsetY by mutableFloatStateOf(0f)

    private var lastScale = 1f
    private var lastOffsetX = 0f
    private var lastOffsetY = 0f

    fun updateTransform(newScale: Float, newOffsetX: Float, newOffsetY: Float) {
        val scaleDiff = abs(newScale - lastScale)
        val offsetXDiff = abs(newOffsetX - lastOffsetX)
        val offsetYDiff = abs(newOffsetY - lastOffsetY)

        if (scaleDiff > 0.01f || offsetXDiff > 1f || offsetYDiff > 1f) {
            scale = newScale
            offsetX = newOffsetX
            offsetY = newOffsetY
            lastScale = newScale
            lastOffsetX = newOffsetX
            lastOffsetY = newOffsetY
        }
    }

    fun resetToLast() {
        scale = lastScale
        offsetX = lastOffsetX
        offsetY = lastOffsetY
    }
}

/**
 * 图像显示区域组件
 */
@Composable
private fun ImageDisplayArea(
    imageUri: Uri,
    animatedScale: Float,
    animatedOffsetX: Float,
    animatedOffsetY: Float,
    transformState: ImageTransformState,
    onImageSizeChanged: (Size) -> Unit,
    modifier: Modifier = Modifier
) {
    val scope = rememberCoroutineScope()

    AsyncImage(
        model = ImageRequest.Builder(LocalContext.current)
            .data(imageUri)
            .crossfade(true)
            .build(),
        contentDescription = stringResource(R.string.settings_custom_background),
        contentScale = ContentScale.Fit,
        modifier = modifier
            .graphicsLayer(
                scaleX = animatedScale,
                scaleY = animatedScale,
                translationX = animatedOffsetX,
                translationY = animatedOffsetY
            )
            .pointerInput(Unit) {
                detectTransformGestures { _, pan, zoom, _ ->
                    scope.launch {
                        try {
                            val newScale = (transformState.scale * zoom).coerceIn(0.5f, 3f)
                            val maxOffsetX = max(0f, size.width * (newScale - 1) / 2)
                            val maxOffsetY = max(0f, size.height * (newScale - 1) / 2)

                            val newOffsetX = if (maxOffsetX > 0) {
                                (transformState.offsetX + pan.x).coerceIn(-maxOffsetX, maxOffsetX)
                            } else 0f

                            val newOffsetY = if (maxOffsetY > 0) {
                                (transformState.offsetY + pan.y).coerceIn(-maxOffsetY, maxOffsetY)
                            } else 0f

                            transformState.updateTransform(newScale, newOffsetX, newOffsetY)
                        } catch (_: Exception) {
                            transformState.resetToLast()
                        }
                    }
                }
            }
            .onSizeChanged { size ->
                onImageSizeChanged(Size(size.width.toFloat(), size.height.toFloat()))
            }
    )
}

/**
 * 顶部工具栏组件
 */
@Composable
private fun TopToolbar(
    onDismiss: () -> Unit,
    onFullscreen: () -> Unit,
    onConfirm: () -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(24.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        // 关闭按钮
        ActionButton(
            onClick = onDismiss,
            icon = Icons.Default.Close,
            contentDescription = stringResource(R.string.cancel),
            backgroundColor = MaterialTheme.colorScheme.error.copy(alpha = 0.9f)
        )

        // 全屏按钮
        ActionButton(
            onClick = onFullscreen,
            icon = Icons.Default.Fullscreen,
            contentDescription = stringResource(R.string.reprovision),
            backgroundColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.9f)
        )

        // 确认按钮
        ActionButton(
            onClick = onConfirm,
            icon = Icons.Default.Check,
            contentDescription = stringResource(R.string.confirm),
            backgroundColor = Color(0xFF4CAF50).copy(alpha = 0.9f)
        )
    }
}

/**
 * 操作按钮组件
 */
@Composable
private fun ActionButton(
    onClick: () -> Unit,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    contentDescription: String,
    backgroundColor: Color,
    modifier: Modifier = Modifier
) {
    var isPressed by remember { mutableStateOf(false) }

    val buttonScale by animateFloatAsState(
        targetValue = if (isPressed) 0.85f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessHigh
        ),
        label = "ButtonScale"
    )

    val buttonAlpha by animateFloatAsState(
        targetValue = if (isPressed) 0.8f else 1f,
        animationSpec = tween(100),
        label = "ButtonAlpha"
    )

    Surface(
        onClick = {
            isPressed = true
            onClick()
        },
        modifier = modifier
            .size(64.dp)
            .graphicsLayer(
                scaleX = buttonScale,
                scaleY = buttonScale,
                alpha = buttonAlpha
            ),
        shape = CircleShape,
        color = backgroundColor,
        shadowElevation = 8.dp
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.fillMaxSize()
        ) {
            Icon(
                imageVector = icon,
                contentDescription = contentDescription,
                tint = Color.White,
                modifier = Modifier.size(28.dp)
            )
        }
    }

    LaunchedEffect(isPressed) {
        if (isPressed) {
            kotlinx.coroutines.delay(150)
            isPressed = false
        }
    }
}

/**
 * 底部提示卡片组件
 */
@Composable
private fun BottomHintCard(
    modifier: Modifier = Modifier
) {
    var isVisible by remember { mutableStateOf(true) }

    val cardAlpha by animateFloatAsState(
        targetValue = if (isVisible) 1f else 0f,
        animationSpec = tween(
            durationMillis = 500,
            easing = EaseInOutCubic
        ),
        label = "HintAlpha"
    )

    val cardTranslationY by animateFloatAsState(
        targetValue = if (isVisible) 0f else 100f,
        animationSpec = tween(
            durationMillis = 500,
            easing = EaseInOutCubic
        ),
        label = "HintTranslation"
    )

    LaunchedEffect(Unit) {
        kotlinx.coroutines.delay(4000)
        isVisible = false
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(24.dp)
            .alpha(cardAlpha)
            .graphicsLayer {
                translationY = cardTranslationY
            },
        colors = CardDefaults.cardColors(
            containerColor = Color.Black.copy(alpha = 0.85f)
        ),
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 12.dp)
    ) {
        Text(
            text = stringResource(id = R.string.image_editor_hint),
            color = Color.White,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier
                .padding(20.dp)
                .fillMaxWidth()
        )
    }
}
