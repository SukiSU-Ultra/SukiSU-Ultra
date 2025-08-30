package com.sukisu.ultra.ui.component

import android.net.Uri
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Fullscreen
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Size
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
import com.sukisu.ultra.ui.util.BackgroundTransformation
import com.sukisu.ultra.ui.util.saveTransformedBackground
import kotlinx.coroutines.launch
import kotlin.math.max

@Composable
fun ImageEditorDialog(
    imageUri: Uri,
    onDismiss: () -> Unit,
    onConfirm: (Uri) -> Unit
) {
    var scale by remember { mutableFloatStateOf(1f) }
    var offsetX by remember { mutableFloatStateOf(0f) }
    var offsetY by remember { mutableFloatStateOf(0f) }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var lastScale by remember { mutableFloatStateOf(1f) }
    var lastOffsetX by remember { mutableFloatStateOf(0f) }
    var lastOffsetY by remember { mutableFloatStateOf(0f) }
    var imageSize by remember { mutableStateOf(Size.Zero) }
    var screenSize by remember { mutableStateOf(Size.Zero) }
    val animatedScale by animateFloatAsState(
        targetValue = scale,
        label = "ScaleAnimation"
    )
    val animatedOffsetX by animateFloatAsState(
        targetValue = offsetX,
        label = "OffsetXAnimation"
    )
    val animatedOffsetY by animateFloatAsState(
        targetValue = offsetY,
        label = "OffsetYAnimation"
    )
    val updateTransformation = remember {
        { newScale: Float, newOffsetX: Float, newOffsetY: Float ->
            val scaleDiff = kotlin.math.abs(newScale - lastScale)
            val offsetXDiff = kotlin.math.abs(newOffsetX - lastOffsetX)
            val offsetYDiff = kotlin.math.abs(newOffsetY - lastOffsetY)
            if (scaleDiff > 0.01f || offsetXDiff > 1f || offsetYDiff > 1f) {
                scale = newScale
                offsetX = newOffsetX
                offsetY = newOffsetY
                lastScale = newScale
                lastOffsetX = newOffsetX
                lastOffsetY = newOffsetY
            }
        }
    }
    val scaleToFullScreen = remember {
        {
            if (imageSize.height > 0 && screenSize.height > 0) {
                val newScale = screenSize.height / imageSize.height
                updateTransformation(newScale, 0f, 0f)
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
                .background(Color.Black.copy(alpha = 0.9f))
                .onSizeChanged { size ->
                    screenSize = Size(size.width.toFloat(), size.height.toFloat())
                }
        ) {
            AsyncImage(
                model = ImageRequest.Builder(LocalContext.current)
                    .data(imageUri)
                    .crossfade(true)
                    .build(),
                contentDescription = stringResource(R.string.settings_custom_background),
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
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
                                    val newScale = (scale * zoom).coerceIn(0.5f, 3f)
                                    val maxOffsetX = max(0f, size.width * (newScale - 1) / 2)
                                    val maxOffsetY = max(0f, size.height * (newScale - 1) / 2)
                                    val newOffsetX = if (maxOffsetX > 0) {
                                        (offsetX + pan.x).coerceIn(-maxOffsetX, maxOffsetX)
                                    } else {
                                        0f
                                    }
                                    val newOffsetY = if (maxOffsetY > 0) {
                                        (offsetY + pan.y).coerceIn(-maxOffsetY, maxOffsetY)
                                    } else {
                                        0f
                                    }
                                    updateTransformation(newScale, newOffsetX, newOffsetY)
                                } catch (_: Exception) {
                                    updateTransformation(lastScale, lastOffsetX, lastOffsetY)
                                }
                            }
                        }
                    }
                    .onSizeChanged { size ->
                        imageSize = Size(size.width.toFloat(), size.height.toFloat())
                    }
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .align(Alignment.TopCenter),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(Color.Black.copy(alpha = 0.6f))
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = stringResource(R.string.cancel),
                        tint = Color.White
                    )
                }
                IconButton(
                    onClick = { scaleToFullScreen() },
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(Color.Black.copy(alpha = 0.6f))
                ) {
                    Icon(
                        imageVector = Icons.Default.Fullscreen,
                        contentDescription = stringResource(R.string.reprovision),
                        tint = Color.White
                    )
                }
                IconButton(
                    onClick = {
                        scope.launch {
                            try {
                                val transformation = BackgroundTransformation(scale, offsetX, offsetY)
                                val savedUri = context.saveTransformedBackground(imageUri, transformation)
                                savedUri?.let { onConfirm(it) }
                            } catch (_: Exception) {
                                ""
                            }
                        }
                    },
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(Color.Black.copy(alpha = 0.6f))
                ) {
                    Icon(
                        imageVector = Icons.Default.Check,
                        contentDescription = stringResource(R.string.confirm),
                        tint = Color.White
                    )
                }
            }

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color.Black.copy(alpha = 0.6f))
                    .padding(16.dp)
                    .align(Alignment.BottomCenter)
            ) {
                Text(
                    text = stringResource(id = R.string.image_editor_hint),
                    color = Color.White,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
    }
}