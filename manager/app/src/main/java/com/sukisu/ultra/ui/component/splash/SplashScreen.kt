package com.sukisu.ultra.ui.component.splash

import android.content.Context
import android.content.res.Configuration
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toBitmap
import com.sukisu.ultra.R
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.theme.MiuixTheme

private const val ICON_SIZE_PX = 256
private const val EXIT_DURATION_MS = 360


@Composable
fun SplashScreen(
    isReady: Boolean,
    minDurationMs: Long = 850L,
    onDismissed: () -> Unit = {},
) {
    var contentVisible by remember { mutableStateOf(false) }
    var exitTriggered by remember { mutableStateOf(false) }
    var splashDismissed by remember { mutableStateOf(false) }
    val currentOnDismissed by rememberUpdatedState(onDismissed)

    val isDark = MiuixTheme.colorScheme.background.luminance() < 0.5f

    val context = LocalContext.current
    val appIconBitmap = remember(context, isDark) {
        loadAppIcon(context.withNightMode(isDark))
    }

    val logoScale = remember { Animatable(0.72f) }
    val logoAlpha = remember { Animatable(0f) }

    LaunchedEffect(Unit) {
        contentVisible = true
        launch { logoAlpha.animateTo(1f, tween(320, easing = FastOutSlowInEasing)) }
        launch {
            logoScale.animateTo(
                targetValue = 1f,
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioLowBouncy,
                    stiffness = Spring.StiffnessLow,
                ),
            )
        }
    }

    LaunchedEffect(isReady) {
        if (isReady) {
            delay(minDurationMs)
            exitTriggered = true
            delay(EXIT_DURATION_MS.toLong() + 20L)
            splashDismissed = true
            currentOnDismissed()
        }
    }

    if (splashDismissed) return

    AnimatedVisibility(
        visible = !exitTriggered,
        enter = fadeIn(tween(180)),
        exit = fadeOut(tween(EXIT_DURATION_MS, easing = FastOutSlowInEasing)) +
            scaleOut(
                targetScale = 1.05f,
                animationSpec = tween(EXIT_DURATION_MS, easing = FastOutSlowInEasing),
            ),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MiuixTheme.colorScheme.background)
                .pointerInput(Unit) {}
                .statusBarsPadding()
                .navigationBarsPadding(),
            contentAlignment = Alignment.Center,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(vertical = 36.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.SpaceBetween,
            ) {
                // Top placeholder to balance the column layout
                Spacer(modifier = Modifier.height(16.dp))

                // Center Branding
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Box(
                        modifier = Modifier
                            .graphicsLayer {
                                scaleX = logoScale.value
                                scaleY = logoScale.value
                                alpha = logoAlpha.value
                            }
                            .size(88.dp)
                            .shadow(12.dp, shape = RoundedCornerShape(24.dp), clip = false)
                            .clip(RoundedCornerShape(24.dp))
                            .background(MiuixTheme.colorScheme.surface),
                        contentAlignment = Alignment.Center,
                    ) {
                        appIconBitmap?.let { bitmap ->
                            Image(
                                bitmap = bitmap,
                                contentDescription = stringResource(id = R.string.app_name),
                                modifier = Modifier
                                    .size(76.dp)
                                    .clip(RoundedCornerShape(20.dp)),
                                contentScale = ContentScale.Crop,
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(18.dp))

                    AnimatedVisibility(
                        visible = contentVisible,
                        enter = fadeIn(tween(400, delayMillis = 180, easing = FastOutSlowInEasing)),
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                text = stringResource(id = R.string.app_name),
                                color = MiuixTheme.colorScheme.onBackground,
                                fontSize = 22.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = (-0.3).sp,
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "Kernel-based Root Solution",
                                color = MiuixTheme.colorScheme.onBackground.copy(alpha = 0.55f),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium,
                            )
                        }
                    }
                }

                // Bottom Footer
                AnimatedVisibility(
                    visible = contentVisible,
                    enter = fadeIn(tween(450, delayMillis = 260, easing = FastOutSlowInEasing)),
                ) {
                    Text(
                        text = "What you like, you permit; what you permit, you govern.",
                        color = MiuixTheme.colorScheme.onBackground.copy(alpha = 0.35f),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium,
                    )
                }
            }
        }
    }
}

private fun Context.withNightMode(isDark: Boolean): Context {
    val config = Configuration(resources.configuration)
    val nightFlag = if (isDark) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO
    config.uiMode = (config.uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or nightFlag
    return createConfigurationContext(config)
}

private fun loadAppIcon(themedContext: Context): ImageBitmap? =
    listOf(R.mipmap.ic_launcher, R.drawable.ic_launcher_foreground).firstNotNullOfOrNull { resId ->
        runCatching {
            ContextCompat.getDrawable(themedContext, resId)
                ?.toBitmap(width = ICON_SIZE_PX, height = ICON_SIZE_PX)
                ?.asImageBitmap()
        }.getOrNull()
    }