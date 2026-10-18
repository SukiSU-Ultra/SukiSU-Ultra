package com.sukisu.ultra.ui.kernelFlash

import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.key
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.KeyEventBlocker
import com.sukisu.ultra.ui.kernelFlash.state.FlashState
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.FloatingActionButton
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.FileDownloads
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun KernelFlashMiuix(
    state: FlashState,
    actions: KernelFlashActions,
    logText: String,
    kpmPatchEnabled: Boolean,
    kpmUndoPatch: Boolean
) {
    val scrollState = rememberScrollState()

    BackHandler {
        actions.onBack()
    }

    KeyEventBlocker {
        it.key == Key.VolumeDown || it.key == Key.VolumeUp
    }

    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = stringResource(
                    when {
                        state.error.isNotEmpty() -> R.string.flash_failed
                        state.isCompleted -> R.string.flash_success
                        else -> R.string.kernel_flashing
                    }
                ),
                navigationIcon = {
                    IconButton(
                        modifier = Modifier.padding(start = 16.dp),
                        onClick = actions.onBack
                    ) {
                        val layoutDirection = LocalLayoutDirection.current
                        Icon(
                            modifier = Modifier.graphicsLayer {
                                if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                            },
                            imageVector = MiuixIcons.Back,
                            contentDescription = null,
                            tint = colorScheme.onBackground
                        )
                    }
                },
                actions = {
                    IconButton(
                        modifier = Modifier.padding(end = 16.dp),
                        onClick = { actions.onSaveLog(logText) }
                    ) {
                        Icon(
                            imageVector = MiuixIcons.FileDownloads,
                            contentDescription = stringResource(id = R.string.save_log),
                            tint = colorScheme.onBackground
                        )
                    }
                }
            )
        },
        floatingActionButton = {
            if (state.isCompleted) {
                FloatingActionButton(
                    onClick = actions.onReboot,
                    modifier = Modifier.padding(bottom = 20.dp, end = 20.dp)
                ) {
                    Icon(
                        Icons.Rounded.Refresh,
                        contentDescription = stringResource(id = R.string.reboot)
                    )
                }
            }
        },
        popupHost = { }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .scrollEndHaptic(),
        ) {
            FlashProgressIndicatorMiuix(state, kpmPatchEnabled, kpmUndoPatch)
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                colors = CardDefaults.defaultColors(color = colorScheme.surfaceContainer),
            ) {
                Box(modifier = Modifier.verticalScroll(scrollState)) {
                    LaunchedEffect(logText) {
                        scrollState.animateScrollTo(scrollState.maxValue)
                    }
                    Text(
                        modifier = Modifier.padding(16.dp),
                        text = logText,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        color = colorScheme.onSurfaceContainer
                    )
                }
            }
        }
    }
}

@Composable
private fun FlashProgressIndicatorMiuix(
    flashState: FlashState,
    kpmPatchEnabled: Boolean,
    kpmUndoPatch: Boolean
) {
    val statusColor = when {
        flashState.error.isNotEmpty() -> colorScheme.error
        flashState.isCompleted -> colorScheme.primary
        else -> colorScheme.primary
    }

    val progress = animateFloatAsState(
        targetValue = flashState.progress.coerceIn(0f, 1f),
        label = "FlashProgress"
    )

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = when {
                        flashState.error.isNotEmpty() -> stringResource(R.string.flash_failed)
                        flashState.isCompleted -> stringResource(R.string.flash_success)
                        else -> stringResource(R.string.flashing)
                    },
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Medium,
                    color = statusColor
                )

                when {
                    flashState.error.isNotEmpty() -> {
                        Icon(
                            imageVector = Icons.Default.Error,
                            contentDescription = null,
                            tint = colorScheme.error
                        )
                    }
                    flashState.isCompleted -> {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = colorScheme.primary
                        )
                    }
                }
            }

            if (kpmPatchEnabled || kpmUndoPatch) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = if (kpmUndoPatch) stringResource(R.string.kpm_undo_patch_mode)
                    else stringResource(R.string.kpm_patch_mode),
                    fontSize = 14.sp,
                    color = colorScheme.onSurfaceVariantSummary
                )
            }

            if (flashState.currentStep.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = flashState.currentStep,
                    fontSize = 14.sp,
                    color = colorScheme.onSurfaceVariantSummary
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            LinearProgressIndicator(
                progress = progress.value,
                modifier = Modifier.fillMaxWidth()
            )

            if (flashState.error.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = flashState.error,
                    fontSize = 14.sp,
                    color = colorScheme.onErrorContainer,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(colorScheme.errorContainer)
                        .padding(12.dp)
                )
            }
        }
    }
}
