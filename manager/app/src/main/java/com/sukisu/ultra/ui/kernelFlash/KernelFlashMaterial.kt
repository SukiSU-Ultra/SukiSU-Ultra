package com.sukisu.ultra.ui.kernelFlash

import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import androidx.compose.material3.contentColorFor
import androidx.compose.material3.Surface
import androidx.compose.material3.SmallExtendedFloatingActionButton
import androidx.compose.material3.LinearWavyProgressIndicator
import androidx.compose.material.icons.filled.Save
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.key
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.KeyEventBlocker
import com.sukisu.ultra.ui.kernelFlash.state.FlashState

@Composable
fun KernelFlashMaterial(
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

    DisposableEffect(Unit) {
        onDispose {
            if (state.isCompleted || state.error.isNotEmpty()) {
                KernelFlashStateHolder.clear()
            }
        }
    }

    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(
                            when {
                                state.error.isNotEmpty() -> R.string.flash_failed
                                state.isCompleted -> R.string.flash_success
                                else -> R.string.kernel_flashing
                            }
                        )
                    )
                },
                navigationIcon = {
                    TopBarBackButton(onClick = actions.onBack)
                },
                actions = {
                    IconButton(
                        onClick = { actions.onSaveLog(logText) }
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Save,
                            contentDescription = stringResource(id = R.string.save_log)
                        )
                    }
                },
                colors = expressiveTopAppBarColors()
            )
        },
        floatingActionButton = {
            if (state.isCompleted) {
                SmallExtendedFloatingActionButton(
                    onClick = actions.onReboot,
                    icon = { Icon(Icons.Filled.Refresh, null) },
                    text = { Text(stringResource(id = R.string.reboot)) },
                )
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            FlashProgressIndicatorMaterial(state, kpmPatchEnabled, kpmUndoPatch)
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                shape = MaterialTheme.shapes.large,
                color = MaterialTheme.colorScheme.surfaceContainerLowest,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            ) {
                Box(modifier = Modifier.verticalScroll(scrollState)) {
                    LaunchedEffect(logText) {
                        scrollState.animateScrollTo(scrollState.maxValue)
                    }
                    Text(
                        modifier = Modifier.padding(16.dp),
                        text = logText,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}

@Composable
private fun FlashProgressIndicatorMaterial(
    flashState: FlashState,
    kpmPatchEnabled: Boolean,
    kpmUndoPatch: Boolean
) {
    val failed = flashState.error.isNotEmpty()
    val containerColor = when {
        failed -> MaterialTheme.colorScheme.errorContainer
        flashState.isCompleted -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.surfaceBright
    }
    val contentColor = MaterialTheme.colorScheme.contentColorFor(containerColor)

    val progress = animateFloatAsState(
        targetValue = flashState.progress.coerceIn(0f, 1f),
        label = "FlashProgress"
    )

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        shape = MaterialTheme.shapes.large,
        color = containerColor,
        contentColor = contentColor,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = when {
                        failed -> stringResource(R.string.flash_failed)
                        flashState.isCompleted -> stringResource(R.string.flash_success)
                        else -> stringResource(R.string.flashing)
                    },
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Black,
                )

                when {
                    failed -> Icon(imageVector = Icons.Default.Error, contentDescription = null)
                    flashState.isCompleted -> Icon(imageVector = Icons.Default.CheckCircle, contentDescription = null)
                }
            }

            if (kpmPatchEnabled || kpmUndoPatch) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = if (kpmUndoPatch) stringResource(R.string.kpm_undo_patch_mode)
                    else stringResource(R.string.kpm_patch_mode),
                    style = MaterialTheme.typography.bodyMedium,
                    color = contentColor.copy(alpha = 0.75f)
                )
            }

            if (flashState.currentStep.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = flashState.currentStep,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = contentColor.copy(alpha = 0.75f)
                )
            }

            Spacer(modifier = Modifier.height(14.dp))

            LinearWavyProgressIndicator(
                progress = { progress.value },
                modifier = Modifier.fillMaxWidth(),
                color = if (flashState.isCompleted) contentColor else MaterialTheme.colorScheme.primary,
                trackColor = contentColor.copy(alpha = 0.2f)
            )

            if (flashState.error.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = flashState.error,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onError,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            MaterialTheme.colorScheme.error,
                            MaterialTheme.shapes.small
                        )
                        .padding(12.dp)
                )
            }
        }
    }
}
