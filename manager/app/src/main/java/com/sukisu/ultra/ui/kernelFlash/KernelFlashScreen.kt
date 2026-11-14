package com.sukisu.ultra.ui.kernelFlash

import android.content.Intent
import android.net.Uri
import android.os.Environment
import androidx.activity.compose.LocalActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.kernelFlash.state.HorizonKernelState
import com.sukisu.ultra.ui.kernelFlash.state.HorizonKernelWorker
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.util.reboot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlin.time.Duration.Companion.milliseconds

@Composable
fun KernelFlashScreen(
    kernelUri: Uri,
    selectedSlot: String? = null,
    kpmPatchEnabled: Boolean = false,
    kpmUndoPatch: Boolean = false
) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val resources = LocalResources.current
    val scope = rememberCoroutineScope()
    val activity = LocalActivity.current

    val horizonKernelState = remember(kernelUri, selectedSlot, kpmPatchEnabled, kpmUndoPatch) {
        if (KernelFlashStateHolder.currentState != null &&
            KernelFlashStateHolder.currentUri == kernelUri &&
            KernelFlashStateHolder.currentSlot == selectedSlot &&
            KernelFlashStateHolder.currentKpmPatchEnabled == kpmPatchEnabled &&
            KernelFlashStateHolder.currentKpmUndoPatch == kpmUndoPatch) {
            KernelFlashStateHolder.currentState!!
        } else {
            HorizonKernelState().also {
                KernelFlashStateHolder.currentState = it
                KernelFlashStateHolder.currentUri = kernelUri
                KernelFlashStateHolder.currentSlot = selectedSlot
                KernelFlashStateHolder.currentKpmPatchEnabled = kpmPatchEnabled
                KernelFlashStateHolder.currentKpmUndoPatch = kpmUndoPatch
            }
        }
    }

    val flashState by horizonKernelState.state.collectAsStateWithLifecycle()

    val flashComplete = stringResource(R.string.horizon_flash_complete)

    val logText = remember(flashState.logs, flashState.error, flashState.isCompleted, flashComplete) {
        buildString {
            append(flashState.logs.joinToString("\n"))
            if (flashState.error.isNotEmpty()) {
                append("\n${flashState.error}\n")
            } else if (flashState.isCompleted) {
                append("\n$flashComplete\n")
            }
        }
    }

    LaunchedEffect(flashState.isCompleted, flashState.error) {
        if (flashState.isCompleted && flashState.error.isEmpty()) {
            val intent = activity?.intent
            val isFromExternalIntent = intent?.action?.let { action ->
                action == Intent.ACTION_VIEW ||
                action == Intent.ACTION_SEND ||
                action == Intent.ACTION_SEND_MULTIPLE
            } ?: false

            if (isFromExternalIntent) {
                delay(1500.milliseconds)
                KernelFlashStateHolder.clear()
                activity.finish()
            }
        }
    }

    LaunchedEffect(horizonKernelState) {
        if (horizonKernelState.tryStartFlashing()) {
            try {
                HorizonKernelWorker(
                    context = context.applicationContext,
                    state = horizonKernelState,
                    uri = kernelUri,
                    slot = selectedSlot,
                    kpmPatchEnabled = kpmPatchEnabled,
                    kpmUndoPatch = kpmUndoPatch
                ).start()
            } catch (e: Exception) {
                horizonKernelState.setError(e.message ?: resources.getString(R.string.horizon_unknown_error))
            }
        }
    }

    val actions = KernelFlashActions(
        onBack = {
            if (!horizonKernelState.state.value.isFlashing) {
                if (flashState.isCompleted || flashState.error.isNotEmpty()) {
                    KernelFlashStateHolder.clear()
                }
                navigator.pop()
            }
        },
        onSaveLog = { logContentValue ->
            scope.launch(Dispatchers.IO) {
                val format = SimpleDateFormat("yyyy-MM-dd-HH-mm-ss", Locale.getDefault())
                val date = format.format(Date())
                val file = File(
                    Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                    "SukiSU_kernel_flash_log_${date}.log"
                )
                file.writeText(logContentValue)
            }
        },
        onReboot = {
            scope.launch {
                withContext(Dispatchers.IO) {
                    reboot()
                }
            }
        }
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> KernelFlashMiuix(
            state = flashState,
            actions = actions,
            logText = logText,
            kpmPatchEnabled = kpmPatchEnabled,
            kpmUndoPatch = kpmUndoPatch
        )

        UiMode.Material -> KernelFlashMaterial(
            state = flashState,
            actions = actions,
            logText = logText,
            kpmPatchEnabled = kpmPatchEnabled,
            kpmUndoPatch = kpmUndoPatch
        )
    }
}
