package com.sukisu.ultra.ui.screen.extensions

import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.screen.settings.tools.CpuInfo
import com.sukisu.ultra.ui.screen.settings.tools.SpoofCpuDialogMaterial
import com.sukisu.ultra.ui.screen.settings.tools.SpoofCpuDialogMiuix
import com.sukisu.ultra.ui.screen.settings.tools.SpoofCpuParams
import com.sukisu.ultra.ui.screen.settings.tools.readCurrentCpuIdentity
import com.sukisu.ultra.ui.util.ExtensionId
import com.sukisu.ultra.ui.util.spoofCpu
import com.sukisu.ultra.ui.viewmodel.ExtensionsViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun ExtensionsScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val viewModel: ExtensionsViewModel = viewModel()
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LifecycleResumeEffect(Unit) {
        viewModel.refresh()
        onPauseOrDispose { }
    }

    var cpuDialogVisible by remember { mutableStateOf(false) }
    var cpuInfo by remember { mutableStateOf<CpuInfo?>(null) }

    val openCpuDialog: () -> Unit = {
        cpuDialogVisible = true
        if (cpuInfo == null) {
            scope.launch(Dispatchers.IO) {
                cpuInfo = readCurrentCpuIdentity()
            }
        }
    }

    val applySuccessMsg = stringResource(R.string.spoof_cpu_apply_success)
    val applyFailedMsg = stringResource(R.string.spoof_cpu_apply_failed)
    val configuration = LocalConfiguration.current
    val applyPartialMsg: (Int, Int) -> String = { ok, fail ->
        val resources = context.createConfigurationContext(configuration).resources
        resources.getString(R.string.spoof_cpu_apply_partial_failure, ok, fail)
    }
    val applyCpu: (SpoofCpuParams) -> Unit = { params ->
        scope.launch(Dispatchers.IO) {
            var ok = 0
            var fail = 0
            for (idx in params.cpuIndices) {
                if (spoofCpu(idx, params.midrHex, params.bogomips, params.hwcapHex, params.hwcap2Hex)) ok++ else fail++
            }
            withContext(Dispatchers.Main) {
                cpuDialogVisible = false
                val msg = when {
                    fail == 0 -> applySuccessMsg
                    ok == 0 -> applyFailedMsg
                    else -> applyPartialMsg(ok, fail)
                }
                Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
            }
        }
    }

    val onOpenDetails: (ExtensionId) -> Unit = { id ->
        when (id) {
            ExtensionId.Kpm -> navigator.push(Route.Kpm)
            ExtensionId.DynamicManager -> navigator.push(Route.DynamicManagers)
            ExtensionId.UmountPaths -> navigator.push(Route.UmountManager)
            ExtensionId.CpuSpoof -> openCpuDialog()
            ExtensionId.SuSFS -> navigator.push(Route.SuSFS)
            ExtensionId.VersionSpoof -> navigator.push(Route.VersionSpoof)
        }
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> ExtensionsScreenMiuix(
            state = state,
            onBack = { navigator.pop() },
            onRefresh = viewModel::refresh,
            onOpenDetails = onOpenDetails,
        )
        UiMode.Material -> ExtensionsScreenMaterial(
            state = state,
            onBack = { navigator.pop() },
            onRefresh = viewModel::refresh,
            onOpenDetails = onOpenDetails,
        )
    }

    if (cpuDialogVisible) {
        when (LocalUiMode.current) {
            UiMode.Miuix -> SpoofCpuDialogMiuix(
                currentCpuInfo = cpuInfo,
                onDismiss = { cpuDialogVisible = false },
                onApply = applyCpu,
                onRestore = {
                    cpuInfo?.let { info ->
                        applyCpu(SpoofCpuParams((0 until info.coreCount).toList(), info.midrHex, info.bogomips, info.hwcap, info.hwcap2))
                    }
                },
            )
            UiMode.Material -> SpoofCpuDialogMaterial(
                currentCpuInfo = cpuInfo,
                onDismiss = { cpuDialogVisible = false },
                onApply = applyCpu,
                onRestore = {
                    cpuInfo?.let { info ->
                        applyCpu(SpoofCpuParams((0 until info.coreCount).toList(), info.midrHex, info.bogomips, info.hwcap, info.hwcap2))
                    }
                },
            )
        }
    }
}
