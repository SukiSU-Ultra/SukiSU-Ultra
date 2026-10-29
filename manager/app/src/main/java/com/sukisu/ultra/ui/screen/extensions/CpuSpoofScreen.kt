package com.sukisu.ultra.ui.screen.extensions

import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.screen.settings.tools.CpuInfo
import com.sukisu.ultra.ui.screen.settings.tools.SpoofCpuParams
import com.sukisu.ultra.ui.screen.settings.tools.readCurrentCpuIdentity
import com.sukisu.ultra.ui.util.spoofCpu
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Navigation and CPU spoofing state; the two UIs only own layout and form state. */
@Composable
fun CpuSpoofScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val configuration = LocalConfiguration.current
    var currentInfo by remember { mutableStateOf<CpuInfo?>(null) }
    var loading by remember { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }

    val successMsg = stringResource(R.string.spoof_cpu_apply_success)
    val failedMsg = stringResource(R.string.spoof_cpu_apply_failed)
    val partialMsg: (Int, Int) -> String = { ok, fail ->
        context.createConfigurationContext(configuration).resources
            .getString(R.string.spoof_cpu_apply_partial_failure, ok, fail)
    }

    LaunchedEffect(Unit) {
        currentInfo = readCurrentCpuIdentity()
        loading = false
    }

    val apply: (SpoofCpuParams) -> Unit = { params ->
        if (!busy) {
            busy = true
            scope.launch {
                var ok = 0
                var fail = 0
                withContext(Dispatchers.IO) {
                    for (index in params.cpuIndices) {
                        if (spoofCpu(index, params.midrHex, params.bogomips, params.hwcapHex, params.hwcap2Hex)) {
                            ok++
                        } else {
                            fail++
                        }
                    }
                }
                busy = false
                val message = when {
                    fail == 0 -> successMsg
                    ok == 0 -> failedMsg
                    else -> partialMsg(ok, fail)
                }
                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                // The user may have left while the spoof was running; never pop twice.
                if (navigator.current() == Route.CpuSpoof) navigator.pop()
            }
        }
    }

    val actions = CpuSpoofActions(
        onBack = { navigator.pop() },
        onApply = apply,
    )
    val state = CpuSpoofState(currentInfo = currentInfo, loading = loading, busy = busy)
    when (LocalUiMode.current) {
        UiMode.Miuix -> CpuSpoofMiuix(state, actions)
        UiMode.Material -> CpuSpoofMaterial(state, actions)
    }
}

internal data class CpuSpoofState(
    val currentInfo: CpuInfo? = null,
    val loading: Boolean = true,
    val busy: Boolean = false,
)

internal data class CpuSpoofActions(
    val onBack: () -> Unit,
    val onApply: (SpoofCpuParams) -> Unit,
)
