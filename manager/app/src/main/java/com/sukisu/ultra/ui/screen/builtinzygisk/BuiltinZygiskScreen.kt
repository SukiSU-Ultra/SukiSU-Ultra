package com.sukisu.ultra.ui.screen.builtinzygisk

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.util.reboot
import top.yukonga.miuix.kmp.basic.ButtonDefaults as MiuixButtonDefaults
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator as MiuixCircularProgressIndicator
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme as miuixColorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.textStyles as miuixTextStyles

@Composable
fun BuiltinZygiskScreen() {
    val context = LocalContext.current
    val navigator = LocalNavigator.current
    val viewModel: BuiltinZygiskViewModel = viewModel()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    // `failed`, `incomplete` or `off_pending`: what to tell the user after an action.
    var switchProblem by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        viewModel.load()
    }

    val onBack = dropUnlessResumed { navigator.pop() }
    val onRefresh = {
        viewModel.load()
    }
    val onSetOption = { key: String, value: String ->
        viewModel.setOption(key, value) {
            Toast.makeText(context, R.string.builtin_zygisk_option_failed, Toast.LENGTH_SHORT).show()
        }
    }
    val onSwitch = { target: String, name: String ->
        viewModel.switchTo(target) { ok, fullyActive ->
            when {
                // Only a monitor, a daemon and an injected zygote together make the
                // modules usable; anything less still needs the soft reboot dialog.
                ok && fullyActive -> {
                    val message = context.getString(R.string.builtin_zygisk_switch_done, name)
                    Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                }
                ok -> switchProblem = "incomplete"
                else -> switchProblem = "failed"
            }
        }
    }
    val onToggleProcesses = { id: String ->
        viewModel.toggleModuleProcesses(id)
    }
    val onToggleInjected = { id: String ->
        viewModel.toggleInjectedModule(id)
    }

    if (state.isSwitching) {
        SwitchingDialog()
    }
    switchProblem?.let { problem ->
        ZygiskProblemDialog(problem = problem, onClose = { switchProblem = null })
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> BuiltinZygiskMiuix(
            uiState = state,
            onBack = onBack,
            onRefresh = onRefresh,
            onSwitch = onSwitch,
            onToggleProcesses = onToggleProcesses,
            onToggleInjected = onToggleInjected,
            onSetOption = onSetOption,
        )
        UiMode.Material -> BuiltinZygiskMaterial(
            uiState = state,
            onBack = onBack,
            onRefresh = onRefresh,
            onSwitch = onSwitch,
            onToggleProcesses = onToggleProcesses,
            onToggleInjected = onToggleInjected,
            onSetOption = onSetOption,
        )
    }
}

/// Shown while ksud stops the current implementation and waits for the zygote injection.
@Composable
private fun SwitchingDialog() {
    when (LocalUiMode.current) {
        UiMode.Material -> AlertDialog(
            onDismissRequest = {},
            title = { Text(stringResource(R.string.builtin_zygisk_switching_title)) },
            text = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.builtin_zygisk_switching_message))
                }
            },
            confirmButton = {}
        )
        UiMode.Miuix -> OverlayDialog(
            show = true,
            onDismissRequest = {},
            content = {
                Row(
                    horizontalArrangement = Arrangement.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 24.dp)
                ) {
                    MiuixCircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
                MiuixText(
                    text = stringResource(R.string.builtin_zygisk_switching_title),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp, bottom = 8.dp),
                    style = miuixTextStyles.title4,
                    textAlign = TextAlign.Center,
                    color = miuixColorScheme.onSurface
                )
                MiuixText(
                    text = stringResource(R.string.builtin_zygisk_switching_message),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 8.dp)
                        .padding(bottom = 16.dp),
                    style = miuixTextStyles.body2,
                    textAlign = TextAlign.Center,
                    color = miuixColorScheme.onSurfaceVariantSummary
                )
            }
        )
    }
}

/// Zygisk is not fully up (a failed switch, a half-injected state, or a disable that
/// still needs a reboot): let the user close this or soft reboot to finish it.
@Composable
private fun ZygiskProblemDialog(problem: String, onClose: () -> Unit) {
    val title = problemTitle(problem)
    val message = problemMessage(problem)
    // Only the user space has to restart: a hard reboot would gain nothing here.
    val rebootNow = {
        onClose()
        reboot("soft_reboot")
    }
    when (LocalUiMode.current) {
        UiMode.Material -> AlertDialog(
            onDismissRequest = onClose,
            title = { Text(stringResource(title)) },
            text = { Text(stringResource(message)) },
            confirmButton = {
                TextButton(onClick = rebootNow) {
                    Text(stringResource(R.string.reboot_soft))
                }
            },
            dismissButton = {
                TextButton(onClick = onClose) {
                    Text(stringResource(R.string.close))
                }
            }
        )
        UiMode.Miuix -> OverlayDialog(
            show = true,
            onDismissRequest = onClose,
            content = {
                MiuixText(
                    text = stringResource(title),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 24.dp, bottom = 8.dp),
                    style = miuixTextStyles.title4,
                    textAlign = TextAlign.Center,
                    color = miuixColorScheme.onSurface
                )
                MiuixText(
                    text = stringResource(message),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 8.dp),
                    style = miuixTextStyles.body2,
                    textAlign = TextAlign.Center,
                    color = miuixColorScheme.onSurfaceVariantSummary
                )
                Row(
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 24.dp, end = 24.dp, top = 8.dp, bottom = 24.dp)
                ) {
                    MiuixTextButton(
                        text = stringResource(R.string.close),
                        onClick = onClose,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(Modifier.width(20.dp))
                    MiuixTextButton(
                        text = stringResource(R.string.reboot_soft),
                        onClick = rebootNow,
                        modifier = Modifier.weight(1f),
                        colors = MiuixButtonDefaults.textButtonColorsPrimary()
                    )
                }
            }
        )
    }
}

/// Title for a Zygisk state that still needs a reboot to finish.
internal fun problemTitle(problem: String): Int = when (problem) {
    "incomplete" -> R.string.builtin_zygisk_incomplete_title
    "off_pending" -> R.string.builtin_zygisk_off_pending_title
    else -> R.string.builtin_zygisk_switch_failed
}

/// Body for the same state.
internal fun problemMessage(problem: String): Int = when (problem) {
    "incomplete" -> R.string.builtin_zygisk_incomplete_message
    "off_pending" -> R.string.builtin_zygisk_off_pending_message
    else -> R.string.builtin_zygisk_switch_failed_message
}
