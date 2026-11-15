package com.sukisu.nova.ui.screen.builtinzygisk

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.nova.R
import com.sukisu.nova.ui.LocalUiMode
import com.sukisu.nova.ui.UiMode
import com.sukisu.nova.ui.component.rebootlistpopup.rememberRebootAction
import com.sukisu.nova.ui.component.rebootlistpopup.rememberRebootChoices
import com.sukisu.nova.ui.navigation3.LocalNavigator
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
    // The Home page's reboot action, so a late-load device still gets its warning prompt.
    val rebootAction = rememberRebootAction()
    // Set while the restart question for a just-selected provider is open.
    var exitTarget by remember { mutableStateOf<String?>(null) }

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
        // Selecting a provider leaves this panel: ksud finishes the handover in the
        // background while the user chooses how to restart.
        exitTarget = name
        viewModel.switchInBackground(target) { ok ->
            if (!ok) {
                Toast.makeText(context, R.string.builtin_zygisk_switch_failed, Toast.LENGTH_SHORT).show()
            }
        }
    }
    val onToggleInjected = { id: String ->
        viewModel.toggleInjectedModule(id)
    }
    val onToggleGroup = {
        viewModel.toggleInjectedGroup()
    }

    exitTarget?.let { name ->
        SwitchRestartDialog(
            name = name,
            onReboot = { reason ->
                exitTarget = null
                rebootAction(reason)
            },
            onClose = {
                exitTarget = null
                navigator.pop()
            }
        )
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> BuiltinZygiskMiuix(
            uiState = state,
            onBack = onBack,
            onRefresh = onRefresh,
            onSwitch = onSwitch,
            onToggleInjected = onToggleInjected,
            onSetOption = onSetOption,
            onToggleGroup = onToggleGroup,
        )
        UiMode.Material -> BuiltinZygiskMaterial(
            uiState = state,
            onBack = onBack,
            onRefresh = onRefresh,
            onSwitch = onSwitch,
            onToggleInjected = onToggleInjected,
            onSetOption = onSetOption,
            onToggleGroup = onToggleGroup,
        )
    }
}

/// Asks how to finish a provider switch, with the same 重启/软重启 entries the Home page's
/// reboot menu offers. Dismissing leaves the panel.
@Composable
private fun SwitchRestartDialog(
    name: String,
    onReboot: (String) -> Unit,
    onClose: () -> Unit,
) {
    val choices = rememberRebootChoices()
    val title = stringResource(R.string.builtin_zygisk_switch_reboot_title)
    val message = stringResource(R.string.builtin_zygisk_switch_reboot_message, name)
    when (LocalUiMode.current) {
        UiMode.Material -> AlertDialog(
            onDismissRequest = onClose,
            title = { Text(title) },
            text = { Text(message) },
            confirmButton = {
                Row {
                    choices.forEach { choice ->
                        TextButton(onClick = { onReboot(choice.reason) }) {
                            Text(stringResource(choice.labelRes))
                        }
                    }
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
                    text = title,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 24.dp, bottom = 8.dp),
                    style = miuixTextStyles.title4,
                    textAlign = TextAlign.Center,
                    color = miuixColorScheme.onSurface
                )
                MiuixText(
                    text = message,
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
                    choices.forEach { choice ->
                        Spacer(Modifier.width(20.dp))
                        MiuixTextButton(
                            text = stringResource(choice.labelRes),
                            onClick = { onReboot(choice.reason) },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        )
    }
}
