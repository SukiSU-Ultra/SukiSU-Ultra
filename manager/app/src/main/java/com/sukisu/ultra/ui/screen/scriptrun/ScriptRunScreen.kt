package com.sukisu.ultra.ui.screen.scriptrun

import android.content.Context
import android.widget.Toast
import androidx.activity.compose.LocalActivity
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigationevent.NavigationEventInfo
import androidx.navigationevent.compose.NavigationBackHandler
import androidx.navigationevent.compose.rememberNavigationEventState
import kotlinx.coroutines.launch
import com.sukisu.ultra.R
import com.sukisu.ultra.data.script.ParamError
import com.sukisu.ultra.data.script.ScriptOutcome
import com.sukisu.ultra.data.script.ScriptParam
import com.sukisu.ultra.data.script.ScriptRunRecord
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.screen.executemoduleaction.ActionResultKind
import com.sukisu.ultra.ui.screen.executemoduleaction.ActionResultNotice
import com.sukisu.ultra.ui.screen.executemoduleaction.ExecuteModuleActionScreenActions
import com.sukisu.ultra.ui.screen.executemoduleaction.ExecuteModuleActionScreenMaterial
import com.sukisu.ultra.ui.screen.executemoduleaction.ExecuteModuleActionScreenMiuix
import com.sukisu.ultra.ui.screen.executemoduleaction.ExecuteModuleActionUiState
import com.sukisu.ultra.ui.screen.executemoduleaction.saveLog
import com.sukisu.ultra.ui.screen.flash.FlashIt
import com.sukisu.ultra.ui.viewmodel.ScriptRunViewModel
import java.text.DateFormat
import java.util.Date
import java.util.UUID

/**
 * Run page of a one-shot script: verify + extract, parameter form and source, then the
 * output (shared with module actions) once it runs.
 */
@Composable
fun ScriptRunScreen(arg: ScriptRunArg, onBackEnabledChange: (Boolean) -> Unit) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val uiMode = LocalUiMode.current
    val scope = rememberCoroutineScope()
    val viewModel = viewModel<ScriptRunViewModel>(key = "script-run-${arg.uri}-${arg.registryId}")
    val state by viewModel.state.collectAsStateWithLifecycle()

    val visit = rememberSaveable { UUID.randomUUID().toString() }
    LaunchedEffect(arg, visit) { viewModel.load(arg, visit) }
    // The script cannot be stopped: no back (gesture included) and no swipe-dismiss while it runs.
    val running = state.phase == ScriptRunPhase.RUNNING
    SideEffect { onBackEnabledChange(!running) }
    NavigationBackHandler(
        state = rememberNavigationEventState(NavigationEventInfo.None),
        isBackEnabled = running,
        onBackCompleted = {},
    )
    // ViewModels here live as long as the activity: free the extraction when the page goes away.
    val activity = LocalActivity.current
    DisposableEffect(viewModel) {
        onDispose { if (activity?.isChangingConfigurations != true) viewModel.leave() }
    }

    if (state.phase == ScriptRunPhase.RUNNING || state.phase == ScriptRunPhase.FINISHED) {
        val snackbarHost = remember { SnackbarHostState() }
        val showMessage: (String) -> Unit = { message ->
            scope.launch {
                if (uiMode == UiMode.Material) {
                    snackbarHost.showSnackbar(message)
                } else {
                    Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                }
            }
        }
        val finished = state.phase == ScriptRunPhase.FINISHED
        val exitCode = state.exitCode
        val notice = if (finished && exitCode != null) {
            when (ScriptOutcome.of(exitCode)) {
                ScriptOutcome.SUCCESS -> ActionResultNotice(ActionResultKind.SUCCESS, stringResource(R.string.script_result_success))
                ScriptOutcome.NOT_APPLICABLE -> ActionResultNotice(
                    ActionResultKind.NOT_APPLICABLE,
                    stringResource(R.string.script_result_not_applicable)
                )

                ScriptOutcome.FAILURE -> ActionResultNotice(
                    ActionResultKind.FAILURE,
                    stringResource(R.string.script_result_failed, exitCode)
                )
            }
        } else {
            null
        }
        val outputState = ExecuteModuleActionUiState(
            text = state.output,
            isComplete = finished,
            title = state.prepared?.manifest?.name ?: stringResource(R.string.script_run_title),
            resultNotice = notice,
        )
        val outputActions = ExecuteModuleActionScreenActions(
            // The script cannot be stopped; stay on the output until it ends.
            onBack = dropUnlessResumed { if (finished) navigator.pop() },
            onSaveLog = saveLog(viewModel.logContent, scope, "KernelSU_script_log") { showMessage(it) },
            onClose = { navigator.pop() },
        )
        when (uiMode) {
            UiMode.Miuix -> ExecuteModuleActionScreenMiuix(outputState, outputActions)
            UiMode.Material -> ExecuteModuleActionScreenMaterial(outputState, outputActions, snackbarHost)
        }
        return
    }

    val confirmDialog = rememberConfirmDialog(onConfirm = { viewModel.run() })
    val confirmTitle = stringResource(R.string.script_run_title)
    val confirmContent = stringResource(R.string.script_run_confirm, state.prepared?.manifest?.name.orEmpty())
    val confirmButton = stringResource(R.string.script_run)
    val actions = ScriptRunActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onValueChange = viewModel::setValue,
        onRun = {
            if (state.canRun) {
                confirmDialog.showConfirm(title = confirmTitle, content = confirmContent, confirm = confirmButton)
            }
        },
        onInstallAsModule = {
            if (arg.offerInstall) navigator.replace(Route.Flash(FlashIt.FlashModules(listOf(arg.uri))))
        },
    )

    when (uiMode) {
        UiMode.Miuix -> ScriptRunScreenMiuix(state, actions)
        UiMode.Material -> ScriptRunScreenMaterial(state, actions)
    }
}

@Composable
internal fun paramErrorText(param: ScriptParam, error: ParamError): String = when (error) {
    ParamError.REQUIRED -> stringResource(R.string.script_param_required)
    ParamError.TOO_LONG -> stringResource(R.string.script_param_too_long, (param as? ScriptParam.Text)?.maxLength ?: 0)
    ParamError.INVALID_CHARACTERS -> stringResource(R.string.script_param_invalid_characters)
    ParamError.NOT_AN_INTEGER -> stringResource(R.string.script_param_not_integer)
    ParamError.BELOW_MIN -> stringResource(R.string.script_param_below_min, (param as? ScriptParam.Integer)?.min ?: 0)
    ParamError.ABOVE_MAX -> stringResource(R.string.script_param_above_max, (param as? ScriptParam.Integer)?.max ?: 0)
    ParamError.INVALID_OPTION, ParamError.INVALID_BOOLEAN -> stringResource(R.string.script_param_invalid)
}

internal fun lastRunText(context: Context, record: ScriptRunRecord?): String {
    if (record == null) return context.getString(R.string.script_never_run)
    val time = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(record.time))
    return if (record.versionCode != null) {
        context.getString(R.string.script_last_run_version, time, record.versionCode, record.exitCode)
    } else {
        context.getString(R.string.script_last_run, time, record.exitCode)
    }
}


internal fun scriptSubtitle(id: String, version: String, versionCode: Int?): String = buildString {
    append("ID: ").append(id)
    if (version.isNotBlank()) append(" · ").append(version)
    if (versionCode != null) append(" (").append(versionCode).append(')')
}


internal fun integerKeyboardType(param: ScriptParam.Integer): KeyboardType =
    if ((param.min ?: Int.MIN_VALUE) < 0) KeyboardType.Ascii else KeyboardType.Number
