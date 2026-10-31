package com.sukisu.ultra.ui.screen.ai

import android.content.Context
import android.content.SharedPreferences
import android.widget.Toast
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModelStoreOwner
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.viewmodel.MainActivityViewModel

/**
 * One conversation shared by the chat screen and the home-card status, so the
 * home entry can show a running request after navigating back.
 */
@Composable
fun rememberAiChatViewModel(): AiChatViewModel {
    val activityOwner = LocalActivity.current as? ViewModelStoreOwner
    return if (activityOwner != null) {
        viewModel(viewModelStoreOwner = activityOwner)
    } else {
        viewModel()
    }
}

@Composable
private fun rememberShowAiHomeCard(): Boolean {
    var show by remember { mutableStateOf(SettingsRepositoryImpl().showAiHomeCard) }
    DisposableEffect(Unit) {
        val prefs = ksuApp.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == null || key == "show_ai_home_card") {
                show = SettingsRepositoryImpl().showAiHomeCard
            }
        }
        prefs.registerOnSharedPreferenceChangeListener(listener)
        onDispose { prefs.unregisterOnSharedPreferenceChangeListener(listener) }
    }
    return show
}

@Composable
fun AiChatScreen() {
    val navigator = LocalNavigator.current
    val model = rememberAiChatViewModel()
    val state by model.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val localNetworkPermissionDenied = stringResource(R.string.ai_local_network_permission_denied)
    val homeEntryEnabled = rememberShowAiHomeCard()
    var disclaimerAccepted by remember {
        mutableStateOf(AiDisclaimer.isAccepted(context))
    }

    LaunchedEffect(homeEntryEnabled) {
        if (!homeEntryEnabled) {
            model.stop()
            // Only pop when the assistant is actually the visible destination; a pushed
            // settings page above it must not be removed by this effect.
            if (navigator.current() == Route.AiAssistant) navigator.pop()
        }
    }

    val currentHomeEntryEnabled by rememberUpdatedState(homeEntryEnabled)
    LifecycleResumeEffect(model) {
        if (!currentHomeEntryEnabled) {
            model.stop()
            if (navigator.current() == Route.AiAssistant) navigator.pop()
        } else {
            model.refreshConfig()
            if (disclaimerAccepted) model.ensureSuggestions()
        }
        onPauseOrDispose { }
    }

    LaunchedEffect(state.messages.isEmpty(), disclaimerAccepted) {
        if (disclaimerAccepted && state.messages.isEmpty()) model.ensureSuggestions()
    }

    val openImageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> model.onFilePicked(uri) }
    val createImageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("image/*")
    ) { uri -> model.onFilePicked(uri) }
    val openFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> model.onFilePicked(uri) }
    val createFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri -> model.onFilePicked(uri) }
    LaunchedEffect(state.pendingFilePicker?.id) {
        val request = state.pendingFilePicker ?: return@LaunchedEffect
        when (request.mode) {
            AiFilePickerMode.OPEN_IMAGE ->
                openImageLauncher.launch(arrayOf("image/*"))
            AiFilePickerMode.CREATE_IMAGE ->
                createImageLauncher.launch(request.suggestedName.ifBlank { "theme-image.png" })
            AiFilePickerMode.OPEN_FILE ->
                openFileLauncher.launch(arrayOf("*/*"))
            AiFilePickerMode.CREATE_FILE ->
                createFileLauncher.launch(request.suggestedName.ifBlank { "SukiSU-file" })
        }
    }

    val activityOwner = LocalActivity.current as? ViewModelStoreOwner
    val mainViewModel: MainActivityViewModel = if (activityOwner != null) {
        viewModel(viewModelStoreOwner = activityOwner)
    } else {
        viewModel()
    }

    var pendingNetworkAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    val networkPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            pendingNetworkAction?.invoke()
        } else {
            model.reportError(localNetworkPermissionDenied)
        }
        pendingNetworkAction = null
    }
    val runWithLocalNetwork: (() -> Unit) -> Unit = { action ->
        if (AiLocalNetwork.needsPermission(context, state.config)) {
            pendingNetworkAction = action
            networkPermissionLauncher.launch(AiLocalNetwork.PERMISSION)
        } else {
            action()
        }
    }

    var pendingRunCommand by remember { mutableStateOf<String?>(null) }
    val runDialog = rememberConfirmDialog(
        onConfirm = {
            pendingRunCommand?.let(model::runCodeBlock)
            pendingRunCommand = null
        },
        onDismiss = { pendingRunCommand = null },
    )
    val runTitle = stringResource(R.string.ai_run_code_title)
    val runMessage = stringResource(R.string.ai_run_code_message)
    val runConfirm = stringResource(R.string.ai_run_code_confirm)

    val actions = AiChatActions(
        onBack = { navigator.pop() },
        onInputChange = model::onInputChange,
        onSend = {
            if (disclaimerAccepted) {
                runWithLocalNetwork { model.send() }
            }
        },
        onStop = model::stop,
        onClearHistory = model::clearHistory,
        onApprove = model::approvePending,
        onApproveAlways = model::approveAlwaysForRequest,
        onDeny = model::denyPending,
        onOpenSettings = { navigator.push(Route.AiSettings) },
        onGrantRoot = model::grantRootForRequest,
        onAnswerQuestion = model::answerQuestion,
        onRunCode = { code ->
            pendingRunCommand = code
            val preview = if (code.length > 600) code.take(600) + "\n…" else code
            runDialog.showConfirm(
                title = runTitle,
                content = "$runMessage\n\n$preview",
                confirm = runConfirm,
            )
        },
        onDeleteMessage = model::deleteMessage,
        onDismissError = model::clearError,
        onRefreshSuggestions = {
            if (disclaimerAccepted) {
                runWithLocalNetwork { model.refreshSuggestions() }
            }
        },
        onSetCapability = model::setCapability,
        onNavigate = { target ->
            when (target) {
                is AiNavigationTarget.Tab -> {
                    mainViewModel.openMainPage(target.pageIndex, target.section)
                    navigator.popUntil { it is Route.Main }
                }

                is AiNavigationTarget.Push -> navigator.navigateTo(target.route)
            }
        },
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> AiChatMiuix(state, actions)
        UiMode.Material -> AiChatMaterial(state, actions)
    }

    if (!disclaimerAccepted) {
        val onAccept = {
            AiDisclaimer.accept(context)
            disclaimerAccepted = true
        }
        val onExit = {
            if (navigator.current() == Route.AiAssistant) navigator.pop()
        }
        when (LocalUiMode.current) {
            UiMode.Material -> AiDisclaimerDialogMaterial(onAccept = onAccept, onExit = onExit)
            UiMode.Miuix -> AiDisclaimerDialogMiuix(onAccept = onAccept, onExit = onExit)
        }
    }
}

data class AiChatActions(
    val onBack: () -> Unit,
    val onInputChange: (String) -> Unit,
    val onSend: () -> Unit,
    val onStop: () -> Unit,
    val onClearHistory: () -> Unit,
    val onApprove: () -> Unit,
    val onApproveAlways: () -> Unit,
    val onDeny: () -> Unit,
    val onOpenSettings: () -> Unit,
    val onGrantRoot: () -> Unit,
    val onAnswerQuestion: (String?) -> Unit,
    val onRunCode: (String) -> Unit,
    val onDeleteMessage: (String) -> Unit,
    val onDismissError: () -> Unit,
    val onRefreshSuggestions: () -> Unit,
    val onNavigate: (AiNavigationTarget) -> Unit,
    val onSetCapability: (AiCapability, Boolean) -> Unit,
)
