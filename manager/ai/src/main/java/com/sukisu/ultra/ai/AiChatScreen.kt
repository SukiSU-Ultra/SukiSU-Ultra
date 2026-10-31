package com.sukisu.ultra.ai
import com.sukisu.ultra.ai.api.AiUiMode

import com.sukisu.ultra.ai.api.AiNavigationTarget

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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.ViewModelStoreOwner
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel

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
    val host = AiAssistant.requireHost()
    var show by remember { mutableStateOf(host.showAiHomeCard()) }
    DisposableEffect(host) {
        val registration = host.registerShowAiHomeCardListener {
            show = host.showAiHomeCard()
        }
        onDispose { registration.close() }
    }
    return show
}

/**
 * The assistant chat. Navigation is delegated to the host: [onClose] pops the
 * chat, [onOpenSettings] pushes the settings page, and [onNavigate] handles a
 * tool's host-defined destination.
 */
@Composable
fun AiChatScreen(
    uiMode: AiUiMode,
    onClose: () -> Unit,
    onOpenSettings: () -> Unit,
    onNavigate: (AiNavigationTarget) -> Unit,
) {
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
            onClose()
        }
    }

    val currentHomeEntryEnabled by rememberUpdatedState(homeEntryEnabled)
    LifecycleResumeEffect(model) {
        if (!currentHomeEntryEnabled) {
            model.stop()
            onClose()
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
    val runDialog = rememberAiConfirmDialog(
        uiMode = uiMode,
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
        onBack = onClose,
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
        onOpenSettings = onOpenSettings,
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
        onNavigate = onNavigate,
    )

    when (uiMode) {
        AiUiMode.Miuix -> AiChatMiuix(state, actions)
        AiUiMode.Material -> AiChatMaterial(state, actions)
    }

    if (!disclaimerAccepted) {
        val onAccept = {
            AiDisclaimer.accept(context)
            disclaimerAccepted = true
        }
        val onExit = onClose
        when (uiMode) {
            AiUiMode.Material -> AiDisclaimerDialogMaterial(onAccept = onAccept, onExit = onExit)
            AiUiMode.Miuix -> AiDisclaimerDialogMiuix(onAccept = onAccept, onExit = onExit)
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
