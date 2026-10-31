package com.sukisu.ultra.ui.screen.ai

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.AddComment
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog
import com.sukisu.ultra.ui.component.material.ExpressiveDialog
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.ExpressiveSwitch
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import java.io.File

@Composable
fun AiChatMaterial(
    state: AiChatUiState,
    actions: AiChatActions,
) {
    val listState = rememberLazyListState()
    BackHandler(enabled = state.pendingQuestion != null) {
        actions.onAnswerQuestion(null)
    }
    val keyboardController = LocalSoftwareKeyboardController.current
    LaunchedEffect(state.pendingQuestion) {
        if (state.pendingQuestion != null) keyboardController?.hide()
    }
    val clearDialog = rememberConfirmDialog(onConfirm = actions.onClearHistory)
    val clearTitle = stringResource(R.string.ai_clear_history_title)
    val clearContent = stringResource(R.string.ai_clear_history_message)
    val clearConfirm = stringResource(R.string.ai_clear_history_confirm)
    var pendingDeleteId by remember { mutableStateOf<String?>(null) }
    val deleteTitle = stringResource(R.string.ai_delete_message_title)
    val deleteContent = stringResource(R.string.ai_delete_message_message)
    val deleteConfirm = stringResource(R.string.ai_delete_message_confirm)
    val deleteDialog = rememberConfirmDialog(
        onConfirm = {
            pendingDeleteId?.let(actions.onDeleteMessage)
            pendingDeleteId = null
        },
        onDismiss = { pendingDeleteId = null },
    )

    LaunchedEffect(
        state.messages.size,
        state.messages.lastOrNull()?.content?.length,
        state.suggestions,
        state.suggestionsLoading,
        state.isSending,
    ) {
        if (state.messages.isNotEmpty()) {
            val last = listState.layoutInfo.totalItemsCount - 1
            if (last >= 0) listState.scrollToItem(last)
        }
    }

    ExpressiveScaffold(
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ai_chat_title)) },
                navigationIcon = { TopBarBackButton(onClick = actions.onBack) },
                actions = {
                    IconButton(onClick = actions.onOpenSettings) {
                        Icon(Icons.Rounded.Tune, contentDescription = stringResource(R.string.ai_settings))
                    }
                    IconButton(onClick = {
                        clearDialog.showConfirm(
                            title = clearTitle,
                            content = clearContent,
                            confirm = clearConfirm,
                        )
                    }) {
                        Icon(Icons.Rounded.AddComment, contentDescription = stringResource(R.string.ai_new_chat))
                    }
                },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            LazyColumn(
                state = listState,
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (!state.config.isConfigured || !state.config.enabled) {
                    item(key = "setup") {
                        AiSetupCardMaterial(
                            enabled = state.config.enabled,
                            onOpenSettings = actions.onOpenSettings,
                        )
                    }
                }
                if (state.messages.isEmpty()) {
                    item(key = "welcome") {
                        AiWelcomeMaterial(
                            suggestions = state.suggestions,
                            loading = state.suggestionsLoading,
                            onSuggestion = { text ->
                                actions.onInputChange(text)
                                actions.onSend()
                            },
                            onRefresh = actions.onRefreshSuggestions,
                        )
                    }
                }
                items(state.messages, key = { it.id }) { message ->
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .combinedClickable(
                                onClick = {},
                                onLongClick = {
                                    if (!message.streaming) {
                                        pendingDeleteId = message.id
                                        deleteDialog.showConfirm(
                                            title = deleteTitle,
                                            content = deleteContent,
                                            confirm = deleteConfirm,
                                        )
                                    }
                                },
                            )
                    ) {
                        AiMessageBubbleMaterial(
                            message = message,
                            config = state.config,
                            rootGrantedForRequest = state.rootGrantedForRequest,
                            onNavigate = actions.onNavigate,
                            onCapabilityChange = actions.onSetCapability,
                            onGrantRoot = actions.onGrantRoot,
                            onRunCode = actions.onRunCode,
                        )
                    }
                }
                if (state.messages.isNotEmpty() && !state.isSending) {
                    item(key = "followups") {
                        AiFollowUpSuggestionsMaterial(
                            suggestions = state.suggestions,
                            loading = state.suggestionsLoading,
                            onSuggestion = { text ->
                                actions.onInputChange(text)
                                actions.onSend()
                            },
                            onRefresh = actions.onRefreshSuggestions,
                        )
                    }
                }
                item(key = "bottom") { Spacer(Modifier.height(4.dp)) }
            }

            state.pendingQuestion?.let { question ->
                AiQuestionPanelMaterial(
                    question = question,
                    onAnswer = actions.onAnswerQuestion,
                )
            }

            AiComposerMaterial(
                value = state.input,
                isSending = state.isSending,
                error = state.error,
                onValueChange = actions.onInputChange,
                onSend = actions.onSend,
                onStop = actions.onStop,
                onDismissError = actions.onDismissError,
            )
        }
    }

    state.pendingApproval?.let { pending ->
        AiApprovalDialogMaterial(
            pending = pending,
            onAllow = actions.onApprove,
            onAllowAlways = actions.onApproveAlways,
            onDeny = actions.onDeny,
        )
    }
}

@Composable
private fun AiFollowUpSuggestionsMaterial(
    suggestions: List<String>,
    loading: Boolean,
    onSuggestion: (String) -> Unit,
    onRefresh: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = stringResource(R.string.ai_follow_up_title),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.weight(1f))
            if (loading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(12.dp),
                    strokeWidth = 2.dp,
                )
                Spacer(Modifier.size(8.dp))
            }
            IconButton(
                onClick = onRefresh,
                modifier = Modifier.size(32.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.Refresh,
                    contentDescription = stringResource(R.string.ai_suggestions_refresh),
                    modifier = Modifier.size(18.dp),
                )
            }
        }
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            suggestions.forEach { suggestion ->
                SuggestionChip(
                    onClick = { onSuggestion(suggestion) },
                    label = {
                        Text(
                            text = suggestion,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                )
            }
        }
    }
}

@Composable
private fun AiSetupCardMaterial(
    enabled: Boolean,
    onOpenSettings: () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(
                    if (enabled) R.string.ai_setup_required else R.string.ai_setup_disabled
                ),
                style = MaterialTheme.typography.titleSmall,
            )
            Button(onClick = onOpenSettings, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.ai_open_settings))
            }
        }
    }
}

@Composable
private fun AiMessageBubbleMaterial(
    message: AiChatMessage,
    config: AiConfig,
    rootGrantedForRequest: Boolean,
    onNavigate: (AiNavigationTarget) -> Unit,
    onCapabilityChange: (AiCapability, Boolean) -> Unit,
    onGrantRoot: () -> Unit,
    onRunCode: (String) -> Unit,
) {
    val copy = rememberAiCopyText()
    var pendingRiskCapability by remember { mutableStateOf<AiCapability?>(null) }
    var pendingRootGrant by remember { mutableStateOf(false) }
    when (message.role) {
        AiMessageRole.USER -> {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                Surface(
                    shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp, bottomStart = 24.dp, bottomEnd = 8.dp),
                    color = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                ) {
                    Text(
                        text = message.content,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
        }

        AiMessageRole.ASSISTANT -> {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.Top,
            ) {
                Surface(
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    modifier = Modifier.padding(end = 8.dp),
                ) {
                    AiAvatarImage(
                        modifier = Modifier.padding(6.dp),
                        size = 22.dp,
                    )
                }
                Surface(
                    shape = RoundedCornerShape(topStart = 8.dp, topEnd = 24.dp, bottomStart = 24.dp, bottomEnd = 24.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    modifier = Modifier.weight(1f, fill = false),
                ) {
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        AiMarkdownMaterial(
                            content = message.content,
                            allowCodeExecution = config.allowCodeExecution,
                            onRunCode = onRunCode,
                        )
                        if (message.streaming) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(14.dp),
                                strokeWidth = 2.dp,
                            )
                        } else if (message.content.isNotBlank()) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.End,
                            ) {
                                IconButton(
                                    onClick = { copy(message.content) },
                                    modifier = Modifier.size(28.dp),
                                ) {
                                    Icon(
                                        imageVector = Icons.Rounded.ContentCopy,
                                        contentDescription = stringResource(R.string.ai_copy),
                                        modifier = Modifier.size(15.dp),
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        AiMessageRole.TOOL -> {
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = MaterialTheme.colorScheme.secondaryContainer,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Terminal,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.onSecondaryContainer,
                        )
                        Text(
                            text = message.toolName ?: stringResource(R.string.ai_tool),
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                        )
                        if (message.streaming) {
                            CircularProgressIndicator(modifier = Modifier.size(12.dp), strokeWidth = 2.dp)
                        }
                        Spacer(Modifier.weight(1f))
                        if (message.content.isNotBlank()) {
                            IconButton(
                                onClick = { copy(message.content) },
                                modifier = Modifier.size(28.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.ContentCopy,
                                    contentDescription = stringResource(R.string.ai_copy),
                                    modifier = Modifier.size(15.dp),
                                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                                )
                            }
                        }
                    }
                    SelectionContainer {
                        Text(
                            text = linkifyAiText(message.content, MaterialTheme.colorScheme.primary),
                            modifier = Modifier
                                .heightIn(max = 260.dp)
                                .verticalScroll(rememberScrollState()),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                        )
                    }
                    val imagePath = message.imagePath
                    if (imagePath != null) {
                        AsyncImage(
                            model = File(imagePath),
                            contentDescription = null,
                            contentScale = ContentScale.Crop,
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(max = 240.dp)
                                .clip(RoundedCornerShape(12.dp)),
                        )
                    }
                    val navigation = message.navigation
                    if (navigation != null) {
                        Button(
                            onClick = { onNavigate(navigation) },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Rounded.OpenInNew,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Text(
                                text = stringResource(
                                    R.string.ai_go_to_page,
                                    message.navigationTitle.orEmpty(),
                                ),
                                modifier = Modifier.padding(start = 6.dp),
                            )
                        }
                    }
                    val capability = message.capability
                    if (capability != null) {
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = MaterialTheme.colorScheme.tertiaryContainer,
                            contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth().padding(10.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    text = stringResource(R.string.ai_capability_needed),
                                    style = MaterialTheme.typography.labelLarge,
                                )
                                Text(
                                    text = stringResource(R.string.ai_capability_hint),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(
                                        text = stringResource(capability.labelRes()),
                                        modifier = Modifier.weight(1f),
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                    ExpressiveSwitch(
                                        checked = config.capabilityEnabled(capability),
                                        onCheckedChange = { enabled ->
                                            if (!enabled) {
                                                onCapabilityChange(capability, false)
                                            } else if (capability.riskKind() != null) {
                                                pendingRiskCapability = capability
                                            } else {
                                                onCapabilityChange(capability, true)
                                            }
                                        },
                                    )
                                }
                                if (capability == AiCapability.ROOT) {
                                    if (rootGrantedForRequest) {
                                        Text(
                                            text = stringResource(R.string.ai_root_granted_for_request),
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                    } else if (!config.allowRootAccess) {
                                        TextButton(onClick = { pendingRootGrant = true }) {
                                            Text(stringResource(R.string.ai_root_allow_once))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        AiMessageRole.ERROR -> {
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = MaterialTheme.colorScheme.errorContainer,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = message.content,
                    modifier = Modifier.padding(14.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }
    }

    pendingRiskCapability?.let { capability ->
        val kind = capability.riskKind()
        if (kind != null) {
            AiRiskDialogMaterial(
                kind = kind,
                onConfirm = {
                    pendingRiskCapability = null
                    onCapabilityChange(capability, true)
                },
                onDismiss = { pendingRiskCapability = null },
            )
        }
    }

    if (pendingRootGrant) {
        AiRiskDialogMaterial(
            kind = AiRiskKind.ROOT,
            onConfirm = {
                pendingRootGrant = false
                onGrantRoot()
            },
            onDismiss = { pendingRootGrant = false },
        )
    }
}

@Composable
private fun AiWelcomeMaterial(
    suggestions: List<String>,
    loading: Boolean,
    onSuggestion: (String) -> Unit,
    onRefresh: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Surface(
            shape = CircleShape,
            color = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ) {
            AiAvatarImage(
                modifier = Modifier.padding(12.dp),
                size = 40.dp,
            )
        }
        Text(
            text = stringResource(R.string.ai_welcome_title),
            style = MaterialTheme.typography.titleLarge,
            textAlign = TextAlign.Center,
        )
        Text(
            text = stringResource(R.string.ai_welcome_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 24.dp),
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            suggestions.forEach { suggestion ->
                SuggestionChip(
                    onClick = { onSuggestion(suggestion) },
                    label = {
                        Text(
                            text = suggestion,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                )
            }
        }
        if (loading) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                CircularProgressIndicator(
                    modifier = Modifier.size(14.dp),
                    strokeWidth = 2.dp,
                )
                Text(
                    text = stringResource(R.string.ai_suggestions_loading),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        TextButton(onClick = onRefresh) {
            Icon(
                imageVector = Icons.Rounded.Refresh,
                contentDescription = null,
                modifier = Modifier.size(16.dp),
            )
            Text(
                text = stringResource(R.string.ai_suggestions_refresh),
                modifier = Modifier.padding(start = 6.dp),
            )
        }
    }
}

@Composable
private fun AiComposerMaterial(
    value: String,
    isSending: Boolean,
    error: String?,
    onValueChange: (String) -> Unit,
    onSend: () -> Unit,
    onStop: () -> Unit,
    onDismissError: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .imePadding()
            .navigationBarsPadding()
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        AnimatedVisibility(visible = error != null) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.errorContainer,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    modifier = Modifier.padding(start = 14.dp, top = 6.dp, bottom = 6.dp, end = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = error.orEmpty(),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    IconButton(onClick = onDismissError) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = stringResource(R.string.ai_close),
                            modifier = Modifier.size(18.dp),
                            tint = MaterialTheme.colorScheme.onErrorContainer,
                        )
                    }
                }
            }
        }
        Surface(
            shape = RoundedCornerShape(28.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            tonalElevation = 2.dp,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(6.dp),
                verticalAlignment = Alignment.Bottom,
            ) {
                OutlinedTextField(
                    value = value,
                    onValueChange = onValueChange,
                    placeholder = { Text(stringResource(R.string.ai_chat_input_hint)) },
                    maxLines = 5,
                    shape = RoundedCornerShape(22.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = Color.Transparent,
                        focusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
                        unfocusedBorderColor = Color.Transparent,
                    ),
                    modifier = Modifier.weight(1f),
                )
                FilledIconButton(
                    onClick = if (isSending) onStop else onSend,
                    enabled = isSending || value.isNotBlank(),
                    modifier = Modifier.padding(6.dp).size(48.dp),
                ) {
                    Icon(
                        imageVector = if (isSending) Icons.Rounded.Stop else Icons.AutoMirrored.Rounded.Send,
                        contentDescription = stringResource(
                            if (isSending) R.string.ai_stop else R.string.ai_send
                        ),
                    )
                }
            }
        }
    }
}

@Composable
private fun AiApprovalDialogMaterial(
    pending: AiPendingApproval,
    onAllow: () -> Unit,
    onAllowAlways: () -> Unit,
    onDeny: () -> Unit,
) {
    var alwaysAllow by remember(pending.request) { mutableStateOf(false) }
    ExpressiveDialog(
        onDismissRequest = onDeny,
        title = { Text(stringResource(R.string.ai_approval_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(pending.request.title, style = MaterialTheme.typography.bodyLarge)
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerLowest,
                ) {
                    SelectionContainer {
                        Text(
                            text = pending.request.detail,
                            modifier = Modifier
                                .padding(12.dp)
                                .heightIn(max = 220.dp)
                                .verticalScroll(rememberScrollState()),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Checkbox(
                        checked = alwaysAllow,
                        onCheckedChange = { alwaysAllow = it },
                    )
                    Text(
                        text = stringResource(R.string.ai_approval_always),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { if (alwaysAllow) onAllowAlways() else onAllow() },
            ) {
                Text(stringResource(R.string.ai_approval_allow))
            }
        },
        dismissButton = {
            TextButton(onClick = onDeny) { Text(stringResource(R.string.ai_approval_deny)) }
        },
    )
}

@Composable
internal fun AiDisclaimerDialogMaterial(
    onAccept: () -> Unit,
    onExit: () -> Unit,
) {
    var checked by remember { mutableStateOf(false) }
    ExpressiveDialog(
        onDismissRequest = onExit,
        title = { Text(stringResource(R.string.ai_disclaimer_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = stringResource(R.string.ai_disclaimer_body),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .heightIn(max = 260.dp)
                        .verticalScroll(rememberScrollState()),
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Checkbox(
                        checked = checked,
                        onCheckedChange = { checked = it },
                    )
                    Text(
                        text = stringResource(R.string.ai_disclaimer_check),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = onAccept, enabled = checked) {
                Text(stringResource(R.string.ai_disclaimer_accept))
            }
        },
        dismissButton = {
            TextButton(onClick = onExit) {
                Text(stringResource(R.string.ai_disclaimer_exit))
            }
        },
    )
}

@Composable
internal fun AiRiskDialogMaterial(
    kind: AiRiskKind,
    phrase: String? = null,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    var checked by remember(kind, phrase) { mutableStateOf(false) }
    var phraseInput by remember(kind, phrase) { mutableStateOf("") }
    val phraseMatches = phrase == null || phraseInput.trim().equals(phrase, ignoreCase = true)
    ExpressiveDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.ai_risk_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = stringResource(kind.bodyRes),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .heightIn(max = 240.dp)
                        .verticalScroll(rememberScrollState()),
                )
                if (phrase != null) {
                    OutlinedTextField(
                        value = phraseInput,
                        onValueChange = { phraseInput = it.take(32) },
                        label = { Text(stringResource(R.string.ai_advanced_phrase)) },
                        placeholder = { Text(stringResource(R.string.ai_advanced_phrase_hint)) },
                        singleLine = true,
                        shape = MaterialTheme.shapes.large,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Checkbox(
                        checked = checked,
                        onCheckedChange = { checked = it },
                    )
                    Text(
                        text = stringResource(R.string.ai_risk_check),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = onConfirm, enabled = checked && phraseMatches) {
                Text(stringResource(R.string.ai_risk_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.ai_risk_cancel))
            }
        },
    )
}
