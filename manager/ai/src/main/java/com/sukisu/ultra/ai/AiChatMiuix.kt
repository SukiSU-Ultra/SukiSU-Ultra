package com.sukisu.ultra.ai
import com.sukisu.ultra.ai.api.AiUiMode

import com.sukisu.ultra.ai.api.AiNavigationTarget

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
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
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.sukisu.ultra.ai.R
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Checkbox
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.ProgressIndicatorDefaults
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Copy
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic
import java.io.File

@Composable
fun AiChatMiuix(
    state: AiChatUiState,
    actions: AiChatActions,
) {
    val scroll = MiuixScrollBehavior()
    val listState = rememberLazyListState()
    BackHandler(enabled = state.pendingQuestion != null) {
        actions.onAnswerQuestion(null)
    }
    val keyboardController = LocalSoftwareKeyboardController.current
    LaunchedEffect(state.pendingQuestion) {
        if (state.pendingQuestion != null) keyboardController?.hide()
    }
    val clearDialog = rememberAiConfirmDialog(AiUiMode.Miuix, onConfirm = actions.onClearHistory)
    val clearTitle = stringResource(R.string.ai_clear_history_title)
    val clearContent = stringResource(R.string.ai_clear_history_message)
    val clearConfirm = stringResource(R.string.ai_clear_history_confirm)
    var pendingDeleteId by remember { mutableStateOf<String?>(null) }
    val deleteTitle = stringResource(R.string.ai_delete_message_title)
    val deleteContent = stringResource(R.string.ai_delete_message_message)
    val deleteConfirm = stringResource(R.string.ai_delete_message_confirm)
    val deleteDialog = rememberAiConfirmDialog(
        AiUiMode.Miuix,
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

    AiAppScaffold(
        // The assistant is a full-screen tool page: never let the global
        // custom background show through here.
        containerColor = colorScheme.surface,
        topBar = {
            TopAppBar(
                title = stringResource(R.string.ai_chat_title),
                navigationIcon = {
                    IconButton(onClick = actions.onBack) {
                        Icon(
                            imageVector = MiuixIcons.Back,
                            contentDescription = null,
                            tint = colorScheme.onBackground,
                        )
                    }
                },
                actions = {
                    IconButton(onClick = actions.onOpenSettings) {
                        Icon(
                            imageVector = Icons.Rounded.Tune,
                            contentDescription = stringResource(R.string.ai_settings),
                            tint = colorScheme.onBackground,
                        )
                    }
                    IconButton(onClick = {
                        clearDialog.showConfirm(
                            title = clearTitle,
                            content = clearContent,
                            confirm = clearConfirm,
                        )
                    }) {
                        Icon(
                            imageVector = Icons.Rounded.AddComment,
                            contentDescription = stringResource(R.string.ai_new_chat),
                            tint = colorScheme.onBackground,
                        )
                    }
                },
                scrollBehavior = scroll,
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(colorScheme.surface)
                .imePadding(),
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .overScrollVertical()
                    .scrollEndHaptic()
                    .nestedScroll(scroll.nestedScrollConnection),
                contentPadding = PaddingValues(
                    start = 14.dp,
                    end = 14.dp,
                    top = padding.calculateTopPadding() + 8.dp,
                    bottom = 8.dp,
                ),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                overscrollEffect = null,
            ) {
                if (!state.config.isConfigured || !state.config.enabled) {
                    item(key = "setup") {
                        AiSetupCardMiuix(
                            enabled = state.config.enabled,
                            onOpenSettings = actions.onOpenSettings,
                        )
                    }
                }
                if (state.messages.isEmpty()) {
                    item(key = "welcome") {
                        AiWelcomeMiuix(
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
                        AiMessageBubbleMiuix(
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
                        AiFollowUpSuggestionsMiuix(
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
                AiQuestionPanelMiuix(
                    question = question,
                    onAnswer = actions.onAnswerQuestion,
                )
            }

            AiComposerMiuix(
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
        var alwaysAllow by remember(pending.request) { mutableStateOf(false) }
        OverlayDialog(
            show = true,
            title = stringResource(R.string.ai_approval_title),
            onDismissRequest = actions.onDeny,
            content = {
                Text(
                    text = pending.request.title,
                    style = MiuixTheme.textStyles.body1,
                )
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(colorScheme.surfaceContainerHighest)
                        .padding(12.dp),
                ) {
                    SelectionContainer {
                        Text(
                            text = pending.request.detail,
                            modifier = Modifier
                                .heightIn(max = 220.dp)
                                .verticalScroll(rememberScrollState()),
                            style = MiuixTheme.textStyles.body2,
                            fontFamily = FontFamily.Monospace,
                            color = colorScheme.onSurface,
                        )
                    }
                }
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Checkbox(
                        state = ToggleableState(alwaysAllow),
                        onClick = { alwaysAllow = !alwaysAllow },
                    )
                    Text(
                        text = stringResource(R.string.ai_approval_always),
                        style = MiuixTheme.textStyles.body1,
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    TextButton(
                        text = stringResource(R.string.ai_approval_deny),
                        onClick = actions.onDeny,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        text = stringResource(R.string.ai_approval_allow),
                        onClick = {
                            if (alwaysAllow) actions.onApproveAlways else actions.onApprove()
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                    )
                }
            },
        )
    }
}

@Composable
private fun AiFollowUpSuggestionsMiuix(
    suggestions: List<String>,
    loading: Boolean,
    onSuggestion: (String) -> Unit,
    onRefresh: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = stringResource(R.string.ai_follow_up_title),
                style = MiuixTheme.textStyles.body2,
                color = colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.weight(1f))
            IconButton(
                onClick = onRefresh,
                modifier = Modifier.size(32.dp),
            ) {
                if (loading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        colors = ProgressIndicatorDefaults.progressIndicatorColors(
                            foregroundColor = colorScheme.onSurfaceVariantActions,
                            backgroundColor = Color.Transparent,
                        ),
                        strokeWidth = 2.dp,
                    )
                } else {
                    Icon(
                        imageVector = Icons.Rounded.Refresh,
                        contentDescription = stringResource(R.string.ai_suggestions_refresh),
                        modifier = Modifier.size(18.dp),
                        tint = colorScheme.onSurfaceVariantActions,
                    )
                }
            }
        }
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            suggestions.forEach { suggestion ->
                MiuixSuggestionChip(
                    text = suggestion,
                    onClick = { onSuggestion(suggestion) },
                )
            }
        }
    }
}

@Composable
private fun MiuixSuggestionChip(
    text: String,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(18.dp))
            .background(colorScheme.secondaryContainer)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 8.dp),
    ) {
        Text(
            text = text,
            style = MiuixTheme.textStyles.body2,
            color = colorScheme.onSecondaryContainer,
            maxLines = 3,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun AiSetupCardMiuix(
    enabled: Boolean,
    onOpenSettings: () -> Unit,
) {
    AiAppCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(color = colorScheme.tertiaryContainer),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(
                    if (enabled) R.string.ai_setup_required else R.string.ai_setup_disabled
                ),
                style = MiuixTheme.textStyles.body1,
                color = colorScheme.onTertiaryContainer,
            )
            Button(onClick = onOpenSettings, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.ai_open_settings))
            }
        }
    }
}

@Composable
private fun AiMessageBubbleMiuix(
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
                Box(
                    modifier = Modifier
                        .clip(
                            RoundedCornerShape(
                                topStart = 22.dp,
                                topEnd = 22.dp,
                                bottomStart = 22.dp,
                                bottomEnd = 8.dp,
                            )
                        )
                        .background(colorScheme.primary)
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                ) {
                    Text(
                        text = message.content,
                        style = MiuixTheme.textStyles.body1,
                        color = colorScheme.onPrimary,
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
                Box(
                    modifier = Modifier
                        .padding(end = 8.dp)
                        .size(34.dp)
                        .clip(CircleShape)
                        .background(colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center,
                ) {
                    AiAvatarImage(
                        size = 24.dp,
                    )
                }
                Box(
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .clip(
                            RoundedCornerShape(
                                topStart = 8.dp,
                                topEnd = 22.dp,
                                bottomStart = 22.dp,
                                bottomEnd = 22.dp,
                            )
                        )
                        .background(colorScheme.surfaceContainerHigh)
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        AiMarkdownMiuix(
                            content = message.content,
                            allowCodeExecution = config.allowCodeExecution,
                            onRunCode = onRunCode,
                        )
                        if (message.streaming) {
                            CircularProgressIndicator(modifier = Modifier.size(14.dp))
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
                                        imageVector = MiuixIcons.Copy,
                                        contentDescription = stringResource(R.string.ai_copy),
                                        modifier = Modifier.size(15.dp),
                                        tint = colorScheme.onSurfaceVariantSummary,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        AiMessageRole.TOOL -> {
            AiAppCard(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.defaultColors(color = colorScheme.secondaryContainer),
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(12.dp),
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
                            tint = colorScheme.onSecondaryContainer,
                        )
                        Text(
                            text = message.toolName ?: stringResource(R.string.ai_tool),
                            style = MiuixTheme.textStyles.body2,
                            color = colorScheme.onSecondaryContainer,
                        )
                        if (message.streaming) {
                            CircularProgressIndicator(modifier = Modifier.size(12.dp))
                        }
                        Spacer(Modifier.weight(1f))
                        if (message.content.isNotBlank()) {
                            IconButton(
                                onClick = { copy(message.content) },
                                modifier = Modifier.size(28.dp),
                            ) {
                                Icon(
                                    imageVector = MiuixIcons.Copy,
                                    contentDescription = stringResource(R.string.ai_copy),
                                    modifier = Modifier.size(15.dp),
                                    tint = colorScheme.onSecondaryContainer,
                                )
                            }
                        }
                    }
                    SelectionContainer {
                        Text(
                            text = linkifyAiText(message.content, colorScheme.primary),
                            modifier = Modifier
                                .heightIn(max = 260.dp)
                                .verticalScroll(rememberScrollState()),
                            style = MiuixTheme.textStyles.body2,
                            fontFamily = FontFamily.Monospace,
                            color = colorScheme.onSecondaryContainer,
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
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Rounded.OpenInNew,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp),
                                )
                                Text(
                                    stringResource(
                                        R.string.ai_go_to_page,
                                        message.navigationTitle.orEmpty(),
                                    )
                                )
                            }
                        }
                    }
                    val capability = message.capability
                    if (capability != null) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .background(colorScheme.tertiaryContainer)
                                .padding(10.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Text(
                                text = stringResource(R.string.ai_capability_needed),
                                style = MiuixTheme.textStyles.body1,
                                color = colorScheme.onTertiaryContainer,
                            )
                            Text(
                                text = stringResource(R.string.ai_capability_hint),
                                style = MiuixTheme.textStyles.body2,
                                color = colorScheme.onTertiaryContainer,
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = stringResource(capability.labelRes()),
                                    modifier = Modifier.weight(1f),
                                    style = MiuixTheme.textStyles.body2,
                                    color = colorScheme.onTertiaryContainer,
                                )
                                Switch(
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
                                        style = MiuixTheme.textStyles.body2,
                                        color = colorScheme.onTertiaryContainer,
                                    )
                                } else if (!config.allowRootAccess) {
                                    TextButton(
                                        text = stringResource(R.string.ai_root_allow_once),
                                        onClick = { pendingRootGrant = true },
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        AiMessageRole.ERROR -> {
            AiAppCard(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.defaultColors(color = colorScheme.errorContainer),
            ) {
                Text(
                    text = message.content,
                    modifier = Modifier.fillMaxWidth().padding(12.dp),
                    style = MiuixTheme.textStyles.body2,
                    color = colorScheme.onErrorContainer,
                )
            }
        }
    }

    pendingRiskCapability?.let { capability ->
        val kind = capability.riskKind()
        if (kind != null) {
            AiRiskDialogMiuix(
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
        AiRiskDialogMiuix(
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
private fun AiWelcomeMiuix(
    suggestions: List<String>,
    loading: Boolean,
    onSuggestion: (String) -> Unit,
    onRefresh: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            modifier = Modifier
                .size(64.dp)
                .clip(CircleShape)
                .background(colorScheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            AiAvatarImage(
                size = 46.dp,
            )
        }
        Text(
            text = stringResource(R.string.ai_welcome_title),
            style = MiuixTheme.textStyles.title2,
            textAlign = TextAlign.Center,
        )
        Text(
            text = stringResource(R.string.ai_welcome_body),
            modifier = Modifier.padding(horizontal = 20.dp),
            style = MiuixTheme.textStyles.body2,
            color = colorScheme.onSurfaceVariantSummary,
            textAlign = TextAlign.Center,
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            suggestions.forEach { suggestion ->
                MiuixSuggestionChip(
                    text = suggestion,
                    onClick = { onSuggestion(suggestion) },
                )
            }
        }
        Button(
            onClick = onRefresh,
            colors = ButtonDefaults.buttonColors(),
            insideMargin = PaddingValues(horizontal = 16.dp, vertical = 13.dp),
        ) {
            if (loading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    colors = ProgressIndicatorDefaults.progressIndicatorColors(
                        foregroundColor = colorScheme.onSecondaryVariant,
                        backgroundColor = Color.Transparent,
                    ),
                    strokeWidth = 2.dp,
                )
                Spacer(Modifier.size(8.dp))
            } else {
                Icon(
                    imageVector = Icons.Rounded.Refresh,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp),
                    tint = colorScheme.onSecondaryVariant,
                )
                Spacer(Modifier.size(6.dp))
            }
            Text(
                text = stringResource(R.string.ai_suggestions_refresh),
                style = MiuixTheme.textStyles.button,
            )
        }
    }
}

@Composable
private fun AiComposerMiuix(
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
            .navigationBarsPadding()
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        AnimatedVisibility(visible = error != null) {
            AiAppCard(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.defaultColors(color = colorScheme.errorContainer),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(start = 12.dp, top = 4.dp, bottom = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = error.orEmpty(),
                        modifier = Modifier.weight(1f),
                        style = MiuixTheme.textStyles.body2,
                        color = colorScheme.onErrorContainer,
                    )
                    IconButton(onClick = onDismissError) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = stringResource(R.string.ai_close),
                            modifier = Modifier.size(18.dp),
                            tint = colorScheme.onErrorContainer,
                        )
                    }
                }
            }
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(24.dp))
                .background(colorScheme.surfaceContainerHigh)
                .padding(8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            TextField(
                value = value,
                onValueChange = onValueChange,
                label = stringResource(R.string.ai_chat_input_hint),
                useLabelAsPlaceholder = true,
                modifier = Modifier.weight(1f),
            )
            IconButton(
                onClick = if (isSending) onStop else onSend,
                enabled = isSending || value.isNotBlank(),
            ) {
                Icon(
                    imageVector = if (isSending) Icons.Rounded.Stop else Icons.AutoMirrored.Rounded.Send,
                    contentDescription = stringResource(
                        if (isSending) R.string.ai_stop else R.string.ai_send
                    ),
                    tint = colorScheme.primary,
                )
            }
        }
    }
}

@Composable
internal fun AiDisclaimerDialogMiuix(
    onAccept: () -> Unit,
    onExit: () -> Unit,
) {
    var checked by remember { mutableStateOf(false) }
    OverlayDialog(
        show = true,
        title = stringResource(R.string.ai_disclaimer_title),
        onDismissRequest = onExit,
        content = {
            Text(
                text = stringResource(R.string.ai_disclaimer_body),
                style = MiuixTheme.textStyles.body2,
                modifier = Modifier
                    .heightIn(max = 260.dp)
                    .verticalScroll(rememberScrollState()),
            )
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Checkbox(
                    state = ToggleableState(checked),
                    onClick = { checked = !checked },
                )
                Text(
                    text = stringResource(R.string.ai_disclaimer_check),
                    style = MiuixTheme.textStyles.body2,
                    modifier = Modifier.weight(1f),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(
                    text = stringResource(R.string.ai_disclaimer_exit),
                    onClick = onExit,
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    text = stringResource(R.string.ai_disclaimer_accept),
                    onClick = onAccept,
                    enabled = checked,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        },
    )
}

@Composable
internal fun AiRiskDialogMiuix(
    kind: AiRiskKind,
    phrase: String? = null,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    var checked by remember(kind, phrase) { mutableStateOf(false) }
    var phraseInput by remember(kind, phrase) { mutableStateOf("") }
    val phraseMatches = phrase == null || phraseInput.trim().equals(phrase, ignoreCase = true)
    OverlayDialog(
        show = true,
        title = stringResource(R.string.ai_risk_title),
        onDismissRequest = onDismiss,
        content = {
            Text(
                text = stringResource(kind.bodyRes),
                style = MiuixTheme.textStyles.body2,
                modifier = Modifier
                    .heightIn(max = 240.dp)
                    .verticalScroll(rememberScrollState()),
            )
            if (phrase != null) {
                TextField(
                    value = phraseInput,
                    onValueChange = { phraseInput = it.take(32) },
                    label = stringResource(R.string.ai_advanced_phrase),
                    useLabelAsPlaceholder = true,
                    maxLines = 1,
                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Checkbox(
                    state = ToggleableState(checked),
                    onClick = { checked = !checked },
                )
                Text(
                    text = stringResource(R.string.ai_risk_check),
                    style = MiuixTheme.textStyles.body2,
                    modifier = Modifier.weight(1f),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(
                    text = stringResource(R.string.ai_risk_cancel),
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    text = stringResource(R.string.ai_risk_confirm),
                    onClick = onConfirm,
                    enabled = checked && phraseMatches,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        },
    )
}
