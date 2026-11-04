package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Chat
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.AccountUserSummary
import com.sukisu.ultra.data.model.ThemeComment
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors

@Composable
internal fun ThemeStoreMessagesScreen(
    state: ThemeStoreUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onLogin: () -> Unit,
    onReply: (UserMessageConversation, String, String?) -> Unit,
    onDelete: (UserMessageConversation, ThemeComment) -> Unit,
    mentionUsers: List<AccountUserSummary>,
    mentionLoading: Boolean,
    mentionError: String?,
    onSearchMentions: (UserMessageConversation, String) -> Unit,
    onClearMentionSearch: () -> Unit,
) {
    var lastSending by remember { mutableStateOf(false) }
    val replyTargets = remember { mutableStateMapOf<String, ThemeComment>() }
    val drafts = remember { mutableStateMapOf<String, TextFieldValue>() }

    LaunchedEffect(Unit) { onRefresh() }

    LaunchedEffect(state.messagesSending) {
        if (lastSending && !state.messagesSending && state.messagesError == null) {
            drafts.clear()
            replyTargets.clear()
        }
        lastSending = state.messagesSending
    }

    val retentionHint = if (state.messagesRetentionDays > 0) {
        stringResource(R.string.theme_store_messages_retention, state.messagesRetentionDays)
    } else {
        stringResource(R.string.theme_store_messages_keep_forever)
    }
    val pageContainer = MaterialTheme.colorScheme.surface
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(
        rememberTopAppBarState(),
    )

    ExpressiveScaffold(
        containerColor = pageContainer,
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(stringResource(R.string.theme_store_messages_title)) },
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                actions = {
                    IconButton(
                        onClick = onRefresh,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Refresh,
                            contentDescription = stringResource(R.string.theme_store_messages_refresh),
                        )
                    }
                },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
                scrollBehavior = scrollBehavior,
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 8.dp, bottom = 36.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item(key = "messages-hint") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "$retentionHint · ${stringResource(R.string.theme_store_messages_long_press_hint)}",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    if (state.messagesLoading) {
                        CircularWavyProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            stroke = Stroke(width = 2f),
                        )
                    }
                }
            }

            state.messagesError?.takeIf { it.isNotBlank() }?.let { error ->
                item(key = "messages-error") {
                    ThemeStoreInlineNotice(text = error, isError = true)
                }
            }

            if (state.accounts.isEmpty()) {
                item(key = "messages-login") {
                    ThemeStoreInlineNotice(
                        text = stringResource(R.string.theme_store_messages_login_required),
                    )
                    Button(
                        onClick = onLogin,
                        shapes = ButtonDefaults.shapes(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                    ) {
                        Text(stringResource(R.string.theme_store_messages_sign_in))
                    }
                }
            } else if (state.messages.isEmpty() && !state.messagesLoading) {
                item(key = "messages-empty") {
                    Box(modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp)) {
                        Text(
                            text = stringResource(R.string.theme_store_messages_empty),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            items(state.messages, key = { it.key }) { conversation ->
                MessageConversationCard(
                    conversation = conversation,
                    replyTarget = replyTargets[conversation.key],
                    draft = drafts[conversation.key] ?: TextFieldValue(""),
                    sending = state.messagesSending,
                    onDraftChange = { value ->
                        if (value.text.length <= 2000) drafts[conversation.key] = value
                    },
                    onReplyTarget = { comment -> replyTargets[conversation.key] = comment },
                    onClearReplyTarget = { replyTargets.remove(conversation.key) },
                    onDelete = { comment -> onDelete(conversation, comment) },
                    onLoginRequired = onLogin,
                    mentionUsers = mentionUsers,
                    mentionLoading = mentionLoading,
                    mentionError = mentionError,
                    onSearchMentions = { query -> onSearchMentions(conversation, query) },
                    onClearMentionSearch = onClearMentionSearch,
                    onSend = {
                        val target = replyTargets[conversation.key]
                        if (target != null) {
                            onReply(conversation, drafts[conversation.key]?.text.orEmpty(), target.id)
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun MessageConversationCard(
    conversation: UserMessageConversation,
    replyTarget: ThemeComment?,
    draft: TextFieldValue,
    sending: Boolean,
    onDraftChange: (TextFieldValue) -> Unit,
    onReplyTarget: (ThemeComment) -> Unit,
    onClearReplyTarget: () -> Unit,
    onDelete: (ThemeComment) -> Unit,
    onLoginRequired: () -> Unit,
    mentionUsers: List<AccountUserSummary>,
    mentionLoading: Boolean,
    mentionError: String?,
    onSearchMentions: (String) -> Unit,
    onClearMentionSearch: () -> Unit,
    onSend: () -> Unit,
) {
    var showMentionDialog by remember { mutableStateOf(false) }
    val themeName = conversation.conversation.themeName
        .ifBlank { conversation.conversation.themeId }
    val author = conversation.conversation.themeAuthor
    val subtitle = buildString {
        if (author.isNotBlank()) append(author)
        if (conversation.conversation.isThemeAuthor) {
            if (isNotEmpty()) append(" · ")
            append(stringResource(R.string.theme_store_messages_my_theme))
        }
        if (conversation.conversation.mentioned) {
            if (isNotEmpty()) append(" · ")
            append(stringResource(R.string.theme_store_comments_mentioned_you))
        }
        val accountName = conversation.account.session.user.displayName
            .ifBlank { conversation.account.session.user.username }
        if (accountName.isNotBlank()) {
            if (isNotEmpty()) append(" · ")
            append(accountName)
        }
    }
    ThemeStoreSectionCard(
        title = themeName,
        icon = Icons.AutoMirrored.Rounded.Chat,
        subtitle = subtitle.ifBlank { null },
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            conversation.conversation.comments.forEach { thread ->
                ThemeStoreCommentRow(
                    comment = thread,
                    isReply = false,
                    baseUrl = conversation.account.source.baseUrl,
                    token = conversation.account.source.token,
                    loggedIn = true,
                    onLoginRequired = onLoginRequired,
                    onReply = onReplyTarget,
                    onDelete = onDelete,
                )
                thread.replies.forEach { reply ->
                    Box(modifier = Modifier.padding(start = 22.dp)) {
                        ThemeStoreCommentRow(
                            comment = reply,
                            isReply = true,
                            baseUrl = conversation.account.source.baseUrl,
                            token = conversation.account.source.token,
                            loggedIn = true,
                            onLoginRequired = onLoginRequired,
                            onReply = onReplyTarget,
                            onDelete = onDelete,
                        )
                    }
                }
            }
        }

        AnimatedVisibility(
            visible = replyTarget != null,
            enter = fadeIn(MaterialTheme.motionScheme.defaultEffectsSpec()) +
                expandVertically(MaterialTheme.motionScheme.defaultSpatialSpec()),
            exit = fadeOut(MaterialTheme.motionScheme.fastEffectsSpec()) +
                shrinkVertically(MaterialTheme.motionScheme.defaultSpatialSpec()),
        ) {
            replyTarget?.let { target ->
                val name = target.displayName.ifBlank { target.username }
                Surface(
                    shape = MaterialTheme.shapes.large,
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = stringResource(R.string.theme_store_comments_replying, name),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(onClick = onClearReplyTarget) {
                            Text(stringResource(R.string.theme_store_comments_cancel_reply))
                        }
                    }
                }
            }
        }

        OutlinedTextField(
            value = draft,
            onValueChange = onDraftChange,
            modifier = Modifier.fillMaxWidth(),
            placeholder = {
                Text(
                    stringResource(
                        if (replyTarget == null) R.string.theme_store_messages_select_reply
                        else R.string.theme_store_messages_reply_placeholder,
                    ),
                )
            },
            enabled = replyTarget != null,
            minLines = 2,
            maxLines = 4,
            shape = MaterialTheme.shapes.extraLarge,
        )
        if (replyTarget != null) {
            ThemeStoreMarkdownToolbar(
                value = draft,
                onValueChange = onDraftChange,
                onMention = {
                    showMentionDialog = true
                    onClearMentionSearch()
                },
            )
        }

        Button(
            onClick = onSend,
            enabled = replyTarget != null && draft.text.isNotBlank() && !sending,
            shapes = ButtonDefaults.shapes(),
            modifier = Modifier
                .fillMaxWidth()
                .height(44.dp),
        ) {
            if (sending) {
                CircularWavyProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    color = MaterialTheme.colorScheme.onPrimary,
                    trackColor = MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.24f),
                    stroke = Stroke(width = 2f),
                )
                Spacer(Modifier.width(6.dp))
            } else {
                Icon(
                    imageVector = Icons.AutoMirrored.Rounded.Send,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
            }
            Text(stringResource(R.string.theme_store_comments_send))
        }
    }

    if (showMentionDialog) {
        ThemeStoreMentionPickerDialog(
            users = mentionUsers,
            loading = mentionLoading,
            error = mentionError,
            onQueryChange = onSearchMentions,
            onSelect = { token ->
                onDraftChange(draft.insertAtSelection("$token "))
                showMentionDialog = false
                onClearMentionSearch()
            },
            onDismiss = {
                showMentionDialog = false
                onClearMentionSearch()
            },
        )
    }
}
