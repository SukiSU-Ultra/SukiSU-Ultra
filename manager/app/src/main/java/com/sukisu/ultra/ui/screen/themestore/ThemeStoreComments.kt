package com.sukisu.ultra.ui.screen.themestore

import android.annotation.SuppressLint
import android.content.ClipData
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.automirrored.rounded.Chat
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.AddComment
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.TonalCard
import com.sukisu.ultra.data.model.AccountUserSummary
import com.sukisu.ultra.data.model.ThemeComment
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import coil.compose.AsyncImage
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import androidx.compose.ui.platform.LocalLocale
import kotlin.time.Duration.Companion.milliseconds

@Composable
internal fun ThemeStoreCommentsSection(
    state: ThemeStoreUiState,
    baseUrl: String,
    token: String,
    loggedIn: Boolean,
    onLogin: () -> Unit,
    onRefresh: () -> Unit,
    onSend: (String) -> Unit,
    onDelete: (ThemeComment) -> Unit,
    onReplyTargetChange: (ThemeComment?) -> Unit,
    onVisibilityChange: (String) -> Unit,
    onSearchMentions: (String) -> Unit,
    onClearMentionSearch: () -> Unit,
) {
    val retentionHint = when {
        state.commentsRetentionDays > 0 ->
            stringResource(R.string.theme_store_comments_retention, state.commentsRetentionDays)
        else -> stringResource(R.string.theme_store_comments_keep_forever)
    }
    var draft by rememberSaveable(
        state.commentsThemeKey,
        stateSaver = TextFieldValue.Saver,
    ) {
        mutableStateOf(TextFieldValue(""))
    }
    var showMentionDialog by remember { mutableStateOf(false) }
    var deleteTarget by remember { mutableStateOf<ThemeComment?>(null) }
    var lastSentCount by remember { mutableLongStateOf(state.commentsSentCount) }
    LaunchedEffect(state.commentsSentCount) {
        if (state.commentsSentCount != lastSentCount) {
            draft = TextFieldValue("")
            lastSentCount = state.commentsSentCount
        }
    }

    ThemeStoreSectionCard(
        title = stringResource(R.string.theme_store_comments_title),
        icon = Icons.AutoMirrored.Rounded.Chat,
        subtitle = if (loggedIn) {
            "$retentionHint · ${stringResource(R.string.theme_store_comments_long_press_hint)}"
        } else {
            retentionHint
        },
        modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (state.commentsLoading) {
                CircularWavyProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    stroke = Stroke(width = 2f),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.theme_store_comments_loading),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Text(
                    text = stringResource(
                        R.string.theme_store_comments_count,
                        state.comments.sumOf { 1 + it.replies.size },
                    ),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.weight(1f))
            AssistChip(
                onClick = onRefresh,
                label = { Text(stringResource(R.string.theme_store_comments_refresh)) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Rounded.Refresh,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                },
                shape = MaterialTheme.shapes.small,
            )
        }

        state.commentsError?.takeIf { it.isNotBlank() }?.let { error ->
            ThemeStoreInlineNotice(text = error, isError = true)
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (state.comments.isEmpty() && !state.commentsLoading) {
                Text(
                    text = stringResource(R.string.theme_store_comments_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            state.comments.forEach { thread ->
                ThemeStoreCommentRow(
                    comment = thread,
                    isReply = false,
                    baseUrl = baseUrl,
                    token = token,
                    loggedIn = loggedIn,
                    onLoginRequired = onLogin,
                    onReply = onReplyTargetChange,
                    onDelete = { deleteTarget = it },
                )
                thread.replies.forEach { reply ->
                    Box(modifier = Modifier.padding(start = 22.dp)) {
                        ThemeStoreCommentRow(
                            comment = reply,
                            isReply = true,
                            baseUrl = baseUrl,
                            token = token,
                            loggedIn = loggedIn,
                            onLoginRequired = onLogin,
                            onReply = onReplyTargetChange,
                            onDelete = { deleteTarget = it },
                        )
                    }
                }
            }
        }

        if (!loggedIn) {
            ThemeStoreInlineNotice(text = stringResource(R.string.theme_store_comments_login_hint))
            Button(
                onClick = onLogin,
                shapes = ButtonDefaults.shapes(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.theme_store_comments_login))
            }
        } else {
            AnimatedVisibility(
                visible = state.commentReplyTarget != null,
                enter = fadeIn(MaterialTheme.motionScheme.defaultEffectsSpec()) +
                    expandVertically(MaterialTheme.motionScheme.defaultSpatialSpec()),
                exit = fadeOut(MaterialTheme.motionScheme.fastEffectsSpec()) +
                    shrinkVertically(MaterialTheme.motionScheme.defaultSpatialSpec()),
            ) {
                state.commentReplyTarget?.let { target ->
                    val targetName = target.displayName.ifBlank { target.username }
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
                                text = stringResource(
                                    R.string.theme_store_comments_replying,
                                    targetName,
                                ),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSecondaryContainer,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(onClick = { onReplyTargetChange(null) }) {
                                Text(stringResource(R.string.theme_store_comments_cancel_reply))
                            }
                        }
                    }
                }
            }

            OutlinedTextField(
                value = draft,
                onValueChange = { value -> if (value.text.length <= 2000) draft = value },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text(stringResource(R.string.theme_store_comments_placeholder)) },
                minLines = 2,
                maxLines = 5,
                shape = MaterialTheme.shapes.extraLarge,
            )
            ThemeStoreMarkdownToolbar(
                value = draft,
                onValueChange = { draft = it },
                onMention = {
                    showMentionDialog = true
                    onClearMentionSearch()
                },
            )
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                FilterChip(
                    selected = state.commentVisibility == "public",
                    onClick = { onVisibilityChange("public") },
                    label = { Text(stringResource(R.string.theme_store_comments_public)) },
                )
                FilterChip(
                    selected = state.commentVisibility == "author",
                    onClick = { onVisibilityChange("author") },
                    label = { Text(stringResource(R.string.theme_store_comments_private)) },
                )
            }
            Button(
                onClick = { if (draft.text.isNotBlank()) onSend(draft.text) },
                enabled = draft.text.isNotBlank() && !state.commentsSending,
                shapes = ButtonDefaults.shapes(),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(44.dp),
            ) {
                if (state.commentsSending) {
                    CircularWavyProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        trackColor = MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.24f),
                        stroke = Stroke(width = 2f),
                    )
                } else {
                    Icon(
                        imageVector = Icons.AutoMirrored.Rounded.Send,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                }
                Spacer(Modifier.width(6.dp))
                Text(
                    stringResource(
                        if (state.commentsSending) R.string.theme_store_comments_sending
                        else R.string.theme_store_comments_send,
                    ),
                )
            }
        }
    }

    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            shape = MaterialTheme.shapes.extraLarge,
            title = { Text(stringResource(R.string.theme_store_comments_delete)) },
            text = { Text(stringResource(R.string.theme_store_comments_delete_confirm)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        deleteTarget = null
                        onDelete(target)
                    },
                ) {
                    Text(
                        text = stringResource(R.string.theme_store_comments_delete),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(stringResource(android.R.string.cancel))
                }
            },
        )
    }

    if (showMentionDialog) {
        ThemeStoreMentionPickerDialog(
            users = state.mentionUsers,
            loading = state.mentionLoading,
            error = state.mentionError,
            onQueryChange = onSearchMentions,
            onSelect = { token ->
                draft = draft.insertAtSelection("$token ")
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

internal fun TextFieldValue.insertAtSelection(insert: String): TextFieldValue {
    val start = selection.min
    val end = selection.max
    val newText = text.substring(0, start) + insert + text.substring(end)
    return TextFieldValue(newText, selection = TextRange(start + insert.length))
}

internal fun TextFieldValue.applyMarkdown(
    prefix: String,
    suffix: String = prefix,
    placeholder: String = "",
): TextFieldValue {
    val start = selection.min
    val end = selection.max
    val selected = text.substring(start, end)
    val body = selected.ifEmpty { placeholder }
    val inserted = prefix + body + suffix
    val newText = text.substring(0, start) + inserted + text.substring(end)
    val newSelection = if (selected.isEmpty()) {
        TextRange(start + prefix.length, start + prefix.length + body.length)
    } else {
        TextRange(start + inserted.length)
    }
    return TextFieldValue(newText, selection = newSelection)
}

@Composable
internal fun ThemeStoreMarkdownToolbar(
    value: TextFieldValue,
    onValueChange: (TextFieldValue) -> Unit,
    onMention: (() -> Unit)? = null,
    mentionEnabled: Boolean = true,
) {
    val boldPlaceholder = stringResource(R.string.theme_store_comments_format_bold_text)
    val italicPlaceholder = stringResource(R.string.theme_store_comments_format_italic_text)
    val codePlaceholder = stringResource(R.string.theme_store_comments_format_code_text)
    val linkPlaceholder = stringResource(R.string.theme_store_comments_format_link_text)
    val newline = System.lineSeparator()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TextButton(
            onClick = { onValueChange(value.applyMarkdown("**", "**", boldPlaceholder)) },
            contentPadding = PaddingValues(horizontal = 8.dp),
            modifier = Modifier.height(32.dp),
        ) {
            Text("B", fontWeight = FontWeight.Bold)
        }
        TextButton(
            onClick = { onValueChange(value.applyMarkdown("*", "*", italicPlaceholder)) },
            contentPadding = PaddingValues(horizontal = 8.dp),
            modifier = Modifier.height(32.dp),
        ) {
            Text("I", fontStyle = FontStyle.Italic)
        }
        TextButton(
            onClick = { onValueChange(value.applyMarkdown("`", "`", codePlaceholder)) },
            contentPadding = PaddingValues(horizontal = 8.dp),
            modifier = Modifier.height(32.dp),
        ) {
            Text("</>", fontFamily = FontFamily.Monospace)
        }
        TextButton(
            onClick = {
                onValueChange(
                    value.applyMarkdown(
                        prefix = "${newline}```${newline}",
                        suffix = "${newline}```${newline}",
                        placeholder = codePlaceholder,
                    ),
                )
            },
            contentPadding = PaddingValues(horizontal = 8.dp),
            modifier = Modifier.height(32.dp),
        ) {
            Text("```", fontFamily = FontFamily.Monospace)
        }
        TextButton(
            onClick = {
                onValueChange(value.applyMarkdown("[", "](https://)", linkPlaceholder))
            },
            contentPadding = PaddingValues(horizontal = 8.dp),
            modifier = Modifier.height(32.dp),
        ) {
            Icon(
                imageVector = Icons.Rounded.Link,
                contentDescription = stringResource(R.string.theme_store_comments_format_link),
                modifier = Modifier.size(18.dp),
            )
        }
        if (onMention != null) {
            AssistChip(
                onClick = onMention,
                enabled = mentionEnabled,
                label = { Text(stringResource(R.string.theme_store_comments_mention_button)) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Rounded.AddComment,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                },
                shape = MaterialTheme.shapes.small,
            )
        }
    }
}

@Composable
internal fun ThemeStoreMentionPickerDialog(
    users: List<AccountUserSummary>,
    loading: Boolean,
    error: String?,
    onQueryChange: (String) -> Unit,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var query by remember { mutableStateOf("") }
    LaunchedEffect(query) {
        if (query.isBlank()) {
            onQueryChange("")
            return@LaunchedEffect
        }
        delay(250.milliseconds)
        onQueryChange(query)
    }
    val platforms = listOf(
        "github",
        "gitee",
        "bilibili",
        "coolapk",
        "telegram",
        "weibo",
        "xiaohongshu",
        "xda",
        "youtube",
        "afdian",
        "twitter",
        "x",
        "zhihu",
        "threads",
        "douyin",
    )
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = MaterialTheme.shapes.extraLarge,
        title = { Text(stringResource(R.string.theme_store_comments_mention_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { value -> query = value.take(32) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    placeholder = {
                        Text(stringResource(R.string.theme_store_comments_mention_search))
                    },
                    shape = MaterialTheme.shapes.extraLarge,
                )
                if (loading) {
                    CircularWavyProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        stroke = Stroke(width = 2f),
                    )
                }
                error?.takeIf { it.isNotBlank() }?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 220.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    users.forEach { user ->
                        val name = user.displayName.ifBlank { user.username }
                        val initial = name.trim().take(1).uppercase(LocalLocale.current.platformLocale)
                            .ifBlank { "?" }
                        TonalCard(
                            onClick = { onSelect("@" + user.username) },
                            modifier = Modifier.fillMaxWidth(),
                            shape = MaterialTheme.shapes.large,
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                        ) {
                            Row(
                                modifier = Modifier.padding(8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(26.dp)
                                        .clip(CircleShape)
                                        .background(MaterialTheme.colorScheme.primary),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Text(
                                        text = initial,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onPrimary,
                                    )
                                    if (user.avatarUrl.isNotBlank()) {
                                        AsyncImage(
                                            model = user.avatarUrl,
                                            contentDescription = null,
                                            contentScale = ContentScale.Crop,
                                            modifier = Modifier.fillMaxSize(),
                                        )
                                    }
                                }
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = name,
                                        style = MaterialTheme.typography.titleSmall,
                                    )
                                    Text(
                                        text = "@" + user.username,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                if (user.isAuthor) {
                                    CommentBadge(
                                        text = stringResource(R.string.theme_store_comments_author_badge),
                                        highlighted = true,
                                    )
                                }
                            }
                        }
                    }
                    if (query.isBlank()) {
                        Text(
                            text = stringResource(R.string.theme_store_comments_mention_hint),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else if (users.isEmpty() && !loading) {
                        Text(
                            text = stringResource(R.string.theme_store_comments_mention_empty),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                Text(
                    text = stringResource(R.string.theme_store_comments_mention_platforms),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    platforms.forEach { platform ->
                        AssistChip(
                            onClick = { onSelect("@$platform") },
                            label = {
                                Text(
                                    text = "@$platform",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                )
                            },
                            shape = MaterialTheme.shapes.small,
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(android.R.string.cancel))
            }
        },
    )
}

@Composable
internal fun ThemeStoreCommentRow(
    comment: ThemeComment,
    isReply: Boolean,
    baseUrl: String,
    token: String,
    loggedIn: Boolean,
    onLoginRequired: () -> Unit,
    onReply: (ThemeComment) -> Unit,
    onDelete: (ThemeComment) -> Unit,
) {
    var menuExpanded by remember { mutableStateOf(false) }
    val clipboard = LocalClipboard.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val avatarUrl = remember(comment.avatarUrl, baseUrl) {
        if (comment.avatarUrl.isBlank()) {
            null
        } else {
            ThemeStoreRepository.assetUrl(baseUrl, comment.avatarUrl)
        }
    }
    val name = comment.displayName.ifBlank { comment.username }.ifBlank {
        stringResource(R.string.theme_store_comments_anonymous)
    }
    val initial = name.trim().take(1).uppercase(LocalLocale.current.platformLocale).ifBlank { "?" }

    Box(modifier = Modifier.fillMaxWidth()) {
        TonalCard(
            modifier = Modifier.fillMaxWidth(),
            containerColor = if (isReply) {
                MaterialTheme.colorScheme.surfaceContainerHigh.copy(alpha = 0.55f)
            } else {
                MaterialTheme.colorScheme.surfaceContainerHigh
            },
            shape = if (isReply) MaterialTheme.shapes.medium else MaterialTheme.shapes.large,
            onClick = { menuExpanded = true },
            onLongClick = { menuExpanded = true },
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(if (isReply) 28.dp else 34.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = initial,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    if (avatarUrl != null) {
                        AsyncImage(
                            model = themeImageRequest(context, avatarUrl, token),
                            contentDescription = name,
                            contentScale = ContentScale.Crop,
                            modifier = Modifier.fillMaxSize(),
                        )
                    }
                }
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Text(
                            text = name,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (comment.isThemeAuthor) {
                            CommentBadge(
                                text = stringResource(R.string.theme_store_comments_author_badge),
                                highlighted = true,
                            )
                        }
                        if (comment.isAdmin) {
                            CommentBadge(
                                text = stringResource(R.string.theme_store_comments_admin_badge),
                                highlighted = true,
                            )
                        }
                        if (comment.visibility == "author") {
                            CommentBadge(
                                text = stringResource(R.string.theme_store_comments_private_badge),
                                highlighted = false,
                            )
                        }
                        if (comment.mentionsMe) {
                            CommentBadge(
                                text = stringResource(R.string.theme_store_comments_mentioned_you),
                                highlighted = true,
                            )
                        }
                        Spacer(Modifier.weight(1f))
                        Text(
                            text = formatCommentTime(comment.createdAt),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.width(2.dp))
                        IconButton(
                            onClick = { menuExpanded = true },
                            modifier = Modifier.size(28.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.MoreVert,
                                contentDescription = stringResource(R.string.theme_store_more),
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                    Text(
                        text = themeStoreMarkdown(comment.content),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }
        }
        DropdownMenu(
            expanded = menuExpanded,
            onDismissRequest = { menuExpanded = false },
            shape = MaterialTheme.shapes.large,
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
            tonalElevation = 0.dp,
            shadowElevation = 3.dp,
        ) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.theme_store_comments_copy)) },
                leadingIcon = { Icon(Icons.Rounded.ContentCopy, contentDescription = null) },
                onClick = {
                    menuExpanded = false
                    val text = comment.content
                    scope.launch {
                        clipboard.setClipEntry(
                            ClipEntry(ClipData.newPlainText("theme comment", text)),
                        )
                    }
                },
            )
            if (comment.canReply || (!loggedIn && comment.visibility == "public")) {
                DropdownMenuItem(
                    text = {
                        Text(
                            stringResource(
                                if (loggedIn) {
                                    R.string.theme_store_comments_reply
                                } else {
                                    R.string.theme_store_comments_login_to_reply
                                },
                            ),
                        )
                    },
                    leadingIcon = { Icon(Icons.Rounded.AddComment, contentDescription = null) },
                    onClick = {
                        menuExpanded = false
                        if (loggedIn) {
                            onReply(comment)
                        } else {
                            onLoginRequired()
                        }
                    },
                )
            }
            if (comment.canDelete) {
                DropdownMenuItem(
                    text = {
                        Text(
                            text = stringResource(R.string.theme_store_comments_delete),
                            color = MaterialTheme.colorScheme.error,
                        )
                    },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Rounded.Delete,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                        )
                    },
                    onClick = {
                        menuExpanded = false
                        onDelete(comment)
                    },
                )
            }
        }
    }
}

@Composable
private fun CommentBadge(text: String, highlighted: Boolean) {
    Surface(
        shape = CircleShape,
        color = if (highlighted) {
            MaterialTheme.colorScheme.primaryContainer
        } else {
            MaterialTheme.colorScheme.tertiaryContainer
        },
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = if (highlighted) {
                MaterialTheme.colorScheme.onPrimaryContainer
            } else {
                MaterialTheme.colorScheme.onTertiaryContainer
            },
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp),
        )
    }
}

@SuppressLint("ConstantLocale")
private val COMMENT_TIME_FORMAT: DateTimeFormatter =
    DateTimeFormatter.ofPattern("MM-dd HH:mm", Locale.getDefault())

private fun formatCommentTime(value: String): String {
    if (value.isBlank()) return ""
    return runCatching {
        Instant.parse(value)
            .atZone(ZoneId.systemDefault())
            .format(COMMENT_TIME_FORMAT)
    }.getOrDefault(value)
}
