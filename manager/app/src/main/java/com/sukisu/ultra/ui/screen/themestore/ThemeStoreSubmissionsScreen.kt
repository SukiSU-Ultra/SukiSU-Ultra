package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton

/**
 * Aggregated user content across every logged-in mirror source: editable themes, the newest
 * submissions and withdrawn themes that can still be restored.
 */
@Composable
internal fun ThemeStoreSubmissionsScreen(
    accounts: List<ThemeStoreAccount>,
    themes: List<UserTheme>,
    submissions: List<UserSubmission>,
    submissionsLoading: Boolean,
    submissionsError: String?,
    withdrawnThemes: List<UserTheme>,
    withdrawingThemeKey: String?,
    withdrawError: String?,
    restoringThemeKey: String?,
    restoreError: String?,
    onRefresh: () -> Unit,
    onEditTheme: (UserTheme) -> Unit,
    onWithdrawTheme: (UserSubmission) -> Unit,
    onRestoreTheme: (UserTheme) -> Unit,
    onBack: () -> Unit,
    onLogin: () -> Unit,
    onOpenWeb: (ThemeStoreAccount) -> Unit,
) {
    var confirmWithdraw by remember { mutableStateOf<UserSubmission?>(null) }
    var confirmRestore by remember { mutableStateOf<UserTheme?>(null) }
    var themeQuery by rememberSaveable { mutableStateOf("") }
    val recentSubmissions = remember(submissions) { submissions.latestUserSubmissions() }
    val editableThemes = remember(themes) {
        themes.sortedWith(compareByDescending { it.theme.updatedAt.orEmpty() })
    }
    val filteredThemes = remember(editableThemes, themeQuery) {
        val normalized = themeQuery.trim()
        if (normalized.isEmpty()) {
            editableThemes
        } else {
            editableThemes.filter { userTheme ->
                userTheme.theme.id.contains(normalized, ignoreCase = true) ||
                    userTheme.theme.name.contains(normalized, ignoreCase = true)
            }
        }
    }
    val container = MaterialTheme.colorScheme.surface

    ExpressiveScaffold(
        containerColor = container,
        topBar = {
            TopAppBar(
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                title = { Text(stringResource(R.string.theme_store_my_content_title)) },
                subtitle = {
                    Text(
                        text = stringResource(
                            R.string.theme_store_connected_sources,
                            accounts.size,
                        ),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                actions = {
                    IconButton(
                        onClick = onRefresh,
                        enabled = accounts.isNotEmpty() && !submissionsLoading,
                        colors = themeStoreTopBarIconColors(),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Refresh,
                            contentDescription = stringResource(R.string.theme_store_upload_refresh),
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = container,
                    scrolledContainerColor = container,
                ),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(
                start = 18.dp,
                end = 18.dp,
                top = 10.dp,
                bottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 24.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            if (accounts.isEmpty()) {
                item(key = "login") {
                    SubmissionsLoginCard(onLogin = onLogin)
                }
            } else {
                item(key = "themes") {
                    ThemeStoreSectionCard(
                        title = stringResource(R.string.theme_store_my_themes_title),
                        icon = Icons.Rounded.Palette,
                    ) {
                        if (editableThemes.isNotEmpty()) {
                            OutlinedTextField(
                                value = themeQuery,
                                onValueChange = { themeQuery = it },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                shape = MaterialTheme.shapes.large,
                                label = {
                                    Text(stringResource(R.string.theme_store_my_themes_search))
                                },
                                leadingIcon = {
                                    Icon(
                                        imageVector = Icons.Rounded.Search,
                                        contentDescription = null,
                                    )
                                },
                                trailingIcon = {
                                    if (themeQuery.isNotEmpty()) {
                                        IconButton(onClick = { themeQuery = "" }) {
                                            Icon(
                                                imageVector = Icons.Rounded.Close,
                                                contentDescription = stringResource(
                                                    R.string.theme_store_clear_search,
                                                ),
                                            )
                                        }
                                    }
                                },
                            )
                        }
                        when {
                            submissionsLoading && editableThemes.isEmpty() -> Row(
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                CircularWavyProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    stroke = Stroke(width = 2f),
                                )
                                Spacer(Modifier.width(8.dp))
                                SubmissionHint(
                                    stringResource(R.string.theme_store_upload_submissions_loading),
                                )
                            }

                            editableThemes.isEmpty() -> SubmissionHint(
                                stringResource(R.string.theme_store_my_themes_empty),
                            )

                            filteredThemes.isEmpty() -> SubmissionHint(
                                stringResource(R.string.theme_store_my_themes_no_match),
                            )

                            else -> filteredThemes.forEachIndexed { index, theme ->
                                EditableThemeRow(
                                    theme = theme,
                                    onEdit = { onEditTheme(theme) },
                                )
                                if (index != filteredThemes.lastIndex) {
                                    HorizontalDivider(
                                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                                    )
                                }
                            }
                        }
                    }
                }
                item(key = "recent") {
                    ThemeStoreSectionCard(
                        title = stringResource(R.string.theme_store_upload_submissions_recent),
                        icon = Icons.Rounded.History,
                    ) {
                        when {
                            submissionsLoading && submissions.isEmpty() -> Row(
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                CircularWavyProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    stroke = Stroke(width = 2f),
                                )
                                Spacer(Modifier.width(8.dp))
                                SubmissionHint(
                                    stringResource(R.string.theme_store_upload_submissions_loading),
                                )
                            }

                            !submissionsError.isNullOrBlank() && submissions.isEmpty() ->
                                ThemeStoreInlineNotice(
                                    text = submissionsError,
                                    isError = true,
                                )

                            submissions.isEmpty() -> SubmissionHint(
                                stringResource(R.string.theme_store_upload_submissions_empty),
                            )

                            else -> recentSubmissions.forEachIndexed { index, submission ->
                                SubmissionRow(
                                    submission = submission,
                                    withdrawing = withdrawingThemeKey == submission.key,
                                    withdrawEnabled = withdrawingThemeKey == null,
                                    onWithdraw = { confirmWithdraw = submission },
                                )
                                if (index != recentSubmissions.lastIndex) {
                                    HorizontalDivider(
                                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                                    )
                                }
                            }
                        }
                        if (!submissionsError.isNullOrBlank() && submissions.isNotEmpty()) {
                            ThemeStoreInlineNotice(
                                text = submissionsError,
                                isError = true,
                            )
                        }
                        if (withdrawError != null) {
                            ThemeStoreInlineNotice(
                                text = withdrawError,
                                isError = true,
                            )
                        }
                    }
                }
                item(key = "web") {
                    ThemeStoreSectionCard(
                        title = stringResource(R.string.theme_store_open_web),
                        icon = Icons.AutoMirrored.Rounded.OpenInNew,
                    ) {
                        SubmissionHint(
                            stringResource(R.string.theme_store_submissions_recent_limit),
                        )
                        accounts.forEach { account ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = account.source.displayName(),
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                    Text(
                                        text = "@${account.session.user.username}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                TextButton(
                                    onClick = { onOpenWeb(account) },
                                    shapes = ButtonDefaults.shapes(),
                                ) {
                                    Icon(
                                        imageVector = Icons.AutoMirrored.Rounded.OpenInNew,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp),
                                    )
                                    Spacer(Modifier.width(6.dp))
                                    Text(stringResource(R.string.theme_store_open_web))
                                }
                            }
                        }
                    }
                }
                if (withdrawnThemes.isNotEmpty()) {
                    item(key = "withdrawn") {
                        ThemeStoreSectionCard(
                            title = stringResource(R.string.theme_store_upload_withdrawn_title),
                            icon = Icons.Rounded.Restore,
                        ) {
                            withdrawnThemes.forEachIndexed { index, theme ->
                                WithdrawnThemeRow(
                                    theme = theme,
                                    restoring = restoringThemeKey == theme.key,
                                    restoreEnabled = restoringThemeKey == null,
                                    onRestore = { confirmRestore = theme },
                                )
                                if (index != withdrawnThemes.lastIndex) {
                                    HorizontalDivider(
                                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                                    )
                                }
                            }
                            if (restoreError != null) {
                                ThemeStoreInlineNotice(
                                    text = restoreError,
                                    isError = true,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    confirmWithdraw?.let { submission ->
        val item = submission.submission
        AlertDialog(
            onDismissRequest = { confirmWithdraw = null },
            shape = MaterialTheme.shapes.extraLarge,
            title = {
                Text(stringResource(R.string.theme_store_upload_withdraw_title))
            },
            text = {
                Text(
                    stringResource(
                        R.string.theme_store_upload_withdraw_confirm,
                        item.name
                            ?.takeIf { it.isNotBlank() }
                            ?: item.id.ifBlank { item.submissionId },
                    ),
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmWithdraw = null
                        onWithdrawTheme(submission)
                    },
                    shapes = ButtonDefaults.shapes(),
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Text(stringResource(R.string.theme_store_upload_withdraw))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { confirmWithdraw = null },
                    shapes = ButtonDefaults.shapes(),
                ) {
                    Text(stringResource(R.string.theme_store_upload_cancel))
                }
            },
        )
    }
    confirmRestore?.let { theme ->
        val item = theme.theme
        AlertDialog(
            onDismissRequest = { confirmRestore = null },
            shape = MaterialTheme.shapes.extraLarge,
            title = {
                Text(stringResource(R.string.theme_store_upload_restore_title))
            },
            text = {
                Text(
                    stringResource(
                        R.string.theme_store_upload_restore_confirm,
                        item.name.ifBlank { item.id },
                    ),
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmRestore = null
                        onRestoreTheme(theme)
                    },
                    shapes = ButtonDefaults.shapes(),
                ) {
                    Text(stringResource(R.string.theme_store_upload_restore))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { confirmRestore = null },
                    shapes = ButtonDefaults.shapes(),
                ) {
                    Text(stringResource(R.string.theme_store_upload_cancel))
                }
            },
        )
    }
}

@Composable
private fun SubmissionRow(
    submission: UserSubmission,
    withdrawing: Boolean,
    withdrawEnabled: Boolean,
    onWithdraw: () -> Unit,
) {
    val item = submission.submission
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = item.name
                    ?.takeIf { it.isNotBlank() }
                    ?: item.id.ifBlank { item.submissionId },
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                text = if (item.sha256.isNotBlank()) {
                    stringResource(
                        R.string.theme_store_upload_submission_meta,
                        item.version,
                        item.id.ifBlank { "—" },
                        item.sha256.take(16),
                    )
                } else {
                    stringResource(
                        R.string.theme_store_upload_submission_meta_no_sha,
                        item.version,
                        item.id.ifBlank { "—" },
                    )
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = submission.account.source.displayName(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            item.rejectReason?.takeIf { it.isNotBlank() }?.let { reason ->
                Text(
                    text = stringResource(
                        R.string.theme_store_upload_submission_reason,
                        reason,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
        ThemeStoreStatusBadge(status = item.status)
        if (item.status == "approved") {
            TextButton(
                onClick = onWithdraw,
                enabled = withdrawEnabled,
                shapes = ButtonDefaults.shapes(),
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colorScheme.error,
                    disabledContentColor = MaterialTheme.colorScheme.error.copy(alpha = 0.38f),
                ),
            ) {
                if (withdrawing) {
                    CircularWavyProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        color = MaterialTheme.colorScheme.error,
                        trackColor = MaterialTheme.colorScheme.error.copy(alpha = 0.24f),
                        stroke = Stroke(width = 2f),
                    )
                } else {
                    Text(stringResource(R.string.theme_store_upload_withdraw))
                }
            }
        }
    }
}

@Composable
private fun EditableThemeRow(
    theme: UserTheme,
    onEdit: () -> Unit,
) {
    val item = theme.theme
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = item.name.ifBlank { item.id },
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = stringResource(
                    R.string.theme_store_upload_submission_meta_no_sha,
                    item.version,
                    item.id,
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = theme.account.source.displayName(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        TextButton(
            onClick = onEdit,
            shapes = ButtonDefaults.shapes(),
        ) {
            Text(stringResource(R.string.theme_store_edit))
        }
    }
}

@Composable
private fun WithdrawnThemeRow(
    theme: UserTheme,
    restoring: Boolean,
    restoreEnabled: Boolean,
    onRestore: () -> Unit,
) {
    val item = theme.theme
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = item.name.ifBlank { item.id },
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = stringResource(
                    R.string.theme_store_upload_submission_meta_no_sha,
                    item.version,
                    item.id,
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = theme.account.source.displayName(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val expires = item.expiresAt
                ?.replace('T', ' ')
                ?.take(16)
                .orEmpty()
            if (expires.isNotBlank()) {
                Text(
                    text = stringResource(
                        R.string.theme_store_upload_withdrawn_until,
                        expires,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary,
                )
            }
        }
        TextButton(
            onClick = onRestore,
            enabled = restoreEnabled,
            shapes = ButtonDefaults.shapes(),
        ) {
            if (restoring) {
                CircularWavyProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    stroke = Stroke(width = 2f),
                )
            } else {
                Text(stringResource(R.string.theme_store_upload_restore))
            }
        }
    }
}

@Composable
private fun SubmissionsLoginCard(onLogin: () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(
                imageVector = Icons.Rounded.History,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(40.dp),
            )
            Text(
                text = stringResource(R.string.theme_store_submissions_login_required),
                style = MaterialTheme.typography.titleMedium,
            )
            Button(
                onClick = onLogin,
                modifier = Modifier.fillMaxWidth(),
                shapes = ButtonDefaults.shapes(),
            ) {
                Text(stringResource(R.string.account_login))
            }
        }
    }
}

@Composable
private fun SubmissionHint(text: String, isError: Boolean = false) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = if (isError) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
    )
}
