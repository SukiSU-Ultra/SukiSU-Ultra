package com.sukisu.ultra.ui.screen.account

import android.content.Intent
import android.net.Uri
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.navigation3.LocalNavigator

@Composable
fun AccountScreen(viewModel: AccountViewModel = viewModel()) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val navigator = LocalNavigator.current
    val context = LocalContext.current

    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                navigationIcon = { TopBarBackButton(onClick = { navigator.pop() }) },
                title = { Text(stringResource(R.string.account_title)) },
                colors = expressiveTopAppBarColors(),
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
                .padding(padding)
                .padding(horizontal = 18.dp),
            contentPadding = PaddingValues(top = 12.dp, bottom = 36.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            item {
                SourceSelectorCard(
                    sources = state.sources,
                    sessions = state.sessions,
                    selectedBaseUrl = state.baseUrl,
                    defaultUploadBaseUrl = state.defaultUploadBaseUrl,
                    onSelect = viewModel::selectSource,
                    onSetDefaultUploadSource = viewModel::setDefaultUploadSource,
                )
            }
            item {
                key(state.baseUrl) {
                    val session = state.session
                    if (session == null) {
                        AuthCard(state = state, viewModel = viewModel)
                    } else {
                        ProfileCard(
                            session = session,
                            state = state,
                            onRefresh = viewModel::refresh,
                            onLogout = viewModel::logout,
                            onOpenWeb = {
                                viewModel.accountUrl()?.let { url ->
                                    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
                                }
                            },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SourceSelectorCard(
    sources: List<AccountSource>,
    sessions: Map<String, AccountSession>,
    selectedBaseUrl: String,
    defaultUploadBaseUrl: String,
    onSelect: (String) -> Unit,
    onSetDefaultUploadSource: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val selected = sources.firstOrNull { it.baseUrl == selectedBaseUrl }
    val defaultUploadSource = sources.firstOrNull { it.baseUrl == defaultUploadBaseUrl }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                stringResource(R.string.account_source),
                style = MaterialTheme.typography.titleMedium,
            )
            Box {
                OutlinedButton(
                    onClick = { expanded = true },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                ) {
                    Column(
                        modifier = Modifier.weight(1f),
                        horizontalAlignment = Alignment.Start,
                    ) {
                        Text(sourceLabel(selected), style = MaterialTheme.typography.bodyLarge)
                        selected?.baseUrl?.takeIf { it.isNotBlank() }?.let { baseUrl ->
                            Text(
                                baseUrl,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                    Icon(
                        imageVector = Icons.Rounded.KeyboardArrowDown,
                        contentDescription = null,
                    )
                }
                DropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false },
                ) {
                    sources.forEach { source ->
                        val session = sessions[source.baseUrl]
                        DropdownMenuItem(
                            text = {
                                Column {
                                    Text(sourceLabel(source), style = MaterialTheme.typography.bodyLarge)
                                    Text(
                                        if (session != null) {
                                            stringResource(
                                                R.string.account_source_signed_in,
                                                session.user.username,
                                            )
                                        } else {
                                            stringResource(R.string.account_source_signed_out)
                                        },
                                        style = MaterialTheme.typography.bodySmall,
                                        color = if (session != null) {
                                            MaterialTheme.colorScheme.primary
                                        } else {
                                            MaterialTheme.colorScheme.onSurfaceVariant
                                        },
                                    )
                                }
                            },
                            onClick = {
                                expanded = false
                                onSelect(source.baseUrl)
                            },
                        )
                    }
                }
            }
            Text(
                stringResource(R.string.account_sources_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            HorizontalDivider()
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    Text(
                        stringResource(R.string.account_default_upload_source),
                        style = MaterialTheme.typography.labelLarge,
                    )
                    Text(
                        sourceLabel(defaultUploadSource),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (selectedBaseUrl == defaultUploadBaseUrl) {
                    Text(
                        stringResource(R.string.account_default_upload_source_current),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                } else {
                    TextButton(
                        onClick = { onSetDefaultUploadSource(selectedBaseUrl) },
                        enabled = sessions[selectedBaseUrl] != null,
                    ) {
                        Text(stringResource(R.string.account_set_default_upload_source))
                    }
                }
            }
        }
    }
}

@Composable
private fun sourceLabel(source: AccountSource?): String = when {
    source == null -> ""
    source.isDefault && source.name.isBlank() -> stringResource(R.string.theme_store_default_source)
    source.name.isNotBlank() -> source.name
    else -> source.baseUrl.removePrefix("https://").removePrefix("http://").removeSuffix("/")
}

@Composable
private fun AuthCard(state: AccountUiState, viewModel: AccountViewModel) {
    var login by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var register by remember { mutableStateOf(false) }
    var username by remember { mutableStateOf("") }
    var displayName by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var registerPassword by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    val baseUrl = state.baseUrl
    val context = LocalContext.current

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(
                stringResource(
                    if (register) R.string.account_register_title
                    else R.string.account_login_title,
                ),
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                stringResource(R.string.account_auth_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (state.message != null) {
                Text(state.message, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall)
            }
            if (state.error != null) {
                Text(state.error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }

            if (!register) {
                OutlinedTextField(
                    value = login,
                    onValueChange = { login = it },
                    label = { Text(stringResource(R.string.account_login_field)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(stringResource(R.string.account_password)) },
                    singleLine = true,
                    visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { showPassword = !showPassword }) {
                            Icon(
                                if (showPassword) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility,
                                contentDescription = stringResource(R.string.account_show_password),
                            )
                        }
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = { viewModel.login(state.baseUrl, login.trim(), password) },
                    enabled = !state.submitting && login.isNotBlank() && password.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    if (state.submitting) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    } else {
                        Text(stringResource(R.string.account_login))
                    }
                }
                TextButton(onClick = { register = true; viewModel.clearNotice() }) {
                    Text(stringResource(R.string.account_register_link))
                }
                TextButton(
                    onClick = {
                        viewModel.accountUrl()?.let { url ->
                            runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
                        }
                    },
                ) {
                    Text(stringResource(R.string.account_web_links))
                }
            } else {
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text(stringResource(R.string.account_username)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = displayName,
                    onValueChange = { displayName = it },
                    label = { Text(stringResource(R.string.account_author_display)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = { Text(stringResource(R.string.account_email)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = registerPassword,
                    onValueChange = { registerPassword = it },
                    label = { Text(stringResource(R.string.account_password_min)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = {
                        viewModel.register(
                            baseUrl = baseUrl,
                            username = username.trim(),
                            displayName = displayName.trim(),
                            email = email.trim(),
                            password = registerPassword,
                        )
                    },
                    enabled = !state.submitting && username.isNotBlank() && email.isNotBlank() && registerPassword.length >= 8,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    if (state.submitting) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    } else {
                        Text(stringResource(R.string.account_register))
                    }
                }
                TextButton(onClick = { register = false; viewModel.clearNotice() }) {
                    Text(stringResource(R.string.account_login_link))
                }
            }
        }
    }
}

@Composable
private fun ProfileCard(
    session: AccountSession,
    state: AccountUiState,
    onRefresh: () -> Unit,
    onLogout: () -> Unit,
    onOpenWeb: () -> Unit,
) {
    val user = session.user
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(user.displayName.ifBlank { user.username }, style = MaterialTheme.typography.headlineSmall)
                    Text("@${user.username}${user.email?.let { " · $it" } ?: ""}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text(
                    when (user.status) {
                        "active" -> stringResource(R.string.account_status_active)
                        "pending" -> stringResource(R.string.account_status_pending)
                        "email_pending" -> stringResource(R.string.account_status_email_pending)
                        "rejected" -> stringResource(R.string.account_status_rejected)
                        "disabled" -> stringResource(R.string.account_status_disabled)
                        else -> user.status
                    },
                    color = if (user.status == "active") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.labelLarge,
                )
            }
            if (user.status == "pending" || user.status == "email_pending") {
                Text(
                    stringResource(R.string.account_pending_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (!user.emailVerified) {
                Text(
                    stringResource(R.string.account_email_unverified),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            HorizontalDivider()
            Text(
                stringResource(R.string.account_author_section),
                style = MaterialTheme.typography.titleMedium,
            )
            val author = session.activeAuthor
            if (author == null) {
                Text(
                    stringResource(R.string.account_author_none),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Text(
                    author.displayName ?: stringResource(R.string.account_author_unnamed),
                    style = MaterialTheme.typography.bodyLarge,
                )
                Text(
                    author.fingerprint,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(
                        if (author.autoPublish) R.string.account_author_auto_publish
                        else R.string.account_author_review,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (state.error != null) {
                Text(state.error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onRefresh, enabled = !state.loading) {
                    if (state.loading) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                    else Text(stringResource(R.string.account_refresh))
                }
                TextButton(onClick = onOpenWeb) {
                    Text(stringResource(R.string.account_open_web))
                }
                TextButton(onClick = onLogout) {
                    Text(stringResource(R.string.account_logout))
                }
            }
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(R.string.account_web_manage_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
