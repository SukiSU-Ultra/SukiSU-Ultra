package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveConfirmDialog
import com.sukisu.ultra.ui.component.material.ExpressiveDialog
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.ExpressiveSwitch
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors

@Composable
internal fun ThemeStoreConsentDialog(
    alreadyAccepted: Boolean,
    onAccept: () -> Unit,
    onDismiss: () -> Unit,
) {
    val scrollState = rememberScrollState()
    ExpressiveDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.theme_store_consent_title)) },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 340.dp)
                    .verticalScroll(scrollState),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    stringResource(R.string.theme_store_consent_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.theme_store_consent_r18_notice),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = if (alreadyAccepted) onDismiss else onAccept,
                shapes = ButtonDefaults.shapes(),
            ) {
                Text(
                    stringResource(
                        if (alreadyAccepted) R.string.theme_store_consent_close
                        else R.string.theme_store_consent_accept,
                    ),
                )
            }
        },
        dismissButton = if (alreadyAccepted) {
            null
        } else {
            {
                FilledTonalButton(onClick = onDismiss, shapes = ButtonDefaults.shapes()) {
                    Text(stringResource(R.string.theme_store_consent_decline))
                }
            }
        },
    )
}

@Composable
internal fun ThemeStorePreferencesScreen(
    consentAccepted: Boolean,
    showR18: Boolean,
    onToggleShowR18: (Boolean) -> Unit,
    onRequestConsent: () -> Unit,
    onRevokeConsent: () -> Unit,
    onBack: () -> Unit,
) {
    var showAgreement by remember { mutableStateOf(false) }
    var showRevokeConfirm by remember { mutableStateOf(false) }
    val pageContainer = MaterialTheme.colorScheme.surface

    ExpressiveScaffold(
        containerColor = pageContainer,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.theme_store_preferences)) },
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 18.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                ),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        stringResource(R.string.theme_store_consent_section),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        stringResource(
                            if (consentAccepted) {
                                R.string.theme_store_consent_status_accepted
                            } else {
                                R.string.theme_store_consent_status_revoked
                            },
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (consentAccepted) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.error
                        },
                    )
                    Text(
                        stringResource(
                            if (consentAccepted) {
                                R.string.theme_store_consent_connected_hint
                            } else {
                                R.string.theme_store_consent_revoked_hint
                            },
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (consentAccepted) {
                            FilledTonalButton(
                                onClick = { showRevokeConfirm = true },
                                shapes = ButtonDefaults.shapes(),
                                colors = ButtonDefaults.filledTonalButtonColors(
                                    containerColor = MaterialTheme.colorScheme.errorContainer,
                                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                                ),
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text(stringResource(R.string.theme_store_consent_revoke))
                            }
                        } else {
                            Button(
                                onClick = onRequestConsent,
                                shapes = ButtonDefaults.shapes(),
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text(stringResource(R.string.theme_store_consent_reagree))
                            }
                        }
                        FilledTonalButton(
                            onClick = { showAgreement = true },
                            shapes = ButtonDefaults.shapes(),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(R.string.theme_store_consent_view))
                        }
                    }
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                ),
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                stringResource(R.string.theme_store_show_r18),
                                style = MaterialTheme.typography.titleMedium,
                            )
                            Spacer(Modifier.size(4.dp))
                            Text(
                                stringResource(R.string.theme_store_show_r18_summary),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        ExpressiveSwitch(
                            checked = showR18,
                            onCheckedChange = onToggleShowR18,
                            enabled = consentAccepted,
                        )
                    }
                    Text(
                        stringResource(
                            if (consentAccepted) {
                                R.string.theme_store_show_r18_sync_hint
                            } else {
                                R.string.theme_store_show_r18_need_consent
                            },
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (consentAccepted) {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        } else {
                            MaterialTheme.colorScheme.error
                        },
                    )
                }
            }
        }
    }

    if (showAgreement) {
        ThemeStoreConsentDialog(
            alreadyAccepted = consentAccepted,
            onAccept = { showAgreement = false },
            onDismiss = { showAgreement = false },
        )
    }
    if (showRevokeConfirm) {
        ExpressiveConfirmDialog(
            title = stringResource(R.string.theme_store_consent_revoke_title),
            message = stringResource(R.string.theme_store_consent_revoke_message),
            confirmText = stringResource(R.string.theme_store_consent_revoke),
            dismissText = stringResource(R.string.cancel),
            onConfirm = {
                showRevokeConfirm = false
                onRevokeConsent()
            },
            onDismiss = { showRevokeConfirm = false },
        )
    }
}

@Composable
internal fun ThemeStoreConsentRequiredMaterial(
    onRequestConsent: () -> Unit,
    onOpenPreferences: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            imageVector = Icons.Rounded.Lock,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(40.dp),
        )
        Spacer(Modifier.size(8.dp))
        Text(
            stringResource(R.string.theme_store_consent_required_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.size(4.dp))
        Text(
            stringResource(R.string.theme_store_consent_required_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.size(12.dp))
        Button(onClick = onRequestConsent, shapes = ButtonDefaults.shapes()) {
            Text(stringResource(R.string.theme_store_consent_accept))
        }
        FilledTonalButton(onClick = onOpenPreferences, shapes = ButtonDefaults.shapes()) {
            Text(stringResource(R.string.theme_store_preferences))
        }
    }
}
