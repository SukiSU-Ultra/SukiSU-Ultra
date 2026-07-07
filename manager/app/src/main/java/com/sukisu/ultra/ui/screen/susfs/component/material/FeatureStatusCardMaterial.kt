package com.sukisu.ultra.ui.screen.susfs.component.material

import android.annotation.SuppressLint
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.util.EnabledFeature
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import kotlinx.coroutines.launch

@Composable
fun FeatureStatusCardMaterial(
    feature: EnabledFeature,
    onRefresh: (() -> Unit)? = null,
    @SuppressLint("ModifierParameter") modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    var showLogConfigDialog by remember { mutableStateOf(false) }
    var logEnabled by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        logEnabled = SuSFSManager.getEnableLogState()
    }

    val showLogConfigDialogState = remember { mutableStateOf(showLogConfigDialog) }

    LaunchedEffect(showLogConfigDialog) {
        showLogConfigDialogState.value = showLogConfigDialog
    }

    if (showLogConfigDialogState.value) {
        AlertDialog(
            onDismissRequest = {
                coroutineScope.launch { logEnabled = SuSFSManager.getEnableLogState() }
                showLogConfigDialog = false
            },
            title = {
                Text(text = stringResource(R.string.susfs_log_config_title))
            },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = stringResource(R.string.susfs_log_config_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = stringResource(R.string.susfs_enable_log_label),
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Switch(
                            checked = logEnabled,
                            onCheckedChange = { checked -> logEnabled = checked }
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        coroutineScope.launch {
                            if (SuSFSManager.setEnableLog(context, logEnabled)) {
                                onRefresh?.invoke()
                            }
                            showLogConfigDialog = false
                        }
                    }
                ) {
                    Text(stringResource(R.string.susfs_apply))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        coroutineScope.launch { logEnabled = SuSFSManager.getEnableLogState() }
                        showLogConfigDialog = false
                    }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp)
            .then(
                if (feature.canConfigure) {
                    Modifier.clickable {
                        coroutineScope.launch { logEnabled = SuSFSManager.getEnableLogState() }
                        showLogConfigDialog = true
                    }
                } else {
                    Modifier
                }
            ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = feature.name,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
                if (feature.canConfigure) {
                    Text(
                        text = stringResource(R.string.susfs_feature_configurable),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(
                            when {
                                feature.isEnabled -> MaterialTheme.colorScheme.primaryContainer
                                else -> MaterialTheme.colorScheme.onSurfaceVariant
                            }
                        )
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = feature.statusText,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = when {
                            feature.isEnabled -> MaterialTheme.colorScheme.onPrimaryContainer
                            else -> MaterialTheme.colorScheme.surface
                        }
                    )
                }
            }
        }
    }
}
