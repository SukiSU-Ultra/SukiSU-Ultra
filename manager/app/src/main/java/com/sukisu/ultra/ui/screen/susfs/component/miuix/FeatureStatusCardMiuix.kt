package com.sukisu.ultra.ui.screen.susfs.component.miuix

import android.annotation.SuppressLint
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
fun FeatureStatusCardMiuix(
    feature: SuSFSManager.EnabledFeature,
    onRefresh: (() -> Unit)? = null,
    @SuppressLint("ModifierParameter") modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    var showLogConfigDialog by remember { mutableStateOf(false) }
    var logEnabled by remember { mutableStateOf(SuSFSManager.getEnableLogState(context)) }

    val showLogConfigDialogState = remember { mutableStateOf(showLogConfigDialog) }

    LaunchedEffect(showLogConfigDialog) {
        showLogConfigDialogState.value = showLogConfigDialog
    }

    if (showLogConfigDialogState.value) {
        OverlayDialog(
            show = showLogConfigDialogState.value,
            title = stringResource(R.string.susfs_log_config_title),
            onDismissRequest = {
                logEnabled = SuSFSManager.getEnableLogState(context)
                showLogConfigDialog = false
            },
            content = {
                Column(
                    modifier = Modifier
                        .padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = stringResource(R.string.susfs_log_config_description),
                        style = MiuixTheme.textStyles.body2,
                        color = colorScheme.onSurfaceVariantSummary
                    )

                    SwitchPreference(
                        title = stringResource(R.string.susfs_enable_log_label),
                        summary = "",
                        checked = logEnabled,
                        onCheckedChange = { checked -> logEnabled = checked }
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = {
                                logEnabled = SuSFSManager.getEnableLogState(context)
                                showLogConfigDialog = false
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(
                                text = stringResource(R.string.cancel)
                            )
                        }
                        Button(
                            onClick = {
                                coroutineScope.launch {
                                    if (SuSFSManager.setEnableLog(context, logEnabled)) {
                                        onRefresh?.invoke()
                                    }
                                    showLogConfigDialog = false
                                }
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(
                                text = stringResource(R.string.susfs_apply)
                            )
                        }
                    }
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
                        logEnabled = SuSFSManager.getEnableLogState(context)
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
                    style = MiuixTheme.textStyles.body1,
                    fontWeight = FontWeight.Medium
                )
                if (feature.canConfigure) {
                    Text(
                        text = stringResource(R.string.susfs_feature_configurable),
                        style = MiuixTheme.textStyles.body2,
                        color = colorScheme.onSurfaceVariantSummary
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
                                feature.isEnabled -> colorScheme.primaryContainer
                                else -> colorScheme.onSurfaceVariantSummary
                            }
                        )
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = feature.statusText,
                        style = MiuixTheme.textStyles.body2,
                        fontWeight = FontWeight.Medium,
                        color = when {
                            feature.isEnabled -> colorScheme.onPrimaryContainer
                            else -> colorScheme.onSurface
                        }
                    )
                }
            }
        }
    }
}
