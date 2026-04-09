package com.sukisu.ultra.ui.screen.susfs.component.miuix

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Storage
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.util.isAbDevice
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import kotlin.collections.forEach

@Composable
fun SlotInfoDialogMiuix(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    slotInfoList: List<SuSFSManager.SlotInfo>,
    currentActiveSlot: String,
    isLoadingSlotInfo: Boolean,
    onRefresh: () -> Unit,
    onUseUname: (String) -> Unit,
    onUseBuildTime: (String) -> Unit
) {
    val isAbDevice = produceState(initialValue = false) {
        value = isAbDevice()
    }.value

    val showDialogState = remember { mutableStateOf(showDialog && isAbDevice) }

    LaunchedEffect(showDialog, isAbDevice) {
        showDialogState.value = showDialog && isAbDevice
    }

    if (showDialogState.value) {
        OverlayDialog(
            show = showDialogState.value,
            title = stringResource(R.string.susfs_slot_info_title),
            onDismissRequest = onDismiss,
            content = {
                Column(
                    modifier = Modifier.padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = stringResource(R.string.susfs_current_active_slot, currentActiveSlot),
                        style = MiuixTheme.textStyles.body2,
                        fontWeight = FontWeight.Medium,
                        color = colorScheme.primary
                    )

                    if (slotInfoList.isNotEmpty()) {
                        slotInfoList.forEach { slotInfo ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.defaultColors(
                                    if (slotInfo.slotName == currentActiveSlot) {
                                        colorScheme.primary.copy(alpha = 0.1f)
                                    } else {
                                        colorScheme.surface.copy(alpha = 0.5f)
                                    }
                                ),
                                cornerRadius = 8.dp
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Storage,
                                            contentDescription = null,
                                            tint = if (slotInfo.slotName == currentActiveSlot) {
                                                colorScheme.primary
                                            } else {
                                                colorScheme.onSurface
                                            },
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = slotInfo.slotName,
                                            style = MiuixTheme.textStyles.body1,
                                            fontWeight = FontWeight.Bold,
                                            color = if (slotInfo.slotName == currentActiveSlot) {
                                                colorScheme.primary
                                            } else {
                                                colorScheme.onSurface
                                            }
                                        )
                                        if (slotInfo.slotName == currentActiveSlot) {
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Box(
                                                modifier = Modifier
                                                    .background(
                                                        color = colorScheme.primary,
                                                        shape = RoundedCornerShape(4.dp)
                                                    )
                                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                                            ) {
                                                Text(
                                                    text = stringResource(R.string.susfs_slot_current_badge),
                                                    style = MiuixTheme.textStyles.body2,
                                                    color = colorScheme.onPrimary
                                                )
                                            }
                                        }
                                    }
                                    Text(
                                        text = stringResource(R.string.susfs_slot_uname, slotInfo.uname),
                                        style = MiuixTheme.textStyles.body2.copy(fontSize = 13.sp),
                                        color = colorScheme.onSurface
                                    )
                                    Text(
                                        text = stringResource(R.string.susfs_slot_build_time, slotInfo.buildTime),
                                        style = MiuixTheme.textStyles.body2.copy(fontSize = 13.sp),
                                        color = colorScheme.onSurface
                                    )

                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Button(
                                            onClick = { onUseUname(slotInfo.uname) },
                                            modifier = Modifier
                                                .weight(1f)
                                                .heightIn(min = 48.dp)
                                                .padding(vertical = 8.dp),
                                            cornerRadius = 8.dp
                                        ) {
                                            Text(
                                                text = stringResource(R.string.susfs_slot_use_uname),
                                                style = MiuixTheme.textStyles.body2,
                                                maxLines = 2
                                            )
                                        }
                                        Button(
                                            onClick = { onUseBuildTime(slotInfo.buildTime) },
                                            modifier = Modifier
                                                .weight(1f)
                                                .heightIn(min = 48.dp)
                                                .padding(vertical = 8.dp),
                                            cornerRadius = 8.dp
                                        ) {
                                            Text(
                                                text = stringResource(R.string.susfs_slot_use_build_time),
                                                style = MiuixTheme.textStyles.body2,
                                                maxLines = 2
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        Text(
                            text = stringResource(R.string.susfs_slot_info_unavailable),
                            style = MiuixTheme.textStyles.body2,
                            color = colorScheme.error
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Button(
                        onClick = onRefresh,
                        enabled = !isLoadingSlotInfo,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .padding(vertical = 8.dp),
                        cornerRadius = 8.dp
                    ) {
                        Text(
                            text = stringResource(R.string.refresh)
                        )
                    }

                    Button(
                        onClick = onDismiss,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .padding(vertical = 8.dp),
                        cornerRadius = 8.dp
                    ) {
                        Text(
                            text = stringResource(android.R.string.cancel)
                        )
                    }
                }
            }
        )
    }
}