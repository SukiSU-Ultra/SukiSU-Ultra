package com.sukisu.ultra.ui.screen.extensions

import android.annotation.SuppressLint
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Update
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.SuSFSManager
import kotlinx.coroutines.launch

/**
 * 统一的按钮布局组件
 */
@Composable
fun UnifiedButtonRow(
    primaryButton: @Composable () -> Unit,
    secondaryButtons: @Composable () -> Unit = {},
    @SuppressLint("ModifierParameter") modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            secondaryButtons()
        }
        primaryButton()
    }
}

/**
 * 空状态显示组件
 */
@Composable
fun EmptyStateCard(
    message: String,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f)
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = message,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }
    }
}

/**
 * 路径项目卡片组件
 */
@Composable
fun PathItemCard(
    path: String,
    icon: ImageVector,
    onDelete: () -> Unit,
    isLoading: Boolean = false,
    additionalInfo: String? = null
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp),
        shape = RoundedCornerShape(8.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(
                        text = path,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium
                    )
                    if (additionalInfo != null) {
                        Text(
                            text = additionalInfo,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            IconButton(
                onClick = onDelete,
                enabled = !isLoading,
                modifier = Modifier.size(32.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Delete,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}

/**
 * Kstat配置项目卡片组件
 */
@Composable
fun KstatConfigItemCard(
    config: String,
    onDelete: () -> Unit,
    isLoading: Boolean = false
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp),
        shape = RoundedCornerShape(8.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    val parts = config.split("|")
                    if (parts.isNotEmpty()) {
                        Text(
                            text = parts[0], // 路径
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.Medium
                        )
                        if (parts.size > 1) {
                            Text(
                                text = "参数: ${parts.drop(1).joinToString(" ")}",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        Text(
                            text = config,
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
            IconButton(
                onClick = onDelete,
                enabled = !isLoading,
                modifier = Modifier.size(32.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Delete,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}

/**
 * Add Kstat路径项目卡片组件
 */
@Composable
fun AddKstatPathItemCard(
    path: String,
    onDelete: () -> Unit,
    onUpdate: () -> Unit,
    onUpdateFullClone: () -> Unit,
    isLoading: Boolean = false
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp),
        shape = RoundedCornerShape(8.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                Icon(
                    imageVector = Icons.Default.Folder,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = path,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                IconButton(
                    onClick = onUpdate,
                    enabled = !isLoading,
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Update,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.secondary,
                        modifier = Modifier.size(16.dp)
                    )
                }
                IconButton(
                    onClick = onUpdateFullClone,
                    enabled = !isLoading,
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.PlayArrow,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.size(16.dp)
                    )
                }
                IconButton(
                    onClick = onDelete,
                    enabled = !isLoading,
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}

/**
 * 启用功能状态卡片组件
 */
@Composable
fun FeatureStatusCard(
    feature: SuSFSManager.EnabledFeature,
    onRefresh: (() -> Unit)? = null,
    @SuppressLint("ModifierParameter") modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    // 日志配置对话框状态
    var showLogConfigDialog by remember { mutableStateOf(false) }
    var logEnabled by remember { mutableStateOf(SuSFSManager.getEnableLogState(context)) }

    // 日志配置对话框
    if (showLogConfigDialog) {
        AlertDialog(
            onDismissRequest = { showLogConfigDialog = false },
            title = {
                Text(
                    text = stringResource(R.string.susfs_log_config_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
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
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.Medium
                        )
                        Switch(
                            checked = logEnabled,
                            onCheckedChange = { logEnabled = it }
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        coroutineScope.launch {
                            if (SuSFSManager.setEnableLog(context, logEnabled)) {
                                onRefresh?.invoke()
                            }
                            showLogConfigDialog = false
                        }
                    },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.susfs_apply))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        // 恢复原始状态
                        logEnabled = SuSFSManager.getEnableLogState(context)
                        showLogConfigDialog = false
                    },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp)
            .then(
                if (feature.canConfigure) {
                    Modifier.clickable {
                        // 更新当前状态
                        logEnabled = SuSFSManager.getEnableLogState(context)
                        showLogConfigDialog = true
                    }
                } else {
                    Modifier
                }
            ),
        shape = RoundedCornerShape(8.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
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
                // 状态标签
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = when {
                        feature.isEnabled -> MaterialTheme.colorScheme.primary
                        else -> Color.Gray
                    }
                ) {
                    Text(
                        text = feature.statusText,
                        style = MaterialTheme.typography.labelLarge,
                        color = when {
                            feature.isEnabled -> MaterialTheme.colorScheme.onPrimary
                            else -> Color.White
                        },
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }
        }
    }
}

/**
 * SUS路径内容组件
 */
@Composable
fun SusPathsContent(
    susPaths: Set<String>,
    isLoading: Boolean,
    onAddPath: () -> Unit,
    onRemovePath: (String) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        UnifiedButtonRow(
            primaryButton = {
                FloatingActionButton(
                    onClick = onAddPath,
                    modifier = Modifier.size(48.dp),
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ) {
                    Icon(
                        imageVector = Icons.Default.Add,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                }
            },
            secondaryButtons = {
                Text(
                    text = stringResource(R.string.susfs_sus_paths_management),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            }
        )

        if (susPaths.isEmpty()) {
            EmptyStateCard(
                message = stringResource(R.string.susfs_no_paths_configured)
            )
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(susPaths.toList()) { path ->
                    PathItemCard(
                        path = path,
                        icon = Icons.Default.Folder,
                        onDelete = { onRemovePath(path) },
                        isLoading = isLoading
                    )
                }
            }
        }
    }
}

/**
 * SUS挂载隐藏控制卡片组件
 */
@Composable
fun SusMountHidingControlCard(
    hideSusMountsForAllProcs: Boolean,
    isLoading: Boolean,
    onToggleHiding: (Boolean) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 标题行
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (hideSusMountsForAllProcs) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.susfs_hide_mounts_control_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }

            // 描述文本
            Text(
                text = stringResource(R.string.susfs_hide_mounts_control_description),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 16.sp
            )

            // 控制开关行
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        text = stringResource(R.string.susfs_hide_mounts_for_all_procs_label),
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = if (hideSusMountsForAllProcs) {
                            stringResource(R.string.susfs_hide_mounts_for_all_procs_enabled_description)
                        } else {
                            stringResource(R.string.susfs_hide_mounts_for_all_procs_disabled_description)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 14.sp
                    )
                }
                Switch(
                    checked = hideSusMountsForAllProcs,
                    onCheckedChange = onToggleHiding,
                    enabled = !isLoading
                )
            }

            // 当前设置显示
            Text(
                text = stringResource(
                    R.string.susfs_hide_mounts_current_setting,
                    if (hideSusMountsForAllProcs) {
                        stringResource(R.string.susfs_hide_mounts_setting_all)
                    } else {
                        stringResource(R.string.susfs_hide_mounts_setting_non_ksu)
                    }
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.Medium
            )

            // 建议文本
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                ),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text(
                    text = stringResource(R.string.susfs_hide_mounts_recommendation),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 14.sp,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }
    }
}

/**
 * SUS挂载内容组件
 */
@Composable
fun SusMountsContent(
    susMounts: Set<String>,
    hideSusMountsForAllProcs: Boolean,
    isSusVersion_1_5_8: Boolean,
    isLoading: Boolean,
    onAddMount: () -> Unit,
    onRemoveMount: (String) -> Unit,
    onToggleHideSusMountsForAllProcs: (Boolean) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        UnifiedButtonRow(
            primaryButton = {
                FloatingActionButton(
                    onClick = onAddMount,
                    modifier = Modifier.size(48.dp),
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ) {
                    Icon(
                        imageVector = Icons.Default.Add,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                }
            },
            secondaryButtons = {
                Text(
                    text = stringResource(R.string.susfs_sus_mounts_management),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            }
        )

        // SUS挂载隐藏控制卡片
        if (isSusVersion_1_5_8) {
            SusMountHidingControlCard(
                hideSusMountsForAllProcs = hideSusMountsForAllProcs,
                isLoading = isLoading,
                onToggleHiding = onToggleHideSusMountsForAllProcs
            )
        }
        if (susMounts.isEmpty()) {
            EmptyStateCard(
                message = stringResource(R.string.susfs_no_mounts_configured)
            )
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(susMounts.toList()) { mount ->
                    PathItemCard(
                        path = mount,
                        icon = Icons.Default.Storage,
                        onDelete = { onRemoveMount(mount) },
                        isLoading = isLoading
                    )
                }
            }
        }
    }
}


/**
 * 尝试卸载内容组件
 */
@Composable
fun TryUmountContent(
    tryUmounts: Set<String>,
    isLoading: Boolean,
    onAddUmount: () -> Unit,
    onRunUmount: () -> Unit,
    onRemoveUmount: (String) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        UnifiedButtonRow(
            primaryButton = {
                FloatingActionButton(
                    onClick = onAddUmount,
                    modifier = Modifier.size(48.dp),
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ) {
                    Icon(
                        imageVector = Icons.Default.Add,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                }
            },
            secondaryButtons = {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.susfs_try_umount_management),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    if (tryUmounts.isNotEmpty()) {
                        FloatingActionButton(
                            onClick = onRunUmount,
                            modifier = Modifier.size(40.dp),
                            containerColor = MaterialTheme.colorScheme.secondary,
                            contentColor = MaterialTheme.colorScheme.onSecondary
                        ) {
                            Icon(
                                imageVector = Icons.Default.PlayArrow,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }
            }
        )

        if (tryUmounts.isEmpty()) {
            EmptyStateCard(
                message = stringResource(R.string.susfs_no_umounts_configured)
            )
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(tryUmounts.toList()) { umountEntry ->
                    val parts = umountEntry.split("|")
                    val path = if (parts.isNotEmpty()) parts[0] else umountEntry
                    val mode = if (parts.size > 1) parts[1] else "0"
                    val modeText = if (mode == "0")
                        stringResource(R.string.susfs_umount_mode_normal_short)
                    else
                        stringResource(R.string.susfs_umount_mode_detach_short)

                    PathItemCard(
                        path = path,
                        icon = Icons.Default.Storage,
                        additionalInfo = stringResource(R.string.susfs_umount_mode_display, modeText, mode),
                        onDelete = { onRemoveUmount(umountEntry) },
                        isLoading = isLoading
                    )
                }
            }
        }
    }
}

/**
 * Kstat配置内容组件
 */
@Composable
fun KstatConfigContent(
    kstatConfigs: Set<String>,
    addKstatPaths: Set<String>,
    isLoading: Boolean,
    onAddKstatStatically: () -> Unit,
    onAddKstat: () -> Unit,
    onRemoveKstatConfig: (String) -> Unit,
    onRemoveAddKstat: (String) -> Unit,
    onUpdateKstat: (String) -> Unit,
    onUpdateKstatFullClone: (String) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 标题和添加按钮
        UnifiedButtonRow(
            primaryButton = {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FloatingActionButton(
                        onClick = onAddKstatStatically,
                        modifier = Modifier.size(48.dp),
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary
                    ) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    FloatingActionButton(
                        onClick = onAddKstat,
                        modifier = Modifier.size(48.dp),
                        containerColor = MaterialTheme.colorScheme.secondary,
                        contentColor = MaterialTheme.colorScheme.onSecondary
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            },
            secondaryButtons = {
                Text(
                    text = stringResource(R.string.kstat_config_management),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            }
        )

        // 说明卡片
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = stringResource(R.string.kstat_config_description_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = stringResource(R.string.kstat_config_description_add_statically),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = stringResource(R.string.kstat_config_description_add),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = stringResource(R.string.kstat_config_description_update),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = stringResource(R.string.kstat_config_description_update_full_clone),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // 静态Kstat配置列表
        if (kstatConfigs.isNotEmpty()) {
            Text(
                text = stringResource(R.string.static_kstat_config),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            LazyColumn(
                modifier = Modifier.weight(0.5f),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(kstatConfigs.toList()) { config ->
                    KstatConfigItemCard(
                        config = config,
                        onDelete = { onRemoveKstatConfig(config) },
                        isLoading = isLoading
                    )
                }
            }
        }

        // Add Kstat路径列表
        if (addKstatPaths.isNotEmpty()) {
            Text(
                text = stringResource(R.string.kstat_path_management),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            LazyColumn(
                modifier = Modifier.weight(0.5f),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(addKstatPaths.toList()) { path ->
                    AddKstatPathItemCard(
                        path = path,
                        onDelete = { onRemoveAddKstat(path) },
                        onUpdate = { onUpdateKstat(path) },
                        onUpdateFullClone = { onUpdateKstatFullClone(path) },
                        isLoading = isLoading
                    )
                }
            }
        }

        // 空状态显示
        if (kstatConfigs.isEmpty() && addKstatPaths.isEmpty()) {
            EmptyStateCard(
                message = stringResource(R.string.no_kstat_config_message)
            )
        }
    }
}