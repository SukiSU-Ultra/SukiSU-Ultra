package com.sukisu.ultra.ui.component

import android.annotation.SuppressLint
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Loop
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.SuSFSManager
import com.sukisu.ultra.ui.util.SuSFSManager.isSusVersion158
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel

/**
 * SUS路径内容组件
 */
@Composable
fun SusPathsContent(
    susPaths: Set<String>,
    isLoading: Boolean,
    onAddPath: () -> Unit,
    onAddAppPath: () -> Unit,
    onRemovePath: (String) -> Unit,
    onEditPath: ((String) -> Unit)? = null,
    forceRefreshApps: Boolean = false
) {
    val superUserApps = SuperUserViewModel.apps
    val superUserIsRefreshing = remember { SuperUserViewModel().isRefreshing }

    LaunchedEffect(superUserIsRefreshing, superUserApps.size) {
        if (!superUserIsRefreshing && superUserApps.isNotEmpty()) {
            AppInfoCache.clearCache()
        }
    }

    LaunchedEffect(forceRefreshApps) {
        if (forceRefreshApps) {
            AppInfoCache.clearCache()
        }
    }

    val (appPathGroups, otherPaths) = remember(susPaths) {
        val appPathRegex = Regex(".*/Android/data/([^/]+)/?.*")
        val appPathMap = mutableMapOf<String, MutableList<String>>()
        val others = mutableListOf<String>()

        susPaths.forEach { path ->
            val matchResult = appPathRegex.find(path)
            if (matchResult != null) {
                val packageName = matchResult.groupValues[1]
                appPathMap.getOrPut(packageName) { mutableListOf() }.add(path)
            } else {
                others.add(path)
            }
        }

        val sortedAppGroups = appPathMap.toList()
            .sortedBy { it.first }
            .map { (packageName, paths) -> packageName to paths.sorted() }

        Pair(sortedAppGroups, others.sorted())
    }

    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 应用路径分组
            if (appPathGroups.isNotEmpty()) {
                item {
                    SectionHeader(
                        title = stringResource(R.string.app_paths_section),
                        subtitle = null,
                        icon = Icons.Default.Apps,
                        count = appPathGroups.size
                    )
                }

                items(appPathGroups) { (packageName, paths) ->
                    AppPathGroupCard(
                        packageName = packageName,
                        paths = paths,
                        onDeleteGroup = {
                            paths.forEach { path -> onRemovePath(path) }
                        },
                        onEditGroup = if (onEditPath != null) {
                            {
                                onEditPath(paths.first())
                            }
                        } else null,
                        isLoading = isLoading
                    )
                }
            }

            // 其他路径
            if (otherPaths.isNotEmpty()) {
                item {
                    SectionHeader(
                        title = stringResource(R.string.other_paths_section),
                        subtitle = null,
                        icon = Icons.Default.Folder,
                        count = otherPaths.size
                    )
                }

                items(otherPaths) { path ->
                    PathItemCard(
                        path = path,
                        icon = Icons.Default.Folder,
                        onDelete = { onRemovePath(path) },
                        onEdit = if (onEditPath != null) { { onEditPath(path) } } else null,
                        isLoading = isLoading
                    )
                }
            }

            if (susPaths.isEmpty()) {
                item {
                    EmptyStateCard(
                        message = stringResource(R.string.susfs_no_paths_configured)
                    )
                }
            }

            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = onAddPath,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(text = stringResource(R.string.add_custom_path))
                    }

                    Button(
                        onClick = onAddAppPath,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Apps,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(text = stringResource(R.string.add_app_path))
                    }
                }
            }
        }
    }
}

/**
 * SUS循环路径内容组件
 */
@Composable
fun SusLoopPathsContent(
    susLoopPaths: Set<String>,
    isLoading: Boolean,
    onAddLoopPath: () -> Unit,
    onRemoveLoopPath: (String) -> Unit,
    onEditLoopPath: ((String) -> Unit)? = null
) {
    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 说明卡片
            item {
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
                            text = stringResource(R.string.sus_loop_paths_description_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = stringResource(R.string.sus_loop_paths_description_text),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = stringResource(R.string.susfs_loop_path_restriction_warning),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.secondary
                        )
                    }
                }
            }

            if (susLoopPaths.isEmpty()) {
                item {
                    EmptyStateCard(
                        message = stringResource(R.string.susfs_no_loop_paths_configured)
                    )
                }
            } else {
                item {
                    SectionHeader(
                        title = stringResource(R.string.loop_paths_section),
                        subtitle = null,
                        icon = Icons.Default.Loop,
                        count = susLoopPaths.size
                    )
                }

                items(susLoopPaths.toList()) { path ->
                    PathItemCard(
                        path = path,
                        icon = Icons.Default.Loop,
                        onDelete = { onRemoveLoopPath(path) },
                        onEdit = if (onEditLoopPath != null) { { onEditLoopPath(path) } } else null,
                        isLoading = isLoading
                    )
                }
            }

            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = onAddLoopPath,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(text = stringResource(R.string.add_loop_path))
                    }
                }
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
    isSusVersion158: Boolean,
    isLoading: Boolean,
    onAddMount: () -> Unit,
    onRemoveMount: (String) -> Unit,
    onEditMount: ((String) -> Unit)? = null,
    onToggleHideSusMountsForAllProcs: (Boolean) -> Unit
) {
    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (isSusVersion158) {
                item {
                    SusMountHidingControlCard(
                        hideSusMountsForAllProcs = hideSusMountsForAllProcs,
                        isLoading = isLoading,
                        onToggleHiding = onToggleHideSusMountsForAllProcs
                    )
                }
            }

            if (susMounts.isEmpty()) {
                item {
                    EmptyStateCard(
                        message = stringResource(R.string.susfs_no_mounts_configured)
                    )
                }
            } else {
                items(susMounts.toList()) { mount ->
                    PathItemCard(
                        path = mount,
                        icon = Icons.Default.Storage,
                        onDelete = { onRemoveMount(mount) },
                        onEdit = if (onEditMount != null) { { onEditMount(mount) } } else null,
                        isLoading = isLoading
                    )
                }
            }

            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = onAddMount,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(text = stringResource(R.string.add))
                    }
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
    umountForZygoteIsoService: Boolean,
    isLoading: Boolean,
    onAddUmount: () -> Unit,
    onRunUmount: () -> Unit,
    onRemoveUmount: (String) -> Unit,
    onEditUmount: ((String) -> Unit)? = null,
    onToggleUmountForZygoteIsoService: (Boolean) -> Unit
) {
    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (isSusVersion158()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surface
                        ),
                        shape = RoundedCornerShape(12.dp)
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
                                Row(
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Security,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = stringResource(R.string.umount_zygote_iso_service),
                                        style = MaterialTheme.typography.titleMedium,
                                        fontWeight = FontWeight.Medium,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = stringResource(R.string.umount_zygote_iso_service_description),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    lineHeight = 14.sp
                                )
                            }
                            Switch(
                                checked = umountForZygoteIsoService,
                                onCheckedChange = onToggleUmountForZygoteIsoService,
                                enabled = !isLoading
                            )
                        }
                    }
                }
            }

            if (tryUmounts.isEmpty()) {
                item {
                    EmptyStateCard(
                        message = stringResource(R.string.susfs_no_umounts_configured)
                    )
                }
            } else {
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
                        onEdit = if (onEditUmount != null) { { onEditUmount(umountEntry) } } else null,
                        isLoading = isLoading
                    )
                }
            }

            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = onAddUmount,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(text = stringResource(R.string.add))
                    }

                    if (tryUmounts.isNotEmpty()) {
                        Button(
                            onClick = onRunUmount,
                            modifier = Modifier
                                .weight(1f)
                                .height(48.dp),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.PlayArrow,
                                contentDescription = null,
                                modifier = Modifier.size(24.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(text = stringResource(R.string.susfs_run))
                        }
                    }
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
    onEditKstatConfig: ((String) -> Unit)? = null,
    onRemoveAddKstat: (String) -> Unit,
    onEditAddKstat: ((String) -> Unit)? = null,
    onUpdateKstat: (String) -> Unit,
    onUpdateKstatFullClone: (String) -> Unit
) {
    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
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
            }

            if (kstatConfigs.isNotEmpty()) {
                item {
                    Text(
                        text = stringResource(R.string.static_kstat_config),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
                items(kstatConfigs.toList()) { config ->
                    KstatConfigItemCard(
                        config = config,
                        onDelete = { onRemoveKstatConfig(config) },
                        onEdit = if (onEditKstatConfig != null) { { onEditKstatConfig(config) } } else null,
                        isLoading = isLoading
                    )
                }
            }

            if (addKstatPaths.isNotEmpty()) {
                item {
                    Text(
                        text = stringResource(R.string.kstat_path_management),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
                items(addKstatPaths.toList()) { path ->
                    AddKstatPathItemCard(
                        path = path,
                        onDelete = { onRemoveAddKstat(path) },
                        onEdit = if (onEditAddKstat != null) { { onEditAddKstat(path) } } else null,
                        onUpdate = { onUpdateKstat(path) },
                        onUpdateFullClone = { onUpdateKstatFullClone(path) },
                        isLoading = isLoading
                    )
                }
            }

            if (kstatConfigs.isEmpty() && addKstatPaths.isEmpty()) {
                item {
                    EmptyStateCard(
                        message = stringResource(R.string.no_kstat_config_message)
                    )
                }
            }

            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = onAddKstat,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(text = stringResource(R.string.add))
                    }

                    Button(
                        onClick = onAddKstatStatically,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(text = stringResource(R.string.add))
                    }
                }
            }
        }
    }
}

/**
 * 路径设置内容组件
 */
@SuppressLint("SdCardPath")
@Composable
fun PathSettingsContent(
    androidDataPath: String,
    onAndroidDataPathChange: (String) -> Unit,
    sdcardPath: String,
    onSdcardPathChange: (String) -> Unit,
    isLoading: Boolean,
    onSetAndroidDataPath: () -> Unit,
    onSetSdcardPath: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedTextField(
                        value = androidDataPath,
                        onValueChange = onAndroidDataPathChange,
                        label = { Text(stringResource(R.string.susfs_android_data_path_label)) },
                        placeholder = { Text("/sdcard/Android/data") },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isLoading,
                        singleLine = true,
                        shape = RoundedCornerShape(8.dp)
                    )

                    Button(
                        onClick = onSetAndroidDataPath,
                        enabled = !isLoading && androidDataPath.isNotBlank(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(40.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(stringResource(R.string.susfs_set_android_data_path))
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedTextField(
                        value = sdcardPath,
                        onValueChange = onSdcardPathChange,
                        label = { Text(stringResource(R.string.susfs_sdcard_path_label)) },
                        placeholder = { Text("/sdcard") },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isLoading,
                        singleLine = true,
                        shape = RoundedCornerShape(8.dp)
                    )

                    Button(
                        onClick = onSetSdcardPath,
                        enabled = !isLoading && sdcardPath.isNotBlank(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(40.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(stringResource(R.string.susfs_set_sdcard_path))
                    }
                }
            }
        }
    }
}

/**
 * 启用功能状态内容组件
 */
@Composable
fun EnabledFeaturesContent(
    enabledFeatures: List<SuSFSManager.EnabledFeature>,
    onRefresh: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(
                    modifier = Modifier.padding(12.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.susfs_enabled_features_description),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        if (enabledFeatures.isEmpty()) {
            item {
                EmptyStateCard(
                    message = stringResource(R.string.susfs_no_features_found)
                )
            }
        } else {
            items(enabledFeatures) { feature ->
                FeatureStatusCard(
                    feature = feature,
                    onRefresh = onRefresh
                )
            }
        }
    }
}