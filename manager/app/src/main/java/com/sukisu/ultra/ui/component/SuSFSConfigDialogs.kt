package com.sukisu.ultra.ui.component

import android.annotation.SuppressLint
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.util.Log
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Update
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import coil.request.ImageRequest
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.SuSFSManager
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.launch

/**
 * 添加路径对话框
 */
@Composable
fun AddPathDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
    isLoading: Boolean,
    titleRes: Int,
    labelRes: Int,
    placeholderRes: Int,
    initialValue: String = ""
) {
    var newPath by remember { mutableStateOf("") }

    // 当对话框显示时，设置初始值
    LaunchedEffect(showDialog, initialValue) {
        if (showDialog) {
            newPath = initialValue
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = {
                Text(
                    stringResource(titleRes),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                OutlinedTextField(
                    value = newPath,
                    onValueChange = { newPath = it },
                    label = { Text(stringResource(labelRes)) },
                    placeholder = { Text(stringResource(placeholderRes)) },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp)
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (newPath.isNotBlank()) {
                            onConfirm(newPath.trim())
                            newPath = ""
                        }
                    },
                    enabled = newPath.isNotBlank() && !isLoading,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(if (initialValue.isNotEmpty()) R.string.susfs_save else R.string.add))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        newPath = ""
                    },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }
}

/**
 * 快捷添加应用路径对话框
 */
@Composable
fun AddAppPathDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (List<String>) -> Unit,
    isLoading: Boolean,
    apps: List<SuSFSManager.AppInfo> = emptyList(),
    onLoadApps: () -> Unit,
    existingSusPaths: Set<String> = emptySet()
) {
    var searchText by remember { mutableStateOf("") }
    var selectedApps by remember { mutableStateOf(setOf<SuSFSManager.AppInfo>()) }

    // 获取已添加的包名
    val addedPackageNames = remember(existingSusPaths) {
        existingSusPaths.mapNotNull { path ->
            val regex = Regex(".*/Android/data/([^/]+)/?.*")
            regex.find(path)?.groupValues?.get(1)
        }.toSet()
    }

    // 过滤掉已添加的应用
    val availableApps = remember(apps, addedPackageNames) {
        apps.filter { app ->
            !addedPackageNames.contains(app.packageName)
        }
    }

    val filteredApps = remember(availableApps, searchText) {
        if (searchText.isBlank()) {
            availableApps
        } else {
            availableApps.filter { app ->
                app.appName.contains(searchText, ignoreCase = true) ||
                        app.packageName.contains(searchText, ignoreCase = true)
            }
        }
    }

    LaunchedEffect(showDialog) {
        if (showDialog && apps.isEmpty()) {
            onLoadApps()
        }
        // 当对话框显示时清空选择
        if (showDialog) {
            selectedApps = setOf()
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = {
                Text(
                    text = stringResource(R.string.susfs_add_app_path),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedTextField(
                        value = searchText,
                        onValueChange = { searchText = it },
                        label = { Text(stringResource(R.string.search_apps)) },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Search,
                                contentDescription = null
                            )
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp)
                    )

                    // 显示统计信息
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        if (selectedApps.isNotEmpty()) {
                            Text(
                                text = stringResource(R.string.selected_apps_count, selectedApps.size),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.Medium
                            )
                        }
                        if (addedPackageNames.isNotEmpty()) {
                            Text(
                                text = stringResource(R.string.already_added_apps_count, addedPackageNames.size),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    if (filteredApps.isEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                            )
                        ) {
                            Text(
                                text = if (availableApps.isEmpty()) {
                                    stringResource(R.string.all_apps_already_added)
                                } else {
                                    stringResource(R.string.no_apps_found)
                                },
                                modifier = Modifier.padding(16.dp),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        LazyColumn(
                            modifier = Modifier.height(300.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            items(filteredApps) { app ->
                                val isSelected = selectedApps.contains(app)

                                Card(
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = CardDefaults.cardColors(
                                        containerColor = if (isSelected) {
                                            MaterialTheme.colorScheme.primaryContainer
                                        } else {
                                            MaterialTheme.colorScheme.surface
                                        }
                                    ),
                                    onClick = {
                                        selectedApps = if (isSelected) {
                                            selectedApps - app
                                        } else {
                                            selectedApps + app
                                        }
                                    }
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        // 应用图标
                                        AppIcon(
                                            packageName = app.packageName,
                                            packageInfo = app.packageInfo,
                                            modifier = Modifier.size(40.dp)
                                        )

                                        Column(
                                            modifier = Modifier
                                                .weight(1f)
                                                .padding(start = 12.dp)
                                        ) {
                                            Text(
                                                text = app.appName,
                                                style = MaterialTheme.typography.bodyLarge,
                                                fontWeight = FontWeight.Medium,
                                                color = if (isSelected) {
                                                    MaterialTheme.colorScheme.onPrimaryContainer
                                                } else {
                                                    MaterialTheme.colorScheme.onSurface
                                                }
                                            )
                                            Text(
                                                text = app.packageName,
                                                style = MaterialTheme.typography.bodyMedium,
                                                color = if (isSelected) {
                                                    MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                                                } else {
                                                    MaterialTheme.colorScheme.onSurfaceVariant
                                                }
                                            )
                                        }

                                        // 选择指示器
                                        if (isSelected) {
                                            Icon(
                                                imageVector = Icons.Default.CheckCircle,
                                                contentDescription = null,
                                                tint = MaterialTheme.colorScheme.primary,
                                                modifier = Modifier.size(24.dp)
                                            )
                                        } else {
                                            Icon(
                                                imageVector = Icons.Default.RadioButtonUnchecked,
                                                contentDescription = null,
                                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                                modifier = Modifier.size(24.dp)
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (selectedApps.isNotEmpty()) {
                            onConfirm(selectedApps.map { it.packageName })
                        }
                        selectedApps = setOf()
                        searchText = ""
                    },
                    enabled = selectedApps.isNotEmpty() && !isLoading,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = stringResource(R.string.add)
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        selectedApps = setOf()
                        searchText = ""
                    },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }
}


/**
 * 应用图标组件
 */
@Composable
fun AppIcon(
    packageName: String,
    packageInfo: PackageInfo? = null,
    @SuppressLint("ModifierParameter") modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    if (packageInfo != null) {
        AsyncImage(
            model = ImageRequest.Builder(context)
                .data(packageInfo)
                .crossfade(true)
                .build(),
            contentDescription = null,
            modifier = modifier.clip(RoundedCornerShape(8.dp))
        )
    } else {
        var appIcon by remember(packageName) {
            mutableStateOf(
                AppInfoCache.getAppInfo(packageName)?.drawable
            )
        }

        LaunchedEffect(packageName) {
            if (appIcon == null && !AppInfoCache.hasCache(packageName)) {
                try {
                    val packageManager = context.packageManager
                    val applicationInfo = packageManager.getApplicationInfo(packageName, 0)
                    val drawable = packageManager.getApplicationIcon(applicationInfo)
                    appIcon = drawable
                    val cachedInfo = AppInfoCache.CachedAppInfo(
                        appName = packageName,
                        packageInfo = null,
                        drawable = drawable
                    )
                    AppInfoCache.putAppInfo(packageName, cachedInfo)
                } catch (_: Exception) {
                    Log.d("获取应用图标失败", packageName)
                }
            }
        }
        Image(
            painter = rememberDrawablePainter(appIcon),
            contentDescription = null,
            modifier = modifier.clip(RoundedCornerShape(8.dp))
        )
    }
}


/**
 * 添加尝试卸载对话框
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddTryUmountDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String, Int) -> Unit,
    isLoading: Boolean,
    initialPath: String = "",
    initialMode: Int = 0
) {
    var newUmountPath by remember { mutableStateOf("") }
    var newUmountMode by remember { mutableIntStateOf(0) }
    var umountModeExpanded by remember { mutableStateOf(false) }

    // 当对话框显示时，设置初始值
    LaunchedEffect(showDialog, initialPath, initialMode) {
        if (showDialog) {
            newUmountPath = initialPath
            newUmountMode = initialMode
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = {
                Text(
                    stringResource(if (initialPath.isNotEmpty()) R.string.susfs_edit_try_umount else R.string.susfs_add_try_umount),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedTextField(
                        value = newUmountPath,
                        onValueChange = { newUmountPath = it },
                        label = { Text(stringResource(R.string.susfs_path_label)) },
                        placeholder = { Text(stringResource(R.string.susfs_path_placeholder)) },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp)
                    )

                    ExposedDropdownMenuBox(
                        expanded = umountModeExpanded,
                        onExpandedChange = { umountModeExpanded = !umountModeExpanded }
                    ) {
                        OutlinedTextField(
                            value = if (newUmountMode == 0)
                                stringResource(R.string.susfs_umount_mode_normal)
                            else
                                stringResource(R.string.susfs_umount_mode_detach),
                            onValueChange = { },
                            readOnly = true,
                            label = { Text(stringResource(R.string.susfs_umount_mode_label)) },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = umountModeExpanded) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .menuAnchor(MenuAnchorType.PrimaryEditable, true),
                            shape = RoundedCornerShape(8.dp)
                        )
                        ExposedDropdownMenu(
                            expanded = umountModeExpanded,
                            onDismissRequest = { umountModeExpanded = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.susfs_umount_mode_normal)) },
                                onClick = {
                                    newUmountMode = 0
                                    umountModeExpanded = false
                                }
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.susfs_umount_mode_detach)) },
                                onClick = {
                                    newUmountMode = 1
                                    umountModeExpanded = false
                                }
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (newUmountPath.isNotBlank()) {
                            onConfirm(newUmountPath.trim(), newUmountMode)
                            newUmountPath = ""
                            newUmountMode = 0
                        }
                    },
                    enabled = newUmountPath.isNotBlank() && !isLoading,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(if (initialPath.isNotEmpty()) R.string.susfs_save else R.string.add))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        newUmountPath = ""
                        newUmountMode = 0
                    },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }
}

/**
 * 添加Kstat静态配置对话框
 */
@Composable
fun AddKstatStaticallyDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String, String, String, String, String, String, String, String, String, String, String, String, String) -> Unit,
    isLoading: Boolean,
    initialConfig: String = ""
) {
    var newKstatPath by remember { mutableStateOf("") }
    var newKstatIno by remember { mutableStateOf("") }
    var newKstatDev by remember { mutableStateOf("") }
    var newKstatNlink by remember { mutableStateOf("") }
    var newKstatSize by remember { mutableStateOf("") }
    var newKstatAtime by remember { mutableStateOf("") }
    var newKstatAtimeNsec by remember { mutableStateOf("") }
    var newKstatMtime by remember { mutableStateOf("") }
    var newKstatMtimeNsec by remember { mutableStateOf("") }
    var newKstatCtime by remember { mutableStateOf("") }
    var newKstatCtimeNsec by remember { mutableStateOf("") }
    var newKstatBlocks by remember { mutableStateOf("") }
    var newKstatBlksize by remember { mutableStateOf("") }

    // 当对话框显示时，解析初始配置
    LaunchedEffect(showDialog, initialConfig) {
        if (showDialog && initialConfig.isNotEmpty()) {
            val parts = initialConfig.split("|")
            if (parts.size >= 13) {
                newKstatPath = parts[0]
                newKstatIno = if (parts[1] == "default") "" else parts[1]
                newKstatDev = if (parts[2] == "default") "" else parts[2]
                newKstatNlink = if (parts[3] == "default") "" else parts[3]
                newKstatSize = if (parts[4] == "default") "" else parts[4]
                newKstatAtime = if (parts[5] == "default") "" else parts[5]
                newKstatAtimeNsec = if (parts[6] == "default") "" else parts[6]
                newKstatMtime = if (parts[7] == "default") "" else parts[7]
                newKstatMtimeNsec = if (parts[8] == "default") "" else parts[8]
                newKstatCtime = if (parts[9] == "default") "" else parts[9]
                newKstatCtimeNsec = if (parts[10] == "default") "" else parts[10]
                newKstatBlocks = if (parts[11] == "default") "" else parts[11]
                newKstatBlksize = if (parts[12] == "default") "" else parts[12]
            }
        } else if (showDialog && initialConfig.isEmpty()) {
            // 清空所有字段
            newKstatPath = ""
            newKstatIno = ""
            newKstatDev = ""
            newKstatNlink = ""
            newKstatSize = ""
            newKstatAtime = ""
            newKstatAtimeNsec = ""
            newKstatMtime = ""
            newKstatMtimeNsec = ""
            newKstatCtime = ""
            newKstatCtimeNsec = ""
            newKstatBlocks = ""
            newKstatBlksize = ""
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = {
                Text(
                    stringResource(if (initialConfig.isNotEmpty()) R.string.edit_kstat_statically_title else R.string.add_kstat_statically_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = newKstatPath,
                        onValueChange = { newKstatPath = it },
                        label = { Text(stringResource(R.string.file_or_directory_path_label)) },
                        placeholder = { Text("/path/to/file_or_directory") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = newKstatIno,
                            onValueChange = { newKstatIno = it },
                            label = { Text("ino") },
                            placeholder = { Text("1234") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                        OutlinedTextField(
                            value = newKstatDev,
                            onValueChange = { newKstatDev = it },
                            label = { Text("dev") },
                            placeholder = { Text("1234") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = newKstatNlink,
                            onValueChange = { newKstatNlink = it },
                            label = { Text("nlink") },
                            placeholder = { Text("2") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                        OutlinedTextField(
                            value = newKstatSize,
                            onValueChange = { newKstatSize = it },
                            label = { Text("size") },
                            placeholder = { Text("223344") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = newKstatAtime,
                            onValueChange = { newKstatAtime = it },
                            label = { Text("atime") },
                            placeholder = { Text("1712592355") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                        OutlinedTextField(
                            value = newKstatAtimeNsec,
                            onValueChange = { newKstatAtimeNsec = it },
                            label = { Text("atime_nsec") },
                            placeholder = { Text("0") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = newKstatMtime,
                            onValueChange = { newKstatMtime = it },
                            label = { Text("mtime") },
                            placeholder = { Text("1712592355") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                        OutlinedTextField(
                            value = newKstatMtimeNsec,
                            onValueChange = { newKstatMtimeNsec = it },
                            label = { Text("mtime_nsec") },
                            placeholder = { Text("0") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = newKstatCtime,
                            onValueChange = { newKstatCtime = it },
                            label = { Text("ctime") },
                            placeholder = { Text("1712592355") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                        OutlinedTextField(
                            value = newKstatCtimeNsec,
                            onValueChange = { newKstatCtimeNsec = it },
                            label = { Text("ctime_nsec") },
                            placeholder = { Text("0") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = newKstatBlocks,
                            onValueChange = { newKstatBlocks = it },
                            label = { Text("blocks") },
                            placeholder = { Text("16") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                        OutlinedTextField(
                            value = newKstatBlksize,
                            onValueChange = { newKstatBlksize = it },
                            label = { Text("blksize") },
                            placeholder = { Text("512") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp)
                        )
                    }

                    Text(
                        text = stringResource(R.string.hint_use_default_value),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (newKstatPath.isNotBlank()) {
                            onConfirm(
                                newKstatPath.trim(),
                                newKstatIno.trim().ifBlank { "default" },
                                newKstatDev.trim().ifBlank { "default" },
                                newKstatNlink.trim().ifBlank { "default" },
                                newKstatSize.trim().ifBlank { "default" },
                                newKstatAtime.trim().ifBlank { "default" },
                                newKstatAtimeNsec.trim().ifBlank { "default" },
                                newKstatMtime.trim().ifBlank { "default" },
                                newKstatMtimeNsec.trim().ifBlank { "default" },
                                newKstatCtime.trim().ifBlank { "default" },
                                newKstatCtimeNsec.trim().ifBlank { "default" },
                                newKstatBlocks.trim().ifBlank { "default" },
                                newKstatBlksize.trim().ifBlank { "default" }
                            )
                            // 清空所有字段
                            newKstatPath = ""
                            newKstatIno = ""
                            newKstatDev = ""
                            newKstatNlink = ""
                            newKstatSize = ""
                            newKstatAtime = ""
                            newKstatAtimeNsec = ""
                            newKstatMtime = ""
                            newKstatMtimeNsec = ""
                            newKstatCtime = ""
                            newKstatCtimeNsec = ""
                            newKstatBlocks = ""
                            newKstatBlksize = ""
                        }
                    },
                    enabled = newKstatPath.isNotBlank() && !isLoading,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(if (initialConfig.isNotEmpty()) R.string.susfs_save else R.string.add))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        // 清空所有字段
                        newKstatPath = ""
                        newKstatIno = ""
                        newKstatDev = ""
                        newKstatNlink = ""
                        newKstatSize = ""
                        newKstatAtime = ""
                        newKstatAtimeNsec = ""
                        newKstatMtime = ""
                        newKstatMtimeNsec = ""
                        newKstatCtime = ""
                        newKstatCtimeNsec = ""
                        newKstatBlocks = ""
                        newKstatBlksize = ""
                    },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }
}

/**
 * 确认对话框
 */
@Composable
fun ConfirmDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    titleRes: Int,
    messageRes: Int,
    isLoading: Boolean = false,
    isDestructive: Boolean = false
) {
    if (showDialog) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = {
                Text(
                    text = stringResource(titleRes),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = { Text(stringResource(messageRes)) },
            confirmButton = {
                Button(
                    onClick = onConfirm,
                    enabled = !isLoading,
                    colors = if (isDestructive) {
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error
                        )
                    } else {
                        ButtonDefaults.buttonColors()
                    },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.confirm))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = onDismiss,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(stringResource(R.string.cancel))
                }
            },
            shape = RoundedCornerShape(12.dp)
        )
    }
}

// 应用信息缓存
object AppInfoCache {
    private val appInfoMap = mutableMapOf<String, CachedAppInfo>()

    data class CachedAppInfo(
        val appName: String,
        val packageInfo: PackageInfo?,
        val drawable: Drawable?,
        val timestamp: Long = System.currentTimeMillis()
    )

    fun getAppInfo(packageName: String): CachedAppInfo? {
        return appInfoMap[packageName]
    }

    fun putAppInfo(packageName: String, appInfo: CachedAppInfo) {
        appInfoMap[packageName] = appInfo
    }

    fun clearCache() {
        appInfoMap.clear()
    }

    fun hasCache(packageName: String): Boolean {
        return appInfoMap.containsKey(packageName)
    }

    fun getAppInfoFromSuperUser(packageName: String): CachedAppInfo? {
        val superUserApp = SuperUserViewModel.apps.find { it.packageName == packageName }
        return superUserApp?.let { app ->
            CachedAppInfo(
                appName = app.label,
                packageInfo = app.packageInfo,
                drawable = null
            )
        }
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
    onEdit: (() -> Unit)? = null,
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
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                if (onEdit != null) {
                    IconButton(
                        onClick = onEdit,
                        enabled = !isLoading,
                        modifier = Modifier.size(32.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = stringResource(R.string.edit),
                            tint = MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
                IconButton(
                    onClick = onDelete,
                    enabled = !isLoading,
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = stringResource(R.string.delete),
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(16.dp)
                    )
                }
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
    onEdit: (() -> Unit)? = null,
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
                                text = parts.drop(1).joinToString(" "),
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
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                if (onEdit != null) {
                    IconButton(
                        onClick = onEdit,
                        enabled = !isLoading,
                        modifier = Modifier.size(32.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = stringResource(R.string.edit),
                            tint = MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
                IconButton(
                    onClick = onDelete,
                    enabled = !isLoading,
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = stringResource(R.string.delete),
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(16.dp)
                    )
                }
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
    onEdit: (() -> Unit)? = null,
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
                if (onEdit != null) {
                    IconButton(
                        onClick = onEdit,
                        enabled = !isLoading,
                        modifier = Modifier.size(32.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = stringResource(R.string.edit),
                            tint = MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
                IconButton(
                    onClick = onUpdate,
                    enabled = !isLoading,
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Update,
                        contentDescription = stringResource(R.string.update),
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
                        contentDescription = stringResource(R.string.susfs_update_full_clone),
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
                        contentDescription = stringResource(R.string.delete),
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
 * 应用路径分组卡片
 */
@Composable
fun AppPathGroupCard(
    packageName: String,
    paths: List<String>,
    onDeleteGroup: () -> Unit,
    onEditGroup: (() -> Unit)? = null,
    isLoading: Boolean
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val superUserApps = SuperUserViewModel.apps
    var cachedAppInfo by remember(packageName, superUserApps.size) {
        mutableStateOf(AppInfoCache.getAppInfo(packageName))
    }
    var isLoadingAppInfo by remember(packageName, superUserApps.size) { mutableStateOf(false) }

    LaunchedEffect(packageName, superUserApps.size) {
        if (cachedAppInfo == null || superUserApps.isNotEmpty()) {
            isLoadingAppInfo = true
            coroutineScope.launch {
                try {
                    val superUserAppInfo = AppInfoCache.getAppInfoFromSuperUser(packageName)

                    if (superUserAppInfo != null) {
                        val packageManager = context.packageManager
                        val drawable = try {
                            superUserAppInfo.packageInfo?.applicationInfo?.let {
                                packageManager.getApplicationIcon(it)
                            }
                        } catch (_: Exception) {
                            null
                        }

                        val newCachedInfo = AppInfoCache.CachedAppInfo(
                            appName = superUserAppInfo.appName,
                            packageInfo = superUserAppInfo.packageInfo,
                            drawable = drawable
                        )

                        AppInfoCache.putAppInfo(packageName, newCachedInfo)
                        cachedAppInfo = newCachedInfo
                    } else {
                        val packageManager = context.packageManager
                        val appInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_META_DATA)

                        val appName = try {
                            appInfo.applicationInfo?.let {
                                packageManager.getApplicationLabel(it).toString()
                            } ?: packageName
                        } catch (_: Exception) {
                            packageName
                        }

                        val drawable = try {
                            appInfo.applicationInfo?.let {
                                packageManager.getApplicationIcon(it)
                            }
                        } catch (_: Exception) {
                            null
                        }

                        val newCachedInfo = AppInfoCache.CachedAppInfo(
                            appName = appName,
                            packageInfo = appInfo,
                            drawable = drawable
                        )

                        AppInfoCache.putAppInfo(packageName, newCachedInfo)
                        cachedAppInfo = newCachedInfo
                    }
                } catch (_: Exception) {
                    val newCachedInfo = AppInfoCache.CachedAppInfo(
                        appName = packageName,
                        packageInfo = null,
                        drawable = null
                    )
                    AppInfoCache.putAppInfo(packageName, newCachedInfo)
                    cachedAppInfo = newCachedInfo
                } finally {
                    isLoadingAppInfo = false
                }
            }
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // 应用图标
                AppIcon(
                    packageName = packageName,
                    packageInfo = cachedAppInfo?.packageInfo,
                    modifier = Modifier.size(32.dp)
                )

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    val displayName = cachedAppInfo?.appName?.ifEmpty { packageName } ?: packageName
                    Text(
                        text = displayName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    if (!isLoadingAppInfo && cachedAppInfo?.appName?.isNotEmpty() == true &&
                        cachedAppInfo?.appName != packageName) {
                        Text(
                            text = packageName,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Row(
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (onEditGroup != null) {
                        IconButton(
                            onClick = onEditGroup,
                            enabled = !isLoading
                        ) {
                            Icon(
                                imageVector = Icons.Default.Edit,
                                contentDescription = stringResource(R.string.edit),
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                    IconButton(
                        onClick = onDeleteGroup,
                        enabled = !isLoading
                    ) {
                        Icon(
                            imageVector = Icons.Default.Delete,
                            contentDescription = stringResource(R.string.delete),
                            tint = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }

            // 显示所有路径
            Spacer(modifier = Modifier.height(8.dp))

            paths.forEach { path ->
                Text(
                    text = path,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                            RoundedCornerShape(6.dp)
                        )
                        .padding(8.dp)
                )

                if (path != paths.last()) {
                    Spacer(modifier = Modifier.height(4.dp))
                }
            }
        }
    }
}

/**
 * 分组标题组件
 */
@Composable
fun SectionHeader(
    title: String,
    subtitle: String?,
    icon: ImageVector,
    count: Int
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                subtitle?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.primary
            ) {
                Text(
                    text = count.toString(),
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onPrimary,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}