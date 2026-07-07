package com.sukisu.ultra.ui.screen.susfs.component.material

import android.annotation.SuppressLint
import android.content.pm.PackageInfo
import android.util.Log
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Update
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.util.AppInfoCache
import com.sukisu.ultra.ui.screen.susfs.util.AppInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext


@Composable
fun AddPathDialogMaterial(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
    isLoading: Boolean,
    titleRes: Int,
    labelRes: Int,
    initialValue: String = ""
) {
    var newPath by remember { mutableStateOf(initialValue) }

    LaunchedEffect(showDialog, initialValue) {
        if (showDialog) {
            newPath = initialValue
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = {
                onDismiss()
                newPath = ""
            },
            title = { Text(stringResource(titleRes)) },
            text = {
                OutlinedTextField(
                    value = newPath,
                    onValueChange = { newPath = it },
                    label = { Text(stringResource(labelRes)) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isLoading,
                    singleLine = true
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (newPath.isNotBlank()) {
                            onConfirm(newPath.trim())
                            newPath = ""
                        }
                    },
                    enabled = newPath.isNotBlank() && !isLoading
                ) {
                    Text(stringResource(if (initialValue.isNotEmpty()) R.string.susfs_save else R.string.add))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        newPath = ""
                    }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@Composable
fun AddAppPathDialogMaterial(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (List<String>) -> Unit,
    isLoading: Boolean,
    apps: List<AppInfo> = emptyList(),
    onLoadApps: () -> Unit,
    existingSusPaths: Set<String> = emptySet()
) {
    var searchText by remember { mutableStateOf("") }
    var selectedApps by remember { mutableStateOf(setOf<AppInfo>()) }

    val addedPackageNames = remember(existingSusPaths) {
        existingSusPaths.mapNotNull { path ->
            val regex = Regex(".*/Android/data/([^/]+)/?.*")
            regex.find(path)?.groupValues?.get(1)
        }.toSet()
    }

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
        if (showDialog) {
            selectedApps = setOf()
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = {
                onDismiss()
                selectedApps = setOf()
                searchText = ""
            },
            title = { Text(stringResource(R.string.susfs_add_app_path)) },
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 400.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedTextField(
                        value = searchText,
                        onValueChange = { searchText = it },
                        label = { Text(stringResource(R.string.search_apps)) },
                        leadingIcon = {
                            Icon(Icons.Default.Search, contentDescription = null)
                        },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )

                    if (selectedApps.isNotEmpty()) {
                        Text(
                            text = stringResource(R.string.selected_apps_count, selectedApps.size),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.Medium
                        )
                    }

                    if (filteredApps.isEmpty()) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = if (availableApps.isEmpty()) {
                                    stringResource(R.string.all_apps_already_added)
                                } else {
                                    stringResource(R.string.no_apps_found)
                                },
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = TextAlign.Center
                            )
                        }
                    } else {
                        LazyColumn(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            items(filteredApps) { app ->
                                val isSelected = selectedApps.contains(app)
                                Card(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            selectedApps = if (isSelected) {
                                                selectedApps - app
                                            } else {
                                                selectedApps + app
                                            }
                                        },
                                    colors = CardDefaults.cardColors(
                                        containerColor = if (isSelected) {
                                            MaterialTheme.colorScheme.primaryContainer
                                        } else {
                                            MaterialTheme.colorScheme.surface
                                        }
                                    )
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        AppIconMaterial(
                                            packageName = app.packageName,
                                            modifier = Modifier.size(40.dp)
                                        )
                                        Column(
                                            modifier = Modifier
                                                .weight(1f)
                                                .padding(start = 12.dp)
                                        ) {
                                            Text(
                                                text = app.appName,
                                                style = MaterialTheme.typography.bodyMedium,
                                                fontWeight = FontWeight.Medium
                                            )
                                            Text(
                                                text = app.packageName,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                        Icon(
                                            imageVector = if (isSelected) Icons.Default.CheckCircle else Icons.Default.RadioButtonUnchecked,
                                            contentDescription = null,
                                            tint = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (selectedApps.isNotEmpty()) {
                            onConfirm(selectedApps.map { it.packageName })
                        }
                        selectedApps = setOf()
                        searchText = ""
                    },
                    enabled = selectedApps.isNotEmpty() && !isLoading
                ) {
                    Text(stringResource(R.string.add))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        selectedApps = setOf()
                        searchText = ""
                    }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@SuppressLint("SdCardPath")
@Composable
fun AddKstatStaticallyDialogMaterial(
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

    val resetFields = {
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

    if (showDialog) {
        AlertDialog(
            onDismissRequest = {
                onDismiss()
                resetFields()
            },
            title = { Text(stringResource(if (initialConfig.isNotEmpty()) R.string.edit_kstat_statically_title else R.string.add_kstat_statically_title)) },
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = newKstatPath,
                        onValueChange = { newKstatPath = it },
                        label = { Text(stringResource(R.string.file_or_directory_path_label)) },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isLoading,
                        singleLine = true
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = newKstatIno,
                            onValueChange = { newKstatIno = it },
                            label = { Text("ino") },
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = newKstatDev,
                            onValueChange = { newKstatDev = it },
                            label = { Text("dev") },
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
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
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = newKstatSize,
                            onValueChange = { newKstatSize = it },
                            label = { Text("size") },
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
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
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = newKstatAtimeNsec,
                            onValueChange = { newKstatAtimeNsec = it },
                            label = { Text("atime_nsec") },
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
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
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = newKstatMtimeNsec,
                            onValueChange = { newKstatMtimeNsec = it },
                            label = { Text("mtime_nsec") },
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
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
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = newKstatCtimeNsec,
                            onValueChange = { newKstatCtimeNsec = it },
                            label = { Text("ctime_nsec") },
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
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
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = newKstatBlksize,
                            onValueChange = { newKstatBlksize = it },
                            label = { Text("blksize") },
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            singleLine = true
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
                TextButton(
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
                            resetFields()
                        }
                    },
                    enabled = newKstatPath.isNotBlank() && !isLoading
                ) {
                    Text(stringResource(if (initialConfig.isNotEmpty()) R.string.susfs_save else R.string.add))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        onDismiss()
                        resetFields()
                    }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@Composable
fun PathItemCardMaterial(
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
            .padding(vertical = 2.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
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
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = path,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    additionalInfo?.let {
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                onEdit?.let {
                    IconButton(onClick = it, enabled = !isLoading) {
                        Icon(
                            Icons.Default.Edit,
                            contentDescription = stringResource(R.string.edit),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
                IconButton(onClick = onDelete, enabled = !isLoading) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = stringResource(R.string.delete),
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

@Composable
fun KstatConfigItemCardMaterial(
    config: String,
    onDelete: () -> Unit,
    onEdit: (() -> Unit)? = null,
    isLoading: Boolean = false
) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
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
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    val parts = config.split("|")
                    Text(
                        text = parts.firstOrNull() ?: config,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    if (parts.size > 1) {
                        Text(
                            text = parts.drop(1).joinToString(" "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                onEdit?.let {
                    IconButton(onClick = it, enabled = !isLoading) {
                        Icon(Icons.Default.Edit, contentDescription = stringResource(R.string.edit), tint = MaterialTheme.colorScheme.primary)
                    }
                }
                IconButton(onClick = onDelete, enabled = !isLoading) {
                    Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.delete), tint = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

@Composable
fun AddKstatPathItemCardMaterial(
    path: String,
    onDelete: () -> Unit,
    onEdit: (() -> Unit)? = null,
    onUpdate: () -> Unit,
    onUpdateFullClone: () -> Unit,
    isLoading: Boolean = false
) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
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
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = path,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f)
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                onEdit?.let {
                    IconButton(onClick = it, enabled = !isLoading) {
                        Icon(Icons.Default.Edit, contentDescription = stringResource(R.string.edit), tint = MaterialTheme.colorScheme.primary)
                    }
                }
                IconButton(onClick = onUpdate, enabled = !isLoading) {
                    Icon(Icons.Default.Update, contentDescription = stringResource(R.string.update), tint = MaterialTheme.colorScheme.secondary)
                }
                IconButton(onClick = onUpdateFullClone, enabled = !isLoading) {
                    Icon(Icons.Default.PlayArrow, contentDescription = stringResource(R.string.susfs_update_full_clone), tint = MaterialTheme.colorScheme.tertiary)
                }
                IconButton(onClick = onDelete, enabled = !isLoading) {
                    Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.delete), tint = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

@Composable
fun AppIconMaterial(
    packageName: String,
    packageInfo: PackageInfo? = null,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var iconBitmap by remember(packageName, packageInfo) { mutableStateOf<ImageBitmap?>(null) }
    var isLoadingIcon by remember(packageName, packageInfo) { mutableStateOf(true) }

    LaunchedEffect(packageName, packageInfo) {
        isLoadingIcon = true
        iconBitmap = null

        withContext(Dispatchers.IO) {
            try {
                val drawable = when {
                    packageInfo != null -> {
                        packageInfo.applicationInfo?.loadIcon(context.packageManager)
                    }
                    else -> {
                        val cachedInfo = AppInfoCache.getAppInfo(packageName)
                        if (cachedInfo?.drawable != null) {
                            cachedInfo.drawable
                        } else if (cachedInfo?.packageInfo != null) {
                            cachedInfo.packageInfo.applicationInfo?.loadIcon(context.packageManager)
                        } else {
                            // 尝试从 PackageManager 获取
                            try {
                                val packageManager = context.packageManager
                                val applicationInfo = packageManager.getApplicationInfo(packageName, 0)
                                val icon = packageManager.getApplicationIcon(applicationInfo)
                                // 更新缓存
                                val newCachedInfo = AppInfoCache.CachedAppInfo(
                                    appName = packageName,
                                    packageInfo = null,
                                    drawable = icon
                                )
                                AppInfoCache.putAppInfo(packageName, newCachedInfo)
                                icon
                            } catch (e: Exception) {
                                Log.d("AppIcon", "获取应用图标失败: $packageName", e)
                                null
                            }
                        }
                    }
                }

                iconBitmap = drawable?.toBitmap()?.asImageBitmap()
            } catch (e: Exception) {
                Log.d("AppIcon", "获取应用图标失败: $packageName", e)
            } finally {
                isLoadingIcon = false
            }
        }
    }

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(
                if (iconBitmap == null) MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                else Color.Transparent
            ),
        contentAlignment = Alignment.Center
    ) {
        if (iconBitmap != null) {
            Image(
                bitmap = iconBitmap!!,
                contentDescription = null,
                modifier = Modifier.fillMaxSize()
            )
        } else if (!isLoadingIcon) {
            // 显示占位图标
            Icon(
                imageVector = Icons.Default.Android,
                contentDescription = null,
                modifier = Modifier.size(20.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
            )
        }
    }
}

@Composable
fun AppPathGroupCardMaterial(
    packageName: String,
    paths: List<String>,
    onDeleteGroup: () -> Unit,
    onEditGroup: (() -> Unit)? = null,
    isLoading: Boolean
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                AppIconMaterial(
                    packageName = packageName,
                    modifier = Modifier.size(32.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = packageName,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Medium
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    onEditGroup?.let {
                        IconButton(onClick = it, enabled = !isLoading) {
                            Icon(Icons.Default.Edit, contentDescription = stringResource(R.string.edit), tint = MaterialTheme.colorScheme.primary)
                        }
                    }
                    IconButton(onClick = onDeleteGroup, enabled = !isLoading) {
                        Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.delete), tint = MaterialTheme.colorScheme.error)
                    }
                }
            }
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
