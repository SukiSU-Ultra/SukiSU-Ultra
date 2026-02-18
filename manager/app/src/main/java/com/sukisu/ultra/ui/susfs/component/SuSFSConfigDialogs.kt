package com.sukisu.ultra.ui.susfs.component

import android.annotation.SuppressLint
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.util.Log
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.background
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshotFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.core.graphics.drawable.toBitmap
import com.sukisu.ultra.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.sukisu.ultra.ui.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.extra.SuperDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.extra.SuperSwitch


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

    fun getAppInfoFromSuperUser(packageName: String): CachedAppInfo? {
        val superUserApp = SuperUserViewModel.getAppsSafely().find { it.packageName == packageName }
        return superUserApp?.let { app ->
            CachedAppInfo(
                appName = app.label,
                packageInfo = app.packageInfo,
                drawable = null
            )
        }
    }
}

@Composable
fun AppIcon(
    packageName: String,
    packageInfo: PackageInfo? = null,
    @SuppressLint("ModifierParameter") modifier: Modifier = Modifier
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
                if (iconBitmap == null) colorScheme.surfaceVariant.copy(alpha = 0.3f)
                else androidx.compose.ui.graphics.Color.Transparent
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
                tint = colorScheme.onSurfaceVariantSummary.copy(alpha = 0.6f)
            )
        }
    }
}

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
    var superUserApps by remember { mutableStateOf(SuperUserViewModel.getAppsSafely()) }

    LaunchedEffect(Unit) {
        snapshotFlow { SuperUserViewModel.apps }
            .distinctUntilChanged()
            .collect { _ ->
                superUserApps = SuperUserViewModel.getAppsSafely()
            }
    }

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
        colors = CardDefaults.defaultColors(
            color = colorScheme.surface
        )
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
                        style = MiuixTheme.textStyles.title2,
                        fontWeight = FontWeight.Medium,
                        color = colorScheme.onSurface
                    )
                    if (!isLoadingAppInfo && cachedAppInfo?.appName?.isNotEmpty() == true &&
                        cachedAppInfo?.appName != packageName) {
                        Text(
                            text = packageName,
                            style = MiuixTheme.textStyles.body2,
                            color = colorScheme.onSurfaceVariantSummary
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
                                tint = colorScheme.primary
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
                            tint = colorScheme.error
                        )
                    }
                }
            }

            // 显示所有路径
            Spacer(modifier = Modifier.height(8.dp))

            paths.forEach { path ->
                Text(
                    text = path,
                    style = MiuixTheme.textStyles.body2,
                    color = colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            colorScheme.surfaceVariant.copy(alpha = 0.3f),
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

@Composable
fun AddPathDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
    isLoading: Boolean,
    titleRes: Int,
    labelRes: Int,
    initialValue: String = ""
) {
    var newPath by remember { mutableStateOf("") }

    // 当对话框显示时，设置初始值
    LaunchedEffect(showDialog, initialValue) {
        if (showDialog) {
            newPath = initialValue
        }
    }

    UniversalDialog(
        showDialog = showDialog,
        onDismiss = onDismiss,
        onConfirm = {
            if (newPath.isNotBlank()) {
                onConfirm(newPath.trim())
                true
            } else {
                false
            }
        },
        titleRes = titleRes,
        isLoading = isLoading,
        fields = listOf(
            DialogField.TextField(
                value = newPath,
                onValueChange = { newPath = it },
                labelRes = labelRes,
                enabled = !isLoading
            )
        ),
        confirmTextRes = if (initialValue.isNotEmpty()) R.string.susfs_save else R.string.add,
        isConfirmEnabled = newPath.isNotBlank() && !isLoading,
        onReset = { }
    )
}

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

    val showDialogState = remember { mutableStateOf(showDialog) }
    
    LaunchedEffect(showDialog) {
        showDialogState.value = showDialog
    }

    if (showDialogState.value) {
        SuperDialog(
            show = showDialogState,
            title = stringResource(R.string.susfs_add_app_path),
            onDismissRequest = {
                onDismiss()
                searchText = ""
            },
            content = {
                Column(
                    modifier = Modifier
                        .padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    TextField(
                        value = searchText,
                        onValueChange = { searchText = it },
                        label = stringResource(R.string.search_apps),
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Search,
                                contentDescription = null
                            )
                        },
                        modifier = Modifier.fillMaxWidth()
                    )

                    // 显示统计信息
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        if (selectedApps.isNotEmpty()) {
                            Text(
                                text = stringResource(R.string.selected_apps_count, selectedApps.size),
                                style = MiuixTheme.textStyles.body2,
                                color = colorScheme.primary,
                                fontWeight = FontWeight.Medium
                            )
                        }
                        if (addedPackageNames.isNotEmpty()) {
                            Text(
                                text = stringResource(R.string.already_added_apps_count, addedPackageNames.size),
                                style = MiuixTheme.textStyles.body2,
                                color = colorScheme.onSurfaceVariantSummary
                            )
                        }
                    }

                    if (filteredApps.isEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.defaultColors(
                                color = colorScheme.surfaceVariant.copy(alpha = 0.2f)
                            )
                        ) {
                            Text(
                                text = if (availableApps.isEmpty()) {
                                    stringResource(R.string.all_apps_already_added)
                                } else {
                                    stringResource(R.string.no_apps_found)
                                },
                                modifier = Modifier.padding(16.dp),
                                style = MiuixTheme.textStyles.body2,
                                color = colorScheme.onSurfaceVariantSummary,
                                textAlign = TextAlign.Center
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
                                    colors = CardDefaults.defaultColors(
                                        color = if (isSelected) {
                                            colorScheme.primaryContainer.copy(alpha = 0.6f)
                                        } else {
                                            colorScheme.surface
                                        }
                                    ),
                                    onClick = {
                                        selectedApps = if (isSelected) {
                                            selectedApps - app
                                        } else {
                                            selectedApps + app
                                        }
                                    },
                                    cornerRadius = 8.dp
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
                                                style = MiuixTheme.textStyles.body1,
                                                fontWeight = FontWeight.Medium,
                                                color = if (isSelected) {
                                                    colorScheme.onPrimaryContainer
                                                } else {
                                                    colorScheme.onSurface
                                                }
                                            )
                                            Text(
                                                text = app.packageName,
                                                style = MiuixTheme.textStyles.body2,
                                                color = if (isSelected) {
                                                    colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                                                } else {
                                                    colorScheme.onSurfaceVariantSummary
                                                }
                                            )
                                        }

                                        // 选择指示器
                                        if (isSelected) {
                                            Icon(
                                                imageVector = Icons.Default.CheckCircle,
                                                contentDescription = null,
                                                tint = colorScheme.primary,
                                                modifier = Modifier.size(24.dp)
                                            )
                                        } else {
                                            Icon(
                                                imageVector = Icons.Default.RadioButtonUnchecked,
                                                contentDescription = null,
                                                tint = colorScheme.onSurfaceVariantSummary,
                                                modifier = Modifier.size(24.dp)
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // 按钮
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = {
                                onDismiss()
                                selectedApps = setOf()
                                searchText = ""
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
                                if (selectedApps.isNotEmpty()) {
                                    onConfirm(selectedApps.map { it.packageName })
                                }
                                selectedApps = setOf()
                                searchText = ""
                            },
                            enabled = selectedApps.isNotEmpty() && !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(
                                text = stringResource(R.string.add)
                            )
                        }
                    }
                }
            }
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

    UniversalDialog(
        showDialog = showDialog,
        onDismiss = onDismiss,
        onConfirm = {
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
                true
            } else {
                false
            }
        },
        titleRes = if (initialConfig.isNotEmpty()) R.string.edit_kstat_statically_title else R.string.add_kstat_statically_title,
        isLoading = isLoading,
        fields = listOf(
            DialogField.CustomContent {
                TextField(
                    value = newKstatPath,
                    onValueChange = { newKstatPath = it },
                    label = stringResource(R.string.file_or_directory_path_label),
                    useLabelAsPlaceholder = true,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isLoading
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TextField(
                        value = newKstatIno,
                        onValueChange = { newKstatIno = it },
                        label = "ino",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                    TextField(
                        value = newKstatDev,
                        onValueChange = { newKstatDev = it },
                        label = "dev",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TextField(
                        value = newKstatNlink,
                        onValueChange = { newKstatNlink = it },
                        label = "nlink",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                    TextField(
                        value = newKstatSize,
                        onValueChange = { newKstatSize = it },
                        label = "size",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TextField(
                        value = newKstatAtime,
                        onValueChange = { newKstatAtime = it },
                        label = "atime",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                    TextField(
                        value = newKstatAtimeNsec,
                        onValueChange = { newKstatAtimeNsec = it },
                        label = "atime_nsec",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TextField(
                        value = newKstatMtime,
                        onValueChange = { newKstatMtime = it },
                        label = "mtime",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                    TextField(
                        value = newKstatMtimeNsec,
                        onValueChange = { newKstatMtimeNsec = it },
                        label = "mtime_nsec",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TextField(
                        value = newKstatCtime,
                        onValueChange = { newKstatCtime = it },
                        label = "ctime",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                    TextField(
                        value = newKstatCtimeNsec,
                        onValueChange = { newKstatCtimeNsec = it },
                        label = "ctime_nsec",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TextField(
                        value = newKstatBlocks,
                        onValueChange = { newKstatBlocks = it },
                        label = "blocks",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                    TextField(
                        value = newKstatBlksize,
                        onValueChange = { newKstatBlksize = it },
                        label = "blksize",
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading
                    )
                }

                Text(
                    text = stringResource(R.string.hint_use_default_value),
                    style = MiuixTheme.textStyles.body2,
                    color = colorScheme.onSurfaceVariantSummary
                )
            }
        ),
        confirmTextRes = if (initialConfig.isNotEmpty()) R.string.susfs_save else R.string.add,
        isConfirmEnabled = newKstatPath.isNotBlank() && !isLoading,
        scrollable = true,
        onReset = resetFields
    )
}

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
            .padding(vertical = 2.dp),
        cornerRadius = 8.dp
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
                    tint = colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        text = path,
                        style = MiuixTheme.textStyles.body1,
                        fontWeight = FontWeight.Medium,
                        color = colorScheme.onSurface
                    )
                    if (additionalInfo != null) {
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = additionalInfo,
                            style = MiuixTheme.textStyles.body2,
                            color = colorScheme.onSurfaceVariantSummary
                        )
                    }
                }
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                if (onEdit != null) {
                    IconButton(
                        onClick = onEdit,
                        enabled = !isLoading,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = stringResource(R.string.edit),
                            tint = colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
                IconButton(
                    onClick = onDelete,
                    enabled = !isLoading,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = stringResource(R.string.delete),
                        tint = colorScheme.error,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }
    }
}

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
            .padding(vertical = 2.dp),
        cornerRadius = 8.dp
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
                    imageVector = Icons.Default.Settings,
                    contentDescription = null,
                    tint = colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(
                    modifier = Modifier.weight(1f)
                ) {
                    val parts = config.split("|")
                    if (parts.isNotEmpty()) {
                        Text(
                            text = parts[0], // 路径
                            style = MiuixTheme.textStyles.body1,
                            fontWeight = FontWeight.Medium,
                            color = colorScheme.onSurface
                        )
                        if (parts.size > 1) {
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = parts.drop(1).joinToString(" "),
                                style = MiuixTheme.textStyles.body2,
                                color = colorScheme.onSurfaceVariantSummary
                            )
                        }
                    } else {
                        Text(
                            text = config,
                            style = MiuixTheme.textStyles.body1,
                            fontWeight = FontWeight.Medium,
                            color = colorScheme.onSurface
                        )
                    }
                }
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                if (onEdit != null) {
                    IconButton(
                        onClick = onEdit,
                        enabled = !isLoading,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = stringResource(R.string.edit),
                            tint = colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
                IconButton(
                    onClick = onDelete,
                    enabled = !isLoading,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = stringResource(R.string.delete),
                        tint = colorScheme.error,
                        modifier = Modifier.size(18.dp)
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
            .padding(vertical = 2.dp),
        cornerRadius = 8.dp
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
                    imageVector = Icons.Default.Folder,
                    contentDescription = null,
                    tint = colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = path,
                    style = MiuixTheme.textStyles.body1,
                    fontWeight = FontWeight.Medium,
                    color = colorScheme.onSurface,
                    modifier = Modifier.weight(1f)
                )
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                if (onEdit != null) {
                    IconButton(
                        onClick = onEdit,
                        enabled = !isLoading,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Edit,
                            contentDescription = stringResource(R.string.edit),
                            tint = colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
                IconButton(
                    onClick = onUpdate,
                    enabled = !isLoading,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Update,
                        contentDescription = stringResource(R.string.update),
                        tint = colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
                IconButton(
                    onClick = onUpdateFullClone,
                    enabled = !isLoading,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.PlayArrow,
                        contentDescription = stringResource(R.string.susfs_update_full_clone),
                        tint = colorScheme.secondary,
                        modifier = Modifier.size(18.dp)
                    )
                }
                IconButton(
                    onClick = onDelete,
                    enabled = !isLoading,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = stringResource(R.string.delete),
                        tint = colorScheme.error,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }
    }
}

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
    val showLogConfigDialogState = remember { mutableStateOf(showLogConfigDialog) }
    
    LaunchedEffect(showLogConfigDialog) {
        showLogConfigDialogState.value = showLogConfigDialog
    }

    if (showLogConfigDialogState.value) {
        SuperDialog(
            show = showLogConfigDialogState,
            title = stringResource(R.string.susfs_log_config_title),
            onDismissRequest = {
                // 恢复原始状态
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

                    SuperSwitch(
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
                                // 恢复原始状态
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
                        // 更新当前状态
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
                // 状态标签
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

