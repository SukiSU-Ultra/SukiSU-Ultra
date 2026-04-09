package com.sukisu.ultra.ui.screen.susfs.component.miuix

import android.annotation.SuppressLint
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.util.Log
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.background
import androidx.compose.foundation.lazy.LazyColumn
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
import androidx.compose.foundation.lazy.items
import androidx.core.graphics.drawable.toBitmap
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.util.AppInfoCache
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.overlay.OverlayDialog

@Composable
fun AppIconMiuix(
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
                            try {
                                val packageManager = context.packageManager
                                val applicationInfo = packageManager.getApplicationInfo(packageName, 0)
                                val icon = packageManager.getApplicationIcon(applicationInfo)
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
fun AppPathGroupCardMiuix(
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
                AppIconMiuix(
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
fun AddPathDialogMiuix(
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

    val showDialogState = remember { mutableStateOf(showDialog) }

    LaunchedEffect(showDialog) {
        showDialogState.value = showDialog
    }

    if (showDialogState.value) {
        OverlayDialog(
            show = showDialogState.value,
            title = stringResource(titleRes),
            onDismissRequest = {
                onDismiss()
                newPath = ""
            },
            content = {
                Column(
                    modifier = Modifier.padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    TextField(
                        value = newPath,
                        onValueChange = { newPath = it },
                        label = stringResource(labelRes),
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isLoading
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = {
                                onDismiss()
                                newPath = ""
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                        Button(
                            onClick = {
                                if (newPath.isNotBlank()) {
                                    onConfirm(newPath.trim())
                                    newPath = ""
                                }
                            },
                            enabled = newPath.isNotBlank() && !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(
                                text = stringResource(
                                    if (initialValue.isNotEmpty()) R.string.susfs_save else R.string.add
                                )
                            )
                        }
                    }
                }
            }
        )
    }
}

@Composable
fun AddAppPathDialogMiuix(
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

    val showDialogState = remember { mutableStateOf(showDialog) }

    LaunchedEffect(showDialog) {
        showDialogState.value = showDialog
    }

    if (showDialogState.value) {
        OverlayDialog(
            show = showDialogState.value,
            title = stringResource(R.string.susfs_add_app_path),
            onDismissRequest = {
                onDismiss()
                selectedApps = setOf()
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
                                        AppIconMiuix(
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

@Composable
fun AddKstatStaticallyDialogMiuix(
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

    UniversalDialogMiuix(
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
            DialogFieldMiuix.CustomContent {
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
fun PathItemCardMiuix(
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
fun KstatConfigItemCardMiuix(
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
                            text = parts[0],
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

@Composable
fun AddKstatPathItemCardMiuix(
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
