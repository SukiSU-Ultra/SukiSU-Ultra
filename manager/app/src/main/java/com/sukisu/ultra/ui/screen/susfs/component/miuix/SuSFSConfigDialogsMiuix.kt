package com.sukisu.ultra.ui.screen.susfs.component.miuix

import android.annotation.SuppressLint
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshotFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.screen.susfs.util.AppInfoCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults as MiuixButtonDefaults
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.window.WindowDialog

@Composable
fun AppIconMiuix(
    packageName: String,
    packageInfo: PackageInfo? = null,
    @SuppressLint("ModifierParameter") modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val resolvedInfo by produceState(packageInfo, packageName, packageInfo) {
        if (value == null) {
            value = withContext(Dispatchers.IO) {
                AppInfoCache.getAppInfoFromSuperUser(packageName)?.packageInfo
                    ?: runCatching { context.packageManager.getPackageInfo(packageName, 0) }.getOrNull()
            }
        }
    }
    resolvedInfo?.let {
        com.sukisu.ultra.ui.component.AppIconImage(
            packageInfo = it,
            label = packageName,
            modifier = modifier,
        )
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

    AppCard(
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
        WindowDialog(
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
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                        Button(
                            onClick = {
                                if (newPath.isNotBlank()) {
                                    onConfirm(newPath.trim())
                                }
                            },
                            enabled = newPath.isNotBlank() && !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
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
                newKstatIno = parts[1].takeUnless { it == "default" }.orEmpty()
                newKstatDev = parts[2].takeUnless { it == "default" }.orEmpty()
                newKstatNlink = parts[3].takeUnless { it == "default" }.orEmpty()
                newKstatSize = parts[4].takeUnless { it == "default" }.orEmpty()
                newKstatAtime = parts[5].takeUnless { it == "default" }.orEmpty()
                newKstatAtimeNsec = parts[6].takeUnless { it == "default" }.orEmpty()
                newKstatMtime = parts[7].takeUnless { it == "default" }.orEmpty()
                newKstatMtimeNsec = parts[8].takeUnless { it == "default" }.orEmpty()
                newKstatCtime = parts[9].takeUnless { it == "default" }.orEmpty()
                newKstatCtimeNsec = parts[10].takeUnless { it == "default" }.orEmpty()
                newKstatBlocks = parts[11].takeUnless { it == "default" }.orEmpty()
                newKstatBlksize = parts[12].takeUnless { it == "default" }.orEmpty()
            }
        } else if (showDialog) {
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
        WindowDialog(
            show = true,
            title = stringResource(if (initialConfig.isNotEmpty()) R.string.edit_kstat_statically_title else R.string.add_kstat_statically_title),
            onDismissRequest = {
                onDismiss()
                resetFields()
            }
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 620.dp)
                    .padding(horizontal = 24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Column(
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    TextField(
                        value = newKstatPath,
                        onValueChange = { newKstatPath = it },
                        label = stringResource(R.string.file_or_directory_path_label),
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isLoading,
                        singleLine = true
                    )

                    KstatSectionMiuix(stringResource(R.string.kstat_section_identity)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMiuix("ino", newKstatIno, { newKstatIno = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMiuix("dev", newKstatDev, { newKstatDev = it }, !isLoading, Modifier.weight(1f))
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMiuix("nlink", newKstatNlink, { newKstatNlink = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMiuix("size", newKstatSize, { newKstatSize = it }, !isLoading, Modifier.weight(1f))
                        }
                    }

                    KstatSectionMiuix(stringResource(R.string.kstat_section_timestamps)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMiuix("atime", newKstatAtime, { newKstatAtime = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMiuix("atime_nsec", newKstatAtimeNsec, { newKstatAtimeNsec = it }, !isLoading, Modifier.weight(1f))
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMiuix("mtime", newKstatMtime, { newKstatMtime = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMiuix("mtime_nsec", newKstatMtimeNsec, { newKstatMtimeNsec = it }, !isLoading, Modifier.weight(1f))
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMiuix("ctime", newKstatCtime, { newKstatCtime = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMiuix("ctime_nsec", newKstatCtimeNsec, { newKstatCtimeNsec = it }, !isLoading, Modifier.weight(1f))
                        }
                    }

                    KstatSectionMiuix(stringResource(R.string.kstat_section_storage)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            KstatNumberFieldMiuix("blocks", newKstatBlocks, { newKstatBlocks = it }, !isLoading, Modifier.weight(1f))
                            KstatNumberFieldMiuix("blksize", newKstatBlksize, { newKstatBlksize = it }, !isLoading, Modifier.weight(1f))
                        }
                    }

                    AppCard(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.defaultColors(color = colorScheme.secondaryContainer)
                    ) {
                        Text(
                            text = stringResource(R.string.hint_use_default_value),
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                            style = MiuixTheme.textStyles.body2,
                            color = colorScheme.onSecondaryContainer
                        )
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    MiuixTextButton(
                        text = stringResource(R.string.cancel),
                        onClick = {
                            onDismiss()
                            resetFields()
                        },
                        enabled = !isLoading,
                        modifier = Modifier.weight(1f)
                    )
                    MiuixTextButton(
                        text = stringResource(if (initialConfig.isNotEmpty()) R.string.susfs_save else R.string.add),
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
                        enabled = newKstatPath.isNotBlank() && !isLoading,
                        modifier = Modifier.weight(1f),
                        colors = MiuixButtonDefaults.textButtonColorsPrimary()
                    )
                }
            }
        }
    }
}

@Composable
private fun KstatSectionMiuix(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    AppCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(color = colorScheme.surfaceContainer)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = title,
                style = MiuixTheme.textStyles.body1,
                fontWeight = FontWeight.Medium,
                color = colorScheme.primary
            )
            content()
        }
    }
}

@Composable
private fun KstatNumberFieldMiuix(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean,
    modifier: Modifier = Modifier
) {
    TextField(
        value = value,
        onValueChange = onValueChange,
        label = label,
        useLabelAsPlaceholder = true,
        modifier = modifier,
        enabled = enabled,
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.NumberSigned
        )
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
    AppCard(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp)
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
                        modifier = Modifier.size(48.dp)
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
                    modifier = Modifier.size(48.dp)
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
    AppCard(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp)
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
                        modifier = Modifier.size(48.dp)
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
                    modifier = Modifier.size(48.dp)
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
    AppCard(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp)
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
                        modifier = Modifier.size(48.dp)
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
                    modifier = Modifier.size(48.dp)
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
                    modifier = Modifier.size(48.dp)
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
                    modifier = Modifier.size(48.dp)
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
