package com.sukisu.ultra.ui.screen

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Undo
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.core.content.edit
import com.maxkeppeker.sheets.core.models.base.IconSource
import com.maxkeppeler.sheets.list.models.ListOption
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.AppProfileTemplateScreenDestination
import com.ramcosta.composedestinations.generated.destinations.FlashScreenDestination
import com.ramcosta.composedestinations.generated.destinations.MoreSettingsScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.*
import com.sukisu.ultra.ui.component.*
import com.sukisu.ultra.ui.theme.*
import com.sukisu.ultra.ui.theme.CardConfig.cardAlpha
import com.sukisu.ultra.ui.util.LocalSnackbarHost
import com.sukisu.ultra.ui.util.getBugreportFile
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter


@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun SettingScreen(navigator: DestinationsNavigator) {
    val scrollBehavior = TopAppBarDefaults.enterAlwaysScrollBehavior(rememberTopAppBarState())
    val snackBarHost = LocalSnackbarHost.current
    val ksuIsValid = Natives.isKsuValid(ksuApp.packageName)

    Scaffold(
        topBar = {
            TopBar(
                scrollBehavior = scrollBehavior
            )
        },
        snackbarHost = { SnackbarHost(snackBarHost) },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { paddingValues ->
        val aboutDialog = rememberCustomDialog {
            AboutDialog(it)
        }
        val loadingDialog = rememberLoadingDialog()
        // endregion

        Column(
            modifier = Modifier
                .padding(paddingValues)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
        ) {
            // region 上下文与协程
            val context = LocalContext.current
            val scope = rememberCoroutineScope()
            // endregion

            // region 日志导出功能
            val exportBugreportLauncher = rememberLauncherForActivityResult(
                ActivityResultContracts.CreateDocument("application/gzip")
            ) { uri: Uri? ->
                if (uri == null) return@rememberLauncherForActivityResult
                scope.launch(Dispatchers.IO) {
                    loadingDialog.show()
                    context.contentResolver.openOutputStream(uri)?.use { output ->
                        getBugreportFile(context).inputStream().use {
                            it.copyTo(output)
                        }
                    }
                    loadingDialog.hide()
                    snackBarHost.showSnackbar(context.getString(R.string.log_saved))
                }
            }

            // 设置分组卡片 - 配置
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = cardAlpha)
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
            ) {
                Column(modifier = Modifier.padding(vertical = 8.dp)) {
                    Text(
                        text = stringResource(R.string.configuration),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                    )

                    // 配置文件模板入口
                    val profileTemplate = stringResource(id = R.string.settings_profile_template)
                    if (ksuIsValid) {
                        SettingItem(
                            icon = Icons.Filled.Fence,
                            title = profileTemplate,
                            summary = stringResource(id = R.string.settings_profile_template_summary),
                            onClick = {
                                navigator.navigate(AppProfileTemplateScreenDestination)
                            }
                        )
                    }

                    // 卸载模块开关
                    var umountChecked by rememberSaveable {
                        mutableStateOf(Natives.isDefaultUmountModules())
                    }

                    if (ksuIsValid) {
                        SwitchSettingItem(
                            icon = Icons.Filled.FolderDelete,
                            title = stringResource(id = R.string.settings_umount_modules_default),
                            summary = stringResource(id = R.string.settings_umount_modules_default_summary),
                            checked = umountChecked,
                            onCheckedChange = {
                                if (Natives.setDefaultUmountModules(it)) {
                                    umountChecked = it
                                }
                            }
                        )
                    }

                    // SU 禁用开关（仅在兼容版本显示）
                    if (ksuIsValid) {
                        if (Natives.version >= Natives.MINIMAL_SUPPORTED_SU_COMPAT) {
                            var isSuDisabled by rememberSaveable {
                                mutableStateOf(!Natives.isSuEnabled())
                            }
                            SwitchSettingItem(
                                icon = Icons.Filled.RemoveModerator,
                                title = stringResource(id = R.string.settings_disable_su),
                                summary = stringResource(id = R.string.settings_disable_su_summary),
                                checked = isSuDisabled,
                                onCheckedChange = { checked ->
                                    val shouldEnable = !checked
                                    if (Natives.setSuEnabled(shouldEnable)) {
                                        isSuDisabled = !shouldEnable
                                    }
                                }
                            )
                        }
                    }
                }
            }

            // 设置分组卡片 - 应用设置
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = cardAlpha)
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
            ) {
                Column(modifier = Modifier.padding(vertical = 8.dp)) {
                    Text(
                        text = stringResource(R.string.app_settings),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                    )

                    val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

                    // 更新检查开关
                    var checkUpdate by rememberSaveable {
                        mutableStateOf(
                            prefs.getBoolean("check_update", true)
                        )
                    }
                    SwitchSettingItem(
                        icon = Icons.Filled.Update,
                        title = stringResource(id = R.string.settings_check_update),
                        summary = stringResource(id = R.string.settings_check_update_summary),
                        checked = checkUpdate,
                        onCheckedChange = {
                            prefs.edit {putBoolean("check_update", it) }
                            checkUpdate = it
                        }
                    )

                    // Web调试开关
                    var enableWebDebugging by rememberSaveable {
                        mutableStateOf(
                            prefs.getBoolean("enable_web_debugging", false)
                        )
                    }
                    if (Natives.isKsuValid(ksuApp.packageName)) {
                        SwitchSettingItem(
                            icon = Icons.Filled.DeveloperMode,
                            title = stringResource(id = R.string.enable_web_debugging),
                            summary = stringResource(id = R.string.enable_web_debugging_summary),
                            checked = enableWebDebugging,
                            onCheckedChange = {
                                prefs.edit { putBoolean("enable_web_debugging", it) }
                                enableWebDebugging = it
                            }
                        )
                    }

                    // 更多设置
                    SettingItem(
                        icon = Icons.Filled.Settings,
                        title = stringResource(id = R.string.more_settings),
                        summary = stringResource(id = R.string.more_settings),
                        onClick = {
                            navigator.navigate(MoreSettingsScreenDestination)
                        }
                    )
                }
            }

            // 设置分组卡片 - 工具
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = cardAlpha)
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
            ) {
                Column(modifier = Modifier.padding(vertical = 8.dp)) {
                    Text(
                        text = stringResource(R.string.tools),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                    )

                    var showBottomsheet by remember { mutableStateOf(false) }

                    SettingItem(
                        icon = Icons.Filled.BugReport,
                        title = stringResource(id = R.string.send_log),
                        onClick = {
                            showBottomsheet = true
                        }
                    )

                    if (showBottomsheet) {
                        ModalBottomSheet(
                            onDismissRequest = { showBottomsheet = false },
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(16.dp),
                                horizontalArrangement = Arrangement.SpaceEvenly
                            ) {
                                LogActionButton(
                                    icon = Icons.Filled.Save,
                                    text = stringResource(R.string.save_log),
                                    onClick = {
                                        val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH_mm")
                                        val current = LocalDateTime.now().format(formatter)
                                        exportBugreportLauncher.launch("KernelSU_bugreport_${current}.tar.gz")
                                        showBottomsheet = false
                                    }
                                )

                                LogActionButton(
                                    icon = Icons.Filled.Share,
                                    text = stringResource(R.string.send_log),
                                    onClick = {
                                        scope.launch {
                                            val bugreport = loadingDialog.withLoading {
                                                withContext(Dispatchers.IO) {
                                                    getBugreportFile(context)
                                                }
                                            }

                                            val uri: Uri =
                                                FileProvider.getUriForFile(
                                                    context,
                                                    "${BuildConfig.APPLICATION_ID}.fileprovider",
                                                    bugreport
                                                )

                                            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                                putExtra(Intent.EXTRA_STREAM, uri)
                                                setDataAndType(uri, "application/gzip")
                                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                            }

                                            context.startActivity(
                                                Intent.createChooser(
                                                    shareIntent,
                                                    context.getString(R.string.send_log)
                                                )
                                            )

                                            showBottomsheet = false
                                        }
                                    }
                                )
                            }
                            Spacer(modifier = Modifier.height(16.dp))
                        }
                    }

                    val lkmMode = Natives.version >= Natives.MINIMAL_SUPPORTED_KERNEL_LKM && Natives.isLkmMode
                    if (lkmMode) {
                        UninstallItem(navigator) {
                            loadingDialog.withLoading(it)
                        }
                    }
                }
            }

            // 设置分组卡片 - 关于
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = cardAlpha)
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
            ) {
                Column(modifier = Modifier.padding(vertical = 8.dp)) {
                    Text(
                        text = stringResource(R.string.about),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                    )

                    SettingItem(
                        icon = Icons.Filled.Info,
                        title = stringResource(R.string.about),
                        onClick = {
                            aboutDialog.show()
                        }
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
fun LogActionButton(
    icon: ImageVector,
    text: String,
    onClick: () -> Unit
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .clickable(onClick = onClick)
            .padding(8.dp)
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(56.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primaryContainer)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = text,
                tint = MaterialTheme.colorScheme.onPrimaryContainer,
                modifier = Modifier.size(24.dp)
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
fun SettingItem(
    icon: ImageVector,
    title: String,
    summary: String? = null,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier
                .padding(end = 16.dp)
                .size(24.dp)
        )

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            if (summary != null) {
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Icon(
            imageVector = Icons.Filled.ChevronRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp)
        )
    }
}

@Composable
fun SwitchSettingItem(
    icon: ImageVector,
    title: String,
    summary: String? = null,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier
                .padding(end = 16.dp)
                .size(24.dp)
        )

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            if (summary != null) {
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                checkedTrackColor = MaterialTheme.colorScheme.primary,
                checkedIconColor = MaterialTheme.colorScheme.primary,
                uncheckedThumbColor = MaterialTheme.colorScheme.outline,
                uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant,
                uncheckedIconColor = MaterialTheme.colorScheme.surfaceVariant
            )
        )
    }
}

@Composable
fun UninstallItem(
    navigator: DestinationsNavigator,
    withLoading: suspend (suspend () -> Unit) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val uninstallConfirmDialog = rememberConfirmDialog()
    val showTodo = {
        Toast.makeText(context, "TODO", Toast.LENGTH_SHORT).show()
    }
    val uninstallDialog = rememberUninstallDialog { uninstallType ->
        scope.launch {
            val result = uninstallConfirmDialog.awaitConfirm(
                title = context.getString(uninstallType.title),
                content = context.getString(uninstallType.message)
            )
            if (result == ConfirmResult.Confirmed) {
                withLoading {
                    when (uninstallType) {
                        UninstallType.TEMPORARY -> showTodo()
                        UninstallType.PERMANENT -> navigator.navigate(
                            FlashScreenDestination(FlashIt.FlashUninstall)
                        )
                        UninstallType.RESTORE_STOCK_IMAGE -> navigator.navigate(
                            FlashScreenDestination(FlashIt.FlashRestore)
                        )
                        UninstallType.NONE -> Unit
                    }
                }
            }
        }
    }

    SettingItem(
        icon = Icons.Filled.Delete,
        title = stringResource(id = R.string.settings_uninstall),
        onClick = {
            uninstallDialog.show()
        }
    )
}

enum class UninstallType(val title: Int, val message: Int, val icon: ImageVector) {
    TEMPORARY(
        R.string.settings_uninstall_temporary,
        R.string.settings_uninstall_temporary_message,
        Icons.Filled.Delete
    ),
    PERMANENT(
        R.string.settings_uninstall_permanent,
        R.string.settings_uninstall_permanent_message,
        Icons.Filled.DeleteForever
    ),
    RESTORE_STOCK_IMAGE(
        R.string.settings_restore_stock_image,
        R.string.settings_restore_stock_image_message,
        Icons.AutoMirrored.Filled.Undo
    ),
    NONE(0, 0, Icons.Filled.Delete)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun rememberUninstallDialog(onSelected: (UninstallType) -> Unit): DialogHandle {
    return rememberCustomDialog { dismiss ->
        val options = listOf(
            // UninstallType.TEMPORARY,
            UninstallType.PERMANENT,
            UninstallType.RESTORE_STOCK_IMAGE
        )
        val listOptions = options.map {
            ListOption(
                titleText = stringResource(it.title),
                subtitleText = if (it.message != 0) stringResource(it.message) else null,
                icon = IconSource(it.icon)
            )
        }

        var selection = UninstallType.NONE
        val cardColor = if (!ThemeConfig.useDynamicColor) {
            ThemeConfig.currentTheme.ButtonContrast
        } else {
            MaterialTheme.colorScheme.surfaceContainerHigh
        }

        AlertDialog(
            onDismissRequest = {
                dismiss()
            },
            title = {
                Text(
                    text = stringResource(R.string.settings_uninstall),
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            },
            text = {
                Column(
                    modifier = Modifier.padding(vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    listOptions.forEachIndexed { index, option ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(MaterialTheme.shapes.medium)
                                .clickable {
                                    selection = options[index]
                                }
                                .padding(vertical = 12.dp, horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = options[index].icon,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier
                                    .padding(end = 16.dp)
                                    .size(24.dp)
                            )
                            Column {
                                Text(
                                    text = option.titleText,
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                option.subtitleText?.let {
                                    Text(
                                        text = it,
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (selection != UninstallType.NONE) {
                            onSelected(selection)
                        }
                        dismiss()
                    }
                ) {
                    Text(
                        text = stringResource(android.R.string.ok),
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        dismiss()
                    }
                ) {
                    Text(
                        text = stringResource(android.R.string.cancel),
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            },
            containerColor = cardColor,
            shape = MaterialTheme.shapes.extraLarge,
            tonalElevation = 4.dp
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar(
    scrollBehavior: TopAppBarScrollBehavior? = null
) {
    val systemIsDark = isSystemInDarkTheme()
    val cardColor = MaterialTheme.colorScheme.surfaceVariant
    val cardAlpha = if (ThemeConfig.customBackgroundUri != null) {
        cardAlpha
    } else {
        if (systemIsDark) 0.35f else 0.80f
    }

    TopAppBar(
        title = {
            Text(
                text = stringResource(R.string.settings),
                style = MaterialTheme.typography.titleLarge
            )
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = cardColor.copy(alpha = cardAlpha),
            scrolledContainerColor = cardColor.copy(alpha = cardAlpha)
        ),
        windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        scrollBehavior = scrollBehavior
    )
}