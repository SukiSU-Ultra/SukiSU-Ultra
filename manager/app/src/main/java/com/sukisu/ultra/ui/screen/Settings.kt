package com.sukisu.ultra.ui.screen

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.graphics.Color
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
import com.sukisu.ultra.ui.component.*
import com.sukisu.ultra.ui.theme.*
import com.sukisu.ultra.ui.theme.CardConfig.cardAlpha
import com.sukisu.ultra.ui.util.LocalSnackbarHost
import com.sukisu.ultra.ui.util.getBugreportFile
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import com.sukisu.ultra.ui.component.KsuIsValid

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
private val SPACING_SMALL = 3.dp
private val SPACING_MEDIUM = 8.dp
private val SPACING_LARGE = 16.dp

@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun SettingScreen(navigator: DestinationsNavigator) {
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val snackBarHost = LocalSnackbarHost.current
    val context = LocalContext.current
    val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    var selectedEngine by rememberSaveable {
        mutableStateOf(
            prefs.getString("webui_engine", "default") ?: "default"
        )
    }

    Scaffold(
        // containerColor = MaterialTheme.colorScheme.surfaceBright,
        topBar = {
            TopBar(scrollBehavior = scrollBehavior)
        },
        snackbarHost = { SnackbarHost(snackBarHost) },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { paddingValues ->
        val aboutDialog = rememberCustomDialog {
            AboutDialog(it)
        }
        val loadingDialog = rememberLoadingDialog()

        Column(
            modifier = Modifier
                .padding(paddingValues)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
        ) {
            val context = LocalContext.current
            val scope = rememberCoroutineScope()
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

            // 配置卡片
            KsuIsValid {
                SettingsGroupCard(
                    title = stringResource(R.string.configuration),
                    content = {
                        // 配置文件模板入口
                        SettingItem(
                            icon = Icons.Filled.Fence,
                            title = stringResource(R.string.settings_profile_template),
                            summary = stringResource(R.string.settings_profile_template_summary),
                            onClick = {
                                navigator.navigate(AppProfileTemplateScreenDestination)
                            }
                        )
                        
                        // 卸载模块开关
                        var umountChecked by rememberSaveable {
                            mutableStateOf(Natives.isDefaultUmountModules())
                        }

                        SwitchItem(
                            icon = Icons.Filled.FolderDelete,
                            title = stringResource(R.string.settings_umount_modules_default),
                            summary = stringResource(R.string.settings_umount_modules_default_summary),
                            checked = umountChecked,
                            onCheckedChange = { enabled ->
                                if (Natives.setDefaultUmountModules(enabled)) {
                                    umountChecked = enabled
                                }
                            }
                        )

                        // SU 禁用开关
                        if (Natives.version >= Natives.MINIMAL_SUPPORTED_SU_COMPAT) {
                            var isSuDisabled by rememberSaveable {
                                mutableStateOf(!Natives.isSuEnabled())
                            }
                            SwitchItem(
                                icon = Icons.Filled.RemoveModerator,
                                title = stringResource(R.string.settings_disable_su),
                                summary = stringResource(R.string.settings_disable_su_summary),
                                checked = isSuDisabled,
                                onCheckedChange = { enabled ->
                                    val shouldEnable = !enabled
                                    if (Natives.setSuEnabled(shouldEnable)) {
                                        isSuDisabled = enabled
                                    }
                                }
                            )
                        }
                        // 强制签名验证开关
                        var forceSignatureVerification by rememberSaveable {
                            mutableStateOf(prefs.getBoolean("force_signature_verification", false))
                        }
                        SwitchItem(
                            icon = Icons.Filled.Security,
                            title = stringResource(R.string.module_signature_verification),
                            summary = stringResource(R.string.module_signature_verification_summary),
                            checked = forceSignatureVerification,
                            onCheckedChange = { enabled ->
                                prefs.edit { putBoolean("force_signature_verification", enabled) }
                                forceSignatureVerification = enabled
                            }
                        )
                    }
                )
            }

            // 应用设置卡片
            SettingsGroupCard(
                title = stringResource(R.string.app_settings),
                content = {
                    // 更新检查开关
                    var checkUpdate by rememberSaveable {
                        mutableStateOf(prefs.getBoolean("check_update", true))
                    }
                    SwitchItem(
                        icon = Icons.Filled.Update,
                        title = stringResource(R.string.settings_check_update),
                        summary = stringResource(R.string.settings_check_update_summary),
                        checked = checkUpdate,
                        onCheckedChange = { enabled ->
                            prefs.edit { putBoolean("check_update", enabled) }
                            checkUpdate = enabled
                        }
                    )

                    // WebUI引擎选择
                    KsuIsValid {
                        WebUIEngineSelector(
                            selectedEngine = selectedEngine,
                            onEngineSelected = { engine ->
                                selectedEngine = engine
                                prefs.edit { putString("webui_engine", engine) }
                            }
                        )
                    }

                    // Web调试和Web X Eruda 开关
                    var enableWebDebugging by rememberSaveable {
                        mutableStateOf(prefs.getBoolean("enable_web_debugging", false))
                    }
                    var useWebUIXEruda by rememberSaveable {
                        mutableStateOf(prefs.getBoolean("use_webuix_eruda", false))
                    }

                    KsuIsValid {
                        SwitchItem(
                            icon = Icons.Filled.DeveloperMode,
                            title = stringResource(R.string.enable_web_debugging),
                            summary = stringResource(R.string.enable_web_debugging_summary),
                            checked = enableWebDebugging,
                            onCheckedChange = { enabled ->
                                prefs.edit { putBoolean("enable_web_debugging", enabled) }
                                enableWebDebugging = enabled
                            }
                        )

                        AnimatedVisibility(
                            visible = enableWebDebugging && selectedEngine == "wx",
                            enter = fadeIn() + expandVertically(),
                            exit = fadeOut() + shrinkVertically()
                        ) {
                            SwitchItem(
                                icon = Icons.Filled.FormatListNumbered,
                                title = stringResource(R.string.use_webuix_eruda),
                                summary = stringResource(R.string.use_webuix_eruda_summary),
                                checked = useWebUIXEruda,
                                onCheckedChange = { enabled ->
                                    prefs.edit { putBoolean("use_webuix_eruda", enabled) }
                                    useWebUIXEruda = enabled
                                }
                            )
                        }
                    }

                    // 更多设置
                    SettingItem(
                        icon = Icons.Filled.Settings,
                        title = stringResource(R.string.more_settings),
                        summary = stringResource(R.string.more_settings),
                        onClick = {
                            navigator.navigate(MoreSettingsScreenDestination)
                        }
                    )
                }
            )

            // 工具卡片
            SettingsGroupCard(
                title = stringResource(R.string.tools),
                content = {
                    var showBottomsheet by remember { mutableStateOf(false) }

                    SettingItem(
                        icon = Icons.Filled.BugReport,
                        title = stringResource(R.string.send_log),
                        onClick = {
                            showBottomsheet = true
                        }
                    )

                    if (showBottomsheet) {
                        LogBottomSheet(
                            onDismiss = { showBottomsheet = false },
                            onSaveLog = {
                                val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH_mm")
                                val current = LocalDateTime.now().format(formatter)
                                exportBugreportLauncher.launch("KernelSU_bugreport_${current}.tar.gz")
                                showBottomsheet = false
                            },
                            onShareLog = {
                                scope.launch {
                                    val bugreport = loadingDialog.withLoading {
                                        withContext(Dispatchers.IO) {
                                            getBugreportFile(context)
                                        }
                                    }

                                    val uri = FileProvider.getUriForFile(
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

                    val lkmMode = Natives.version >= Natives.MINIMAL_SUPPORTED_KERNEL_LKM && Natives.isLkmMode
                    if (lkmMode) {
                        UninstallItem(navigator) {
                            loadingDialog.withLoading(it)
                        }
                    }
                }
            )

            // 关于卡片
            SettingsGroupCard(
                title = stringResource(R.string.about),
                content = {
                    SettingItem(
                        icon = Icons.Filled.Info,
                        title = stringResource(R.string.about),
                        onClick = {
                            aboutDialog.show()
                        }
                    )
                }
            )

            Spacer(modifier = Modifier.height(SPACING_LARGE))
        }
    }
}

@Composable
private fun SettingsGroupCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = SPACING_LARGE, vertical = SPACING_MEDIUM),
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerLow),
        elevation = getCardElevation()
    ) {
        Column(
            modifier = Modifier.padding(vertical = SPACING_MEDIUM)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = SPACING_LARGE, vertical = SPACING_MEDIUM),
                color = MaterialTheme.colorScheme.primary
            )
            content()
        }
    }
}

@Composable
private fun WebUIEngineSelector(
    selectedEngine: String,
    onEngineSelected: (String) -> Unit
) {
    var showDialog by remember { mutableStateOf(false) }
    val engineOptions = listOf(
        "default" to stringResource(R.string.engine_auto_select),
        "wx" to stringResource(R.string.engine_force_webuix),
        "ksu" to stringResource(R.string.engine_force_ksu)
    )

    SettingItem(
        icon = Icons.Filled.WebAsset,
        title = stringResource(R.string.use_webuix),
        summary = engineOptions.find { it.first == selectedEngine }?.second
            ?: stringResource(R.string.engine_auto_select),
        onClick = { showDialog = true }
    )

    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            title = { Text(stringResource(R.string.use_webuix)) },
            text = {
                Column {
                    engineOptions.forEach { (value, label) ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    onEngineSelected(value)
                                    showDialog = false
                                }
                                .padding(vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = selectedEngine == value,
                                onClick = null
                            )
                            Spacer(modifier = Modifier.width(SPACING_MEDIUM))
                            Text(text = label)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LogBottomSheet(
    onDismiss: () -> Unit,
    onSaveLog: () -> Unit,
    onShareLog: () -> Unit
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(SPACING_LARGE),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            LogActionButton(
                icon = Icons.Filled.Save,
                text = stringResource(R.string.save_log),
                onClick = onSaveLog
            )

            LogActionButton(
                icon = Icons.Filled.Share,
                text = stringResource(R.string.send_log),
                onClick = onShareLog
            )
        }
        Spacer(modifier = Modifier.height(SPACING_LARGE))
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
            .padding(SPACING_MEDIUM)
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
        Spacer(modifier = Modifier.height(SPACING_MEDIUM))
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium
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
            .padding(horizontal = SPACING_LARGE, vertical = 12.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier
                .padding(end = SPACING_LARGE)
                .size(24.dp)
        )

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium
            )
            if (summary != null) {
                Spacer(modifier = Modifier.height(SPACING_SMALL))
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodyMedium
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
fun SwitchItem(
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
            .padding(horizontal = SPACING_LARGE, vertical = 12.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (checked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier
                .padding(end = SPACING_LARGE)
                .size(24.dp)
        )

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium
            )
            if (summary != null) {
                Spacer(modifier = Modifier.height(SPACING_SMALL))
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange
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

        var selectedOption by remember { mutableStateOf<UninstallType?>(null) }

        MaterialTheme(
            colorScheme = MaterialTheme.colorScheme.copy(
                surface = MaterialTheme.colorScheme.surfaceContainerHigh
            )
        ) {
            AlertDialog(
                onDismissRequest = {
                    dismiss()
                },
                title = {
                    Text(
                        text = stringResource(R.string.settings_uninstall),
                        style = MaterialTheme.typography.headlineSmall,
                    )
                },
                text = {
                    Column(
                        modifier = Modifier.padding(vertical = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        options.forEachIndexed { index, option ->
                            val isSelected = selectedOption == option
                            val backgroundColor = if (isSelected)
                                MaterialTheme.colorScheme.primaryContainer
                            else
                                Color.Transparent
                            val contentColor = if (isSelected)
                                MaterialTheme.colorScheme.onPrimaryContainer
                            else
                                MaterialTheme.colorScheme.onSurface

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(MaterialTheme.shapes.medium)
                                    .background(backgroundColor)
                                    .clickable {
                                        selectedOption = option
                                    }
                                    .padding(vertical = 12.dp, horizontal = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = option.icon,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier
                                        .padding(end = 16.dp)
                                        .size(24.dp)
                                )
                                Column(
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(
                                        text = listOptions[index].titleText,
                                        style = MaterialTheme.typography.titleMedium,
                                    )
                                    listOptions[index].subtitleText?.let {
                                        Text(
                                            text = it,
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = if (isSelected)
                                                contentColor.copy(alpha = 0.8f)
                                            else
                                                MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                                if (isSelected) {
                                    Icon(
                                        imageVector = Icons.Default.RadioButtonChecked,
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
                },
                confirmButton = {
                    Button(
                        onClick = {
                            selectedOption?.let { onSelected(it) }
                            dismiss()
                        },
                        enabled = selectedOption != null,
                    ) {
                        Text(
                            text = stringResource(android.R.string.ok)
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
                        )
                    }
                },
                shape = MaterialTheme.shapes.extraLarge,
                tonalElevation = 4.dp
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar(
    scrollBehavior: TopAppBarScrollBehavior? = null
) {
    val colorScheme = MaterialTheme.colorScheme
    val cardColor = if (CardConfig.isCustomBackgroundEnabled) {
        colorScheme.surfaceContainerLow
    } else {
        colorScheme.background
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
