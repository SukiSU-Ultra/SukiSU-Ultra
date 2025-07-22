package com.sukisu.ultra.ui.screen

import android.annotation.SuppressLint
import android.app.Activity.*
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.*
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.*
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.ExecuteModuleActionScreenDestination
import com.ramcosta.composedestinations.generated.destinations.FlashScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.navigation.EmptyDestinationsNavigator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.component.ConfirmResult
import com.sukisu.ultra.ui.component.SearchAppBar
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.component.rememberLoadingDialog
import com.sukisu.ultra.ui.util.DownloadListener
import com.sukisu.ultra.ui.util.*
import com.sukisu.ultra.ui.util.download
import com.sukisu.ultra.ui.util.hasMagisk
import com.sukisu.ultra.ui.util.reboot
import com.sukisu.ultra.ui.util.restoreModule
import com.sukisu.ultra.ui.util.toggleModule
import com.sukisu.ultra.ui.util.uninstallModule
import com.sukisu.ultra.ui.webui.WebUIActivity
import okhttp3.OkHttpClient
import com.sukisu.ultra.ui.util.ModuleModify
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.viewmodel.ModuleViewModel
import java.util.concurrent.TimeUnit
import androidx.core.content.edit
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.webui.WebUIXActivity
import com.dergoogler.mmrl.platform.Platform
import androidx.core.net.toUri
import com.dergoogler.mmrl.platform.model.ModuleConfig
import com.dergoogler.mmrl.platform.model.ModuleConfig.Companion.asModuleConfig
import com.sukisu.ultra.ui.component.AnimatedFab
import com.sukisu.ultra.ui.component.rememberFabVisibilityState
import com.sukisu.ultra.ui.theme.getCardElevation

// 菜单项数据类
data class ModuleBottomSheetMenuItem(
    val icon: ImageVector,
    val titleRes: Int,
    val onClick: () -> Unit
)

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
@SuppressLint("ResourceType", "AutoboxingStateCreation")
@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun ModuleScreen(navigator: DestinationsNavigator) {
    val viewModel = viewModel<ModuleViewModel>()
    val context = LocalContext.current
    val snackBarHost = LocalSnackbarHost.current
    val scope = rememberCoroutineScope()
    val confirmDialog = rememberConfirmDialog()
    var lastClickTime by remember { mutableStateOf(0L) }

    // 初始化缓存系统
    LaunchedEffect(Unit) {
        viewModel.initializeCache(context)
    }

    // BottomSheet状态
    val bottomSheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true
    )
    var showBottomSheet by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val fabVisible by rememberFabVisibilityState(listState)

    val selectZipLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode != RESULT_OK) {
            return@rememberLauncherForActivityResult
        }
        val data = it.data ?: return@rememberLauncherForActivityResult

        scope.launch {
            val clipData = data.clipData
            if (clipData != null) {
                val selectedModules = mutableListOf<Uri>()
                val selectedModuleNames = mutableMapOf<Uri, String>()

                fun processUri(uri: Uri) {
                    try {
                        if (!ModuleUtils.isUriAccessible(context, uri)) {
                            return
                        }
                        ModuleUtils.takePersistableUriPermission(context, uri)
                        val moduleName = ModuleUtils.extractModuleName(context, uri)
                        selectedModules.add(uri)
                        selectedModuleNames[uri] = moduleName
                    } catch (e: Exception) {
                        Log.e("ModuleScreen", "Error while processing URI: $uri, Error: ${e.message}")
                    }
                }

                for (i in 0 until clipData.itemCount) {
                    val uri = clipData.getItemAt(i).uri
                    processUri(uri)
                }

                if (selectedModules.isEmpty()) {
                    snackBarHost.showSnackbar("Unable to access selected module files")
                    return@launch
                }

                val modulesList = selectedModuleNames.values.joinToString("\n• ", "• ")
                val confirmResult = confirmDialog.awaitConfirm(
                    title = context.getString(R.string.module_install),
                    content = context.getString(R.string.module_install_multiple_confirm_with_names, selectedModules.size, modulesList),
                    confirm = context.getString(R.string.install),
                    dismiss = context.getString(R.string.cancel)
                )

                if (confirmResult == ConfirmResult.Confirmed) {
                    try {
                        // 批量安装模块
                        navigator.navigate(FlashScreenDestination(FlashIt.FlashModules(selectedModules)))
                        viewModel.markNeedRefresh()
                    } catch (e: Exception) {
                        Log.e("ModuleScreen", "Error navigating to FlashScreen: ${e.message}")
                        snackBarHost.showSnackbar("Error while installing module: ${e.message}")
                    }
                }
            } else {
                val uri = data.data ?: return@launch
                // 单个安装模块
                try {
                    if (!ModuleUtils.isUriAccessible(context, uri)) {
                        snackBarHost.showSnackbar("Unable to access selected module files")
                        return@launch
                    }

                    ModuleUtils.takePersistableUriPermission(context, uri)

                    val moduleName = ModuleUtils.extractModuleName(context, uri)

                    val confirmResult = confirmDialog.awaitConfirm(
                        title = context.getString(R.string.module_install),
                        content = context.getString(R.string.module_install_confirm, moduleName),
                        confirm = context.getString(R.string.install),
                        dismiss = context.getString(R.string.cancel)
                    )

                    if (confirmResult == ConfirmResult.Confirmed) {
                        navigator.navigate(FlashScreenDestination(FlashIt.FlashModule(uri)))
                        viewModel.markNeedRefresh()
                    }
                } catch (e: Exception) {
                    Log.e("ModuleScreen", "Error processing a single URI: $uri, Error: ${e.message}")
                    snackBarHost.showSnackbar("Error processing module file: ${e.message}")
                }
            }
        }
    }

    val backupLauncher = ModuleModify.rememberModuleBackupLauncher(context, snackBarHost)
    val restoreLauncher = ModuleModify.rememberModuleRestoreLauncher(context, snackBarHost)

    val prefs = context.getSharedPreferences("settings", MODE_PRIVATE)

    LaunchedEffect(Unit) {
        if (viewModel.moduleList.isEmpty() || viewModel.isNeedRefresh) {
            viewModel.sortEnabledFirst = prefs.getBoolean("module_sort_enabled_first", false)
            viewModel.sortActionFirst = prefs.getBoolean("module_sort_action_first", false)
            viewModel.fetchModuleList()
        }
    }

    val isSafeMode = Natives.isSafeMode
    val hasMagisk = hasMagisk()

    val hideInstallButton = isSafeMode || hasMagisk

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    val webUILauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { viewModel.fetchModuleList() }

    // BottomSheet菜单项
    val bottomSheetMenuItems = remember {
        listOf(
            ModuleBottomSheetMenuItem(
                icon = Icons.Outlined.Save,
                titleRes = R.string.backup_modules,
                onClick = {
                    backupLauncher.launch(ModuleModify.createBackupIntent())
                    scope.launch {
                        bottomSheetState.hide()
                        showBottomSheet = false
                    }
                }
            ),
            ModuleBottomSheetMenuItem(
                icon = Icons.Outlined.RestoreFromTrash,
                titleRes = R.string.restore_modules,
                onClick = {
                    restoreLauncher.launch(ModuleModify.createRestoreIntent())
                    scope.launch {
                        bottomSheetState.hide()
                        showBottomSheet = false
                    }
                }
            )
        )
    }

    Scaffold(
        topBar = {
            SearchAppBar(
                title = { Text(stringResource(R.string.module)) },
                searchText = viewModel.search,
                onSearchTextChange = { viewModel.search = it },
                onClearClick = { viewModel.search = "" },
                dropdownContent = {
                    IconButton(
                        onClick = { showBottomSheet = true },
                    ) {
                        Icon(
                            imageVector = Icons.Filled.MoreVert,
                            contentDescription = stringResource(id = R.string.settings),
                        )
                    }
                },
                scrollBehavior = scrollBehavior,
            )
        },
        floatingActionButton = {
            AnimatedFab(visible = !hideInstallButton && fabVisible) {
                FloatingActionButton(
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                    containerColor = MaterialTheme.colorScheme.primary,
                    onClick = {
                        selectZipLauncher.launch(
                            Intent(Intent.ACTION_GET_CONTENT).apply {
                                type = "application/zip"
                                putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
                            }
                        )
                    },
                    content = {
                        Icon(
                            painter = painterResource(id = R.drawable.package_import),
                            contentDescription = null
                        )
                    }
                )
            }
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        ),
        snackbarHost = { SnackbarHost(hostState = snackBarHost) }
    ) { innerPadding ->
        when {
            hasMagisk -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Warning,
                            contentDescription = null,
                            modifier = Modifier
                                .size(64.dp)
                                .padding(bottom = 16.dp)
                        )
                        Text(
                            stringResource(R.string.module_magisk_conflict),
                            textAlign = TextAlign.Center,
                            style = MaterialTheme.typography.bodyLarge,
                        )
                    }
                }
            }
            else -> {
                ModuleList(
                    navigator = navigator,
                    viewModel = viewModel,
                    listState = listState,
                    modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
                    boxModifier = Modifier.padding(innerPadding),
                    onInstallModule = {
                        navigator.navigate(FlashScreenDestination(FlashIt.FlashModule(it)))
                    },
                    onUpdateModule = {
                        navigator.navigate(FlashScreenDestination(FlashIt.FlashModuleUpdate(it)))
                    },
                    onClickModule = { id, name, hasWebUi ->
                        val currentTime = System.currentTimeMillis()
                        if (currentTime - lastClickTime < 600) {
                            Log.d("ModuleScreen", "Click too fast, ignoring")
                            return@ModuleList
                        }
                        lastClickTime = currentTime

                        if (hasWebUi) {
                            try {
                                val wxEngine = Intent(context, WebUIXActivity::class.java)
                                    .setData("kernelsu://webuix/$id".toUri())
                                    .putExtra("id", id)
                                    .putExtra("name", name)

                                val ksuEngine = Intent(context, WebUIActivity::class.java)
                                    .setData("kernelsu://webui/$id".toUri())
                                    .putExtra("id", id)
                                    .putExtra("name", name)

                                val config = try {
                                    id.asModuleConfig
                                } catch (e: Exception) {
                                    Log.e("ModuleScreen", "Failed to get config from id: $id", e)
                                    null
                                }

                                val globalEngine = prefs.getString("webui_engine", "default") ?: "default"
                                val moduleEngine = config?.getWebuiEngine(context)
                                val selectedEngine = when (globalEngine) {
                                    "wx" -> wxEngine
                                    "ksu" -> ksuEngine
                                    "default" -> {
                                        when (moduleEngine) {
                                            "wx" -> wxEngine
                                            "ksu" -> ksuEngine
                                            else -> {
                                                if (Platform.isAlive) {
                                                    wxEngine
                                                } else {
                                                    ksuEngine
                                                }
                                            }
                                        }
                                    }
                                    else -> ksuEngine
                                }
                                webUILauncher.launch(selectedEngine)
                            } catch (e: Exception) {
                                Log.e("ModuleScreen", "Error launching WebUI: ${e.message}", e)
                                scope.launch {
                                    snackBarHost.showSnackbar("Error launching WebUI: ${e.message}")
                                }
                            }
                            return@ModuleList
                        }
                    },
                    context = context,
                    snackBarHost = snackBarHost
                )
            }
        }

        // BottomSheet
        if (showBottomSheet) {
            ModalBottomSheet(
                onDismissRequest = {
                    showBottomSheet = false
                },
                sheetState = bottomSheetState,
                dragHandle = {
                    Surface(
                        modifier = Modifier.padding(vertical = 11.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Box(
                            Modifier.size(
                                width = 32.dp,
                                height = 4.dp
                            )
                        )
                    }
                }
            ) {
                ModuleBottomSheetContent(
                    menuItems = bottomSheetMenuItems,
                    viewModel = viewModel,
                    prefs = prefs,
                    scope = scope,
                    bottomSheetState = bottomSheetState,
                    onDismiss = { showBottomSheet = false }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModuleBottomSheetContent(
    menuItems: List<ModuleBottomSheetMenuItem>,
    viewModel: ModuleViewModel,
    prefs: android.content.SharedPreferences,
    scope: kotlinx.coroutines.CoroutineScope,
    bottomSheetState: SheetState,
    onDismiss: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 24.dp)
    ) {
        // 标题
        Text(
            text = stringResource(R.string.menu_options),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
        )

        // 菜单选项网格
        LazyVerticalGrid(
            columns = GridCells.Fixed(4),
            modifier = Modifier.fillMaxWidth(),
            contentPadding = PaddingValues(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            items(menuItems) { menuItem ->
                ModuleBottomSheetMenuItemView(
                    menuItem = menuItem
                )
            }
        }

        // 排序选项
        Spacer(modifier = Modifier.height(24.dp))
        HorizontalDivider(modifier = Modifier.padding(horizontal = 24.dp))

        Text(
            text = stringResource(R.string.sort_options),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
        )

        // 排序选项
        Column(
            modifier = Modifier.padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // 优先显示有操作的模块
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.module_sort_action_first),
                    style = MaterialTheme.typography.bodyMedium
                )
                Switch(
                    checked = viewModel.sortActionFirst,
                    onCheckedChange = { checked ->
                        viewModel.sortActionFirst = checked
                        prefs.edit {
                            putBoolean("module_sort_action_first", checked)
                        }
                        scope.launch {
                            viewModel.fetchModuleList()
                            bottomSheetState.hide()
                            onDismiss()
                        }
                    }
                )
            }

            // 优先显示已启用的模块
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.module_sort_enabled_first),
                    style = MaterialTheme.typography.bodyMedium
                )
                Switch(
                    checked = viewModel.sortEnabledFirst,
                    onCheckedChange = { checked ->
                        viewModel.sortEnabledFirst = checked
                        prefs.edit {
                            putBoolean("module_sort_enabled_first", checked)
                        }
                        scope.launch {
                            viewModel.fetchModuleList()
                            bottomSheetState.hide()
                            onDismiss()
                        }
                    }
                )
            }
        }
    }
}

@Composable
private fun ModuleBottomSheetMenuItemView(menuItem: ModuleBottomSheetMenuItem) {
    // 添加交互状态
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.95f else 1.0f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessHigh
        ),
        label = "menuItemScale"
    )

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .scale(scale)
            .clickable(
                interactionSource = interactionSource,
                indication = null
            ) { menuItem.onClick() }
            .padding(8.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Surface(
            modifier = Modifier.size(48.dp),
            shape = CircleShape,
            color = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer
        ) {
            Box(
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = menuItem.icon,
                    contentDescription = stringResource(menuItem.titleRes),
                    modifier = Modifier.size(24.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = stringResource(menuItem.titleRes),
            style = MaterialTheme.typography.labelSmall,
            textAlign = TextAlign.Center,
            maxLines = 2
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModuleList(
    navigator: DestinationsNavigator,
    viewModel: ModuleViewModel,
    listState: LazyListState,
    modifier: Modifier = Modifier,
    boxModifier: Modifier = Modifier,
    onInstallModule: (Uri) -> Unit,
    onUpdateModule: (Uri) -> Unit,
    onClickModule: (id: String, name: String, hasWebUi: Boolean) -> Unit,
    context: Context,
    snackBarHost: SnackbarHostState
) {
    val failedEnable = stringResource(R.string.module_failed_to_enable)
    val failedDisable = stringResource(R.string.module_failed_to_disable)
    val failedUninstall = stringResource(R.string.module_uninstall_failed)
    val successUninstall = stringResource(R.string.module_uninstall_success)
    val reboot = stringResource(R.string.reboot)
    val rebootToApply = stringResource(R.string.reboot_to_apply)
    val moduleStr = stringResource(R.string.module)
    val uninstall = stringResource(R.string.uninstall)
    val cancel = stringResource(android.R.string.cancel)
    val moduleUninstallConfirm = stringResource(R.string.module_uninstall_confirm)
    val updateText = stringResource(R.string.module_update)
    val changelogText = stringResource(R.string.module_changelog)
    val downloadingText = stringResource(R.string.module_downloading)
    val startDownloadingText = stringResource(R.string.module_start_downloading)
    val fetchChangeLogFailed = stringResource(R.string.module_changelog_failed)
    val downloadErrorText = stringResource(R.string.module_download_error)

    val loadingDialog = rememberLoadingDialog()
    val confirmDialog = rememberConfirmDialog()

    suspend fun onModuleUpdate(
        module: ModuleViewModel.ModuleInfo,
        changelogUrl: String,
        downloadUrl: String,
        fileName: String
    ) {
        val client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

        val request = okhttp3.Request.Builder()
            .url(changelogUrl)
            .header("User-Agent", "SukiSU-Ultra/2.0")
            .build()

        val changelogResult = loadingDialog.withLoading {
            withContext(Dispatchers.IO) {
                runCatching {
                    client.newCall(request).execute().body!!.string()
                }
            }
        }

        val showToast: suspend (String) -> Unit = { msg ->
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    context,
                    msg,
                    Toast.LENGTH_SHORT
                ).show()
            }
        }

        val changelog = changelogResult.getOrElse {
            showToast(fetchChangeLogFailed.format(it.message))
            return
        }.ifBlank {
            showToast(fetchChangeLogFailed.format(module.name))
            return
        }

        // changelog is not empty, show it and wait for confirm
        val confirmResult = confirmDialog.awaitConfirm(
            changelogText,
            content = changelog,
            markdown = true,
            confirm = updateText,
        )

        if (confirmResult != ConfirmResult.Confirmed) {
            return
        }

        showToast(startDownloadingText.format(module.name))

        val downloading = downloadingText.format(module.name)
        withContext(Dispatchers.IO) {
            download(
                context,
                downloadUrl,
                fileName,
                downloading,
                onDownloaded = onUpdateModule,
                onDownloading = {
                    launch(Dispatchers.Main) {
                        Toast.makeText(context, downloading, Toast.LENGTH_SHORT).show()
                    }
                },
                onError = { errorMsg ->
                    launch(Dispatchers.Main) {
                        Toast.makeText(context, "$downloadErrorText: $errorMsg", Toast.LENGTH_LONG).show()
                    }
                }
            )
        }
    }

    suspend fun onModuleUninstallClicked(module: ModuleViewModel.ModuleInfo) {
        val isUninstall = !module.remove
        if (isUninstall) {
            val confirmResult = confirmDialog.awaitConfirm(
                moduleStr,
                content = moduleUninstallConfirm.format(module.name),
                confirm = uninstall,
                dismiss = cancel
            )
            if (confirmResult != ConfirmResult.Confirmed) {
                return
            }
        }

        val success = loadingDialog.withLoading {
            withContext(Dispatchers.IO) {
                if (isUninstall) {
                    uninstallModule(module.dirId)
                } else {
                    restoreModule(module.dirId)
                }
            }
        }

        if (success) {
            viewModel.fetchModuleList()
            viewModel.markNeedRefresh()
        }
        if (!isUninstall) return
        val message = if (success) {
            successUninstall.format(module.name)
        } else {
            failedUninstall.format(module.name)
        }
        val actionLabel = if (success) {
            reboot
        } else {
            null
        }
        val result = snackBarHost.showSnackbar(
            message = message,
            actionLabel = actionLabel,
            duration = SnackbarDuration.Long
        )
        if (result == SnackbarResult.ActionPerformed) {
            reboot()
        }
    }
    PullToRefreshBox(
        modifier = boxModifier,
        onRefresh = {
            viewModel.fetchModuleList()
        },
        isRefreshing = viewModel.isRefreshing
    ) {
        LazyColumn(
            state = listState,
            modifier = modifier,
            verticalArrangement = Arrangement.spacedBy(16.dp),
            contentPadding = remember {
                PaddingValues(
                    start = 16.dp,
                    top = 16.dp,
                    end = 16.dp,
                    bottom = 16.dp + 56.dp + 16.dp + 48.dp + 6.dp /* Scaffold Fab Spacing + Fab container height + SnackBar height */
                )
            },
        ) {
            when {
                viewModel.moduleList.isEmpty() -> {
                    item {
                        Box(
                            modifier = Modifier.fillParentMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Outlined.Extension,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.6f),
                                    modifier = Modifier
                                        .size(96.dp)
                                        .padding(bottom = 16.dp)
                                )
                                Text(
                                    text = stringResource(R.string.module_empty),
                                    textAlign = TextAlign.Center,
                                    style = MaterialTheme.typography.bodyLarge,
                                )
                            }
                        }
                    }
                }

                else -> {
                    items(viewModel.moduleList) { module ->
                        val scope = rememberCoroutineScope()
                        val updatedModule by produceState(initialValue = Triple("", "", "")) {
                            scope.launch(Dispatchers.IO) {
                                value = viewModel.checkUpdate(module)
                            }
                        }

                        ModuleItem(
                            navigator = navigator,
                            module = module,
                            updateUrl = updatedModule.first,
                            onUninstallClicked = {
                                scope.launch { onModuleUninstallClicked(module) }
                            },
                            onCheckChanged = {
                                scope.launch {
                                    val success = withContext(Dispatchers.IO) {
                                        toggleModule(module.dirId, !module.enabled)
                                    }
                                    if (success) {
                                        viewModel.fetchModuleList()

                                        val result = snackBarHost.showSnackbar(
                                            message = rebootToApply,
                                            actionLabel = reboot,
                                            duration = SnackbarDuration.Long
                                        )
                                        if (result == SnackbarResult.ActionPerformed) {
                                            reboot()
                                        }
                                    } else {
                                        val message = if (module.enabled) failedDisable else failedEnable
                                        snackBarHost.showSnackbar(message.format(module.name))
                                    }
                                }
                            },
                            onUpdate = {
                                scope.launch {
                                    onModuleUpdate(
                                        module,
                                        updatedModule.third,
                                        updatedModule.first,
                                        "${module.name}-${updatedModule.second}.zip"
                                    )
                                }
                            },
                            onClick = {
                                onClickModule(it.dirId, it.name, it.hasWebUi)
                            }
                        )

                        // fix last item shadow incomplete in LazyColumn
                        Spacer(Modifier.height(1.dp))
                    }
                }
            }
        }

        DownloadListener(context, onInstallModule)

    }
}

@Composable
fun ModuleItem(
    navigator: DestinationsNavigator,
    module: ModuleViewModel.ModuleInfo,
    updateUrl: String,
    onUninstallClicked: (ModuleViewModel.ModuleInfo) -> Unit,
    onCheckChanged: (Boolean) -> Unit,
    onUpdate: (ModuleViewModel.ModuleInfo) -> Unit,
    onClick: (ModuleViewModel.ModuleInfo) -> Unit
) {
    val context = LocalContext.current
    val prefs = context.getSharedPreferences("settings", MODE_PRIVATE)
    val isHideTagRow = prefs.getBoolean("is_hide_tag_row", false)
    // 获取显示更多模块信息的设置
    val showMoreModuleInfo = prefs.getBoolean("show_more_module_info", false)

    // 剪贴板管理器和触觉反馈
    val clipboardManager = context.getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
    val hapticFeedback = LocalHapticFeedback.current

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerHigh),
        elevation = getCardElevation(),
    ) {
        val textDecoration = if (!module.remove) null else TextDecoration.LineThrough
        val interactionSource = remember { MutableInteractionSource() }
        val indication = LocalIndication.current
        val viewModel = viewModel<ModuleViewModel>()

        // 使用缓存系统获取模块大小
        val sizeStr = remember(module.dirId) {
            viewModel.getModuleSize(module.dirId)
        }

        Column(
            modifier = Modifier
                .run {
                    if (module.hasWebUi) {
                        toggleable(
                            value = module.enabled,
                            enabled = !module.remove && module.enabled,
                            interactionSource = interactionSource,
                            role = Role.Button,
                            indication = indication,
                            onValueChange = { onClick(module) }
                        )
                    } else {
                        this
                    }
                }
                .padding(22.dp, 18.dp, 22.dp, 12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                val moduleVersion = stringResource(id = R.string.module_version)
                val moduleAuthor = stringResource(id = R.string.module_author)

                Column(
                    modifier = Modifier.fillMaxWidth(0.8f)
                ) {
                    Text(
                        text = module.name,
                        fontSize = MaterialTheme.typography.titleMedium.fontSize,
                        fontWeight = FontWeight.SemiBold,
                        lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                        fontFamily = MaterialTheme.typography.titleMedium.fontFamily,
                        textDecoration = textDecoration,
                    )

                    Text(
                        text = "$moduleVersion: ${module.version}",
                        fontSize = MaterialTheme.typography.bodySmall.fontSize,
                        lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                        fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                        textDecoration = textDecoration,
                    )

                    Text(
                        text = "$moduleAuthor: ${module.author}",
                        fontSize = MaterialTheme.typography.bodySmall.fontSize,
                        lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                        fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                        textDecoration = textDecoration,
                    )

                    // 显示更多模块信息时添加updateJson
                    if (showMoreModuleInfo && module.updateJson.isNotEmpty()) {
                        val updateJsonLabel = stringResource(R.string.module_update_json)
                        Text(
                            text = "$updateJsonLabel: ${module.updateJson}",
                            fontSize = MaterialTheme.typography.bodySmall.fontSize,
                            lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                            fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                            textDecoration = textDecoration,
                            color = MaterialTheme.colorScheme.primary,
                            maxLines = 5,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier
                                .fillMaxWidth()
                                .combinedClickable(
                                    onClick = {
                                    },
                                    onLongClick = {
                                        // 长按复制updateJson地址
                                        val clipData = ClipData.newPlainText(
                                            "Update JSON URL",
                                            module.updateJson
                                        )
                                        clipboardManager.setPrimaryClip(clipData)
                                        hapticFeedback.performHapticFeedback(HapticFeedbackType.LongPress)

                                        // 显示复制成功的提示
                                        Toast.makeText(
                                            context,
                                            context.getString(R.string.module_update_json_copied),
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }
                                ),
                        )
                    }
                }

                Spacer(modifier = Modifier.weight(1f))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    Switch(
                        enabled = !module.update,
                        checked = module.enabled,
                        onCheckedChange = onCheckChanged,
                        interactionSource = if (!module.hasWebUi) interactionSource else null,
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = module.description,
                fontSize = MaterialTheme.typography.bodySmall.fontSize,
                fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                fontWeight = MaterialTheme.typography.bodySmall.fontWeight,
                overflow = TextOverflow.Ellipsis,
                maxLines = 4,
                textDecoration = textDecoration,
            )
            if (!isHideTagRow) {

                Spacer(modifier = Modifier.height(12.dp))
                // 文件夹名称和大小标签
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Surface(
                        shape = RoundedCornerShape(4.dp),
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                    ) {
                        Text(
                            text = module.dirId,
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Surface(
                        shape = RoundedCornerShape(4.dp),
                        color = MaterialTheme.colorScheme.secondaryContainer,
                        modifier = Modifier
                    ) {
                        Text(
                            text = sizeStr,
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp),
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                            maxLines = 1
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            HorizontalDivider(thickness = Dp.Hairline)

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (module.hasActionScript) {
                    FilledTonalButton(
                        modifier = Modifier.defaultMinSize(minWidth = 52.dp, minHeight = 32.dp),
                        enabled = !module.remove && module.enabled,
                        onClick = {
                            navigator.navigate(ExecuteModuleActionScreenDestination(module.dirId))
                            viewModel.markNeedRefresh()
                        },
                        contentPadding = ButtonDefaults.TextButtonContentPadding,
                    ) {
                        Icon(
                            modifier = Modifier.size(20.dp),
                            imageVector = Icons.Outlined.PlayArrow,
                            contentDescription = null
                        )
                    }
                }

                if (module.hasWebUi) {
                    FilledTonalButton(
                        modifier = Modifier.defaultMinSize(minWidth = 52.dp, minHeight = 32.dp),
                        enabled = !module.remove && module.enabled,
                        onClick = { onClick(module) },
                        interactionSource = interactionSource,
                        contentPadding = ButtonDefaults.TextButtonContentPadding,

                        ) {
                        Icon(
                            modifier = Modifier.size(20.dp),
                            imageVector = Icons.AutoMirrored.Outlined.Wysiwyg,
                            contentDescription = null
                        )
                    }
                }

                Spacer(modifier = Modifier.weight(1f, true))

                if (updateUrl.isNotEmpty()) {
                    Button(
                        modifier = Modifier.defaultMinSize(minWidth = 52.dp, minHeight = 32.dp),
                        enabled = !module.remove,
                        onClick = { onUpdate(module) },
                        shape = ButtonDefaults.textShape,
                        contentPadding = ButtonDefaults.TextButtonContentPadding,
                    ) {
                        Icon(
                            modifier = Modifier.size(20.dp),
                            imageVector = Icons.Outlined.Download,
                            contentDescription = null
                        )
                    }
                }

                FilledTonalButton(
                    modifier = Modifier.defaultMinSize(minWidth = 52.dp, minHeight = 32.dp),
                    onClick = { onUninstallClicked(module) },
                    contentPadding = ButtonDefaults.TextButtonContentPadding,
                ) {
                    if (!module.remove) {
                        Icon(
                            modifier = Modifier.size(20.dp),
                            imageVector = Icons.Outlined.Delete,
                            contentDescription = null,
                        )
                    } else {
                        Icon(
                            modifier = Modifier.size(20.dp).rotate(180f),
                            imageVector = Icons.Outlined.Refresh,
                            contentDescription = null
                        )
                    }
                }
            }
        }
    }
}

@Preview
@Composable
fun ModuleItemPreview() {
    val module = ModuleViewModel.ModuleInfo(
        id = "id",
        name = "name",
        version = "version",
        versionCode = 1,
        author = "author",
        description = "I am a test module and i do nothing but show a very long description",
        enabled = true,
        update = true,
        remove = false,
        updateJson = "",
        hasWebUi = false,
        hasActionScript = false,
        dirId = "dirId",
        config = ModuleConfig(),
    )
    ModuleItem(EmptyDestinationsNavigator, module, "", {}, {}, {}, {})
}