package com.sukisu.ultra.ui.screen

import android.content.Context
import android.content.Intent
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.CoroutineScope
import androidx.compose.ui.layout.SubcomposeLayout
import androidx.compose.foundation.isSystemInDarkTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import com.sukisu.ultra.ui.component.*
import com.sukisu.ultra.ui.viewmodel.KpmViewModel
import com.sukisu.ultra.ui.util.*
import java.io.File
import androidx.core.content.edit
import com.sukisu.ultra.R
import java.io.FileInputStream
import java.net.*
import android.app.Activity
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.LayoutDirection
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.HazeStyle
import dev.chrisbanes.haze.HazeTint
import dev.chrisbanes.haze.hazeSource
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.extra.SuperDialog
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * KPM 管理界面
 * 以下内核模块功能由KernelPatch开发，经过修改后加入SukiSU Ultra的内核模块功能
 * 开发者：ShirkNeko, Liaokong
 */
@Composable
fun KpmScreen(
    viewModel: KpmViewModel = viewModel(),
    bottomInnerPadding: Dp = 0.dp
) {
    val context = LocalContext.current
    val enableBlur = LocalEnableBlur.current
    val scope = rememberCoroutineScope()
    val confirmDialog = rememberConfirmDialog()

    val listState = rememberLazyListState()
    var fabVisible by remember { mutableStateOf(true) }
    var scrollDistance by remember { mutableFloatStateOf(0f) }
    
    val searchStatus by viewModel.searchStatus
    val scrollBehavior = MiuixScrollBehavior()
    val dynamicTopPadding by remember {
        derivedStateOf { 12.dp * (1f - scrollBehavior.state.collapsedFraction) }
    }

    val showEmptyState by remember {
        derivedStateOf {
            viewModel.moduleList.isEmpty() && searchStatus.searchText.isEmpty()
        }
    }

    val moduleConfirmContentMap = viewModel.moduleList.associate { module ->
        module.id to stringResource(R.string.confirm_uninstall_content, module.id)
    }

    val hazeState = remember { HazeState() }
    val hazeStyle = if (enableBlur) {
        HazeStyle(
            backgroundColor = colorScheme.surface,
            tint = HazeTint(colorScheme.surface.copy(0.8f))
        )
    } else {
        HazeStyle.Unspecified
    }

    LaunchedEffect(searchStatus.searchText) {
        viewModel.updateSearchText(searchStatus.searchText)
    }

    val kpmInstallSuccess = stringResource(R.string.kpm_install_success)
    val kpmInstallFailed = stringResource(R.string.kpm_install_failed)
    val cancel = stringResource(R.string.cancel)
    val uninstall = stringResource(R.string.uninstall)
    val failedToCheckModuleFile = stringResource(R.string.snackbar_failed_to_check_module_file)
    val kpmUninstallSuccess = stringResource(R.string.kpm_uninstall_success)
    val kpmUninstallFailed = stringResource(R.string.kpm_uninstall_failed)
    val kpmInstallMode = stringResource(R.string.kpm_install_mode)
    val kpmInstallModeLoad = stringResource(R.string.kpm_install_mode_load)
    val kpmInstallModeEmbed = stringResource(R.string.kpm_install_mode_embed)
    val invalidFileTypeMessage = stringResource(R.string.invalid_file_type)
    val confirmTitle = stringResource(R.string.confirm_uninstall_title_with_filename)

    val showToast: suspend (String) -> Unit = { msg ->
        scope.launch(Dispatchers.Main) {
            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
        }
    }

    var tempFileForInstall by remember { mutableStateOf<File?>(null) }
    var showInstallModeDialog by remember { mutableStateOf(false) }
    val showInstallDialogState = remember { mutableStateOf(false) }
    var moduleName by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(tempFileForInstall) {
        moduleName = tempFileForInstall?.let { extractModuleName(it) }
    }

    LaunchedEffect(showInstallModeDialog) {
        showInstallDialogState.value = showInstallModeDialog
    }
    
    fun clearInstallState() {
        runCatching {
            showInstallDialogState.value = false
            showInstallModeDialog = false
            runCatching { tempFileForInstall?.delete() }
            tempFileForInstall = null
            moduleName = null
        }.onFailure {
            Log.e("KsuCli", "clearInstallState: ${it.message}", it)
        }
    }

    if (showInstallModeDialog) {
        SuperDialog(
            show = showInstallDialogState,
            title = kpmInstallMode,
            onDismissRequest = {
                clearInstallState()
            },
            content = {
                Column {
                    moduleName?.let {
                        Text(
                            text = stringResource(R.string.kpm_install_mode_description, it),
                            color = colorScheme.onBackground
                        )
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                scope.launch {
                                    val tempFile = tempFileForInstall
                                    tempFile?.let {
                                        handleModuleInstall(
                                            tempFile = it,
                                            isEmbed = false,
                                            viewModel = viewModel,
                                            showToast = showToast,
                                            kpmInstallSuccess = kpmInstallSuccess,
                                            kpmInstallFailed = kpmInstallFailed
                                        )
                                    }
                                    clearInstallState()
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Download,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp).padding(end = 4.dp)
                            )
                            Text(kpmInstallModeLoad)
                        }

                        Button(
                            onClick = {
                                scope.launch {
                                    val tempFile = tempFileForInstall
                                    tempFile?.let {
                                        handleModuleInstall(
                                            tempFile = it,
                                            isEmbed = true,
                                            viewModel = viewModel,
                                            showToast = showToast,
                                            kpmInstallSuccess = kpmInstallSuccess,
                                            kpmInstallFailed = kpmInstallFailed
                                        )
                                    }
                                    clearInstallState()
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Inventory,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp).padding(end = 4.dp)
                            )
                            Text(kpmInstallModeEmbed)
                        }
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        TextButton(
                            text = cancel,
                            onClick = {
                                clearInstallState()
                            },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        )
    }

    val selectPatchLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode != Activity.RESULT_OK) return@rememberLauncherForActivityResult

        val uri = result.data?.data ?: return@rememberLauncherForActivityResult

        scope.launch {
            val fileName = uri.lastPathSegment ?: "unknown.kpm"
            val encodedFileName = URLEncoder.encode(fileName, "UTF-8")
            val tempFile = File(context.cacheDir, encodedFileName)

            context.contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }

            if (!isValidKpmFile(tempFile, context.contentResolver.getType(uri))) {
                showToast(invalidFileTypeMessage)
                tempFile.delete()
                return@launch
            }
            
            tempFileForInstall = tempFile
            showInstallModeDialog = true
        }
    }

    LaunchedEffect(Unit) {
        while(true) {
            viewModel.fetchModuleList()
            delay(5000)
        }
    }

    val nestedScrollConnection = remember(listState) {
        object : NestedScrollConnection {
            override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                if (isScrolledToEnd(listState)) return Offset.Zero

                scrollDistance += available.y

                if (scrollDistance <= -50f && fabVisible) {
                    fabVisible = false
                    scrollDistance = 0f
                    return Offset(0f, available.y)
                }

                if (scrollDistance >= 50f && !fabVisible) {
                    fabVisible = true
                    scrollDistance = 0f
                    return Offset(0f, available.y)
                }

                return Offset.Zero
            }
        }
    }
    val offsetHeight by animateDpAsState(
        targetValue = if (fabVisible) 0.dp else 180.dp + WindowInsets.systemBars.asPaddingValues().calculateBottomPadding(),
        animationSpec = tween(durationMillis = 350)
    )

    Scaffold(
        topBar = {
            searchStatus.TopAppBarAnim(hazeState = hazeState, hazeStyle = hazeStyle) {
                TopAppBar(
                    color = if (enableBlur) Color.Transparent else colorScheme.surface,
                    title = stringResource(R.string.kpm_title),
                    actions = {
                        IconButton(
                            onClick = { viewModel.fetchModuleList() }
                        ) {
                            Icon(
                                imageVector = MiuixIcons.Refresh,
                                contentDescription = stringResource(R.string.refresh),
                                tint = colorScheme.onBackground
                            )
                        }
                    },
                    scrollBehavior = scrollBehavior
                )
            }
        },
        floatingActionButton = {
            AnimatedVisibility(visible = fabVisible) {
                FloatingActionButton(
                    modifier = Modifier
                        .offset(y = offsetHeight)
                        .padding(bottom = bottomInnerPadding + 20.dp, end = 20.dp)
                        .border(0.05.dp, colorScheme.outline.copy(alpha = 0.5f), CircleShape),
                    shadowElevation = 0.dp,
                    onClick = {
                        selectPatchLauncher.launch(
                            Intent(Intent.ACTION_GET_CONTENT).apply {
                                type = "application/octet-stream"
                            }
                        )
                    },
                    content = {
                        Icon(
                            painter = painterResource(id = R.drawable.package_import),
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(40.dp)
                        )
                    }
                )
            }
        },
        popupHost = {
            searchStatus.SearchPager(
                defaultResult = {},
                searchBarTopPadding = dynamicTopPadding,
            ) {
                item {
                    Spacer(Modifier.height(6.dp))
                }
                items(viewModel.moduleList) { module ->
                    KpmModuleItem(
                        module = module,
                        onUninstall = {
                            scope.launch {
                                val confirmContent = moduleConfirmContentMap[module.id] ?: ""
                                handleModuleUninstall(
                                    module = module,
                                    viewModel = viewModel,
                                    showToast = showToast,
                                    kpmUninstallSuccess = kpmUninstallSuccess,
                                    kpmUninstallFailed = kpmUninstallFailed,
                                    failedToCheckModuleFile = failedToCheckModuleFile,
                                    uninstall = uninstall,
                                    cancel = cancel,
                                    confirmDialog = confirmDialog,
                                    confirmTitle = confirmTitle,
                                    confirmContent = confirmContent
                                )
                            }
                        },
                        onControl = {
                            viewModel.loadModuleDetail(module.id)
                        }
                    )
                }
                item {
                    val imeBottomPadding = WindowInsets.ime.asPaddingValues().calculateBottomPadding()
                    Spacer(Modifier.height(maxOf(bottomInnerPadding, imeBottomPadding)))
                }
            }
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        val layoutDirection = LocalLayoutDirection.current
        
        if (showEmptyState) {
            EmptyStateView(
                innerPadding = innerPadding,
                bottomInnerPadding = bottomInnerPadding,
                layoutDirection = layoutDirection
            )
        } else {
            searchStatus.SearchBox(
                searchBarTopPadding = dynamicTopPadding,
                contentPadding = PaddingValues(
                    top = innerPadding.calculateTopPadding(),
                    start = innerPadding.calculateStartPadding(layoutDirection),
                    end = innerPadding.calculateEndPadding(layoutDirection)
                ),
                hazeState = hazeState,
                hazeStyle = hazeStyle
            ) { boxHeight  ->
                KpmList(
                    viewModel = viewModel,
                    scope = scope,
                    moduleConfirmContentMap = moduleConfirmContentMap,
                    showToast = showToast,
                    kpmUninstallSuccess = kpmUninstallSuccess,
                    kpmUninstallFailed = kpmUninstallFailed,
                    failedToCheckModuleFile = failedToCheckModuleFile,
                    uninstall = uninstall,
                    cancel = cancel,
                    confirmDialog = confirmDialog,
                    confirmTitle = confirmTitle,
                    scrollBehavior = scrollBehavior,
                    nestedScrollConnection = nestedScrollConnection,
                    hazeState = hazeState,
                    innerPadding = innerPadding,
                    bottomInnerPadding = bottomInnerPadding,
                    boxHeight = boxHeight,
                    layoutDirection = layoutDirection
                )
            }
        }
    }
}

private suspend fun handleModuleInstall(
    tempFile: File,
    isEmbed: Boolean,
    viewModel: KpmViewModel,
    showToast: suspend (String) -> Unit,
    kpmInstallSuccess: String,
    kpmInstallFailed: String
) {
    val moduleId = extractModuleName(tempFile)
    if (moduleId.isNullOrEmpty()) {
        Log.e("KsuCli", "Failed to extract module ID from file: ${tempFile.name}")
        showToast(kpmInstallFailed)
        tempFile.delete()
        return
    }

    val targetPath = "/data/adb/kpm/$moduleId.kpm"

    try {
        if (isEmbed) {
            val shell = getRootShell()
            shell.newJob().add("mkdir -p /data/adb/kpm").exec()
            shell.newJob().add("cp ${tempFile.absolutePath} $targetPath").exec()
        }

        val loadResult = loadKpmModule(tempFile.absolutePath)
        if (!loadResult) {
            Log.e("KsuCli", "Failed to load KPM module")
            showToast(kpmInstallFailed)
        } else {
            viewModel.fetchModuleList()
            showToast(kpmInstallSuccess)
        }
    } catch (e: Exception) {
        Log.e("KsuCli", "Failed to load KPM module: ${e.message}", e)
        showToast(kpmInstallFailed)
    }
    tempFile.delete()
}

private suspend fun handleModuleUninstall(
    module: KpmViewModel.ModuleInfo,
    viewModel: KpmViewModel,
    showToast: suspend (String) -> Unit,
    kpmUninstallSuccess: String,
    kpmUninstallFailed: String,
    failedToCheckModuleFile: String,
    uninstall: String,
    cancel: String,
    confirmTitle : String,
    confirmContent : String,
    confirmDialog: ConfirmDialogHandle
) {
    val moduleFileName = "${module.id}.kpm"
    val moduleFilePath = "/data/adb/kpm/$moduleFileName"

    val fileExists = try {
        val shell = getRootShell()
        val result = shell.newJob().add("ls /data/adb/kpm/$moduleFileName").exec()
        result.isSuccess
    } catch (e: Exception) {
        Log.e("KsuCli", "Failed to check module file existence: ${e.message}", e)
        showToast(failedToCheckModuleFile)
        false
    }

    val confirmResult = confirmDialog.awaitConfirm(
        title = confirmTitle,
        content = confirmContent,
        confirm = uninstall,
        dismiss = cancel
    )

    if (confirmResult == ConfirmResult.Confirmed) {
        try {
            val unloadResult = unloadKpmModule(module.id)
            if (!unloadResult) {
                Log.e("KsuCli", "Failed to unload KPM module")
                showToast(kpmUninstallFailed)
                return
            }

            if (fileExists) {
                val shell = getRootShell()
                shell.newJob().add("rm $moduleFilePath").exec()
            }

            viewModel.fetchModuleList()
            showToast(kpmUninstallSuccess)
        } catch (e: Exception) {
            Log.e("KsuCli", "Failed to unload KPM module: ${e.message}", e)
            showToast(kpmUninstallFailed)
        }
    }
}

@Composable
private fun KpmList(
    viewModel: KpmViewModel,
    scope: CoroutineScope,
    moduleConfirmContentMap: Map<String, String>,
    showToast: suspend (String) -> Unit,
    kpmUninstallSuccess: String,
    kpmUninstallFailed: String,
    failedToCheckModuleFile: String,
    uninstall: String,
    cancel: String,
    confirmDialog: ConfirmDialogHandle,
    confirmTitle: String,
    scrollBehavior: ScrollBehavior,
    nestedScrollConnection: NestedScrollConnection,
    hazeState: HazeState,
    innerPadding: PaddingValues,
    bottomInnerPadding: Dp,
    boxHeight: MutableState<Dp>,
    layoutDirection: LayoutDirection
) {
    val context = LocalContext.current
    val enableBlur = LocalEnableBlur.current
    val sharedPreferences = context.getSharedPreferences("app_preferences", Context.MODE_PRIVATE)
    var isNoticeClosed by remember { mutableStateOf(sharedPreferences.getBoolean("is_notice_closed", false)) }

    val refreshPulling = stringResource(R.string.refresh_pulling)
    val refreshRelease = stringResource(R.string.refresh_release)
    val refreshRefresh = stringResource(R.string.refresh_refresh)
    val refreshComplete = stringResource(R.string.refresh_complete)
    
    var isRefreshing by rememberSaveable { mutableStateOf(false) }
    val pullToRefreshState = rememberPullToRefreshState()
    val refreshTexts = remember {
        listOf(
            refreshPulling,
            refreshRelease,
            refreshRefresh,
            refreshComplete,
        )
    }
    
    LaunchedEffect(isRefreshing) {
        if (isRefreshing) {
            delay(350)
            viewModel.fetchModuleList()
            isRefreshing = false
        }
    }

    PullToRefresh(
        isRefreshing = isRefreshing,
        pullToRefreshState = pullToRefreshState,
        onRefresh = { if (!isRefreshing) isRefreshing = true },
        refreshTexts = refreshTexts,
        contentPadding = PaddingValues(
            top = innerPadding.calculateTopPadding() + boxHeight.value + 6.dp,
            start = innerPadding.calculateStartPadding(layoutDirection),
            end = innerPadding.calculateEndPadding(layoutDirection),
        ),
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .nestedScroll(nestedScrollConnection)
                .let { if (enableBlur) it.hazeSource(state = hazeState) else it },
            contentPadding = PaddingValues(
                top = innerPadding.calculateTopPadding() + boxHeight.value + 6.dp,
                start = innerPadding.calculateStartPadding(layoutDirection),
                end = innerPadding.calculateEndPadding(layoutDirection),
            ),
            overscrollEffect = null,
        ) {
            if (!isNoticeClosed) {
                item {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 12.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Info,
                                contentDescription = null,
                                modifier = Modifier
                                    .padding(end = 16.dp)
                                    .size(24.dp),
                                tint = colorScheme.onBackground
                            )

                            Text(
                                text = stringResource(R.string.kernel_module_notice),
                                modifier = Modifier.weight(1f),
                                color = colorScheme.onBackground
                            )

                            IconButton(
                                onClick = {
                                    isNoticeClosed = true
                                    sharedPreferences.edit { putBoolean("is_notice_closed", true) }
                                },
                                modifier = Modifier.size(24.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Close,
                                    contentDescription = stringResource(R.string.close_notice),
                                    tint = colorScheme.onBackground
                                )
                            }
                        }
                    }
                }
            }
            
            items(viewModel.moduleList) { module ->
                KpmModuleItem(
                    module = module,
                    onUninstall = {
                        scope.launch {
                            val confirmContent = moduleConfirmContentMap[module.id] ?: ""
                            handleModuleUninstall(
                                module = module,
                                viewModel = viewModel,
                                showToast = showToast,
                                kpmUninstallSuccess = kpmUninstallSuccess,
                                kpmUninstallFailed = kpmUninstallFailed,
                                failedToCheckModuleFile = failedToCheckModuleFile,
                                uninstall = uninstall,
                                cancel = cancel,
                                confirmDialog = confirmDialog,
                                confirmTitle = confirmTitle,
                                confirmContent = confirmContent
                            )
                        }
                    },
                    onControl = {
                        viewModel.loadModuleDetail(module.id)
                    }
                )
            }
            item {
                Spacer(Modifier.height(bottomInnerPadding))
            }
        }
    }
}

@Composable
private fun KpmModuleItem(
    module: KpmViewModel.ModuleInfo,
    onUninstall: () -> Unit,
    onControl: () -> Unit
) {
    val viewModel: KpmViewModel = viewModel()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val successMessage = stringResource(R.string.kpm_control_success)
    val failureMessage = stringResource(R.string.kpm_control_failed)

    val showToast: suspend (String) -> Unit = { msg ->
        scope.launch(Dispatchers.Main) {
            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
        }
    }

    val showInputDialog = viewModel.showInputDialog && viewModel.selectedModuleId == module.id
    val showDialogState = remember { mutableStateOf(false) }

    LaunchedEffect(viewModel.showInputDialog, viewModel.selectedModuleId) {
        showDialogState.value = viewModel.showInputDialog && viewModel.selectedModuleId == module.id
    }

    if (showInputDialog) {
        SuperDialog(
            show = showDialogState,
            title = stringResource(R.string.kpm_control),
            onDismissRequest = {
                showDialogState.value = false
                viewModel.hideInputDialog()
            },
            content = {
                Column {
                    TextField(
                        value = viewModel.inputArgs,
                        onValueChange = { viewModel.updateInputArgs(it) },
                        label = stringResource(R.string.kpm_args),
                        modifier = Modifier.fillMaxWidth(),
                        useLabelAsPlaceholder = viewModel.inputArgs.isEmpty()
                    )
                    if (viewModel.inputArgs.isEmpty() && module.args.isNotEmpty()) {
                        Text(
                            text = module.args,
                            color = colorScheme.onSurfaceVariantSummary,
                            fontSize = MiuixTheme.textStyles.body2.fontSize,
                            modifier = Modifier.padding(start = 16.dp, top = 4.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        TextButton(
                            text = stringResource(R.string.cancel),
                            onClick = {
                                showDialogState.value = false
                                viewModel.hideInputDialog()
                            },
                            modifier = Modifier.weight(1f)
                        )
                        Spacer(modifier = Modifier.width(20.dp))
                        TextButton(
                            text = stringResource(R.string.confirm),
                            onClick = {
                                scope.launch {
                                    val result = viewModel.executeControl()
                                    val message = when (result) {
                                        0 -> successMessage
                                        else -> failureMessage
                                    }
                                    showToast(message)
                                    showDialogState.value = false
                                    onControl()
                                }
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.textButtonColorsPrimary()
                        )
                    }
                }
            }
        )
    }

    val isDark = isSystemInDarkTheme()
    val onSurface = colorScheme.onSurface
    val secondaryContainer = colorScheme.secondaryContainer.copy(alpha = 0.8f)
    val actionIconTint = remember(isDark) { onSurface.copy(alpha = if (isDark) 0.7f else 0.9f) }

    Card(
        modifier = Modifier
            .padding(horizontal = 12.dp)
            .padding(bottom = 12.dp),
        insideMargin = PaddingValues(16.dp)
    ) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 4.dp)
            ) {
                val kpmVersion = stringResource(R.string.kpm_version)
                val kpmAuthor = stringResource(R.string.kpm_author)
                val kpmArgs = stringResource(R.string.kpm_args)

                SubcomposeLayout { constraints ->
                    val namePlaceable = subcompose("name") {
                        Text(
                            text = module.name,
                            fontSize = 17.sp,
                            fontWeight = FontWeight(550),
                            color = colorScheme.onSurface,
                            onTextLayout = { }
                        )
                    }.first().measure(constraints)

                    layout(namePlaceable.width, namePlaceable.height) {
                        namePlaceable.placeRelative(0, 0)
                    }
                }
                Text(
                    text = "$kpmVersion: ${module.version}",
                    fontSize = 12.sp,
                    modifier = Modifier.padding(top = 2.dp),
                    fontWeight = FontWeight(550),
                    color = colorScheme.onSurfaceVariantSummary
                )
                Text(
                    text = "$kpmAuthor: ${module.author}",
                    fontSize = 12.sp,
                    modifier = Modifier.padding(bottom = 1.dp),
                    fontWeight = FontWeight(550),
                    color = colorScheme.onSurfaceVariantSummary
                )
                if (module.args.isNotEmpty()) {
                    Text(
                        text = "$kpmArgs: ${module.args}",
                        fontSize = 12.sp,
                        fontWeight = FontWeight(550),
                        color = colorScheme.onSurfaceVariantSummary
                    )
                }
            }
        }

        if (module.description.isNotBlank()) {
            Text(
                text = module.description,
                fontSize = 14.sp,
                color = colorScheme.onSurfaceVariantSummary,
                modifier = Modifier.padding(top = 2.dp),
                overflow = TextOverflow.Ellipsis,
                maxLines = 4
            )
        }

        HorizontalDivider(
            modifier = Modifier.padding(vertical = 8.dp),
            thickness = 0.5.dp,
            color = colorScheme.outline.copy(alpha = 0.5f)
        )

        Row {
            AnimatedVisibility(
                visible = module.hasAction,
                enter = fadeIn(),
                exit = fadeOut()
            ) {
                IconButton(
                    backgroundColor = secondaryContainer,
                    minHeight = 35.dp,
                    minWidth = 35.dp,
                    onClick = {
                        viewModel.showInputDialog(module.id)
                    },
                ) {
                    Icon(
                        modifier = Modifier.size(20.dp),
                        imageVector = Icons.Filled.Settings,
                        tint = actionIconTint,
                        contentDescription = stringResource(R.string.kpm_control)
                    )
                }
            }

            Spacer(Modifier.weight(1f))

            IconButton(
                minHeight = 35.dp,
                minWidth = 35.dp,
                onClick = onUninstall,
                backgroundColor = secondaryContainer,
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        modifier = Modifier.size(20.dp),
                        imageVector = Icons.Filled.Delete,
                        tint = actionIconTint,
                        contentDescription = null
                    )
                    Text(
                        modifier = Modifier.padding(start = 4.dp, end = 3.dp),
                        text = stringResource(R.string.kpm_uninstall),
                        color = actionIconTint,
                        fontWeight = FontWeight.Medium,
                        fontSize = 15.sp
                    )
                }
            }
        }
    }
}

private fun extractModuleName(file: File): String? {
    return try {
        val shell = getRootShell()
        val command = "strings ${file.absolutePath} | grep 'name='"
        val result = shell.newJob().add(command).to(ArrayList(), null).exec()
        if (result.isSuccess) {
            result.out.firstOrNull { it.startsWith("name=") }
                ?.substringAfter("name=")
                ?.trim()
                ?.takeIf { it.isNotEmpty() }
        } else null
    } catch (e: Exception) {
        Log.e("KsuCli", "Failed to extract module name: ${e.message}", e)
        null
    }
}

private fun isValidKpmFile(file: File, mimeType: String?): Boolean {
    val isCorrectMimeType = mimeType == null || mimeType.contains("application/octet-stream")
    if (isCorrectMimeType) return true
    
    return try {
        checkStringsCommand(file) >= 1 || isElfFile(file)
    } catch (e: Exception) {
        Log.e("KsuCli", "Failed to validate file: ${e.message}", e)
        false
    }
}

private fun checkStringsCommand(tempFile: File): Int {
    val shell = getRootShell()
    val command = "strings ${tempFile.absolutePath} | grep -E 'name=|version=|license=|author='"
    val result = shell.newJob().add(command).to(ArrayList(), null).exec()

    if (!result.isSuccess) return 0

    val keywords = listOf("name=", "version=", "license=", "author=")
    var nameExists = false
    var matchCount = 0

    for (line in result.out) {
        when {
            !nameExists && line.startsWith("name=") -> {
                nameExists = true
                matchCount++
            }
            nameExists && keywords.any { line.startsWith(it) } -> {
                matchCount++
            }
        }
    }

    return if (nameExists) matchCount else 0
}

private fun isElfFile(tempFile: File): Boolean {
    val elfMagic = byteArrayOf(0x7F, 0x45, 0x4C, 0x46) // "\u007FELF"
    return try {
        FileInputStream(tempFile).use { input ->
            val bytes = ByteArray(4)
            input.read(bytes) == 4 && bytes.contentEquals(elfMagic)
        }
    } catch (e: Exception) {
        Log.e("KsuCli", "Failed to check ELF file: ${e.message}", e)
        false
    }
}

private fun isScrolledToEnd(listState: LazyListState): Boolean {
    val layoutInfo = listState.layoutInfo
    val lastItem = layoutInfo.visibleItemsInfo.lastOrNull() ?: return false
    return lastItem.index == layoutInfo.totalItemsCount - 1 &&
            lastItem.size < layoutInfo.viewportEndOffset
}

@Composable
private fun EmptyStateView(
    innerPadding: PaddingValues,
    bottomInnerPadding: Dp,
    layoutDirection: LayoutDirection
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(
                top = innerPadding.calculateTopPadding(),
                start = innerPadding.calculateStartPadding(layoutDirection),
                end = innerPadding.calculateEndPadding(layoutDirection),
                bottom = bottomInnerPadding
            ),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                imageVector = Icons.Filled.Code,
                contentDescription = null,
                tint = colorScheme.primary.copy(alpha = 0.6f),
                modifier = Modifier
                    .size(96.dp)
                    .padding(bottom = 16.dp)
            )
            Text(
                stringResource(R.string.kpm_empty),
                textAlign = TextAlign.Center,
                color = colorScheme.onBackground
            )
        }
    }
}
