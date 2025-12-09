package com.sukisu.ultra.ui.screen.moduleRepo

import android.content.Context
import android.content.Context.MODE_PRIVATE
import android.content.SharedPreferences
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.SignalWifiOff
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.WebAsset
import androidx.compose.material.icons.rounded.Star
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SheetState
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.PullToRefreshDefaults
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.core.content.edit
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.FlashScreenDestination
import com.ramcosta.composedestinations.generated.destinations.OnlineModuleDetailScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.navigation.EmptyDestinationsNavigator
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.module.ReleaseAssetInfo
import com.sukisu.ultra.ui.util.module.ReleaseInfo
import com.sukisu.ultra.ui.activity.util.isNetworkAvailable
import com.sukisu.ultra.ui.component.ConfirmDialogHandle
import com.sukisu.ultra.ui.component.ConfirmResult
import com.sukisu.ultra.ui.component.DialogHandle
import com.sukisu.ultra.ui.component.SearchAppBar
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.component.rememberCustomDialog
import com.sukisu.ultra.ui.screen.FlashIt
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.theme.getCardElevation
import com.sukisu.ultra.ui.util.LocalSnackbarHost
import com.sukisu.ultra.ui.util.download
import com.sukisu.ultra.ui.viewmodel.ModuleRepoViewModel
import com.sukisu.ultra.ui.viewmodel.ModuleRepoViewModel.RepoModule
import com.sukisu.ultra.ui.viewmodel.formatFileSize
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * @author AlexLiuDev233
 * @date 2025/12/6
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
@Destination<RootGraph>
@Composable
fun ModuleRepoScreen(navigator: DestinationsNavigator) {
    val context = LocalContext.current
    val prefs = context.getSharedPreferences("settings", MODE_PRIVATE)
    val viewModel = viewModel<ModuleRepoViewModel>()
    val snackBarHost = LocalSnackbarHost.current
    val topAppBarState = rememberTopAppBarState()
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(topAppBarState)
    val currentModuleForChooseDialog = remember { mutableStateOf<RepoModule?>(null) }
    val chooseDialog = rememberCustomDialog({ dismiss ->
        ChooseDialogContent(currentModuleForChooseDialog, navigator, viewModel,dismiss)
    })
    val confirmDialog = rememberConfirmDialog()
    val bottomSheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true
    )
    var showBottomSheet by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val pullRefreshState = rememberPullToRefreshState()

    LaunchedEffect(Unit) {
        viewModel.sortStargazerCountFirst = prefs.getBoolean("module_repo_sort_star_first", false)
        scrollBehavior.state.heightOffset =
            scrollBehavior.state.heightOffsetLimit
    }

    Scaffold(
        topBar = {
            SearchAppBar(
                title = { Text(stringResource(R.string.module_repo)) },
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
                navigationContent = {
                    IconButton(
                        onClick = { navigator.popBackStack() },
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(id = R.string.back),
                        )
                    }
                },
                scrollBehavior = scrollBehavior
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        ),
        snackbarHost = { SnackbarHost(hostState = snackBarHost) }
    ) { innerPadding ->
        val isLoading = viewModel.modules.isEmpty()
        var offline by remember { mutableStateOf(!isNetworkAvailable(context)) }

        if (isLoading) {
            Box(
                modifier = Modifier
                    .fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                if (offline) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Box(
                            modifier = Modifier
                                .size(64.dp)
                                .clip(CircleShape)
                                .background(MaterialTheme.colorScheme.surfaceVariant),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.SignalWifiOff,
                                contentDescription = null,
                                modifier = Modifier.size(32.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Spacer(Modifier.height(12.dp))

                        Text(
                            text = stringResource(R.string.network_offline),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.titleMediumEmphasized
                        )
                        Spacer(modifier = Modifier.height(1.dp))

                        Text(
                            text = stringResource(R.string.please_check_network),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodyMediumEmphasized
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        Button(
                            contentPadding = PaddingValues(horizontal = 50.dp),
                            onClick = { viewModel.refresh() },
                        ) {
                            Text(text = stringResource(R.string.network_retry))
                        }
                    }
                } else {
                    LoadingIndicator()
                    viewModel.refresh(onFailure = {
                        offline = true
                    })
                }
            }
        } else {
            PullToRefreshBox(
                state = pullRefreshState,
                isRefreshing = viewModel.isRefreshing,
                onRefresh = {
                    viewModel.refresh()
                },
                indicator = {
                    PullToRefreshDefaults.LoadingIndicator(
                        state = pullRefreshState,
                        isRefreshing = viewModel.isRefreshing,
                        modifier = Modifier.align(Alignment.TopCenter),
                    )
                },
                modifier = Modifier.padding(innerPadding)
            ) {
                LazyColumn(
                    state = rememberLazyListState(),
                    modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                    contentPadding = remember {
                        PaddingValues(
                            start = 16.dp,
                            top = 16.dp,
                            end = 16.dp,
                            bottom = 16.dp + 56.dp + 16.dp + 48.dp + 6.dp /* Scaffold Fab Spacing + Fab container height + SnackBar height */
                        )
                    }
                ) {
                    items(viewModel.modules) { module ->
                        OnlineModuleItem(navigator, module, viewModel, confirmDialog, chooseDialog, currentModuleForChooseDialog)
                    }
                }
            }
        }
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
                ModuleRepoBottomSheetContent(
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
private fun ModuleRepoBottomSheetContent(
    viewModel: ModuleRepoViewModel,
    prefs: SharedPreferences,
    scope: CoroutineScope,
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

        // 排序选项

        Text(
            text = stringResource(R.string.sort_options),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
        )

        Column(
            modifier = Modifier.padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // 优先显示有星标的模块
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.module_sort_star_first),
                    style = MaterialTheme.typography.bodyMedium
                )
                Switch(
                    checked = viewModel.sortStargazerCountFirst,
                    onCheckedChange = { checked ->
                        viewModel.sortStargazerCountFirst = checked
                        prefs.edit {
                            putBoolean("module_repo_sort_star_first", checked)
                        }
                        scope.launch {
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
fun OnlineModuleItem(
    navigator: DestinationsNavigator,
    module: RepoModule,
    viewModel: ModuleRepoViewModel,
    confirmDialog: ConfirmDialogHandle,
    chooseDialog: DialogHandle,
    currentModuleForChooseDialog: MutableState<RepoModule?>
) {
    val context = LocalContext.current

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerHigh),
        modifier = Modifier.clickable {
            navigator.navigate(OnlineModuleDetailScreenDestination(module))
        },
        elevation = getCardElevation(),
    ) {
        Column(
            modifier = Modifier.padding(22.dp, 18.dp, 22.dp, 12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                val moduleVersion = stringResource(id = R.string.module_version)
                val moduleAuthor = stringResource(id = R.string.module_author)

                Column(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = module.moduleName,
                            fontSize = MaterialTheme.typography.titleMedium.fontSize,
                            fontWeight = FontWeight.SemiBold,
                            lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                            fontFamily = MaterialTheme.typography.titleMedium.fontFamily
                        )
                        Spacer(modifier = Modifier.weight(1f))
                        Row(
                            horizontalArrangement = Arrangement.End,
                        ) {
                            if (module.stargazerCount > 0) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Rounded.Star,
                                        contentDescription = "stars",
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Text(
                                        text = module.stargazerCount.toString(),
                                        fontSize = 12.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.padding(start = 4.dp)
                                    )
                                }
                            }
                        }
                    }

                    Text(
                        text = "$moduleVersion: ${module.latestRelease} (${module.latestVersionCode})",
                        fontSize = MaterialTheme.typography.bodySmall.fontSize,
                        lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                        fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                    )

                    Text(
                        text = "$moduleAuthor: ${module.authors}",
                        fontSize = MaterialTheme.typography.bodySmall.fontSize,
                        lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                        fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                    )
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = module.summary,
                fontSize = MaterialTheme.typography.bodySmall.fontSize,
                fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                fontWeight = MaterialTheme.typography.bodySmall.fontWeight,
                overflow = TextOverflow.Ellipsis,
                maxLines = 4,
            )
            Spacer(modifier = Modifier.height(12.dp))

            // 文件夹名称和metamodule标签
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
                        text = module.moduleId,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                if (module.metamodule) {
                    Surface(
                        shape = RoundedCornerShape(4.dp),
                        color = MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier
                    ) {
                        Text(
                            text = "META",
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp),
                            color = MaterialTheme.colorScheme.onTertiary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
                if (module.installed) {
                    Surface(
                        shape = RoundedCornerShape(4.dp),
                        color = MaterialTheme.colorScheme.secondary,
                        modifier = Modifier
                    ) {
                        Text(
                            text = stringResource(R.string.installed),
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp),
                            color = MaterialTheme.colorScheme.onSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(16.dp))

            HorizontalDivider(thickness = Dp.Hairline)

            Spacer(modifier = Modifier.height(8.dp))

            Row(horizontalArrangement = Arrangement.SpaceBetween) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.align(Alignment.CenterVertically)) {
                    Spacer(modifier = Modifier.weight(1f))
                    FilledTonalButton(
                        modifier = Modifier.defaultMinSize(minWidth = 52.dp, minHeight = 32.dp),
                        onClick = {
                            navigator.navigate(OnlineModuleDetailScreenDestination(module))
                        },
                        contentPadding = ButtonDefaults.TextButtonContentPadding,
                    ) {
                        Icon(
                            modifier = Modifier.size(20.dp),
                            imageVector = Icons.Outlined.WebAsset,
                            contentDescription = null
                        )
                    }
                    Spacer(Modifier.width(10.dp))

                    if (module.latestAsset != null) {
                        val confirmInstallTitle =
                            stringResource(R.string.confirm_install_module_title, module.moduleName)
                        FilledTonalButton(
                            modifier = Modifier.defaultMinSize(minWidth = 52.dp, minHeight = 32.dp),
                            onClick = {
                                viewModel.viewModelScope.launch {
                                    val result = confirmDialog.awaitConfirm(
                                        title = confirmInstallTitle,
                                        html = true,
                                        content = module.latestAsset.descriptionHTML
                                    )

                                    if (result == ConfirmResult.Canceled) return@launch

                                    val assets = module.latestAsset.assets
                                    if (assets.size <= 1) {
                                        assets.firstOrNull()?.let { asset ->
                                            downloadAssetAndInstall(
                                                context,
                                                module,
                                                asset,
                                                navigator,
                                                viewModel.viewModelScope
                                            )
                                        }
                                    } else {
                                        currentModuleForChooseDialog.value = module
                                        chooseDialog.show()
                                    }
                                }
                            },
                            contentPadding = ButtonDefaults.TextButtonContentPadding,
                        ) {
                            Icon(
                                modifier = Modifier.size(20.dp),
                                imageVector = Icons.Outlined.Download,
                                contentDescription = null
                            )
                        }
                    }
                }
            }
        }
    }
}

fun downloadAssetAndInstall(
    context: Context,
    module: RepoModule,
    asset: ReleaseAssetInfo,
    navigator: DestinationsNavigator,
    coroutineScope: CoroutineScope
) {
    val downloadingText = context.getText(R.string.module_downloading).toString()
    val downloadErrorText = context.getText(R.string.module_download_error).toString()
    coroutineScope.launch {
        withContext(Dispatchers.IO) {
            download(
                context,
                asset.downloadUrl,
                asset.name,
                downloadingText.format(module.moduleName),
                onDownloaded = { uri ->
                    navigator.navigate(
                        FlashScreenDestination(
                            FlashIt.FlashModule(uri)
                        )
                    )
                },
                onDownloading = {
                    launch(Dispatchers.Main) {
                        Toast.makeText(context, downloadingText.format(module.moduleName), Toast.LENGTH_SHORT).show()
                    }
                },
                onError = { errorMsg ->
                    launch(Dispatchers.Main) {
                        Toast.makeText(context, "$downloadErrorText: $errorMsg", Toast.LENGTH_LONG)
                            .show()
                    }
                }
            )
        }
    }
}

@Composable
fun ChooseDialogContent(
    currentModuleForChooseDialog: MutableState<RepoModule?>,
    navigator: DestinationsNavigator,
    viewModel: ModuleRepoViewModel,
    dismiss: () -> Unit
) {
    val context = LocalContext.current
    val module = currentModuleForChooseDialog.value
    if (module == null || module.latestAsset == null) {
        dismiss()
        return
    }
    var selectedAsset by remember { mutableStateOf<ReleaseAssetInfo?>(null) }

    Dialog(
        onDismissRequest = { dismiss() }
    ) {
        ElevatedCard(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(
                    text = stringResource(R.string.assets_multiple_select_dialog_title),
                    style = MaterialTheme.typography.titleMedium,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(10.dp))

                LazyColumn(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(module.latestAsset.assets) { asset ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(shape = RoundedCornerShape(24.dp))
                                .clickable { selectedAsset = asset }
                                .padding(vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = selectedAsset == asset,
                                onClick = null
                            )
                            Spacer(modifier = Modifier.width(8.dp))

                            Column {
                                Text(
                                    text = asset.name,
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Text(
                                    text = stringResource(R.string.assets_multiple_select_dialog_content_description,formatFileSize(asset.size), asset.downloadCount),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = { dismiss() }) {
                        Text(stringResource(android.R.string.cancel))
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    TextButton(
                        onClick = {
                            if (selectedAsset == null) {
                                Toast.makeText(context, R.string.assets_multiple_select_dialog_warning, Toast.LENGTH_SHORT).show()
                                return@TextButton
                            }
                            selectedAsset?.let { selected ->
                                dismiss()
                                downloadAssetAndInstall(context,module,selected, navigator, viewModel.viewModelScope)
                            }
                        }
                    ) {
                        Text(stringResource(android.R.string.ok))
                    }
                }
            }
        }
    }
}


// 下面全是预览相关了

fun initFakeRepoModuleForPreview() : RepoModule {
    return RepoModule(
        moduleId = "id",
        moduleName = "name",
        authors = "author",
        authorList = ArrayList<ModuleRepoViewModel.Author>().apply {
            add(
                ModuleRepoViewModel.Author(
                    name = "name",
                    link = "link"
                )
            )
        },
        summary = "I am a test module and i do nothing but show a very long description",
        metamodule = true,
        stargazerCount = 1,
        updatedAt = "updateAt",
        createdAt = "createAt",
        latestRelease = "latestRelease",
        latestReleaseTime = "latestReleaseTime",
        latestVersionCode = 1,
        latestAsset = ReleaseInfo(
            name = "name",
            tagName = "tagName",
            publishedAt = "publishedAt",
            descriptionHTML = "descriptionHTML",
            assets = ArrayList<ReleaseAssetInfo>().apply {
                add(
                    ReleaseAssetInfo(
                        name = "name",
                        downloadUrl = "downloadUrl",
                        size = 0,
                        downloadCount = 0
                    )
                )
                add(
                    ReleaseAssetInfo(
                        name = "name2",
                        downloadUrl = "downloadUrl2",
                        size = 0,
                        downloadCount = 0
                    )
                )
            }
        ),
        installed = true,
        readme = "README",
        sourceUrl = "Source URL",
        releases = emptyList()
    )
}

@Preview(locale = "en")
@Composable
fun OnlineModuleItemPreview() {
    val currentModuleForChooseDialog = remember { mutableStateOf<RepoModule?>(null) }

    OnlineModuleItem(
        EmptyDestinationsNavigator,
        initFakeRepoModuleForPreview(),
        viewModel<ModuleRepoViewModel>(),
        rememberConfirmDialog(),
        rememberCustomDialog { },
        currentModuleForChooseDialog,
    )
}

@Preview(locale = "zh-rCN", showBackground = true)
@Composable
fun ChooseDialogPreview() {
    val currentModuleForChooseDialog = remember { mutableStateOf<RepoModule?>(initFakeRepoModuleForPreview()) }

    ChooseDialogContent(currentModuleForChooseDialog, EmptyDestinationsNavigator, viewModel<ModuleRepoViewModel>()) {}
}