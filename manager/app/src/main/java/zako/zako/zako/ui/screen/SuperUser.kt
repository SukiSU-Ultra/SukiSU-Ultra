package zako.zako.zako.ui.screen

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.ExperimentalMaterialApi
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import zako.zako.zako.R
import coil.compose.AsyncImage
import coil.request.ImageRequest
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.AppProfileScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import kotlinx.coroutines.launch
import zako.zako.zako.Natives
import zako.zako.zako.ui.component.SearchAppBar
import zako.zako.zako.ui.util.ModuleModify
import zako.zako.zako.ui.viewmodel.SuperUserViewModel

@OptIn(ExperimentalMaterialApi::class, ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun SuperUserScreen(navigator: DestinationsNavigator) {
    val viewModel = viewModel<SuperUserViewModel>()
    val scope = rememberCoroutineScope()
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val listState = rememberLazyListState()
    val context = LocalContext.current
    val snackBarHostState = remember { SnackbarHostState() }

    // 添加备份和还原启动器
    val backupLauncher = ModuleModify.rememberAllowlistBackupLauncher(context, snackBarHostState)
    val restoreLauncher = ModuleModify.rememberAllowlistRestoreLauncher(context, snackBarHostState)

    LaunchedEffect(key1 = navigator) {
        viewModel.search = ""
        if (viewModel.appList.isEmpty()) {
            viewModel.fetchAppList()
        }
    }

    LaunchedEffect(viewModel.search) {
        if (viewModel.search.isEmpty()) {
            listState.scrollToItem(0)
        }
    }

    Scaffold(
        topBar = {
            SearchAppBar(
                title = { Text(stringResource(R.string.superuser)) },
                searchText = viewModel.search,
                onSearchTextChange = { viewModel.search = it },
                onClearClick = { viewModel.search = "" },
                dropdownContent = {
                    var showDropdown by remember { mutableStateOf(false) }

                    IconButton(
                        onClick = { showDropdown = true },
                    ) {
                        Icon(
                            imageVector = Icons.Filled.MoreVert,
                            contentDescription = stringResource(id = R.string.settings)
                        )

                        DropdownMenu(expanded = showDropdown, onDismissRequest = {
                            showDropdown = false
                        }) {
                            DropdownMenuItem(text = {
                                Text(stringResource(R.string.refresh))
                            }, onClick = {
                                scope.launch {
                                    viewModel.fetchAppList()
                                }
                                showDropdown = false
                            })
                            DropdownMenuItem(text = {
                                Text(
                                    if (viewModel.showSystemApps) {
                                        stringResource(R.string.hide_system_apps)
                                    } else {
                                        stringResource(R.string.show_system_apps)
                                    }
                                )
                            }, onClick = {
                                viewModel.showSystemApps = !viewModel.showSystemApps
                                showDropdown = false
                            })
                            DropdownMenuItem(text = {
                                Text(stringResource(R.string.backup_allowlist))
                            }, onClick = {
                                backupLauncher.launch(ModuleModify.createAllowlistBackupIntent())
                                showDropdown = false
                            })
                            DropdownMenuItem(text = {
                                Text(stringResource(R.string.restore_allowlist))
                            }, onClick = {
                                restoreLauncher.launch(ModuleModify.createAllowlistRestoreIntent())
                                showDropdown = false
                            })
                        }
                    }
                },
                scrollBehavior = scrollBehavior
            )
        },
        snackbarHost = { SnackbarHost(snackBarHostState) },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        bottomBar = {
            // 批量操作按钮，直接放在底部栏
            if (viewModel.showBatchActions && viewModel.selectedApps.isNotEmpty()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surface)
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    Button(
                        onClick = {
                            scope.launch {
                                viewModel.updateBatchPermissions(true)
                            }
                        }
                    ) {
                        Text(stringResource(R.string.batch_authorization))
                    }

                    Button(
                        onClick = {
                            scope.launch {
                                viewModel.updateBatchPermissions(false)
                            }
                        }
                    ) {
                        Text(stringResource(R.string.batch_cancel_authorization))
                    }
                }
            }
        }
    ) { innerPadding ->
        PullToRefreshBox(
            modifier = Modifier.padding(innerPadding),
            onRefresh = {
                scope.launch { viewModel.fetchAppList() }
            },
            isRefreshing = viewModel.isRefreshing
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .nestedScroll(scrollBehavior.nestedScrollConnection)
            ) {
                // 获取分组后的应用列表 - 修改分组逻辑，避免应用重复出现在多个分组中
                val rootApps = viewModel.appList.filter { it.allowSu }
                val customApps = viewModel.appList.filter { !it.allowSu && it.hasCustomProfile }
                val otherApps = viewModel.appList.filter { !it.allowSu && !it.hasCustomProfile }

                // 显示ROOT权限应用组
                if (rootApps.isNotEmpty()) {
                    items(rootApps, key = { "root_" + it.packageName + it.uid }) { app ->
                        AppItem(
                            app = app,
                            isSelected = viewModel.selectedApps.contains(app.packageName),
                            onToggleSelection = { viewModel.toggleAppSelection(app.packageName) },
                            onSwitchChange = { allowSu ->
                                scope.launch {
                                    val profile = Natives.getAppProfile(app.packageName, app.uid)
                                    val updatedProfile = profile.copy(allowSu = allowSu)
                                    if (Natives.setAppProfile(updatedProfile)) {
                                        viewModel.fetchAppList()
                                    }
                                }
                            },
                            onClick = {
                                if (viewModel.showBatchActions) {
                                    viewModel.toggleAppSelection(app.packageName)
                                } else {
                                    navigator.navigate(AppProfileScreenDestination(app))
                                }
                            },
                            onLongClick = {
                                // 长按进入多选模式
                                if (!viewModel.showBatchActions) {
                                    viewModel.toggleBatchMode()
                                    viewModel.toggleAppSelection(app.packageName)
                                }
                            },
                            viewModel = viewModel
                        )
                    }
                }

                // 显示自定义配置应用组
                if (customApps.isNotEmpty()) {
                    items(customApps, key = { "custom_" + it.packageName + it.uid }) { app ->
                        AppItem(
                            app = app,
                            isSelected = viewModel.selectedApps.contains(app.packageName),
                            onToggleSelection = { viewModel.toggleAppSelection(app.packageName) },
                            onSwitchChange = { allowSu ->
                                scope.launch {
                                    val profile = Natives.getAppProfile(app.packageName, app.uid)
                                    val updatedProfile = profile.copy(allowSu = allowSu)
                                    if (Natives.setAppProfile(updatedProfile)) {
                                        viewModel.fetchAppList()
                                    }
                                }
                            },
                            onClick = {
                                if (viewModel.showBatchActions) {
                                    viewModel.toggleAppSelection(app.packageName)
                                } else {
                                    navigator.navigate(AppProfileScreenDestination(app))
                                }
                            },
                            onLongClick = {
                                // 长按进入多选模式
                                if (!viewModel.showBatchActions) {
                                    viewModel.toggleBatchMode()
                                    viewModel.toggleAppSelection(app.packageName)
                                }
                            },
                            viewModel = viewModel
                        )
                    }
                }

                // 显示其他应用组
                if (otherApps.isNotEmpty()) {
                    items(otherApps, key = { "other_" + it.packageName + it.uid }) { app ->
                        AppItem(
                            app = app,
                            isSelected = viewModel.selectedApps.contains(app.packageName),
                            onToggleSelection = { viewModel.toggleAppSelection(app.packageName) },
                            onSwitchChange = { allowSu ->
                                scope.launch {
                                    val profile = Natives.getAppProfile(app.packageName, app.uid)
                                    val updatedProfile = profile.copy(allowSu = allowSu)
                                    if (Natives.setAppProfile(updatedProfile)) {
                                        viewModel.fetchAppList()
                                    }
                                }
                            },
                            onClick = {
                                if (viewModel.showBatchActions) {
                                    viewModel.toggleAppSelection(app.packageName)
                                } else {
                                    navigator.navigate(AppProfileScreenDestination(app))
                                }
                            },
                            onLongClick = {
                                // 长按进入多选模式
                                if (!viewModel.showBatchActions) {
                                    viewModel.toggleBatchMode()
                                    viewModel.toggleAppSelection(app.packageName)
                                }
                            },
                            viewModel = viewModel
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun GroupHeader(title: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Text(
            text = title,
            style = TextStyle(
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AppItem(
    app: SuperUserViewModel.AppInfo,
    isSelected: Boolean,
    onToggleSelection: () -> Unit,
    onSwitchChange: (Boolean) -> Unit,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    viewModel: SuperUserViewModel
) {
    ListItem(
        modifier = Modifier
            .pointerInput(Unit) {
                detectTapGestures(
                    onLongPress = { onLongClick() },
                    onTap = { onClick() }
                )
            },
        headlineContent = { Text(app.label) },
        supportingContent = {
            Column {
                Text(app.packageName)
                FlowRow {
                    if (app.allowSu) {
                        LabelText(label = "ROOT")
                    } else {
                        if (Natives.uidShouldUmount(app.uid)) {
                            LabelText(label = "UMOUNT")
                        }
                    }
                    if (app.hasCustomProfile) {
                        LabelText(label = "CUSTOM")
                    }
                }
            }
        },
        leadingContent = {
            AsyncImage(
                model = ImageRequest.Builder(LocalContext.current)
                    .data(app.packageInfo)
                    .crossfade(true)
                    .build(),
                contentDescription = app.label,
                modifier = Modifier
                    .padding(4.dp)
                    .width(48.dp)
                    .height(48.dp)
            )
        },
        trailingContent = {
            if (!viewModel.showBatchActions) {
                Switch(
                    checked = app.allowSu,
                    onCheckedChange = onSwitchChange
                )
            } else {
                Checkbox(
                    checked = isSelected,
                    onCheckedChange = { onToggleSelection() }
                )
            }
        }
    )
}

@Composable
fun LabelText(label: String) {
    Box(
        modifier = Modifier
            .padding(top = 4.dp, end = 4.dp)
            .background(
                Color.Black,
                shape = RoundedCornerShape(4.dp)
            )
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(vertical = 2.dp, horizontal = 5.dp),
            style = TextStyle(
                fontSize = 8.sp,
                color = Color.White,
            )
        )
    }
}