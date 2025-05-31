package com.sukisu.ultra.ui.screen

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.ExperimentalMaterialApi
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import coil.compose.AsyncImage
import coil.request.ImageRequest
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.AppProfileScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import kotlinx.coroutines.launch
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.component.SearchAppBar
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.util.ModuleModify
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import com.dergoogler.mmrl.ui.component.LabelItem
import com.dergoogler.mmrl.ui.component.LabelItemDefaults

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
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
            // 取消自动滚动到顶部的行为
            // listState.scrollToItem(0)
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
                            contentDescription = stringResource(id = R.string.settings),
                        )

                        DropdownMenu(expanded = showDropdown, onDismissRequest = {
                            showDropdown = false
                        }) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.refresh)) },
                                leadingIcon = {
                                    Icon(
                                        imageVector = Icons.Filled.Refresh,
                                        contentDescription = null,
                                    )
                                },
                                onClick = {
                                    scope.launch {
                                        viewModel.fetchAppList()
                                    }
                                    showDropdown = false
                                }
                            )
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        if (viewModel.showSystemApps) {
                                            stringResource(R.string.hide_system_apps)
                                        } else {
                                            stringResource(R.string.show_system_apps)
                                        }
                                    )
                                },
                                leadingIcon = {
                                    Icon(
                                        imageVector = if (viewModel.showSystemApps)
                                            Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                        contentDescription = null,
                                    )
                                },
                                onClick = {
                                    viewModel.showSystemApps = !viewModel.showSystemApps
                                    showDropdown = false
                                }
                            )
                            HorizontalDivider(thickness = 0.5.dp, modifier = Modifier.padding(vertical = 4.dp))
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.backup_allowlist)) },
                                leadingIcon = {
                                    Icon(
                                        imageVector = Icons.Filled.Save,
                                        contentDescription = null,
                                    )
                                },
                                onClick = {
                                    backupLauncher.launch(ModuleModify.createAllowlistBackupIntent())
                                    showDropdown = false
                                }
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.restore_allowlist)) },
                                leadingIcon = {
                                    Icon(
                                        imageVector = Icons.Filled.RestoreFromTrash,
                                        contentDescription = null,
                                    )
                                },
                                onClick = {
                                    restoreLauncher.launch(ModuleModify.createAllowlistRestoreIntent())
                                    showDropdown = false
                                }
                            )
                        }
                    }
                },
                scrollBehavior = scrollBehavior
            )
        },
        snackbarHost = { SnackbarHost(snackBarHostState) },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        floatingActionButton = {
            // 侧边悬浮按钮集合
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.End
            ) {
                // 批量操作相关按钮
                // 只有在批量模式且有选中应用时才显示批量操作按钮
                if (viewModel.showBatchActions && viewModel.selectedApps.isNotEmpty()) {
                    // 取消按钮
                    val cancelInteractionSource = remember { MutableInteractionSource() }
                    val isCancelPressed by cancelInteractionSource.collectIsPressedAsState()

                    FloatingActionButton(
                        onClick = {
                            viewModel.selectedApps = emptySet()
                            viewModel.showBatchActions = false
                        },
                        modifier = Modifier.size(if (isCancelPressed) 56.dp else 40.dp),
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                        contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        shape = CircleShape,
                        interactionSource = cancelInteractionSource,
                        elevation = FloatingActionButtonDefaults.elevation(4.dp, 6.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Close,
                                contentDescription = stringResource(android.R.string.cancel),
                                modifier = Modifier.size(24.dp)
                            )
                            AnimatedVisibility(
                                visible = isCancelPressed,
                                enter = expandHorizontally() + fadeIn(),
                                exit = shrinkHorizontally() + fadeOut()
                            ) {
                                Text(
                                    stringResource(android.R.string.cancel),
                                    modifier = Modifier.padding(end = 4.dp),
                                    style = MaterialTheme.typography.labelMedium
                                )
                            }
                        }
                    }

                    // 取消授权按钮
                    val unauthorizeInteractionSource = remember { MutableInteractionSource() }
                    val isUnauthorizePressed by unauthorizeInteractionSource.collectIsPressedAsState()

                    FloatingActionButton(
                        onClick = {
                            scope.launch {
                                viewModel.updateBatchPermissions(false)
                            }
                        },
                        modifier = Modifier.size(if (isUnauthorizePressed) 56.dp else 40.dp),
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        shape = CircleShape,
                        interactionSource = unauthorizeInteractionSource,
                        elevation = FloatingActionButtonDefaults.elevation(4.dp, 6.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Block,
                                contentDescription = stringResource(R.string.batch_cancel_authorization),
                                modifier = Modifier.size(24.dp)
                            )
                            AnimatedVisibility(
                                visible = isUnauthorizePressed,
                                enter = expandHorizontally() + fadeIn(),
                                exit = shrinkHorizontally() + fadeOut()
                            ) {
                                Text(
                                    stringResource(R.string.batch_cancel_authorization),
                                    modifier = Modifier.padding(end = 4.dp),
                                    style = MaterialTheme.typography.labelMedium
                                )
                            }
                        }
                    }

                    // 授权按钮
                    val authorizeInteractionSource = remember { MutableInteractionSource() }
                    val isAuthorizePressed by authorizeInteractionSource.collectIsPressedAsState()

                    FloatingActionButton(
                        onClick = {
                            scope.launch {
                                viewModel.updateBatchPermissions(true)
                            }
                        },
                        modifier = Modifier.size(if (isAuthorizePressed) 56.dp else 40.dp),
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        shape = CircleShape,
                        interactionSource = authorizeInteractionSource,
                        elevation = FloatingActionButtonDefaults.elevation(4.dp, 6.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Check,
                                contentDescription = stringResource(R.string.batch_authorization),
                                modifier = Modifier.size(24.dp)
                            )
                            AnimatedVisibility(
                                visible = isAuthorizePressed,
                                enter = expandHorizontally() + fadeIn(),
                                exit = shrinkHorizontally() + fadeOut()
                            ) {
                                Text(
                                    stringResource(R.string.batch_authorization),
                                    modifier = Modifier.padding(end = 4.dp),
                                    style = MaterialTheme.typography.labelMedium
                                )
                            }
                        }
                    }

                    // 添加分隔
                    Spacer(modifier = Modifier.height(8.dp))
                }

                if (viewModel.showBatchActions && viewModel.selectedApps.isNotEmpty()) {

                // 在批量操作按钮组中添加卸载模块的按钮
                // 卸载模块启用按钮
                val umountEnableInteractionSource = remember { MutableInteractionSource() }
                val isUmountEnablePressed by umountEnableInteractionSource.collectIsPressedAsState()

                FloatingActionButton(
                    onClick = {
                        scope.launch {
                            viewModel.updateBatchPermissions(
                                allowSu = false, // 不改变ROOT权限状态
                                umountModules = true // 启用卸载模块
                            )
                        }
                    },
                    modifier = Modifier.size(if (isUmountEnablePressed) 56.dp else 40.dp),
                    containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                    contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                    shape = CircleShape,
                    interactionSource = umountEnableInteractionSource,
                    elevation = FloatingActionButtonDefaults.elevation(4.dp, 6.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.FolderOff,
                            contentDescription = stringResource(R.string.profile_umount_modules),
                            modifier = Modifier.size(24.dp)
                        )
                        AnimatedVisibility(
                            visible = isUmountEnablePressed,
                            enter = expandHorizontally() + fadeIn(),
                            exit = shrinkHorizontally() + fadeOut()
                        ) {
                            Text(
                                stringResource(R.string.profile_umount_modules),
                                modifier = Modifier.padding(end = 4.dp),
                                style = MaterialTheme.typography.labelMedium
                            )
                        }
                    }
                }

                // 卸载模块禁用按钮
                val umountDisableInteractionSource = remember { MutableInteractionSource() }
                val isUmountDisablePressed by umountDisableInteractionSource.collectIsPressedAsState()

                FloatingActionButton(
                    onClick = {
                        scope.launch {
                            viewModel.updateBatchPermissions(
                                allowSu = false, // 不改变ROOT权限状态
                                umountModules = false // 禁用卸载模块
                            )
                        }
                    },
                    modifier = Modifier.size(if (isUmountDisablePressed) 56.dp else 40.dp),
                    containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                    contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                    shape = CircleShape,
                    interactionSource = umountDisableInteractionSource,
                    elevation = FloatingActionButtonDefaults.elevation(4.dp, 6.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Folder,
                            contentDescription = stringResource(R.string.profile_umount_modules_disable),
                            modifier = Modifier.size(24.dp)
                        )
                        AnimatedVisibility(
                            visible = isUmountDisablePressed,
                            enter = expandHorizontally() + fadeIn(),
                            exit = shrinkHorizontally() + fadeOut()
                        ) {
                            Text(
                                stringResource(R.string.profile_umount_modules_disable),
                                modifier = Modifier.padding(end = 4.dp),
                                style = MaterialTheme.typography.labelMedium
                            )
                        }
                    }
                    // 添加分隔
                    Spacer(modifier = Modifier.height(8.dp))
                }
                    }

                // 向上导航按钮
                val topBtnInteractionSource = remember { MutableInteractionSource() }
                val isTopBtnPressed by topBtnInteractionSource.collectIsPressedAsState()

                FloatingActionButton(
                    onClick = {
                        scope.launch {
                            listState.animateScrollToItem(0)
                        }
                    },
                    modifier = Modifier.size(if (isTopBtnPressed) 56.dp else 40.dp),
                    containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 1f),
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    shape = CircleShape,
                    interactionSource = topBtnInteractionSource,
                    elevation = FloatingActionButtonDefaults.elevation(4.dp, 6.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.KeyboardArrowUp,
                            contentDescription = stringResource(R.string.scroll_to_top_description),
                            modifier = Modifier.size(24.dp)
                        )
                        AnimatedVisibility(
                            visible = isTopBtnPressed,
                            enter = expandHorizontally() + fadeIn(),
                            exit = shrinkHorizontally() + fadeOut()
                        ) {
                            Text(
                                stringResource(R.string.scroll_to_top),
                                modifier = Modifier.padding(end = 4.dp),
                                style = MaterialTheme.typography.labelMedium
                            )
                        }
                    }
                }

                // 向下导航按钮
                val bottomBtnInteractionSource = remember { MutableInteractionSource() }
                val isBottomBtnPressed by bottomBtnInteractionSource.collectIsPressedAsState()

                FloatingActionButton(
                    onClick = {
                        scope.launch {
                            val lastIndex = viewModel.appList.size - 1
                            if (lastIndex >= 0) {
                                listState.animateScrollToItem(lastIndex)
                            }
                        }
                    },
                    modifier = Modifier.size(if (isBottomBtnPressed) 56.dp else 40.dp),
                    containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 1f),
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    shape = CircleShape,
                    interactionSource = bottomBtnInteractionSource,
                    elevation = FloatingActionButtonDefaults.elevation(4.dp, 6.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.Filled.KeyboardArrowDown,
                            contentDescription = stringResource(R.string.scroll_to_bottom_description),
                            modifier = Modifier.size(24.dp)
                        )
                        AnimatedVisibility(
                            visible = isBottomBtnPressed,
                            enter = expandHorizontally() + fadeIn(),
                            exit = shrinkHorizontally() + fadeOut()
                        ) {
                            Text(
                                stringResource(R.string.scroll_to_bottom),
                                modifier = Modifier.padding(end = 4.dp),
                                style = MaterialTheme.typography.labelMedium
                            )
                        }
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
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                contentPadding = PaddingValues(
                    top = 8.dp,
                    bottom = 16.dp
                )
            ) {
                // 获取分组后的应用列表
                val rootApps = viewModel.appList.filter { it.allowSu }
                val customApps = viewModel.appList.filter { !it.allowSu && it.hasCustomProfile }
                val otherApps = viewModel.appList.filter { !it.allowSu && !it.hasCustomProfile }

                // 显示ROOT权限应用组
                if (rootApps.isNotEmpty()) {
                    item {
                        GroupHeader(title = stringResource(R.string.apps_with_root))
                    }

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
                                        viewModel.updateAppProfileLocally(app.packageName, updatedProfile)
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
                    item {
                        GroupHeader(title = stringResource(R.string.apps_with_custom_profile))
                    }

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
                                        viewModel.updateAppProfileLocally(app.packageName, updatedProfile)
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
                    item {
                        GroupHeader(title = stringResource(R.string.other_apps))
                    }

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
                                        viewModel.updateAppProfileLocally(app.packageName, updatedProfile)
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

                // 当没有应用显示时显示空状态
                if (viewModel.appList.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(400.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Apps,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.6f),
                                    modifier = Modifier
                                        .size(96.dp)
                                        .padding(bottom = 16.dp)
                                )
                                Text(
                                    text = stringResource(R.string.no_apps_found),
                                    textAlign = TextAlign.Center,
                                    style = MaterialTheme.typography.bodyLarge,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
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
            .background(MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = 0.7f))
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Text(
            text = title,
            style = TextStyle(
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
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
    val cardAlpha = CardConfig.cardAlpha

    val cardColor = if (app.allowSu)
        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = cardAlpha)
    else if (app.hasCustomProfile)
        MaterialTheme.colorScheme.secondaryContainer.copy(alpha = cardAlpha)
    else
        MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = cardAlpha)

    Card(
        colors = CardDefaults.cardColors(containerColor = cardColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 4.dp)
            .clip(MaterialTheme.shapes.medium)
            .shadow(
                elevation = 0.dp,
                shape = MaterialTheme.shapes.medium,
                spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
            )
            .then(
                if (isSelected)
                    Modifier.border(
                        width = 2.dp,
                        color = MaterialTheme.colorScheme.primary,
                        shape = MaterialTheme.shapes.medium
                    )
                else
                    Modifier
            )
            .pointerInput(Unit) {
                detectTapGestures(
                    onLongPress = { onLongClick() },
                    onTap = { onClick() }
                )
            }
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            AsyncImage(
                model = ImageRequest.Builder(LocalContext.current)
                    .data(app.packageInfo)
                    .crossfade(true)
                    .build(),
                contentDescription = app.label,
                modifier = Modifier
                    .padding(end = 16.dp)
                    .size(48.dp)
                    .clip(MaterialTheme.shapes.small)
            )

            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 8.dp)
            ) {
                Text(
                    text = app.label,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                )

                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                )

                FlowRow(
                    modifier = Modifier.padding(top = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (app.allowSu) {
                        LabelItem(text = "ROOT",)
                    }
                    if (Natives.uidShouldUmount(app.uid)) {
                        LabelItem(text = "UNMOUNT", style = LabelItemDefaults.style.copy(
                            containerColor = MaterialTheme.colorScheme.secondaryContainer,
                            contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                            )
                        )
                    }
                    if (app.hasCustomProfile) {
                        LabelItem(text = "CUSTOM", style = LabelItemDefaults.style.copy(
                            containerColor = MaterialTheme.colorScheme.onTertiary,
                            contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                            )
                        )
                    }
                }
            }

            if (!viewModel.showBatchActions) {
                // 开关交互源
                val switchInteractionSource = remember { MutableInteractionSource() }
                val isSwitchPressed by switchInteractionSource.collectIsPressedAsState()

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.End
                ) {
                    AnimatedVisibility(
                        visible = isSwitchPressed,
                        enter = expandHorizontally() + fadeIn(),
                        exit = shrinkHorizontally() + fadeOut()
                    ) {
                        Text(
                            text = if (app.allowSu) stringResource(R.string.authorized) else stringResource(R.string.unauthorized),
                            style = MaterialTheme.typography.labelMedium,
                            color = if (app.allowSu) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                            modifier = Modifier.padding(end = 4.dp)
                        )
                    }

                    Switch(
                        checked = app.allowSu,
                        onCheckedChange = onSwitchChange,
                        interactionSource = switchInteractionSource,
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
            } else {
                // 复选框交互源
                val checkboxInteractionSource = remember { MutableInteractionSource() }
                val isCheckboxPressed by checkboxInteractionSource.collectIsPressedAsState()

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.End
                ) {
                    AnimatedVisibility(
                        visible = isCheckboxPressed,
                        enter = expandHorizontally() + fadeIn(),
                        exit = shrinkHorizontally() + fadeOut()
                    ) {
                        Text(
                            text = if (isSelected) stringResource(R.string.selected) else stringResource(R.string.select),
                            style = MaterialTheme.typography.labelMedium,
                            color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                            modifier = Modifier.padding(end = 4.dp)
                        )
                    }

                    Checkbox(
                        checked = isSelected,
                        onCheckedChange = { onToggleSelection() },
                        interactionSource = checkboxInteractionSource,
                        colors = CheckboxDefaults.colors(
                            checkedColor = MaterialTheme.colorScheme.primary,
                            uncheckedColor = MaterialTheme.colorScheme.outline
                        )
                    )
                }
            }
        }
    }
}

@Composable
fun LabelText(label: String, backgroundColor: Color) {
    Box(
        modifier = Modifier
            .padding(top = 2.dp, end = 2.dp)
            .background(
                backgroundColor,
                shape = RoundedCornerShape(4.dp)
            )
            .clip(RoundedCornerShape(4.dp))
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(vertical = 2.dp, horizontal = 6.dp),
            style = TextStyle(
                fontSize = 10.sp,
                color = Color.White,
                fontWeight = FontWeight.Medium
            )
        )
    }
}