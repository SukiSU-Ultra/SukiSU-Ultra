package com.sukisu.ultra.ui.screen

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import com.sukisu.ultra.ui.util.ModuleModify
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel

@OptIn(ExperimentalMaterialApi::class, ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun SuperUserScreen(navigator: DestinationsNavigator) {
    val viewModel = viewModel<SuperUserViewModel>()
    val scope = rememberCoroutineScope()
    val scrollBehavior = TopAppBarDefaults.enterAlwaysScrollBehavior(rememberTopAppBarState())
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
                            contentDescription = stringResource(id = R.string.settings),
                            tint = MaterialTheme.colorScheme.primary
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
                                        tint = MaterialTheme.colorScheme.primary
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
                                        tint = MaterialTheme.colorScheme.primary
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
                                        tint = MaterialTheme.colorScheme.primary
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
                                        tint = MaterialTheme.colorScheme.primary
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
        bottomBar = {
            // 批量操作按钮，直接放在底部栏
            AnimatedVisibility(
                visible = viewModel.showBatchActions && viewModel.selectedApps.isNotEmpty(),
                enter = slideInVertically(initialOffsetY = { it }),
                exit = slideOutVertically(targetOffsetY = { it })
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceContainerHighest,
                    tonalElevation = 0.dp,
                    shadowElevation = 0.dp
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                // 修改为重新赋值为空集合
                                viewModel.selectedApps = emptySet()
                                viewModel.showBatchActions = false
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.primary
                            )
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Close,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(stringResource(android.R.string.cancel))
                        }

                        Button(
                            onClick = {
                                scope.launch {
                                    viewModel.updateBatchPermissions(true)
                                }
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.primary
                            )
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Check,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(stringResource(R.string.batch_authorization))
                        }

                        Button(
                            onClick = {
                                scope.launch {
                                    viewModel.updateBatchPermissions(false)
                                }
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Block,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(stringResource(R.string.batch_cancel_authorization))
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
                    bottom = if (viewModel.showBatchActions && viewModel.selectedApps.isNotEmpty()) 88.dp else 16.dp
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
    val cardColor = if (app.allowSu)
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
    else if (app.hasCustomProfile)
        MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.3f)
    else
        MaterialTheme.colorScheme.surfaceContainerLow

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
                        LabelText(label = "ROOT", backgroundColor = MaterialTheme.colorScheme.primary)
                    }
                    if (Natives.uidShouldUmount(app.uid)) {
                        LabelText(label = "UMOUNT", backgroundColor = MaterialTheme.colorScheme.tertiary)
                    }
                    if (app.hasCustomProfile) {
                        LabelText(label = "CUSTOM", backgroundColor = MaterialTheme.colorScheme.secondary)
                    }
                }
            }

            if (!viewModel.showBatchActions) {
                Switch(
                    checked = app.allowSu,
                    onCheckedChange = onSwitchChange,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                        checkedTrackColor = MaterialTheme.colorScheme.primary,
                        checkedIconColor = MaterialTheme.colorScheme.primary,
                        uncheckedThumbColor = MaterialTheme.colorScheme.outline,
                        uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant,
                        uncheckedIconColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                )
            } else {
                Checkbox(
                    checked = isSelected,
                    onCheckedChange = { onToggleSelection() },
                    colors = CheckboxDefaults.colors(
                        checkedColor = MaterialTheme.colorScheme.primary,
                        uncheckedColor = MaterialTheme.colorScheme.outline
                    )
                )
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