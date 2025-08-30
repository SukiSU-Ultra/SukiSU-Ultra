package com.sukisu.ultra.ui.screen

import android.annotation.SuppressLint
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
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
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import coil.compose.AsyncImage
import coil.request.ImageRequest
import com.dergoogler.mmrl.ui.component.LabelItem
import com.dergoogler.mmrl.ui.component.LabelItemDefaults
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.AppProfileScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.FabMenuPresets
import com.sukisu.ultra.ui.component.SearchAppBar
import com.sukisu.ultra.ui.component.VerticalExpandableFab
import com.sukisu.ultra.ui.util.ModuleModify
import com.sukisu.ultra.ui.viewmodel.AppCategory
import com.sukisu.ultra.ui.viewmodel.SortType
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.launch
import java.io.File

// 应用优先级枚举
enum class AppPriority(val value: Int) {
    ROOT(1),      // root权限应用
    CUSTOM(2),    // 自定义应用
    DEFAULT(3) // 默认应用
}

// 菜单项数据类
data class BottomSheetMenuItem(
    val icon: ImageVector,
    val titleRes: Int,
    val onClick: () -> Unit
)

/**
 * 获取应用的优先级
 */
private fun getAppPriority(app: SuperUserViewModel.AppInfo): AppPriority {
    return when {
        app.allowSu -> AppPriority.ROOT
        app.hasCustomProfile -> AppPriority.CUSTOM
        else -> AppPriority.DEFAULT
    }
}

/**
 * 获取多选模式的主按钮图标
 */
private fun getMultiSelectMainIcon(isExpanded: Boolean): ImageVector {
    return if (isExpanded) {
        Icons.Filled.Close
    } else {
        Icons.Filled.GridView
    }
}

/**
 * 获取单选模式的主按钮图标
 */
private fun getSingleSelectMainIcon(isExpanded: Boolean): ImageVector {
    return if (isExpanded) {
        Icons.Filled.Close
    } else {
        Icons.Filled.Add
    }
}

/**
 * @author ShirkNeko
 * @date 2025/6/8
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

    // 使用ViewModel中的状态，这些状态现在都会从SharedPreferences中加载并自动保存
    val selectedCategory = viewModel.selectedCategory
    val currentSortType = viewModel.currentSortType

    // BottomSheet状态
    val bottomSheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true
    )
    var showBottomSheet by remember { mutableStateOf(false) }

    // 添加备份和还原启动器
    val backupLauncher = ModuleModify.rememberAllowlistBackupLauncher(context, snackBarHostState)
    val restoreLauncher = ModuleModify.rememberAllowlistRestoreLauncher(context, snackBarHostState)

    LaunchedEffect(key1 = navigator) {
        viewModel.search = ""
        if (viewModel.appList.isEmpty()) {
            // viewModel.fetchAppList()
        }
    }

    LaunchedEffect(viewModel.search) {
        if (viewModel.search.isEmpty()) {
            // 取消自动滚动到顶部的行为
            // listState.scrollToItem(0)
        }
    }

    // 监听选中应用的变化，如果在多选模式下没有选中任何应用，则自动退出多选模式
    LaunchedEffect(viewModel.selectedApps, viewModel.showBatchActions) {
        if (viewModel.showBatchActions && viewModel.selectedApps.isEmpty()) {
            viewModel.showBatchActions = false
        }
    }

    // 应用分类和排序逻辑
    val filteredAndSortedApps = remember(
        viewModel.appList,
        selectedCategory,
        currentSortType,
        viewModel.search,
        viewModel.showSystemApps
    ) {
        var apps = viewModel.appList

        // 按分类筛选
        apps = when (selectedCategory) {
            AppCategory.ALL -> apps
            AppCategory.ROOT -> apps.filter { it.allowSu }
            AppCategory.CUSTOM -> apps.filter { !it.allowSu && it.hasCustomProfile }
            AppCategory.DEFAULT -> apps.filter { !it.allowSu && !it.hasCustomProfile }
        }

        // 优先级排序 + 二次排序
        apps = apps.sortedWith { app1, app2 ->
            val priority1 = getAppPriority(app1)
            val priority2 = getAppPriority(app2)

            // 首先按优先级排序
            val priorityComparison = priority1.value.compareTo(priority2.value)

            if (priorityComparison != 0) {
                priorityComparison
            } else {
                // 在相同优先级内按指定排序方式排序
                when (currentSortType) {
                    SortType.NAME_ASC -> app1.label.lowercase().compareTo(app2.label.lowercase())
                    SortType.NAME_DESC -> app2.label.lowercase().compareTo(app1.label.lowercase())
                    SortType.INSTALL_TIME_NEW -> app2.packageInfo.firstInstallTime.compareTo(app1.packageInfo.firstInstallTime)
                    SortType.INSTALL_TIME_OLD -> app1.packageInfo.firstInstallTime.compareTo(app2.packageInfo.firstInstallTime)
                    SortType.SIZE_DESC -> {
                        val size1: Long = app1.packageInfo.applicationInfo?.let {
                            try {
                                File(context.packageManager.getApplicationInfo(it.packageName, 0).sourceDir).length()
                            } catch (_: Exception) {
                                0L
                            }
                        } ?: 0L
                        val size2: Long = app2.packageInfo.applicationInfo?.let {
                            try {
                                File(context.packageManager.getApplicationInfo(it.packageName, 0).sourceDir).length()
                            } catch (_: Exception) {
                                0L
                            }
                        } ?: 0L
                        size2.compareTo(size1)
                    }
                    SortType.SIZE_ASC -> {
                        val size1: Long = app1.packageInfo.applicationInfo?.let {
                            try {
                                File(context.packageManager.getApplicationInfo(it.packageName, 0).sourceDir).length()
                            } catch (_: Exception) {
                                0L
                            }
                        } ?: 0L
                        val size2: Long = app2.packageInfo.applicationInfo?.let {
                            try {
                                File(context.packageManager.getApplicationInfo(it.packageName, 0).sourceDir).length()
                            } catch (_: Exception) {
                                0L
                            }
                        } ?: 0L
                        size1.compareTo(size2)
                    }
                    SortType.USAGE_FREQ -> app1.label.lowercase().compareTo(app2.label.lowercase()) // 默认按名称排序
                }
            }
        }

        apps
    }

    // 计算应用数量
    val appCounts = remember(viewModel.appList, viewModel.showSystemApps) {
        mapOf(
            AppCategory.ALL to viewModel.appList.size,
            AppCategory.ROOT to viewModel.appList.count { it.allowSu },
            AppCategory.CUSTOM to viewModel.appList.count { !it.allowSu && it.hasCustomProfile },
            AppCategory.DEFAULT to viewModel.appList.count { !it.allowSu && !it.hasCustomProfile }
        )
    }

    // BottomSheet菜单项
    val bottomSheetMenuItems = remember(viewModel.showSystemApps) {
        listOf(
            BottomSheetMenuItem(
                icon = Icons.Filled.Refresh,
                titleRes = R.string.refresh,
                onClick = {
                    scope.launch {
                        viewModel.fetchAppList()
                        bottomSheetState.hide()
                        showBottomSheet = false
                    }
                }
            ),
            BottomSheetMenuItem(
                icon = if (viewModel.showSystemApps) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                titleRes = if (viewModel.showSystemApps) {
                    R.string.hide_system_apps
                } else {
                    R.string.show_system_apps
                },
                onClick = {
                    viewModel.updateShowSystemApps(!viewModel.showSystemApps)
                    scope.launch {
                        kotlinx.coroutines.delay(100)
                        bottomSheetState.hide()
                        showBottomSheet = false
                    }
                }
            ),
            BottomSheetMenuItem(
                icon = Icons.Filled.Save,
                titleRes = R.string.backup_allowlist,
                onClick = {
                    backupLauncher.launch(ModuleModify.createAllowlistBackupIntent())
                    scope.launch {
                        bottomSheetState.hide()
                        showBottomSheet = false
                    }
                }
            ),
            BottomSheetMenuItem(
                icon = Icons.Filled.RestoreFromTrash,
                titleRes = R.string.restore_allowlist,
                onClick = {
                    restoreLauncher.launch(ModuleModify.createAllowlistRestoreIntent())
                    scope.launch {
                        bottomSheetState.hide()
                        showBottomSheet = false
                    }
                }
            )
        )
    }

    // 记录FAB展开状态用于图标动画
    var isFabExpanded by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            SearchAppBar(
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(stringResource(R.string.superuser))
                        // 显示当前分类和应用数量
                        if (selectedCategory != AppCategory.ALL) {
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = MaterialTheme.colorScheme.primaryContainer,
                                modifier = Modifier.padding(start = 4.dp)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Text(
                                        text = stringResource(selectedCategory.displayNameRes),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onPrimaryContainer
                                    )
                                    Text(
                                        text = "(${appCounts[selectedCategory] ?: 0})",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onPrimaryContainer
                                    )
                                }
                            }
                        }
                    }
                },
                searchText = viewModel.search,
                onSearchTextChange = { viewModel.search = it },
                onClearClick = { viewModel.search = "" },
                dropdownContent = {
                    IconButton(
                        onClick = {
                            showBottomSheet = true
                        },
                    ) {
                        Icon(
                            imageVector = Icons.Filled.MoreVert,
                            contentDescription = stringResource(id = R.string.settings),
                        )
                    }
                },
                scrollBehavior = scrollBehavior
            )
        },
        snackbarHost = { SnackbarHost(snackBarHostState) },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        floatingActionButton = {
            VerticalExpandableFab(
                menuItems = if (viewModel.showBatchActions && viewModel.selectedApps.isNotEmpty()) {
                    FabMenuPresets.getBatchActionMenuItems(
                        onCancel = {
                            viewModel.selectedApps = emptySet()
                            viewModel.showBatchActions = false
                        },
                        onDeny = {
                            scope.launch {
                                viewModel.updateBatchPermissions(false)
                            }
                        },
                        onAllow = {
                            scope.launch {
                                viewModel.updateBatchPermissions(true)
                            }
                        },
                        onUnmountModules = {
                            scope.launch {
                                viewModel.updateBatchPermissions(
                                    allowSu = false,
                                    umountModules = true
                                )
                            }
                        },
                        onDisableUnmount = {
                            scope.launch {
                                viewModel.updateBatchPermissions(
                                    allowSu = false,
                                    umountModules = false
                                )
                            }
                        }
                    )
                } else {
                    FabMenuPresets.getScrollMenuItems(
                        onScrollToTop = {
                            scope.launch {
                                listState.animateScrollToItem(0)
                            }
                        },
                        onScrollToBottom = {
                            scope.launch {
                                val lastIndex = filteredAndSortedApps.size - 1
                                if (lastIndex >= 0) {
                                    listState.animateScrollToItem(lastIndex)
                                }
                            }
                        }
                    )
                },
                buttonSpacing = 72.dp,
                animationDurationMs = 300,
                staggerDelayMs = 50,
                // 根据模式选择不同的图标
                mainButtonIcon = if (viewModel.showBatchActions && viewModel.selectedApps.isNotEmpty()) {
                    getMultiSelectMainIcon(isFabExpanded)
                } else {
                    getSingleSelectMainIcon(isFabExpanded)
                },
                mainButtonExpandedIcon = Icons.Filled.Close
            )
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
                items(filteredAndSortedApps, key = { it.packageName + it.uid }) { app ->
                    AppItem(
                        app = app,
                        isSelected = viewModel.selectedApps.contains(app.packageName),
                        onToggleSelection = { viewModel.toggleAppSelection(app.packageName) },
                        onClick = {
                            if (viewModel.showBatchActions) {
                                viewModel.toggleAppSelection(app.packageName)
                            } else {
                                navigator.navigate(AppProfileScreenDestination(app))
                            }
                        },
                        onLongClick = {
                            if (!viewModel.showBatchActions) {
                                viewModel.toggleBatchMode()
                                viewModel.toggleAppSelection(app.packageName)
                            }
                        },
                        viewModel = viewModel
                    )
                }

                // 当没有应用显示时显示加载动画或空状态
                if (filteredAndSortedApps.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(400.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            // 根据加载状态显示不同内容
                            if ((viewModel.isRefreshing || viewModel.appList.isEmpty()) && viewModel.search.isEmpty()) {
                                LoadingAnimation(
                                    isLoading = true
                                )
                            } else {
                                EmptyState(
                                    selectedCategory = selectedCategory,
                                    isSearchEmpty = viewModel.search.isNotEmpty()
                                )
                            }
                        }
                    }
                }
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
                BottomSheetContent(
                    menuItems = bottomSheetMenuItems,
                    currentSortType = currentSortType,
                    onSortTypeChanged = { newSortType ->
                        viewModel.updateCurrentSortType(newSortType)
                        scope.launch {
                            bottomSheetState.hide()
                            showBottomSheet = false
                        }
                    },
                    selectedCategory = selectedCategory,
                    onCategorySelected = { newCategory ->
                        viewModel.updateSelectedCategory(newCategory)
                        scope.launch {
                            listState.animateScrollToItem(0)
                            bottomSheetState.hide()
                            showBottomSheet = false
                        }
                    },
                    appCounts = appCounts
                )
            }
        }
    }
}

@Composable
private fun BottomSheetContent(
    menuItems: List<BottomSheetMenuItem>,
    currentSortType: SortType,
    onSortTypeChanged: (SortType) -> Unit,
    selectedCategory: AppCategory,
    onCategorySelected: (AppCategory) -> Unit,
    appCounts: Map<AppCategory, Int>
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
                BottomSheetMenuItemView(
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

        LazyRow(
            modifier = Modifier.fillMaxWidth(),
            contentPadding = PaddingValues(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(SortType.entries.toTypedArray()) { sortType ->
                FilterChip(
                    onClick = { onSortTypeChanged(sortType) },
                    label = { Text(stringResource(sortType.displayNameRes)) },
                    selected = currentSortType == sortType
                )
            }
        }

        // 应用分类选项
        Spacer(modifier = Modifier.height(24.dp))
        HorizontalDivider(modifier = Modifier.padding(horizontal = 24.dp))

        Text(
            text = stringResource(R.string.app_categories),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
        )

        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            modifier = Modifier.fillMaxWidth(),
            contentPadding = PaddingValues(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(AppCategory.entries.toTypedArray()) { category ->
                CategoryChip(
                    category = category,
                    isSelected = selectedCategory == category,
                    onClick = { onCategorySelected(category) },
                    appCount = appCounts[category] ?: 0
                )
            }
        }
    }
}

@Composable
private fun CategoryChip(
    category: AppCategory,
    isSelected: Boolean,
    onClick: () -> Unit,
    appCount: Int,
    modifier: Modifier = Modifier
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.95f else 1.0f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessHigh
        ),
        label = "categoryChipScale"
    )

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .scale(scale)
            .clickable(
                interactionSource = interactionSource,
                indication = null
            ) { onClick() },
        shape = RoundedCornerShape(12.dp),
        color = if (isSelected) {
            MaterialTheme.colorScheme.primaryContainer
        } else {
            MaterialTheme.colorScheme.surfaceVariant
        },
        tonalElevation = if (isSelected) 4.dp else 0.dp
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // 分类信息行
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = stringResource(category.displayNameRes),
                    style = MaterialTheme.typography.titleSmall.copy(
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium
                    ),
                    color = if (isSelected) {
                        MaterialTheme.colorScheme.onPrimaryContainer
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )

                // 选中指示器
                AnimatedVisibility(
                    visible = isSelected,
                    enter = scaleIn() + fadeIn(),
                    exit = scaleOut() + fadeOut()
                ) {
                    Icon(
                        imageVector = Icons.Filled.Check,
                        contentDescription = stringResource(R.string.selected),
                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            // 应用数量
            Text(
                text = "$appCount apps",
                style = MaterialTheme.typography.labelSmall,
                color = if (isSelected) {
                    MaterialTheme.colorScheme.onPrimaryContainer
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                }
            )
        }
    }
}

@Composable
private fun BottomSheetMenuItemView(menuItem: BottomSheetMenuItem) {
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

@OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)
@Composable
private fun AppItem(
    app: SuperUserViewModel.AppInfo,
    isSelected: Boolean,
    onToggleSelection: () -> Unit,
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

                Spacer(modifier = Modifier.height(4.dp))

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (app.allowSu) {
                        LabelItem(
                            text = "ROOT",
                        )
                    } else {
                        if (Natives.uidShouldUmount(app.uid)) {
                            LabelItem(
                                text = "UMOUNT",
                                style = LabelItemDefaults.style.copy(
                                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                                )
                            )
                        }
                    }
                    if (app.hasCustomProfile) {
                        LabelItem(
                            text = "CUSTOM",
                            style = LabelItemDefaults.style.copy(
                                containerColor = MaterialTheme.colorScheme.onTertiary,
                                contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                            )
                        )
                    } else if (!app.allowSu) {
                        LabelItem(
                            text = "DEFAULT",
                            style = LabelItemDefaults.style.copy(
                                containerColor = Color.Gray
                            )
                        )
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
            if (viewModel.showBatchActions) {
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
                            modifier = Modifier.padding(end = 4.dp)
                        )
                    }
                    Checkbox(
                        checked = isSelected,
                        onCheckedChange = { onToggleSelection() },
                        interactionSource = checkboxInteractionSource,
                    )
                }
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

/**
 * 加载动画组件
 */
@Composable
private fun LoadingAnimation(
    modifier: Modifier = Modifier,
    isLoading: Boolean = true
) {
    val infiniteTransition = rememberInfiniteTransition(label = "loading")

    // 透明度动画
    val alpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(600, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "alpha"
    )

    AnimatedVisibility(
        visible = isLoading,
        enter = fadeIn() + scaleIn(),
        exit = fadeOut() + scaleOut(),
        modifier = modifier
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // 进度指示器
            LinearProgressIndicator(
                modifier = Modifier
                    .width(200.dp)
                    .height(4.dp),
                color = MaterialTheme.colorScheme.primary.copy(alpha = alpha),
                trackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.2f)
            )
        }
    }
}

/**
 * 空状态组件
 */
@Composable
@SuppressLint("ModifierParameter")
private fun EmptyState(
    selectedCategory: AppCategory,
    modifier: Modifier = Modifier,
    isSearchEmpty: Boolean = false
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        modifier = modifier
    ) {
        Icon(
            imageVector = if (isSearchEmpty) Icons.Filled.SearchOff else Icons.Filled.Archive,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.6f),
            modifier = Modifier
                .size(96.dp)
                .padding(bottom = 16.dp)
        )
        Text(
            text = if (isSearchEmpty || selectedCategory == AppCategory.ALL) {
                stringResource(R.string.no_apps_found)
            } else {
                stringResource(R.string.no_apps_in_category)
            },
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.bodyLarge,
        )
    }
}