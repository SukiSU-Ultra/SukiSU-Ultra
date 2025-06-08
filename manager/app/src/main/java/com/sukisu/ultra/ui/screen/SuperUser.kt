package com.sukisu.ultra.ui.screen

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
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
import androidx.compose.foundation.clickable
import androidx.compose.material.ExperimentalMaterialApi
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.font.FontWeight
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
import com.sukisu.ultra.ui.component.VerticalExpandableFab
import com.sukisu.ultra.ui.component.FabMenuPresets
import com.sukisu.ultra.ui.util.ModuleModify
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import com.dergoogler.mmrl.ui.component.LabelItem
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.theme.getCardElevation
import kotlin.math.*

// 应用分类
enum class AppCategory(val displayNameRes: Int) {
    ALL(R.string.category_all_apps),
    ROOT(R.string.category_root_apps),
    CUSTOM(R.string.category_custom_apps),
    DEFAULT(R.string.category_default_apps)
}

// 排序方式
enum class SortType(val displayNameRes: Int) {
    NAME_ASC(R.string.sort_name_asc),
    NAME_DESC(R.string.sort_name_desc),
    INSTALL_TIME_NEW(R.string.sort_install_time_new),
    INSTALL_TIME_OLD(R.string.sort_install_time_old),
    SIZE_DESC(R.string.sort_size_desc),
    SIZE_ASC(R.string.sort_size_asc),
    USAGE_FREQ(R.string.sort_usage_freq)
}

// 菜单项数据类
data class BottomSheetMenuItem(
    val icon: ImageVector,
    val titleRes: Int,
    val onClick: () -> Unit
)

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

    // 分类和排序状态
    var selectedCategory by remember { mutableStateOf(AppCategory.ALL) }
    var currentSortType by remember { mutableStateOf(SortType.NAME_ASC) }

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

    // 应用分类和排序逻辑
    val filteredAndSortedApps = remember(viewModel.appList, selectedCategory, currentSortType, viewModel.search) {
        var apps = viewModel.appList

        // 按分类筛选
        apps = when (selectedCategory) {
            AppCategory.ALL -> apps
            AppCategory.ROOT -> apps.filter { it.allowSu }
            AppCategory.CUSTOM -> apps.filter { !it.allowSu && it.hasCustomProfile }
            AppCategory.DEFAULT -> apps.filter { !it.allowSu && !it.hasCustomProfile }
        }

        // 按排序方式排序
        apps = when (currentSortType) {
            SortType.NAME_ASC -> apps.sortedBy { it.label.lowercase() }
            SortType.NAME_DESC -> apps.sortedByDescending { it.label.lowercase() }
            SortType.INSTALL_TIME_NEW -> apps.sortedByDescending { it.packageInfo.firstInstallTime }
            SortType.INSTALL_TIME_OLD -> apps.sortedBy { it.packageInfo.firstInstallTime }
            SortType.SIZE_DESC -> apps.sortedByDescending { it.packageInfo.applicationInfo?.let { context.packageManager.getApplicationInfo(it.packageName, 0).sourceDir.length } ?: 0 }
            SortType.SIZE_ASC -> apps.sortedBy { it.packageInfo.applicationInfo?.let { context.packageManager.getApplicationInfo(it.packageName, 0).sourceDir.length } ?: 0 }
            SortType.USAGE_FREQ -> apps
        }

        apps
    }

    // BottomSheet菜单项
    val bottomSheetMenuItems = remember {
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

    Scaffold(
        topBar = {
            SearchAppBar(
                title = { Text(stringResource(R.string.superuser)) },
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
                mainButtonIcon = Icons.Filled.Add,
                mainButtonExpandedIcon = Icons.Filled.Close
            )
        }
    ) { innerPadding ->

        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            // 主要内容区域
            PullToRefreshBox(
                modifier = Modifier.weight(1f),
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
                        start = 16.dp,
                        end = 4.dp,
                        top = 16.dp,
                        bottom = 16.dp
                    ),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
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

                    // 当没有应用显示时显示空状态
                    if (filteredAndSortedApps.isEmpty()) {
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
                                        imageVector = Icons.Filled.Archive,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.6f),
                                        modifier = Modifier
                                            .size(96.dp)
                                            .padding(bottom = 16.dp)
                                    )
                                    Text(
                                        text = if (selectedCategory == AppCategory.ALL) {
                                            stringResource(R.string.no_apps_found)
                                        } else {
                                            stringResource(R.string.no_apps_in_category)
                                        },
                                        textAlign = TextAlign.Center,
                                        style = MaterialTheme.typography.bodyLarge,
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // 右侧分类栏
            CategorySidebar(
                selectedCategory = selectedCategory,
                onCategorySelected = { category ->
                    selectedCategory = category
                    // 切换分类时滚动到顶部
                    scope.launch {
                        listState.animateScrollToItem(0)
                    }
                },
                appCounts = mapOf(
                    AppCategory.ALL to viewModel.appList.size,
                    AppCategory.ROOT to viewModel.appList.count { it.allowSu },
                    AppCategory.CUSTOM to viewModel.appList.count { !it.allowSu && it.hasCustomProfile },
                    AppCategory.DEFAULT to viewModel.appList.count { !it.allowSu && !it.hasCustomProfile }
                ),
                modifier = Modifier.width(86.dp)
            )
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
                        currentSortType = newSortType
                        scope.launch {
                            bottomSheetState.hide()
                            showBottomSheet = false
                        }
                    }
                )
            }
        }
    }
}

@Composable
private fun BottomSheetContent(
    menuItems: List<BottomSheetMenuItem>,
    currentSortType: SortType,
    onSortTypeChanged: (SortType) -> Unit
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

@Composable
private fun CategorySidebar(
    selectedCategory: AppCategory,
    onCategorySelected: (AppCategory) -> Unit,
    appCounts: Map<AppCategory, Int>,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.fillMaxHeight(),
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 2.dp,
        shape = RoundedCornerShape(topStart = 16.dp, bottomStart = 16.dp)
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(horizontal = 4.dp)
        ) {
            items(AppCategory.entries.toTypedArray()) { category ->
                CategoryItem(
                    category = category,
                    isSelected = selectedCategory == category,
                    appCount = appCounts[category] ?: 0,
                    onClick = { onCategorySelected(category) }
                )
            }
        }
    }
}

@Composable
private fun CategoryItem(
    category: AppCategory,
    isSelected: Boolean,
    appCount: Int,
) {
    // 添加交互状态
    val animatedScale by animateFloatAsState(
        targetValue = 1.0f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessHigh
        ),
        label = "categoryScale"
    )

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .scale(animatedScale),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.surfaceBright
            }
        ),
        elevation = getCardElevation()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // 分类图标
            val iconVector = when (category) {
                AppCategory.ALL -> Icons.Filled.Apps
                AppCategory.ROOT -> Icons.Filled.Security
                AppCategory.CUSTOM -> Icons.Filled.Settings
                AppCategory.DEFAULT -> Icons.Filled.Smartphone
            }

            val iconColor = if (isSelected) {
                MaterialTheme.colorScheme.onPrimary
            } else {
                MaterialTheme.colorScheme.onSurface
            }

            Icon(
                imageVector = iconVector,
                contentDescription = stringResource(category.displayNameRes),
                tint = iconColor,
                modifier = Modifier.size(20.dp)
            )

            Spacer(modifier = Modifier.height(2.dp))

            // 分类名称
            Text(
                text = stringResource(category.displayNameRes),
                style = MaterialTheme.typography.labelSmall,
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                color = if (isSelected) {
                    MaterialTheme.colorScheme.onPrimary
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
                textAlign = TextAlign.Center,
                maxLines = 2,
                fontSize = 10.sp
            )

            // 应用数量
            Text(
                text = appCount.toString(),
                style = MaterialTheme.typography.labelSmall,
                color = if (isSelected) {
                    MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.8f)
                } else {
                    MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f)
                },
                modifier = Modifier.padding(top = 1.dp),
                fontSize = 9.sp
            )
        }
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
    // 添加交互状态
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    // 优化的缩放动画
    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.98f else 1.0f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessHigh
        ),
        label = "appItemScale"
    )

    Card(
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerHigh),
        elevation = getCardElevation(),
        modifier = Modifier
            .scale(scale)
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
                    maxLines = 1,
                )

                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                )

                FlowRow(
                    modifier = Modifier.padding(top = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (app.allowSu) {
                        LabelItem(text = stringResource(R.string.label_root))
                    }
                    if (Natives.uidShouldUmount(app.uid)) {
                        LabelItem(text = stringResource(R.string.label_unmount))
                    }
                    if (app.hasCustomProfile) {
                        LabelItem(text = stringResource(R.string.label_custom))
                    }
                }
            }

            
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
    }
}

@Composable
fun LabelText(label: String) {
    Box(
        modifier = Modifier
            .padding(top = 2.dp, end = 2.dp)
            .background(
                Color.Black,
                shape = RoundedCornerShape(4.dp)
            )
            .clip(RoundedCornerShape(4.dp))
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(vertical = 2.dp, horizontal = 6.dp),
            style = TextStyle(
                fontSize = 8.sp,
                color = Color.White,
            )
        )
    }
}