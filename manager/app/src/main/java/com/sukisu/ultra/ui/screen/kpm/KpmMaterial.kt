package com.sukisu.ultra.ui.screen.kpm

import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TonalCard
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.material3.Surface
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.OutlinedButton
import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.edit
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.viewmodel.KpmViewModel
import kotlinx.coroutines.delay
import top.yukonga.miuix.kmp.basic.TextButton

@Composable
fun KpmMaterial(
    viewModel: KpmViewModel,
    actions: KpmActions,
    bottomInnerPadding: Dp = 0.dp
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    val showEmptyState by remember {
        derivedStateOf {
            state.moduleList.isEmpty() && state.searchStatus.searchText.isEmpty() && !state.isRefreshing
        }
    }

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    val kpmInstallMode = stringResource(R.string.kpm_install_mode)
    val kpmInstallModeLoad = stringResource(R.string.kpm_install_mode_load)
    val kpmInstallModeEmbed = stringResource(R.string.kpm_install_mode_embed)
    val cancel = stringResource(R.string.cancel)

    val scrollDistance = remember { mutableFloatStateOf(0f) }
    var fabVisible by remember { mutableStateOf(true) }

    val nestedScrollConnection = remember(listState) {
        object : NestedScrollConnection {
            override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                if (isScrolledToEnd(listState)) return Offset.Zero

                scrollDistance.floatValue += available.y

                if (scrollDistance.floatValue <= -50f && fabVisible) {
                    fabVisible = false
                    scrollDistance.floatValue = 0f
                    return Offset(0f, available.y)
                }

                if (scrollDistance.floatValue >= 50f && !fabVisible) {
                    fabVisible = true
                    scrollDistance.floatValue = 0f
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

    if (state.showInstallModeDialog) {
        AlertDialog(
            onDismissRequest = { actions.onDismissInstallDialog() },
            title = { Text(kpmInstallMode) },
            text = {
                Column {
                    state.tempModuleName?.let {
                        Text(text = stringResource(R.string.kpm_install_mode_description, it))
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { actions.onConfirmInstall("", false) },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Download,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(kpmInstallModeLoad)
                        }

                        Button(
                            onClick = { actions.onConfirmInstall("", true) },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Inventory,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
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
                            onClick = { actions.onDismissInstallDialog() },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            },
            confirmButton = {},
            dismissButton = {}
        )
    }

    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.kpm_title)) },
                actions = {
                    IconButton(
                        onClick = actions.onRefresh
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Refresh,
                            contentDescription = stringResource(R.string.refresh),
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    }
                },
                scrollBehavior = scrollBehavior,
                colors = expressiveTopAppBarColors()
            )
        },
        floatingActionButton = {
            AnimatedVisibility(visible = fabVisible) {
                FloatingActionButton(
                    modifier = Modifier
                        .offset { IntOffset(0, offsetHeight.roundToPx()) }
                        .padding(bottom = bottomInnerPadding + 20.dp, end = 20.dp),
                    onClick = actions.onRequestInstall,
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.package_import),
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(40.dp)
                    )
                }
            }
        },
        contentWindowInsets = WindowInsets.systemBars.only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        val layoutDirection = LocalLayoutDirection.current

        if (showEmptyState) {
            EmptyStateViewMaterial(
                innerPadding = innerPadding,
                bottomInnerPadding = bottomInnerPadding,
                layoutDirection = layoutDirection
            )
        } else {
            KpmListMaterial(
                state = state,
                actions = actions,
                scrollBehavior = scrollBehavior,
                nestedScrollConnection = nestedScrollConnection,
                innerPadding = innerPadding,
                bottomInnerPadding = bottomInnerPadding,
                layoutDirection = layoutDirection
            )
        }
    }
}

@Composable
private fun KpmListMaterial(
    state: KpmUiState,
    actions: KpmActions,
    scrollBehavior: TopAppBarScrollBehavior,
    nestedScrollConnection: NestedScrollConnection,
    innerPadding: PaddingValues,
    bottomInnerPadding: Dp,
    layoutDirection: LayoutDirection
) {
    val context = LocalContext.current
    val sharedPreferences = context.getSharedPreferences("app_preferences", Context.MODE_PRIVATE)
    var isNoticeClosed by remember { mutableStateOf(sharedPreferences.getBoolean("is_notice_closed", false)) }

    var isRefreshing by rememberSaveable { mutableStateOf(false) }

    LaunchedEffect(isRefreshing) {
        if (isRefreshing) {
            delay(350)
            actions.onRefresh()
            isRefreshing = false
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)
    ) {
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = { if (!isRefreshing) isRefreshing = true },
            modifier = Modifier.fillMaxSize()
        ) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxHeight()
                    .nestedScroll(scrollBehavior.nestedScrollConnection)
                    .nestedScroll(nestedScrollConnection),
                contentPadding = PaddingValues(
                    start = innerPadding.calculateStartPadding(layoutDirection),
                    end = innerPadding.calculateEndPadding(layoutDirection),
                ),
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
                                    tint = MaterialTheme.colorScheme.onSurface
                                )

                                Text(
                                    text = stringResource(R.string.kernel_module_notice),
                                    modifier = Modifier.weight(1f),
                                    color = MaterialTheme.colorScheme.onSurface
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
                                        tint = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            }
                        }
                    }
                }

                items(state.moduleList) { module ->
                    KpmModuleItemMaterial(
                        module = module,
                        state = state,
                        actions = actions,
                        onUninstall = { actions.onRequestUninstall(module.id) }
                    )
                }
                item {
                    Spacer(Modifier.height(bottomInnerPadding))
                }
            }
        }
    }
}

@Composable
private fun KpmModuleItemMaterial(
    module: KpmViewModel.ModuleInfo,
    state: KpmUiState,
    actions: KpmActions,
    onUninstall: () -> Unit
) {
    val showInputDialog = state.inputDialogState.visible && state.inputDialogState.moduleId == module.id

    if (showInputDialog) {
        AlertDialog(
            onDismissRequest = {
                actions.onHideInputDialog()
            },
            title = { Text(stringResource(R.string.kpm_control)) },
            text = {
                Column {
                    OutlinedTextField(
                        value = state.inputDialogState.args,
                        onValueChange = { actions.onInputArgsChange(it) },
                        label = { Text(stringResource(R.string.kpm_args)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    if (state.inputDialogState.args.isEmpty() && module.args.isNotEmpty()) {
                        Text(
                            text = module.args,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = MaterialTheme.typography.bodySmall.fontSize,
                            modifier = Modifier.padding(start = 16.dp, top = 4.dp)
                        )
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        TextButton(
                            onClick = { actions.onHideInputDialog() },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(stringResource(R.string.cancel))
                        }
                        Spacer(modifier = Modifier.width(20.dp))
                        Button(
                            onClick = { actions.onExecuteControl() },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(stringResource(R.string.confirm))
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {}
        )
    }

    TonalCard(
        modifier = Modifier
            .padding(horizontal = 16.dp)
            .padding(bottom = 12.dp),
    ) {
        Column(
            modifier = Modifier.padding(18.dp, 16.dp, 16.dp, 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = module.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = "${module.version}, ${module.author}",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (module.description.isNotBlank()) {
                Text(
                    text = module.description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    overflow = TextOverflow.Ellipsis,
                    maxLines = 4
                )
            }

            if (module.args.isNotEmpty()) {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = MaterialTheme.colorScheme.surfaceContainerLowest,
                ) {
                    Text(
                        text = "${stringResource(R.string.kpm_args)}: ${module.args}",
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                AnimatedVisibility(
                    visible = module.hasAction,
                    enter = fadeIn(),
                    exit = fadeOut()
                ) {
                    OutlinedButton(onClick = { actions.onShowInputDialog(module.id) }) {
                        Icon(
                            imageVector = Icons.Filled.Settings,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(stringResource(R.string.kpm_control))
                    }
                }

                Spacer(Modifier.weight(1f))

                FilledTonalButton(onClick = onUninstall) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(stringResource(R.string.kpm_uninstall))
                }
            }
        }
    }
}

@Composable
private fun EmptyStateViewMaterial(
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
                tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.6f),
                modifier = Modifier
                    .size(96.dp)
                    .padding(bottom = 16.dp)
            )
            Text(
                stringResource(R.string.kpm_empty),
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}
