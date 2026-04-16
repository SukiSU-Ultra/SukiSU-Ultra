package com.sukisu.ultra.ui.screen.kpm

import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.border
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.layout.SubcomposeLayout
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
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import com.sukisu.ultra.ui.viewmodel.KpmViewModel
import kotlinx.coroutines.delay
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun KpmMiuix(
    viewModel: KpmViewModel,
    actions: KpmActions,
    bottomInnerPadding: Dp = 0.dp
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    val enableBlur = LocalEnableBlur.current

    val showEmptyState by remember {
        derivedStateOf {
            uiState.moduleList.isEmpty() && !uiState.isRefreshing
        }
    }

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

    val kpmInstallMode = stringResource(R.string.kpm_install_mode)
    val kpmInstallModeLoad = stringResource(R.string.kpm_install_mode_load)
    val kpmInstallModeEmbed = stringResource(R.string.kpm_install_mode_embed)
    val cancel = stringResource(R.string.cancel)

    if (uiState.showInstallModeDialog) {
        OverlayDialog(
            show = true,
            title = kpmInstallMode,
            onDismissRequest = {
                actions.onDismissInstallDialog()
            },
            content = {
                Column {
                    uiState.tempModuleName?.let {
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
                            onClick = { actions.onConfirmInstall("", false) },
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
                            onClick = { actions.onConfirmInstall("", true) },
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
                            onClick = { actions.onDismissInstallDialog() },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        )
    }

    val scrollBehavior = MiuixScrollBehavior()
    val backdrop = rememberBlurBackdrop(enableBlur)

    Scaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    color = if (enableBlur) Color.Transparent else colorScheme.surface,
                    title = stringResource(R.string.kpm_title),
                    actions = {
                        IconButton(
                            onClick = actions.onRefresh
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
                        .offset { IntOffset(0, offsetHeight.roundToPx()) }
                        .padding(bottom = bottomInnerPadding + 20.dp, end = 20.dp)
                        .border(0.05.dp, colorScheme.outline.copy(alpha = 0.5f), CircleShape),
                    shadowElevation = 0.dp,
                    onClick = actions.onRequestInstall,
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
            KpmList(
                state = uiState,
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
private fun KpmList(
    state: KpmUiState,
    actions: KpmActions,
    scrollBehavior: ScrollBehavior,
    nestedScrollConnection: NestedScrollConnection,
    innerPadding: PaddingValues,
    bottomInnerPadding: Dp,
    layoutDirection: LayoutDirection
) {
    val context = LocalContext.current
    val sharedPreferences = context.getSharedPreferences("app_preferences", Context.MODE_PRIVATE)
    var isNoticeClosed by remember { mutableStateOf(sharedPreferences.getBoolean("is_notice_closed", false)) }

    val refreshPulling = stringResource(R.string.refresh_pulling)
    val refreshRelease = stringResource(R.string.refresh_release)
    val refreshRefresh = stringResource(R.string.refresh_refresh)
    val refreshComplete = stringResource(R.string.refresh_complete)

    var isRefreshing by rememberSaveable { mutableStateOf(false) }
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
            actions.onRefresh()
            isRefreshing = false
        }
    }

    PullToRefresh(
        isRefreshing = isRefreshing,
        onRefresh = { if (!isRefreshing) isRefreshing = true },
        refreshTexts = refreshTexts,
        contentPadding = PaddingValues(
            top = innerPadding.calculateTopPadding() + 6.dp,
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
                .nestedScroll(nestedScrollConnection),
            contentPadding = PaddingValues(
                top = innerPadding.calculateTopPadding() + 6.dp,
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

            items(state.moduleList) { module ->
                KpmModuleItem(
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

@Composable
private fun KpmModuleItem(
    module: KpmViewModel.ModuleInfo,
    state: KpmUiState,
    actions: KpmActions,
    onUninstall: () -> Unit
) {
    val showInputDialog = state.inputDialogState.visible && state.inputDialogState.moduleId == module.id

    if (showInputDialog) {
        OverlayDialog(
            show = true,
            title = stringResource(R.string.kpm_control),
            onDismissRequest = {
                actions.onHideInputDialog()
            },
            content = {
                Column {
                    TextField(
                        value = state.inputDialogState.args,
                        onValueChange = { actions.onInputArgsChange(it) },
                        label = stringResource(R.string.kpm_args),
                        modifier = Modifier.fillMaxWidth(),
                        useLabelAsPlaceholder = state.inputDialogState.args.isEmpty()
                    )
                    if (state.inputDialogState.args.isEmpty() && module.args.isNotEmpty()) {
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
                            onClick = { actions.onHideInputDialog() },
                            modifier = Modifier.weight(1f)
                        )
                        Spacer(modifier = Modifier.width(20.dp))
                        TextButton(
                            text = stringResource(R.string.confirm),
                            onClick = { actions.onExecuteControl() },
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
                    onClick = { actions.onShowInputDialog(module.id) },
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
