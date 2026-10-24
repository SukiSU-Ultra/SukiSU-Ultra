package com.sukisu.ultra.ui.screen.dynamicmanagers

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.AppIconImage
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.theme.isInDarkTheme
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.DynamicManagerState
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.FloatingActionButton
import top.yukonga.miuix.kmp.basic.FloatingActionButtonDefaults
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.PullToRefresh
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberPullToRefreshState
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
internal fun DynamicManagersMiuix(
    state: DynamicManagerState?,
    currentManager: InstalledApp?,
    installedApps: List<InstalledApp>,
    apps: List<InstalledApp>,
    busy: Boolean,
    error: String?,
    actions: DynamicManagersActions,
) {
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var showAddSearch by rememberSaveable { mutableStateOf(false) }
    val searchFocusRequester = remember { FocusRequester() }
    val enableBlur = LocalEnableBlur.current
    val scrollBehavior = MiuixScrollBehavior()
    val listState: LazyListState = rememberLazyListState()
    val layoutDirection = LocalLayoutDirection.current

    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive) Color.Transparent else colorScheme.surface

    Scaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    color = barColor,
                    title = stringResource(R.string.dynamic_manager_title),
                    navigationIcon = {
                        IconButton(onClick = actions.onBack) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                                tint = colorScheme.onSurface,
                                contentDescription = null,
                            )
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        floatingActionButton = {
            val addManager = stringResource(R.string.dynamic_manager_add)
            FloatingActionButton(
                modifier = Modifier
                    .padding(bottom = 20.dp, end = 20.dp)
                    .alpha(if (busy) 0.5f else 1f)
                    .border(0.05.dp, colorScheme.outline.copy(alpha = 0.5f), CircleShape),
                shadowElevation = 0.dp,
                onClick = {
                    if (!busy) {
                        searchQuery = ""
                        showAddSearch = true
                        actions.onLoadApps()
                    }
                },
                content = {
                    Icon(
                        Icons.Rounded.Add,
                        addManager,
                        modifier = Modifier.size(40.dp),
                        tint = colorScheme.onPrimary,
                    )
                },
            )
        },
        contentWindowInsets = WindowInsets.systemBars
            .add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
    ) { innerPadding ->
        val pullToRefreshState = rememberPullToRefreshState()
        val refreshTexts = listOf(
            stringResource(R.string.refresh_pulling),
            stringResource(R.string.refresh_release),
            stringResource(R.string.refresh_refresh),
            stringResource(R.string.refresh_complete),
        )
        val contentPadding = PaddingValues(
            top = innerPadding.calculateTopPadding() + 6.dp,
            start = innerPadding.calculateStartPadding(layoutDirection),
            end = innerPadding.calculateEndPadding(layoutDirection),
            bottom = FloatingActionButtonDefaults.MinHeight + 20.dp + 12.dp,
        )

        PullToRefresh(
            isRefreshing = busy,
            pullToRefreshState = pullToRefreshState,
            onRefresh = actions.onRefresh,
            refreshTexts = refreshTexts,
            contentPadding = contentPadding,
        ) {
            Box(
                modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier
            ) {
                LazyColumn(
                    state = listState,
                    modifier = Modifier
                        .fillMaxSize()
                        .nestedScroll(scrollBehavior.nestedScrollConnection),
                    contentPadding = contentPadding,
                ) {
                    item(key = "status", contentType = "status") {
                        StatusCard(
                            state = state,
                            error = error,
                            onSetEnabled = actions.onSetEnabled,
                        )
                    }

                    currentManager?.let { app ->
                        item(key = "current", contentType = "manager") {
                            val currentDetail = state?.entries
                                ?.firstOrNull { it.packageName == app.packageName }
                                ?.let { "${it.certSize} bytes · ${it.hash}" }
                            ManagerCard(
                                app = app,
                                packageName = app.packageName,
                                uid = app.uid,
                                detail = currentDetail,
                                current = true,
                                onRemove = null,
                            )
                        }
                    }

                    val entries = state?.entries.orEmpty()
                    if (entries.isNotEmpty()) {
                        item(key = "authorized_header", contentType = "header") {
                            SectionTitle(stringResource(R.string.dynamic_manager_authorized))
                        }
                        items(
                            items = entries.filter { it.packageName != currentManager?.packageName },
                            key = { it.packageName },
                            contentType = { "manager" },
                        ) { entry ->
                            val app = installedApps.firstOrNull { it.packageName == entry.packageName }
                            ManagerCard(
                                app = app,
                                packageName = entry.packageName,
                                uid = entry.uid,
                                detail = "${entry.certSize} bytes · ${entry.hash}",
                                current = false,
                            ) {
                                actions.onRemove(entry.packageName)
                            }
                        }
                    }

                }
            }
        }
    }

    if (showAddSearch) {
        val entries = state?.entries.orEmpty()
        val availableApps = apps.filterNot { app -> entries.any { it.packageName == app.packageName } }
        val query = searchQuery.trim()
        val filteredApps = if (query.isEmpty()) availableApps else availableApps.filter { app ->
            app.uid.toString().contains(query, ignoreCase = true) ||
                    app.packageName.contains(query, ignoreCase = true) ||
                    app.label.contains(query, ignoreCase = true)
        }

        Dialog(
            onDismissRequest = { showAddSearch = false },
            properties = DialogProperties(usePlatformDefaultWidth = false),
        ) {
            LaunchedEffect(Unit) { searchFocusRequester.requestFocus() }
            Card(
                modifier = Modifier.fillMaxSize(),
                insideMargin = PaddingValues(0.dp),
                onClick = null,
            ) {
                Column(modifier = Modifier.fillMaxSize().imePadding()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 8.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        IconButton(onClick = { showAddSearch = false }) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                                tint = colorScheme.onSurface,
                                contentDescription = null,
                            )
                        }
                        TextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            label = stringResource(R.string.search_apps),
                            useLabelAsPlaceholder = true,
                            modifier = Modifier
                                .weight(1f)
                                .focusRequester(searchFocusRequester),
                        )
                    }
                    if (busy && apps.isEmpty()) {
                        top.yukonga.miuix.kmp.basic.LinearProgressIndicator(
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    error?.let {
                        Text(
                            text = it,
                            fontSize = 12.sp,
                            color = colorScheme.error,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        )
                    }
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(start = 12.dp, end = 12.dp, bottom = 16.dp),
                    ) {
                        items(
                            items = filteredApps,
                            key = { "search_app_${it.packageName}" },
                            contentType = { "app" },
                        ) { app ->
                            AppCandidateCard(
                                app = app,
                                onAdd = {
                                    showAddSearch = false
                                    actions.onAdd(app)
                                },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusCard(
    state: DynamicManagerState?,
    error: String?,
    onSetEnabled: (Boolean) -> Unit,
) {
    Card(
        modifier = Modifier
            .padding(horizontal = 12.dp)
            .padding(bottom = 12.dp),
        insideMargin = PaddingValues(0.dp),
        onClick = null,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(end = 4.dp)
                ) {
                    Text(
                        text = stringResource(R.string.dynamic_manager_enabled),
                        fontSize = 17.sp,
                        fontWeight = FontWeight(550),
                        color = colorScheme.onSurface,
                    )
                    Text(
                        text = stringResource(R.string.dynamic_manager_summary),
                        fontSize = 12.sp,
                        fontWeight = FontWeight(550),
                        color = colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.padding(top = 2.dp),
                    )
                }
                Switch(
                    enabled = state != null,
                    checked = state?.enabled ?: false,
                    onCheckedChange = onSetEnabled,
                )
            }

            error?.let {
                Text(
                    text = it,
                    fontSize = 12.sp,
                    color = colorScheme.error,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun ManagerCard(
    app: InstalledApp?,
    packageName: String,
    uid: Int,
    detail: String?,
    current: Boolean,
    onRemove: (() -> Unit)?,
) {
    var expanded by rememberSaveable(packageName) { mutableStateOf(false) }
    val tagBg = colorScheme.tertiaryContainer.copy(alpha = 0.6f)
    val tagTint = colorScheme.onTertiaryContainer.copy(alpha = 0.8f)

    Card(
        modifier = Modifier
            .padding(horizontal = 12.dp)
            .padding(bottom = 12.dp),
        insideMargin = PaddingValues(0.dp),
        onClick = { expanded = !expanded },
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (app != null) {
                    AppIconImage(Modifier.size(48.dp), app.packageInfo, app.label)
                } else {
                    Spacer(Modifier.size(48.dp))
                }
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(start = 12.dp, end = 4.dp)
                ) {
                    Text(
                        text = app?.label ?: packageName,
                        fontSize = 17.sp,
                        fontWeight = FontWeight(550),
                        color = colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = "UID $uid",
                        fontSize = 12.sp,
                        fontWeight = FontWeight(550),
                        color = colorScheme.onSurfaceVariantSummary,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(top = 2.dp),
                    )
                }
                if (current) {
                    Text(
                        text = stringResource(R.string.dynamic_manager_default),
                        fontSize = 12.sp,
                        color = tagTint,
                        fontWeight = FontWeight(750),
                        maxLines = 1,
                        softWrap = false,
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(tagBg)
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                }
            }

            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut(),
            ) {
                Column(modifier = Modifier.padding(top = 8.dp)) {
                    detail?.let {
                        Text(
                            text = it,
                            fontSize = 14.sp,
                            color = colorScheme.onSurfaceVariantSummary,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                    Text(
                        text = packageName,
                        fontSize = 12.sp,
                        fontWeight = FontWeight(550),
                        color = colorScheme.onSurfaceVariantSummary,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }

            if (onRemove != null) {
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 8.dp),
                    thickness = 0.5.dp,
                    color = colorScheme.outline.copy(alpha = 0.5f),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    PillButton(
                        icon = Icons.Rounded.Delete,
                        label = stringResource(R.string.dynamic_manager_remove),
                        onClick = onRemove,
                    )
                }
            }
        }
    }
}

@Composable
private fun AppCandidateCard(
    app: InstalledApp,
    onAdd: () -> Unit,
) {
    val secondaryContainer = colorScheme.secondaryContainer.copy(alpha = 0.8f)
    val actionIconTint = colorScheme.onSurface.copy(alpha = if (isInDarkTheme()) 0.7f else 0.9f)

    Card(
        modifier = Modifier
            .padding(horizontal = 12.dp)
            .padding(bottom = 12.dp),
        insideMargin = PaddingValues(0.dp),
        onClick = null,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            AppIconImage(Modifier.size(48.dp), app.packageInfo, app.label)
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(start = 12.dp, end = 4.dp)
            ) {
                Text(
                    text = app.label,
                    fontSize = 17.sp,
                    fontWeight = FontWeight(550),
                    color = colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = app.packageName,
                    fontSize = 12.sp,
                    fontWeight = FontWeight(550),
                    color = colorScheme.onSurfaceVariantSummary,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            Row(
                modifier = Modifier
                    .heightIn(min = 35.dp)
                    .widthIn(min = 35.dp)
                    .clip(CircleShape)
                    .background(secondaryContainer)
                    .clickable(onClick = onAdd),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center,
            ) {
                Icon(
                    modifier = Modifier.size(24.dp),
                    imageVector = Icons.Rounded.Add,
                    tint = actionIconTint,
                    contentDescription = stringResource(R.string.dynamic_manager_authorize, app.label),
                )
            }
        }
    }
}

@Composable
private fun PillButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    onClick: () -> Unit,
) {
    val secondaryContainer = colorScheme.secondaryContainer.copy(alpha = 0.8f)
    val actionIconTint = colorScheme.onSurface.copy(alpha = if (isInDarkTheme()) 0.7f else 0.9f)

    Row(
        modifier = Modifier
            .heightIn(min = 35.dp)
            .clip(CircleShape)
            .background(secondaryContainer)
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center,
    ) {
        Icon(
            modifier = Modifier.size(22.dp),
            imageVector = icon,
            tint = actionIconTint,
            contentDescription = label,
        )
        Text(
            modifier = Modifier.padding(start = 4.dp, end = 2.dp),
            text = label,
            color = actionIconTint,
            fontWeight = FontWeight.Medium,
            fontSize = 15.sp,
        )
    }
}

@Composable
private fun SectionTitle(title: String) {
    Text(
        text = title,
        fontSize = 13.sp,
        fontWeight = FontWeight(550),
        color = colorScheme.onSurfaceVariantSummary,
        modifier = Modifier.padding(start = 16.dp, top = 8.dp, bottom = 8.dp),
    )
}
