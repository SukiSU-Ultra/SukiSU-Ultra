package com.sukisu.ultra.ui.screen

import android.content.Context
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.*
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.CardConfig.cardAlpha
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.theme.getCardElevation
import com.sukisu.ultra.ui.util.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.*
import java.time.format.DateTimeFormatter
import android.os.Process.myUid
import androidx.core.content.edit

private val SPACING_SMALL = 4.dp
private val SPACING_MEDIUM = 8.dp
private val SPACING_LARGE = 16.dp

private const val PAGE_SIZE = 10000
private const val MAX_TOTAL_LOGS = 100000

private const val LOGS_PATCH = "/data/adb/ksu/log/sulog.log"

data class LogEntry(
    val timestamp: String,
    val type: LogType,
    val uid: String,
    val comm: String,
    val details: String,
    val pid: String,
    val rawLine: String
)

data class LogPageInfo(
    val currentPage: Int = 0,
    val totalPages: Int = 0,
    val totalLogs: Int = 0,
    val hasMore: Boolean = false
)

enum class LogType(val displayName: String, val color: Color) {
    SU_GRANT("SU_GRANT", Color(0xFF4CAF50)),
    SU_EXEC("SU_EXEC", Color(0xFF2196F3)),
    PERM_CHECK("PERM_CHECK", Color(0xFFFF9800)),
    SYSCALL("SYSCALL", Color(0xFF00BCD4)),
    MANAGER_OP("MANAGER_OP", Color(0xFF9C27B0)),
    UNKNOWN("UNKNOWN", Color(0xFF757575))
}

enum class LogExclType(val displayName: String, val color: Color) {
    CURRENT_APP("Current app", Color(0xFF9E9E9E)),
    PRCTL_STAR("prctl_*", Color(0xFF00BCD4)),
    PRCTL_UNKNOWN("prctl_unknown", Color(0xFF00BCD4)),
    SETUID("setuid", Color(0xFF00BCD4))
}

private val utcFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
private val localFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")

private fun saveExcludedSubTypes(context: Context, types: Set<LogExclType>) {
    val prefs = context.getSharedPreferences("sulog", Context.MODE_PRIVATE)
    val nameSet = types.map { it.name }.toSet()
    prefs.edit { putStringSet("excluded_subtypes", nameSet) }
}

private fun loadExcludedSubTypes(context: Context): Set<LogExclType> {
    val prefs = context.getSharedPreferences("sulog", Context.MODE_PRIVATE)
    val nameSet = prefs.getStringSet("excluded_subtypes", emptySet()) ?: emptySet()
    return nameSet.mapNotNull { name ->
        LogExclType.entries.firstOrNull { it.name == name }
    }.toSet()
}

@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun LogViewerScreen(navigator: DestinationsNavigator) {
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val snackBarHost = LocalSnackbarHost.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var logEntries by remember { mutableStateOf<List<LogEntry>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var filterType by rememberSaveable { mutableStateOf<LogType?>(null) }
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var showSearchBar by rememberSaveable { mutableStateOf(false) }
    var pageInfo by remember { mutableStateOf(LogPageInfo()) }
    var lastLogFileHash by remember { mutableStateOf("") }
    val currentUid = remember { myUid().toString() }

    val initialExcluded = remember {
        loadExcludedSubTypes(context)
    }

    var excludedSubTypes by rememberSaveable { mutableStateOf(initialExcluded) }

    LaunchedEffect(excludedSubTypes) {
        saveExcludedSubTypes(context, excludedSubTypes)
    }

    val filteredEntries = remember(
        logEntries, filterType, searchQuery, excludedSubTypes
    ) {
        logEntries.filter { entry ->
            val matchesSearch = searchQuery.isEmpty() ||
                    entry.comm.contains(searchQuery, ignoreCase = true) ||
                    entry.details.contains(searchQuery, ignoreCase = true) ||
                    entry.uid.contains(searchQuery, ignoreCase = true)

            // 排除本应用
            if (LogExclType.CURRENT_APP in excludedSubTypes && entry.uid == currentUid) return@filter false

            // 排除 SYSCALL 子类型
            if (entry.type == LogType.SYSCALL) {
                val detail = entry.details
                if (LogExclType.PRCTL_STAR in excludedSubTypes && detail.startsWith("Syscall: prctl") && !detail.startsWith("Syscall: prctl_unknown")) return@filter false
                if (LogExclType.PRCTL_UNKNOWN in excludedSubTypes && detail.startsWith("Syscall: prctl_unknown")) return@filter false
                if (LogExclType.SETUID in excludedSubTypes && detail.startsWith("Syscall: setuid")) return@filter false
            }

            // 普通类型筛选
            val matchesFilter = filterType == null || entry.type == filterType
            matchesFilter && matchesSearch
        }
    }

    val loadingDialog = rememberLoadingDialog()
    val confirmDialog = rememberConfirmDialog()

    val loadPage: (Int, Boolean) -> Unit = { page, forceRefresh ->
        scope.launch {
            if (isLoading) return@launch

            isLoading = true
            try {
                loadLogsWithPagination(
                    page,
                    forceRefresh,
                    lastLogFileHash
                ) { entries, newPageInfo, newHash ->
                    logEntries = if (page == 0 || forceRefresh) {
                        entries
                    } else {
                        logEntries + entries
                    }
                    pageInfo = newPageInfo
                    lastLogFileHash = newHash
                }
            } finally {
                isLoading = false
            }
        }
    }

    val onManualRefresh: () -> Unit = {
        loadPage(0, true)
    }

    val loadNextPage: () -> Unit = {
        if (pageInfo.hasMore && !isLoading) {
            loadPage(pageInfo.currentPage + 1, false)
        }
    }

    LaunchedEffect(Unit) {
        while (true) {
            delay(5_000)
            if (!isLoading) {
                scope.launch {
                    val hasNewLogs = checkForNewLogs(lastLogFileHash)
                    if (hasNewLogs) {
                        loadPage(0, true)
                    }
                }
            }
        }
    }

    LaunchedEffect(Unit) {
        loadPage(0, true)
    }

    Scaffold(
        topBar = {
            LogViewerTopBar(
                scrollBehavior = scrollBehavior,
                onBackClick = { navigator.navigateUp() },
                showSearchBar = showSearchBar,
                searchQuery = searchQuery,
                onSearchQueryChange = { searchQuery = it },
                onSearchToggle = { showSearchBar = !showSearchBar },
                onRefresh = onManualRefresh,
                onClearLogs = {
                    scope.launch {
                        val result = confirmDialog.awaitConfirm(
                            title = context.getString(R.string.log_viewer_clear_logs),
                            content = context.getString(R.string.log_viewer_clear_logs_confirm)
                        )
                        if (result == ConfirmResult.Confirmed) {
                            loadingDialog.withLoading {
                                clearLogs()
                                loadPage(0, true)
                            }
                            snackBarHost.showSnackbar(context.getString(R.string.log_viewer_logs_cleared))
                        }
                    }
                }
            )
        },
        snackbarHost = { SnackbarHost(snackBarHost) },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .padding(paddingValues)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
        ) {
            LogControlPanel(
                filterType = filterType,
                onFilterTypeSelected = { filterType = it },
                logCount = filteredEntries.size,
                totalCount = logEntries.size,
                pageInfo = pageInfo,
                excludedSubTypes = excludedSubTypes,
                onExcludeToggle = { excl ->
                    excludedSubTypes = if (excl in excludedSubTypes)
                        excludedSubTypes - excl
                    else
                        excludedSubTypes + excl
                }
            )

            // 日志列表
            if (isLoading && logEntries.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            } else if (filteredEntries.isEmpty()) {
                EmptyLogState(
                    hasLogs = logEntries.isNotEmpty(),
                    onRefresh = onManualRefresh
                )
            } else {
                LogList(
                    entries = filteredEntries,
                    pageInfo = pageInfo,
                    isLoading = isLoading,
                    onLoadMore = loadNextPage,
                    modifier = Modifier.fillMaxSize()
                )
            }
        }
    }
}

@Composable
private fun LogControlPanel(
    filterType: LogType?,
    onFilterTypeSelected: (LogType?) -> Unit,
    logCount: Int,
    totalCount: Int,
    pageInfo: LogPageInfo,
    excludedSubTypes: Set<LogExclType>,
    onExcludeToggle: (LogExclType) -> Unit
) {
    var isExpanded by rememberSaveable { mutableStateOf(true) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = SPACING_LARGE, vertical = SPACING_MEDIUM),
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerLow),
        elevation = getCardElevation()
    ) {
        Column {
            // 标题栏（点击展开/收起）
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { isExpanded = !isExpanded }
                    .padding(SPACING_LARGE),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = stringResource(R.string.settings),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Icon(
                    imageVector = if (isExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
            }

            AnimatedVisibility(
                visible = isExpanded,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                Column(
                    modifier = Modifier.padding(horizontal = SPACING_LARGE)
                ) {
                    // 类型过滤
                    Text(
                        text = stringResource(R.string.log_viewer_filter_type),
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(SPACING_MEDIUM))
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(SPACING_MEDIUM)) {
                        item {
                            FilterChip(
                                onClick = { onFilterTypeSelected(null) },
                                label = { Text(stringResource(R.string.log_viewer_all_types)) },
                                selected = filterType == null
                            )
                        }
                        items(LogType.entries.toTypedArray()) { type ->
                            FilterChip(
                                onClick = { onFilterTypeSelected(if (filterType == type) null else type) },
                                label = { Text(type.displayName) },
                                selected = filterType == type,
                                leadingIcon = {
                                    Box(
                                        modifier = Modifier
                                            .size(8.dp)
                                            .background(type.color, RoundedCornerShape(4.dp))
                                    )
                                }
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(SPACING_MEDIUM))

                    // 排除子类型
                    Text(
                        text = stringResource(R.string.log_viewer_exclude_subtypes),
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(SPACING_MEDIUM))
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(SPACING_MEDIUM)) {
                        items(LogExclType.entries.toTypedArray()) { excl ->
                            val label = if (excl == LogExclType.CURRENT_APP)
                                stringResource(R.string.log_viewer_exclude_current_app)
                            else excl.displayName

                            FilterChip(
                                onClick = { onExcludeToggle(excl) },
                                label = { Text(label) },
                                selected = excl in excludedSubTypes,
                                leadingIcon = {
                                    Box(
                                        modifier = Modifier
                                            .size(8.dp)
                                            .background(excl.color, RoundedCornerShape(4.dp))
                                    )
                                }
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(SPACING_MEDIUM))

                    // 统计信息
                    Column(verticalArrangement = Arrangement.spacedBy(SPACING_SMALL)) {
                        Text(
                            text = stringResource(R.string.log_viewer_showing_entries, logCount, totalCount),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (pageInfo.totalPages > 0) {
                            Text(
                                text = stringResource(
                                    R.string.log_viewer_page_info,
                                    pageInfo.currentPage + 1,
                                    pageInfo.totalPages,
                                    pageInfo.totalLogs
                                ),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        if (pageInfo.totalLogs >= MAX_TOTAL_LOGS) {
                            Text(
                                text = stringResource(R.string.log_viewer_too_many_logs, MAX_TOTAL_LOGS),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(SPACING_LARGE))
                }
            }
        }
    }
}

@Composable
private fun LogList(
    entries: List<LogEntry>,
    pageInfo: LogPageInfo,
    isLoading: Boolean,
    onLoadMore: () -> Unit,
    modifier: Modifier = Modifier
) {
    val listState = rememberLazyListState()

    LazyColumn(
        state = listState,
        modifier = modifier,
        contentPadding = PaddingValues(horizontal = SPACING_LARGE, vertical = SPACING_MEDIUM),
        verticalArrangement = Arrangement.spacedBy(SPACING_SMALL)
    ) {
        items(entries) { entry ->
            LogEntryCard(entry = entry)
        }

        // 加载更多按钮或加载指示器
        if (pageInfo.hasMore) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(SPACING_LARGE),
                    contentAlignment = Alignment.Center
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp)
                        )
                    } else {
                        Button(
                            onClick = onLoadMore,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(
                                imageVector = Icons.Filled.ExpandMore,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(SPACING_MEDIUM))
                            Text(stringResource(R.string.log_viewer_load_more))
                        }
                    }
                }
            }
        } else if (entries.isNotEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(SPACING_LARGE),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = stringResource(R.string.log_viewer_all_logs_loaded),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun LogEntryCard(entry: LogEntry) {
    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded },
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerLow),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(
            modifier = Modifier.padding(SPACING_MEDIUM)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(SPACING_MEDIUM)
                ) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .background(entry.type.color, RoundedCornerShape(6.dp))
                    )
                    Text(
                        text = entry.type.displayName,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
                Text(
                    text = entry.timestamp,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(SPACING_SMALL))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "UID: ${entry.uid}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "PID: ${entry.pid}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Text(
                text = entry.comm,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                maxLines = if (expanded) Int.MAX_VALUE else 1,
                overflow = TextOverflow.Ellipsis
            )

            if (entry.details.isNotEmpty()) {
                Spacer(modifier = Modifier.height(SPACING_SMALL))
                Text(
                    text = entry.details,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = if (expanded) Int.MAX_VALUE else 2,
                    overflow = TextOverflow.Ellipsis
                )
            }

            AnimatedVisibility(
                visible = expanded,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column {
                    Spacer(modifier = Modifier.height(SPACING_MEDIUM))
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Spacer(modifier = Modifier.height(SPACING_MEDIUM))
                    Text(
                        text = stringResource(R.string.log_viewer_raw_log),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(SPACING_SMALL))
                    Text(
                        text = entry.rawLine,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun EmptyLogState(
    hasLogs: Boolean,
    onRefresh: () -> Unit
) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(SPACING_LARGE)
        ) {
            Icon(
                imageVector = if (hasLogs) Icons.Filled.FilterList else Icons.Filled.Description,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = stringResource(
                    if (hasLogs) R.string.log_viewer_no_matching_logs
                    else R.string.log_viewer_no_logs
                ),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Button(onClick = onRefresh) {
                Icon(
                    imageVector = Icons.Filled.Refresh,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(SPACING_MEDIUM))
                Text(stringResource(R.string.log_viewer_refresh))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LogViewerTopBar(
    scrollBehavior: TopAppBarScrollBehavior? = null,
    onBackClick: () -> Unit,
    showSearchBar: Boolean,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    onSearchToggle: () -> Unit,
    onRefresh: () -> Unit,
    onClearLogs: () -> Unit
) {
    val colorScheme = MaterialTheme.colorScheme
    val cardColor = if (CardConfig.isCustomBackgroundEnabled) {
        colorScheme.surfaceContainerLow
    } else {
        colorScheme.background
    }

    Column {
        TopAppBar(
            title = {
                Text(
                    text = stringResource(R.string.log_viewer_title),
                    style = MaterialTheme.typography.titleLarge
                )
            },
            navigationIcon = {
                IconButton(onClick = onBackClick) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = stringResource(R.string.log_viewer_back)
                    )
                }
            },
            actions = {
                IconButton(onClick = onSearchToggle) {
                    Icon(
                        imageVector = if (showSearchBar) Icons.Filled.SearchOff else Icons.Filled.Search,
                        contentDescription = stringResource(R.string.log_viewer_search)
                    )
                }
                IconButton(onClick = onRefresh) {
                    Icon(
                        imageVector = Icons.Filled.Refresh,
                        contentDescription = stringResource(R.string.log_viewer_refresh)
                    )
                }
                IconButton(onClick = onClearLogs) {
                    Icon(
                        imageVector = Icons.Filled.DeleteSweep,
                        contentDescription = stringResource(R.string.log_viewer_clear_logs)
                    )
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(
                containerColor = cardColor.copy(alpha = cardAlpha),
                scrolledContainerColor = cardColor.copy(alpha = cardAlpha)
            ),
            windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
            scrollBehavior = scrollBehavior
        )

        AnimatedVisibility(
            visible = showSearchBar,
            enter = fadeIn() + expandVertically(),
            exit = fadeOut() + shrinkVertically()
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = onSearchQueryChange,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = SPACING_LARGE, vertical = SPACING_MEDIUM),
                placeholder = { Text(stringResource(R.string.log_viewer_search_placeholder)) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.Search,
                        contentDescription = null
                    )
                },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { onSearchQueryChange("") }) {
                            Icon(
                                imageVector = Icons.Filled.Clear,
                                contentDescription = stringResource(R.string.log_viewer_clear_search)
                            )
                        }
                    }
                },
                singleLine = true
            )
        }
    }
}

private suspend fun checkForNewLogs(
    lastHash: String
): Boolean {
    return withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()
            val logPath = "/data/adb/ksu/log/sulog.log"

            val result = runCmd(shell, "stat -c '%Y %s' $logPath 2>/dev/null || echo '0 0'")
            val currentHash = result.trim()

            currentHash != lastHash && currentHash != "0 0"
        } catch (_: Exception) {
            false
        }
    }
}

private suspend fun loadLogsWithPagination(
    page: Int,
    forceRefresh: Boolean,
    lastHash: String,
    onLoaded: (List<LogEntry>, LogPageInfo, String) -> Unit
) {
    withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()

            // 获取文件信息
            val statResult = runCmd(shell, "stat -c '%Y %s' $LOGS_PATCH 2>/dev/null || echo '0 0'")
            val currentHash = statResult.trim()

            if (!forceRefresh && currentHash == lastHash && currentHash != "0 0") {
                withContext(Dispatchers.Main) {
                    onLoaded(emptyList(), LogPageInfo(), currentHash)
                }
                return@withContext
            }

            // 获取总行数
            val totalLinesResult = runCmd(shell, "wc -l < $LOGS_PATCH 2>/dev/null || echo '0'")
            val totalLines = totalLinesResult.trim().toIntOrNull() ?: 0

            if (totalLines == 0) {
                withContext(Dispatchers.Main) {
                    onLoaded(emptyList(), LogPageInfo(), currentHash)
                }
                return@withContext
            }

            // 限制最大日志数量
            val effectiveTotal = minOf(totalLines, MAX_TOTAL_LOGS)
            val totalPages = (effectiveTotal + PAGE_SIZE - 1) / PAGE_SIZE

            // 计算要读取的行数范围
            val startLine = if (page == 0) {
                maxOf(1, totalLines - effectiveTotal + 1)
            } else {
                val skipLines = page * PAGE_SIZE
                maxOf(1, totalLines - effectiveTotal + 1 + skipLines)
            }

            val endLine = minOf(startLine + PAGE_SIZE - 1, totalLines)

            if (startLine > totalLines) {
                withContext(Dispatchers.Main) {
                    onLoaded(emptyList(), LogPageInfo(page, totalPages, effectiveTotal, false), currentHash)
                }
                return@withContext
            }

            val result = runCmd(shell, "sed -n '${startLine},${endLine}p' $LOGS_PATCH 2>/dev/null || echo ''")
            val entries = parseLogEntries(result)

            val hasMore = endLine < totalLines
            val pageInfo = LogPageInfo(page, totalPages, effectiveTotal, hasMore)

            withContext(Dispatchers.Main) {
                onLoaded(entries, pageInfo, currentHash)
            }
        } catch (_: Exception) {
            withContext(Dispatchers.Main) {
                onLoaded(emptyList(), LogPageInfo(), lastHash)
            }
        }
    }
}

private suspend fun clearLogs() {
    withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()
            runCmd(shell, "echo '' > $LOGS_PATCH")
        } catch (_: Exception) {
        }
    }
}

private fun parseLogEntries(logContent: String): List<LogEntry> {
    if (logContent.isBlank()) return emptyList()

    val entries = logContent.lines()
        .filter { it.isNotBlank() && it.startsWith("[") }
        .mapNotNull { line ->
            try {
                parseLogLine(line)
            } catch (_: Exception) {
                null
            }
        }

    return entries.reversed()
}
private fun utcToLocal(utc: String): String {
    return try {
        val instant = LocalDateTime.parse(utc, utcFormatter).atOffset(ZoneOffset.UTC).toInstant()
        val local = instant.atZone(ZoneId.systemDefault())
        local.format(localFormatter)
    } catch (_: Exception) {
        utc
    }
}

private fun parseLogLine(line: String): LogEntry? {
    // 解析格式: [timestamp] TYPE: UID=xxx COMM=xxx ...
    val timestampRegex = """\[(.*?)]""".toRegex()
    val timestampMatch = timestampRegex.find(line) ?: return null
    val timestamp = utcToLocal(timestampMatch.groupValues[1])

    val afterTimestamp = line.substring(timestampMatch.range.last + 1).trim()
    val parts = afterTimestamp.split(":")
    if (parts.size < 2) return null

    val typeStr = parts[0].trim()
    val type = when (typeStr) {
        "SU_GRANT" -> LogType.SU_GRANT
        "SU_EXEC" -> LogType.SU_EXEC
        "PERM_CHECK" -> LogType.PERM_CHECK
        "SYSCALL" -> LogType.SYSCALL
        "MANAGER_OP" -> LogType.MANAGER_OP
        else -> LogType.UNKNOWN
    }

    val details = parts[1].trim()
    val uid: String = extractValue(details, "UID") ?: ""
    val comm: String = extractValue(details, "COMM") ?: ""
    val pid: String = extractValue(details, "PID") ?: ""

    // 构建详细信息字符串
    val detailsStr = when (type) {
        LogType.SU_GRANT -> {
            val method: String = extractValue(details, "METHOD") ?: ""
            "Method: $method"
        }
        LogType.SU_EXEC -> {
            val target: String = extractValue(details, "TARGET") ?: ""
            val result: String = extractValue(details, "RESULT") ?: ""
            "Target: $target, Result: $result"
        }
        LogType.PERM_CHECK -> {
            val result: String = extractValue(details, "RESULT") ?: ""
            "Result: $result"
        }
        LogType.SYSCALL -> {
            val syscall = extractValue(details, "SYSCALL") ?: ""
            val args = extractValue(details, "ARGS") ?: ""
            "Syscall: $syscall, Args: $args"
        }
        LogType.MANAGER_OP -> {
            val op: String = extractValue(details, "OP") ?: ""
            val managerUid: String = extractValue(details, "MANAGER_UID") ?: ""
            val targetUid: String = extractValue(details, "TARGET_UID") ?: ""
            "Operation: $op, Manager UID: $managerUid, Target UID: $targetUid"
        }
        else -> details
    }

    return LogEntry(
        timestamp = timestamp,
        type = type,
        uid = uid,
        comm = comm,
        details = detailsStr,
        pid = pid,
        rawLine = line
    )
}

private fun extractValue(text: String, key: String): String? {
    val regex = """$key=(\S+)""".toRegex()
    return regex.find(text)?.groupValues?.get(1)
}