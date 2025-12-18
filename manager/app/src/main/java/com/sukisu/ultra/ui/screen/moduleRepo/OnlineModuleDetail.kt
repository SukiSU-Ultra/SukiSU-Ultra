package com.sukisu.ultra.ui.screen.moduleRepo

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.OpenInBrowser
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.navigation.EmptyDestinationsNavigator
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.ConfirmResult
import com.sukisu.ultra.ui.component.GithubMarkdown
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.util.LocalSnackbarHost
import com.sukisu.ultra.ui.util.module.ReleaseAssetInfo
import com.sukisu.ultra.ui.util.module.ReleaseInfo
import com.sukisu.ultra.ui.viewmodel.ModuleRepoViewModel
import com.sukisu.ultra.ui.viewmodel.formatFileSize
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * @author AlexLiuDev233
 * @date 2025/12/7
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
@Destination<RootGraph>
@Composable
fun OnlineModuleDetailScreen(navigator: DestinationsNavigator, module: ModuleRepoViewModel.RepoModule) {
    val snackBarHost = LocalSnackbarHost.current
    val topAppBarState = rememberTopAppBarState()
    val coroutineScope = rememberCoroutineScope()
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(topAppBarState)

    val tabTitles = listOf(stringResource(R.string.readme), stringResource(R.string.release), stringResource(R.string.info))
    val uriHandler = LocalUriHandler.current
    val pagerState = rememberPagerState(pageCount = { tabTitles.size })

    LaunchedEffect(Unit) {
        scrollBehavior.state.heightOffset =
            scrollBehavior.state.heightOffsetLimit
    }

    Scaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(module.moduleName) },
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(
                        onClick = { navigator.popBackStack() },
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(id = R.string.back),
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = {
                            uriHandler.openUri("https://modules.kernelsu.org/module/${module.moduleId}")
                        }
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.OpenInBrowser,
                            contentDescription = stringResource(R.string.open_module_home_page),
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors().copy(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer,
                    scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer
                )
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        ),
        snackbarHost = { SnackbarHost(hostState = snackBarHost) }
    ) { innerPadding ->
        Column(modifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)
            .nestedScroll(scrollBehavior.nestedScrollConnection)) {
            PrimaryTabRow(
                selectedTabIndex = pagerState.currentPage,
                containerColor = MaterialTheme.colorScheme.surfaceContainer,
                modifier = Modifier.fillMaxWidth()
            ) {
                tabTitles.forEachIndexed { index, title ->
                    Tab(
                        selected = pagerState.currentPage == index,
                        onClick = {
                            coroutineScope.launch {
                                pagerState.animateScrollToPage(index)
                            }
                        },
                        unselectedContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        text = { Text(title) }
                    )
                }
            }

            HorizontalPager(
                state = pagerState,
                modifier = Modifier.fillMaxSize()
            ) { page ->
                when (page) {
                    0 -> ReadmeTab(module, scrollBehavior.nestedScrollConnection)
                    1 -> ReleasesTab(module, scrollBehavior.nestedScrollConnection, coroutineScope, navigator)
                    2 -> InfoTab(module, scrollBehavior.nestedScrollConnection)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun InfoTab(module: ModuleRepoViewModel.RepoModule, nestedScrollConnection: NestedScrollConnection) {
    val uriHandler = LocalUriHandler.current
    LazyColumn(modifier = Modifier
        .fillMaxSize()
        .padding(16.dp)
        .nestedScroll(nestedScrollConnection)) {
        item {
            Text(
                text = stringResource(R.string.author),
                style = MaterialTheme.typography.titleMediumEmphasized,
                modifier = Modifier.padding(bottom = 8.dp, start = 13.dp)
            )
        }

        itemsIndexed(module.authorList) { index, author ->
            val shape = when {
                module.authorList.size == 1 -> RoundedCornerShape(12.dp)
                index == 0 -> RoundedCornerShape(
                    topStart = 12.dp,
                    topEnd = 12.dp,
                    bottomStart = 0.dp,
                    bottomEnd = 0.dp
                )
                index == module.authorList.lastIndex -> RoundedCornerShape(
                    topStart = 0.dp,
                    topEnd = 0.dp,
                    bottomStart = 12.dp,
                    bottomEnd = 12.dp
                )
                else -> RoundedCornerShape(0.dp)
            }

            ListItem(
                modifier = Modifier
                    .clip(shape),
                leadingContent = {
                    Icon(imageVector = Icons.Default.Person, contentDescription = null)
                },
                headlineContent = {
                    Text(
                        text = author.name,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                trailingContent = {
                    IconButton(onClick = { uriHandler.openUri(author.link) }) {
                        Icon(
                            imageVector = Icons.Default.Link,
                            contentDescription = stringResource(R.string.author_link)
                        )
                    }
                },
                colors = ListItemDefaults.colors().copy(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer
                )
            )

            if (index != module.authorList.lastIndex) {
                Spacer(modifier = Modifier.height(3.dp))
            }
        }

        item {
            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = stringResource(R.string.source_code),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(bottom = 8.dp, start = 13.dp)
            )

            ListItem(
                modifier = Modifier
                    .clip(RoundedCornerShape(12.dp))
                    .clickable {
                        uriHandler.openUri(module.sourceUrl)
                    },
                leadingContent = {
                    Icon(
                        imageVector = Icons.Default.Code,
                        contentDescription = null
                    )
                },
                headlineContent = {
                    Text(
                        text = module.sourceUrl,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                colors = ListItemDefaults.colors().copy(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer
                )
            )
        }
    }
}

@Composable
fun ReleasesTab(module: ModuleRepoViewModel.RepoModule, nestedScrollConnection: NestedScrollConnection, coroutineScope : CoroutineScope, navigator: DestinationsNavigator) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .nestedScroll(nestedScrollConnection),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        items(module.releases) { it ->
            ReleaseCard(module,it, coroutineScope, navigator)
            Spacer(modifier = Modifier.height(5.dp))
        }
    }
}

@Composable
fun ReadmeTab(module: ModuleRepoViewModel.RepoModule, nestedScrollConnection: NestedScrollConnection) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .nestedScroll(nestedScrollConnection),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Row(modifier = Modifier.fillMaxSize()) {
                GithubMarkdown(
                    content = module.readme,
                    backgroundColor = MaterialTheme.colorScheme.background
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun ReleaseCard(module: ModuleRepoViewModel.RepoModule, release: ReleaseInfo, coroutineScope: CoroutineScope, navigator: DestinationsNavigator) {
    val context = LocalContext.current
    val confirmInstallTitle =
        stringResource(R.string.confirm_install_module_title, module.moduleName)
    val confirmDialog = rememberConfirmDialog()

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 12.dp, end = 12.dp, top = 12.dp),
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(4.dp),
        colors = CardDefaults.cardColors().copy(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    modifier = Modifier.weight(1f),
                    text = release.name,
                    style = MaterialTheme.typography.bodyMediumEmphasized,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onBackground
                )
                Text(
                    text = release.publishedAt,
                    style = MaterialTheme.typography.bodySmallEmphasized,
                    color = MaterialTheme.colorScheme.outline,
                    modifier = Modifier.align(Alignment.CenterVertically)
                )
            }
            HorizontalDivider(
                modifier = Modifier.padding(
                    top = 5.dp,
                    bottom = 5.dp
                )
            )
            CollapsibleContent(
                title = stringResource(R.string.show_detail_or_hide_detail),
                enter = EnterTransition.None
            ) {
                GithubMarkdown(
                    content = release.descriptionHTML,
                    backgroundColor = MaterialTheme.colorScheme.surfaceContainer
                )
            }
            HorizontalDivider(
                modifier = Modifier.padding(
                    top = 5.dp,
                    bottom = 5.dp
                )
            )
            if (release.assets.isEmpty()) return@Card
            release.assets.forEachIndexed { index, asset ->
                val shape = when {
                    release.assets.size == 1 -> RoundedCornerShape(12.dp)
                    index == 0 -> RoundedCornerShape(
                        topStart = 12.dp,
                        topEnd = 12.dp,
                        bottomStart = 0.dp,
                        bottomEnd = 0.dp
                    )
                    index == release.assets.lastIndex -> RoundedCornerShape(
                        topStart = 0.dp,
                        topEnd = 0.dp,
                        bottomStart = 12.dp,
                        bottomEnd = 12.dp
                    )
                    else -> RoundedCornerShape(0.dp)
                }

                ListItem(
                    modifier = Modifier
                        .clip(shape),
                    headlineContent = {
                        Text(
                            text = asset.name,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    },
                    supportingContent = {
                        Text(
                            text = stringResource(R.string.assert_support_content).format(
                                formatFileSize(asset.size),
                                asset.downloadCount
                            ),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    },
                    trailingContent = {
                        FilledTonalButton(
                            modifier = Modifier.defaultMinSize(minWidth = 52.dp, minHeight = 32.dp),
                            onClick = {
                                coroutineScope.launch {
                                    val result = confirmDialog.awaitConfirm(
                                        title = confirmInstallTitle,
                                        html = true,
                                        content = release.descriptionHTML
                                    )

                                    if (result == ConfirmResult.Canceled) return@launch

                                    downloadAssetAndInstall(
                                        context,
                                        module,
                                        asset,
                                        navigator,
                                        coroutineScope
                                    )
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
                    },
                    colors = ListItemDefaults.colors().copy(
                        containerColor = MaterialTheme.colorScheme.surfaceContainer
                    )
                )

                if (index != release.assets.lastIndex) {
                    Spacer(modifier = Modifier.height(3.dp))
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun CollapsibleContent(
    modifier: Modifier = Modifier,
    title: String,
    enter: EnterTransition = expandVertically() + fadeIn(),
    exit: ExitTransition = shrinkVertically() + fadeOut(),
    content: @Composable () -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val rotation by animateFloatAsState(if (expanded) 180f else 0f)

    Column(modifier) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .clickable { expanded = !expanded }
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmallEmphasized,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.weight(1f)
            )

            Icon(
                imageVector = Icons.Default.KeyboardArrowDown,
                contentDescription = null,
                modifier = Modifier.rotate(rotation),
                tint = MaterialTheme.colorScheme.onBackground
            )
        }

        AnimatedVisibility(
            visible = expanded,
            enter = enter,
            exit = exit
        ) {
            content()
        }
    }
}


@Composable
@Preview
fun ReleaseCardPreview() {
    val release = ReleaseInfo(
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
    )
    ReleaseCard(initFakeRepoModuleForPreview(),release, rememberCoroutineScope(), EmptyDestinationsNavigator)
}