package com.sukisu.ultra.ui.screen.modulerepo

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalUriHandler
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.screen.flash.FlashIt
import com.sukisu.ultra.ui.util.module.fetchModuleDetail
import com.sukisu.ultra.ui.viewmodel.ModuleRepoViewModel
import com.sukisu.ultra.ui.viewmodel.ModuleViewModel

@Composable
fun ModuleRepoScreen() {
    val navigator = LocalNavigator.current
    val viewModel = viewModel<ModuleRepoViewModel>()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val installedVm = viewModel<ModuleViewModel>()
    val installedUiState by installedVm.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        if (uiState.modules.isEmpty()) {
            viewModel.refresh()
        }
        if (installedUiState.moduleList.isEmpty()) {
            installedVm.fetchModuleList()
        }
    }

    val actions = ModuleRepoActions(
        onBack = { navigator.pop() },
        onRefresh = viewModel::refresh,
        onSearchTextChange = viewModel::updateSearchText,
        onClearSearch = { viewModel.updateSearchText("") },
        onSearchStatusChange = viewModel::updateSearchStatus,
        onSetSortOrder = viewModel::setSortOrder,
        onOpenRepoDetail = { module ->
            val args = RepoModuleArg(
                moduleId = module.moduleId,
                moduleName = module.moduleName,
                authors = module.authors,
                authorsList = module.authorList.map { AuthorArg(it.name, it.link) },
                latestRelease = module.latestRelease,
                latestReleaseTime = module.latestReleaseTime,
                releases = module.mmrl?.versions?.map { version ->
                    ReleaseArg(
                        tagName = version.version,
                        name = version.version,
                        publishedAt = version.time,
                        assets = listOf(
                            ReleaseAssetArg(
                                name = version.zipUrl.substringAfterLast('/'),
                                downloadUrl = version.zipUrl,
                                size = version.size,
                                downloadCount = 0,
                                downloadUrlFallback = version.zipUrlFallback,
                            )
                        ),
                        changelogUrl = version.changelogUrl,
                    )
                } ?: emptyList(),
                sourceId = module.sourceId,
                sourceName = module.sourceName,
                readmeUrl = module.mmrl?.readmeUrl,
                webUrl = module.mmrl?.supportUrl,
            )
            navigator.push(Route.ModuleRepoDetail(args))
        },
        onAddSource = viewModel::addSource,
        onRemoveSource = viewModel::removeSource,
        onSetSourceEnabled = viewModel::setSourceEnabled,
        onRenameSource = viewModel::renameSource,
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> ModuleRepoScreenMiuix(uiState, actions)
        UiMode.Material -> ModuleRepoScreenMaterial(uiState, actions)
    }
}

@Composable
fun ModuleRepoDetailScreen(module: RepoModuleArg) {
    val navigator = LocalNavigator.current
    val uriHandler = LocalUriHandler.current
    var readmeHtml by remember(module.moduleId) { mutableStateOf<String?>(null) }
    var readmeLoaded by remember(module.moduleId) { mutableStateOf(false) }
    var detailReleases by remember(module.moduleId) { mutableStateOf<List<ReleaseArg>>(emptyList()) }
    var webUrl by remember(module.moduleId) {
        mutableStateOf(module.webUrl ?: if (module.isMmrl) "" else "https://modules.kernelsu.org/module/${module.moduleId}")
    }
    var sourceUrl by remember(module.moduleId) {
        mutableStateOf(module.webUrl ?: if (module.isMmrl) "" else "https://github.com/KernelSU-Modules-Repo/${module.moduleId}")
    }

    LaunchedEffect(module.moduleId) {
        if (module.moduleId.isNotEmpty()) {
            withContext(Dispatchers.IO) {
                runCatching {
                    val detail = fetchModuleDetail(module)
                    if (detail != null) {
                        readmeHtml = detail.readmeHtml
                        if (detail.url.isNotEmpty() && detail.url != "null") {
                            webUrl = detail.url
                        }
                        if (detail.sourceUrl.isNotEmpty() && detail.sourceUrl != "null") {
                            sourceUrl = detail.sourceUrl
                        }
                        detailReleases = detail.releases.map { r ->
                            ReleaseArg(
                                tagName = r.tagName,
                                name = r.name,
                                publishedAt = r.publishedAt,
                                assets = r.assets.map { a ->
                                    ReleaseAssetArg(
                                        a.name,
                                        a.downloadUrl,
                                        a.size,
                                        a.downloadCount,
                                        a.downloadUrlFallback,
                                    )
                                },
                                descriptionHTML = r.descriptionHTML
                            )
                        }
                    } else {
                        detailReleases = emptyList()
                    }
                }.onSuccess {
                    readmeLoaded = true
                }.onFailure {
                    readmeLoaded = true
                    detailReleases = emptyList()
                }
            }
        } else {
            readmeLoaded = true
        }
    }

    val state = ModuleRepoDetailUiState(
        module = module,
        readmeHtml = readmeHtml,
        readmeLoaded = readmeLoaded,
        detailReleases = detailReleases,
        webUrl = webUrl,
        sourceUrl = sourceUrl,
    )
    val actions = ModuleRepoDetailActions(
        onBack = { navigator.pop() },
        onOpenWebUrl = { if (webUrl.isNotEmpty()) uriHandler.openUri(webUrl) },
        onOpenUrl = uriHandler::openUri,
        onInstallModule = { uri -> navigator.push(Route.Flash(FlashIt.FlashModules(listOf(uri)))) },
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> ModuleRepoDetailScreenMiuix(state, actions)
        UiMode.Material -> ModuleRepoDetailScreenMaterial(state, actions)
    }
}
