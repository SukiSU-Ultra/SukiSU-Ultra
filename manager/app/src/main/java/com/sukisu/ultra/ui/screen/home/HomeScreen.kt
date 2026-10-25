package com.sukisu.ultra.ui.screen.home

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.sukisu.ultra.R
import com.sukisu.ultra.magica.MagicaService
import com.sukisu.ultra.ui.LocalMainPagerState
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.bottombar.BottomBarDestination
import com.sukisu.ultra.ui.component.dialog.rememberLoadingDialog
import com.sukisu.ultra.ui.navigation3.Navigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.util.rootAvailable
import com.sukisu.ultra.ui.viewmodel.HomeViewModel
import kotlin.time.Duration.Companion.milliseconds

@Composable
fun HomePager(
    navigator: Navigator,
    bottomInnerPadding: Dp,
    isCurrentPage: Boolean = true,
) {
    val viewModel = viewModel<HomeViewModel>()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val uriHandler = LocalUriHandler.current
    val context = LocalContext.current
    val loadingDialog = rememberLoadingDialog()
    val scope = rememberCoroutineScope()
    val latestIsCurrentPage by rememberUpdatedState(isCurrentPage)

    // The ViewModel starts the first probe; only later foreground resumes need another one.
    LifecycleResumeEffect(viewModel) {
        viewModel.onResume(latestIsCurrentPage)
        onPauseOrDispose { }
    }

    // Switching back to this tab must still refresh counts changed elsewhere; the ViewModel
    // already probed once on creation, so skip the selection that coincides with it.
    val skipInitialSelection = remember { mutableStateOf(isCurrentPage) }
    LaunchedEffect(isCurrentPage) {
        if (!isCurrentPage) return@LaunchedEffect
        if (skipInitialSelection.value) skipInitialSelection.value = false else viewModel.refresh()
    }

    LaunchedEffect(uiState.error, isCurrentPage) {
        if (isCurrentPage && uiState.content != null && uiState.error != null) {
            Toast.makeText(
                context,
                "${context.getString(R.string.operation_failed)}: ${uiState.error}",
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    val state = uiState.content
    if (state == null) {
        HomeLoadingContent(uiState, bottomInnerPadding, viewModel::refresh)
        return
    }

    var pendingCiInstall by rememberSaveable { mutableStateOf(false) }
    val storagePermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) {
            if (pendingCiInstall) viewModel.installCiUpdate() else viewModel.installReleaseUpdate()
        }
    }
    val startUpdate: (Boolean) -> Unit = { isCi ->
        scope.launch {
            val hasRoot = withContext(Dispatchers.IO) { rootAvailable() }
            when {
                !hasRoot && !context.packageManager.canRequestPackageInstalls() -> {
                    Toast.makeText(context, R.string.ci_update_install_permission, Toast.LENGTH_LONG).show()
                    context.startActivity(Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        android.net.Uri.parse("package:${context.packageName}")))
                }
                Build.VERSION.SDK_INT <= Build.VERSION_CODES.P &&
                    ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED -> {
                    pendingCiInstall = isCi
                    storagePermission.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                }
                else -> if (isCi) viewModel.installCiUpdate() else viewModel.installReleaseUpdate()
            }
        }
    }

    val mainPagerState = LocalMainPagerState.current
    val actions = HomeActions(
        onInstallClick = { navigator.push(Route.Install()) },
        onSuperuserClick = { mainPagerState.animateToPage(BottomBarDestination.SuperUser.ordinal) },
        onModuleClick = { mainPagerState.animateToPage(BottomBarDestination.Module.ordinal) },
        onOpenUrl = uriHandler::openUri,
        onCiUpdateClick = { startUpdate(true) },
        onReleaseUpdateClick = { startUpdate(false) },
        onOpenVersionSpoof = { navigator.push(Route.VersionSpoof) },
        onJailbreakClick = {
            loadingDialog.showLoading()
            context.startService(Intent(context, MagicaService::class.java))
            // Manager will be force-stopped and restarted by late-load on success.
            // If that doesn't happen within timeout, jailbreak likely failed.
            scope.launch(Dispatchers.IO) {
                delay(30_000.milliseconds)
                withContext(Dispatchers.Main) {
                    loadingDialog.hide()
                    Toast.makeText(context, R.string.jailbreak_timeout, Toast.LENGTH_LONG).show()
                }
            }
        },
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> HomePagerMiuix(
            state = state,
            actions = actions,
            bottomInnerPadding = bottomInnerPadding,
        )

        UiMode.Material -> HomePagerMaterial(
            state = state,
            actions = actions,
            bottomInnerPadding = bottomInnerPadding,
        )
    }
}

@Composable
private fun HomeLoadingContent(
    state: HomeLoadState,
    bottomInnerPadding: Dp,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(bottom = bottomInnerPadding).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        when (LocalUiMode.current) {
            UiMode.Material -> if (state.isRefreshing) {
                androidx.compose.material3.LoadingIndicator()
            } else {
                androidx.compose.material3.Text(stringResource(R.string.operation_failed))
                state.error?.let { androidx.compose.material3.Text(it) }
                androidx.compose.material3.TextButton(onClick = onRetry) {
                    androidx.compose.material3.Text(stringResource(R.string.network_retry))
                }
            }

            UiMode.Miuix -> if (state.isRefreshing) {
                top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator()
            } else {
                top.yukonga.miuix.kmp.basic.Text(stringResource(R.string.operation_failed))
                state.error?.let { top.yukonga.miuix.kmp.basic.Text(it) }
                top.yukonga.miuix.kmp.basic.TextButton(
                    text = stringResource(R.string.network_retry),
                    onClick = onRetry,
                )
            }
        }
    }
}
