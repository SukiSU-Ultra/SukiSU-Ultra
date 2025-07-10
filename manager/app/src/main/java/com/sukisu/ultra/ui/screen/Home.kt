package com.sukisu.ultra.ui.screen

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.os.PowerManager
import android.system.Os
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.ExperimentalMaterialApi
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.TaskAlt
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material.pullrefresh.pullRefresh
import androidx.compose.material.pullrefresh.rememberPullRefreshState
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.content.pm.PackageInfoCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.InstallScreenDestination
import com.ramcosta.composedestinations.generated.destinations.SuSFSConfigScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.KernelVersion
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.KsuIsValid
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.CardConfig.cardAlpha
import com.sukisu.ultra.ui.theme.CardConfig.cardElevation
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.theme.getCardElevation
import com.sukisu.ultra.ui.util.checkNewVersion
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import com.sukisu.ultra.ui.util.reboot
import com.sukisu.ultra.ui.util.getSuSFS
import com.sukisu.ultra.ui.util.SuSFSManager
import com.sukisu.ultra.ui.viewmodel.HomeViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.random.Random

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterialApi::class)
@Destination<RootGraph>(start = true)
@Composable
fun HomeScreen(navigator: DestinationsNavigator) {
    val context = LocalContext.current
    val viewModel = viewModel<HomeViewModel>()
    val coroutineScope = rememberCoroutineScope()

    LaunchedEffect(key1 = navigator) {
        coroutineScope.launch {
            viewModel.refreshAllData(context)
        }
    }

    LaunchedEffect(Unit) {
        viewModel.loadUserSettings(context)
        viewModel.initializeData()
        viewModel.checkForUpdates(context)
    }

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val scrollState = rememberScrollState()

    Scaffold(
        topBar = {
            TopBar(
                scrollBehavior = scrollBehavior,
                navigator = navigator
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        )
    ) { innerPadding ->
        val pullRefreshState = rememberPullRefreshState(
            refreshing = false,
            onRefresh = {
                coroutineScope.launch {
                    viewModel.refreshAllData(context)
                }
            }
        )

        Box(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize()
                .pullRefresh(pullRefreshState)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(scrollState)
                    .padding(top = 12.dp, start = 16.dp, end = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatusCard(
                    systemStatus = viewModel.systemStatus,
                    onClickInstall = {
                        navigator.navigate(InstallScreenDestination)
                    }
                )

                if (viewModel.systemStatus.requireNewKernel) {
                    WarningCard(
                        stringResource(id = R.string.require_kernel_version).format(
                            Natives.getSimpleVersionFull(),
                            Natives.MINIMAL_SUPPORTED_KERNEL_FULL
                        )
                    )
                }

                if (viewModel.systemStatus.ksuVersion != null && !viewModel.systemStatus.isRootAvailable) {
                    WarningCard(
                        stringResource(id = R.string.grant_root_failed)
                    )
                }

                val checkUpdate = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
                    .getBoolean("check_update", true)
                if (checkUpdate) {
                    UpdateCard()
                }

                InfoCard(
                    systemInfo = viewModel.systemInfo,
                    isSimpleMode = viewModel.isSimpleMode,
                    isHideSusfsStatus = viewModel.isHideSusfsStatus,
                    showKpmInfo = viewModel.showKpmInfo,
                    lkmMode = viewModel.systemStatus.lkmMode,
                )

                if (!viewModel.isSimpleMode) {
                    if (!viewModel.isHideLinkCard) {
                        ContributionCard()
                        DonateCard()
                        LearnMoreCard()
                    }
                }
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

@Composable
fun UpdateCard() {
    val context = LocalContext.current
    val latestVersionInfo = LatestVersionInfo()
    val newVersion by produceState(initialValue = latestVersionInfo) {
        value = withContext(Dispatchers.IO) {
            checkNewVersion()
        }
    }

    val currentVersionCode = getManagerVersion(context).second
    val newVersionCode = newVersion.versionCode
    val newVersionUrl = newVersion.downloadUrl
    val changelog = newVersion.changelog

    val uriHandler = LocalUriHandler.current
    val title = stringResource(id = R.string.module_changelog)
    val updateText = stringResource(id = R.string.module_update)

    AnimatedVisibility(
        visible = newVersionCode > currentVersionCode,
        enter = fadeIn() + expandVertically(
            animationSpec = spring(
                dampingRatio = Spring.DampingRatioMediumBouncy,
                stiffness = Spring.StiffnessLow
            )
        ),
        exit = shrinkVertically() + fadeOut()
    ) {
        val updateDialog = rememberConfirmDialog(onConfirm = { uriHandler.openUri(newVersionUrl) })
        WarningCard(
            message = stringResource(id = R.string.new_version_available).format(newVersionCode),
            color = MaterialTheme.colorScheme.outlineVariant,
            onClick = {
                if (changelog.isEmpty()) {
                    uriHandler.openUri(newVersionUrl)
                } else {
                    updateDialog.showConfirm(
                        title = title,
                        content = changelog,
                        markdown = true,
                        confirm = updateText
                    )
                }
            }
        )
    }
}

@Composable
fun RebootDropdownItem(@StringRes id: Int, reason: String = "") {
    DropdownMenuItem(
        text = { Text(stringResource(id)) },
        onClick = { reboot(reason) })
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar(
    scrollBehavior: TopAppBarScrollBehavior? = null,
    navigator: DestinationsNavigator
) {
    val context = LocalContext.current
    val colorScheme = MaterialTheme.colorScheme
    val cardColor = if (CardConfig.isCustomBackgroundEnabled) {
        colorScheme.surfaceContainerLow
    } else {
        colorScheme.background
    }

    TopAppBar(
        title = {
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.titleLarge
            )
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = cardColor.copy(alpha = cardAlpha),
            scrolledContainerColor = cardColor.copy(alpha = cardAlpha)
        ),
        actions = {
            // SuSFS 配置按钮
            if (getSuSFS() == "Supported" && SuSFSManager.isBinaryAvailable(context)) {
                IconButton(onClick = {
                    navigator.navigate(SuSFSConfigScreenDestination)
                }) {
                    Icon(
                        imageVector = Icons.Filled.Tune,
                        contentDescription = stringResource(R.string.susfs_config_setting_title)
                    )
                }
            }

            // 重启按钮
            var showDropdown by remember { mutableStateOf(false) }
            KsuIsValid {
                IconButton(onClick = {
                    showDropdown = true
                }) {
                    Icon(
                        imageVector = Icons.Filled.PowerSettingsNew,
                        contentDescription = stringResource(id = R.string.reboot)
                    )

                    DropdownMenu(expanded = showDropdown, onDismissRequest = {
                        showDropdown = false
                    }) {
                        RebootDropdownItem(id = R.string.reboot)

                        val pm =
                            LocalContext.current.getSystemService(Context.POWER_SERVICE) as PowerManager?
                        @Suppress("DEPRECATION")
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && pm?.isRebootingUserspaceSupported == true) {
                            RebootDropdownItem(id = R.string.reboot_userspace, reason = "userspace")
                        }
                        RebootDropdownItem(id = R.string.reboot_recovery, reason = "recovery")
                        RebootDropdownItem(id = R.string.reboot_bootloader, reason = "bootloader")
                        RebootDropdownItem(id = R.string.reboot_download, reason = "download")
                        RebootDropdownItem(id = R.string.reboot_edl, reason = "edl")
                    }
                }
            }
        },
        windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        scrollBehavior = scrollBehavior
    )
}

@Composable
private fun StatusCard(
    systemStatus: HomeViewModel.SystemStatus,
    onClickInstall: () -> Unit = {}
) {
    ElevatedCard(
        colors = getCardColors(
            if (systemStatus.ksuVersion != null) MaterialTheme.colorScheme.secondaryContainer
            else MaterialTheme.colorScheme.errorContainer
        ),
        elevation = getCardElevation(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    if (systemStatus.isRootAvailable || systemStatus.kernelVersion.isGKI()) {
                        onClickInstall()
                    }
                }
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            when {
                systemStatus.ksuVersion != null -> {

                    val workingModeText = when {
                        Natives.isSafeMode == true -> stringResource(id = R.string.safe_mode)
                        else -> stringResource(id = R.string.home_working)
                    }

                    val workingModeSurfaceText = when {
                        systemStatus.lkmMode == true -> "LKM"
                        systemStatus.lkmMode == null && systemStatus.kernelVersion.isGKI1() -> "GKI 1.0"
                        systemStatus.lkmMode == false || systemStatus.kernelVersion.isGKI() -> "GKI 2.0"
                        else -> "N-GKI"
                    }

                    Icon(
                        Icons.Outlined.TaskAlt,
                        contentDescription = stringResource(R.string.home_working),
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .size(28.dp)
                            .padding(
                                horizontal = 4.dp
                            ),
                    )

                    Column(Modifier.padding(start = 20.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = workingModeText,
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.primary,
                            )

                            Spacer(Modifier.width(8.dp))

                            // 工作模式标签
                            Surface(
                                shape = RoundedCornerShape(4.dp),
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier
                            ) {
                                Text(
                                    text = workingModeSurfaceText,
                                    style = MaterialTheme.typography.labelMedium,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    color = MaterialTheme.colorScheme.onPrimary
                                )
                            }

                            Spacer(Modifier.width(6.dp))

                            // 架构标签
                            if (Os.uname().machine != "aarch64") {
                                Surface(
                                    shape = RoundedCornerShape(4.dp),
                                    color = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier
                                ) {
                                    Text(
                                        text = Os.uname().machine,
                                        style = MaterialTheme.typography.labelMedium,
                                        modifier = Modifier.padding(
                                            horizontal = 6.dp,
                                            vertical = 2.dp
                                        ),
                                        color = MaterialTheme.colorScheme.onPrimary
                                    )
                                }
                            }
                        }

                        val isHideVersion = LocalContext.current.getSharedPreferences(
                            "settings",
                            Context.MODE_PRIVATE
                        )
                            .getBoolean("is_hide_version", false)

                        if (!isHideVersion) {
                            Spacer(Modifier.height(4.dp))
                            systemStatus.ksuFullVersion?.let {
                                Text(
                                    text = stringResource(R.string.home_working_version, it),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.secondary,
                                )
                            }
                        }
                    }
                }

                systemStatus.kernelVersion.isGKI() -> {
                    Icon(
                        Icons.Outlined.Warning,
                        contentDescription = stringResource(R.string.home_not_installed),
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier
                            .size(28.dp)
                            .padding(
                                horizontal = 4.dp
                            ),
                    )

                    Column(Modifier.padding(start = 20.dp)) {
                        Text(
                            text = stringResource(R.string.home_not_installed),
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.error
                        )

                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = stringResource(R.string.home_click_to_install),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }

                else -> {
                    Icon(
                        Icons.Outlined.Block,
                        contentDescription = stringResource(R.string.home_unsupported),
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier
                            .size(28.dp)
                            .padding(
                                horizontal = 4.dp
                            ),
                    )

                    Column(Modifier.padding(start = 20.dp)) {
                        Text(
                            text = stringResource(R.string.home_unsupported),
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.error
                        )

                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = stringResource(R.string.home_unsupported_reason),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun WarningCard(
    message: String,
    color: Color = MaterialTheme.colorScheme.error,
    onClick: (() -> Unit)? = null
) {
    ElevatedCard(
        colors = getCardColors(color),
        elevation = getCardElevation(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .then(onClick?.let { Modifier.clickable { it() } } ?: Modifier)
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
fun ContributionCard() {
    val uriHandler = LocalUriHandler.current
    val links = listOf("https://github.com/ShirkNeko", "https://github.com/udochina")

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainer),
        elevation = getCardElevation(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    val randomIndex = Random.nextInt(links.size)
                    uriHandler.openUri(links[randomIndex])
                }
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = stringResource(R.string.home_ContributionCard_kernelsu),
                    style = MaterialTheme.typography.titleSmall,
                )

                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.home_click_to_ContributionCard_kernelsu),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
fun LearnMoreCard() {
    val uriHandler = LocalUriHandler.current
    val url = stringResource(R.string.home_learn_kernelsu_url)

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = cardElevation)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    uriHandler.openUri(url)
                }
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = stringResource(R.string.home_learn_kernelsu),
                    style = MaterialTheme.typography.titleSmall,
                )

                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.home_click_to_learn_kernelsu),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
fun DonateCard() {
    val uriHandler = LocalUriHandler.current

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainer),
        elevation = getCardElevation(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    uriHandler.openUri("https://patreon.com/weishu")
                }
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = stringResource(R.string.home_support_title),
                    style = MaterialTheme.typography.titleSmall,
                )

                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.home_support_content),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun InfoCard(
    systemInfo: HomeViewModel.SystemInfo,
    isSimpleMode: Boolean,
    isHideSusfsStatus: Boolean,
    showKpmInfo: Boolean,
    lkmMode: Boolean?
) {
    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainer),
        elevation = getCardElevation(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 24.dp, top = 24.dp, end = 24.dp, bottom = 16.dp),
        ) {
            @Composable
            fun InfoCardItem(
                label: String,
                content: String,
                icon: ImageVector? = null,
            ) {
                Row(
                    verticalAlignment = Alignment.Top,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp)
                ) {
                    if (icon != null) {
                        Icon(
                            imageVector = icon,
                            contentDescription = label,
                            modifier = Modifier
                                .size(28.dp)
                                .padding(vertical = 4.dp),
                        )
                    }
                    Spacer(modifier = Modifier.width(16.dp))
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f)
                    ) {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelLarge,
                        )
                        Text(
                            text = content,
                            style = MaterialTheme.typography.bodyMedium,
                            softWrap = true
                        )
                    }
                }
            }

            InfoCardItem(
                stringResource(R.string.home_kernel),
                systemInfo.kernelRelease,
                icon = Icons.Default.Memory,
            )

            if (!isSimpleMode) {
                InfoCardItem(
                    stringResource(R.string.home_android_version),
                    systemInfo.androidVersion,
                    icon = Icons.Default.Android,
                )
            }

            InfoCardItem(
                stringResource(R.string.home_device_model),
                systemInfo.deviceModel,
                icon = Icons.Default.PhoneAndroid,
            )

            InfoCardItem(
                stringResource(R.string.home_manager_version),
                "${systemInfo.managerVersion.first} (${systemInfo.managerVersion.second.toInt()})",
                icon = Icons.Default.SettingsSuggest,
            )

            // 活跃管理器
            if (!isSimpleMode && systemInfo.isDynamicSignEnabled && systemInfo.managersList != null) {
                val signatureMap = systemInfo.managersList.managers.groupBy { it.signatureIndex }

                val managersText = buildString {
                    signatureMap.toSortedMap().forEach { (signatureIndex, managers) ->
                        append(managers.joinToString(", ") { "UID: ${it.uid}" })
                        append(" ")
                        append(
                            when (signatureIndex) {
                                1 -> "(${stringResource(R.string.default_signature)})"
                                2 -> "(${stringResource(R.string.dynamic_signature)})"
                                else -> if (signatureIndex >= 0) "(${
                                    stringResource(
                                        R.string.signature_index,
                                        signatureIndex
                                    )
                                })" else "(${stringResource(R.string.unknown_signature)})"
                            }
                        )
                        append(" | ")
                    }
                }.trimEnd(' ', '|')

                InfoCardItem(
                    stringResource(R.string.multi_manager_list),
                    managersText.ifEmpty { stringResource(R.string.no_active_manager) },
                    icon = Icons.Default.Group,
                )
            }

            InfoCardItem(
                stringResource(R.string.home_selinux_status),
                systemInfo.seLinuxStatus,
                icon = Icons.Default.Security,
            )

            if (!isSimpleMode && systemInfo.zygiskImplement != "None") {
                InfoCardItem(
                    stringResource(R.string.home_zygisk_implement),
                    systemInfo.zygiskImplement,
                    icon = Icons.Default.Adb,
                )
            }

            if (!isSimpleMode) {
                // 根据showKpmInfo决定是否显示KPM信息
                if (lkmMode != true && !showKpmInfo) {
                    val displayVersion =
                        if (systemInfo.kpmVersion.isEmpty() || systemInfo.kpmVersion.startsWith("Error")) {
                            val statusText = if (Natives.isKPMEnabled()) {
                                stringResource(R.string.kernel_patched)
                            } else {
                                stringResource(R.string.kernel_not_enabled)
                            }
                            "${stringResource(R.string.not_supported)} ($statusText)"
                        } else {
                            "${stringResource(R.string.supported)} (${systemInfo.kpmVersion})"
                        }

                    InfoCardItem(
                        stringResource(R.string.home_kpm_version),
                        displayVersion,
                        icon = Icons.Default.Archive
                    )
                }
            }

            if (!isSimpleMode && !isHideSusfsStatus &&
                systemInfo.suSFSStatus == "Supported" &&
                systemInfo.suSFSVersion.isNotEmpty()
            ) {

                val infoText = SuSFSInfoText(systemInfo)

                InfoCardItem(
                    stringResource(R.string.home_susfs_version),
                    infoText,
                    icon = Icons.Default.Storage
                )
            }
        }
    }
}

@SuppressLint("ComposableNaming")
@Composable
private fun SuSFSInfoText(systemInfo: HomeViewModel.SystemInfo): String = buildString {
    append(systemInfo.suSFSVersion)

    val isSUS_SU = systemInfo.suSFSFeatures == "CONFIG_KSU_SUSFS_SUS_SU"
    val isKprobesHook = Natives.getHookType() == "Kprobes"

    when {
        isSUS_SU && isKprobesHook -> {
            append(" (${systemInfo.suSFSVariant})")
            if (systemInfo.susSUMode.isNotEmpty()) {
                append(" ${stringResource(R.string.sus_su_mode)} ${systemInfo.susSUMode}")
            }
        }

        Natives.getHookType() == "Manual" -> {
            append(" (${stringResource(R.string.manual_hook)})")
        }

        else -> {
            append(" (${Natives.getHookType()})")
        }
    }
}

fun getManagerVersion(context: Context): Pair<String, Long> {
    val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)!!
    val versionCode = PackageInfoCompat.getLongVersionCode(packageInfo)
    return Pair(packageInfo.versionName!!, versionCode)
}

@Preview
@Composable
private fun StatusCardPreview() {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        StatusCard(
            HomeViewModel.SystemStatus(
                isManager = true,
                ksuVersion = 1,
                lkmMode = null,
                kernelVersion = KernelVersion(5, 10, 101),
                isRootAvailable = true
            )
        )

        StatusCard(
            HomeViewModel.SystemStatus(
                isManager = true,
                ksuVersion = 20000,
                lkmMode = true,
                kernelVersion = KernelVersion(5, 10, 101),
                isRootAvailable = true
            )
        )

        StatusCard(
            HomeViewModel.SystemStatus(
                isManager = false,
                ksuVersion = null,
                lkmMode = true,
                kernelVersion = KernelVersion(5, 10, 101),
                isRootAvailable = false
            )
        )

        StatusCard(
            HomeViewModel.SystemStatus(
                isManager = false,
                ksuVersion = null,
                lkmMode = false,
                kernelVersion = KernelVersion(4, 10, 101),
                isRootAvailable = false
            )
        )
    }
}

@Preview
@Composable
private fun WarningCardPreview() {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        WarningCard(message = "Warning message")
        WarningCard(
            message = "Warning message ",
            MaterialTheme.colorScheme.outlineVariant,
            onClick = {})
    }
}
