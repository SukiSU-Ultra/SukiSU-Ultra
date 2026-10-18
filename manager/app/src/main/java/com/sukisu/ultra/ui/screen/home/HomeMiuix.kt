package com.sukisu.ultra.ui.screen.home

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.MenuBook
import androidx.compose.material.icons.filled.VolunteerActivism
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.UriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.KernelVersion
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.WarningLevel
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog
import com.sukisu.ultra.ui.component.miuix.WarningCard
import com.sukisu.ultra.ui.component.rebootlistpopup.RebootListPopupMiuix
import com.sukisu.ultra.ui.component.statustag.StatusTag
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.theme.isInDarkTheme
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.isDynamicColor
import top.yukonga.miuix.kmp.utils.PressFeedbackType
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun HomePagerMiuix(
    state: HomeUiState,
    actions: HomeActions,
    bottomInnerPadding: Dp,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive) Color.Transparent else colorScheme.surface
    Scaffold(
        topBar = {
            TopBar(
                scrollBehavior = scrollBehavior,
                backdrop = backdrop,
                barColor = barColor,
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxHeight()
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection)
                    .padding(horizontal = 12.dp),
                contentPadding = innerPadding,
                overscrollEffect = null,
            ) {
                item {
                    Column(
                        modifier = Modifier.padding(top = 12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        StatusCard(
                            state = state,
                            actions = actions,
                        )
                        if (state.checkUpdateEnabled) {
                            UpdateCard(state = state, actions = actions)
                        }
                        if (state.showManagerPrBuildWarning && state.showFullStatus) {
                            WarningCard(stringResource(id = R.string.home_pr_build_warning), level = WarningLevel.Notice)
                        } else if (state.showKernelPrBuildWarning && state.showFullStatus) {
                            WarningCard(stringResource(id = R.string.home_pr_kernel_warning), level = WarningLevel.Notice)
                        }
                        if (state.requiresNewKernel && state.showFullStatus) {
                            WarningCard(
                                stringResource(
                                    id = if (state.canInstallKernelUpdate) R.string.require_kernel_version else R.string.require_kernel_version_gki
                                ),
                                onClick = if (state.canInstallKernelUpdate) actions.onInstallClick else null
                            )
                        }
                        if (state.requiresNewManager) {
                            WarningCard(
                                stringResource(
                                    id = R.string.require_manager_version
                                )
                            )
                        }
                        if (state.showLkmUpdate && state.showFullStatus) {
                            WarningCard(
                                message = stringResource(R.string.home_lkm_update_available),
                                level = WarningLevel.Notice,
                                onClick = actions.onInstallClick,
                            )
                        }
                        if (state.showRootWarning) {
                            WarningCard(stringResource(id = R.string.grant_root_failed))
                        }
                        if (state.isPreviewMode) {
                            WarningCard(stringResource(id = R.string.home_preview_mode), level = WarningLevel.Notice)
                        }
                        StatsRow(state = state, actions = actions)
                        InfoCard(
                            systemInfo = state.systemInfo,
                            showFullStatus = state.showFullStatus,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        SupportLinks(
                            onOpenUrl = actions.onOpenUrl,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(
                            Modifier.height(
                                bottomInnerPadding + if (!Natives.isFullFeatured())
                                    WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() else 0.dp
                            )
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun UpdateCard(
    state: HomeUiState,
    actions: HomeActions,
) {
    val newVersion = state.latestVersionInfo
    val title = stringResource(id = R.string.module_changelog)
    val updateText = stringResource(id = R.string.module_update)
    val updateDialog = rememberConfirmDialog(onConfirm = { actions.onOpenUrl(newVersion.downloadUrl) })

    AnimatedVisibility(
        visible = state.hasUpdate,
        enter = fadeIn() + expandVertically(),
        exit = shrinkVertically() + fadeOut()
    ) {
        WarningCard(
            message = stringResource(id = R.string.new_version_available, newVersion.versionCode),
            level = WarningLevel.Notice,
            onClick = {
                if (newVersion.changelog.isEmpty()) {
                    actions.onOpenUrl(newVersion.downloadUrl)
                } else {
                    updateDialog.showConfirm(
                        title = title,
                        content = newVersion.changelog,
                        markdown = true,
                        confirm = updateText
                    )
                }
            }
        )
    }
}

@Composable
private fun TopBar(
    scrollBehavior: ScrollBehavior,
    backdrop: LayerBackdrop?,
    barColor: Color,
) {
    BlurredBar(backdrop) {
        TopAppBar(
            color = barColor,
            title = stringResource(R.string.app_name),
            actions = {
                RebootListPopupMiuix()
            },
            scrollBehavior = scrollBehavior
        )
    }
}

@Composable
private fun StatusCard(
    state: HomeUiState,
    actions: HomeActions,
) {
    val onClick = {
        if (!state.isLateLoadMode) {
            actions.onInstallClick()
        }
    }
    when {
        state.ksuVersion != null -> ActiveStatusCard(state = state, onClick = onClick)
        else -> InactiveStatusCard(
            state = state,
            actions = actions,
            notInstalled = state.kernelVersion.isGKI(),
            onClick = onClick,
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ActiveStatusCard(
    state: HomeUiState,
    onClick: () -> Unit,
) {
    val isDark = isInDarkTheme()
    val accentColor = if (isDynamicColor) colorScheme.primary else Color(0xFF36D167)
    val tagBackground = when {
        isDynamicColor -> colorScheme.tertiaryContainer
        isDark -> Color(0xFF315D3E)
        else -> Color(0xFFB8E8C5)
    }
    val tagContent = when {
        isDynamicColor -> colorScheme.onTertiaryContainer
        isDark -> Color(0xFFB8E8C5)
        else -> Color(0xFF164A29)
    }
    val workingMode = when (state.lkmMode) {
        null -> null
        true -> "LKM"
        else -> "Built-in"
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(
            color = when {
                isDynamicColor -> colorScheme.secondaryContainer
                isDark -> Color(0xFF1A3825)
                else -> Color(0xFFDFFAE4)
            }
        ),
        onClick = onClick,
        showIndication = !state.isLateLoadMode,
        pressFeedbackType = PressFeedbackType.Tilt
    ) {
        Box {
            Icon(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .offset(27.dp, 31.dp)
                    .size(150.dp),
                imageVector = Icons.Rounded.CheckCircleOutline,
                tint = accentColor.copy(alpha = if (isDynamicColor) 0.8f else 1f),
                contentDescription = null
            )
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 188.dp)
                    .padding(22.dp),
                verticalArrangement = Arrangement.SpaceBetween,
            ) {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    if (workingMode != null) {
                        StatusTag(
                            label = workingMode,
                            contentColor = if (isDynamicColor) colorScheme.onPrimary else Color.White,
                            backgroundColor = accentColor,
                        )
                    }
                    if (state.showCustomLkmBadge) {
                        StatusTag(
                            label = stringResource(R.string.home_lkm_custom),
                            contentColor = tagContent,
                            backgroundColor = tagBackground,
                        )
                    }
                    if (state.isSafeMode) {
                        StatusTag(
                            label = stringResource(id = R.string.safe_mode),
                            contentColor = colorScheme.onErrorContainer,
                            backgroundColor = colorScheme.errorContainer,
                        )
                    }
                    if (state.isLateLoadMode) {
                        StatusTag(
                            label = stringResource(id = R.string.jailbreak_mode),
                            contentColor = colorScheme.onErrorContainer,
                            backgroundColor = colorScheme.errorContainer,
                        )
                    }
                }
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = stringResource(R.string.home_working),
                        fontSize = 36.sp,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = stringResource(
                            R.string.home_working_version,
                            "${state.ksuVersion}-${state.kernelUAPIVersion}"
                        ),
                        fontSize = 14.sp,
                        fontFamily = FontFamily.Monospace,
                        color = colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        }
    }
}

@Composable
private fun InactiveStatusCard(
    state: HomeUiState,
    actions: HomeActions,
    notInstalled: Boolean,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick,
        showIndication = !state.isLateLoadMode,
        pressFeedbackType = PressFeedbackType.Tilt
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 188.dp)
                .padding(22.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.ErrorOutline,
                    contentDescription = null,
                    tint = colorScheme.error,
                    modifier = Modifier.size(18.dp),
                )
                Text(
                    text = stringResource(
                        if (notInstalled) R.string.home_click_to_install else R.string.home_unsupported_reason
                    ),
                    fontSize = 14.sp,
                    color = colorScheme.error,
                )
            }
            Text(
                text = stringResource(if (notInstalled) R.string.home_not_installed else R.string.home_unsupported),
                modifier = Modifier.padding(vertical = 12.dp),
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold,
            )
            if (notInstalled) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    TextButton(
                        text = stringResource(R.string.install),
                        onClick = actions.onInstallClick,
                        colors = ButtonDefaults.textButtonColorsPrimary()
                    )
                    if (state.isSELinuxPermissive) {
                        TextButton(
                            text = stringResource(R.string.home_jailbreak),
                            onClick = actions.onJailbreakClick,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StatsRow(
    state: HomeUiState,
    actions: HomeActions,
) {
    val tiles = buildList<Triple<Int, Int, (() -> Unit)?>> {
        state.superuserCount?.let { add(Triple(it, R.string.superuser, actions.onSuperuserClick)) }
        state.moduleCount?.let { add(Triple(it, R.string.module, actions.onModuleClick)) }
        state.kpmCount?.let { add(Triple(it, R.string.kpm_title, null)) }
    }
    if (tiles.isEmpty()) return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        tiles.forEach { (count, label, onClick) ->
            Card(
                modifier = Modifier.weight(1f),
                onClick = onClick,
                showIndication = onClick != null,
                pressFeedbackType = PressFeedbackType.Sink
            ) {
                Column(
                    modifier = Modifier
                        .height(88.dp)
                        .padding(14.dp),
                    verticalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = count.toString(),
                        fontSize = 26.sp,
                        fontWeight = FontWeight.Bold,
                        color = colorScheme.onSurface,
                    )
                    Text(
                        text = stringResource(label),
                        fontSize = MiuixTheme.textStyles.body2.fontSize,
                        color = colorScheme.onSurfaceVariantSummary,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

@Composable
private fun SupportLinks(
    onOpenUrl: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val learnMoreUrl = stringResource(R.string.home_learn_kernelsu_url)

    Card(modifier = modifier) {
        ArrowPreference(
            title = stringResource(R.string.home_support_title),
            summary = stringResource(R.string.home_support_content),
            startAction = {
                Icon(
                    imageVector = Icons.Filled.VolunteerActivism,
                    contentDescription = stringResource(R.string.home_support_title),
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colorScheme.onBackground,
                )
            },
            onClick = { onOpenUrl("https://patreon.com/weishu") },
        )
        ArrowPreference(
            title = stringResource(R.string.home_learn_kernelsu),
            summary = stringResource(R.string.home_click_to_learn_kernelsu),
            startAction = {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.MenuBook,
                    contentDescription = stringResource(R.string.home_learn_kernelsu),
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colorScheme.onBackground,
                )
            },
            onClick = { onOpenUrl(learnMoreUrl) },
        )
    }
}

@Composable
private fun SpecSheet(
    rows: List<Pair<String, String>>,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
            rows.forEachIndexed { index, (label, value) ->
                if (index > 0) {
                    HorizontalDivider()
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    Text(
                        text = label,
                        fontSize = MiuixTheme.textStyles.body2.fontSize,
                        fontWeight = FontWeight.Medium,
                        color = colorScheme.onSurface,
                    )
                    Text(
                        text = value,
                        modifier = Modifier.weight(1f),
                        fontSize = 13.sp,
                        fontFamily = FontFamily.Monospace,
                        color = colorScheme.onSurfaceVariantSummary,
                        textAlign = TextAlign.End,
                    )
                }
            }
        }
    }
}

@Composable
private fun InfoCard(
    systemInfo: SystemInfo,
    modifier: Modifier = Modifier,
    showFullStatus: Boolean = true,
) {
    val selinuxDisplay = when (systemInfo.selinuxStatus) {
        "Enforcing" -> stringResource(R.string.selinux_status_enforcing)
        "Permissive" -> stringResource(R.string.selinux_status_permissive)
        "Disabled" -> stringResource(R.string.selinux_status_disabled)
        else -> stringResource(R.string.selinux_status_unknown)
    }
    val seccompDisplay = when (systemInfo.seccompStatus) {
        -1 -> stringResource(R.string.seccomp_status_not_supported)
        0 -> stringResource(R.string.seccomp_status_disabled)
        1 -> stringResource(R.string.seccomp_status_strict)
        2 -> stringResource(R.string.seccomp_status_filter)
        else -> stringResource(R.string.seccomp_status_unknown)
    }

    val manualHookText = stringResource(R.string.manual_hook)
    val inlineHookText = stringResource(R.string.inline_hook)
    val tracepointHookText = stringResource(R.string.tracepoint_hook)
    val unknownHookText = stringResource(R.string.selinux_status_unknown)
    val susfsInfo = rememberSusfsInfo(manualHookText, inlineHookText)
    val isSusfsSupported = susfsInfo.status == SusfsStatus.Supported
    val hookTypeLabel = rememberHookTypeLabel(manualHookText, inlineHookText, tracepointHookText, unknownHookText)

    val systemRows = buildList {
        add(stringResource(R.string.home_manager_version) to systemInfo.managerVersion)
        add(stringResource(R.string.home_kernel) to systemInfo.kernelVersion)
        if (showFullStatus) {
            if (!systemInfo.kernelFullVersion.isNullOrBlank()) {
                add(stringResource(R.string.home_kernel_full_version) to systemInfo.kernelFullVersion)
            }
            if (isSusfsSupported) {
                add(stringResource(R.string.home_susfs_version) to susfsInfo.detail)
            } else if (!hookTypeLabel.isNullOrBlank()) {
                add(stringResource(R.string.hook_type) to hookTypeLabel)
            }
            if (!systemInfo.zygiskImplementation.isNullOrBlank()) {
                add(stringResource(R.string.home_zygisk_implementation) to systemInfo.zygiskImplementation)
            }
        }
        add(stringResource(R.string.home_device_model) to systemInfo.deviceModel)
        add(stringResource(R.string.home_fingerprint) to systemInfo.fingerprint)
    }
    val securityRows = listOf(
        stringResource(R.string.home_selinux_status) to selinuxDisplay,
        stringResource(R.string.home_seccomp_status) to seccompDisplay,
    )

    Column(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SpecSheet(rows = systemRows)
        SpecSheet(rows = securityRows)
    }
}

@Preview(name = "Activated")
@Composable
private fun StatusCardActivatedPreview() {
    StatusCard(
        state = previewHomeScreenState(ksuVersion = 12345, lkmMode = true),
        actions = HomeActions({}, {})
    )
}

@Preview(name = "Not Activated")
@Composable
private fun StatusCardNotActivatedPreview() {
    StatusCard(state = previewHomeScreenState(ksuVersion = null, lkmMode = null), actions = HomeActions({}, {}))
}

@Preview(name = "Permissive")
@Composable
private fun StatusCardPermissivePreview() {
    StatusCard(
        state = previewHomeScreenState(ksuVersion = null, lkmMode = null, selinuxStatus = "Permissive"),
        actions = HomeActions({}, {})
    )
}

@Preview(name = "Jailbreak")
@Composable
private fun StatusCardJailbreakPreview() {
    StatusCard(
        state = previewHomeScreenState(ksuVersion = 12345, lkmMode = true, isLateLoadMode = true),
        actions = HomeActions({}, {})
    )
}

private val previewSystemInfo = SystemInfo(
    kernelVersion = "6.1.0-android14-0-g1234567",
    managerVersion = "1.0.0 (10000)",
    deviceModel = "Xiaomi 17 Pro Max",
    fingerprint = "Xiaomi/popsicle/popsicle:16/BQ2A.250705.001-BP2A.250605.031.A3/OS3.0.313.0.WPBCNXM:user/release-keys",
    kernelFullVersion = "v4.1.2-abc1234@main",
    selinuxStatus = "Enforcing",
    seccompStatus = 2
)

private val previewUriHandler = object : UriHandler {
    override fun openUri(uri: String) {}
}

@Composable
private fun HomeScreenPreviewContent(
    ksuVersion: Int?,
    lkmMode: Boolean?,
    isSafeMode: Boolean = false,
    isLateLoadMode: Boolean = false,
    selinuxStatus: String = "Enforcing",
) {
    CompositionLocalProvider(LocalUriHandler provides previewUriHandler) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val actions = HomeActions({}, {})
            StatusCard(
                state = previewHomeScreenState(
                    ksuVersion = ksuVersion,
                    lkmMode = lkmMode,
                    isSafeMode = isSafeMode,
                    isLateLoadMode = isLateLoadMode,
                    selinuxStatus = selinuxStatus,
                ),
                actions = actions
            )
            InfoCard(
                systemInfo = previewSystemInfo.copy(selinuxStatus = selinuxStatus),
                showFullStatus = true,
                modifier = Modifier.fillMaxWidth(),
            )
            SupportLinks(
                onOpenUrl = {},
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Preview(name = "Home Activated", showBackground = true)
@Composable
private fun HomeScreenActivatedPreview() {
    HomeScreenPreviewContent(ksuVersion = 12345, lkmMode = true)
}

@Preview(name = "Home Not Activated", showBackground = true)
@Composable
private fun HomeScreenNotActivatedPreview() {
    HomeScreenPreviewContent(ksuVersion = null, lkmMode = null)
}

@Preview(name = "Home Permissive", showBackground = true)
@Composable
private fun HomeScreenPermissivePreview() {
    HomeScreenPreviewContent(ksuVersion = null, lkmMode = null, selinuxStatus = "Permissive")
}

@Preview(name = "Home Jailbreak", showBackground = true)
@Composable
private fun HomeScreenJailbreakPreview() {
    HomeScreenPreviewContent(ksuVersion = 12345, lkmMode = true, isLateLoadMode = true)
}

private fun previewHomeScreenState(
    ksuVersion: Int?,
    lkmMode: Boolean?,
    isSafeMode: Boolean = false,
    isLateLoadMode: Boolean = false,
    selinuxStatus: String = "Enforcing",
) = HomeUiState(
    kernelVersion = KernelVersion(6, 1, 0),
    ksuVersion = ksuVersion,
    lkmMode = lkmMode,
    isLkmBundled = lkmMode == true,
    isManager = true,
    isManagerPrBuild = false,
    isKernelPrBuild = false,
    requiresNewKernel = false,
    requiresNewManager = false,
    isRootAvailable = ksuVersion != null,
    isSafeMode = isSafeMode,
    isLateLoadMode = isLateLoadMode,
    checkUpdateEnabled = false,
    showFullStatus = true,
    latestVersionInfo = LatestVersionInfo(),
    currentManagerVersionCode = 10000,
    systemInfo = previewSystemInfo.copy(selinuxStatus = selinuxStatus),
    kernelUAPIVersion = 1,
    managerUAPIVersion = 1,
)
