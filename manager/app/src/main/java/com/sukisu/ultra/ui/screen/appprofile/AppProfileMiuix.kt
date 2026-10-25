package com.sukisu.ultra.ui.screen.appprofile

import com.sukisu.ultra.ui.component.profile.TemporaryRootControls
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.basicMarquee
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.captionBar
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountCircle
import androidx.compose.material.icons.rounded.Check
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.toggleableState
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.AppIconImage
import com.sukisu.ultra.ui.component.ListPopupDefaults
import com.sukisu.ultra.ui.component.miuix.DropdownItem
import com.sukisu.ultra.ui.component.profile.AppProfileConfig
import com.sukisu.ultra.ui.component.profile.RootProfileConfig
import com.sukisu.ultra.ui.component.profile.TemplateConfig
import com.sukisu.ultra.ui.component.statustag.StatusTag
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.listAppProfileTemplates
import com.sukisu.ultra.ui.util.ownerNameForUid
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import com.sukisu.ultra.ui.util.setSepolicy
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.ListPopupColumn
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.PopupPositionProvider
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.Switch
import androidx.compose.foundation.layout.offset
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.spring
import androidx.compose.ui.unit.IntOffset
import com.sukisu.ultra.ui.viewmodel.getTemplateInfoById
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.MoreCircle
import top.yukonga.miuix.kmp.overlay.OverlayListPopup
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.PressFeedbackType
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * @author weishu
 * @date 2023/5/16.
 */
@Composable
fun AppProfileScreenMiuix(
    state: AppProfileUiState,
    actions: AppProfileActions,
) {
    val enableBlur = LocalEnableBlur.current
    val scrollBehavior = MiuixScrollBehavior()
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive) Color.Transparent else colorScheme.surface
    Scaffold(
        topBar = {
            TopBar(
                onBack = actions.onBack,
                showActions = !state.isUidGroup && !state.appGroup.primary.isWebViewZygote,
                packageName = state.packageName,
                userId = state.uid / 100000,
                onLaunchApp = actions.onLaunchApp,
                onForceStopApp = actions.onForceStopApp,
                onRestartApp = actions.onRestartApp,
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
                    .padding(top = 16.dp)
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                contentPadding = innerPadding,
                overscrollEffect = null
            ) {
                item {
                    AppProfileInner(
                        packageName = if (state.isUidGroup) {
                            ""
                        } else {
                            state.appGroup.primary.displayIdentifier
                        },
                        appLabel = if (state.isUidGroup) ownerNameForUid(state.appGroup.primary.uid) else state.appGroup.primary.label,
                        appIcon = {
                            AppIconImage(
                                packageInfo = state.appGroup.primary.packageInfo,
                                label = state.appGroup.primary.label,
                                modifier = Modifier.size(60.dp).clip(RoundedCornerShape(20.dp))
                            )
                        },
                        appUid = state.uid,
                        sharedUserId = if (state.isUidGroup) state.sharedUserId else "",
                        appVersionName = if (state.isUidGroup) "" else (state.appGroup.primary.packageInfo.versionName ?: ""),
                        appVersionCode = if (state.isUidGroup) 0L else state.appGroup.primary.packageInfo.longVersionCode,
                        profile = state.profile,
                        isUidGroup = state.isUidGroup,
                        isSpecialApp = state.appGroup.primary.special,
                        affectedApps = state.appGroup.apps,
                        onViewTemplate = actions.onViewTemplate,
                        onManageTemplate = actions.onManageTemplate,
                        onProfileChange = actions.onProfileChange,
                        onPermanentRootChange = actions.onPermanentRootChange,
                        temporaryRoot = state.temporaryRoot,
                        onTemporaryRootChange = actions.onTemporaryRootChange,
                        onTemporaryRootGrant = actions.onTemporaryRootGrant,
                    )
                    Spacer(
                        Modifier.height(
                            WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() +
                                    WindowInsets.captionBar.asPaddingValues().calculateBottomPadding()
                        )
                    )
                }
            }
        }
    }
}

@Composable
private fun AppProfileInner(
    modifier: Modifier = Modifier,
    packageName: String,
    appLabel: String,
    appIcon: @Composable (() -> Unit),
    appUid: Int,
    sharedUserId: String = "",
    appVersionName: String,
    appVersionCode: Long,
    profile: Natives.Profile,
    onPermanentRootChange: (Boolean) -> Unit = {},
    temporaryRoot: Boolean = false,
    onTemporaryRootChange: (Boolean) -> Unit = {},
    onTemporaryRootGrant: (Long?) -> Unit = {},
    isUidGroup: Boolean = false,
    isSpecialApp: Boolean = false,
    affectedApps: List<SuperUserViewModel.AppInfo> = emptyList(),
    onViewTemplate: (id: String) -> Unit = {},
    onManageTemplate: () -> Unit = {},
    onProfileChange: (Natives.Profile) -> Unit,
) {
    val isRootGranted = !isSpecialApp && profile.allowSu
    val userId = appUid / 100000
    val appId = appUid % 100000
    val templates = remember { listAppProfileTemplates() }

    val initialRootMode = if (profile.rootUseDefault) {
        Mode.Default
    } else if (profile.rootTemplate != null) {
        Mode.Template
    } else {
        Mode.Custom
    }
    var rootMode by rememberSaveable {
        mutableStateOf(initialRootMode)
    }
    val nonRootMode = if (profile.nonRootUseDefault) Mode.Default else Mode.Custom
    val dropdownMode = if (isRootGranted) rootMode else nonRootMode

    Column(
        modifier = modifier
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            appIcon()
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(
                    text = appLabel,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = colorScheme.onSurface,
                    modifier = Modifier.basicMarquee(),
                    maxLines = 1,
                    softWrap = false
                )
                val details = buildList {
                    if (isSpecialApp) {
                        add(packageName)
                    } else if (!isUidGroup) {
                        add(packageName)
                        add("$appVersionName ($appVersionCode)")
                    } else {
                        if (sharedUserId.isNotEmpty()) add(sharedUserId)
                        add(stringResource(R.string.group_contains_apps, affectedApps.size))
                    }
                }
                details.forEach {
                    Text(
                        text = it,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        color = colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.basicMarquee(),
                        maxLines = 1,
                        softWrap = false
                    )
                }
            }
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                if (userId != 0) {
                    StatusTag(
                        label = "USER $userId",
                        backgroundColor = colorScheme.primary.copy(alpha = 0.8f),
                        contentColor = colorScheme.onPrimary
                    )
                }
                StatusTag(
                    label = "UID ${if (userId != 0) appId else appUid}",
                    backgroundColor = colorScheme.primary.copy(alpha = 0.8f),
                    contentColor = colorScheme.onPrimary
                )
            }
        }

        if (!isSpecialApp) {
            val checked = isRootGranted
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp)
                    .padding(top = 4.dp, bottom = 12.dp)
                    .semantics {
                        role = Role.Switch
                        toggleableState = ToggleableState(checked)
                    },
                colors = CardDefaults.defaultColors(
                    color = if (checked) colorScheme.primary else colorScheme.surfaceContainer
                ),
                insideMargin = PaddingValues(horizontal = 20.dp, vertical = 14.dp),
                onClick = { onPermanentRootChange(!checked) },
                pressFeedbackType = PressFeedbackType.Sink,
            ) {
                Row(
                    modifier = Modifier.heightIn(min = 48.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(id = R.string.superuser),
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (checked) colorScheme.onPrimary else colorScheme.onSurface,
                        )
                        Text(
                            text = if (isRootGranted && temporaryRoot) stringResource(R.string.temporary_root_active) else dropdownMode.text,
                            fontSize = 13.sp,
                            color = if (checked) {
                                colorScheme.onPrimary.copy(alpha = 0.75f)
                            } else {
                                colorScheme.onSurfaceVariantSummary
                            },
                        )
                    }
                    SuperuserSwitch(checked = checked)
                }
            }
        }

        if (!isSpecialApp) {
            TemporaryRootControls(
                enabled = temporaryRoot,
                granted = isRootGranted,
                onEnabledChange = onTemporaryRootChange,
                onChoose = onTemporaryRootGrant,
            )
        }

        ProfileBox(dropdownMode, isRootGranted) { mode ->
            if (isRootGranted) {
                when (mode) {
                    Mode.Default, Mode.Custom -> {
                        onProfileChange(
                            profile.copy(
                                rootUseDefault = mode == Mode.Default,
                                rootTemplate = null
                            )
                        )
                        rootMode = mode
                    }

                    Mode.Template -> {
                        if (templates.isNotEmpty()) {
                            val selected = profile.rootTemplate ?: templates[0]
                            val info = getTemplateInfoById(selected)
                            if (info != null && setSepolicy(selected, info.rules.joinToString("\n"))) {
                                onProfileChange(
                                    profile.copy(
                                        rootUseDefault = false,
                                        rootTemplate = selected,
                                        uid = info.uid,
                                        gid = info.gid,
                                        groups = info.groups,
                                        capabilities = info.capabilities,
                                        context = info.context,
                                        namespace = info.namespace,
                                    )
                                )
                            } else if (profile.rootTemplate != selected || profile.rootUseDefault) {
                                onProfileChange(
                                    profile.copy(
                                        rootUseDefault = false,
                                        rootTemplate = selected
                                    )
                                )
                            }
                            rootMode = Mode.Template
                        }
                    }
                }
            } else {
                onProfileChange(profile.copy(nonRootUseDefault = (mode == Mode.Default)))
            }
        }
        Spacer(Modifier.height(12.dp))

        AnimatedVisibility(
            visible = isRootGranted,
            enter = fadeIn() + expandVertically(),
            exit = fadeOut() + shrinkVertically()
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp)
                    .padding(bottom = if (rootMode != Mode.Default) 12.dp else 0.dp),
            ) {
                AnimatedVisibility(
                    visible = rootMode == Mode.Template,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
                    TemplateConfig(
                        profile = profile,
                        onViewTemplate = onViewTemplate,
                        onManageTemplate = onManageTemplate,
                        onProfileChange = onProfileChange
                    )
                }
                AnimatedVisibility(
                    visible = rootMode == Mode.Custom,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
                    RootProfileConfig(
                        fixedName = true,
                        enabled = rootMode == Mode.Custom,
                        profile = profile,
                        onProfileChange = onProfileChange
                    )
                }
            }
        }
        AnimatedVisibility(
            visible = !isRootGranted,
            enter = fadeIn() + expandVertically(),
            exit = fadeOut() + shrinkVertically()
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp)
                    .padding(bottom = if (nonRootMode != Mode.Default) 12.dp else 0.dp),
            ) {
                AnimatedVisibility(
                    visible = nonRootMode == Mode.Custom,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
                    AppProfileConfig(
                        fixedName = true,
                        profile = profile,
                        enabled = true,
                        onProfileChange = onProfileChange
                    )
                }
            }
        }

        if (isUidGroup) {
            SmallTitle(
                text = stringResource(R.string.app_profile_affects_following_apps),
                modifier = Modifier.padding(top = 4.dp)
            )
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp)
                    .padding(bottom = 12.dp),
            ) {
                Spacer(Modifier.height(3.dp))
                affectedApps.forEach { app ->
                    BasicComponent(
                        startAction = {
                            AppIconImage(
                                packageInfo = app.packageInfo,
                                label = app.label,
                                modifier = Modifier
                                    .padding(end = 1.dp)
                                    .size(48.dp)
                            )
                        },
                        title = app.label,
                        summary = app.displayIdentifier,
                        insideMargin = PaddingValues(start = 11.dp, end = 16.dp, top = 8.dp, bottom = 8.dp)
                    )
                }
                Spacer(Modifier.height(3.dp))
            }
        }
    }
}

@Composable
private fun TopBar(
    onBack: () -> Unit,
    showActions: Boolean = true,
    packageName: String,
    userId: Int,
    onLaunchApp: (String, Int) -> Unit = { _, _ -> },
    onForceStopApp: (String, Int) -> Unit = { _, _ -> },
    onRestartApp: (String, Int) -> Unit = { _, _ -> },
    scrollBehavior: ScrollBehavior,
    backdrop: LayerBackdrop?,
    barColor: Color,
) {
    BlurredBar(backdrop) {
        TopAppBar(
            color = barColor,
            title = stringResource(R.string.profile),
            navigationIcon = {
                IconButton(
                    onClick = onBack
                ) {
                    val layoutDirection = LocalLayoutDirection.current
                    Icon(
                        modifier = Modifier.graphicsLayer {
                            if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                        },
                        imageVector = MiuixIcons.Back,
                        contentDescription = null,
                        tint = colorScheme.onBackground
                    )
                }
            },
            actions = {
                if (showActions) {
                    val showTopPopup = remember { mutableStateOf(false) }
                    IconButton(
                        onClick = { showTopPopup.value = true },
                        holdDownState = showTopPopup.value
                    ) {
                        Icon(
                            imageVector = MiuixIcons.MoreCircle,
                            tint = colorScheme.onSurface,
                            contentDescription = stringResource(id = R.string.settings)
                        )
                    }
                    OverlayListPopup(
                        show = showTopPopup.value,
                        popupPositionProvider = ListPopupDefaults.MenuPositionProvider,
                        alignment = PopupPositionProvider.Align.TopEnd,
                        onDismissRequest = { showTopPopup.value = false },
                        content = {
                            ListPopupColumn {
                                val items = listOf(
                                    stringResource(id = R.string.launch_app),
                                    stringResource(id = R.string.force_stop_app),
                                    stringResource(id = R.string.restart_app)
                                )

                                items.forEachIndexed { index, text ->
                                    DropdownItem(
                                        text = text,
                                        optionSize = items.size,
                                        index = index,
                                        onSelectedIndexChange = { selectedIndex ->
                                            when (selectedIndex) {
                                                0 -> onLaunchApp(packageName, userId)
                                                1 -> onForceStopApp(packageName, userId)
                                                2 -> onRestartApp(packageName, userId)
                                            }
                                            showTopPopup.value = false
                                        }
                                    )
                                }
                            }
                        }
                    )
                }
            },
            scrollBehavior = scrollBehavior
        )
    }
}

@Composable
private fun ProfileBox(
    mode: Mode,
    hasTemplate: Boolean,
    onModeChange: (Mode) -> Unit,
) {
    val defaultText = stringResource(R.string.profile_default)
    val templateText = stringResource(R.string.profile_template)
    val customText = stringResource(R.string.profile_custom)
    val list =
        remember(hasTemplate, defaultText, templateText, customText) {
            buildList {
                add(defaultText)
                if (hasTemplate) {
                    add(templateText)
                }
                add(customText)
            }
        }

    val modesAndTitles = remember(hasTemplate, defaultText, templateText, customText) {
        buildList {
            add(Mode.Default to defaultText)
            if (hasTemplate) {
                add(Mode.Template to templateText)
            }
            add(Mode.Custom to customText)
        }
    }
    val selectedIndex = modesAndTitles.indexOfFirst { it.first == mode }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp),
    ) {
        OverlayDropdownPreference(
            title = stringResource(R.string.profile),
            items = list,
            startAction = {
                Icon(
                    Icons.Rounded.AccountCircle,
                    modifier = Modifier.padding(end = 6.dp),
                    contentDescription = null,
                    tint = colorScheme.onBackground
                )
            },
            selectedIndex = if (selectedIndex == -1) 0 else selectedIndex,
        ) {
            onModeChange(modesAndTitles[it].first)
        }
    }
}
/** Local decoration for the superuser card; other Miuix switches stay unchanged. */
@Composable
private fun SuperuserSwitch(checked: Boolean) {
    // Match the thumb geometry and spring in Miuix 0.9.4. Keep the icon in
    // logical start coordinates so that it follows the thumb in RTL as well.
    val thumbOffset by animateDpAsState(
        targetValue = if (checked) 25.dp else 4.dp,
        animationSpec = spring(dampingRatio = 0.7f, stiffness = 987f),
        label = "superuser_check_offset",
    )
    Box(Modifier.size(width = 49.dp, height = 28.dp)) {
        // The enclosing card owns the click action and switch semantics.
        Switch(checked = checked, onCheckedChange = null)
        if (checked) {
            Box(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .offset { IntOffset(thumbOffset.roundToPx(), 0) }
                    .size(20.dp),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Check,
                    contentDescription = null,
                    tint = colorScheme.primary,
                    modifier = Modifier.size(14.dp),
                )
            }
        }
    }
}
