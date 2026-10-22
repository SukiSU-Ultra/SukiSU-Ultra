package com.sukisu.ultra.ui.screen.appprofile

import com.sukisu.ultra.ui.component.profile.TemporaryRootControls
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.Crossfade
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.ButtonGroupDefaults
import androidx.compose.material3.DropdownMenuGroup
import androidx.compose.material3.SelectableDropdownMenuItem
import androidx.compose.material3.DropdownMenuPopup
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuDefaults
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.AppIconImage
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.ExpressiveToggleButton
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.ExpressiveSwitch
import com.sukisu.ultra.ui.component.material.SnackBarHost
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.component.profile.AppProfileConfig
import com.sukisu.ultra.ui.component.profile.RootProfileConfig
import com.sukisu.ultra.ui.component.profile.TemplateConfig
import com.sukisu.ultra.ui.component.statustag.StatusTag
import com.sukisu.ultra.ui.util.ownerNameForUid
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel

/**
 * @author weishu
 * @date 2023/5/16.
 */
@Composable
fun AppProfileScreenMaterial(
    state: AppProfileUiState,
    actions: AppProfileActions,
    snackBarHost: SnackbarHostState,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            TopBar(
                onBack = actions.onBack,
                scrollBehavior = scrollBehavior,
                isUidGroup = state.isUidGroup,
                showActions = !state.appGroup.primary.isWebViewZygote,
                packageName = state.packageName,
                userId = state.uid / 100000,
                onLaunchApp = actions.onLaunchApp,
                onForceStopApp = actions.onForceStopApp,
                onRestartApp = actions.onRestartApp,
            )
        },
        snackbarHost = { SnackBarHost(hostState = snackBarHost, modifier = Modifier.safeDrawingPadding()) },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { paddingValues ->
        AppProfileInner(
            modifier = Modifier
                .padding(paddingValues)
                .fillMaxHeight()
                .imePadding()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState()),
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
                    modifier = Modifier
                        .size(60.dp)
                        .clip(RoundedCornerShape(20.dp))
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

    val initialRootMode = if (profile.rootUseDefault) {
        Mode.Default
    } else if (profile.rootTemplate != null) {
        Mode.Template
    } else {
        Mode.Custom
    }
    var rootMode by rememberSaveable(profile) {
        mutableStateOf(initialRootMode)
    }
    val nonRootMode = if (profile.nonRootUseDefault) Mode.Default else Mode.Custom
    val mode = if (isRootGranted) rootMode else nonRootMode

    Column(modifier = modifier) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 8.dp),
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
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Black,
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
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                if (userId != 0) {
                    StatusTag(
                        label = "USER $userId",
                        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                        backgroundColor = MaterialTheme.colorScheme.tertiaryContainer
                    )
                }
                StatusTag(
                    label = "UID ${if (userId != 0) appId else appUid}",
                    contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                    backgroundColor = MaterialTheme.colorScheme.tertiaryContainer
                )
            }
        }

        if (isSpecialApp) {
            SegmentedColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                content = listOf {
                    SegmentedListItem(
                        headlineContent = { Text(stringResource(R.string.profile)) },
                        supportingContent = { Text(mode.text, color = MaterialTheme.colorScheme.onSurfaceVariant) },
                        leadingContent = { Icon(Icons.Filled.AccountCircle, null) },
                    )
                }
            )
        } else {
            RootSwitchCard(
                checked = isRootGranted,
                summary = if (isRootGranted && temporaryRoot) stringResource(R.string.temporary_root_active) else mode.text,
                onCheckedChange = onPermanentRootChange,
            )
        }

        if (!isSpecialApp) {
            TemporaryRootControls(
                enabled = temporaryRoot,
                granted = isRootGranted,
                onEnabledChange = onTemporaryRootChange,
                onChoose = onTemporaryRootGrant,
            )
        }

        Crossfade(targetState = isRootGranted, label = "") { current ->
            Column(
                modifier = Modifier.padding(bottom = 6.dp + 48.dp + 6.dp /* SnackBar height */)
            ) {
                if (current) {
                    ProfileBox(mode, true) {
                        // template mode shouldn't change profile here!
                        if (it == Mode.Default || it == Mode.Custom) {
                            onProfileChange(
                                profile.copy(
                                    rootUseDefault = it == Mode.Default,
                                    rootTemplate = null
                                )
                            )
                        }
                        rootMode = it
                    }
                    AnimatedVisibility(
                        visible = mode == Mode.Template,
                        enter = expandVertically() + fadeIn(),
                        exit = shrinkVertically() + fadeOut()
                    ) {
                        TemplateConfig(
                            profile = profile,
                            onViewTemplate = onViewTemplate,
                            onManageTemplate = onManageTemplate,
                            onProfileChange = onProfileChange
                        )
                    }
                    AnimatedVisibility(
                        visible = mode == Mode.Custom,
                        enter = expandVertically() + fadeIn(),
                        exit = shrinkVertically() + fadeOut()
                    ) {
                        RootProfileConfig(
                            fixedName = true,
                            enabled = mode == Mode.Custom,
                            profile = profile,
                            onProfileChange = onProfileChange
                        )
                    }
                } else {
                    ProfileBox(mode, false) {
                        onProfileChange(profile.copy(nonRootUseDefault = (it == Mode.Default)))
                    }
                    AnimatedVisibility(
                        visible = true,
                        enter = expandVertically() + fadeIn(),
                        exit = shrinkVertically() + fadeOut()
                    ) {
                        AppProfileConfig(
                            fixedName = true,
                            profile = profile,
                            enabled = mode == Mode.Custom,
                            onProfileChange = onProfileChange
                        )
                    }
                }
                if (isUidGroup) {
                    val appItems = affectedApps.map<SuperUserViewModel.AppInfo, @Composable () -> Unit> { app ->
                        {
                            SegmentedListItem(
                                headlineContent = { Text(app.label) },
                                supportingContent = { Text(app.displayIdentifier) },
                                leadingContent = {
                                    AppIconImage(
                                        packageInfo = app.packageInfo,
                                        label = app.label,
                                        modifier = Modifier.size(36.dp)
                                    )
                                }
                            )
                        }
                    }
                    SegmentedColumn(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        title = stringResource(R.string.app_profile_affects_following_apps),
                        content = appItems
                    )
                }
            }
        }
    }
}

@Composable
private fun RootSwitchCard(
    checked: Boolean,
    summary: String,
    onCheckedChange: (Boolean) -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    val containerColor by animateColorAsState(
        if (checked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceBright,
        label = "root_card_container"
    )
    val contentColor by animateColorAsState(
        if (checked) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface,
        label = "root_card_content"
    )
    Surface(
        checked = checked,
        onCheckedChange = {
            haptic.performHapticFeedback(HapticFeedbackType.VirtualKey)
            onCheckedChange(it)
        },
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        shape = MaterialTheme.shapes.large,
        color = containerColor,
        contentColor = contentColor,
    ) {
        Row(
            modifier = Modifier
                .heightIn(min = 76.dp)
                .padding(horizontal = 20.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.superuser),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodySmall,
                    color = contentColor.copy(alpha = 0.75f),
                )
            }
            ExpressiveSwitch(
                checked = checked,
                onCheckedChange = null,
            )
        }
    }
}

@Composable
private fun TopBar(
    onBack: () -> Unit,
    scrollBehavior: TopAppBarScrollBehavior? = null,
    isUidGroup: Boolean = false,
    showActions: Boolean = true,
    packageName: String = "",
    userId: Int = 0,
    onLaunchApp: (String, Int) -> Unit,
    onForceStopApp: (String, Int) -> Unit,
    onRestartApp: (String, Int) -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    LargeFlexibleTopAppBar(
        title = { Text(stringResource(R.string.profile)) },
        navigationIcon = {
            TopBarBackButton(onClick = onBack)
        },
        actions = {
            if (!isUidGroup && showActions) {
                var showDropdown by remember { mutableStateOf(false) }

                IconButton(
                    onClick = { showDropdown = true },
                ) {
                    Icon(
                        imageVector = Icons.Filled.MoreVert,
                        contentDescription = stringResource(id = R.string.settings)
                    )
                    DropdownMenuPopup(
                        expanded = showDropdown,
                        onDismissRequest = { showDropdown = false }
                    ) {
                        val menuItems = listOf(
                            R.string.launch_app to onLaunchApp,
                            R.string.force_stop_app to onForceStopApp,
                            R.string.restart_app to onRestartApp,
                        )
                        DropdownMenuGroup(shapes = MenuDefaults.groupShapes()) {
                            menuItems.forEachIndexed { index, (resId, action) ->
                                SelectableDropdownMenuItem(
                                    selected = false,
                                    onClick = {
                                        haptic.performHapticFeedback(HapticFeedbackType.VirtualKey)
                                        showDropdown = false
                                        action(packageName, userId)
                                    },
                                    text = { Text(stringResource(id = resId)) },
                                    shapes = MenuDefaults.itemShape(index = index, count = menuItems.size),
                                )
                            }
                        }
                    }
                }
            }
        },
        colors = expressiveTopAppBarColors(),
        windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        scrollBehavior = scrollBehavior
    )
}

@Composable
private fun ProfileBox(
    mode: Mode,
    hasTemplate: Boolean,
    onModeChange: (Mode) -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(ButtonGroupDefaults.ConnectedSpaceBetween),
    ) {
        val options = listOf(
            Mode.Default to stringResource(R.string.profile_default),
            Mode.Template to stringResource(R.string.profile_template),
            Mode.Custom to stringResource(R.string.profile_custom),
        )

        options.forEachIndexed { index, (m, label) ->
            ExpressiveToggleButton(
                checked = mode == m,
                onCheckedChange = { checked ->
                    if (checked && (m != Mode.Template || hasTemplate)) {
                        haptic.performHapticFeedback(HapticFeedbackType.ContextClick)
                        onModeChange(m)
                    }
                },
                enabled = if (m == Mode.Template) hasTemplate else true,
                modifier = Modifier
                    .weight(1f)
                    .semantics { role = Role.RadioButton },
                shapes = when (index) {
                    0 -> ButtonGroupDefaults.connectedLeadingButtonShapes()
                    options.lastIndex -> ButtonGroupDefaults.connectedTrailingButtonShapes()
                    else -> ButtonGroupDefaults.connectedMiddleButtonShapes()
                },
            ) {
                Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Preview
@Composable
private fun AppProfilePreview() {
    var profile by remember { mutableStateOf(Natives.Profile("")) }
    AppProfileInner(
        packageName = "icu.nullptr.test",
        appLabel = "Test",
        appIcon = { Icon(Icons.Filled.Android, null) },
        appUid = 1,
        appVersionName = "v1.0.0",
        appVersionCode = 12345,
        profile = profile,
        onProfileChange = {
            profile = it
        },
    )
}
