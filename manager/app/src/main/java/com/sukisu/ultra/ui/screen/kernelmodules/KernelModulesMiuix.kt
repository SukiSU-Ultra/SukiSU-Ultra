package com.sukisu.ultra.ui.screen.kernelmodules

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.WarningLevel
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.component.miuix.WarningCard
import com.sukisu.ultra.ui.component.statustag.StatusTag
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Copy
import top.yukonga.miuix.kmp.icon.extended.ExpandLess
import top.yukonga.miuix.kmp.icon.extended.ExpandMore
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.textStyles
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun KernelModulesMiuix(
    state: KernelModulesUiState,
    actions: KernelModulesActions,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive || hasCustomBackground) Color.Transparent else colorScheme.surface

    AppScaffold(
        topBar = {
            BlurredBar(backdrop, scrollBehavior = scrollBehavior) {
                TopAppBar(
                    title = stringResource(R.string.kernel_modules_title),
                    color = barColor,
                    navigationIcon = {
                        IconButton(onClick = actions.onBack) {
                            val layoutDirection = LocalLayoutDirection.current
                            Icon(
                                modifier = Modifier.graphicsLayer {
                                    if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                                },
                                imageVector = MiuixIcons.Back,
                                contentDescription = null,
                                tint = colorScheme.onBackground,
                            )
                        }
                    },
                    actions = {
                        IconButton(onClick = actions.onRefresh, enabled = !state.isLoading) {
                            Icon(
                                imageVector = MiuixIcons.Refresh,
                                contentDescription = stringResource(R.string.refresh),
                                tint = colorScheme.onBackground,
                            )
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
    ) { padding ->
        when {
            state.snapshot == null && state.isLoading -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator()
                }
            }

            state.snapshot == null -> {
                ErrorStateMiuix(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding),
                    onRetry = actions.onRefresh,
                )
            }

            else -> {
                val snapshot = state.snapshot
                val isEmpty = snapshot.entries.isEmpty() &&
                    snapshot.suggestedNames.isEmpty() &&
                    snapshot.paramsNames.isEmpty() &&
                    snapshot.hiddenDeviceBlocklistCount == 0
                // An unreadable source must never look like "nothing is blocked".
                if (isEmpty && snapshot.activeAvailable && snapshot.configAvailable) {
                    EmptyStateMiuix(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding),
                    )
                    return@AppScaffold
                }

                val sourceNotice = kernelModulesSourceNotice(snapshot)

                LazyColumn(
                    modifier = Modifier
                        .then(if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier)
                        .fillMaxHeight()
                        .scrollEndHaptic()
                        .overScrollVertical()
                        .nestedScroll(scrollBehavior.nestedScrollConnection)
                        .padding(horizontal = 12.dp),
                    contentPadding = padding,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    overscrollEffect = null,
                ) {
                    item(key = "summary") {
                        SummaryCardMiuix(snapshot)
                    }

                    if (sourceNotice != null) {
                        item(key = "source-notice") {
                            WarningCard(
                                message = sourceNotice,
                                modifier = Modifier.fillMaxWidth(),
                                level = WarningLevel.Notice,
                            )
                        }
                    }

                    if (!snapshot.dependencyDataAvailable) {
                        item(key = "dependency-notice") {
                            WarningCard(
                                message = stringResource(R.string.kernel_modules_dependency_unavailable),
                                modifier = Modifier.fillMaxWidth(),
                                level = WarningLevel.Notice,
                            )
                        }
                    }

                    if (snapshot.hiddenDeviceBlocklistCount > 0) {
                        item(key = "hidden-device-blocklist") {
                            WarningCard(
                                message = pluralStringResource(
                                    R.plurals.kernel_modules_device_blocklist_hidden,
                                    snapshot.hiddenDeviceBlocklistCount,
                                    snapshot.hiddenDeviceBlocklistCount,
                                ),
                                modifier = Modifier.fillMaxWidth(),
                                level = WarningLevel.Notice,
                            )
                        }
                    }

                    if (state.failed) {
                        item(key = "error-banner") {
                            WarningCard(
                                message = stringResource(R.string.kernel_modules_load_failed),
                                modifier = Modifier.fillMaxWidth(),
                                level = WarningLevel.Error,
                            )
                        }
                    }

                    if (snapshot.entries.isNotEmpty()) {
                        item(key = "blocked-title") {
                            SmallTitle(
                                text = stringResource(R.string.kernel_modules_section_blocked),
                                modifier = Modifier.padding(top = 4.dp),
                                insideMargin = PaddingValues(start = 16.dp, bottom = 8.dp),
                            )
                        }
                        items(snapshot.entries, key = { it.name }) { entry ->
                            ModuleCardMiuix(
                                entry = entry,
                                expanded = entry.name in state.expanded,
                                activeAvailable = snapshot.activeAvailable,
                                dependencyDataAvailable = snapshot.dependencyDataAvailable,
                                onToggle = { actions.onToggleExpanded(entry.name) },
                            )
                        }
                    }

                    if (snapshot.suggestedNames.isNotEmpty()) {
                        item(key = "suggested-title") {
                            SmallTitle(
                                text = stringResource(R.string.kernel_modules_section_suggested),
                                modifier = Modifier.padding(top = 4.dp),
                                insideMargin = PaddingValues(start = 16.dp, bottom = 8.dp),
                            )
                        }
                        item(key = "suggested") {
                            SuggestedCardMiuix(snapshot.suggestedNames)
                        }
                    }

                    item(key = "params-title") {
                        SmallTitle(
                            text = stringResource(R.string.kernel_modules_section_params),
                            modifier = Modifier.padding(top = 4.dp),
                            insideMargin = PaddingValues(start = 16.dp, bottom = 8.dp),
                        )
                    }
                    item(key = "params") {
                        ParamsCardMiuix(snapshot, actions.onCopy)
                    }

                    item(key = "bottom-inset") {
                        Spacer(
                            Modifier.height(
                                WindowInsets.navigationBars
                                    .asPaddingValues()
                                    .calculateBottomPadding() + 4.dp,
                            ),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryCardMiuix(snapshot: KernelModulesSnapshot) {
    val count = if (snapshot.activeAvailable) {
        snapshot.activeNames.size
    } else {
        snapshot.configuredNames.size
    }
    val countText = if (snapshot.activeAvailable) {
        pluralStringResource(R.plurals.kernel_modules_summary_count, count, count)
    } else {
        pluralStringResource(R.plurals.kernel_modules_summary_configured, count, count)
    }
    AppCard(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 12.dp),
        insideMargin = PaddingValues(20.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(52.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(colorScheme.primaryContainer),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Memory,
                    contentDescription = null,
                    modifier = Modifier.size(26.dp),
                    tint = colorScheme.onPrimaryContainer,
                )
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = countText,
                    style = textStyles.title2,
                    color = colorScheme.onSurface,
                )
                Text(
                    text = stringResource(
                        R.string.kernel_modules_summary_details,
                        snapshot.configuredNames.size,
                        snapshot.currentlyLoadedCount,
                    ),
                    style = textStyles.body2,
                    color = colorScheme.onSurfaceVariantSummary,
                )
                if (snapshot.affectedBootModules > 0) {
                    Text(
                        text = pluralStringResource(
                            R.plurals.kernel_modules_summary_affected,
                            snapshot.affectedBootModules,
                            snapshot.affectedBootModules,
                        ),
                        style = textStyles.body2,
                        color = colorScheme.primary,
                    )
                }
                val deviceOnlyCount = snapshot.entries.count {
                    it.deviceBlocklist && !it.active && !it.configured
                }
                if (deviceOnlyCount > 0) {
                    Text(
                        text = pluralStringResource(
                            R.plurals.kernel_modules_summary_device,
                            deviceOnlyCount,
                            deviceOnlyCount,
                        ),
                        style = textStyles.body2,
                        color = colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        }
    }
}

@Composable
private fun ModuleCardMiuix(
    entry: KernelModuleEntry,
    expanded: Boolean,
    activeAvailable: Boolean,
    dependencyDataAvailable: Boolean,
    onToggle: () -> Unit,
) {
    val (badgeBackground, badgeContent) = statusColorsMiuix(entry.status)
    AppCard(modifier = Modifier.fillMaxWidth()) {
        BasicComponent(
            title = entry.name,
            summary = kernelModuleSummary(entry, activeAvailable),
            startAction = { ModuleIconMiuix() },
            endActions = {
                StatusTag(
                    label = kernelModuleStatusText(entry.status, activeAvailable),
                    backgroundColor = badgeBackground,
                    contentColor = badgeContent,
                )
                Spacer(Modifier.width(6.dp))
                Icon(
                    imageVector = if (expanded) MiuixIcons.ExpandLess else MiuixIcons.ExpandMore,
                    contentDescription = stringResource(
                        if (expanded) {
                            R.string.kernel_modules_collapse
                        } else {
                            R.string.kernel_modules_expand
                        },
                    ),
                    modifier = Modifier.size(16.dp),
                    tint = colorScheme.onSurfaceVariantActions,
                )
            },
            onClick = onToggle,
        )
        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically() + fadeIn(),
            exit = shrinkVertically() + fadeOut(),
        ) {
            DependencyDetailsMiuix(
                entry = entry,
                dependencyDataAvailable = dependencyDataAvailable,
            )
        }
    }
}

@Composable
private fun ModuleIconMiuix() {
    Box(
        modifier = Modifier
            .padding(end = 8.dp)
            .size(36.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(colorScheme.secondaryContainer),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = Icons.Rounded.Memory,
            contentDescription = null,
            modifier = Modifier.size(20.dp),
            tint = colorScheme.onSecondaryContainer,
        )
    }
}

@Composable
private fun DependencyDetailsMiuix(
    entry: KernelModuleEntry,
    dependencyDataAvailable: Boolean,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        HorizontalDivider(
            thickness = 0.5.dp,
            color = colorScheme.outline.copy(alpha = 0.5f),
        )
        Text(
            text = stringResource(R.string.kernel_modules_dependents_title),
            style = textStyles.footnote1,
            color = colorScheme.onSurfaceVariantSummary,
        )
        when {
            !dependencyDataAvailable -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_unavailable),
                    style = textStyles.body2,
                    color = colorScheme.onSurfaceVariantSummary,
                )
            }

            entry.path == null -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_not_in_table),
                    style = textStyles.body2,
                    color = colorScheme.onSurfaceVariantSummary,
                )
            }

            entry.dependents.isEmpty() -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_empty),
                    style = textStyles.body2,
                    color = colorScheme.onSurfaceVariantSummary,
                )
            }

            else -> {
                entry.dependents.forEach { dependent ->
                    DependentRowMiuix(dependent)
                }
            }
        }
        val impacted = if (entry.active) {
            entry.dependents
                .filter { it.boot && !it.loaded && !it.blocked }
                .map { it.name }
        } else {
            emptyList()
        }
        when {
            impacted.isNotEmpty() -> {
                Text(
                    text = stringResource(
                        R.string.kernel_modules_dependents_impacted,
                        impacted.joinToString(", "),
                    ),
                    style = textStyles.body2,
                    color = colorScheme.error,
                )
            }

            entry.active && entry.dependents.any { !it.loaded && !it.blocked } -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_warning),
                    style = textStyles.body2,
                    color = colorScheme.error,
                )
            }

            entry.configured && entry.dependents.any { it.boot && !it.loaded && !it.blocked } -> {
                Text(
                    text = stringResource(R.string.kernel_modules_dependents_warning_pending),
                    style = textStyles.body2,
                    color = colorScheme.error,
                )
            }
        }
        entry.path?.let { path ->
            Text(
                text = path,
                style = textStyles.footnote2,
                color = colorScheme.onSurfaceVariantSummary,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun DependentRowMiuix(dependent: KernelModuleDependent) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = dependent.name,
            modifier = Modifier.weight(1f),
            style = textStyles.body2,
            fontFamily = FontFamily.Monospace,
            color = colorScheme.onSurface,
        )
        when {
            dependent.loaded -> StatusTag(
                label = stringResource(R.string.kernel_modules_dependents_loaded),
                backgroundColor = colorScheme.secondaryContainer,
                contentColor = colorScheme.onSecondaryContainer,
            )

            dependent.blocked -> StatusTag(
                label = stringResource(R.string.kernel_modules_dependents_blocked),
                backgroundColor = colorScheme.surfaceContainerHigh,
                contentColor = colorScheme.onSurfaceContainerHigh,
            )

            dependent.boot -> StatusTag(
                label = stringResource(R.string.kernel_modules_dependents_boot),
                backgroundColor = colorScheme.tertiaryContainer,
                contentColor = colorScheme.onTertiaryContainer,
            )
        }
    }
}

@Composable
private fun SuggestedCardMiuix(names: List<String>) {
    AppCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.kernel_modules_suggested_summary),
                style = textStyles.body2,
                color = colorScheme.onSurfaceVariantSummary,
            )
            Text(
                text = names.joinToString(", "),
                style = textStyles.body2,
                fontFamily = FontFamily.Monospace,
                color = colorScheme.onSurface,
            )
        }
    }
}

@Composable
private fun ParamsCardMiuix(
    snapshot: KernelModulesSnapshot,
    onCopy: (String) -> Unit,
) {
    AppCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            if (snapshot.paramsNames.isEmpty()) {
                Text(
                    text = stringResource(R.string.kernel_modules_params_empty),
                    style = textStyles.body2,
                    color = colorScheme.onSurface,
                )
            } else {
                ParameterRowMiuix(
                    label = stringResource(R.string.kernel_modules_params_config),
                    value = snapshot.paramsConfigLine,
                    onCopy = onCopy,
                )
                HorizontalDivider(
                    thickness = 0.5.dp,
                    color = colorScheme.outline.copy(alpha = 0.5f),
                )
                ParameterRowMiuix(
                    label = stringResource(R.string.kernel_modules_params_cli),
                    value = snapshot.paramsCliLine,
                    onCopy = onCopy,
                )
                if (snapshot.paramsTooLong) {
                    Text(
                        text = stringResource(R.string.kernel_modules_params_too_long),
                        style = textStyles.body2,
                        color = colorScheme.error,
                    )
                }
            }
            if (snapshot.paramsNames.isNotEmpty()) {
                Text(
                    text = stringResource(kernelModulesParamsSourceLabel(snapshot.paramsSource)),
                    style = textStyles.body2,
                    color = colorScheme.onSurfaceVariantSummary,
                )
            }
            Text(
                text = stringResource(R.string.kernel_modules_params_note),
                style = textStyles.footnote1,
                color = colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

@Composable
private fun ParameterRowMiuix(
    label: String,
    value: String,
    onCopy: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            text = label,
            style = textStyles.footnote2,
            color = colorScheme.onSurfaceVariantSummary,
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = value,
                modifier = Modifier.weight(1f),
                style = textStyles.body2,
                fontFamily = FontFamily.Monospace,
                color = colorScheme.onSurface,
            )
            IconButton(
                onClick = { onCopy(value) },
                minHeight = 36.dp,
                minWidth = 36.dp,
            ) {
                Icon(
                    imageVector = MiuixIcons.Copy,
                    contentDescription = stringResource(R.string.kernel_modules_params_copy),
                    modifier = Modifier.size(18.dp),
                    tint = colorScheme.primary,
                )
            }
        }
    }
}

@Composable
private fun statusColorsMiuix(status: KernelModuleStatus): Pair<Color, Color> = when (status) {
    KernelModuleStatus.Blocked ->
        colorScheme.secondaryContainer to colorScheme.onSecondaryContainer

    KernelModuleStatus.BlockedLoaded ->
        colorScheme.errorContainer to colorScheme.onErrorContainer

    KernelModuleStatus.ConfigPending ->
        colorScheme.tertiaryContainer to colorScheme.onTertiaryContainer

    KernelModuleStatus.DeviceBlocklist ->
        colorScheme.surfaceContainerHigh to colorScheme.onSurfaceContainerHigh

    KernelModuleStatus.NotFound ->
        colorScheme.surfaceContainerHigh to colorScheme.onSurfaceContainerVariant
}

@Composable
private fun EmptyStateMiuix(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
    ) {
        Icon(
            imageVector = Icons.Rounded.Memory,
            contentDescription = null,
            modifier = Modifier.size(40.dp),
            tint = colorScheme.onSurfaceVariantSummary,
        )
        Text(
            text = stringResource(R.string.kernel_modules_empty_title),
            style = textStyles.title3,
        )
        Text(
            text = stringResource(R.string.kernel_modules_empty_summary),
            style = textStyles.body2,
            color = colorScheme.onSurfaceVariantSummary,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun ErrorStateMiuix(
    modifier: Modifier = Modifier,
    onRetry: () -> Unit,
) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
    ) {
        Text(
            text = stringResource(R.string.kernel_modules_load_failed),
            style = textStyles.title3,
            textAlign = TextAlign.Center,
        )
        TextButton(
            text = stringResource(R.string.kernel_modules_retry),
            onClick = onRetry,
        )
    }
}
