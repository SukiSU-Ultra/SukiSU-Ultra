package com.sukisu.nova.ui.screen.builtinzygisk

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Extension
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.nova.R
import com.sukisu.nova.ui.component.miuix.AppCard
import com.sukisu.nova.ui.component.miuix.AppScaffold
import com.sukisu.nova.ui.theme.LocalBackgroundImagePath
import com.sukisu.nova.ui.theme.LocalEnableBlur
import com.sukisu.nova.ui.util.BlurredBar
import com.sukisu.nova.ui.util.CustomTextKey
import com.sukisu.nova.ui.util.InjectedZygiskModule
import com.sukisu.nova.ui.util.customText
import com.sukisu.nova.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.textStyles
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun BuiltinZygiskMiuix(
    uiState: BuiltinZygiskUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onSwitch: (String, String) -> Unit,
    onToggleInjected: (String) -> Unit,
    onSetOption: (String, String) -> Unit,
    onToggleGroup: () -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive || hasCustomBackground) Color.Transparent else colorScheme.surface

    AppScaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    title = customText(CustomTextKey.ZYGISK_DASHBOARD_TITLE),
                    color = barColor,
                    navigationIcon = {
                        IconButton(onClick = onBack) {
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
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .then(if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier)
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 32.dp),
        ) {
            item {
                val status = uiState.status

                // One card: the live state first, then the modules each daemon is serving.
                AppCard(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 20.dp, end = 8.dp, top = 4.dp, bottom = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = stringResource(R.string.builtin_zygisk_status_title),
                            style = textStyles.title4,
                            color = colorScheme.primary,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(onClick = onRefresh) {
                            Icon(
                                imageVector = MiuixIcons.Refresh,
                                contentDescription = null,
                                tint = colorScheme.onBackground,
                            )
                        }
                    }

                    HorizontalDivider()
                    BasicComponent(
                        title = stringResource(R.string.builtin_zygisk_monitor_status),
                        summary = status.monitor?.label
                            ?: stringResource(R.string.builtin_zygisk_status_stopped),
                        endActions = {
                            StatusChipMiuix(
                                text = stringResource(
                                    if (status.monitorRunning) {
                                        R.string.builtin_zygisk_status_running
                                    } else {
                                        R.string.builtin_zygisk_status_stopped
                                    }
                                ),
                                ok = status.monitorRunning
                            )
                        }
                    )

                    // One row per zygote ABI: which zygotes actually carry the loader.
                    status.zygotes.forEach { zygote ->
                        HorizontalDivider()
                        BasicComponent(
                            title = stringResource(R.string.builtin_zygisk_zygote_status, zygote.abi),
                            endActions = {
                                StatusChipMiuix(
                                    text = stringResource(zygoteStateText(zygote.status)),
                                    ok = zygote.status == "injected"
                                )
                            }
                        )
                    }

                    HorizontalDivider()
                    BasicComponent(
                        title = stringResource(R.string.builtin_zygisk_daemon_status),
                        summary = status.daemons
                            .takeIf { it.isNotEmpty() }
                            ?.joinToString("\n") { it.label }
                            ?: stringResource(R.string.builtin_zygisk_status_stopped),
                        endActions = {
                            StatusChipMiuix(
                                text = stringResource(
                                    if (status.daemonRunning) {
                                        R.string.builtin_zygisk_status_running
                                    } else {
                                        R.string.builtin_zygisk_status_stopped
                                    }
                                ),
                                ok = status.daemonRunning
                            )
                        }
                    )

                    if (uiState.injectedModules.isEmpty()) {
                        HorizontalDivider()
                        BasicComponent(
                            title = stringResource(R.string.builtin_zygisk_injected_empty)
                        )
                    }

                    if (uiState.injectedModules.isNotEmpty()) {
                        HorizontalDivider()
                        GroupRowMiuix(
                            title = stringResource(
                                R.string.builtin_zygisk_injected_group,
                                uiState.injectedModules.size
                            ),
                            expanded = uiState.injectedGroupExpanded,
                            onClick = onToggleGroup
                        )
                        if (uiState.injectedGroupExpanded) {
                            uiState.injectedModules.forEach { module ->
                                val isNext = module.type == "next"
                                val isExpanded = isNext &&
                                    uiState.expandedInjectedId == module.id
                                val chevronRotation by animateFloatAsState(
                                    targetValue = if (isExpanded) 180f else 0f,
                                    label = "moduleChevron"
                                )
                                HorizontalDivider()
                                BasicComponent(
                                    title = module.name,
                                    summary = buildString {
                                        append(moduleSummaryMiuix(module))
                                        if (module.targets.isNotEmpty()) {
                                            append("\n").append(
                                                stringResource(
                                                    R.string.builtin_zygisk_targets,
                                                    module.targets.joinToString(", ")
                                                )
                                            )
                                        }
                                    },
                                    onClick = if (isNext) {
                                        { onToggleInjected(module.id) }
                                    } else {
                                        null
                                    },
                                    endActions = {
                                        if (isNext && module.processes.isNotEmpty()) {
                                            ZygiskBadgeMiuix(
                                                stringResource(
                                                    R.string.builtin_zygisk_process_count,
                                                    module.processes.size
                                                ),
                                                primary = true
                                            )
                                            Spacer(Modifier.width(6.dp))
                                        }
                                        module.abi.forEach { abi ->
                                            ZygiskBadgeMiuix(abi, primary = false)
                                            Spacer(Modifier.width(4.dp))
                                        }
                                        if (isNext) {
                                            androidx.compose.material3.Icon(
                                                imageVector = Icons.Rounded.ExpandMore,
                                                contentDescription = null,
                                                tint = colorScheme.onSurfaceVariantSummary,
                                                modifier = Modifier.rotate(chevronRotation)
                                            )
                                        }
                                    }
                                )
                                if (isExpanded) {
                                    if (module.processes.isEmpty()) {
                                        HorizontalDivider()
                                        BasicComponent(
                                            title = stringResource(R.string.builtin_zygisk_no_processes),
                                            modifier = Modifier.padding(start = 16.dp)
                                        )
                                    } else {
                                        module.processes.forEach { process ->
                                            HorizontalDivider()
                                            BasicComponent(
                                                title = process.name,
                                                modifier = Modifier.padding(start = 16.dp),
                                                endActions = {
                                                    PidTagMiuix(process.pid)
                                                }
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item {
                Text(
                    text = stringResource(R.string.builtin_zygisk_options_title),
                    style = textStyles.title4,
                    color = colorScheme.primary,
                    modifier = Modifier.padding(start = 12.dp, bottom = 4.dp)
                )
                Text(
                    text = stringResource(R.string.builtin_zygisk_options_hint),
                    style = textStyles.footnote1,
                    color = colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(start = 12.dp, bottom = 8.dp)
                )

                AppCard(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    SwitchPreference(
                        title = stringResource(R.string.builtin_zygisk_opt_anonymous_memory),
                        summary = stringResource(R.string.builtin_zygisk_opt_anonymous_memory_summary),
                        checked = uiState.config.anonymousMemory,
                        onCheckedChange = { onSetOption("anonymous_memory", if (it) "1" else "0") }
                    )
                    SwitchPreference(
                        title = stringResource(R.string.builtin_zygisk_opt_custom_linker),
                        summary = stringResource(R.string.builtin_zygisk_opt_custom_linker_summary),
                        checked = uiState.config.customLinker,
                        onCheckedChange = { onSetOption("custom_linker", if (it) "1" else "0") }
                    )
                    SwitchPreference(
                        title = stringResource(R.string.builtin_zygisk_opt_lsplt),
                        summary = stringResource(R.string.builtin_zygisk_opt_lsplt_summary),
                        checked = uiState.config.pltEngine == "lsplt",
                        onCheckedChange = { onSetOption("plt_engine", if (it) "lsplt" else "bytehook") }
                    )
                }
            }

            item {
                Text(
                    text = stringResource(R.string.builtin_zygisk_modules_title),
                    style = textStyles.title4,
                    color = colorScheme.primary,
                    modifier = Modifier.padding(start = 12.dp, bottom = 4.dp)
                )
                Text(
                    text = stringResource(R.string.builtin_zygisk_impl_hint),
                    style = textStyles.footnote1,
                    color = colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(start = 12.dp, bottom = 8.dp)
                )
            }

            if (uiState.zygiskModules.isEmpty()) {
                item {
                    AppCard(
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = stringResource(R.string.builtin_zygisk_no_modules),
                            style = textStyles.body2,
                            color = colorScheme.onBackground.copy(alpha = 0.75f),
                            modifier = Modifier.padding(24.dp)
                        )
                    }
                }
            } else {
                item {
                    AppCard(
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        val providers = uiState.implementation.providers
                        val currentId = uiState.implementation.id
                        val primaryColor = androidx.compose.material3.MaterialTheme.colorScheme.primary
                        val errorColor = androidx.compose.material3.MaterialTheme.colorScheme.error
                        uiState.zygiskModules.forEachIndexed { index, module ->
                            val isProvider = providers.contains(module.id)
                            val isCurrent = module.id == currentId &&
                                uiState.implementation.state == "running"
                            if (index > 0) HorizontalDivider()
                            val moduleSummary = buildString {
                                append("${module.version} (${module.author})\n")
                                if (module.suppressedByBuiltin) {
                                    append(stringResource(R.string.builtin_zygisk_suppressed_hint))
                                } else if (module.description.isNotEmpty()) {
                                    append(module.description)
                                }
                            }.trimEnd()
                            val isSuppressed = module.suppressedByBuiltin
                            val suppressedTag = stringResource(R.string.module_suppressed_by_builtin)
                            val errorContainerColor = androidx.compose.material3.MaterialTheme.colorScheme.errorContainer
                            val onErrorContainerColor = androidx.compose.material3.MaterialTheme.colorScheme.onErrorContainer

                            BasicComponent(
                                title = module.name,
                                summary = moduleSummary,
                                onClick = if (isProvider && !isCurrent) {
                                    { onSwitch(module.id, module.name) }
                                } else {
                                    null
                                },
                                startAction = {
                                    androidx.compose.material3.Icon(
                                        imageVector = Icons.Rounded.Extension,
                                        contentDescription = null,
                                        tint = if (isSuppressed) errorColor else primaryColor,
                                        modifier = Modifier.padding(end = 12.dp)
                                    )
                                },
                                endActions = {
                                    if (isSuppressed) {
                                        Box(
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(4.dp))
                                                .background(errorContainerColor)
                                                .padding(horizontal = 6.dp, vertical = 2.dp)
                                        ) {
                                            Text(
                                                text = suppressedTag,
                                                style = textStyles.body2,
                                                color = onErrorContainerColor
                                            )
                                        }
                                    }
                                    if (isCurrent) {
                                        androidx.compose.material3.Icon(
                                            imageVector = Icons.Rounded.CheckCircle,
                                            contentDescription = null,
                                            tint = primaryColor
                                        )
                                    }
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

/// A small label for the module API and its ABIs, matching the Material rows.
@Composable
private fun ZygiskBadgeMiuix(text: String, primary: Boolean) {
    val colors = androidx.compose.material3.MaterialTheme.colorScheme
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (primary) colors.secondaryContainer else colors.surfaceVariant)
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(
            text = text,
            style = textStyles.body2,
            color = if (primary) colors.onSecondaryContainer else colors.onSurfaceVariant
        )
    }
}

/// The tag carrying a process id: Miuix labels are rounded rectangles, not pills.
@Composable
private fun PidTagMiuix(pid: Int) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(colorScheme.surfaceContainerHigh)
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(
            text = "PID $pid",
            style = textStyles.footnote1,
            color = colorScheme.onSurfaceVariantSummary
        )
    }
}

/// A collapsible group of served modules inside the status card.
@Composable
private fun GroupRowMiuix(title: String, expanded: Boolean, onClick: () -> Unit) {
    val rotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        label = "groupChevron"
    )
    BasicComponent(
        title = title,
        onClick = onClick,
        endActions = {
            androidx.compose.material3.Icon(
                imageVector = Icons.Rounded.ExpandMore,
                contentDescription = null,
                tint = colorScheme.onSurfaceVariantSummary,
                modifier = Modifier.rotate(rotation)
            )
        }
    )
}

/// The version and state line shared by both module groups.
@Composable
private fun moduleSummaryMiuix(module: InjectedZygiskModule): String =
    listOf(module.version, stringResource(injectedStateText(module.state)))
        .filter { it.isNotEmpty() }
        .joinToString(" · ")

/// The rounded state chip of the live rows.
@Composable
private fun StatusChipMiuix(text: String, ok: Boolean) {
    val colors = androidx.compose.material3.MaterialTheme.colorScheme
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(if (ok) colors.primaryContainer else colors.errorContainer)
            .padding(horizontal = 10.dp, vertical = 4.dp)
    ) {
        Text(
            text = text,
            style = textStyles.body2,
            color = if (ok) colors.onPrimaryContainer else colors.onErrorContainer
        )
    }
}
