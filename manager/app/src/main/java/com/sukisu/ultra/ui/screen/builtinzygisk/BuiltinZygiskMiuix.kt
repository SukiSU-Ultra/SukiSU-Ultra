package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Extension
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BUILTIN_ZYGISK_TARGET
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
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
    onToggleProcesses: (String) -> Unit,
    onToggleInjected: (String) -> Unit,
    onSetOption: (String, String) -> Unit,
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
                    title = stringResource(R.string.settings_builtin_zygisk_dashboard),
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
                    actions = {
                        IconButton(onClick = onRefresh) {
                            Icon(
                                imageVector = MiuixIcons.Refresh,
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
                Text(
                    text = stringResource(R.string.builtin_zygisk_status_title),
                    style = textStyles.title4,
                    color = colorScheme.primary,
                    modifier = Modifier.padding(start = 12.dp, bottom = 8.dp)
                )

                AppCard(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    val daemons = uiState.status.daemons
                    val daemonText = if (daemons.isEmpty()) {
                        stringResource(R.string.builtin_zygisk_status_stopped)
                    } else {
                        daemons.joinToString("\n") { it.label }
                    }
                    val isDaemonOk = uiState.status.daemonRunning
                    BasicComponent(
                        title = stringResource(R.string.builtin_zygisk_daemon_status),
                        summary = daemonText,
                        startAction = {
                            androidx.compose.material3.Icon(
                                imageVector = if (isDaemonOk) Icons.Rounded.CheckCircle else Icons.Rounded.Warning,
                                contentDescription = null,
                                tint = if (isDaemonOk) androidx.compose.material3.MaterialTheme.colorScheme.primary else androidx.compose.material3.MaterialTheme.colorScheme.error,
                                modifier = Modifier.padding(end = 12.dp)
                            )
                        }
                    )

                    val monitorText = uiState.status.monitor?.label
                        ?: stringResource(R.string.builtin_zygisk_status_stopped)
                    val isMonitorOk = uiState.status.monitorRunning
                    BasicComponent(
                        title = stringResource(R.string.builtin_zygisk_monitor_status),
                        summary = monitorText,
                        startAction = {
                            androidx.compose.material3.Icon(
                                imageVector = if (isMonitorOk) Icons.Rounded.CheckCircle else Icons.Rounded.Warning,
                                contentDescription = null,
                                tint = if (isMonitorOk) androidx.compose.material3.MaterialTheme.colorScheme.primary else androidx.compose.material3.MaterialTheme.colorScheme.error,
                                modifier = Modifier.padding(end = 12.dp)
                            )
                        }
                    )
                }
            }

            item {
                Text(
                    text = stringResource(R.string.builtin_zygisk_impl_title),
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

                AppCard(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    val builtinName = stringResource(R.string.builtin_zygisk_impl_builtin)
                    val currentTarget = uiState.implementation.id
                    val primaryColor = androidx.compose.material3.MaterialTheme.colorScheme.primary
                    val idleColor = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant

                    BasicComponent(
                        title = builtinName,
                        summary = stringResource(R.string.builtin_zygisk_impl_builtin_summary),
                        onClick = {
                            if (!uiState.isSwitching && currentTarget != BUILTIN_ZYGISK_TARGET) {
                                onSwitch(BUILTIN_ZYGISK_TARGET, builtinName)
                            }
                        },
                        startAction = {
                            androidx.compose.material3.Icon(
                                imageVector = Icons.Rounded.Memory,
                                contentDescription = null,
                                tint = if (currentTarget == BUILTIN_ZYGISK_TARGET) primaryColor else idleColor,
                                modifier = Modifier.padding(end = 12.dp)
                            )
                        },
                        endActions = {
                            if (currentTarget == BUILTIN_ZYGISK_TARGET) {
                                androidx.compose.material3.Icon(
                                    imageVector = Icons.Rounded.CheckCircle,
                                    contentDescription = null,
                                    tint = primaryColor
                                )
                            }
                        }
                    )

                    uiState.zygiskModules.filter { it.enabled && !it.remove }.forEach { module ->
                        val isCurrent = module.id == currentTarget
                        HorizontalDivider()
                        BasicComponent(
                            title = module.name,
                            summary = "${module.version} (${module.author})",
                            onClick = {
                                if (!uiState.isSwitching && !isCurrent) {
                                    onSwitch(module.id, module.name)
                                }
                            },
                            startAction = {
                                androidx.compose.material3.Icon(
                                    imageVector = Icons.Rounded.Extension,
                                    contentDescription = null,
                                    tint = if (isCurrent) primaryColor else idleColor,
                                    modifier = Modifier.padding(end = 12.dp)
                                )
                            },
                            endActions = {
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
                    text = stringResource(R.string.builtin_zygisk_injected_title),
                    style = textStyles.title4,
                    color = colorScheme.primary,
                    modifier = Modifier.padding(start = 12.dp, top = 8.dp, bottom = 8.dp)
                )
            }

            if (uiState.injectedModules.isEmpty()) {
                item {
                    AppCard(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = stringResource(R.string.builtin_zygisk_injected_empty),
                            style = textStyles.body2,
                            color = colorScheme.onBackground.copy(alpha = 0.75f),
                            modifier = Modifier.padding(24.dp)
                        )
                    }
                }
            } else {
                item {
                    AppCard(modifier = Modifier.fillMaxWidth()) {
                        uiState.injectedModules.forEachIndexed { index, module ->
                            val isExpanded = uiState.expandedInjectedId == module.id
                            val chevronRotation by animateFloatAsState(
                                targetValue = if (isExpanded) 180f else 0f,
                                label = "injectedChevron"
                            )
                            if (index > 0) HorizontalDivider()
                            val moduleSummary = buildString {
                                val state = stringResource(injectedStateText(module.state))
                                if (module.version.isNotEmpty()) {
                                    append(module.version).append(" · ")
                                }
                                append(state)
                                if (module.targets.isNotEmpty()) {
                                    append("\n").append(
                                        stringResource(
                                            R.string.builtin_zygisk_targets,
                                            module.targets.joinToString(", ")
                                        )
                                    )
                                }
                                if (isExpanded) {
                                    if (module.processes.isEmpty()) {
                                        append("\n").append(
                                            stringResource(R.string.builtin_zygisk_no_processes)
                                        )
                                    } else {
                                        append("\n").append(
                                            stringResource(
                                                R.string.builtin_zygisk_process_count,
                                                module.processes.size
                                            )
                                        )
                                        module.processes.forEach { process ->
                                            append("\n").append(process.label)
                                        }
                                    }
                                }
                            }
                            val typeLabel = stringResource(
                                if (module.type == "next") {
                                    R.string.builtin_zygisk_type_next
                                } else {
                                    R.string.builtin_zygisk_type_zygisk
                                }
                            )
                            BasicComponent(
                                title = module.name,
                                summary = moduleSummary,
                                onClick = { onToggleInjected(module.id) },
                                endActions = {
                                    ZygiskBadgeMiuix(typeLabel, primary = true)
                                    module.abi.forEach { abi ->
                                        Spacer(Modifier.width(4.dp))
                                        ZygiskBadgeMiuix(abi, primary = false)
                                    }
                                    androidx.compose.material3.Icon(
                                        imageVector = Icons.Rounded.ExpandMore,
                                        contentDescription = null,
                                        tint = colorScheme.onSurfaceVariantSummary,
                                        modifier = Modifier
                                            .padding(start = 8.dp)
                                            .rotate(chevronRotation)
                                    )
                                }
                            )
                        }
                    }
                }
            }

            item {
                Text(
                    text = stringResource(R.string.builtin_zygisk_modules_title),
                    style = textStyles.title4,
                    color = colorScheme.primary,
                    modifier = Modifier.padding(start = 12.dp, top = 8.dp, bottom = 8.dp)
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
                        uiState.zygiskModules.forEachIndexed { index, module ->
                            val isActive = module.id == uiState.implementation.id &&
                                uiState.implementation.state == "running"
                            val isExpanded = isActive && uiState.expandedModuleId == module.id
                            val chevronRotation by animateFloatAsState(
                                targetValue = if (isExpanded) 180f else 0f,
                                label = "moduleChevron"
                            )
                            if (index > 0) HorizontalDivider()
                            val moduleSummary = buildString {
                                append("${module.version} (${module.author})\n")
                                if (module.suppressedByBuiltin) {
                                    append(stringResource(R.string.builtin_zygisk_suppressed_hint))
                                } else if (module.description.isNotEmpty()) {
                                    append(module.description)
                                }
                                if (isExpanded) {
                                    val processes = uiState.moduleProcesses
                                    if (processes.monitors.isEmpty() && processes.daemons.isEmpty()) {
                                        append("\n").append(stringResource(R.string.builtin_zygisk_status_stopped))
                                    } else {
                                        processes.monitors.forEach { process ->
                                            append("\n")
                                                .append(stringResource(R.string.builtin_zygisk_monitor_status))
                                                .append(": ")
                                                .append(process.label)
                                        }
                                        processes.daemons.forEach { process ->
                                            append("\n")
                                                .append(stringResource(R.string.builtin_zygisk_daemon_status))
                                                .append(": ")
                                                .append(process.label)
                                        }
                                    }
                                }
                            }.trimEnd()
                            val isSuppressed = module.suppressedByBuiltin
                            val suppressedTag = stringResource(R.string.module_suppressed_by_builtin)
                            val errorContainerColor = androidx.compose.material3.MaterialTheme.colorScheme.errorContainer
                            val onErrorContainerColor = androidx.compose.material3.MaterialTheme.colorScheme.onErrorContainer
                            val primaryColor = androidx.compose.material3.MaterialTheme.colorScheme.primary
                            val errorColor = androidx.compose.material3.MaterialTheme.colorScheme.error

                            BasicComponent(
                                title = module.name,
                                summary = moduleSummary,
                                onClick = if (isActive) {
                                    { onToggleProcesses(module.id) }
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
                                    if (isActive) {
                                        androidx.compose.material3.Icon(
                                            imageVector = Icons.Rounded.ExpandMore,
                                            contentDescription = null,
                                            tint = colorScheme.onSurfaceVariantSummary,
                                            modifier = Modifier
                                                .padding(start = 8.dp)
                                                .rotate(chevronRotation)
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
            .clip(RoundedCornerShape(6.dp))
            .background(if (primary) colors.secondaryContainer else colors.surfaceVariant)
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = text,
            style = textStyles.body2,
            color = if (primary) colors.onSecondaryContainer else colors.onSurfaceVariant
        )
    }
}
