package com.sukisu.ultra.ui.screen.builtinzygisk

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Extension
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
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
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Refresh
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.textStyles
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun BuiltinZygiskMiuix(
    uiState: BuiltinZygiskUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRearm: () -> Unit,
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
                    val daemonText = if (uiState.status.daemonRunning) {
                        stringResource(R.string.builtin_zygisk_status_running)
                    } else {
                        stringResource(R.string.builtin_zygisk_status_stopped)
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

                    val monitorText = if (uiState.status.monitorRunning) {
                        stringResource(R.string.builtin_zygisk_status_running)
                    } else {
                        stringResource(R.string.builtin_zygisk_status_stopped)
                    }
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

                    ArrowPreference(
                        title = stringResource(R.string.builtin_zygisk_rearm),
                        summary = stringResource(R.string.settings_builtin_zygisk_summary),
                        startAction = {
                            androidx.compose.material3.Icon(
                                Icons.Rounded.RestartAlt,
                                contentDescription = null,
                                tint = androidx.compose.material3.MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(end = 12.dp)
                            )
                        },
                        onClick = onRearm
                    )
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
                        uiState.zygiskModules.forEach { module ->
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
                            val primaryColor = androidx.compose.material3.MaterialTheme.colorScheme.primary
                            val errorColor = androidx.compose.material3.MaterialTheme.colorScheme.error

                            BasicComponent(
                                title = module.name,
                                summary = moduleSummary,
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
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}
