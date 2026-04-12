package com.sukisu.ultra.ui.screen.install

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.SdStorage
import androidx.compose.material.icons.filled.Security
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog
import com.sukisu.ultra.ui.kernelFlash.KpmPatchOption
import com.sukisu.ultra.ui.kernelFlash.KpmPatchSelectionDialog
import com.sukisu.ultra.ui.kernelFlash.component.SlotSelectionDialog
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.LkmSelection
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import com.sukisu.ultra.ui.util.isAbDevice
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.basic.ArrowRight
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Close
import top.yukonga.miuix.kmp.icon.extended.ConvertFile
import top.yukonga.miuix.kmp.icon.extended.ExpandLess
import top.yukonga.miuix.kmp.icon.extended.ExpandMore
import top.yukonga.miuix.kmp.icon.extended.MoveFile
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.CheckboxPreference
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * @author weishu
 * @date 2024/3/12.
 */
@Composable
internal fun InstallScreenMiuix(
    uiState: InstallUiState,
    actions: InstallScreenActions,
) {
    val enableBlur = LocalEnableBlur.current
    val scrollBehavior = MiuixScrollBehavior()
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive) Color.Transparent else colorScheme.surface
    val isAbDevice by produceState(initialValue = false) {
        value = isAbDevice()
    }
    val isGkiDevice by produceState(initialValue = false) {
        value = getKernelVersion().isGKI()
    }

    // 槽位选择对话框
    if (uiState.showSlotSelectionDialog && isAbDevice) {
        SlotSelectionDialog(
            show = true,
            onDismiss = { uiState.anyKernel3State?.onDismissSlotDialog() },
            onSlotSelected = { slot ->
                uiState.anyKernel3State?.onSlotSelected(slot)
            }
        )
    }

    // KPM补丁选择对话框
    if (uiState.showKpmPatchDialog) {
        KpmPatchSelectionDialog(
            show = true,
            currentOption = uiState.kpmPatchOption,
            onDismiss = { uiState.anyKernel3State?.onDismissPatchDialog() },
            onOptionSelected = { option ->
                uiState.anyKernel3State?.onOptionSelected(option)
            }
        )
    }

    Scaffold(
        topBar = {
            TopBar(
                onBack = actions.onBack,
                scrollBehavior = scrollBehavior,
                backdrop = backdrop,
                barColor = barColor,
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxHeight()
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection)
                    .padding(top = 12.dp)
                    .padding(horizontal = 16.dp),
                contentPadding = innerPadding,
                overscrollEffect = null,
            ) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        SelectInstallMethod(
                            state = uiState,
                            onSelected = actions.onSelectMethod,
                            onSelectBootImage = actions.onSelectBootImage,
                        )
                    }
                    AnimatedVisibility(
                        visible = uiState.canSelectPartition,
                        enter = expandVertically(),
                        exit = shrinkVertically()
                    ) {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                        ) {
                            OverlayDropdownPreference(
                                items = uiState.displayPartitions,
                                selectedIndex = uiState.partitionSelectionIndex,
                                title = "${stringResource(R.string.install_select_partition)} (${uiState.slotSuffix})",
                                onSelectedIndexChange = actions.onSelectPartition,
                                startAction = {
                                    Icon(
                                        MiuixIcons.ConvertFile,
                                        tint = colorScheme.onSurface,
                                        modifier = Modifier.padding(end = 12.dp),
                                        contentDescription = null
                                    )
                                }
                            )
                        }
                    }

                    // LKM 上传（仅 GKI）
                    if (isGkiDevice && uiState.installMethod !is InstallMethod.HorizonKernel) {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                        ) {
                            BasicComponent(
                                title = stringResource(id = R.string.install_upload_lkm_file),
                                summary = (uiState.lkmSelection as? LkmSelection.LkmUri)?.let {
                                    stringResource(
                                        id = R.string.selected_lkm,
                                        it.uri.lastPathSegment ?: "(file)"
                                    )
                                },
                                onClick = actions.onUploadLkm,
                                startAction = {
                                    Icon(
                                        MiuixIcons.MoveFile,
                                        tint = colorScheme.onSurface,
                                        modifier = Modifier.padding(end = 12.dp),
                                        contentDescription = null
                                    )
                                },
                                endActions = {
                                    if (uiState.lkmSelection is LkmSelection.LkmUri) {
                                        IconButton(onClick = actions.onClearLkm) {
                                            Icon(
                                                MiuixIcons.Close,
                                                modifier = Modifier.size(16.dp),
                                                contentDescription = stringResource(android.R.string.cancel),
                                                tint = colorScheme.onSurfaceVariantActions
                                            )
                                        }
                                    } else {
                                        val layoutDirection = LocalLayoutDirection.current
                                        Icon(
                                            modifier = Modifier
                                                .size(width = 10.dp, height = 16.dp)
                                                .graphicsLayer {
                                                    scaleX =
                                                        if (layoutDirection == LayoutDirection.Rtl) -1f else 1f
                                                }
                                                .align(Alignment.CenterVertically),
                                            imageVector = MiuixIcons.Basic.ArrowRight,
                                            contentDescription = null,
                                            tint = colorScheme.onSurfaceVariantActions,
                                        )
                                    }
                                }
                            )
                        }
                    }

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                    ) {
                        BasicComponent(
                            title = stringResource(id = R.string.advanced_options),
                            onClick = actions.onAdvancedOptionsClicked,
                            endActions = {
                                Icon(
                                    if (uiState.advancedOptionsShown) MiuixIcons.ExpandLess else MiuixIcons.ExpandMore,
                                    modifier = Modifier.size(16.dp),
                                    tint = colorScheme.onSurfaceVariantActions,
                                    contentDescription = stringResource(R.string.expand),
                                )
                            }
                        )
                        AnimatedVisibility(
                            visible = uiState.advancedOptionsShown,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut()
                        ) {
                            Column {
                                CheckboxPreference(
                                    title = stringResource(id = R.string.allow_shell),
                                    checked = uiState.allowShell,
                                    summary = stringResource(id = R.string.allow_shell_summary),
                                    onCheckedChange = actions.onSelectAllowShell
                                )
                                CheckboxPreference(
                                    title = stringResource(id = R.string.enable_adb),
                                    checked = uiState.enableAdb,
                                    summary = stringResource(id = R.string.enable_adb_summary),
                                    onCheckedChange = actions.onSelectEnableAdb
                                )
                            }
                        }
                    }

                    // AnyKernel3 刷写
                    (uiState.installMethod as? InstallMethod.HorizonKernel)?.let { method ->
                        if (isAbDevice && method.slot != null) {
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 12.dp),
                            ) {
                                ArrowPreference(
                                    title = stringResource(
                                        id = R.string.selected_slot,
                                        if (method.slot == "a") stringResource(id = R.string.slot_a)
                                        else stringResource(id = R.string.slot_b)
                                    ),
                                    onClick = {
                                        actions.onReopenSlotDialog(method)
                                    },
                                    startAction = {
                                        Icon(
                                            Icons.Filled.SdStorage,
                                            tint = colorScheme.primary,
                                            modifier = Modifier.padding(end = 16.dp),
                                            contentDescription = null
                                        )
                                    }
                                )
                            }
                        }

                        // KPM 状态显示
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                        ) {
                            ArrowPreference(
                                title = when (uiState.kpmPatchOption) {
                                    KpmPatchOption.PATCH_KPM -> stringResource(R.string.kpm_patch_enabled)
                                    KpmPatchOption.UNDO_PATCH_KPM -> stringResource(R.string.kpm_undo_patch_enabled)
                                    KpmPatchOption.FOLLOW_KERNEL -> stringResource(R.string.kpm_follow_kernel_file)
                                },
                                onClick = {
                                    actions.onReopenKpmDialog(method)
                                },
                                startAction = {
                                    Icon(
                                        Icons.Filled.Security,
                                        tint = when (uiState.kpmPatchOption) {
                                            KpmPatchOption.PATCH_KPM -> colorScheme.primary
                                            KpmPatchOption.UNDO_PATCH_KPM -> colorScheme.secondary
                                            KpmPatchOption.FOLLOW_KERNEL -> colorScheme.onSurfaceVariantSummary
                                        },
                                        modifier = Modifier.padding(end = 16.dp),
                                        contentDescription = null
                                    )
                                }
                            )
                        }
                    }
                    
                    TextButton(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                            text = stringResource(id = R.string.install_next),
                            enabled = uiState.installMethod != null,
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                            onClick = actions.onNext
                        )
                    Spacer(
                        Modifier.height(
                            WindowInsets.navigationBars.asPaddingValues()
                                .calculateBottomPadding() +
                                    WindowInsets.captionBar.asPaddingValues()
                                        .calculateBottomPadding()
                        )
                    )
                }
            }
        }
    }
}

@Composable
private fun SelectInstallMethod(
    state: InstallUiState,
    onSelected: (InstallMethod) -> Unit,
    onSelectBootImage: (InstallMethod) -> Unit,
) {
    val confirmDialog = rememberConfirmDialog(
        onConfirm = {
            onSelected(InstallMethod.DirectInstallToInactiveSlot)
        }
    )
    val dialogTitle = stringResource(id = android.R.string.dialog_alert_title)
    val dialogContent = stringResource(id = R.string.install_inactive_slot_warning)

    val onClick = { option: InstallMethod ->
        when (option) {
            is InstallMethod.SelectFile -> onSelectBootImage(option)
            is InstallMethod.HorizonKernel -> onSelectBootImage(option)
            is InstallMethod.DirectInstall -> onSelected(option)
            is InstallMethod.DirectInstallToInactiveSlot -> confirmDialog.showConfirm(dialogTitle, dialogContent)
        }
    }

    Column {
        state.installMethodOptions.forEach { option ->
            val interactionSource = remember { MutableInteractionSource() }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .toggleable(
                        value = state.installMethod?.let { option::class == it::class } ?: false,
                        onValueChange = { onClick(option) },
                        role = Role.RadioButton,
                        indication = LocalIndication.current,
                        interactionSource = interactionSource
                    )
            ) {
                CheckboxPreference(
                    title = stringResource(id = option.label),
                    summary = option.summary,
                    checked = state.installMethod?.let { option::class == it::class } ?: false,
                    onCheckedChange = { onClick(option) },
                )
            }
        }
    }
}

@Composable
private fun TopBar(
    onBack: () -> Unit = {},
    scrollBehavior: ScrollBehavior,
    backdrop: LayerBackdrop?,
    barColor: Color,
) {
    BlurredBar(backdrop) {
        TopAppBar(
            color = barColor,
            title = stringResource(R.string.install),
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
                        tint = colorScheme.onSurface,
                        contentDescription = null,
                    )
                }
            },
            scrollBehavior = scrollBehavior
        )
    }
}