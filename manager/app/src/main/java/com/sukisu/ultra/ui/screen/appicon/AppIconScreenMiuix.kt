package com.sukisu.ultra.ui.screen.appicon

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
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
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.AddToHomeScreen
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.util.CustomTextKey
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.AppIconEntry
import com.sukisu.ultra.ui.util.AppIconPack
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.BuiltinAppIcon
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun AppIconScreenMiuix(
    state: AppIconUiState,
    actions: AppIconActions,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val backdrop = rememberBlurBackdrop(LocalEnableBlur.current)
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val barColor = if (backdrop != null || hasCustomBackground) Color.Transparent else colorScheme.surface

    AppScaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    title = customText(CustomTextKey.PAGE_APP_ICON),
                    color = barColor,
                    navigationIcon = {
                        IconButton(onClick = actions.onBack) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                                contentDescription = null,
                                tint = colorScheme.onBackground,
                            )
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
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
            ) {
                item { Spacer(Modifier.height(12.dp)) }
                item { DynamicColorCard(state, actions) }
                item { Spacer(Modifier.height(12.dp)) }
                item {
                    BuiltinIconCard(
                        selectedId = state.selectedBuiltinId,
                        onSelect = actions.onSelectBuiltin,
                    )
                }
                item { Spacer(Modifier.height(12.dp)) }
                item {
                    ImportIconPackCard(
                        importing = state.importing,
                        onImport = actions.onImportPack,
                    )
                }
                item { Spacer(Modifier.height(12.dp)) }

                when {
                    state.loading -> item { LoadingCard() }
                    state.packs.isEmpty() -> item { EmptyCustomIconsCard() }
                    else -> items(state.packs, key = { it.id }) { pack ->
                        CustomIconPackCard(
                            pack = pack,
                            onPin = actions.onPinCustomIcon,
                            onDelete = actions.onRequestDeletePack,
                        )
                        Spacer(Modifier.height(12.dp))
                    }
                }

                item {
                    Text(
                        text = stringResource(R.string.app_icon_custom_hint),
                        fontSize = 12.sp,
                        color = colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.padding(horizontal = 8.dp),
                    )
                    Spacer(
                        Modifier.height(
                            WindowInsets.navigationBars
                                .asPaddingValues()
                                .calculateBottomPadding() + 16.dp
                        )
                    )
                }
            }
        }
    }

    state.pendingDelete?.let { pack ->
        DeletePackDialog(
            pack = pack,
            onDismiss = actions.onDismissDeletePack,
            onConfirm = actions.onConfirmDeletePack,
        )
    }
}

@Composable
private fun DynamicColorCard(
    state: AppIconUiState,
    actions: AppIconActions,
) {
    AppCard(modifier = Modifier.fillMaxWidth()) {
        SwitchPreference(
            title = stringResource(R.string.app_icon_dynamic_color_title),
            summary = stringResource(R.string.app_icon_dynamic_color_summary),
            checked = state.dynamicColor,
            onCheckedChange = actions.onSetDynamicColor,
        )
    }
}

@Composable
private fun BuiltinIconCard(
    selectedId: String,
    onSelect: (BuiltinAppIcon) -> Unit,
) {
    AppCard(
        modifier = Modifier.fillMaxWidth(),
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
            Text(
                text = stringResource(R.string.app_icon_builtin_section),
                style = MiuixTheme.textStyles.title4,
                color = colorScheme.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            AppIconGrid(BuiltinAppIcons.all) { icon ->
                MiuixIconTile(
                    name = stringResource(icon.nameRes),
                    selected = icon.id == selectedId,
                    onClick = { onSelect(icon) },
                ) {
                    BuiltinAppIconPreview(icon = icon, modifier = Modifier.fillMaxSize())
                }
            }
        }
    }
}

@Composable
private fun ImportIconPackCard(
    importing: Boolean,
    onImport: () -> Unit,
) {
    AppCard(modifier = Modifier.fillMaxWidth()) {
        BasicComponent(
            title = stringResource(R.string.app_icon_import_title),
            summary = if (importing) {
                stringResource(R.string.app_icon_importing)
            } else {
                stringResource(R.string.app_icon_import_summary)
            },
            startAction = {
                if (importing) {
                    CircularProgressIndicator(
                        modifier = Modifier
                            .padding(end = 10.dp)
                            .size(20.dp)
                    )
                } else {
                    Icon(
                        imageVector = Icons.Rounded.FileUpload,
                        modifier = Modifier.padding(end = 6.dp),
                        contentDescription = null,
                        tint = colorScheme.onBackground,
                    )
                }
            },
            onClick = {
                if (!importing) onImport()
            },
        )
    }
}

@Composable
private fun LoadingCard() {
    AppCard(modifier = Modifier.fillMaxWidth()) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            contentAlignment = Alignment.Center,
        ) {
            CircularProgressIndicator(modifier = Modifier.size(24.dp))
        }
    }
}

@Composable
private fun EmptyCustomIconsCard() {
    AppCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = stringResource(R.string.app_icon_empty_custom),
                style = MiuixTheme.textStyles.title4,
                color = colorScheme.onSurface,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.app_icon_empty_custom_summary),
                fontSize = 13.sp,
                color = colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

@Composable
private fun CustomIconPackCard(
    pack: AppIconPack,
    onPin: (AppIconPack, AppIconEntry) -> Unit,
    onDelete: (AppIconPack) -> Unit,
) {
    AppCard(
        modifier = Modifier.fillMaxWidth(),
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = pack.name,
                    style = MiuixTheme.textStyles.title4,
                    color = colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = { onDelete(pack) }) {
                    Icon(
                        imageVector = Icons.Rounded.Delete,
                        contentDescription = stringResource(R.string.app_icon_delete_pack_title),
                        tint = colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
            Spacer(Modifier.height(10.dp))
            AppIconGrid(pack.icons) { entry ->
                MiuixIconTile(
                    name = entry.name,
                    selected = false,
                    onClick = { onPin(pack, entry) },
                    role = Role.Button,
                    badge = {
                        Box(
                            modifier = Modifier
                                .align(Alignment.BottomEnd)
                                .padding(3.dp)
                                .size(16.dp)
                                .clip(CircleShape)
                                .background(colorScheme.secondaryContainer),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Rounded.AddToHomeScreen,
                                contentDescription = stringResource(R.string.app_icon_pin_badge),
                                modifier = Modifier.size(11.dp),
                                tint = colorScheme.onSecondaryContainer,
                            )
                        }
                    },
                ) {
                    CustomAppIconPreview(
                        pack = pack,
                        entry = entry,
                        modifier = Modifier.fillMaxSize(),
                    )
                }
            }
        }
    }
}

@Composable
private fun MiuixIconTile(
    name: String,
    selected: Boolean,
    onClick: () -> Unit,
    role: Role = Role.RadioButton,
    badge: (@Composable BoxScope.() -> Unit)? = null,
    preview: @Composable () -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    val shape = RoundedCornerShape(16.dp)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(shape)
            .clickable(role = role) {
                haptic.performHapticFeedback(HapticFeedbackType.VirtualKey)
                onClick()
            }
            .padding(vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(56.dp)
                .clip(shape)
                .background(colorScheme.surfaceVariant)
                .then(
                    if (selected) {
                        Modifier.border(2.dp, colorScheme.primary, shape)
                    } else {
                        Modifier
                    }
                ),
        ) {
            preview()
            if (selected) {
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(2.dp)
                        .size(16.dp)
                        .clip(CircleShape)
                        .background(colorScheme.primary),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Check,
                        contentDescription = stringResource(R.string.app_icon_selected),
                        modifier = Modifier.size(11.dp),
                        tint = colorScheme.onPrimary,
                    )
                }
            } else {
                badge?.invoke(this)
            }
        }
        Spacer(Modifier.height(6.dp))
        Text(
            text = name,
            fontSize = 12.sp,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.Center,
            color = if (selected) colorScheme.primary else colorScheme.onSurfaceVariantSummary,
        )
    }
}

@Composable
private fun DeletePackDialog(
    pack: AppIconPack,
    onDismiss: () -> Unit,
    onConfirm: (AppIconPack) -> Unit,
) {
    OverlayDialog(
        show = true,
        title = stringResource(R.string.app_icon_delete_pack_title),
        summary = pack.name,
        onDismissRequest = onDismiss,
        content = {
            Row(horizontalArrangement = Arrangement.SpaceBetween) {
                TextButton(
                    text = stringResource(android.R.string.cancel),
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(20.dp))
                TextButton(
                    text = stringResource(R.string.confirm),
                    onClick = { onConfirm(pack) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        },
    )
}
