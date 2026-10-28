package com.sukisu.ultra.ui.screen.appicon

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.AddToHomeScreen
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveConfirmDialog
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.TonalCard
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.util.AppIconEntry
import com.sukisu.ultra.ui.util.AppIconPack
import com.sukisu.ultra.ui.util.BuiltinAppIcon
import com.sukisu.ultra.ui.util.BuiltinAppIcons

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppIconScreenMaterial(
    state: AppIconUiState,
    actions: AppIconActions,
) {
    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_icon_title)) },
                navigationIcon = { TopBarBackButton(onClick = actions.onBack) },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing,
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                BuiltinIconSection(
                    selectedId = state.selectedBuiltinId,
                    onSelect = actions.onSelectBuiltin,
                )
            }
            item {
                ImportIconPackSection(
                    importing = state.importing,
                    onImport = actions.onImportPack,
                )
            }

            when {
                state.loading -> item { LoadingSection() }
                state.packs.isEmpty() -> item { EmptyCustomIconsSection() }
                else -> items(state.packs, key = { it.id }) { pack ->
                    CustomIconPackSection(
                        pack = pack,
                        onPin = actions.onPinCustomIcon,
                        onDelete = actions.onRequestDeletePack,
                    )
                }
            }

            item {
                Text(
                    text = stringResource(R.string.app_icon_custom_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }
        }
    }

    state.pendingDelete?.let { pack ->
        ExpressiveConfirmDialog(
            title = stringResource(R.string.app_icon_delete_pack_title),
            message = stringResource(R.string.app_icon_delete_pack_message, pack.name),
            confirmText = stringResource(R.string.confirm),
            dismissText = stringResource(android.R.string.cancel),
            onConfirm = { actions.onConfirmDeletePack(pack) },
            onDismiss = actions.onDismissDeletePack,
        )
    }
}

@Composable
private fun BuiltinIconSection(
    selectedId: String,
    onSelect: (BuiltinAppIcon) -> Unit,
) {
    Column {
        SectionTitle(stringResource(R.string.app_icon_builtin_section))
        TonalCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                AppIconGrid(BuiltinAppIcons.all) { icon ->
                    MaterialIconTile(
                        name = stringResource(icon.nameRes),
                        selected = icon.id == selectedId,
                        onClick = { onSelect(icon) },
                    ) {
                        BuiltinAppIconPreview(icon = icon, modifier = Modifier.fillMaxSize())
                    }
                }
                Spacer(Modifier.height(10.dp))
                Text(
                    text = stringResource(R.string.app_icon_themed_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ImportIconPackSection(
    importing: Boolean,
    onImport: () -> Unit,
) {
    TonalCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconTile(
                    icon = Icons.Rounded.FileUpload,
                    contentDescription = stringResource(R.string.app_icon_import_title),
                )
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.app_icon_import_title),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        text = stringResource(R.string.app_icon_import_summary),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            FilledTonalButton(
                onClick = onImport,
                enabled = !importing,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (importing) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                    )
                } else {
                    Icon(
                        imageVector = Icons.Rounded.FileUpload,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    text = if (importing) {
                        stringResource(R.string.app_icon_importing)
                    } else {
                        stringResource(R.string.app_icon_import_button)
                    }
                )
            }
        }
    }
}

@Composable
private fun LoadingSection() {
    TonalCard(modifier = Modifier.fillMaxWidth()) {
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
private fun EmptyCustomIconsSection() {
    TonalCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                imageVector = Icons.Rounded.Image,
                contentDescription = null,
                modifier = Modifier.size(32.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.app_icon_empty_custom),
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.app_icon_empty_custom_summary),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun CustomIconPackSection(
    pack: AppIconPack,
    onPin: (AppIconPack, AppIconEntry) -> Unit,
    onDelete: (AppIconPack) -> Unit,
) {
    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = pack.name,
                style = MaterialTheme.typography.titleSmallEmphasized,
                color = MaterialTheme.colorScheme.primary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            IconButton(onClick = { onDelete(pack) }) {
                Icon(
                    imageVector = Icons.Rounded.Delete,
                    contentDescription = stringResource(R.string.app_icon_delete_pack_title),
                    tint = MaterialTheme.colorScheme.error,
                )
            }
        }
        TonalCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                AppIconGrid(pack.icons) { entry ->
                    MaterialIconTile(
                        name = entry.name,
                        selected = false,
                        onClick = { onPin(pack, entry) },
                        badge = {
                            Box(
                                modifier = Modifier
                                    .align(Alignment.BottomEnd)
                                    .padding(3.dp)
                                    .size(18.dp)
                                    .background(
                                        color = MaterialTheme.colorScheme.tertiaryContainer,
                                        shape = CircleShape,
                                    ),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Rounded.AddToHomeScreen,
                                    contentDescription = stringResource(R.string.app_icon_pin_badge),
                                    modifier = Modifier.size(11.dp),
                                    tint = MaterialTheme.colorScheme.onTertiaryContainer,
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
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmallEmphasized,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 4.dp, bottom = 8.dp),
    )
}

@Composable
private fun MaterialIconTile(
    name: String,
    selected: Boolean,
    onClick: () -> Unit,
    badge: (@Composable BoxScope.() -> Unit)? = null,
    preview: @Composable () -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    val interactionSource = remember { MutableInteractionSource() }
    val pressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (pressed) 0.94f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMediumLow,
        ),
        label = "AppIconTilePressScale",
    )
    val shape = RoundedCornerShape(20.dp)

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Surface(
            onClick = {
                haptic.performHapticFeedback(HapticFeedbackType.VirtualKey)
                onClick()
            },
            modifier = Modifier
                .size(60.dp)
                .scale(scale),
            shape = shape,
            color = if (selected) {
                MaterialTheme.colorScheme.secondaryContainer
            } else {
                MaterialTheme.colorScheme.surfaceContainerHigh
            },
            border = if (selected) {
                BorderStroke(2.dp, MaterialTheme.colorScheme.primary)
            } else {
                null
            },
            interactionSource = interactionSource,
        ) {
            Box(modifier = Modifier.fillMaxSize()) {
                preview()
                if (selected) {
                    Box(
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .padding(2.dp)
                            .size(18.dp)
                            .background(
                                color = MaterialTheme.colorScheme.primary,
                                shape = CircleShape,
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Check,
                            contentDescription = stringResource(R.string.app_icon_selected),
                            modifier = Modifier.size(12.dp),
                            tint = MaterialTheme.colorScheme.onPrimary,
                        )
                    }
                } else {
                    badge?.invoke(this)
                }
            }
        }
        Spacer(Modifier.height(6.dp))
        Text(
            text = name,
            style = MaterialTheme.typography.labelMedium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.Center,
            color = if (selected) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            },
        )
    }
}
