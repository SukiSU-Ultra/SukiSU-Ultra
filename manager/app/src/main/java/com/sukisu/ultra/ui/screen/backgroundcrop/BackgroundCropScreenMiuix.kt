package com.sukisu.ultra.ui.screen.backgroundcrop

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.RotateRight
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.PhotoLibrary
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Close
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
fun BackgroundCropScreenMiuix(
    state: BackgroundCropUiState,
    actions: BackgroundCropActions,
    controller: CropController,
) {
    val surface = colorScheme.surface
    AppScaffold(
        modifier = Modifier.drawBehind { drawRect(surface) },
        containerColor = surface,
        topBar = {
            SmallTopAppBar(
                title = stringResource(R.string.background_crop_title),
                color = colorScheme.surface,
                navigationIcon = {
                    IconButton(
                        onClick = actions.onClose,
                        enabled = !state.saving,
                    ) {
                        Icon(
                            imageVector = MiuixIcons.Close,
                            contentDescription = stringResource(android.R.string.cancel),
                            tint = colorScheme.onSurface,
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = actions.onUseOriginal,
                        enabled = !state.saving && state.bitmap != null,
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Image,
                            contentDescription = stringResource(R.string.background_crop_use_original),
                            tint = colorScheme.onSurface,
                        )
                    }
                    TextButton(
                        text = stringResource(R.string.background_crop_done),
                        onClick = actions.onConfirm,
                        enabled = !state.saving && state.bitmap != null,
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                    )
                },
            )
        },
        popupHost = { },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (state.saving) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }

            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                contentAlignment = Alignment.Center,
            ) {
                val bitmap = state.bitmap
                when {
                    bitmap != null -> CropViewport(
                        bitmap = bitmap,
                        aspectRatio = state.aspectRatio,
                        controller = controller,
                        cornerRadius = 20.dp,
                        modifier = Modifier.fillMaxSize(),
                    )

                    state.loading -> CircularProgressIndicator()
                }
            }

            Spacer(Modifier.height(8.dp))

            AppCard(
                modifier = Modifier.fillMaxWidth(),
                insideMargin = PaddingValues(0.dp),
                colors = CardDefaults.defaultColors(),
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = stringResource(R.string.background_crop_hint),
                        fontSize = 13.sp,
                        color = colorScheme.onSurfaceVariantSummary,
                    )
                    Spacer(Modifier.height(10.dp))
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(BackgroundCropRatio.entries) { ratio ->
                            MiuixRatioChip(
                                label = ratio.label(),
                                selected = ratio == state.selectedRatio,
                                onClick = { actions.onSelectRatio(ratio) },
                            )
                        }
                    }
                    Spacer(Modifier.height(14.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        MiuixIconChip(
                            icon = Icons.AutoMirrored.Rounded.RotateRight,
                            contentDescription = stringResource(R.string.background_crop_rotate),
                            enabled = !state.saving,
                            onClick = actions.onRotate,
                        )
                        Spacer(Modifier.width(8.dp))
                        MiuixIconChip(
                            icon = Icons.Rounded.RestartAlt,
                            contentDescription = stringResource(R.string.background_crop_reset),
                            enabled = !state.saving,
                            onClick = actions.onReset,
                        )
                        Spacer(Modifier.weight(1f))
                        if (state.galleryCropAvailable) {
                            Button(
                                onClick = actions.onCropWithGallery,
                                enabled = !state.saving && state.bitmap != null,
                                modifier = Modifier.heightIn(min = 40.dp),
                                colors = ButtonDefaults.buttonColors(
                                    color = colorScheme.secondaryContainer,
                                    contentColor = colorScheme.onSecondaryContainer,
                                ),
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.PhotoLibrary,
                                    contentDescription = null,
                                    modifier = Modifier.size(18.dp),
                                    tint = colorScheme.onSecondaryContainer,
                                )
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    text = stringResource(R.string.background_crop_gallery),
                                    fontSize = 15.sp,
                                    color = colorScheme.onSecondaryContainer,
                                )
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun MiuixRatioChip(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    val container = if (selected) {
        colorScheme.primary
    } else {
        colorScheme.secondaryContainer.copy(alpha = 0.7f)
    }
    val content = if (selected) colorScheme.onPrimary else colorScheme.onSecondaryContainer

    Box(
        modifier = Modifier
            .height(36.dp)
            .clip(CircleShape)
            .background(container)
            .selectable(
                selected = selected,
                role = Role.RadioButton,
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.VirtualKey)
                    onClick()
                },
            )
            .padding(horizontal = 16.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            fontSize = 14.sp,
            fontWeight = FontWeight.Medium,
            color = content,
        )
    }
}

@Composable
private fun MiuixIconChip(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    contentDescription: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(CircleShape)
            .background(colorScheme.secondaryContainer.copy(alpha = 0.7f))
            .clickable(
                enabled = enabled,
                role = Role.Button,
                onClick = onClick,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = contentDescription,
            modifier = Modifier.size(22.dp),
            tint = colorScheme.onSecondaryContainer.copy(
                alpha = if (enabled) 1f else 0.38f,
            ),
        )
    }
}
