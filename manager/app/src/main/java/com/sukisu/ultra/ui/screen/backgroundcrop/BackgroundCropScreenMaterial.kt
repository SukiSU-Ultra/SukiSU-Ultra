package com.sukisu.ultra.ui.screen.backgroundcrop

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.RotateRight
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.PhotoLibrary
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TonalCard
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackgroundCropScreenMaterial(
    state: BackgroundCropUiState,
    actions: BackgroundCropActions,
    controller: CropController,
) {
    val surface = MaterialTheme.colorScheme.surface
    ExpressiveScaffold(
        modifier = Modifier.drawBehind { drawRect(surface) },
        containerColor = surface,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        stringResource(
                            if (state.isHomeCardCrop) {
                                R.string.background_crop_title_home_card
                            } else {
                                R.string.background_crop_title
                            },
                        )
                    )
                },
                navigationIcon = {
                    IconButton(
                        onClick = actions.onClose,
                        enabled = !state.saving,
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = stringResource(android.R.string.cancel),
                        )
                    }
                },
                actions = {
                    if (!state.isHomeCardCrop) {
                        IconButton(
                            onClick = actions.onUseOriginal,
                            enabled = !state.saving && state.bitmap != null,
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Image,
                                contentDescription = stringResource(R.string.background_crop_use_original),
                            )
                        }
                    }
                    Button(
                        onClick = actions.onConfirm,
                        enabled = !state.saving && state.bitmap != null,
                        modifier = Modifier.padding(start = 4.dp, end = 12.dp),
                        contentPadding = PaddingValues(horizontal = 20.dp),
                    ) {
                        Text(stringResource(R.string.background_crop_done))
                    }
                },
                colors = expressiveTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing,
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp),
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
                        cornerRadius = if (state.isHomeCardCrop) 16.dp else 28.dp,
                        modifier = Modifier.fillMaxSize(),
                    )

                    state.loading -> CircularProgressIndicator()
                }
            }

            Spacer(Modifier.height(8.dp))

            TonalCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = stringResource(R.string.background_crop_hint),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (!state.isHomeCardCrop) {
                        Spacer(Modifier.height(10.dp))
                        LazyRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            items(BackgroundCropRatio.entries) { ratio ->
                                FilterChip(
                                    selected = ratio == state.selectedRatio,
                                    onClick = { actions.onSelectRatio(ratio) },
                                    label = { Text(ratio.label()) },
                                    leadingIcon = if (ratio == state.selectedRatio) {
                                        {
                                            Icon(
                                                imageVector = Icons.Rounded.Check,
                                                contentDescription = null,
                                                modifier = Modifier.size(18.dp),
                                            )
                                        }
                                    } else {
                                        null
                                    },
                                    shape = CircleShape,
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(14.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        FilledTonalIconButton(
                            onClick = actions.onRotate,
                            enabled = !state.saving,
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Rounded.RotateRight,
                                contentDescription = stringResource(R.string.background_crop_rotate),
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        FilledTonalIconButton(
                            onClick = actions.onReset,
                            enabled = !state.saving,
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.RestartAlt,
                                contentDescription = stringResource(R.string.background_crop_reset),
                            )
                        }
                        Spacer(Modifier.weight(1f))
                        if (state.galleryCropAvailable) {
                            FilledTonalButton(
                                onClick = actions.onCropWithGallery,
                                enabled = !state.saving && state.bitmap != null,
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.PhotoLibrary,
                                    contentDescription = null,
                                    modifier = Modifier.size(18.dp),
                                )
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(R.string.background_crop_gallery))
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(16.dp))
        }
    }
}
