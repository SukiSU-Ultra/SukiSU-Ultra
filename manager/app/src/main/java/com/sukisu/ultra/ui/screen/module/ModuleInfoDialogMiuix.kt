package com.sukisu.ultra.ui.screen.module

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.Module
import com.sukisu.ultra.data.model.ModuleUpdateInfo
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Copy
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.textStyles

/**
 * Long-press module detail sheet for the Miuix UI: a banner header that can be changed or
 * removed in place, followed by every module field with per-row copy actions.
 */
@Composable
fun ModuleInfoDialogMiuix(
    module: Module,
    updateInfo: ModuleUpdateInfo?,
    onDismiss: () -> Unit,
    onBannerChanged: () -> Unit,
) {
    val context = LocalContext.current
    val resources = LocalResources.current
    val rows = remember(module, updateInfo, resources) { moduleInfoRows(resources, module, updateInfo) }
    val banner = rememberModuleBanner(module.id, module.bannerPath)
    val bannerState = rememberModuleInfoBannerState(module, onBannerChanged)
    val pickBanner = rememberModuleBannerPicker(bannerState)
    val copied = stringResource(R.string.module_info_copied)

    OverlayDialog(
        show = true,
        title = module.name,
        summary = stringResource(R.string.module_info_title),
        onDismissRequest = onDismiss,
        insideMargin = DpSize(0.dp, 20.dp),
        content = {
            Column(modifier = Modifier.heightIn(max = 560.dp)) {
                ModuleInfoBannerHeader(
                    module = module,
                    banner = banner,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp),
                )

                Spacer(Modifier.height(12.dp))

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    TextButton(
                        text = stringResource(
                            if (module.bannerPath == null) {
                                R.string.module_info_banner_add
                            } else {
                                R.string.module_info_banner_change
                            }
                        ),
                        onClick = pickBanner,
                        enabled = !bannerState.busy,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                    )
                    if (module.bannerPath != null) {
                        TextButton(
                            text = stringResource(
                                if (ModuleBannerEditor.isCustomBanner(module)) {
                                    R.string.module_info_banner_remove_custom
                                } else {
                                    R.string.module_info_banner_remove
                                }
                            ),
                            onClick = bannerState::remove,
                            enabled = !bannerState.busy,
                            modifier = Modifier.weight(1f),
                        )
                    }
                }

                Text(
                    text = stringResource(R.string.module_info_banner_hint),
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 2.dp),
                    style = textStyles.footnote2,
                    color = colorScheme.onSurfaceVariantSummary,
                )

                Spacer(Modifier.height(8.dp))
                HorizontalDivider(
                    modifier = Modifier.padding(horizontal = 24.dp),
                    thickness = 0.5.dp,
                    color = colorScheme.outline.copy(alpha = 0.4f),
                )
                Spacer(Modifier.height(4.dp))

                LazyColumn(modifier = Modifier.heightIn(max = 340.dp)) {
                    items(rows, key = { it.key }) { row ->
                        ModuleInfoRowMiuix(
                            row = row,
                            onCopy = { copyModuleInfo(context, it.value, copied) },
                        )
                    }
                }

                Spacer(Modifier.height(4.dp))
                HorizontalDivider(
                    modifier = Modifier.padding(horizontal = 24.dp),
                    thickness = 0.5.dp,
                    color = colorScheme.outline.copy(alpha = 0.4f),
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(20.dp),
                ) {
                    TextButton(
                        text = stringResource(R.string.module_info_copy_all),
                        onClick = { copyModuleInfo(context, moduleInfoText(rows), copied) },
                        enabled = rows.any { it.copyable },
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        text = stringResource(R.string.module_info_close),
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                    )
                }
            }
        },
    )
}

@Composable
private fun ModuleInfoBannerHeader(
    module: Module,
    banner: ImageBitmap?,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .height(136.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(colorScheme.surfaceContainerHigh),
        contentAlignment = Alignment.Center,
    ) {
        if (banner != null) {
            Image(
                bitmap = banner,
                contentDescription = null,
                contentScale = ContentScale.Crop,
                modifier = Modifier.matchParentSize(),
            )
            Box(
                modifier = Modifier
                    .matchParentSize()
                    .background(
                        Brush.verticalGradient(
                            listOf(Color.Transparent, Color.Black.copy(alpha = 0.5f))
                        )
                    )
            )
            Text(
                text = module.name,
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                style = textStyles.title3,
                fontWeight = FontWeight(650),
                color = Color.White,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        } else {
            Text(
                text = stringResource(R.string.module_info_banner_none),
                style = textStyles.body2,
                color = colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

@Composable
private fun ModuleInfoRowMiuix(
    row: ModuleInfoRow,
    onCopy: (ModuleInfoRow) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp, vertical = 7.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = row.label,
            style = textStyles.footnote2,
            color = colorScheme.onSurfaceVariantSummary,
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            SelectionContainer(modifier = Modifier.weight(1f)) {
                Text(
                    text = row.value,
                    style = textStyles.body2,
                    fontFamily = if (row.monospace) FontFamily.Monospace else null,
                    color = colorScheme.onSurface,
                )
            }
            if (row.copyable) {
                IconButton(
                    onClick = { onCopy(row) },
                    minHeight = 36.dp,
                    minWidth = 36.dp,
                ) {
                    Icon(
                        imageVector = MiuixIcons.Copy,
                        contentDescription = stringResource(R.string.module_info_copy),
                        modifier = Modifier.size(18.dp),
                        tint = colorScheme.primary,
                    )
                }
            } else {
                Spacer(Modifier.width(36.dp))
            }
        }
    }
}
