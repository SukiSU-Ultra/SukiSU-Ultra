package com.sukisu.ultra.ui.screen.home

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import coil.request.ImageRequest
import coil.size.Precision
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.HomeCardStickerOverlays
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.isInDarkTheme
import com.sukisu.ultra.ui.util.CustomTextKey
import com.sukisu.ultra.ui.util.HomeCardImageStyle
import com.sukisu.ultra.ui.util.HomeStatusAlignment
import com.sukisu.ultra.ui.util.HomeStatusStyle
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.util.shouldShowHomeCardImage
import java.io.File
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.isDynamicColor
import top.yukonga.miuix.kmp.utils.PressFeedbackType

@Composable
fun ImmersiveStatusCardMiuix(
    state: HomeUiState,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scale = HomeStatusStyle.coerceScale(state.homeStatusScale)
    val pillScale = HomeStatusStyle.coercePillScale(state.homePillScale)
    val widthFraction = HomeStatusStyle.coerceWidth(state.homeStatusWidthFraction)
    val hasBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val showImage = shouldShowHomeCardImage(
        path = state.homeCardImagePath,
        hasCustomBackground = hasBackground,
        showWithoutBackground = state.showHomeCardImageWithoutBackground,
    )
    val borderColor = if (isInDarkTheme()) {
        Color.White.copy(alpha = 0.28f)
    } else {
        colorScheme.onSurface.copy(alpha = 0.12f)
    }
    val dotColor = when {
        state.isLateLoadMode -> colorScheme.error
        state.isSafeMode -> Color(0xFFF0A93B)
        isDynamicColor -> colorScheme.primary
        else -> Color(0xFF36D167)
    }
    val label = when {
        state.isLateLoadMode -> stringResource(R.string.jailbreak_mode)
        state.isSafeMode -> customText(CustomTextKey.HOME_TAG_SAFEMODE)
        else -> customText(CustomTextKey.HOME_STATUS_WORKING)
    }
    val mode = state.workingModeLabel
    val version = "${state.ksuVersion}-${state.kernelUAPIVersion}"
    val meta = if (mode.isBlank()) version else "$mode · $version"
    val clickEnabled = !state.isLateLoadMode
    val bannerShape = RoundedCornerShape(HomeStatusStyle.BannerCorner)
    val banner = state.homeCardImageStyle == HomeCardImageStyle.BANNER && showImage

    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = if (state.homeStatusAlignment == HomeStatusAlignment.END) {
            Alignment.End
        } else {
            Alignment.Start
        },
        verticalArrangement = Arrangement.spacedBy(HomeStatusStyle.ClusterGap),
    ) {
        AppCard(
                modifier = Modifier
                    .heightIn(min = HomeStatusStyle.PillTouchTarget)
                    .border(
                        1.dp,
                        colorScheme.onSurface.copy(alpha = if (hasBackground) 0.14f else 0.08f),
                        RoundedCornerShape(50),
                    ),
                cornerRadius = HomeStatusStyle.PillTouchTarget,
                insideMargin = PaddingValues(0.dp),
                colors = CardDefaults.defaultColors(
                    color = colorScheme.surfaceContainer.copy(
                        alpha = if (hasBackground) 0.88f else 1f
                    ),
                    contentColor = colorScheme.onSurface,
                ),
                pressFeedbackType = PressFeedbackType.Sink,
                showIndication = clickEnabled,
                onClick = if (clickEnabled) onClick else null,
            ) {
                Row(
                    modifier = Modifier
                        .heightIn(
                            min = maxOf(
                                HomeStatusStyle.PillTouchTarget,
                                HomeStatusStyle.pillDp(HomeStatusStyle.PillMinHeight, pillScale),
                            )
                        )
                        .padding(
                            horizontal = HomeStatusStyle.pillDp(
                                HomeStatusStyle.PillHorizontalPadding,
                                pillScale,
                            )
                        ),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(
                        HomeStatusStyle.pillDp(HomeStatusStyle.PillContentGap, pillScale)
                    ),
                ) {
                    Box(
                        modifier = Modifier
                            .size(HomeStatusStyle.pillDp(HomeStatusStyle.DotSize, pillScale))
                            .clip(RoundedCornerShape(50))
                            .background(dotColor)
                    )
                    Text(
                        text = label,
                        color = colorScheme.onSurface,
                        fontSize = HomeStatusStyle.pillSp(HomeStatusStyle.LabelSizeSp, pillScale),
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Box(
                        modifier = Modifier
                            .width(HomeStatusStyle.pillDp(HomeStatusStyle.DividerWidth, pillScale))
                            .height(HomeStatusStyle.pillDp(HomeStatusStyle.DividerHeight, pillScale))
                            .background(colorScheme.onSurface.copy(alpha = 0.18f))
                    )
                    Text(
                        text = meta,
                        modifier = Modifier.weight(1f, fill = false),
                        color = colorScheme.onSurfaceVariantSummary,
                        fontSize = HomeStatusStyle.pillSp(HomeStatusStyle.MetaSizeSp, pillScale),
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }

        if (banner) {
            BoxWithConstraints(
                modifier = Modifier
                    .fillMaxWidth(widthFraction)
                    .height(HomeStatusStyle.scaledDp(HomeStatusStyle.BannerHeight, scale))
                    .clip(bannerShape)
                    .background(colorScheme.surfaceContainer)
                    .border(1.dp, borderColor, bannerShape)
                    .clickable(enabled = clickEnabled, onClick = onClick)
            ) {
                AsyncImage(
                    model = ImageRequest.Builder(LocalContext.current)
                        .data(File(state.homeCardImagePath))
                        .crossfade(true)
                        .precision(Precision.EXACT)
                        .build(),
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    filterQuality = FilterQuality.High,
                    modifier = Modifier.fillMaxSize(),
                )
                HomeCardStickerOverlays(
                    stickers = state.homeCardStickers,
                    cardWidth = maxWidth,
                    cardHeight = maxHeight,
                    heightNormalized = true,
                )
            }
        }
    }
}
