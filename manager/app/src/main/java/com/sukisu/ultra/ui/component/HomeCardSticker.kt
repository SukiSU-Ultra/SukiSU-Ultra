package com.sukisu.ultra.ui.component

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import coil.compose.rememberAsyncImagePainter
import coil.request.ImageRequest
import coil.size.Precision
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.HomeCardSticker
import com.sukisu.ultra.ui.util.HomeCardStickerTransform
import com.sukisu.ultra.ui.util.HomeCardImageStyle
import com.sukisu.ultra.ui.util.HomeLayout
import com.sukisu.ultra.ui.util.HomeStatusAlignment
import com.sukisu.ultra.ui.util.HomeStatusStyle
import com.sukisu.ultra.ui.util.drawPainterCover
import java.io.File

/**
 * Draws every sticker over a status card in list order. [cardWidth] is the card's measured
 * width; placement and size are stored as fractions of it so the stickers keep their relative
 * position on the home card, the preview and the editor stage.
 *
 * When [heightNormalized] is true (the immersive banner), the vertical position uses the card
 * height instead and the size is capped so a sticker cannot exceed the card. The classic card
 * keeps the original width-only math.
 */
@Composable
fun HomeCardStickerOverlays(
    stickers: List<HomeCardSticker>,
    cardWidth: Dp,
    cardHeight: Dp = 0.dp,
    heightNormalized: Boolean = false,
    modifier: Modifier = Modifier,
) {
    stickers.forEach { sticker ->
        key(sticker.path) {
            HomeCardStickerOverlay(
                path = sticker.path,
                transform = sticker.transform,
                cardWidth = cardWidth,
                cardHeight = cardHeight,
                heightNormalized = heightNormalized,
                modifier = modifier,
            )
        }
    }
}

@Composable
private fun HomeCardStickerOverlay(
    path: String,
    transform: HomeCardStickerTransform,
    cardWidth: Dp,
    cardHeight: Dp,
    heightNormalized: Boolean,
    modifier: Modifier = Modifier,
) {
    if (path.isBlank()) return
    val size = if (heightNormalized && cardHeight > 0.dp) {
        cardWidth * transform.size.coerceAtMost(
            transform.maxSizeFor(cardWidth.value, cardHeight.value)
        )
    } else {
        cardWidth * transform.size
    }
    val rawX = (cardWidth - size) / 2 + cardWidth * transform.offsetX
    val x = if (heightNormalized && cardWidth > 0.dp) {
        rawX.coerceIn(0.dp, (cardWidth - size).coerceAtLeast(0.dp))
    } else {
        rawX
    }
    val y = if (heightNormalized && cardHeight > 0.dp) {
        val raw = (cardHeight - size) / 2 + cardHeight * transform.resolvedOffsetYPct()
        val maxY = (cardHeight - size).coerceAtLeast(0.dp)
        raw.coerceIn(0.dp, maxY)
    } else {
        (cardWidth - size) / 2 + cardWidth * transform.offsetY
    }
    Image(
        painter = rememberAsyncImagePainter(
            model = ImageRequest.Builder(LocalContext.current)
                .data(File(path))
                .crossfade(true)
                .build()
        ),
        contentDescription = null,
        contentScale = ContentScale.Crop,
        modifier = modifier
            .offset(x = x, y = y)
            .size(size)
            .graphicsLayer { rotationZ = transform.rotation }
            .clip(RoundedCornerShape(size * 0.24f)),
    )
}


@Composable
fun HomeCardStickerThumbnail(
    path: String,
    selected: Boolean,
    accentColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val shape = RoundedCornerShape(12.dp)
    Image(
        painter = rememberAsyncImagePainter(
            model = ImageRequest.Builder(LocalContext.current)
                .data(File(path))
                .crossfade(true)
                .build()
        ),
        contentDescription = stringResource(R.string.settings_home_card_sticker),
        contentScale = ContentScale.Crop,
        modifier = modifier
            .size(44.dp)
            .clip(shape)
            .then(if (selected) Modifier.border(2.dp, accentColor, shape) else Modifier)
            .clickable(onClick = onClick),
    )
}

/**
 * Editor stage: the same card proportions as the home card with draggable stickers.
 * The selected sticker follows the drag and commits on gesture end; tapping another sticker
 * selects it instead.
 */
@Composable
fun HomeCardStickerStage(
    backgroundImagePath: String,
    stickers: List<HomeCardSticker>,
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
    onTransformChange: (Int, HomeCardStickerTransform) -> Unit,
    onTransformCommit: (Int, HomeCardStickerTransform) -> Unit,
    containerColor: Color,
    contentColor: Color,
    accentColor: Color,
    accentContentColor: Color,
    modifier: Modifier = Modifier,
    layout: HomeLayout = HomeLayout.CLASSIC,
    imageStyle: HomeCardImageStyle = HomeCardImageStyle.BANNER,
    statusScale: Float = HomeStatusStyle.SCALE_DEFAULT,
    statusWidthFraction: Float = HomeStatusStyle.WIDTH_DEFAULT,
    pillScale: Float = HomeStatusStyle.PILL_SCALE_DEFAULT,
    statusAlignment: HomeStatusAlignment = HomeStatusAlignment.START,
) {
    val backgroundPainter = backgroundImagePath.takeIf { it.isNotBlank() && File(it).isFile }?.let { path ->
        rememberAsyncImagePainter(
            model = ImageRequest.Builder(LocalContext.current)
                .data(File(path))
                .crossfade(true)
                .build()
        )
    }
    // The gesture detectors keep running across recompositions; read the latest state and
    // callbacks so a recreated draft list (after a slider commit) does not leave them stale.
    val currentStickers by rememberUpdatedState(stickers)
    val currentSelectedIndex by rememberUpdatedState(selectedIndex)
    val currentOnSelect by rememberUpdatedState(onSelect)
    val currentOnTransformChange by rememberUpdatedState(onTransformChange)
    val currentOnTransformCommit by rememberUpdatedState(onTransformCommit)

    if (layout == HomeLayout.IMMERSIVE) {
        ImmersiveBannerStickerStage(
            backgroundImagePath = backgroundImagePath,
            stickers = stickers,
            selectedIndex = selectedIndex,
            onSelect = currentOnSelect,
            onTransformChange = currentOnTransformChange,
            onTransformCommit = currentOnTransformCommit,
            containerColor = containerColor,
            contentColor = contentColor,
            accentColor = accentColor,
            accentContentColor = accentContentColor,
            statusScale = statusScale,
            modifier = modifier,
            imageStyle = imageStyle,
            statusWidthFraction = statusWidthFraction,
            pillScale = pillScale,
            statusAlignment = statusAlignment,
        )
        return
    }

    BoxWithConstraints(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(360f / 196f)
            .clip(RoundedCornerShape(26.dp))
            .then(
                if (backgroundPainter != null) {
                    Modifier.drawPainterCover(backgroundPainter)
                } else {
                    Modifier.background(containerColor)
                }
            )
    ) {
        val cardWidth = maxWidth
        val widthPx = with(LocalDensity.current) { cardWidth.toPx() }
        val currentWidthPx by rememberUpdatedState(widthPx)
        val heightRatio = with(LocalDensity.current) {
            if (widthPx > 0f) maxHeight.toPx() / widthPx else 1f
        }
        val currentHeightRatio by rememberUpdatedState(heightRatio)
        Box(modifier = Modifier.fillMaxSize()) {
            Row(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(14.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                StageTag("LKM", accentColor, accentContentColor)
                StageTag(
                    text = stringResource(R.string.home_lkm_custom),
                    backgroundColor = contentColor.copy(alpha = 0.18f),
                    textColor = contentColor,
                )
            }
            Column(
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .padding(14.dp),
            ) {
                Text(
                    text = stringResource(R.string.home_working),
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = contentColor,
                )
                Text(
                    text = stringResource(R.string.home_working_version, BuildConfig.VERSION_NAME),
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = contentColor.copy(alpha = 0.75f),
                )
            }
            stickers.forEachIndexed { index, sticker ->
                key(sticker.path) {
                    val transform = sticker.transform
                    val size = cardWidth * transform.size
                    val base = (cardWidth - size) / 2
                    // The drag target stays an unrotated square: rotating the layer inside it
                    // keeps pointer hit-testing stable after the rotation slider changes.
                    val gestureModifier = if (index == selectedIndex) {
                        Modifier.pointerInput(index) {
                            var dragging: HomeCardStickerTransform? = null
                            detectDragGestures(
                                onDragStart = {
                                    dragging = currentStickers.getOrNull(index)?.transform
                                },
                                onDragEnd = {
                                    dragging?.let { currentOnTransformCommit(index, it) }
                                    dragging = null
                                },
                                onDragCancel = { dragging = null },
                            ) { change, dragAmount ->
                                change.consume()
                                val baseTransform = dragging
                                    ?: currentStickers.getOrNull(index)?.transform
                                    ?: return@detectDragGestures
                                // Accumulate locally: recomposition lags individual pointer moves,
                                // so deriving every delta from the committed value loses motion.
                                val maxOffsetY = (currentHeightRatio - 0.5f).coerceAtLeast(-0.5f)
                                val updated = baseTransform.copy(
                                    offsetX = (baseTransform.offsetX + dragAmount.x / currentWidthPx)
                                        .coerceIn(-0.5f, 0.5f),
                                    offsetY = (baseTransform.offsetY + dragAmount.y / currentWidthPx)
                                        .coerceIn(-0.5f, maxOffsetY),
                                ).coerced()
                                dragging = updated
                                currentOnTransformChange(index, updated)
                            }
                        }
                    } else {
                        Modifier.pointerInput(index) {
                            detectTapGestures {
                                if (currentSelectedIndex != index) currentOnSelect(index)
                            }
                        }
                    }
                    Box(
                        modifier = Modifier
                            .offset(
                                x = base + cardWidth * transform.offsetX,
                                y = base + cardWidth * transform.offsetY,
                            )
                            .size(size)
                            .then(gestureModifier),
                    ) {
                        Image(
                            painter = rememberAsyncImagePainter(
                                model = ImageRequest.Builder(LocalContext.current)
                                    .data(File(sticker.path))
                                    .crossfade(true)
                                    .build()
                            ),
                            contentDescription = null,
                            contentScale = ContentScale.Crop,
                            modifier = Modifier
                                .fillMaxSize()
                                .graphicsLayer { rotationZ = transform.rotation }
                                .clip(RoundedCornerShape(size * 0.24f)),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StageTag(
    text: String,
    backgroundColor: Color,
    textColor: Color,
) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(backgroundColor)
            .padding(horizontal = 8.dp, vertical = 3.dp),
    ) {
        Text(
            text = text,
            fontSize = 10.sp,
            fontWeight = FontWeight.Medium,
            color = textColor,
        )
    }
}

/**
 * The immersive sticker editor. The vertical space is the banner image card; the pill above is a
 * non-interactive preview. Sticker Y offsets are stored as fractions of the banner height.
 */
@Composable
private fun ImmersiveBannerStickerStage(
    backgroundImagePath: String,
    stickers: List<HomeCardSticker>,
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
    onTransformChange: (Int, HomeCardStickerTransform) -> Unit,
    onTransformCommit: (Int, HomeCardStickerTransform) -> Unit,
    containerColor: Color,
    contentColor: Color,
    accentColor: Color,
    accentContentColor: Color,
    statusScale: Float,
    imageStyle: HomeCardImageStyle,
    statusWidthFraction: Float,
    pillScale: Float,
    statusAlignment: HomeStatusAlignment,
    modifier: Modifier = Modifier,
) {
    if (imageStyle != HomeCardImageStyle.BANNER) {
        Box(
            modifier = modifier
                .fillMaxWidth()
                .aspectRatio(360f / 120f)
                .clip(RoundedCornerShape(20.dp))
                .background(containerColor)
        )
        return
    }

    val scale = HomeStatusStyle.coerceScale(statusScale)
    val bannerShape = RoundedCornerShape(HomeStatusStyle.BannerCorner)
    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = if (statusAlignment == HomeStatusAlignment.END) {
            Alignment.End
        } else {
            Alignment.Start
        },
        verticalArrangement = Arrangement.spacedBy(HomeStatusStyle.ClusterGap),
    ) {
        ImmersivePillPreview(
            containerColor = containerColor,
            contentColor = contentColor,
            accentColor = accentColor,
            accentContentColor = accentContentColor,
            pillScale = pillScale,
        )
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxWidth(HomeStatusStyle.coerceWidth(statusWidthFraction))
                .height(HomeStatusStyle.scaledDp(HomeStatusStyle.BannerHeight, scale))
                .clip(bannerShape)
                .background(containerColor)
        ) {
            if (backgroundImagePath.isNotBlank() && File(backgroundImagePath).isFile) {
                AsyncImage(
                    model = ImageRequest.Builder(LocalContext.current)
                        .data(File(backgroundImagePath))
                        .crossfade(true)
                        .precision(Precision.EXACT)
                        .build(),
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    filterQuality = FilterQuality.High,
                    modifier = Modifier.fillMaxSize(),
                )
            }
            val cardWidth = maxWidth
            val cardHeight = maxHeight
            val widthPx = with(LocalDensity.current) { cardWidth.toPx() }
            val heightPx = with(LocalDensity.current) { cardHeight.toPx() }
            val currentWidthPx by rememberUpdatedState(widthPx)
            val currentHeightPx by rememberUpdatedState(heightPx)
            val currentWidthDp by rememberUpdatedState(cardWidth.value)
            val currentHeightDp by rememberUpdatedState(cardHeight.value)
            val currentStickers by rememberUpdatedState(stickers)
            val currentSelectedIndex by rememberUpdatedState(selectedIndex)
            val currentOnSelect by rememberUpdatedState(onSelect)
            val currentOnTransformChange by rememberUpdatedState(onTransformChange)
            val currentOnTransformCommit by rememberUpdatedState(onTransformCommit)

            Box(modifier = Modifier.fillMaxSize()) {
                stickers.forEachIndexed { index, sticker ->
                    key(sticker.path) {
                        val transform = sticker.transform
                        val sizeFraction = transform.size.coerceAtMost(
                            transform.maxSizeFor(cardWidth.value, cardHeight.value)
                        )
                        val size = cardWidth * sizeFraction
                        val x = ((cardWidth - size) / 2 + cardWidth * transform.offsetX)
                            .coerceIn(0.dp, (cardWidth - size).coerceAtLeast(0.dp))
                        val y = ((cardHeight - size) / 2 + cardHeight * transform.resolvedOffsetYPct())
                            .coerceIn(0.dp, (cardHeight - size).coerceAtLeast(0.dp))
                        val gestureModifier = if (index == selectedIndex) {
                            Modifier.pointerInput(index) {
                                var dragging: HomeCardStickerTransform? = null
                                detectDragGestures(
                                    onDragStart = {
                                        dragging = currentStickers.getOrNull(index)?.transform
                                    },
                                    onDragEnd = {
                                        dragging?.let { currentOnTransformCommit(index, it) }
                                        dragging = null
                                    },
                                    onDragCancel = { dragging = null },
                                ) { change, dragAmount ->
                                    change.consume()
                                    val baseTransform = dragging
                                        ?: currentStickers.getOrNull(index)?.transform
                                        ?: return@detectDragGestures
                                    val currentSizeFraction = baseTransform.size.coerceAtMost(
                                        baseTransform.maxSizeFor(
                                            currentWidthDp,
                                            currentHeightDp,
                                        )
                                    )
                                    val sizePx = currentWidthPx * currentSizeFraction
                                    val maxOffsetX = ((currentWidthPx - sizePx) / (2f * currentWidthPx))
                                        .coerceAtLeast(0f)
                                    val maxOffsetY = ((currentHeightPx - sizePx) / (2f * currentHeightPx))
                                        .coerceAtLeast(0f)
                                    val updated = baseTransform.copy(
                                        offsetX = (baseTransform.offsetX + dragAmount.x / currentWidthPx)
                                            .coerceIn(-maxOffsetX, maxOffsetX),
                                    ).withHeightOffset(
                                        (baseTransform.resolvedOffsetYPct() + dragAmount.y / currentHeightPx)
                                            .coerceIn(-maxOffsetY, maxOffsetY)
                                    )
                                    dragging = updated
                                    currentOnTransformChange(index, updated)
                                }
                            }
                        } else {
                            Modifier.pointerInput(index) {
                                detectTapGestures {
                                    if (currentSelectedIndex != index) currentOnSelect(index)
                                }
                            }
                        }
                        Box(
                            modifier = Modifier
                                .offset(x = x, y = y)
                                .size(size)
                                .then(gestureModifier),
                        ) {
                            Image(
                                painter = rememberAsyncImagePainter(
                                    model = ImageRequest.Builder(LocalContext.current)
                                        .data(File(sticker.path))
                                        .crossfade(true)
                                        .build()
                                ),
                                contentDescription = null,
                                contentScale = ContentScale.Crop,
                                modifier = Modifier
                                    .fillMaxSize()
                                    .graphicsLayer { rotationZ = transform.rotation }
                                    .clip(RoundedCornerShape(size * 0.24f)),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ImmersivePillPreview(
    containerColor: Color,
    contentColor: Color,
    accentColor: Color,
    accentContentColor: Color,
    pillScale: Float,
    modifier: Modifier = Modifier,
) {
    val shape = RoundedCornerShape(50)
    Row(
        modifier = modifier
            .clip(shape)
            .background(containerColor)
            .border(1.dp, contentColor.copy(alpha = 0.12f), shape)
            .padding(
                horizontal = HomeStatusStyle.pillDp(
                    HomeStatusStyle.PillHorizontalPadding,
                    pillScale,
                ),
                vertical = HomeStatusStyle.pillDp(8.dp, pillScale),
            ),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(
            HomeStatusStyle.pillDp(HomeStatusStyle.PillContentGap, pillScale)
        ),
    ) {
        Box(
            modifier = Modifier
                .size(HomeStatusStyle.pillDp(HomeStatusStyle.DotSize, pillScale))
                .clip(CircleShape)
                .background(accentColor)
        )
        Text(
            text = stringResource(R.string.home_working),
            color = contentColor,
            fontSize = HomeStatusStyle.pillSp(HomeStatusStyle.LabelSizeSp, pillScale),
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Box(
            modifier = Modifier
                .width(HomeStatusStyle.pillDp(HomeStatusStyle.DividerWidth, pillScale))
                .height(HomeStatusStyle.pillDp(HomeStatusStyle.DividerHeight, pillScale))
                .background(contentColor.copy(alpha = 0.18f))
        )
        Text(
            text = "LKM · ${BuildConfig.VERSION_NAME}",
            modifier = Modifier.weight(1f, fill = false),
            color = contentColor.copy(alpha = 0.58f),
            fontSize = HomeStatusStyle.pillSp(HomeStatusStyle.MetaSizeSp, pillScale),
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
