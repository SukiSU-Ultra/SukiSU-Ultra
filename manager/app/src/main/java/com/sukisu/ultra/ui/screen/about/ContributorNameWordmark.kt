/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Adapted from eltavine/Duck-Detector-Refactoring (ContributorNameWordmark).
package com.sukisu.ultra.ui.screen.about

import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Region
import android.graphics.Typeface
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.math.min

private const val WordmarkWord = "SUKISU"
private const val WordmarkWidth = 1000f
private const val WordmarkHeight = 300f
private const val MaxWordmarkZoom = 8f
private const val CharacterColumnWidth = 8f
private const val CharacterRowHeight = 10f
private const val CharacterTextSize = 11f

private val WordmarkOffsetSaver = listSaver<Offset, Float>(
    save = { listOf(it.x, it.y) },
    restore = { Offset(it[0], it[1]) },
)

/** Contributor-name characters fill the SUKISU letterforms; zoom in to read the names. */
@Composable
fun ContributorNameWordmark(names: List<String>, modifier: Modifier = Modifier) {
    if (names.isEmpty()) return

    // Building thousands of glyph paths is CPU-heavy; prepare it off the main thread.
    val layout by produceState<Path?>(initialValue = null, names) {
        value = withContext(Dispatchers.Default) { buildWordmarkPath(names) }
    }
    var viewport by remember { mutableStateOf(IntSize.Zero) }
    var zoom by rememberSaveable { mutableFloatStateOf(1f) }
    var offset by rememberSaveable(stateSaver = WordmarkOffsetSaver) { mutableStateOf(Offset.Zero) }
    val characterColor = MaterialTheme.colorScheme.onSurface.toArgb()
    val characterPaint = remember(characterColor) {
        Paint(Paint.ANTI_ALIAS_FLAG).apply { color = characterColor }
    }

    LaunchedEffect(viewport) {
        offset = constrainWallOffset(offset, wordmarkPanLimit(viewport, zoom))
    }

    val transformState = rememberTransformableState { centroid, zoomChange, panChange, _ ->
        if (viewport.width > 0 && viewport.height > 0) {
            val nextZoom = (zoom * zoomChange).coerceIn(1f, MaxWordmarkZoom)
            val center = Offset(viewport.width / 2f, viewport.height / 2f)
            val anchor = if (centroid == Offset.Unspecified) Offset.Zero else centroid - center
            offset = constrainWallOffset(
                zoomAround(offset, anchor, panChange, nextZoom / zoom),
                wordmarkPanLimit(viewport, nextZoom),
            )
            zoom = nextZoom
        }
    }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(WordmarkWidth / WordmarkHeight)
                .clip(MaterialTheme.shapes.large)
                .onSizeChanged { viewport = it }
                .transformable(state = transformState, canPan = { zoom > 1f })
                .semantics { contentDescription = WordmarkWord },
        ) {
            if (size.width <= 0f || size.height <= 0f) return@Canvas
            val path = layout ?: return@Canvas
            val scale = wordmarkFitScale(Size(size.width, size.height)) * zoom
            val canvas = drawContext.canvas.nativeCanvas
            canvas.save()
            canvas.clipRect(0f, 0f, size.width, size.height)
            canvas.translate(size.width / 2f + offset.x, size.height / 2f + offset.y)
            canvas.scale(scale, scale)
            canvas.translate(-WordmarkWidth / 2f, -WordmarkHeight / 2f)
            canvas.drawPath(path, characterPaint)
            canvas.restore()
        }
        Text(
            text = stringResource(R.string.about_wordmark_hint),
            modifier = Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

private fun buildWordmarkPath(names: List<String>): Path {
    val letters = Path().apply { addWord(WordmarkWord, RectF(30f, 30f, 970f, 270f)) }
    val region = Region().apply {
        setPath(letters, Region(0, 0, WordmarkWidth.toInt(), WordmarkHeight.toInt()))
    }
    val characters = names.flatMap { name ->
        buildList {
            var index = 0
            while (index < name.length) {
                val codePoint = name.codePointAt(index)
                if (Character.isLetterOrDigit(codePoint)) {
                    add(String(Character.toChars(codePoint)))
                }
                index += Character.charCount(codePoint)
            }
        }
    }
    if (characters.isEmpty()) return Path()

    val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.create("sans-serif", Typeface.BOLD)
        textSize = CharacterTextSize
    }
    val fontMetrics = paint.fontMetrics
    val characterPath = Path()
    val glyphPath = Path()
    var characterIndex = 0
    var centerY = CharacterRowHeight / 2f
    while (centerY < WordmarkHeight) {
        var centerX = CharacterColumnWidth / 2f
        while (centerX < WordmarkWidth) {
            if (region.contains(centerX.toInt(), centerY.toInt())) {
                val character = characters[characterIndex % characters.size]
                val baseline = centerY - (fontMetrics.ascent + fontMetrics.descent) / 2f
                val left = centerX - paint.measureText(character) / 2f
                glyphPath.reset()
                paint.getTextPath(character, 0, character.length, left, baseline, glyphPath)
                characterPath.addPath(glyphPath)
                characterIndex++
            }
            centerX += CharacterColumnWidth
        }
        centerY += CharacterRowHeight
    }
    return characterPath
}

private fun wordmarkFitScale(viewport: Size): Float =
    min(viewport.width / WordmarkWidth, viewport.height / WordmarkHeight)

private fun wordmarkPanLimit(viewport: IntSize, zoom: Float): Offset {
    val scale = wordmarkFitScale(Size(viewport.width.toFloat(), viewport.height.toFloat())) * zoom
    return Offset(
        ((WordmarkWidth * scale - viewport.width) / 2f).coerceAtLeast(0f),
        ((WordmarkHeight * scale - viewport.height) / 2f).coerceAtLeast(0f),
    )
}

private fun Path.addWord(word: String, target: RectF) {
    val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.create("sans-serif-black", Typeface.BOLD)
        textSize = 100f
    }
    val wordPath = Path()
    paint.getTextPath(word, 0, word.length, 0f, 0f, wordPath)
    val bounds = RectF()
    wordPath.computeBounds(bounds, true)
    val transform = Matrix().apply { setRectToRect(bounds, target, Matrix.ScaleToFit.CENTER) }
    wordPath.transform(transform)
    addPath(wordPath)
}
