package com.sukisu.ultra.ui.theme

import android.graphics.ColorMatrix
import android.graphics.ColorMatrixColorFilter
import android.graphics.Paint
import android.graphics.RuntimeShader
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.nativeCanvas
import com.sukisu.ultra.ui.util.ResolvedImageEffects
import top.yukonga.miuix.kmp.shader.isRuntimeShaderSupported

/**
 * Static colour adjustments (saturation/contrast/brightness) plus optional GPU sharpening for
 * the background image. The matrix is built once per effect config and the shader uniforms are
 * only updated when the layer size changes, so this adds no per-frame work to the UI thread.
 */
@Composable
fun Modifier.appearanceImageEffects(
    effects: ResolvedImageEffects?,
    allowSharpen: Boolean = true,
): Modifier {
    val matrix = remember(effects) { effects?.toColorMatrix() }
    val sharpen = if (
        allowSharpen &&
        effects != null &&
        effects.sharpen > 0f &&
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
        isRuntimeShaderSupported()
    ) {
        effects.sharpen
    } else {
        0f
    }
    val shader = remember(sharpen) {
        if (sharpen > 0f && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            runCatching { SharpenShader() }.getOrNull()
        } else {
            null
        }
    }

    var modifier = this
    if (matrix != null) {
        modifier = modifier.drawWithCache {
            val paint = Paint().apply {
                colorFilter = ColorMatrixColorFilter(matrix)
            }
            onDrawWithContent {
                drawIntoCanvas { canvas ->
                    canvas.nativeCanvas.saveLayer(0f, 0f, size.width, size.height, paint)
                    drawContent()
                    canvas.nativeCanvas.restore()
                }
            }
        }
    }
    if (shader != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        modifier = modifier.graphicsLayer {
            shader.apply(this, sharpen / 100f * 1.2f)
        }
    }
    return modifier
}

private fun ResolvedImageEffects.toColorMatrix(): ColorMatrix? {
    if (!affectsColor) return null
    val saturationFactor = saturation / 100f
    val contrastFactor = contrast / 100f
    val brightnessOffset = brightness / 100f * 255f
    val contrastOffset = 128f * (1f - contrastFactor) + brightnessOffset

    val matrix = ColorMatrix()
    matrix.setSaturation(saturationFactor)
    matrix.postConcat(
        ColorMatrix(
            floatArrayOf(
                contrastFactor, 0f, 0f, 0f, contrastOffset,
                0f, contrastFactor, 0f, 0f, contrastOffset,
                0f, 0f, contrastFactor, 0f, contrastOffset,
                0f, 0f, 0f, 1f, 0f,
            )
        )
    )
    return matrix
}

/**
 * Offset sampling unsharp mask. `content` is the layer this effect is attached to, so the
 * background's crop/blur result is what gets sharpened.
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
private class SharpenShader {
    private val shader = RuntimeShader(SHARPEN_AGSL)
    private var lastWidth = -1f
    private var lastHeight = -1f
    private var failed = false

    fun apply(scope: androidx.compose.ui.graphics.GraphicsLayerScope, amount: Float) {
        if (failed) return
        try {
            val width = scope.size.width
            val height = scope.size.height
            if (width <= 0f || height <= 0f) return
            if (width != lastWidth || height != lastHeight) {
                lastWidth = width
                lastHeight = height
                shader.setFloatUniform("uTexelSize", 1f / width, 1f / height)
                scope.renderEffect = android.graphics.RenderEffect.createRuntimeShaderEffect(
                    shader,
                    "content",
                ).asComposeRenderEffect()
            }
            shader.setFloatUniform("uAmount", amount)
        } catch (_: Throwable) {
            // AGSL is unavailable or the shader failed to compile on this device.
            failed = true
            scope.renderEffect = null
        }
    }
}

private const val SHARPEN_AGSL = """
uniform shader content;
uniform float2 uTexelSize;
uniform float uAmount;

half4 main(float2 coord) {
    half4 center = content.eval(coord);
    half4 left = content.eval(coord + float2(-uTexelSize.x, 0.0));
    half4 right = content.eval(coord + float2(uTexelSize.x, 0.0));
    half4 up = content.eval(coord + float2(0.0, -uTexelSize.y));
    half4 down = content.eval(coord + float2(0.0, uTexelSize.y));
    half4 blurred = (left + right + up + down) * half(0.25);
    half4 sharpened = center + (center - blurred) * half(uAmount);
    half3 rgb = clamp(sharpened.rgb, half3(0.0), half3(1.0));
    return half4(rgb, center.a);
}
"""
