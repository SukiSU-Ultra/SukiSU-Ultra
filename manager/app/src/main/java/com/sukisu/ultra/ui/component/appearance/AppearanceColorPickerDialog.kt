package com.sukisu.ultra.ui.component.appearance

import android.graphics.Color as AndroidColor
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.material.ExpressiveDialog
import com.sukisu.ultra.ui.util.AppearanceOverlayStore
import com.sukisu.ultra.ui.util.toOverlayColorString
import kotlin.math.roundToInt
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.basic.TextField as MiuixTextField
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

private val HueColors = listOf(
    Color.Red,
    Color.Yellow,
    Color.Green,
    Color.Cyan,
    Color.Blue,
    Color.Magenta,
    Color.Red,
)

@Composable
fun AppearanceColorPickerDialog(
    show: Boolean,
    title: String,
    initialColor: Color,
    clearable: Boolean,
    onDismissRequest: () -> Unit,
    onConfirm: (Color) -> Unit,
    onClear: () -> Unit,
) {
    if (!show) return

    val miuix = LocalUiMode.current == UiMode.Miuix
    val initialArgb = initialColor.toArgb()
    val initialHsv = FloatArray(3).also { AndroidColor.colorToHSV(initialArgb, it) }

    var hue by rememberSaveable(initialArgb) { mutableFloatStateOf(initialHsv[0]) }
    var saturation by rememberSaveable(initialArgb) { mutableFloatStateOf(initialHsv[1]) }
    var value by rememberSaveable(initialArgb) { mutableFloatStateOf(initialHsv[2]) }
    var alpha by rememberSaveable(initialArgb) {
        mutableFloatStateOf(AndroidColor.alpha(initialArgb) / 255f)
    }
    var hexText by rememberSaveable(initialArgb) {
        mutableStateOf(initialArgb.toOverlayColorString())
    }
    var hexFocused by remember { mutableStateOf(false) }
    var hexEditing by remember { mutableStateOf(false) }
    var hexError by remember { mutableStateOf(false) }
    val focusManager = LocalFocusManager.current

    val currentArgb = AndroidColor.HSVToColor(
        (alpha * 255f).roundToInt().coerceIn(0, 255),
        floatArrayOf(hue, saturation, value),
    )
    val currentColor = Color(currentArgb)

    LaunchedEffect(currentArgb, hexFocused, hexEditing) {
        if (!hexFocused && !hexEditing) {
            hexText = currentArgb.toOverlayColorString()
            hexError = false
        }
    }

    fun applyHex(raw: String) {
        val candidate = raw.trim()
        if (candidate.isEmpty()) {
            hexError = false
            return
        }
        val normalized = if (candidate.startsWith("#")) candidate else "#$candidate"
        val parsed = AppearanceOverlayStore.parseColorValue(normalized)
        if (parsed == null) {
            hexError = true
            return
        }
        hexError = false
        val hsv = FloatArray(3).also { AndroidColor.colorToHSV(parsed, it) }
        hue = hsv[0]
        saturation = hsv[1]
        value = hsv[2]
        alpha = AndroidColor.alpha(parsed) / 255f
    }

    val body = @Composable {
        ColorPickerBody(
            miuix = miuix,
            hue = hue,
            saturation = saturation,
            value = value,
            alpha = alpha,
            currentColor = currentColor,
            hexText = hexText,
            hexError = hexError,
            onHexChange = {
                hexEditing = true
                hexText = it
                applyHex(it)
            },
            onHexFocusChange = {
                hexFocused = it
                if (!it) hexEditing = false
            },
            onHueChange = {
                focusManager.clearFocus()
                hexEditing = false
                hue = it
            },
            onSaturationValueChange = { s, v ->
                focusManager.clearFocus()
                hexEditing = false
                saturation = s
                value = v
            },
            onAlphaChange = {
                focusManager.clearFocus()
                hexEditing = false
                alpha = it
            },
        )
    }

    if (miuix) {
        OverlayDialog(
            show = true,
            title = title,
            onDismissRequest = onDismissRequest,
            insideMargin = DpSize(0.dp, 24.dp),
            content = {
                Column(modifier = Modifier.padding(horizontal = 24.dp)) {
                    body()
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (clearable) {
                            MiuixTextButton(
                                text = stringResource(R.string.appearance_override_clear),
                                onClick = onClear,
                                modifier = Modifier.weight(1f),
                            )
                        }
                        MiuixTextButton(
                            text = stringResource(R.string.cancel),
                            onClick = onDismissRequest,
                            modifier = Modifier.weight(1f),
                        )
                        MiuixTextButton(
                            text = stringResource(R.string.appearance_picker_apply),
                            onClick = { onConfirm(currentColor) },
                            modifier = Modifier.weight(1f),
                            enabled = !hexError,
                            colors = top.yukonga.miuix.kmp.basic.ButtonDefaults.textButtonColorsPrimary(),
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                }
            },
        )
    } else {
        ExpressiveDialog(
            onDismissRequest = onDismissRequest,
            title = { MaterialText(title) },
            text = {
                Column {
                    body()
                    if (clearable) {
                        Spacer(Modifier.height(8.dp))
                        MaterialTextButton(onClick = onClear) {
                            MaterialText(stringResource(R.string.appearance_override_clear))
                        }
                    }
                }
            },
            confirmButton = {
                MaterialTextButton(
                    onClick = { onConfirm(currentColor) },
                    enabled = !hexError,
                ) {
                    MaterialText(stringResource(R.string.appearance_picker_apply))
                }
            },
            dismissButton = {
                MaterialTextButton(onClick = onDismissRequest) {
                    MaterialText(stringResource(R.string.cancel))
                }
            },
        )
    }
}

@Composable
private fun ColorPickerBody(
    miuix: Boolean,
    hue: Float,
    saturation: Float,
    value: Float,
    alpha: Float,
    currentColor: Color,
    hexText: String,
    hexError: Boolean,
    onHexChange: (String) -> Unit,
    onHexFocusChange: (Boolean) -> Unit,
    onHueChange: (Float) -> Unit,
    onSaturationValueChange: (Float, Float) -> Unit,
    onAlphaChange: (Float) -> Unit,
) {
    val onSurface = if (miuix) {
        MiuixTheme.colorScheme.onSurface
    } else {
        MaterialTheme.colorScheme.onSurface
    }
    val outline = if (miuix) {
        MiuixTheme.colorScheme.outline
    } else {
        MaterialTheme.colorScheme.outline
    }
    val surface = if (miuix) {
        MiuixTheme.colorScheme.surfaceContainerHigh
    } else {
        MaterialTheme.colorScheme.surfaceContainerHigh
    }
    val primary = if (miuix) {
        MiuixTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.primary
    }
    val errorColor = if (miuix) {
        MiuixTheme.colorScheme.error
    } else {
        MaterialTheme.colorScheme.error
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(52.dp)
                    .clip(CircleShape)
                    .background(currentColor)
            )
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                HexColorField(
                    value = hexText,
                    onValueChange = onHexChange,
                    onFocusChange = onHexFocusChange,
                    isError = hexError,
                    miuix = miuix,
                )
                if (hexError) {
                    PickerLabel(
                        text = stringResource(R.string.appearance_picker_hex_invalid),
                        color = errorColor,
                        miuix = miuix,
                    )
                }
                PickerLabel(
                    text = stringResource(
                        R.string.appearance_picker_alpha_value,
                        (alpha * 100f).roundToInt(),
                    ),
                    color = onSurface.copy(alpha = 0.7f),
                    miuix = miuix,
                )
            }
        }

        SaturationValueField(
            hue = hue,
            saturation = saturation,
            value = value,
            outline = outline,
            onChange = onSaturationValueChange,
        )

        GradientBar(
            brush = Brush.horizontalGradient(HueColors),
            fraction = hue / 360f,
            thumbColor = surface,
            outline = outline,
            onChange = { onHueChange((it * 360f).coerceIn(0f, 360f)) },
        )
        PickerLabel(
            text = stringResource(R.string.appearance_picker_hue),
            color = onSurface.copy(alpha = 0.7f),
            miuix = miuix,
        )

        GradientBar(
            brush = Brush.horizontalGradient(
                listOf(
                    Color.hsv(hue, saturation, value).copy(alpha = 0f),
                    Color.hsv(hue, saturation, value),
                )
            ),
            fraction = alpha,
            thumbColor = surface,
            outline = outline,
            onChange = { onAlphaChange(it.coerceIn(0f, 1f)) },
        )
        PickerLabel(
            text = stringResource(R.string.appearance_picker_alpha),
            color = onSurface.copy(alpha = 0.7f),
            miuix = miuix,
        )

        if (miuix) {
            MiuixText(
                text = stringResource(R.string.appearance_picker_notice),
                style = MiuixTheme.textStyles.body2,
                color = primary,
            )
        } else {
            MaterialText(
                text = stringResource(R.string.appearance_picker_notice),
                style = MaterialTheme.typography.bodySmall,
                color = primary,
            )
        }
    }
}

@Composable
private fun HexColorField(
    value: String,
    onValueChange: (String) -> Unit,
    onFocusChange: (Boolean) -> Unit,
    isError: Boolean,
    miuix: Boolean,
) {
    if (miuix) {
        MiuixTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { onFocusChange(it.isFocused) },
            label = stringResource(R.string.appearance_picker_hex),
            useLabelAsPlaceholder = true,
            singleLine = true,
            textStyle = MiuixTheme.textStyles.main.copy(fontFamily = FontFamily.Monospace),
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Characters,
            ),
        )
    } else {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { onFocusChange(it.isFocused) },
            label = { MaterialText(stringResource(R.string.appearance_picker_hex)) },
            singleLine = true,
            isError = isError,
            textStyle = MaterialTheme.typography.bodyLarge.copy(
                fontFamily = FontFamily.Monospace,
            ),
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Characters,
            ),
        )
    }
}

@Composable
private fun PickerLabel(
    text: String,
    color: Color,
    miuix: Boolean,
    monospace: Boolean = false,
) {
    if (miuix) {
        MiuixText(
            text = text,
            color = color,
            style = MiuixTheme.textStyles.body2,
            fontFamily = if (monospace) FontFamily.Monospace else null,
        )
    } else {
        MaterialText(
            text = text,
            color = color,
            style = if (monospace) {
                MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
            } else {
                MaterialTheme.typography.bodySmall
            },
        )
    }
}

@Composable
private fun SaturationValueField(
    hue: Float,
    saturation: Float,
    value: Float,
    outline: Color,
    onChange: (Float, Float) -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(180.dp)
            .clip(RoundedCornerShape(14.dp))
    ) {
        Canvas(modifier = Modifier.matchParentSize()) {
            drawRect(Brush.horizontalGradient(listOf(Color.White, Color.hsv(hue, 1f, 1f))))
            drawRect(Brush.verticalGradient(listOf(Color.Transparent, Color.Black)))
        }
        Canvas(modifier = Modifier.matchParentSize()) {
            val center = androidx.compose.ui.geometry.Offset(
                saturation * size.width,
                (1f - value) * size.height,
            )
            drawCircle(color = Color.Black.copy(alpha = 0.4f), radius = 9.dp.toPx(), center = center)
            drawCircle(
                color = Color.White,
                radius = 7.dp.toPx(),
                center = center,
                style = Stroke(width = 2.dp.toPx()),
            )
        }
        Box(
            modifier = Modifier
                .matchParentSize()
                .pointerInput(hue) {
                    awaitEachGesture {
                        val down = awaitFirstDown()
                        onChange(
                            (down.position.x / size.width).coerceIn(0f, 1f),
                            (1f - down.position.y / size.height).coerceIn(0f, 1f),
                        )
                        do {
                            val event = awaitPointerEvent()
                            event.changes.forEach { change ->
                                if (change.pressed) {
                                    onChange(
                                        (change.position.x / size.width).coerceIn(0f, 1f),
                                        (1f - change.position.y / size.height).coerceIn(0f, 1f),
                                    )
                                }
                            }
                        } while (event.changes.any { it.pressed })
                    }
                }
        )
    }
}

@Composable
private fun GradientBar(
    brush: Brush,
    fraction: Float,
    thumbColor: Color,
    outline: Color,
    onChange: (Float) -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(24.dp)
            .clip(CircleShape)
            .background(brush)
            .pointerInput(Unit) {
                awaitEachGesture {
                    val down = awaitFirstDown()
                    onChange((down.position.x / size.width).coerceIn(0f, 1f))
                    do {
                        val event = awaitPointerEvent()
                        event.changes.forEach { change ->
                            if (change.pressed) {
                                onChange((change.position.x / size.width).coerceIn(0f, 1f))
                            }
                        }
                    } while (event.changes.any { it.pressed })
                }
            }
    ) {
        Canvas(modifier = Modifier.matchParentSize()) {
            val x = fraction.coerceIn(0f, 1f) * size.width
            drawCircle(
                color = outline,
                radius = 10.dp.toPx(),
                center = androidx.compose.ui.geometry.Offset(x, size.height / 2f),
            )
            drawCircle(
                color = thumbColor,
                radius = 8.dp.toPx(),
                center = androidx.compose.ui.geometry.Offset(x, size.height / 2f),
            )
        }
    }
}
