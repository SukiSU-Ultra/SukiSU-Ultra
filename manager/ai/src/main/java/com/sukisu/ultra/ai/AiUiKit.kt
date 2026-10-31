package com.sukisu.ultra.ai

import com.sukisu.ultra.ai.api.AiUiMode

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.union
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AlertDialogDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FabPosition
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScaffoldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchColors
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarColors
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.contentColorFor
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toBitmap
import top.yukonga.miuix.kmp.basic.Card as MiuixCard
import top.yukonga.miuix.kmp.basic.CardColors
import top.yukonga.miuix.kmp.basic.CardDefaults as MiuixCardDefaults
import top.yukonga.miuix.kmp.basic.FabPosition as MiuixFabPosition
import top.yukonga.miuix.kmp.basic.Scaffold as MiuixScaffold
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.basic.ToolbarPosition
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.MiuixPopupUtils.Companion.MiuixPopupHost

@Composable
private fun backgroundImageActive(): Boolean =
    AiAssistant.requireHost().isBackgroundImageActive()

@Composable
private fun cardBackgroundAlpha(): Float =
    AiAssistant.requireHost().cardBackgroundAlpha()

@Composable
private fun TopBarVeil(color: Color, content: @Composable () -> Unit) {
    if (!backgroundImageActive()) {
        content()
    } else {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.verticalGradient(
                        0f to color.copy(alpha = 0.28f),
                        0.65f to color.copy(alpha = 0.12f),
                        1f to color.copy(alpha = 0f),
                    )
                )
        ) {
            content()
        }
    }
}

/** Material 3 scaffold that follows the host's custom background image. */
@Composable
fun AiExpressiveScaffold(
    modifier: Modifier = Modifier,
    topBar: @Composable () -> Unit = {},
    bottomBar: @Composable () -> Unit = {},
    snackbarHost: @Composable () -> Unit = {},
    floatingActionButton: @Composable () -> Unit = {},
    floatingActionButtonPosition: FabPosition = FabPosition.End,
    containerColor: Color = Color.Unspecified,
    contentColor: Color = Color.Unspecified,
    contentWindowInsets: WindowInsets = ScaffoldDefaults.contentWindowInsets,
    content: @Composable (PaddingValues) -> Unit,
) {
    val resolvedContainerColor = when {
        containerColor != Color.Unspecified -> containerColor
        backgroundImageActive() -> Color.Transparent
        else -> MaterialTheme.colorScheme.surfaceContainer
    }
    val containerContentColor = contentColorFor(resolvedContainerColor)
    val resolvedContentColor = when {
        contentColor != Color.Unspecified -> contentColor
        containerContentColor != Color.Unspecified -> containerContentColor
        else -> LocalContentColor.current
    }
    Scaffold(
        modifier = modifier,
        topBar = { TopBarVeil(MaterialTheme.colorScheme.surface) { topBar() } },
        bottomBar = bottomBar,
        snackbarHost = snackbarHost,
        floatingActionButton = floatingActionButton,
        floatingActionButtonPosition = floatingActionButtonPosition,
        containerColor = resolvedContainerColor,
        contentColor = resolvedContentColor,
        contentWindowInsets = contentWindowInsets,
        content = content,
    )
}

@Composable
fun aiExpressiveTopAppBarColors(
    containerColor: Color = Color.Unspecified,
    scrolledContainerColor: Color = Color.Unspecified,
): TopAppBarColors {
    val resolvedContainerColor = when {
        containerColor != Color.Unspecified -> containerColor
        backgroundImageActive() -> Color.Transparent
        else -> MaterialTheme.colorScheme.surfaceContainer
    }
    val resolvedScrolledContainerColor = if (scrolledContainerColor != Color.Unspecified) {
        scrolledContainerColor
    } else {
        resolvedContainerColor
    }
    return TopAppBarDefaults.topAppBarColors(
        containerColor = resolvedContainerColor,
        scrolledContainerColor = resolvedScrolledContainerColor,
    )
}

/** Miuix scaffold that follows the host's custom background image. */
@Composable
fun AiAppScaffold(
    modifier: Modifier = Modifier,
    topBar: @Composable () -> Unit = {},
    bottomBar: @Composable () -> Unit = {},
    floatingActionButton: @Composable () -> Unit = {},
    floatingActionButtonPosition: MiuixFabPosition = MiuixFabPosition.End,
    floatingToolbar: @Composable () -> Unit = {},
    floatingToolbarPosition: ToolbarPosition = ToolbarPosition.BottomCenter,
    snackbarHost: @Composable () -> Unit = {},
    popupHost: @Composable () -> Unit = { MiuixPopupHost() },
    containerColor: Color = Color.Unspecified,
    contentWindowInsets: WindowInsets = WindowInsets.systemBars.union(WindowInsets.displayCutout),
    content: @Composable (PaddingValues) -> Unit,
) {
    val resolvedContainerColor = when {
        containerColor != Color.Unspecified -> containerColor
        backgroundImageActive() -> Color.Transparent
        else -> MiuixTheme.colorScheme.surface
    }
    MiuixScaffold(
        modifier = modifier,
        topBar = { TopBarVeil(MiuixTheme.colorScheme.surface) { topBar() } },
        bottomBar = bottomBar,
        floatingActionButton = floatingActionButton,
        floatingActionButtonPosition = floatingActionButtonPosition,
        floatingToolbar = floatingToolbar,
        floatingToolbarPosition = floatingToolbarPosition,
        snackbarHost = snackbarHost,
        popupHost = popupHost,
        containerColor = resolvedContainerColor,
        contentWindowInsets = contentWindowInsets,
        content = content,
    )
}

@Composable
fun aiBackgroundAwareColor(
    color: Color,
    backgroundAlpha: Float = cardBackgroundAlpha(),
): Color = if (backgroundImageActive()) {
    color.copy(alpha = backgroundAlpha)
} else {
    color
}

@Composable
fun aiBackgroundAwareCardColors(
    color: Color = MiuixTheme.colorScheme.surfaceContainer,
    contentColor: Color = MiuixTheme.colorScheme.onSurfaceContainer,
    backgroundAlpha: Float = cardBackgroundAlpha(),
): CardColors {
    val adjusted = if (backgroundImageActive()) color.copy(alpha = backgroundAlpha) else color
    return MiuixCardDefaults.defaultColors(color = adjusted, contentColor = contentColor)
}

@Composable
fun AiAppCard(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = MiuixCardDefaults.CornerRadius,
    insideMargin: PaddingValues = MiuixCardDefaults.InsideMargin,
    colors: CardColors = aiBackgroundAwareCardColors(),
    content: @Composable ColumnScope.() -> Unit,
) {
    MiuixCard(
        modifier = modifier,
        cornerRadius = cornerRadius,
        insideMargin = insideMargin,
        colors = colors,
        content = content,
    )
}

@Composable
fun AiTonalCard(
    modifier: Modifier = Modifier,
    containerColor: Color = MaterialTheme.colorScheme.surfaceBright,
    contentColor: Color = contentColorFor(containerColor),
    shape: Shape = MaterialTheme.shapes.large,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(
            containerColor = aiBackgroundAwareColor(containerColor),
            contentColor = contentColor,
        ),
        shape = shape,
    ) { content() }
}

@Composable
fun AiExpressiveSwitch(
    checked: Boolean,
    onCheckedChange: ((Boolean) -> Unit)?,
    modifier: Modifier = Modifier,
    thumbContent: (@Composable () -> Unit)? = null,
    enabled: Boolean = true,
    colors: SwitchColors = aiExpressiveSwitchColors(),
    interactionSource: MutableInteractionSource = remember { MutableInteractionSource() },
    showThumbIcon: Boolean = true,
) {
    Switch(
        checked = checked,
        onCheckedChange = onCheckedChange,
        modifier = modifier,
        thumbContent = thumbContent ?: if (showThumbIcon && (checked || enabled)) {
            {
                Icon(
                    imageVector = if (checked) Icons.Filled.Check else Icons.Filled.Close,
                    contentDescription = null,
                    modifier = Modifier.size(SwitchDefaults.IconSize),
                )
            }
        } else null,
        enabled = enabled,
        colors = colors,
        interactionSource = interactionSource,
    )
}

@Composable
fun aiExpressiveSwitchColors(
    checkedIconColor: Color = MaterialTheme.colorScheme.primary,
    uncheckedIconColor: Color = MaterialTheme.colorScheme.surfaceContainerHighest,
    disabledCheckedThumbColor: Color = MaterialTheme.colorScheme.surface.copy(alpha = 0.38f),
    disabledCheckedTrackColor: Color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f),
    disabledCheckedIconColor: Color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f),
    disabledUncheckedThumbColor: Color = MaterialTheme.colorScheme.outline.copy(alpha = 0.38f),
    disabledUncheckedTrackColor: Color = MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = 0.12f),
    disabledUncheckedBorderColor: Color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f),
    disabledUncheckedIconColor: Color = MaterialTheme.colorScheme.surfaceContainerHighest,
): SwitchColors = SwitchDefaults.colors(
    checkedIconColor = checkedIconColor,
    uncheckedIconColor = uncheckedIconColor,
    disabledCheckedThumbColor = disabledCheckedThumbColor,
    disabledCheckedTrackColor = disabledCheckedTrackColor,
    disabledCheckedIconColor = disabledCheckedIconColor,
    disabledUncheckedThumbColor = disabledUncheckedThumbColor,
    disabledUncheckedTrackColor = disabledUncheckedTrackColor,
    disabledUncheckedBorderColor = disabledUncheckedBorderColor,
    disabledUncheckedIconColor = disabledUncheckedIconColor,
)

@Composable
fun AiTopBarBackButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    contentDescription: String? = null,
) {
    IconButton(
        modifier = modifier.padding(horizontal = 10.dp),
        onClick = onClick,
        colors = IconButtonDefaults.iconButtonColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        ),
    ) {
        Icon(
            imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
            contentDescription = contentDescription,
        )
    }
}

@Composable
fun AiExpressiveDialog(
    onDismissRequest: () -> Unit,
    confirmButton: @Composable () -> Unit,
    modifier: Modifier = Modifier,
    dismissButton: (@Composable () -> Unit)? = null,
    icon: (@Composable () -> Unit)? = null,
    title: (@Composable () -> Unit)? = null,
    text: (@Composable () -> Unit)? = null,
    shape: Shape = MaterialTheme.shapes.extraLarge,
    containerColor: Color = AlertDialogDefaults.containerColor,
    iconContentColor: Color = AlertDialogDefaults.iconContentColor,
    titleContentColor: Color = AlertDialogDefaults.titleContentColor,
    textContentColor: Color = AlertDialogDefaults.textContentColor,
    tonalElevation: Dp = AlertDialogDefaults.TonalElevation,
    properties: DialogProperties = DialogProperties(),
) {
    AlertDialog(
        onDismissRequest = onDismissRequest,
        confirmButton = confirmButton,
        modifier = modifier,
        dismissButton = dismissButton,
        icon = icon,
        title = title,
        text = text,
        shape = shape,
        containerColor = containerColor,
        iconContentColor = iconContentColor,
        titleContentColor = titleContentColor,
        textContentColor = textContentColor,
        tonalElevation = tonalElevation,
        properties = properties,
    )
}

/** Simple two-button confirmation dialog shared by both UI flavours. */
class AiConfirmDialogHandle internal constructor() {
    internal var visible by mutableStateOf(false)
        private set
    internal var title by mutableStateOf("")
        private set
    internal var content by mutableStateOf("")
        private set
    internal var confirmLabel by mutableStateOf("")
        private set
    private var confirmed: (() -> Unit)? = null
    private var dismissed: (() -> Unit)? = null

    fun showConfirm(
        title: String,
        content: String,
        confirm: String,
    ) {
        this.title = title
        this.content = content
        this.confirmLabel = confirm
        visible = true
    }

    internal fun confirm() {
        val callback = confirmed
        visible = false
        callback?.invoke()
    }

    internal fun dismiss() {
        val callback = dismissed
        visible = false
        callback?.invoke()
    }

    internal fun bind(onConfirm: () -> Unit, onDismiss: () -> Unit) {
        confirmed = onConfirm
        dismissed = onDismiss
    }
}

@Composable
fun rememberAiConfirmDialog(
    uiMode: AiUiMode,
    onConfirm: () -> Unit = {},
    onDismiss: () -> Unit = {},
): AiConfirmDialogHandle {
    val handle = remember { AiConfirmDialogHandle() }
    handle.bind(onConfirm, onDismiss)
    if (handle.visible) {
        when (uiMode) {
            AiUiMode.Material -> AlertDialog(
                onDismissRequest = handle::dismiss,
                title = { Text(handle.title) },
                text = { Text(handle.content) },
                confirmButton = {
                    TextButton(onClick = handle::confirm) { Text(handle.confirmLabel) }
                },
                dismissButton = {
                    TextButton(onClick = handle::dismiss) {
                        Text(stringResource(android.R.string.cancel))
                    }
                },
            )

            AiUiMode.Miuix -> OverlayDialog(
                show = true,
                title = handle.title,
                onDismissRequest = handle::dismiss,
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    MiuixText(
                        text = handle.content,
                        style = MiuixTheme.textStyles.body2,
                        textAlign = TextAlign.Start,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        MiuixTextButton(
                            text = stringResource(android.R.string.cancel),
                            onClick = handle::dismiss,
                            modifier = Modifier.weight(1f),
                        )
                        MiuixTextButton(
                            text = handle.confirmLabel,
                            onClick = handle::confirm,
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
        }
    }
    return handle
}

@Composable
fun AiAvatarImage(
    modifier: Modifier = Modifier,
    size: Dp = 24.dp,
) {
    val host = AiAssistant.requireHost()
    val drawables = host.avatarDrawables()
    val iconRes = drawables?.iconRes
    val bitmap = remember(iconRes) {
        drawables?.let {
            runCatching {
                ContextCompat.getDrawable(host.context, it.iconRes)
                    ?.toBitmap(width = 256, height = 256)
                    ?.asImageBitmap()
            }.getOrNull()
        }
    }
    if (bitmap != null) {
        Image(
            bitmap = bitmap,
            contentDescription = null,
            modifier = modifier.size(size),
            contentScale = ContentScale.Crop,
        )
    } else if (drawables != null) {
        Image(
            painter = painterResource(drawables.foregroundRes),
            contentDescription = null,
            modifier = modifier.size(size),
            contentScale = ContentScale.Fit,
        )
    }
}
