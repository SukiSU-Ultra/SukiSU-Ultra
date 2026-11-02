package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text as MaterialText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.statustag.StatusTag
import com.sukisu.ultra.ui.util.ExtensionState
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.viewmodel.ExtensionItem
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** Localised card title: customised copy first, catalog copy, then the kernel wire name. */
@Composable
internal fun extensionTitle(item: ExtensionItem): String =
    item.descriptor.textKey?.let { customText(it) }
        ?: item.descriptor.titleRes?.let { stringResource(it) }
        ?: item.wireName

/**
 * One-line-ish description. Cards cap it at two lines, so a known
 * extension's long summary no longer turns the card into a paragraph.
 */
@Composable
internal fun extensionDescription(item: ExtensionItem): String =
    item.descriptor.summaryRes?.let { stringResource(it) }
        ?: stringResource(R.string.extension_generic_summary)

/**
 * Coloured status tag plus, when relevant, one short lifetime hint:
 * "Needs reboot" / "Survives reboot" / "This boot only". Keeping these on a
 * single row is what stops the card from becoming four lines of small text.
 */
@Composable
internal fun ExtensionStatusRow(
    item: ExtensionItem,
    modifier: Modifier = Modifier,
) {
    val state = item.state
    val pill = pillFor(state)
    val (background, foreground) = statusTagColors(pill)
    val lifecycle = extensionLifecycleText(state)
    val lifecycleStyle: TextStyle
    val lifecycleColor: Color
    when (LocalUiMode.current) {
        UiMode.Material -> {
            lifecycleStyle = MaterialTheme.typography.labelSmall
            lifecycleColor = MaterialTheme.colorScheme.onSurfaceVariant
        }
        UiMode.Miuix -> {
            lifecycleStyle = MiuixTheme.textStyles.footnote1
            lifecycleColor = MiuixTheme.colorScheme.onSurfaceVariantSummary
        }
    }

    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        StatusTag(
            label = stringResource(pill.labelRes),
            backgroundColor = background,
            contentColor = foreground,
        )
        if (lifecycle != null) {
            when (LocalUiMode.current) {
                UiMode.Material -> MaterialText(
                    text = lifecycle,
                    modifier = Modifier.weight(1f, fill = false),
                    style = lifecycleStyle,
                    color = lifecycleColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                UiMode.Miuix -> MiuixText(
                    text = lifecycle,
                    modifier = Modifier.weight(1f, fill = false),
                    style = lifecycleStyle,
                    color = lifecycleColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun statusTagColors(pill: ExtensionPill): Pair<Color, Color> =
    when (LocalUiMode.current) {
        UiMode.Material -> with(MaterialTheme.colorScheme) {
            when (pill) {
                ExtensionPill.Unsupported -> errorContainer to onErrorContainer
                ExtensionPill.Forced,
                ExtensionPill.Managed -> tertiaryContainer to onTertiaryContainer
                ExtensionPill.Enabled -> primaryContainer to onPrimaryContainer
                ExtensionPill.Disabled -> surfaceContainerHighest to onSurfaceVariant
                ExtensionPill.Supported -> secondaryContainer to onSecondaryContainer
            }
        }
        UiMode.Miuix -> with(MiuixTheme.colorScheme) {
            when (pill) {
                ExtensionPill.Unsupported -> errorContainer to onErrorContainer
                ExtensionPill.Forced,
                ExtensionPill.Managed -> tertiaryContainer to onTertiaryContainer
                ExtensionPill.Enabled -> primaryContainer to onPrimaryContainer
                ExtensionPill.Disabled -> surfaceContainerHighest to onSurfaceVariantSummary
                ExtensionPill.Supported -> secondaryContainer to onSecondaryContainer
            }
        }
    }

@Composable
private fun extensionLifecycleText(state: ExtensionState): String? {
    if (!state.supported) return null
    return when {
        state.needsReboot -> stringResource(R.string.extension_status_reboot_short)
        !state.sticky -> null
        state.persistent -> stringResource(R.string.extension_status_persistent_short)
        state.capsKnown -> stringResource(R.string.extension_status_session_only_short)
        else -> null
    }
}
