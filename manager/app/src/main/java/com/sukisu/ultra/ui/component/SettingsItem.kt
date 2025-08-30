package com.sukisu.ultra.ui.component

import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import com.dergoogler.mmrl.ui.component.LabelItem
import com.dergoogler.mmrl.ui.component.text.TextRow
import com.sukisu.ultra.ui.theme.CardConfig

@Composable
fun SwitchItem(
    icon: ImageVector? = null,
    title: String,
    summary: String? = null,
    checked: Boolean,
    enabled: Boolean = true,
    beta: Boolean = false,
    onCheckedChange: (Boolean) -> Unit
) {
    val interactionSource = remember { MutableInteractionSource() }
    val stateAlpha = remember(checked, enabled) { Modifier.alpha(if (enabled) 1f else 0.5f) }

    MaterialTheme(
        colorScheme = MaterialTheme.colorScheme.copy(
            surface = if (CardConfig.isCustomBackgroundEnabled) Color.Transparent else MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        ListItem(
            modifier = Modifier
                .toggleable(
                    value = checked,
                    interactionSource = interactionSource,
                    role = Role.Switch,
                    enabled = enabled,
                    indication = LocalIndication.current,
                    onValueChange = onCheckedChange
                ),
            headlineContent = {
                TextRow(
                    leadingContent = if (beta) {
                        {
                            LabelItem(
                                modifier = Modifier.then(stateAlpha),
                                text = "Beta"
                            )
                        }
                    } else null
                ) {
                    Text(
                        modifier = Modifier.then(stateAlpha),
                        text = title,
                    )
                }
            },
            leadingContent = icon?.let {
                {
                    Icon(
                        modifier = Modifier.then(stateAlpha),
                        imageVector = icon,
                        contentDescription = title
                    )
                }
            },
            trailingContent = {
                Switch(
                    checked = checked,
                    enabled = enabled,
                    onCheckedChange = onCheckedChange,
                    interactionSource = interactionSource
                )
            },
            supportingContent = {
                if (summary != null) {
                    Text(
                        modifier = Modifier.then(stateAlpha),
                        text = summary
                    )
                }
            }
        )
    }
}

@Composable
fun RadioItem(
    title: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    ListItem(
        headlineContent = {
            Text(title)
        },
        leadingContent = {
            RadioButton(selected = selected, onClick = onClick)
        }
    )
}