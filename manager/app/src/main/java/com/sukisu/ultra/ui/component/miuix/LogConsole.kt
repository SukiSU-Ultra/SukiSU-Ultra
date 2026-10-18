package com.sukisu.ultra.ui.component.miuix

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.font.FontFamily
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.basic.CardDefaults

/** Monospace log inside a card, shared by the flash and module action screens. */
@Composable
fun LogConsole(
    text: String,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp),
        colors = CardDefaults.defaultColors(color = colorScheme.surfaceContainer),
    ) {
        Text(
            modifier = Modifier.padding(16.dp),
            text = text,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = colorScheme.onSurfaceContainer,
        )
    }
}
