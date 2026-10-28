package com.sukisu.ultra.ui.screen.appicon

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

internal const val APP_ICON_GRID_COLUMNS = 4

/** Lays icon tiles out in fixed rows so the grid can scroll inside a LazyColumn. */
@Composable
internal fun <T> AppIconGrid(
    items: List<T>,
    tile: @Composable (T) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        items.chunked(APP_ICON_GRID_COLUMNS).forEach { row ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                row.forEach { item ->
                    Box(modifier = Modifier.weight(1f)) {
                        tile(item)
                    }
                }
                repeat(APP_ICON_GRID_COLUMNS - row.size) {
                    Spacer(modifier = Modifier.weight(1f))
                }
            }
        }
    }
}
