package com.sukisu.ultra.ui.component

import androidx.compose.runtime.Composable
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ksuApp

@Composable
fun KsuIsValid(
    content: @Composable () -> Unit
) {
    val isManager = Natives.isManager
    val ksuVersion = if (isManager) Natives.version else null

    if (ksuVersion != null) {
        content()
    }
}