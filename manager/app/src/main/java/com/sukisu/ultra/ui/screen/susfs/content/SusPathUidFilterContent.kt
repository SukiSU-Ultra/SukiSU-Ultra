package com.sukisu.ultra.ui.screen.susfs.content

import androidx.compose.runtime.Composable
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.screen.susfs.content.material.SusPathUidFilterContentMaterial
import com.sukisu.ultra.ui.screen.susfs.content.miuix.SusPathUidFilterContentMiuix

@Composable
fun SusPathUidFilterContent(
    packages: Set<String>,
    isLoading: Boolean,
    onSelectApps: () -> Unit,
    onApply: () -> Unit,
    onClear: () -> Unit,
) {
    when (LocalUiMode.current) {
        UiMode.Material -> SusPathUidFilterContentMaterial(packages, isLoading, onSelectApps, onApply, onClear)
        UiMode.Miuix -> SusPathUidFilterContentMiuix(packages, isLoading, onSelectApps, onApply, onClear)
    }
}
